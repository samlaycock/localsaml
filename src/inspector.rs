//! Request inspector: a middleware that records recent requests so `/dev/requests` and
//! `/dev/api/requests` can show what an app sent, the SAML messages that went back and forth
//! (decoded and indented, like a SAML tracer), and why anything was rejected.
//!
//! Incoming `SAMLRequest`/`SAMLResponse` parameters are decoded here. Handlers attach a
//! [`SamlNote`] for each message they send and an [`ErrorNote`] when they reject a request.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::Value;

use crate::saml::{NS_ASSERTION, NS_PROTOCOL, Status, decode_message};
use crate::state::AppState;
use crate::util::{parse_form, value_to_string};

/// How many requests are kept.
pub const CAPACITY: usize = 500;
/// The same limit axum applies to request bodies by default.
pub(crate) const MAX_BODY: usize = 2 * 1024 * 1024;
/// Decoded messages longer than this are cut short in the record.
const MAX_RECORDED_XML: usize = 256 * 1024;

/// Larger request bodies are passed on but not parsed for the record.
const MAX_RECORDED_BODY: usize = 256 * 1024;

/// Attached to a response that rejects a request, so the inspector can show why.
#[derive(Debug, Clone)]
pub struct ErrorNote {
    pub error: String,
    pub description: String,
}

impl ErrorNote {
    pub fn attach(response: &mut Response, error: impl Into<String>, description: impl Into<String>) {
        response.extensions_mut().insert(ErrorNote { error: error.into(), description: description.into() });
    }
}

/// A SAML message, decoded.
#[derive(Debug, Clone, Serialize)]
pub struct Message {
    /// `received` or `sent`.
    pub direction: &'static str,
    /// `AuthnRequest`, `Response`, `LogoutRequest`, ...
    pub kind: String,
    /// `redirect`, `post` or `api`.
    pub binding: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Indented XML.
    pub xml: String,
}

/// Attached to a response that sends SAML messages (a Response posted to an ACS, a LogoutRequest
/// redirect, ...).
#[derive(Debug, Clone, Default)]
pub struct SamlNote {
    pub messages: Vec<Message>,
    /// The service provider the messages are for.
    pub sp: Option<String>,
    /// A SAML error status sent back to the SP.
    pub status: Option<Status>,
}

impl SamlNote {
    pub fn sent(
        sp: &str,
        kind: &str,
        binding: &'static str,
        destination: &str,
        xml: String,
        status: Option<&Status>,
    ) -> Self {
        Self {
            messages: vec![Message {
                direction: "sent",
                kind: kind.into(),
                binding,
                destination: Some(destination.into()),
                status: status.map(Status::short),
                xml,
            }],
            sp: Some(sp.into()),
            status: status.filter(|s| !s.is_success()).cloned(),
        }
    }

    pub fn attach(mut self, response: &mut Response) {
        for m in &mut self.messages {
            m.xml = truncate_xml(std::mem::take(&mut m.xml));
        }
        match response.extensions_mut().get_mut::<SamlNote>() {
            Some(existing) => {
                existing.messages.extend(self.messages);
                existing.sp = existing.sp.take().or(self.sp);
                existing.status = existing.status.take().or(self.status);
            }
            None => {
                response.extensions_mut().insert(self);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub id: u64,
    /// Real time, in Unix milliseconds.
    pub at: i64,
    pub duration_ms: u64,
    pub method: String,
    pub path: String,
    /// `root` or the template of a `/p/<preset>` issuer.
    pub issuer: String,
    /// The path within the issuer, e.g. `/sso`.
    pub endpoint: String,
    /// `flow`, or `metadata` and `dev` (localsaml's own tools and test SP), which the page hides
    /// by default.
    pub category: &'static str,
    /// The service provider (entity ID) involved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sp: Option<String>,
    /// Query and form parameters; SAML messages are shortened here and decoded in `messages`.
    pub params: BTreeMap<String, String>,
    pub messages: Vec<Message>,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// A one-line summary, e.g. `Response → http://localhost:3000/acs` or the error code.
    pub outcome: String,
    /// Where a redirect or form post went (without its parameters).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
    /// A request localsaml made (a back-channel SOAP call), rather than one it received.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub outgoing: bool,
}

impl Entry {
    pub fn failed(&self) -> bool {
        self.error.is_some() || self.status >= 400
    }
}

#[derive(Debug, Default)]
pub struct Inspector {
    inner: Mutex<Log>,
}

#[derive(Debug, Default)]
struct Log {
    next_id: u64,
    entries: VecDeque<Entry>,
}

#[derive(Debug, Default)]
pub struct Filter {
    pub sp: Option<String>,
    pub errors_only: bool,
    /// Only entries newer than this id.
    pub after: Option<u64>,
    pub limit: Option<usize>,
}

impl Inspector {
    pub fn record(&self, mut entry: Entry) {
        let mut log = self.inner.lock().unwrap();
        log.next_id += 1;
        entry.id = log.next_id;
        log.entries.push_back(entry);
        if log.entries.len() > CAPACITY {
            log.entries.pop_front();
        }
    }

    /// Matching entries, newest first.
    pub fn list(&self, filter: &Filter) -> Vec<Entry> {
        let log = self.inner.lock().unwrap();
        log.entries
            .iter()
            .rev()
            .filter(|e| filter.after.is_none_or(|after| e.id > after))
            .filter(|e| filter.sp.as_ref().is_none_or(|s| e.sp.as_ref() == Some(s)))
            .filter(|e| !filter.errors_only || e.failed())
            .take(filter.limit.unwrap_or(CAPACITY))
            .cloned()
            .collect()
    }

    /// The id of the newest entry ever recorded (0 if none); clearing doesn't reset it.
    pub fn latest_id(&self) -> u64 {
        self.inner.lock().unwrap().next_id
    }

    /// Record a back-channel call localsaml made: the message sent and the answer (or failure).
    #[allow(clippy::too_many_arguments)]
    pub fn record_outgoing(
        &self,
        issuer: &str,
        url: &str,
        sp: &str,
        sent: Message,
        received: Option<Message>,
        status: u16,
        error: Option<(String, String)>,
        outcome: String,
        started: Instant,
    ) {
        self.record(Entry {
            id: 0,
            at: now_ms(),
            duration_ms: started.elapsed().as_millis() as u64,
            method: "POST".into(),
            path: url.into(),
            issuer: issuer.into(),
            endpoint: strip_query(url),
            category: "flow",
            sp: Some(sp.into()),
            params: BTreeMap::new(),
            messages: [Some(sent), received]
                .into_iter()
                .flatten()
                .map(|mut m| {
                    m.xml = truncate_xml(m.xml);
                    m
                })
                .collect(),
            status,
            error_description: error.as_ref().map(|(_, d)| d.clone()),
            error: error.map(|(e, _)| e),
            outcome,
            redirect: None,
            outgoing: true,
        });
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().entries.clear();
    }
}

/// Real time in Unix milliseconds.
pub(crate) fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or_default()
}

/// Paths that are never recorded: static assets, health checks and the inspector itself.
fn ignored(path: &str) -> bool {
    let within = strip_issuer(path).1;
    path.starts_with("/assets/")
        || path == "/health"
        || path == "/favicon.ico"
        || within == "/dev/requests"
        || within == "/dev/api/requests"
}

/// (`root` or the template id, path within the issuer).
pub(crate) fn strip_issuer(path: &str) -> (&str, &str) {
    match path.strip_prefix("/p/") {
        Some(rest) => match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        },
        None => ("root", path),
    }
}

fn category(endpoint: &str) -> &'static str {
    let p = endpoint.trim_end_matches('/');
    if p == "/dev" || p.starts_with("/dev/") || p == "/sp" || p.starts_with("/sp/") || p == "/certificate.pem" {
        "dev"
    } else if crate::faults::Endpoint::for_path(p) == Some(crate::faults::Endpoint::Metadata) {
        "metadata"
    } else {
        "flow"
    }
}

const MESSAGES: &[&str] = &["SAMLRequest", "SAMLResponse"];

/// Mask a parameter for display: SAML messages and signatures down to a prefix (the message is
/// decoded separately).
pub fn mask(key: &str, value: &str) -> String {
    if MESSAGES.contains(&key) || key == "Signature" {
        let n = value.chars().count();
        return if n <= 16 {
            value.into()
        } else {
            format!("{}… ({n} chars)", value.chars().take(16).collect::<String>())
        };
    }
    if key == "password" {
        return "•••".into();
    }
    if value.chars().count() > 300 {
        return format!("{}… ({} chars)", value.chars().take(300).collect::<String>(), value.chars().count());
    }
    value.to_string()
}

pub(crate) fn content_type(headers: &HeaderMap) -> String {
    headers.get(header::CONTENT_TYPE).and_then(|h| h.to_str().ok()).unwrap_or_default().to_ascii_lowercase()
}

/// Request parameters from the query and a form or JSON body.
pub(crate) fn request_params(query: &str, content_type: &str, body: &[u8]) -> BTreeMap<String, String> {
    let mut params: BTreeMap<String, String> = parse_form(query.as_bytes()).into_iter().collect();
    if body.len() > MAX_RECORDED_BODY {
        params.insert("(body)".into(), format!("{} bytes, not recorded", body.len()));
    } else if content_type.starts_with("application/x-www-form-urlencoded") {
        params.extend(parse_form(body));
    } else if content_type.contains("json")
        && let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(body)
    {
        params.extend(map.iter().map(|(k, v)| (k.clone(), value_to_string(v))));
    }
    params
}

/// Decode a message parameter for the record: (kind, issuer, status, indented XML).
pub fn describe_message(value: &str, redirect: bool) -> Option<(String, Option<String>, Option<Status>, String)> {
    let xml = decode_message(value, redirect).ok()?;
    let root = crate::xml::parse(&xml).ok();
    let kind = root.as_ref().map(|r| r.local.clone()).unwrap_or_else(|| "(unparseable)".into());
    let issuer = root.as_ref().and_then(|r| r.find(NS_ASSERTION, "Issuer")).map(|i| i.value());
    let status = root.as_ref().and_then(|r| r.find(NS_PROTOCOL, "Status")).map(|s| Status::from_element(Some(s)));
    let pretty = root.map(|r| r.to_pretty()).unwrap_or(xml);
    Some((kind, issuer, status, pretty))
}

/// Summary of an HTML or text response body.
fn body_outcome(content_type: &str, body: &[u8]) -> Option<String> {
    if content_type.starts_with("text/html") {
        // Pages are summarised by their title, e.g. "page: Sign in".
        let html = String::from_utf8_lossy(body);
        let title = html.split_once("<title>").and_then(|(_, rest)| rest.split_once("</title>")).map(|(t, _)| t);
        return title.map(|t| format!("page: {}", t.trim_end_matches(" · localsaml")));
    }
    if content_type.contains("xml") {
        return Some("XML document".into());
    }
    if content_type.starts_with("text/plain") || content_type.contains("json") {
        return Some(String::from_utf8_lossy(body).chars().take(200).collect());
    }
    None
}

/// Record every request (except [`ignored`] paths) into the inspector.
pub async fn record(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_string();
    if ignored(&path) {
        return next.run(request).await;
    }
    let started = Instant::now();
    let at = now_ms();
    let method = request.method().to_string();
    let query = request.uri().query().unwrap_or_default().to_string();
    let request_type = content_type(request.headers());

    let (parts, body) = request.into_parts();
    let Ok(body) = to_bytes(body, MAX_BODY).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let query_params = parse_form(query.as_bytes());
    let raw_params = request_params(&query, &request_type, &body);
    let soap_body = (crate::soap::is_soap(&parts.headers, &body) && body.len() <= MAX_RECORDED_BODY)
        .then(|| String::from_utf8_lossy(&body).into_owned());
    let response = next.run(Request::from_parts(parts, Body::from(body))).await;

    let (parts, body) = response.into_parts();
    let response_type = content_type(&parts.headers);
    let readable = ["text/plain", "text/html", "xml", "json"].iter().any(|t| response_type.contains(t));
    let (body, response_body): (Body, Option<Bytes>) = if readable {
        match to_bytes(body, MAX_BODY).await {
            Ok(bytes) => (Body::from(bytes.clone()), Some(bytes)),
            Err(_) => (Body::empty(), None),
        }
    } else {
        (body, None)
    };

    let (issuer, endpoint) = strip_issuer(&path);
    let mut messages = vec![];
    let mut sp = None;
    for key in MESSAGES {
        let Some(value) = raw_params.get(*key) else { continue };
        // A message in the query uses the Redirect binding (DEFLATE); in a form, the POST binding.
        let redirect = query_params.contains_key(*key);
        if let Some((kind, msg_issuer, status, xml)) = describe_message(value, redirect) {
            // Messages to the test SP come from the IdP; anything else is from a service provider.
            if !endpoint.starts_with("/sp") {
                sp = sp.or(msg_issuer);
            }
            messages.push(Message {
                direction: "received",
                kind,
                binding: if redirect { "redirect" } else { "post" },
                destination: None,
                status: status.map(|s| s.short()),
                xml: truncate_xml(xml),
            });
        }
    }
    if let Some(xml) = soap_body {
        match crate::soap::unwrap(&xml) {
            Ok((_, message)) => {
                if !endpoint.starts_with("/sp") {
                    sp = sp.or_else(|| message.find(NS_ASSERTION, "Issuer").map(|i| i.value()));
                }
                messages.push(Message {
                    direction: "received",
                    kind: message.local.clone(),
                    binding: "soap",
                    destination: None,
                    status: None,
                    xml: truncate_xml(crate::xml::pretty(&xml)),
                });
            }
            Err(_) => messages.push(Message {
                direction: "received",
                kind: "(not a SOAP envelope)".into(),
                binding: "soap",
                destination: None,
                status: None,
                xml: truncate_xml(xml),
            }),
        }
    }
    let note = parts.extensions.get::<SamlNote>().cloned().unwrap_or_default();
    sp = sp.or(note.sp.clone()).or_else(|| {
        // IdP-initiated links name the service provider in a parameter.
        ["sp", "spEntityID", "providerId", "PartnerSpId"].iter().find_map(|k| raw_params.get(*k).cloned())
    });
    let mut error = parts.extensions.get::<ErrorNote>().map(|n| (n.error.clone(), n.description.clone()));
    if error.is_none()
        && let Some(st) = &note.status
    {
        error = Some((st.short(), st.message.clone().unwrap_or_default()));
    }
    let mut summary = note
        .messages
        .iter()
        .map(|m| {
            let to = m.destination.as_deref().map(|d| format!(" → {}", strip_query(d))).unwrap_or_default();
            let st = m.status.as_deref().filter(|s| *s != "Success").map(|s| format!(" ({s})")).unwrap_or_default();
            format!("{}{to}{st}", m.kind)
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mut redirect = None;
    if let Some(location) = parts.headers.get(header::LOCATION).and_then(|h| h.to_str().ok()) {
        redirect = Some(strip_query(location));
        if summary.is_empty() {
            summary = format!("redirect to {}", strip_query(location));
        }
    }
    if summary.is_empty()
        && let Some(bytes) = &response_body
    {
        summary = body_outcome(&response_type, bytes).unwrap_or_default();
    }
    messages.extend(note.messages);

    let status = parts.status;
    let outcome = match (&error, summary.is_empty()) {
        (Some((code, _)), _) => code.clone(),
        (None, false) => summary,
        (None, true) => status.canonical_reason().unwrap_or("").to_string(),
    };
    state.inspector.record(Entry {
        id: 0,
        at,
        duration_ms: started.elapsed().as_millis() as u64,
        method,
        path: path.clone(),
        issuer: issuer.to_string(),
        endpoint: endpoint.to_string(),
        category: category(endpoint),
        sp,
        params: raw_params.iter().map(|(k, v)| (k.clone(), mask(k, v))).collect(),
        messages,
        status: status.as_u16(),
        error_description: error.as_ref().map(|(_, d)| d.clone()).filter(|d| !d.is_empty()),
        error: error.map(|(code, _)| code),
        outcome,
        redirect,
        outgoing: false,
    });
    Response::from_parts(parts, body)
}

fn truncate_xml(mut xml: String) -> String {
    if xml.len() > MAX_RECORDED_XML {
        let mut cut = MAX_RECORDED_XML;
        while !xml.is_char_boundary(cut) {
            cut -= 1;
        }
        xml.truncate(cut);
        xml.push_str("\n… (cut short)");
    }
    xml
}

fn strip_query(url: &str) -> String {
    url.split(['?', '#']).next().unwrap_or(url).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(sp: &str, status: u16) -> Entry {
        Entry {
            id: 0,
            at: 0,
            duration_ms: 0,
            method: "GET".into(),
            path: "/sso".into(),
            issuer: "root".into(),
            endpoint: "/sso".into(),
            category: "flow",
            sp: Some(sp.into()),
            params: BTreeMap::new(),
            messages: vec![],
            status,
            error: None,
            error_description: None,
            outcome: String::new(),
            redirect: None,
            outgoing: false,
        }
    }

    #[test]
    fn keeps_the_newest_entries_and_filters() {
        let inspector = Inspector::default();
        for i in 0..CAPACITY + 10 {
            inspector.record(entry(if i % 2 == 0 { "a" } else { "b" }, if i % 3 == 0 { 400 } else { 200 }));
        }
        let all = inspector.list(&Filter::default());
        assert_eq!(all.len(), CAPACITY);
        assert_eq!((all[0].id, all[CAPACITY - 1].id), (CAPACITY as u64 + 10, 11));
        let newer = inspector.list(&Filter { after: Some(CAPACITY as u64 + 7), ..Default::default() });
        assert_eq!(newer.iter().map(|e| e.id).collect::<Vec<_>>(), [510, 509, 508]);
        assert!(
            inspector
                .list(&Filter { sp: Some("a".into()), ..Default::default() })
                .iter()
                .all(|e| e.sp.as_deref() == Some("a"))
        );
        assert!(inspector.list(&Filter { errors_only: true, ..Default::default() }).iter().all(|e| e.status == 400));
        inspector.clear();
        assert!(inspector.list(&Filter::default()).is_empty());
    }

    #[test]
    fn masks_and_classifies() {
        assert!(mask("SAMLRequest", &"x".repeat(400)).ends_with("(400 chars)"));
        assert_eq!(mask("RelayState", "/home"), "/home");
        assert_eq!(strip_issuer("/p/okta/app/x/y/sso/saml"), ("okta", "/app/x/y/sso/saml"));
        assert_eq!(category("/metadata"), "metadata");
        assert_eq!(category("/idp/shibboleth"), "metadata");
        assert_eq!(category("/sp/acs"), "dev");
        assert_eq!(category("/sso"), "flow");
        assert!(ignored("/p/okta/dev/api/requests") && ignored("/assets/app.js") && !ignored("/dev/api/response"));
    }
}

//! Non-standard developer endpoints: the assertion generator page and the JSON API behind it,
//! plus service providers, the signing certificate, the clock, faults, sessions and the request
//! inspector.

use std::collections::HashMap;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::html::app_page;
use crate::keys::SigAlg;
use crate::presets::{self, Preset};
use crate::routes::sso::{delivery, finish_name_id_for};
use crate::saml::{self, ResponseSpec, Status, Tamper};
use crate::sp::{ServiceProvider, from_metadata};
use crate::state::{AppState, Session};
use crate::store::Table;
use crate::tenant::Tenant;
use crate::util::b64_std;
use crate::xmlenc::EncAlg;

fn no_store() -> [(header::HeaderName, &'static str); 1] {
    [(header::CACHE_CONTROL, "no-store")]
}

/// A JSON error: `{"error": "...", "error_description": "..."}`.
fn api_error(status: StatusCode, error: &str, description: impl Into<String>) -> Response {
    let description = description.into();
    let mut resp =
        (status, no_store(), Json(json!({ "error": error, "error_description": description }))).into_response();
    crate::inspector::ErrorNote::attach(&mut resp, error, description);
    resp
}

fn invalid(description: impl Into<String>) -> Response {
    api_error(StatusCode::BAD_REQUEST, "invalid_request", description)
}

// ---------------------------------------------------------------------------
// Minting responses
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MintRequest {
    /// Declared user (`[[users]]`) whose identity `attributes` are merged over.
    pub user: Option<String>,
    /// Template whose attribute names, style and signing behaviour are used.
    pub preset: Option<String>,
    /// Service provider entity ID (default: the built-in test SP).
    pub sp: Option<String>,
    /// Default: the service provider's default ACS URL.
    pub acs_url: Option<String>,
    /// Default: the service provider's entity ID.
    pub audience: Option<String>,
    pub in_response_to: Option<String>,
    pub relay_state: Option<String>,
    /// `artifact`: also store the Response for the HTTP-Artifact binding, and return an artifact
    /// the service provider resolves at the ArtifactResolutionService (once, within 5 minutes).
    pub binding: Option<String>,
    pub name_id: Option<String>,
    pub name_id_format: Option<String>,
    /// Merged over the template defaults; `null` removes one.
    pub attributes: Map<String, Value>,
    /// Merge `attributes` over the template defaults (default true).
    pub defaults: Option<bool>,
    pub sign_response: Option<bool>,
    pub sign_assertion: Option<bool>,
    pub signature_algorithm: Option<SigAlg>,
    /// Encrypt the assertion for the service provider's certificate (default: its setting).
    pub encrypt: Option<bool>,
    pub encryption_algorithm: Option<EncAlg>,
    /// Send the NameID as an `EncryptedID` (default: the service provider's setting).
    pub encrypt_name_id: Option<bool>,
    /// Send attributes as `EncryptedAttribute`s (default: the service provider's setting).
    pub encrypt_attributes: Option<bool>,
    /// Assertion lifetime in seconds.
    pub expires_in: Option<i64>,
    pub authn_context: Option<String>,
    pub session_index: Option<String>,
    /// Deliberate defects (see `/dev/api/faults`).
    pub tamper: Vec<Tamper>,
    /// A non-success status: the Response has no assertion.
    pub status: Option<String>,
    pub status_message: Option<String>,
}

#[allow(clippy::result_large_err)]
pub async fn mint(state: &AppState, tenant: &Tenant, req: MintRequest) -> Result<Value, Response> {
    let explicit = match &req.preset {
        Some(id) => Some(presets::get(id).ok_or_else(|| invalid(format!("unknown preset '{id}'")))?),
        None => None,
    };
    let sp = match &req.sp {
        Some(entity) => crate::routes::sso::resolve_sp(state, tenant, entity).await.map_err(invalid)?,
        None => crate::routes::testsp::service_provider(state, tenant),
    };
    let fallback = match (tenant.preset, &sp.preset) {
        (None, Some(p)) => presets::get_or_generic(p),
        _ => tenant.default_preset(&state.config),
    };
    let (preset, mut identity) = match &req.user {
        Some(id) => {
            state.config.user(id).ok_or_else(|| invalid(format!("unknown user '{id}'")))?.resolve(explicit, fallback)
        }
        None => {
            let preset = explicit.unwrap_or(fallback);
            let mut identity = preset.default_identity();
            if req.defaults == Some(false) {
                // No template attributes, so nothing for the NameID to follow: it's derived from
                // the given attributes (or generated) instead.
                identity.attributes.clear();
                identity.name_id.clear();
            }
            (preset, identity)
        }
    };
    for (name, value) in &req.attributes {
        let ok = matches!(value, Value::String(_) | Value::Null)
            || value.as_array().is_some_and(|a| a.iter().all(Value::is_string));
        if !ok {
            return Err(invalid(format!("attribute '{name}' must be a string, a list of strings, or null")));
        }
    }
    preset.apply_overrides(&mut identity, &req.attributes);
    if let Some(format) = &req.name_id_format
        && *format != identity.name_id_format
    {
        identity.name_id_format = format.clone();
        if req.name_id.is_none() {
            identity.name_id = match format.as_str() {
                presets::nameid::EMAIL => {
                    preset.email_attribute.and_then(|a| identity.values(a).into_iter().next()).unwrap_or_default()
                }
                presets::nameid::PERSISTENT | presets::nameid::TRANSIENT => String::new(),
                _ => identity.name_id.clone(),
            };
        }
    }
    if let Some(n) = &req.name_id {
        identity.name_id = n.clone();
    }
    let session_index = req.session_index.clone().unwrap_or_else(|| preset.style.id_style.generate());
    finish_name_id_for(&mut identity, preset, &sp.entity_id, &session_index);

    let acs_url = req
        .acs_url
        .clone()
        .or_else(|| sp.default_acs("post").cloned())
        .ok_or_else(|| invalid(format!("{} has no ACS URL; pass acs_url", sp.label())))?;
    if !crate::util::is_web_url(&acs_url) {
        return Err(invalid(format!("acs_url '{acs_url}' is not an absolute http(s) URL")));
    }
    let mut d = delivery(state, preset, &sp).map_err(invalid)?;
    if let Some(v) = req.sign_response {
        d.sign_response = v;
    }
    if let Some(v) = req.sign_assertion {
        d.sign_assertion = v;
    }
    if let Some(a) = req.signature_algorithm {
        d.sig_alg = a;
    }
    match req.encrypt {
        Some(false) => d.encrypt = None,
        Some(true) => match sp.encryption_key() {
            Some(Ok(key)) => {
                d.encrypt =
                    Some((key, req.encryption_algorithm.or(sp.encryption_algorithm).unwrap_or(preset.encryption)))
            }
            Some(Err(e)) => return Err(invalid(format!("can't encrypt for {}: {e}", sp.label()))),
            None => return Err(invalid(format!("{} has no encryption certificate to encrypt for", sp.label()))),
        },
        None => {
            if let (Some((_, alg)), Some(chosen)) = (&mut d.encrypt, req.encryption_algorithm) {
                *alg = chosen;
            }
        }
    }
    let status = match &req.status {
        Some(s) => Some(Status::parse(s, req.status_message.clone()).map_err(invalid)?),
        None => None,
    };
    let now = state.now();
    let artifact = match req.binding.as_deref() {
        None | Some("post") => false,
        Some("artifact") => true,
        Some(b) => return Err(invalid(format!("binding must be 'post' or 'artifact', not '{b}'"))),
    };
    // An artifact is resolved confidentially, or its assertion is encrypted (Profiles 4.1.4.4).
    if artifact {
        crate::routes::sso::spec_delivery(state, tenant, preset, &sp, "artifact", &mut d).map_err(invalid)?;
    }
    let spec = ResponseSpec {
        preset,
        issuer: tenant.entity_id.clone(),
        identity: &identity,
        destination: acs_url.clone(),
        audience: req.audience.clone().unwrap_or_else(|| sp.audience()),
        in_response_to: req.in_response_to.clone().filter(|v| !v.is_empty()),
        session_index,
        assertion_id: None,
        auth_time: now,
        now,
        sign_response: d.sign_response,
        sign_assertion: d.sign_assertion,
        sig_alg: d.sig_alg,
        encrypt: d.encrypt.clone(),
        encrypt_name_id: match req.encrypt_name_id {
            Some(true) => Some(crate::routes::sso::name_id_encryption(preset, &sp).map_err(invalid)?),
            Some(false) => None,
            None => d.encrypt_name_id.clone(),
        },
        encrypt_attributes: match req.encrypt_attributes {
            Some(true) => Some(crate::routes::sso::name_id_encryption(preset, &sp).map_err(invalid)?),
            Some(false) => None,
            None => d.encrypt_attributes.clone(),
        },
        lifetime: req.expires_in.or(state.config.assertion_ttl),
        authn_context: req.authn_context.clone().unwrap_or_else(|| preset.authn_context.into()),
        sp_name_qualifier: None,
        status,
        tampers: req.tamper.clone(),
        attribute_query: false,
    };
    let issued = state
        .keys
        .with_current(|key| saml::build_response(key, &spec))
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", e))?;
    let encoded = b64_std(&issued.xml);
    let relay = req.relay_state.clone().filter(|r| !r.is_empty());
    let mut curl = format!("curl -s -X POST '{acs_url}' --data-urlencode 'SAMLResponse={encoded}'");
    if let Some(r) = &relay {
        curl.push_str(&format!(" --data-urlencode 'RelayState={}'", r.replace('\'', "'\\''")));
    }
    let artifact = artifact.then(|| {
        let artifact = crate::routes::sso::store_artifact(state, tenant, &sp.entity_id, &issued.xml);
        let mut url = url::Url::parse(&acs_url).expect("the ACS URL was checked");
        url.query_pairs_mut().append_pair("SAMLart", &artifact);
        if let Some(r) = &relay {
            url.query_pairs_mut().append_pair("RelayState", r);
        }
        json!({ "artifact": artifact, "url": url.as_str(), "resolution_url": tenant.url("/artifact") })
    });
    Ok(json!({
        "saml_response": encoded,
        "artifact": artifact,
        "acs_url": acs_url,
        "relay_state": relay,
        "issuer": tenant.entity_id,
        "sp": sp.entity_id,
        "preset": preset.id,
        "name_id": identity.name_id,
        "name_id_format": identity.name_id_format,
        "attributes": identity.attributes,
        "response_id": issued.response_id,
        "assertion_id": issued.assertion_id,
        "signed": { "response": d.sign_response && !req.tamper.contains(&Tamper::Unsigned), "assertion": d.sign_assertion && !req.tamper.contains(&Tamper::Unsigned) },
        "encrypted": issued.encrypted,
        "name_id_encrypted": spec.encrypt_name_id.is_some(),
        "attributes_encrypted": spec.encrypt_attributes.is_some(),
        "xml": issued.xml,
        "pretty": issued.pretty,
        "curl": curl,
    }))
}

fn mint_response(result: Result<Value, Response>, format: Option<&str>) -> Response {
    match (result, format) {
        (Ok(v), Some("base64")) => {
            (no_store(), v["saml_response"].as_str().unwrap_or_default().to_string()).into_response()
        }
        (Ok(v), Some("xml")) => {
            ([(header::CONTENT_TYPE, "application/xml")], v["xml"].as_str().unwrap_or_default().to_string())
                .into_response()
        }
        (Ok(v), _) => (no_store(), Json(v)).into_response(),
        (Err(e), _) => e,
    }
}

pub async fn api_response_post(
    State(state): State<AppState>,
    tenant: Tenant,
    Query(q): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    let req: MintRequest = if body.iter().all(u8::is_ascii_whitespace) {
        MintRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => return invalid(format!("invalid JSON body: {e}")),
        }
    };
    mint_response(mint(&state, &tenant, req).await, q.get("format").map(String::as_str))
}

/// GET variant for quick curl use: known keys are options, every other query parameter becomes
/// an attribute (`a,b` stays one value; pass a JSON array for several).
pub async fn api_response_get(State(state): State<AppState>, tenant: Tenant, RawQuery(q): RawQuery) -> Response {
    let mut req = MintRequest::default();
    let mut format = None;
    for (k, v) in url::form_urlencoded::parse(q.unwrap_or_default().as_bytes()).into_owned() {
        let yes = v != "false" && v != "0";
        match k.as_str() {
            "user" => req.user = Some(v),
            "preset" => req.preset = Some(v),
            "sp" => req.sp = Some(v),
            "acs_url" => req.acs_url = Some(v),
            "audience" => req.audience = Some(v),
            "in_response_to" => req.in_response_to = Some(v),
            "relay_state" | "RelayState" => req.relay_state = Some(v),
            "binding" => req.binding = Some(v),
            "name_id" => req.name_id = Some(v),
            "name_id_format" => req.name_id_format = Some(v),
            "defaults" => req.defaults = Some(yes),
            "sign_response" => req.sign_response = Some(yes),
            "sign_assertion" => req.sign_assertion = Some(yes),
            "encrypt" => req.encrypt = Some(yes),
            "encrypt_name_id" => req.encrypt_name_id = Some(yes),
            "encrypt_attributes" => req.encrypt_attributes = Some(yes),
            "expires_in" => req.expires_in = v.parse().ok(),
            "authn_context" => req.authn_context = Some(v),
            "status" => req.status = Some(v),
            "status_message" => req.status_message = Some(v),
            "format" => format = Some(v),
            "signature_algorithm" => match serde_json::from_value(Value::String(v.clone())) {
                Ok(a) => req.signature_algorithm = Some(a),
                Err(_) => return invalid(format!("unknown signature_algorithm '{v}'")),
            },
            "encryption_algorithm" => match serde_json::from_value(Value::String(v.clone())) {
                Ok(a) => req.encryption_algorithm = Some(a),
                Err(_) => return invalid(format!("unknown encryption_algorithm '{v}'")),
            },
            "tamper" => {
                for name in v.split(',').filter(|n| !n.is_empty()) {
                    match Tamper::parse(name) {
                        Some(t) => req.tamper.push(t),
                        None => return invalid(format!("unknown tamper '{name}'")),
                    }
                }
            }
            _ => {
                let value = match serde_json::from_str::<Value>(&v) {
                    Ok(Value::Array(items)) if items.iter().all(Value::is_string) => Value::Array(items),
                    _ => Value::String(v),
                };
                req.attributes.insert(k, value);
            }
        }
    }
    mint_response(mint(&state, &tenant, req).await, format.as_deref())
}

pub async fn api_presets() -> impl IntoResponse {
    Json(presets::all())
}

/// The declared users, with their identities as this issuer would issue them.
pub async fn api_users(State(state): State<AppState>, tenant: Tenant) -> impl IntoResponse {
    let fallback = tenant.default_preset(&state.config);
    Json(state.config.users.iter().map(|u| u.to_json(fallback)).collect::<Vec<_>>())
}

// ---------------------------------------------------------------------------
// Service providers
// ---------------------------------------------------------------------------

pub async fn api_sps(State(state): State<AppState>, tenant: Tenant) -> Response {
    let mut all = vec![crate::routes::testsp::service_provider(&state, &tenant)];
    all.extend(state.service_providers());
    (no_store(), Json(all)).into_response()
}

/// Register a service provider: JSON settings (like a `[[service_providers]]` entry), or its
/// metadata XML as the body.
pub async fn api_sps_add(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let text = String::from_utf8_lossy(&body).to_string();
    let content_type = crate::inspector::content_type(&headers);
    let mut sp = if content_type.contains("xml") || text.trim_start().starts_with('<') {
        match from_metadata(&text, None) {
            Ok(sp) => sp,
            Err(e) => return invalid(e),
        }
    } else {
        match serde_json::from_str::<ServiceProvider>(&text) {
            Ok(sp) => sp,
            Err(e) => return invalid(format!("invalid service provider: {e}")),
        }
    };
    if let Err(e) = sp.load_local_metadata() {
        return invalid(format!("{e:#}"));
    }
    if sp.metadata_url.is_some()
        && let Err(e) = sp.load_remote_metadata().await
    {
        return invalid(e);
    }
    if let Err(e) = sp.validate() {
        return invalid(format!("{e:#}"));
    }
    if state.config.service_providers.iter().any(|d| d.entity_id == sp.entity_id) {
        return invalid(format!("'{}' is declared in the config file, which wins; change it there", sp.entity_id));
    }
    sp.source = "api".into();
    sp.metadata = None;
    state.register_service_provider(&sp);
    tracing::info!("registered service provider {}", sp.entity_id);
    (StatusCode::CREATED, no_store(), Json(sp)).into_response()
}

pub async fn api_sps_remove(State(state): State<AppState>, Query(q): Query<HashMap<String, String>>) -> Response {
    match q.get("entity_id") {
        Some(id) if state.store.remove(Table::ServiceProviders, id) => StatusCode::NO_CONTENT.into_response(),
        Some(id) => api_error(StatusCode::NOT_FOUND, "not_found", format!("no registered service provider '{id}'")),
        None => {
            state.store.clear(Table::ServiceProviders);
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Certificate and keys
// ---------------------------------------------------------------------------

pub async fn api_certificate(State(state): State<AppState>, tenant: Tenant) -> Response {
    let infos = state.keys.infos();
    (
        no_store(),
        Json(json!({
            "current": infos.first(),
            "retired": &infos[1.min(infos.len())..],
            "metadata_url": tenant.metadata_url(),
        })),
    )
        .into_response()
}

/// Non-standard: rotate the signing key (shared by every issuer). The previous certificates stay
/// in the metadata.
pub async fn api_rotate_keys(State(state): State<AppState>, tenant: Tenant) -> Response {
    let keys = state.keys.clone();
    match tokio::task::spawn_blocking(move || keys.rotate()).await {
        Ok(Ok(rotation)) => (
            no_store(),
            Json(json!({
                "kid": rotation.kid,
                "retired_kids": rotation.retired_kids,
                "certificate": state.keys.current_info(),
                "metadata_url": tenant.metadata_url(),
            })),
        )
            .into_response(),
        Ok(Err(e)) => {
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", format!("key rotation failed: {e:#}"))
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", format!("key rotation panicked: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// A duration as seconds (`3600`) or text (`"1h"`, `"31d"`, `"-5m"`).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum DurationValue {
    Seconds(i64),
    Text(String),
}

impl DurationValue {
    fn seconds(&self) -> Result<i64, String> {
        match self {
            DurationValue::Seconds(s) => Ok(*s),
            DurationValue::Text(t) => crate::util::parse_duration(t),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClockRequest {
    /// Set the offset from real time.
    pub offset: Option<DurationValue>,
    /// Move the clock by this much (negative moves it back).
    pub advance: Option<DurationValue>,
    /// Go back to real time.
    pub reset: bool,
}

/// Offsets beyond this are almost certainly typos, and would overflow timestamp arithmetic.
const MAX_CLOCK_OFFSET: i64 = 100 * 365 * 86_400;

fn clock_json(state: &AppState) -> Value {
    let offset = state.clock().offset();
    json!({
        "now": state.now(),
        "offset": offset,
        "offset_text": crate::util::format_duration(offset),
        "real_now": crate::util::wall_clock(),
    })
}

pub async fn api_clock(State(state): State<AppState>) -> Response {
    (no_store(), Json(clock_json(&state))).into_response()
}

pub async fn api_clock_set(State(state): State<AppState>, Json(req): Json<ClockRequest>) -> Response {
    let parse = |v: &DurationValue, field: &str| v.seconds().map_err(|e| format!("{field}: {e}"));
    let target = match (&req.offset, &req.advance, req.reset) {
        (Some(v), None, false) => parse(v, "offset"),
        (None, Some(v), false) => parse(v, "advance").map(|by| state.clock().offset().saturating_add(by)),
        (None, None, true) => Ok(0),
        _ => Err("send exactly one of offset, advance or reset".into()),
    };
    let offset = match target {
        Ok(o) if o.abs() <= MAX_CLOCK_OFFSET => o,
        Ok(_) => return invalid("clock offset must be within 100 years of real time"),
        Err(e) => return invalid(e),
    };
    state.clock().set_offset(offset);
    tracing::info!("clock offset set to {}", crate::util::format_duration(offset));
    (no_store(), Json(clock_json(&state))).into_response()
}

// ---------------------------------------------------------------------------
// Request inspector
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RequestsQuery {
    pub sp: Option<String>,
    pub errors: Option<bool>,
    pub after: Option<u64>,
    pub limit: Option<usize>,
}

pub async fn api_requests(State(state): State<AppState>, Query(q): Query<RequestsQuery>) -> Response {
    let filter = crate::inspector::Filter {
        sp: q.sp.filter(|c| !c.is_empty()),
        errors_only: q.errors.unwrap_or(false),
        after: q.after,
        limit: q.limit,
    };
    let body = json!({
        "entries": state.inspector.list(&filter),
        // Lets a poller notice a restart: ids start again from 1.
        "latest_id": state.inspector.latest_id(),
        "capacity": crate::inspector::CAPACITY,
    });
    (no_store(), Json(body)).into_response()
}

pub async fn api_requests_clear(State(state): State<AppState>) -> StatusCode {
    state.inspector.clear();
    StatusCode::NO_CONTENT
}

/// The request inspector's page.
pub async fn requests_page(tenant: Tenant) -> Response {
    app_page(&tenant, "Requests")
}

// ---------------------------------------------------------------------------
// Faults
// ---------------------------------------------------------------------------

pub async fn api_faults(State(state): State<AppState>) -> Response {
    let faults: Vec<Value> = state
        .faults
        .list()
        .iter()
        .map(|f| {
            let mut v = json!(f);
            // What it does, in a few words, for people reading the list.
            v["summary"] = json!(f.summary());
            v
        })
        .collect();
    (no_store(), Json(faults)).into_response()
}

pub async fn api_faults_add(State(state): State<AppState>, Json(req): Json<crate::faults::FaultRequest>) -> Response {
    match crate::faults::Fault::from_request(req) {
        Ok(fault) => {
            let fault = state.faults.add(fault);
            tracing::info!("fault {} armed for {:?}: {}", fault.id, fault.endpoint, fault.summary());
            (StatusCode::CREATED, no_store(), Json(fault)).into_response()
        }
        Err(e) => invalid(e),
    }
}

pub async fn api_faults_remove(State(state): State<AppState>, Path(params): Path<HashMap<String, String>>) -> Response {
    let removed = params.get("id").and_then(|id| id.parse().ok()).is_some_and(|id| state.faults.remove(id));
    if removed { StatusCode::NO_CONTENT.into_response() } else { StatusCode::NOT_FOUND.into_response() }
}

pub async fn api_faults_clear(State(state): State<AppState>) -> StatusCode {
    state.faults.clear();
    StatusCode::NO_CONTENT
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

pub async fn api_sessions(State(state): State<AppState>, tenant: Tenant) -> Response {
    let sessions: Vec<Value> = state
        .store
        .entries::<Session>(Table::Sessions)
        .iter()
        .map(|(sid, session, exp)| {
            let mut v = crate::routes::slo::describe(sid, session, *exp);
            v["logout_url"] = json!(format!("{}?sid={sid}", tenant.url("/slo/initiate")));
            v
        })
        .collect();
    (no_store(), Json(sessions)).into_response()
}

/// End a session as if the user logged out elsewhere: service providers with a SOAP
/// SingleLogoutService are logged out back-channel; others can only be reached through the
/// browser (send it to the session's `logout_url` for that).
pub async fn api_sessions_end(State(state): State<AppState>, Path(params): Path<HashMap<String, String>>) -> Response {
    let sid = params.get("sid").cloned().unwrap_or_default();
    let Some(session) = state.store.take::<Session>(Table::Sessions, &sid) else {
        return api_error(StatusCode::NOT_FOUND, "not_found", format!("no active session '{sid}'"));
    };
    let tenant = Tenant::new(&state.config.base_url, presets::get(&session.tenant), &state.config);
    let results = crate::routes::slo::back_channel_all(&state, &tenant, &session, None).await;
    let deliveries: Vec<Value> = results
        .iter()
        .filter(|(_, outcome)| !outcome.starts_with("not notified"))
        .map(|(sp, outcome)| json!({ "sp": sp, "outcome": outcome, "ok": outcome.starts_with("logged out") }))
        .collect();
    let not_notified: Vec<&String> =
        results.iter().filter(|(_, outcome)| outcome.starts_with("not notified")).map(|(sp, _)| sp).collect();
    (no_store(), Json(json!({ "sid": sid, "deliveries": deliveries, "not_notified": not_notified }))).into_response()
}

// ---------------------------------------------------------------------------
// The page
// ---------------------------------------------------------------------------

const FAULT_STATUSES: &[&str] = &[
    "AuthnFailed",
    "NoPassive",
    "RequestDenied",
    "UnknownPrincipal",
    "NoAuthnContext",
    "InvalidNameIDPolicy",
    "RequestUnsupported",
    "UnsupportedBinding",
    "Responder",
    "Requester",
    "PartialLogout",
];

/// Non-standard: what the web UI shows about this identity provider: its endpoints, the other
/// issuers, its certificate, the clock and the armed faults (for the warning banners), and the
/// assertion generator's choices.
pub async fn api_info(State(state): State<AppState>, tenant: Tenant) -> Response {
    let u = |p: &str| tenant.url(p);
    let mut endpoints = vec![
        ("Metadata", tenant.metadata_url()),
        ("Entity ID", tenant.entity_id.clone()),
        ("SSO (Redirect and POST bindings; SOAP for ECP)", tenant.sso_url()),
    ];
    if let Some(slo) = tenant.slo_url() {
        endpoints.push(("Single logout (Redirect, POST and SOAP bindings)", slo));
    }
    endpoints.push(("Artifact resolution (SOAP)", u("/artifact")));
    endpoints.push(("Attribute queries (SOAP)", u("/attribute")));
    endpoints.push(("IdP-initiated SSO (non-standard)", format!("{}?sp=<entity ID>", u("/sso/initiate"))));
    endpoints.push(("Signing certificate (PEM)", u("/certificate.pem")));
    endpoints.push(("Response API (non-standard)", u("/dev/api/response")));
    if let Some(p) = tenant.preset {
        for e in &p.endpoints {
            endpoints.push((e.label, u(e.path)));
        }
        if tenant.sso_url() != u("/sso") {
            endpoints.push(("SSO (generic path)", u("/sso")));
        }
    }
    let root = Tenant::new(&state.config.base_url, None, &state.config);
    let mut issuers = vec![json!({
        "id": null,
        "name": "Root issuer",
        "description": "template chosen at login",
        "entity_id": root.entity_id,
        "prefix": root.prefix,
    })];
    for p in presets::all() {
        let t = Tenant::new(&state.config.base_url, Some(p), &state.config);
        issuers.push(json!({
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "color": p.color,
            "entity_id": t.entity_id,
            "prefix": t.prefix,
        }));
    }
    let preset: &'static Preset = tenant.default_preset(&state.config);
    let body = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "entity_id": tenant.entity_id,
        "prefix": tenant.prefix,
        "metadata_url": tenant.metadata_url(),
        "preset": tenant.preset.map(|p| json!({ "id": p.id, "name": p.name, "color": p.color })),
        "default_preset": preset.id,
        "lenient": state.config.lenient,
        "clock": clock_json(&state),
        "faults_armed": state.faults.list().len(),
        "certificate": state.keys.current_info(),
        "retired_keys_kept": crate::keys::RETIRED_KEYS_KEPT,
        "endpoints": endpoints.iter().map(|(label, url)| json!({ "label": label, "url": url })).collect::<Vec<_>>(),
        "issuers": issuers,
        "test_sp": crate::routes::testsp::entity_id(&tenant),
        "name_id_formats": crate::presets::nameid::ALL,
        "assertion_lifetime": state.config.assertion_ttl.unwrap_or(preset.assertion_lifetime),
        "signature_algorithm": state.config.signature_algorithm.name(),
        "fault_statuses": FAULT_STATUSES,
        "tampers": Tamper::ALL.iter().map(|t| json!({ "name": t.name(), "description": t.describe() })).collect::<Vec<_>>(),
        "max_fault_delay_ms": crate::faults::MAX_DELAY_MS,
        "requests_capacity": crate::inspector::CAPACITY,
    });
    (no_store(), Json(body)).into_response()
}

/// The assertion generator's page.
pub async fn page_handler(tenant: Tenant) -> Response {
    app_page(&tenant, "Assertion generator")
}

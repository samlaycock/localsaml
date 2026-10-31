//! A built-in service provider, so logins can be tried without an app: it starts SP-initiated
//! logins (either binding, signed or not), validates the Response the way a strict SP would and
//! shows what it found, and does SP-initiated single logout.
//!
//! It checks timestamps against real time, like any other app, so a shifted localsaml clock
//! shows up as an expired or not-yet-valid assertion.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};

use crate::dsig::{self, NS_DS, QuerySignature};
use crate::html::{esc, page, saml_post, xml_block};
use crate::presets::{authn, nameid};
use crate::routes::sso::{cookie_value, set_cookie};
use crate::saml::{
    self, BINDING_ARTIFACT, BINDING_POST, BINDING_REDIRECT, Message, NS_ASSERTION, NS_MD, NS_PROTOCOL, Status,
};
use crate::sp::ServiceProvider;
use crate::state::AppState;
use crate::tenant::Tenant;
use crate::util::{b64, b64_decode, b64_std, iso8601, non_empty, parse_form, parse_iso8601, wall_clock};
use crate::xml::{Element, parse};
use crate::xmlenc::{self, EncAlg, NS_XENC};

/// Clock skew the test SP allows, in seconds.
const SKEW: i64 = 60;

pub fn entity_id(tenant: &Tenant) -> String {
    tenant.url("/sp")
}

/// The test SP as the IdP sees it. It shares the IdP's key pair, so its signed requests verify
/// and it can decrypt encrypted assertions.
pub fn service_provider(state: &AppState, tenant: &Tenant) -> ServiceProvider {
    ServiceProvider {
        entity_id: entity_id(tenant),
        name: Some("localsaml test SP".into()),
        acs_urls: vec![tenant.url("/sp/acs")],
        acs_artifact_urls: vec![tenant.url("/sp/acs")],
        slo_url: Some(tenant.url("/sp/slo")),
        certificate: Some(state.keys.with_current(|k| k.cert_b64())),
        source: "builtin".into(),
        ..Default::default()
    }
}

/// The test SP's own session, kept in a cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpSession {
    name_id: String,
    format: String,
    #[serde(default)]
    sp_name_qualifier: Option<String>,
    session_index: Option<String>,
    issuer: String,
    /// The NameID came as an EncryptedID; the LogoutRequest encrypts it too.
    #[serde(default)]
    encrypted: bool,
}

fn session_cookie_name(tenant: &Tenant) -> String {
    format!("localsaml_testsp_{}", tenant.key())
}

fn request_cookie_name(tenant: &Tenant) -> String {
    format!("localsaml_testsp_req_{}", tenant.key())
}

fn cookie(name: &str, value: &str, max_age: i64) -> String {
    format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}")
}

fn sp_session(tenant: &Tenant, headers: &HeaderMap) -> Option<SpSession> {
    let raw = cookie_value(headers, &session_cookie_name(tenant))?;
    serde_json::from_slice(&b64_decode(&raw)?).ok()
}

fn options<'a>(items: impl IntoIterator<Item = &'a str>, selected: &str) -> String {
    items
        .into_iter()
        .map(|v| {
            // urn:…:emailAddress → emailAddress; http://…/multipleauthn → multipleauthn
            let label = if v.starts_with("urn:") { v.rsplit(':').next() } else { v.rsplit('/').next() }.unwrap_or(v);
            let sel = if v == selected { " selected" } else { "" };
            format!(r#"<option value="{}"{sel}>{}</option>"#, esc(v), esc(if v.is_empty() { "(none)" } else { label }))
        })
        .collect()
}

pub async fn home(tenant: Tenant, headers: HeaderMap) -> Response {
    let session = sp_session(&tenant, &headers);
    let signed_in = match &session {
        Some(s) => format!(
            r#"<section class="card"><div class="eyebrow">Signed in</div><h2>As <span class="accent">{}</span></h2>
<p class="muted">NameID format <code>{}</code>{}</p>
<form method="post" action="{}" class="actions"><button class="btn" type="submit">Sign out (SP-initiated logout)</button></form></section>"#,
            esc(&s.name_id),
            esc(&s.format),
            s.session_index.as_ref().map(|i| format!(", SessionIndex <code>{}</code>", esc(i))).unwrap_or_default(),
            esc(&tenant.path("/sp/logout")),
        ),
        None => String::new(),
    };
    let body = format!(
        r#"<section class="card hero">
  <div class="eyebrow">Built-in service provider</div>
  <h1>Test SP for <span class="accent">{entity}</span></h1>
  <p class="muted">Try logins without an app. This service provider validates the Response the way a strict one would (signatures, decryption, audience, recipient, timestamps against real time, InResponseTo, replays) and shows what it found. Its entity ID is <code>{sp}</code>; its <a href="{metadata}">metadata</a> declares the ACS <code>{acs}</code>.</p>
</section>
{signed_in}
<form class="card" method="get" action="{login}">
  <h2>SP-initiated login</h2>
  <div class="opts">
    <label>Binding<select name="binding"><option value="redirect">HTTP-Redirect</option><option value="post">HTTP-POST</option></select></label>
    <label>Response binding<select name="response_binding"><option value="post">HTTP-POST</option><option value="artifact">HTTP-Artifact</option></select></label>
    <label>NameIDPolicy format<select name="name_id_format">{formats}</select></label>
    <label>Requested AuthnContext<select name="authn_context">{contexts}</select></label>
    <label>RelayState<input name="RelayState" value="/welcome"></label>
    <div class="checks">
      <label class="check"><input type="checkbox" name="sign" value="1" checked> Sign the request</label>
      <label class="check"><input type="checkbox" name="force_authn" value="1"> ForceAuthn</label>
      <label class="check"><input type="checkbox" name="is_passive" value="1"> IsPassive</label>
      <label class="check"><input type="checkbox" name="encrypt_name_id" value="1"> Encrypted NameID</label>
    </div>
  </div>
  <div class="actions">
    <button class="btn primary" type="submit">Start login</button>
    <a class="btn ghost" href="{initiate}">IdP-initiated login instead</a>
  </div>
</form>"#,
        entity = esc(&tenant.entity_id),
        sp = esc(&entity_id(&tenant)),
        metadata = esc(&tenant.path("/sp/metadata")),
        acs = esc(&tenant.url("/sp/acs")),
        login = esc(&tenant.path("/sp/login")),
        formats = options(std::iter::once("").chain(nameid::ALL.iter().copied()), ""),
        contexts = options(std::iter::once("").chain(authn::ALL.iter().copied()), ""),
        initiate = esc(&format!(
            "{}?sp={}&RelayState=%2Fwelcome",
            tenant.path("/sso/initiate"),
            dsig::urlencode(&entity_id(&tenant))
        )),
    );
    page(&tenant, "Test SP", &body).into_response()
}

/// Build an AuthnRequest and send it to the IdP's SSO URL (the one its metadata advertises).
pub async fn login(State(state): State<AppState>, tenant: Tenant, RawQuery(q): RawQuery, body: Bytes) -> Response {
    let params = crate::util::merged_params(q.as_deref(), &body);
    let flag = |k: &str| params.get(k).is_some_and(|v| v == "1" || v == "true");
    let style = &tenant.default_preset(&state.config).style;
    let p = |local: &str| Element::new(NS_PROTOCOL, "samlp", local);
    let a = |local: &str| Element::new(NS_ASSERTION, "saml", local);
    let id = crate::util::saml_id("_sp");
    let sso = tenant.sso_url();
    let mut req = p("AuthnRequest")
        .attr("ID", &id)
        .attr("Version", "2.0")
        .attr("IssueInstant", iso8601(wall_clock()))
        .attr("Destination", &sso)
        .attr("AssertionConsumerServiceURL", tenant.url("/sp/acs"))
        .attr(
            "ProtocolBinding",
            if params.get("response_binding").map(String::as_str) == Some("artifact") {
                BINDING_ARTIFACT
            } else {
                BINDING_POST
            },
        )
        .attr_opt("ForceAuthn", flag("force_authn").then_some("true"))
        .attr_opt("IsPassive", flag("is_passive").then_some("true"))
        .declare("samlp", NS_PROTOCOL)
        .declare("saml", NS_ASSERTION)
        .child(a("Issuer").text(entity_id(&tenant)));
    // NameIDPolicy has one Format: asking for an encrypted NameID replaces the format.
    let format = if flag("encrypt_name_id") {
        Some(nameid::ENCRYPTED.to_string())
    } else {
        non_empty(&params, "name_id_format")
    };
    if let Some(f) = format {
        req = req.child(p("NameIDPolicy").attr("Format", f).attr("AllowCreate", "true"));
    }
    if let Some(c) = non_empty(&params, "authn_context") {
        req =
            req.child(p("RequestedAuthnContext").attr("Comparison", "exact").child(a("AuthnContextClassRef").text(c)));
    }
    req.declare_namespaces();
    let relay = non_empty(&params, "RelayState");
    let alg = state.config.signature_algorithm;
    let mut resp = if params.get("binding").map(String::as_str) == Some("post") {
        if flag("sign")
            && let Err(e) = state.keys.with_current(|k| saml::sign_message(&mut req, &id, k, style, alg))
        {
            return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
        }
        saml_post(&sso, "SAMLRequest", &b64_std(req.to_xml()), relay.as_deref()).into_response()
    } else {
        let url = state.keys.with_current(|k| {
            saml::redirect_url(&sso, "SAMLRequest", &req.to_xml(), relay.as_deref(), flag("sign").then_some((k, alg)))
        });
        Redirect::to(&url).into_response()
    };
    set_cookie(&mut resp, &cookie(&request_cookie_name(&tenant), &id, 3600));
    resp
}

/// Assertion IDs the test SP has consumed, to catch replays.
fn seen() -> &'static Mutex<HashSet<String>> {
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    SEEN.get_or_init(Default::default)
}

struct Check {
    /// `None` for information only.
    ok: Option<bool>,
    label: String,
    detail: String,
}

#[derive(Default)]
struct Checks(Vec<Check>);

impl Checks {
    fn ok(&mut self, label: &str, detail: impl Into<String>) {
        self.0.push(Check { ok: Some(true), label: label.into(), detail: detail.into() });
    }
    fn fail(&mut self, label: &str, detail: impl Into<String>) {
        self.0.push(Check { ok: Some(false), label: label.into(), detail: detail.into() });
    }
    fn info(&mut self, label: &str, detail: impl Into<String>) {
        self.0.push(Check { ok: None, label: label.into(), detail: detail.into() });
    }
    fn check(&mut self, ok: bool, label: &str, detail: impl Into<String>) {
        if ok { self.ok(label, detail) } else { self.fail(label, detail) }
    }
    fn passed(&self) -> bool {
        !self.0.iter().any(|c| c.ok == Some(false))
    }
    fn html(&self) -> String {
        let rows: String = self
            .0
            .iter()
            .map(|c| {
                let (mark, class) = match c.ok {
                    Some(true) => ("✓", "ok"),
                    Some(false) => ("✗", "bad"),
                    None => ("·", "muted"),
                };
                format!(
                    r#"<li class="check-{class}"><span class="mark">{mark}</span><b>{}</b> <span>{}</span></li>"#,
                    esc(&c.label),
                    esc(&c.detail)
                )
            })
            .collect();
        format!(r#"<ul class="checks-list">{rows}</ul>"#)
    }
}

/// What the test SP learned from a Response.
struct Outcome {
    checks: Checks,
    name_id: Option<(String, String, Option<String>)>,
    session_index: Option<String>,
    attributes: Vec<(String, Option<String>, Vec<String>)>,
    response_xml: String,
    assertion_xml: Option<String>,
    assertion_id: Option<String>,
    name_id_encrypted: bool,
}

fn validate(state: &AppState, tenant: &Tenant, xml: &str, expected_request: Option<&str>) -> Outcome {
    let mut checks = Checks::default();
    let mut out = Outcome {
        checks: Checks::default(),
        name_id: None,
        session_index: None,
        attributes: vec![],
        response_xml: xml.to_string(),
        assertion_xml: None,
        assertion_id: None,
        name_id_encrypted: false,
    };
    let now = wall_clock();
    let acs = tenant.url("/sp/acs");
    let keys = state.keys.public_keys();
    let doc = match parse(xml) {
        Ok(d) if d.is(NS_PROTOCOL, "Response") => d,
        Ok(d) => {
            checks.fail("Response", format!("expected samlp:Response, got <{}>", d.qname()));
            out.checks = checks;
            return out;
        }
        Err(e) => {
            checks.fail("XML", e);
            out.checks = checks;
            return out;
        }
    };
    out.response_xml = doc.to_pretty();
    let response_id = doc.get_attr("ID").unwrap_or_default().to_string();
    match doc.get_attr("Destination") {
        Some(d) => {
            checks.check(d == acs, "Destination", format!("{d}{}", if d == acs { "" } else { " (expected this ACS)" }))
        }
        None => checks.info("Destination", "not set"),
    }
    let in_response_to = doc.get_attr("InResponseTo");
    match (in_response_to, expected_request) {
        (Some(got), Some(want)) => checks.check(
            got == want,
            "InResponseTo",
            if got == want {
                format!("{got} matches our AuthnRequest")
            } else {
                format!("{got}, but our AuthnRequest was {want}")
            },
        ),
        (Some(got), None) => checks.fail("InResponseTo", format!("{got}, but we didn't send an AuthnRequest")),
        (None, _) => checks.info("InResponseTo", "none: an unsolicited (IdP-initiated) Response"),
    }
    let issuer = doc.find(NS_ASSERTION, "Issuer").map(Element::value);
    match &issuer {
        Some(i) => checks.check(*i == tenant.entity_id, "Response Issuer", i.clone()),
        None => checks.info("Response Issuer", "not set"),
    }
    let status = Status::from_element(doc.find(NS_PROTOCOL, "Status"));
    if !status.is_success() {
        checks.fail(
            "Status",
            format!("{}{}", status.short(), status.message.map(|m| format!(": {m}")).unwrap_or_default()),
        );
        out.checks = checks;
        return out;
    }
    checks.ok("Status", "Success");

    let mut any_signature = false;
    if dsig::signature_of(&doc).is_some() {
        match dsig::verify(&doc, &response_id, &keys) {
            Ok(v) => {
                any_signature = true;
                checks.ok("Response signature", format!("valid ({})", v.alg.name()));
            }
            Err(e) => checks.fail("Response signature", e),
        }
    } else {
        checks.info("Response signature", "not signed");
    }

    // The assertion, decrypted if need be.
    let decrypted;
    let (assertion_doc, assertion): (&Element, &Element) = if let Some(a) = doc.find(NS_ASSERTION, "Assertion") {
        (&doc, a)
    } else if let Some(enc) = doc.find(NS_ASSERTION, "EncryptedAssertion") {
        let alg = enc
            .path(&[(NS_XENC, "EncryptedData"), (NS_XENC, "EncryptionMethod")])
            .and_then(|m| m.get_attr("Algorithm"))
            .unwrap_or("?")
            .rsplit('#')
            .next()
            .unwrap_or("?")
            .to_string();
        match xmlenc::decrypt(enc, &state.keys.private_keys()).and_then(|x| parse(&x)) {
            Ok(a) => {
                checks.ok("Encryption", format!("decrypted the EncryptedAssertion ({alg})"));
                decrypted = a;
                (&decrypted, &decrypted)
            }
            Err(e) => {
                checks.fail("Encryption", e);
                out.checks = checks;
                return out;
            }
        }
    } else {
        checks.fail("Assertion", "the Response has no Assertion");
        out.checks = checks;
        return out;
    };
    out.assertion_xml = (!std::ptr::eq(assertion_doc, &doc)).then(|| assertion.to_pretty());
    let assertion_id = assertion.get_attr("ID").unwrap_or_default().to_string();
    out.assertion_id = Some(assertion_id.clone());
    if dsig::signature_of(assertion).is_some() {
        match dsig::verify(assertion_doc, &assertion_id, &keys) {
            Ok(v) => {
                any_signature = true;
                checks.ok("Assertion signature", format!("valid ({})", v.alg.name()));
            }
            Err(e) => checks.fail("Assertion signature", e),
        }
    } else {
        checks.info("Assertion signature", "not signed");
    }
    if !any_signature {
        checks.fail("Signed", "neither the Response nor the Assertion has a valid signature");
    }
    if let Some(i) = assertion.find(NS_ASSERTION, "Issuer").map(Element::value) {
        checks.check(i == tenant.entity_id, "Assertion Issuer", i);
    }
    // Only accepted assertions are consumed: a rejected response doesn't use its ID up.
    let fresh = !seen().lock().unwrap().contains(&assertion_id);
    checks.check(
        fresh,
        "Replay",
        if fresh {
            format!("assertion {assertion_id} is new")
        } else {
            format!("assertion {assertion_id} was already used")
        },
    );

    let time =
        |el: Option<&Element>, attr: &str| el.and_then(|e| e.get_attr(attr)).map(|v| (v.to_string(), parse_iso8601(v)));
    let subject = assertion.find(NS_ASSERTION, "Subject");
    let decrypted = match subject.and_then(|s| s.find(NS_ASSERTION, "EncryptedID")) {
        Some(e) => match saml::decrypt_id(e, &state.keys.private_keys()) {
            Ok(n) => {
                checks.ok("EncryptedID", "decrypted with the test SP's key");
                out.name_id_encrypted = true;
                Some(n)
            }
            Err(e) => {
                checks.fail("EncryptedID", e);
                None
            }
        },
        None => None,
    };
    if let Some(n) = decrypted.as_ref().or_else(|| subject.and_then(|s| s.find(NS_ASSERTION, "NameID"))) {
        out.name_id = Some((
            n.value(),
            n.get_attr("Format").unwrap_or(nameid::UNSPECIFIED).to_string(),
            n.get_attr("SPNameQualifier").map(String::from),
        ));
    } else {
        checks.fail("NameID", "the assertion has no Subject/NameID or EncryptedID");
    }
    let confirmation = subject.and_then(|s| {
        s.find_all(NS_ASSERTION, "SubjectConfirmation").find(|c| c.get_attr("Method") == Some(saml::CM_BEARER))
    });
    match confirmation.and_then(|c| c.find(NS_ASSERTION, "SubjectConfirmationData")) {
        Some(data) => {
            let recipient = data.get_attr("Recipient").unwrap_or("");
            checks.check(recipient == acs, "Recipient", recipient.to_string());
            if let Some((raw, t)) = time(Some(data), "NotOnOrAfter") {
                let ok = t.is_some_and(|t| now < t + SKEW);
                checks.check(ok, "Confirmation NotOnOrAfter", if ok { raw } else { format!("{raw}: expired") });
            }
            if let (Some(irt), Some(want)) = (data.get_attr("InResponseTo"), expected_request) {
                checks.check(irt == want, "Confirmation InResponseTo", irt.to_string());
            }
        }
        None => checks.fail("SubjectConfirmation", "no bearer SubjectConfirmationData"),
    }
    let conditions = assertion.find(NS_ASSERTION, "Conditions");
    if let Some((raw, t)) = time(conditions, "NotBefore") {
        checks.check(
            t.is_some_and(|t| t <= now + SKEW),
            "NotBefore",
            if t.is_some_and(|t| t > now + SKEW) { format!("{raw}: not valid yet") } else { raw },
        );
    }
    if let Some((raw, t)) = time(conditions, "NotOnOrAfter") {
        checks.check(
            t.is_some_and(|t| now < t + SKEW),
            "NotOnOrAfter",
            if t.is_some_and(|t| now >= t + SKEW) { format!("{raw}: expired") } else { raw },
        );
    }
    let audiences: Vec<String> = conditions
        .map(|c| {
            c.find_all(NS_ASSERTION, "AudienceRestriction")
                .flat_map(|r| r.find_all(NS_ASSERTION, "Audience").map(Element::value))
                .collect()
        })
        .unwrap_or_default();
    let ours = entity_id(tenant);
    checks.check(audiences.contains(&ours), "Audience", audiences.join(", "));
    if let Some(statement) = assertion.find(NS_ASSERTION, "AuthnStatement") {
        out.session_index = statement.get_attr("SessionIndex").map(String::from);
        let class = statement
            .path(&[(NS_ASSERTION, "AuthnContext"), (NS_ASSERTION, "AuthnContextClassRef")])
            .map(Element::value)
            .unwrap_or_default();
        checks.info(
            "AuthnStatement",
            format!("AuthnInstant {}, {}", statement.get_attr("AuthnInstant").unwrap_or("?"), class),
        );
    }
    if let Some(statement) = assertion.find(NS_ASSERTION, "AttributeStatement") {
        for attr in statement.find_all(NS_ASSERTION, "Attribute") {
            out.attributes.push((
                attr.get_attr("Name").unwrap_or_default().to_string(),
                attr.get_attr("FriendlyName").map(String::from),
                attr.find_all(NS_ASSERTION, "AttributeValue").map(|v| v.text_content()).collect(),
            ));
        }
    }
    out.checks = checks;
    out
}

/// Resolve an artifact the way a service provider would: a signed ArtifactResolve over SOAP to
/// the identity provider's ArtifactResolutionService (handled in-process here). Returns the
/// Response it stood for, and checks on the exchange.
async fn resolve_artifact(state: &AppState, tenant: &Tenant, artifact: &str) -> (Checks, Result<String, String>) {
    let mut checks = Checks::default();
    let style = &tenant.default_preset(&state.config).style;
    let (mut resolve, id) =
        saml::artifact_resolve(&entity_id(tenant), &tenant.url("/artifact"), artifact, wall_clock());
    let alg = state.config.signature_algorithm;
    if let Err(e) = state.keys.with_current(|k| saml::sign_message(&mut resolve, &id, k, style, alg)) {
        return (checks, Err(e));
    }
    let envelope = crate::soap::envelope(resolve);
    let resp = crate::routes::backchannel::dispatch(state, tenant, &Bytes::from(envelope)).await;
    let body = match axum::body::to_bytes(resp.into_body(), 4 << 20).await {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => return (checks, Err(format!("reading the ArtifactResponse: {e}"))),
    };
    let (_, answer) = match crate::soap::unwrap(&body) {
        Ok(a) => a,
        Err(e) => return (checks, Err(e)),
    };
    if !answer.is(NS_PROTOCOL, "ArtifactResponse") {
        return (checks, Err(format!("expected samlp:ArtifactResponse, got <{}>", answer.qname())));
    }
    checks.info("Artifact", format!("resolved over SOAP with ArtifactResolve {id}"));
    let answer_id = answer.get_attr("ID").unwrap_or_default();
    match dsig::verify(&answer, answer_id, &state.keys.public_keys()) {
        Ok(v) => checks.ok("ArtifactResponse signature", format!("valid ({})", v.alg.name())),
        Err(e) => checks.fail("ArtifactResponse signature", e),
    }
    let irt = answer.get_attr("InResponseTo").unwrap_or_default();
    checks.check(irt == id, "ArtifactResponse InResponseTo", irt);
    let status = Status::from_element(answer.find(NS_PROTOCOL, "Status"));
    if !status.is_success() {
        return (checks, Err(format!("ArtifactResponse status {}", status.short())));
    }
    let Some(inner_id) = answer.find(NS_PROTOCOL, "Response").and_then(|r| r.get_attr("ID")) else {
        return (
            checks,
            Err("the ArtifactResponse carries no Response: the artifact is unknown, expired or already used".into()),
        );
    };
    let Some((inner, scope)) = answer.find_by_id_scoped(inner_id) else {
        return (checks, Err("the ArtifactResponse carries no Response".into()));
    };
    let mut inner = inner.clone();
    inner.declare_namespaces_in(&scope);
    (checks, Ok(inner.to_xml()))
}

pub async fn acs(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
    body: Bytes,
) -> Response {
    let form = crate::util::merged_params(q.as_deref(), &body);
    let (pre, xml) = if let Some(artifact) = form.get("SAMLart") {
        resolve_artifact(&state, &tenant, artifact).await
    } else if let Some(encoded) = form.get("SAMLResponse") {
        (Checks::default(), saml::decode_message(encoded, false))
    } else {
        return crate::html::error_page(
            &tenant,
            StatusCode::BAD_REQUEST,
            "No SAMLResponse",
            "Post a SAMLResponse here (HTTP-POST binding), or send a SAMLart (HTTP-Artifact binding).",
        );
    };
    let expected = cookie_value(&headers, &request_cookie_name(&tenant));
    let mut outcome = match xml {
        Ok(xml) => validate(&state, &tenant, &xml, expected.as_deref()),
        Err(e) => {
            let mut checks = Checks::default();
            checks.fail("Response", e);
            Outcome {
                checks,
                name_id: None,
                session_index: None,
                attributes: vec![],
                response_xml: String::new(),
                assertion_xml: None,
                assertion_id: None,
                name_id_encrypted: false,
            }
        }
    };
    outcome.checks.0.splice(0..0, pre.0);
    let passed = outcome.checks.passed();
    if passed && let Some(id) = &outcome.assertion_id {
        seen().lock().unwrap().insert(id.clone());
    }
    let attrs: String = outcome
        .attributes
        .iter()
        .map(|(name, friendly, values)| {
            format!(
                "<tr><td><code>{}</code>{}</td><td>{}</td></tr>",
                esc(name),
                friendly.as_ref().map(|f| format!(" <small class=\"muted\">{}</small>", esc(f))).unwrap_or_default(),
                values.iter().map(|v| format!("<code>{}</code>", esc(v))).collect::<Vec<_>>().join(" ")
            )
        })
        .collect();
    let who = outcome
        .name_id
        .as_ref()
        .map(|(v, f, _)| format!("<code>{}</code> <small class=\"muted\">{}</small>", esc(v), esc(f)))
        .unwrap_or_else(|| "–".into());
    let relay = form
        .get("RelayState")
        .filter(|r| !r.is_empty())
        .map(|r| format!(r#"<p class="muted">RelayState <code>{}</code></p>"#, esc(r)))
        .unwrap_or_default();
    let body = format!(
        r#"<section class="card">
  <div class="eyebrow {eyebrow}">{verdict}</div>
  <h1>{title}</h1>
  <p>NameID {who}</p>{relay}
  {checks}
  <div class="actions"><a class="btn" href="{again}">Back to the test SP</a></div>
</section>
<section class="card"><h2>Attributes</h2>{attr_table}</section>
<section class="card"><h2>Response</h2>{xml}{assertion}</section>"#,
        eyebrow = if passed { "" } else { "error" },
        verdict = if passed { "Test SP · login accepted" } else { "Test SP · login rejected" },
        title = if passed { "Signed in" } else { "The Response didn't pass validation" },
        checks = outcome.checks.html(),
        again = esc(&tenant.path("/sp")),
        attr_table = if attrs.is_empty() {
            r#"<p class="muted">No attributes.</p>"#.to_string()
        } else {
            format!(r#"<table class="endpoints">{attrs}</table>"#)
        },
        xml = xml_block("SAML Response", &outcome.response_xml),
        assertion = outcome.assertion_xml.as_ref().map(|a| xml_block("Decrypted assertion", a)).unwrap_or_default(),
    );
    let mut resp =
        page(&tenant, if passed { "Test SP: signed in" } else { "Test SP: rejected" }, &body).into_response();
    if !passed {
        let failed: Vec<String> = outcome
            .checks
            .0
            .iter()
            .filter(|c| c.ok == Some(false))
            .map(|c| format!("{}: {}", c.label, c.detail))
            .collect();
        crate::inspector::ErrorNote::attach(&mut resp, "rejected by the test SP", failed.join("; "));
    }
    set_cookie(&mut resp, &cookie(&request_cookie_name(&tenant), "", 0));
    if passed && let Some((name_id, format, qualifier)) = outcome.name_id {
        let session = SpSession {
            name_id,
            format,
            sp_name_qualifier: qualifier,
            session_index: outcome.session_index,
            issuer: tenant.entity_id.clone(),
            encrypted: outcome.name_id_encrypted,
        };
        let value = b64(serde_json::to_vec(&session).unwrap_or_default());
        set_cookie(&mut resp, &cookie(&session_cookie_name(&tenant), &value, 8 * 3600));
    }
    resp
}

/// SP-initiated logout: send a LogoutRequest for the test SP's session.
pub async fn logout(State(state): State<AppState>, tenant: Tenant, headers: HeaderMap) -> Response {
    let Some(session) = sp_session(&tenant, &headers) else {
        return Redirect::to(&tenant.path("/sp")).into_response();
    };
    let Some(slo) = tenant.slo_url() else {
        let mut resp = crate::html::message_page(
            &tenant,
            "Signed out locally",
            "This identity provider doesn't do single logout, so the test SP only cleared its own session.",
        );
        set_cookie(&mut resp, &cookie(&session_cookie_name(&tenant), "", 0));
        return resp;
    };
    let style = crate::presets::generic().style.clone();
    // An SP that got an EncryptedID encrypts the NameID for the IdP in its LogoutRequest too.
    let idp_key = state.keys.with_current(|k| k.public.clone());
    let encrypt = session.encrypted.then_some((&idp_key, EncAlg::Aes256Gcm));
    let message = saml::logout_request(&saml::LogoutRequestSpec {
        style: &style,
        issuer: &entity_id(&tenant),
        destination: &slo,
        name_id: &session.name_id,
        name_id_format: &session.format,
        sp_name_qualifier: session.sp_name_qualifier.as_deref(),
        session_index: session.session_index.as_deref().unwrap_or_default(),
        now: wall_clock(),
        encrypt,
    });
    let message = match message {
        Ok((m, _)) => m,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let url = state.keys.with_current(|k| {
        saml::redirect_url(
            &slo,
            "SAMLRequest",
            &message.to_xml(),
            Some("/sp"),
            Some((k, state.config.signature_algorithm)),
        )
    });
    Redirect::to(&url).into_response()
}

/// The test SP's SLO endpoint: LogoutResponses to its own logouts, and LogoutRequests from the
/// IdP when another service provider starts a logout.
pub async fn slo(State(state): State<AppState>, tenant: Tenant, RawQuery(q): RawQuery, body: Bytes) -> Response {
    let query = q.unwrap_or_default();
    if let Some(param) = dsig::duplicate_param(&query) {
        return crate::html::error_page(
            &tenant,
            StatusCode::BAD_REQUEST,
            "Duplicate parameter",
            &format!("{param} appears more than once in the query string."),
        );
    }
    let params: HashMap<String, String> = crate::util::merged_params(Some(&query), &body);
    let in_query = parse_form(query.as_bytes());
    let found = ["SAMLRequest", "SAMLResponse"]
        .into_iter()
        .find_map(|k| params.get(k).map(|v| (v.clone(), in_query.contains_key(k))));
    let Some((value, redirect)) = found else {
        return Redirect::to(&tenant.path("/sp")).into_response();
    };
    let parsed = saml::decode_message(&value, redirect).and_then(|x| saml::parse_message(&x));
    let clear = cookie(&session_cookie_name(&tenant), "", 0);
    let (message, root) = match parsed {
        Ok(m) => m,
        Err(e) => return crate::html::error_page(&tenant, StatusCode::BAD_REQUEST, "Invalid logout message", &e),
    };
    let verified = |id: &str| {
        let keys = state.keys.public_keys();
        match (redirect, QuerySignature::from_query(&query)) {
            (true, Some(qs)) => qs.verify(&keys).map(|a| format!("signed ({}), valid", a.name())),
            (true, None) => Err("not signed".into()),
            (false, _) if dsig::signature_of(&root).is_some() => {
                dsig::verify(&root, id, &keys).map(|v| format!("signed ({}), valid", v.alg.name()))
            }
            (false, _) => Err("not signed".into()),
        }
    };
    match message {
        Message::LogoutResponse(resp) => {
            let sig = verified(&resp.id).unwrap_or_else(|e| e);
            let mut page_resp = crate::html::message_page(
                &tenant,
                if resp.status.is_success() { "Signed out" } else { "Logout failed" },
                &format!(
                    "The identity provider answered the test SP's LogoutRequest with {} ({sig}).",
                    resp.status.short()
                ),
            );
            set_cookie(&mut page_resp, &clear);
            page_resp
        }
        Message::LogoutRequest(req) => {
            // Log out locally and answer, so the IdP can continue to the next service provider.
            let Some(slo) = tenant.slo_url() else {
                return crate::html::error_page(
                    &tenant,
                    StatusCode::BAD_REQUEST,
                    "No SLO endpoint",
                    "The identity provider has no SLO endpoint to answer.",
                );
            };
            let name_id = match root.find(NS_ASSERTION, "EncryptedID") {
                Some(e) => saml::decrypt_id(e, &state.keys.private_keys()).map(|_| ()),
                None => Ok(()),
            };
            let status = match verified(&req.id).and(name_id) {
                Ok(_) => Status::success(),
                Err(e) => {
                    Status::parse("Requester", Some(format!("the test SP rejected the LogoutRequest: {e}"))).unwrap()
                }
            };
            let style = crate::presets::generic().style.clone();
            let (message, _) =
                saml::logout_response(&style, &entity_id(&tenant), &slo, Some(&req.id), &status, wall_clock());
            let relay = params.get("RelayState").map(String::as_str);
            let url = state.keys.with_current(|k| {
                saml::redirect_url(
                    &slo,
                    "SAMLResponse",
                    &message.to_xml(),
                    relay,
                    Some((k, state.config.signature_algorithm)),
                )
            });
            let mut resp = Redirect::to(&url).into_response();
            set_cookie(&mut resp, &clear);
            resp
        }
        Message::AuthnRequest(_) | Message::ArtifactResolve(_) => crate::html::error_page(
            &tenant,
            StatusCode::BAD_REQUEST,
            &format!("Unexpected {}", message.kind()),
            "This is the test SP's logout endpoint.",
        ),
    }
}

pub async fn metadata(State(state): State<AppState>, tenant: Tenant) -> Response {
    let md = |local: &str| Element::new(NS_MD, "md", local);
    let cert = state.keys.with_current(|k| k.cert_b64());
    let key = |usage: &str| {
        md("KeyDescriptor").attr("use", usage).child(Element::new(NS_DS, "ds", "KeyInfo").child(
            Element::new(NS_DS, "ds", "X509Data").child(Element::new(NS_DS, "ds", "X509Certificate").text(&cert)),
        ))
    };
    let mut entity =
        md("EntityDescriptor").attr("entityID", entity_id(&tenant)).declare("md", NS_MD).declare("ds", NS_DS).child(
            md("SPSSODescriptor")
                .attr("AuthnRequestsSigned", "false")
                .attr("WantAssertionsSigned", "false")
                .attr("protocolSupportEnumeration", NS_PROTOCOL)
                .child(key("signing"))
                .child(key("encryption"))
                .child(
                    md("SingleLogoutService").attr("Binding", BINDING_REDIRECT).attr("Location", tenant.url("/sp/slo")),
                )
                .child(
                    md("AssertionConsumerService")
                        .attr("Binding", BINDING_POST)
                        .attr("Location", tenant.url("/sp/acs"))
                        .attr("index", "0")
                        .attr("isDefault", "true"),
                )
                .child(
                    md("AssertionConsumerService")
                        .attr("Binding", BINDING_ARTIFACT)
                        .attr("Location", tenant.url("/sp/acs"))
                        .attr("index", "1"),
                ),
        );
    entity.declare_namespaces();
    ([(axum::http::header::CONTENT_TYPE, "text/xml; charset=utf-8")], entity.to_document()).into_response()
}

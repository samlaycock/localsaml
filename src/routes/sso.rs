//! The SAML endpoint (AuthnRequests, plus logout messages for templates that use one endpoint for
//! both), IdP-initiated logins, the login UI and issuing Responses.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{OriginalUri, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::dsig::{self, QuerySignature};
use crate::faults::{self, Endpoint};
use crate::html::{BUTTON, PRIMARY_BUTTON, card, error_page, esc, saml_error_page, saml_post, shell, xml_block};
use crate::inspector::SamlNote;
use crate::presets::{self, Identity, Preset, SessionIndexStyle, nameid};
use crate::saml::{self, AuthnRequest, Message, ResponseSpec, Status, Tamper};
use crate::sp::ServiceProvider;
use crate::state::{AppState, LastResponse, Participant, Pending, Session, StoredArtifact};
use crate::store::Table;
use crate::tenant::Tenant;
use crate::util::{b64_std, merged_params, non_empty, parse_form, parse_json_object};
use crate::xml::Element;

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

pub fn current_session(state: &AppState, tenant: &Tenant, headers: &HeaderMap) -> Option<(String, Session)> {
    let sid = cookie_value(headers, &tenant.cookie_name())?;
    let session = state.store.get::<Session>(Table::Sessions, &sid)?;
    Some((sid, session))
}

fn session_cookie(tenant: &Tenant, sid: &str, max_age: i64) -> String {
    format!("{}={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}", tenant.cookie_name())
}

pub fn clear_session_cookie(tenant: &Tenant) -> String {
    format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0", tenant.cookie_name())
}

pub fn set_cookie(resp: &mut Response, cookie: &str) {
    if let Ok(v) = HeaderValue::from_str(cookie) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
}

// ---------------------------------------------------------------------------
// Service providers and signatures
// ---------------------------------------------------------------------------

/// A declared, registered or built-in service provider, fetching pending metadata if the entity
/// isn't known yet.
pub async fn find_sp(state: &AppState, tenant: &Tenant, entity_id: &str) -> Option<ServiceProvider> {
    if entity_id == tenant.url("/sp") {
        return Some(crate::routes::testsp::service_provider(state, tenant));
    }
    if let Some(sp) = state.service_provider(entity_id) {
        // A declared SP whose metadata URL wasn't reachable yet: try again now it's in use.
        if sp.metadata_pending {
            state.refresh_metadata().await;
            return state.service_provider(entity_id);
        }
        return Some(sp);
    }
    if state.has_pending_metadata() {
        state.refresh_metadata().await;
        return state.service_provider(entity_id);
    }
    None
}

/// The service provider for a message's issuer: known, discovered from metadata at its entity ID,
/// or (lenient only) one made up from the request, whose ACS URLs can't be verified.
pub async fn resolve_sp(state: &AppState, tenant: &Tenant, issuer: &str) -> Result<ServiceProvider, String> {
    if let Some(sp) = find_sp(state, tenant, issuer).await {
        return Ok(sp);
    }
    if state.config.lenient {
        return Ok(ServiceProvider { entity_id: issuer.into(), source: "request".into(), ..Default::default() });
    }
    discover_sp(state, issuer).await.map_err(|e| {
        format!(
            "'{issuer}' isn't a declared or registered service provider, so localsaml can't verify the ACS URLs its requests name (Profiles 4.1.4.1), and its metadata couldn't be read from its entity ID: {e}. Declare it in localsaml.toml, register it with POST /dev/api/service-providers, or run with lenient = true."
        )
    })
}

/// An unknown service provider whose entity ID is a URL serving its metadata: register it from
/// that metadata.
async fn discover_sp(state: &AppState, entity_id: &str) -> Result<ServiceProvider, String> {
    if !crate::util::is_web_url(entity_id) {
        return Err("its entity ID isn't an http(s) URL".into());
    }
    let mut sp =
        ServiceProvider { entity_id: entity_id.into(), metadata_url: Some(entity_id.into()), ..Default::default() };
    sp.load_remote_metadata().await?;
    if sp.entity_id != entity_id {
        return Err(format!("the metadata there is for '{}'", sp.entity_id));
    }
    sp.validate().map_err(|e| e.to_string())?;
    state.register_service_provider(&sp);
    sp.source = "discovered".into();
    Ok(sp)
}

/// May a response go to `url` for this SP? Only to a registered ACS, unless lenient (where an
/// SP without any accepts the request's).
pub fn acs_allowed(state: &AppState, sp: &ServiceProvider, url: &str) -> bool {
    if state.config.lenient { sp.allows_acs(url) } else { sp.registers_acs(url) }
}

/// Is a message the spec requires to be authenticated (logout messages, ArtifactResolve)
/// authenticated by a verified signature? Lenient mode also takes unsigned ones (unless
/// `required`), and signed ones it can't verify. `Err` says why not.
pub fn authenticated(
    state: &AppState,
    sp: &ServiceProvider,
    check: &SigCheck,
    kind: &str,
    required: bool,
) -> Result<(), String> {
    match check {
        SigCheck::Verified(_) => Ok(()),
        SigCheck::Invalid(e) => Err(format!("Invalid {kind} signature: {e}")),
        SigCheck::Unsigned if state.config.lenient && !required => Ok(()),
        SigCheck::Unverified(_) if state.config.lenient => Ok(()),
        SigCheck::Unsigned => Err(format!(
            "Unsigned {kind}: {} must sign it, so localsaml can authenticate it{}",
            sp.label(),
            if state.config.lenient { " (want_logout_signed)" } else { "" }
        )),
        SigCheck::Unverified(_) => {
            Err(format!("Unverifiable {kind} signature: {} has no certificate to authenticate it with", sp.label()))
        }
    }
}

/// How a message was signed.
pub enum SigCheck {
    Unsigned,
    Verified(String),
    /// Signed, but the SP has no certificate to check it with.
    Unverified(String),
    Invalid(String),
}

impl SigCheck {
    pub fn describe(&self) -> String {
        match self {
            SigCheck::Unsigned => "unsigned".into(),
            SigCheck::Verified(how) => format!("{how}, verified"),
            SigCheck::Unverified(how) => format!("{how}, not verified (no certificate for this service provider)"),
            SigCheck::Invalid(e) => format!("invalid: {e}"),
        }
    }
}

pub fn check_signature(sp: &ServiceProvider, root: &Element, id: &str, query_sig: Option<&QuerySignature>) -> SigCheck {
    let key = match sp.signing_key() {
        Some(Ok(k)) => Some(k),
        Some(Err(e)) => return SigCheck::Invalid(format!("the service provider's certificate is unusable: {e}")),
        None => None,
    };
    if let Some(qs) = query_sig {
        let how = format!("Redirect binding signature ({})", qs.alg.map(|a| a.name()).unwrap_or(&qs.alg_uri));
        return match key {
            Some(k) => match qs.verify(&[k]) {
                Ok(_) => SigCheck::Verified(how),
                Err(e) => SigCheck::Invalid(e),
            },
            None => SigCheck::Unverified(how),
        };
    }
    // The message may be the document, or inside one (a SOAP envelope).
    if root.find_by_id(id).and_then(dsig::signature_of).is_some() {
        return match key {
            Some(k) => match dsig::verify(root, id, &[k]) {
                Ok(v) => SigCheck::Verified(format!("XML signature ({})", v.alg.name())),
                Err(e) => SigCheck::Invalid(e),
            },
            None => SigCheck::Unverified("XML signature".into()),
        };
    }
    SigCheck::Unsigned
}

// ---------------------------------------------------------------------------
// The SAML endpoint
// ---------------------------------------------------------------------------

/// Where a message arrived: the binding, its RelayState and any query signature.
pub struct Arrival {
    pub binding: &'static str,
    pub relay_state: Option<String>,
    pub query_signature: Option<QuerySignature>,
    /// Every query and form parameter (for `dev_*` options).
    pub params: HashMap<String, String>,
    /// The URL the message was sent to.
    pub url: String,
}

/// SSO and SLO: decode the message (either binding) and dispatch on its type.
pub async fn endpoint(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    if crate::soap::is_soap(&headers, &body) {
        let url = format!("{}{}", origin(&tenant.base), uri.path());
        return crate::routes::backchannel::dispatch(&state, &tenant, &headers, &url, &body).await;
    }
    let query = query.unwrap_or_default();
    if let Some(param) = dsig::duplicate_param(&query) {
        return saml_error_page(
            &tenant,
            "Duplicate parameter",
            &format!("{param} appears more than once in the query string."),
        );
    }
    let in_query = parse_form(query.as_bytes());
    let form = parse_form(&body);
    let params = merged_params(Some(&query), &body);
    let found = ["SAMLRequest", "SAMLResponse"]
        .into_iter()
        .find_map(|k| in_query.get(k).map(|v| (v.clone(), true)).or_else(|| form.get(k).map(|v| (v.clone(), false))));
    let url = format!("{}{}", origin(&tenant.base), uri.path());
    let Some((value, redirect)) = found else {
        // Okta-style IdP-initiated links: the SSO URL with the SP named in the query.
        if let Some(sp) = sp_param(&params) {
            return start_idp_initiated(&state, &tenant, &headers, &sp, &params).await;
        }
        return saml_error_page(
            &tenant,
            "No SAML message",
            &format!(
                "This is the SAML endpoint of {}. Send an AuthnRequest or a logout message here with the HTTP-Redirect or HTTP-POST binding, or start an IdP-initiated login at {}?sp=<entity ID>.",
                tenant.entity_id,
                tenant.url("/sso/initiate")
            ),
        );
    };
    let bad = |title: &str, detail: &str| saml_error_page(&tenant, title, detail);
    let xml = match saml::decode_message(&value, redirect) {
        Ok(x) => x,
        Err(e) => return bad("Undecodable SAML message", &e),
    };
    let (message, root) = match saml::parse_message(&xml) {
        Ok(m) => m,
        Err(e) => return bad("Invalid SAML message", &e),
    };
    let arrival = Arrival {
        binding: if redirect { "redirect" } else { "post" },
        relay_state: non_empty(&params, "RelayState"),
        query_signature: if redirect { QuerySignature::from_query(&query) } else { None },
        params,
        url,
    };
    match message {
        Message::AuthnRequest(req) => authn_request(&state, &tenant, &headers, req, &root, arrival).await,
        Message::LogoutRequest(req) => {
            crate::routes::slo::logout_request(&state, &tenant, &headers, req, &root, arrival).await
        }
        Message::LogoutResponse(resp) => {
            crate::routes::slo::logout_response(&state, &tenant, resp, &root, arrival).await
        }
        Message::ArtifactResolve(_) | Message::AttributeQuery(_) => saml_error_page(
            &tenant,
            &format!("{} over the wrong binding", message.kind()),
            "Send it with the SOAP binding: POST a SOAP envelope to the ArtifactResolutionService or AttributeService.",
        ),
    }
}

/// ECP (Profiles 4.2): an AuthnRequest relayed over SOAP by an enhanced client. It's checked like
/// any other, the user is signed in with HTTP Basic credentials, and the Response goes back to the
/// client in a SOAP envelope naming the ACS it must deliver it to.
pub async fn ecp(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    req: AuthnRequest,
    message: &Element,
    url: &str,
) -> Response {
    let arrival =
        Arrival { binding: "soap", relay_state: None, query_signature: None, params: HashMap::new(), url: url.into() };
    let resp = authn_request(state, tenant, headers, req, message, arrival).await;
    // What the browser flow shows as an error page is a SOAP fault for an ECP client.
    let soap =
        resp.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.contains("xml"));
    if soap || resp.status() == StatusCode::UNAUTHORIZED {
        return resp;
    }
    let reason = match resp.extensions().get::<crate::inspector::ErrorNote>() {
        Some(note) => format!("{}: {}", note.error, note.description),
        None => "the AuthnRequest was refused".to_string(),
    };
    crate::soap::fault(true, &reason)
}

/// Sign an ECP client's user in with HTTP Basic credentials: a declared user (by id, email or
/// NameID), or the template's identity for that login. Any password is accepted.
async fn ecp_login(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    preset: &'static Preset,
    sp: &ServiceProvider,
    pending: Pending,
) -> Response {
    let login = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' ').filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic")).map(|(_, c)| c))
        .and_then(|b| crate::util::b64_std_decode_lenient(b.trim()))
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|creds| creds.split_once(':').map(|(user, _)| user.to_string()))
        .filter(|user| !user.is_empty());
    let Some(login) = login else {
        let mut resp = (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"localsaml\""))],
            "ECP sign-in needs HTTP Basic credentials: a declared user's id or email, or any login (any password).",
        )
            .into_response();
        crate::inspector::ErrorNote::attach(&mut resp, "ECP credentials missing", "no HTTP Basic Authorization header");
        return resp;
    };
    let (preset, mut identity) = match state.config.user_for_login(&login) {
        Some(user) => user.resolve(None, preset),
        None => {
            let mut identity = preset.default_identity();
            preset.apply_login_hint(&mut identity, &login);
            (preset, identity)
        }
    };
    adapt_name_id(&mut identity, preset, &pending);
    complete(state, tenant, headers, &pending, preset, sp, identity, None, false)
}

/// Do two URLs name the same place (ignoring case in the host, default ports, a trailing slash)?
fn same_url(a: &str, b: &str) -> bool {
    match (url::Url::parse(a.trim_end_matches('/')), url::Url::parse(b.trim_end_matches('/'))) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

pub fn origin(base: &str) -> String {
    url::Url::parse(base).map(|u| u.origin().ascii_serialization()).unwrap_or_default()
}

/// The service provider named by an IdP-initiated link (each IdP calls the parameter something else).
fn sp_param(params: &HashMap<String, String>) -> Option<String> {
    ["sp", "spEntityID", "providerId", "PartnerSpId", "entityID"].iter().find_map(|k| non_empty(params, k))
}

/// The template to sign in with: the issuer's, or on the root issuer the SP's preferred one.
pub fn preset_for(state: &AppState, tenant: &Tenant, sp: &ServiceProvider) -> &'static Preset {
    match (tenant.preset, &sp.preset) {
        (None, Some(p)) => presets::get_or_generic(p),
        _ => tenant.default_preset(&state.config),
    }
}

async fn authn_request(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    req: AuthnRequest,
    root: &Element,
    arrival: Arrival,
) -> Response {
    let bad = |title: &str, detail: &str| saml_error_page(tenant, title, detail);
    let Some(issuer) = req.issuer.clone() else {
        return bad("AuthnRequest has no Issuer", "The request must name the service provider in <saml:Issuer>.");
    };
    let sp = match resolve_sp(state, tenant, &issuer).await {
        Ok(sp) => sp,
        Err(e) => return bad("Unknown service provider", &e),
    };
    let signature = check_signature(&sp, root, &req.id, arrival.query_signature.as_ref());
    // A refused request is answered once its ACS is known (below).
    let refusal = match &signature {
        SigCheck::Invalid(e) => Some(("Invalid AuthnRequest signature".to_string(), e.clone())),
        SigCheck::Unsigned if sp.want_authn_requests_signed => Some((
            "Unsigned AuthnRequest".to_string(),
            format!(
                "{} requires signed AuthnRequests (AuthnRequestsSigned in its metadata, or want_authn_requests_signed).",
                sp.label()
            ),
        )),
        _ => None,
    };

    // The request's ProtocolBinding, else the binding of the ACS it names, else the SP's default.
    let requested_binding = match req.protocol_binding.as_deref() {
        Some(saml::BINDING_ARTIFACT) => Some("artifact"),
        Some(saml::BINDING_POST) => Some("post"),
        _ => None,
    };
    let acs_url = match (&req.acs_url, req.acs_index) {
        (Some(url), _) => {
            if !acs_allowed(state, &sp, url) {
                return bad(
                    "Unregistered AssertionConsumerServiceURL",
                    &format!(
                        "'{url}' isn't one of {}'s ACS URLs: {}.",
                        sp.label(),
                        sp.acs_urls.iter().chain(&sp.acs_artifact_urls).cloned().collect::<Vec<_>>().join(", ")
                    ),
                );
            }
            url.clone()
        }
        (None, Some(index)) => match sp.acs_by_index(index) {
            Some(url) => url.clone(),
            None => {
                return bad(
                    "Unknown AssertionConsumerServiceIndex",
                    &format!("{} has no ACS with index {index}.", sp.label()),
                );
            }
        },
        (None, None) => match sp.default_acs(if arrival.binding == "soap" {
            "paos"
        } else {
            requested_binding.unwrap_or(sp.default_binding())
        }) {
            Some(url) => url.clone(),
            None => {
                return bad(
                    "No AssertionConsumerServiceURL",
                    &format!(
                        "The request has no AssertionConsumerServiceURL and {} has no registered ACS URL to fall back on. Add one to the request, or declare the service provider with acs_urls (or metadata).",
                        sp.label()
                    ),
                );
            }
        },
    };
    // ECP clients take the Response back themselves (PAOS).
    // A URL the request names goes with its ProtocolBinding; an ACS chosen by index or by default
    // goes with the binding it's registered for.
    let response_binding = if arrival.binding == "soap" {
        "paos".to_string()
    } else if req.acs_url.is_some() {
        requested_binding.or_else(|| sp.acs_binding(&acs_url)).unwrap_or(sp.default_binding()).to_string()
    } else {
        sp.acs_binding(&acs_url).or(requested_binding).unwrap_or(sp.default_binding()).to_string()
    };
    if !crate::util::is_web_url(&acs_url) {
        return bad("Invalid AssertionConsumerServiceURL", &format!("'{acs_url}' is not an absolute http(s) URL."));
    }

    let preset = preset_for(state, tenant, &sp);
    let mut warnings = vec![];
    if let Some(b) = &req.protocol_binding
        && b != saml::BINDING_POST
        && b != saml::BINDING_ARTIFACT
        && !(b == saml::BINDING_PAOS && arrival.binding == "soap")
    {
        warnings.push(format!("ProtocolBinding {b} isn't supported; the Response is sent with HTTP-POST."));
    }
    if arrival.relay_state.as_ref().is_some_and(|r| r.len() > 80) {
        warnings.push("RelayState is longer than the 80 bytes SAML allows service providers to send.".into());
    }
    if let Some(t) = req.issue_instant
        && (t - state.now()).abs() > 300
    {
        warnings
            .push(format!("IssueInstant is {} from localsaml's clock.", crate::util::format_duration(t - state.now())));
    }
    if let Some(scoping) = req.scoping.as_ref().filter(|s| !s.requester_ids.is_empty()) {
        warnings.push(format!(
            "Scoping names RequesterID {} (informational: localsaml doesn't proxy).",
            scoping.requester_ids.join(", ")
        ));
    }
    if matches!(signature, SigCheck::Unverified(_)) {
        warnings.push(
            "The request is signed, but there's no certificate for this service provider to verify it with.".into(),
        );
    }

    let authn_context = crate::presets::authn::satisfy(
        &req.requested_authn_contexts,
        &req.requested_authn_decls,
        req.authn_context_comparison.as_deref(),
    );
    let mut pending = Pending {
        id: uuid::Uuid::new_v4().to_string(),
        created: state.now(),
        tenant: tenant.key().into(),
        sp: sp.entity_id.clone(),
        sp_name: sp.name.clone().or(req.provider_name.clone()),
        acs_url,
        audience: sp.audience(),
        request_id: Some(req.id.clone()),
        relay_state: arrival.relay_state.clone(),
        force_authn: req.force_authn,
        is_passive: req.is_passive,
        // `encrypted` isn't a format to issue: the NameID gets the usual format, encrypted.
        name_id_format: req.name_id_format.clone().filter(|f| f != nameid::UNSPECIFIED && f != nameid::ENCRYPTED),
        encrypt_name_id: req.name_id_format.as_deref() == Some(nameid::ENCRYPTED),
        sp_name_qualifier: req.sp_name_qualifier.clone(),
        requested_authn_contexts: req.requested_authn_contexts.clone(),
        authn_context: authn_context.clone().ok().flatten(),
        login_hint: req.subject.clone().or_else(|| non_empty(&arrival.params, "login_hint")),
        subject: req.subject.clone(),
        subject_format: req.subject_format.clone(),
        binding: arrival.binding.into(),
        response_binding,
        signature: signature.describe(),
        warnings,
        tampers: vec![],
        request_xml: Some(root.to_pretty()),
    };
    // RelayState over 80 bytes isn't valid (Bindings 3.4.3, 3.5.3), and returning it would make
    // localsaml send one: a Requester error, without it.
    if let Some(r) = pending.relay_state.as_ref().filter(|r| r.len() > 80 && !state.config.lenient) {
        let message = format!("RelayState is {} bytes; the bindings allow at most 80", r.len());
        pending.relay_state = None;
        return respond_status(
            state,
            tenant,
            preset,
            &sp,
            &pending,
            Status::parse("Requester", Some(message)).unwrap(),
        );
    }
    // Refusing to answer: a RequestDenied Response if the ACS is one registered for the SP
    // (Bindings 3.4.6, 3.5.6); otherwise there's nowhere trustworthy to send one.
    if let Some((title, detail)) = refusal {
        if !sp.registers_acs(&pending.acs_url) {
            return bad(&title, &detail);
        }
        return respond_status(
            state,
            tenant,
            preset,
            &sp,
            &pending,
            Status::parse("RequestDenied", Some(format!("{title}: {detail}"))).unwrap(),
        );
    }
    if req.version != "2.0" {
        let status =
            Status::parse("RequestVersionTooHigh", Some(format!("unsupported SAML version '{}'", req.version)));
        return respond_status(state, tenant, preset, &sp, &pending, status.unwrap_or_else(|_| Status::success()));
    }
    // A request whose Destination isn't where it was sent must be discarded (Core 3.2.1).
    if let Some(d) = &req.destination
        && !same_url(d, &arrival.url)
    {
        let message = format!("Destination is '{d}', but the request was sent to '{}'", arrival.url);
        return respond_status(
            state,
            tenant,
            preset,
            &sp,
            &pending,
            Status::parse("Requester", Some(message)).unwrap(),
        );
    }
    // Scoping: localsaml authenticates users itself and never proxies, so an IDPList that doesn't
    // name it can't be satisfied (Core 3.4.1.5.1).
    if let Some(scoping) = &req.scoping
        && !scoping.idp_list.is_empty()
        && !scoping.idp_list.contains(&tenant.entity_id)
    {
        let message = format!(
            "the request's IDPList ({}) doesn't include {}, and localsaml doesn't proxy",
            scoping.idp_list.join(", "),
            tenant.entity_id
        );
        return respond_status(
            state,
            tenant,
            preset,
            &sp,
            &pending,
            Status::parse("NoSupportedIDP", Some(message)).unwrap(),
        );
    }
    // A RequestedAuthnContext localsaml can't satisfy (Core 3.3.2.2.1).
    if let Err(e) = authn_context {
        return respond_status(state, tenant, preset, &sp, &pending, Status::parse("NoAuthnContext", Some(e)).unwrap());
    }
    // An encrypted NameID needs the SP's encryption certificate (Core 3.4.1.1).
    if pending.encrypt_name_id
        && let Err(e) = name_id_encryption(preset, &sp)
    {
        return respond_status(
            state,
            tenant,
            preset,
            &sp,
            &pending,
            Status::parse("InvalidNameIDPolicy", Some(e)).unwrap(),
        );
    }
    if arrival.binding == "soap" {
        return ecp_login(state, tenant, headers, preset, &sp, pending).await;
    }
    proceed(state, tenant, headers, preset, &sp, pending, &arrival.params).await
}

/// Faults, automated logins, passive requests and session reuse; otherwise the login page.
async fn proceed(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    preset: &'static Preset,
    sp: &ServiceProvider,
    mut pending: Pending,
    params: &HashMap<String, String>,
) -> Response {
    // Non-standard: `dev_status` and `dev_tamper` fail this one login on purpose.
    if let Some(name) = non_empty(params, "dev_status") {
        let message =
            non_empty(params, "dev_status_message").unwrap_or_else(|| "injected by localsaml (dev_status)".into());
        return match Status::parse(&name, Some(message)) {
            Ok(status) => respond_status(state, tenant, preset, sp, &pending, status),
            Err(e) => saml_error_page(tenant, "Invalid dev_status", &e),
        };
    }
    if let Some(list) = non_empty(params, "dev_tamper") {
        for name in list.split([',', ' ']).filter(|n| !n.is_empty()) {
            match Tamper::parse(name) {
                Some(t) => pending.tampers.push(t),
                None => {
                    return saml_error_page(tenant, "Invalid dev_tamper", &format!("unknown tamper '{name}'"));
                }
            }
        }
    }
    let target = faults::Target { endpoint: Endpoint::Sso, issuer: tenant.key(), sp: Some(&pending.sp) };
    if let Some(fault) = state.faults.take(&target) {
        fault.wait().await;
        if let Some(status) = fault.status_with_default_message() {
            return respond_status(state, tenant, preset, sp, &pending, status);
        }
        pending.tampers.extend(fault.tamper.iter().copied());
    }

    // Non-standard: `dev_user` (a declared user) and/or `dev_attributes` (JSON or base64url JSON)
    // sign in immediately, for automated tests.
    let dev_user = non_empty(params, "dev_user");
    let dev_attributes = non_empty(params, "dev_attributes");
    if dev_user.is_some() || dev_attributes.is_some() || non_empty(params, "dev_name_id").is_some() {
        let overrides = match dev_attributes.as_deref().map(parse_json_object).transpose() {
            Ok(m) => m.unwrap_or_default(),
            Err(e) => return saml_error_page(tenant, "Invalid dev_attributes", &e),
        };
        let explicit = non_empty(params, "dev_preset").and_then(|p| presets::get(&p));
        let (preset, mut identity) = match &dev_user {
            Some(id) => match state.config.user(id) {
                Some(user) => user.resolve(explicit, preset),
                None => {
                    return saml_error_page(tenant, "Unknown dev_user", &format!("No [[users]] entry with id '{id}'."));
                }
            },
            None => {
                let preset = explicit.unwrap_or(preset);
                let mut identity = preset.default_identity();
                if let Some(hint) = &pending.login_hint {
                    preset.apply_login_hint(&mut identity, hint);
                }
                (preset, identity)
            }
        };
        if let Err(e) = validate_attributes(&overrides) {
            return saml_error_page(tenant, "Invalid dev_attributes", &e);
        }
        // The NameID policy applies to the final attributes (an emailAddress NameID follows the
        // overridden email); an explicit dev_name_id wins over both.
        preset.apply_overrides(&mut identity, &overrides);
        adapt_name_id(&mut identity, preset, &pending);
        if let Some(n) = non_empty(params, "dev_name_id") {
            identity.name_id = n;
        }
        return complete(state, tenant, headers, &pending, preset, sp, identity, None, false);
    }

    let session = current_session(state, tenant, headers);
    let reuse = |s: &Session| s.tenant == tenant.key();
    // Auto-login needs no interaction, so it can answer passive requests too (below).
    if pending.is_passive && !state.config.auto_login {
        return match session {
            Some((sid, s)) if reuse(&s) && !pending.force_authn => {
                let p = presets::get_or_generic(&s.identity.preset);
                let identity = s.identity.clone();
                complete(state, tenant, headers, &pending, p, sp, identity, Some((sid, s)), false)
            }
            _ => respond_status(
                state,
                tenant,
                preset,
                sp,
                &pending,
                Status::parse("NoPassive", Some("IsPassive was requested and there is no session".into())).unwrap(),
            ),
        };
    }
    if (state.config.silent_sso || state.config.auto_login)
        && !pending.force_authn
        && let Some((sid, s)) = session.clone().filter(|(_, s)| reuse(s))
    {
        let p = presets::get_or_generic(&s.identity.preset);
        let identity = s.identity.clone();
        return complete(state, tenant, headers, &pending, p, sp, identity, Some((sid, s)), false);
    }
    if state.config.auto_login {
        // A login hint naming a declared user (by id, email or NameID) signs in as that user.
        let user = pending.login_hint.as_deref().and_then(|h| state.config.user_for_login(h));
        let (preset, mut identity) = match user {
            Some(user) => user.resolve(None, preset),
            None => {
                let mut identity = preset.default_identity();
                if let Some(hint) = &pending.login_hint {
                    preset.apply_login_hint(&mut identity, hint);
                }
                (preset, identity)
            }
        };
        adapt_name_id(&mut identity, preset, &pending);
        return complete(state, tenant, headers, &pending, preset, sp, identity, None, false);
    }

    // Pending logins stay valid for an hour (and across restarts).
    state.store.put(Table::Pending, &pending.id, &pending, Some(pending.created + 3600));
    render_login(state, tenant, &pending, preset, session.map(|(_, s)| s))
}

/// Use the NameID format the request asked for (`NameIDPolicy/@Format`). An empty NameID is
/// generated later, once the session is known (see [`finish_name_id_for`]).
fn adapt_name_id(identity: &mut Identity, preset: &Preset, pending: &Pending) {
    let Some(format) = pending.name_id_format.clone() else { return };
    if format == identity.name_id_format {
        return;
    }
    identity.name_id = match format.as_str() {
        nameid::EMAIL => preset
            .email_attribute
            .and_then(|a| identity.values(a).into_iter().next())
            .or_else(|| identity.name_id.contains('@').then(|| identity.name_id.clone()))
            .unwrap_or_default(),
        nameid::PERSISTENT | nameid::TRANSIENT => String::new(),
        _ => identity.name_id.clone(),
    };
    identity.name_id_format = format;
}

/// Fill in a NameID left empty: a pairwise persistent ID (stable per user and SP, like Entra ID's
/// and Shibboleth's), or a transient one (new each session).
pub fn finish_name_id_for(identity: &mut Identity, preset: &Preset, sp: &str, session_index: &str) {
    let transient_default = identity.name_id_format == nameid::TRANSIENT && identity.name_id == preset.name_id_example;
    if !identity.name_id.is_empty() && !transient_default {
        return;
    }
    let seed = match identity.name_id_format.as_str() {
        nameid::TRANSIENT => format!("transient:{session_index}:{sp}"),
        _ => {
            let who = preset.derive_name_id(identity).unwrap_or_else(|| identity.describe());
            format!("persistent:{who}:{sp}")
        }
    };
    let digest = Sha256::digest(seed.as_bytes());
    let email = || preset.email_attribute.and_then(|a| identity.values(a).into_iter().next());
    identity.name_id = match identity.name_id_format.as_str() {
        nameid::TRANSIENT => format!("AAdzZWNyZXQx{}", crate::util::b64(&digest[..24])),
        nameid::PERSISTENT => crate::util::b64(digest),
        nameid::EMAIL => {
            email().or_else(|| preset.derive_name_id(identity)).unwrap_or_else(|| preset.name_id_example.into())
        }
        _ => preset.derive_name_id(identity).unwrap_or_else(|| preset.name_id_example.into()),
    };
}

fn validate_attributes(attrs: &Map<String, Value>) -> Result<(), String> {
    for (name, value) in attrs {
        let ok = match value {
            Value::String(_) | Value::Null => true,
            Value::Array(items) => items.iter().all(|v| v.is_string()),
            _ => false,
        };
        if !ok {
            return Err(format!("attribute '{name}' must be a string, a list of strings, or null"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// Signing and encryption for a service provider: its overrides, else the template's behaviour.
pub struct Delivery {
    pub sign_response: bool,
    pub sign_assertion: bool,
    pub sig_alg: crate::keys::SigAlg,
    pub encrypt: Option<(rsa::RsaPublicKey, crate::xmlenc::EncAlg)>,
    pub encrypt_name_id: Option<(rsa::RsaPublicKey, crate::xmlenc::EncAlg)>,
    pub encrypt_attributes: Option<(rsa::RsaPublicKey, crate::xmlenc::EncAlg)>,
}

/// The key and algorithm to encrypt NameIDs (or attributes) for a service provider with.
pub fn name_id_encryption(
    preset: &Preset,
    sp: &ServiceProvider,
) -> Result<(rsa::RsaPublicKey, crate::xmlenc::EncAlg), String> {
    match sp.encryption_key() {
        Some(Ok(key)) => Ok((key, sp.encryption_algorithm.unwrap_or(preset.encryption))),
        Some(Err(e)) => Err(format!("can't encrypt for {}: {e}", sp.label())),
        None => Err(format!("{} has no encryption certificate to encrypt for", sp.label())),
    }
}

pub fn delivery(state: &AppState, preset: &Preset, sp: &ServiceProvider) -> Result<Delivery, String> {
    let encrypt = match sp.encrypt_assertions {
        Some(false) => None,
        explicit => match sp.encryption_key() {
            Some(Ok(key)) if explicit == Some(true) || preset.encrypt_when_possible => {
                Some((key, sp.encryption_algorithm.unwrap_or(preset.encryption)))
            }
            Some(Err(e)) if explicit == Some(true) => return Err(format!("can't encrypt for {}: {e}", sp.label())),
            None if explicit == Some(true) => {
                return Err(format!(
                    "encrypt_assertions is on for {}, but it has no encryption certificate",
                    sp.label()
                ));
            }
            _ => None,
        },
    };
    Ok(Delivery {
        sign_response: sp.sign_response.unwrap_or(preset.sign_response),
        sign_assertion: sp.sign_assertion.unwrap_or(preset.sign_assertion),
        sig_alg: sp.signature_algorithm.unwrap_or(state.config.signature_algorithm),
        encrypt,
        encrypt_name_id: if sp.encrypt_name_id { Some(name_id_encryption(preset, sp)?) } else { None },
        encrypt_attributes: if sp.encrypt_attributes { Some(name_id_encryption(preset, sp)?) } else { None },
    })
}

/// What the spec requires of how a Response with an assertion is delivered (relaxed when lenient):
/// - HTTP-POST and ECP: each assertion signed, or the Response (Profiles 4.1.3.5, 4.2.5).
/// - HTTP-Artifact: a confidential resolution (Profiles 4.1.4.4). Without TLS, the assertion is
///   encrypted for the SP instead.
pub fn spec_delivery(
    state: &AppState,
    tenant: &Tenant,
    preset: &Preset,
    sp: &ServiceProvider,
    binding: &str,
    d: &mut Delivery,
) -> Result<(), String> {
    if state.config.lenient {
        return Ok(());
    }
    if binding != "artifact" && !d.sign_response && !d.sign_assertion {
        return Err(format!(
            "neither the Response nor the assertion would be signed for {}, but assertions delivered by HTTP-POST or ECP must be (Profiles 4.1.3.5). Set sign_response or sign_assertion, or run with lenient = true.",
            sp.label()
        ));
    }
    if binding == "artifact" && !tenant.base.starts_with("https://") && d.encrypt.is_none() {
        let refuse = |why: &str| {
            Err(format!(
                "a Response sent by HTTP-Artifact must be resolved confidentially (Profiles 4.1.4.4), and localsaml isn't served over https, so its assertion has to be encrypted, but {why}. Serve localsaml over https, or run with lenient = true."
            ))
        };
        if sp.encrypt_assertions == Some(false) {
            return refuse(&format!("encrypt_assertions is off for {}", sp.label()));
        }
        match sp.encryption_key() {
            Some(Ok(key)) => d.encrypt = Some((key, sp.encryption_algorithm.unwrap_or(preset.encryption))),
            Some(Err(e)) => return refuse(&format!("{}'s encryption certificate is unusable ({e})", sp.label())),
            None => return refuse(&format!("{} has no encryption certificate", sp.label())),
        }
    }
    Ok(())
}

/// Send a Response with an error status to the service provider.
pub fn respond_status(
    state: &AppState,
    tenant: &Tenant,
    preset: &'static Preset,
    sp: &ServiceProvider,
    pending: &Pending,
    status: Status,
) -> Response {
    let identity = preset.default_identity();
    // No assertion, so nothing to encrypt: only the signing settings matter.
    let sign_response = sp.sign_response.unwrap_or(preset.sign_response);
    let sig_alg = sp.signature_algorithm.unwrap_or(state.config.signature_algorithm);
    let spec = ResponseSpec {
        preset,
        issuer: tenant.entity_id.clone(),
        identity: &identity,
        destination: pending.acs_url.clone(),
        audience: pending.audience.clone(),
        in_response_to: pending.request_id.clone(),
        session_index: String::new(),
        assertion_id: None,
        auth_time: state.now(),
        now: state.now(),
        sign_response,
        sign_assertion: false,
        sig_alg,
        encrypt: None,
        encrypt_name_id: None,
        encrypt_attributes: None,
        lifetime: None,
        authn_context: String::new(),
        sp_name_qualifier: None,
        status: Some(status.clone()),
        tampers: vec![],
        attribute_query: false,
    };
    let issued = match state.keys.with_current(|key| saml::build_response(key, &spec)) {
        Ok(i) => i,
        Err(e) => return error_page(tenant, StatusCode::INTERNAL_SERVER_ERROR, "Couldn't build the Response", &e),
    };
    deliver(state, tenant, pending, &issued.xml, issued.pretty, "Response", Some(&status), false)
}

/// Issue the Response for an authenticated user and post it to the service provider (or show it
/// for review first).
#[allow(clippy::too_many_arguments)]
pub fn complete(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    pending: &Pending,
    preset: &'static Preset,
    sp: &ServiceProvider,
    mut identity: Identity,
    existing: Option<(String, Session)>,
    review: bool,
) -> Response {
    let now = state.now();
    let existing =
        existing.or_else(|| current_session(state, tenant, headers).filter(|(_, s)| s.tenant == tenant.key()));
    // Re-use the session (and its SessionIndex) in this browser; a fresh login (ForceAuthn, or a
    // different identity) restarts the authentication time.
    let (sid, mut session) = match existing {
        Some((sid, mut s)) => {
            if pending.force_authn || s.identity != identity {
                s.auth_time = now;
            }
            (sid, s)
        }
        None => (
            uuid::Uuid::new_v4().to_string(),
            Session {
                tenant: tenant.key().into(),
                issuer: tenant.entity_id.clone(),
                identity: identity.clone(),
                auth_time: now,
                session_index: preset.style.id_style.generate(),
                participants: vec![],
            },
        ),
    };
    session.identity = identity.clone();
    finish_name_id_for(&mut identity, preset, &pending.sp, &session.session_index);
    // An AuthnRequest naming a Subject only gets an assertion if the user signed in as that
    // subject; otherwise an error and no assertion (Profiles 4.1.4.1).
    if let Some(subject) = &pending.subject {
        let format_matches =
            pending.subject_format.as_ref().is_none_or(|f| f == nameid::UNSPECIFIED || *f == identity.name_id_format);
        if identity.name_id != *subject || !format_matches {
            let message = format!(
                "the request is for '{subject}', but the user signed in as '{}' ({})",
                identity.name_id, identity.name_id_format
            );
            return respond_status(
                state,
                tenant,
                preset,
                sp,
                pending,
                Status::parse("UnknownPrincipal", Some(message)).unwrap(),
            );
        }
    }
    session.participants.retain(|p| p.entity_id != pending.sp);
    // Templates differ in what they use as the SessionIndex; logout sends each SP back its own.
    let assertion_id = saml::new_assertion_id(&preset.style);
    let session_index = match preset.session_index {
        SessionIndexStyle::Session => session.session_index.clone(),
        SessionIndexStyle::AssertionId => assertion_id.clone(),
        SessionIndexStyle::RequestId => pending.request_id.clone().unwrap_or_else(|| session.session_index.clone()),
    };
    session.participants.push(Participant {
        entity_id: pending.sp.clone(),
        name_id: identity.name_id.clone(),
        name_id_format: identity.name_id_format.clone(),
        sp_name_qualifier: pending.sp_name_qualifier.clone(),
        session_index: session_index.clone(),
        name_id_encrypted: pending.encrypt_name_id || sp.encrypt_name_id,
    });
    state.store.put(Table::Sessions, &sid, &session, Some(now + state.config.session_ttl));

    let replay = pending.tampers.contains(&Tamper::Replay);
    let previous = replay.then(|| state.last_responses.lock().unwrap().get(&pending.sp).cloned()).flatten();
    let (xml, pretty) = match previous {
        Some(prev) => (prev.xml, prev.pretty),
        None => {
            let mut d = match delivery(state, preset, sp) {
                Ok(d) => d,
                Err(e) => return saml_error_page(tenant, "Can't send the Response", &e),
            };
            if pending.encrypt_name_id && d.encrypt_name_id.is_none() {
                match name_id_encryption(preset, sp) {
                    Ok(e) => d.encrypt_name_id = Some(e),
                    Err(e) => return saml_error_page(tenant, "Can't send the Response", &e),
                }
            }
            if let Err(e) = spec_delivery(state, tenant, preset, sp, &pending.response_binding, &mut d) {
                return saml_error_page(tenant, "Can't send the Response", &e);
            }
            let authn_context = pending
                .authn_context
                .clone()
                .or_else(|| pending.requested_authn_contexts.first().cloned())
                .unwrap_or_else(|| preset.authn_context.to_string());
            let spec = ResponseSpec {
                preset,
                issuer: tenant.entity_id.clone(),
                identity: &identity,
                destination: pending.acs_url.clone(),
                audience: pending.audience.clone(),
                in_response_to: pending.request_id.clone(),
                session_index,
                assertion_id: Some(assertion_id),
                auth_time: session.auth_time,
                now,
                sign_response: d.sign_response,
                sign_assertion: d.sign_assertion,
                sig_alg: d.sig_alg,
                encrypt: d.encrypt,
                encrypt_name_id: d.encrypt_name_id,
                encrypt_attributes: d.encrypt_attributes,
                lifetime: state.config.assertion_ttl,
                authn_context,
                sp_name_qualifier: pending.sp_name_qualifier.clone(),
                status: None,
                tampers: pending.tampers.clone(),
                attribute_query: false,
            };
            match state.keys.with_current(|key| saml::build_response(key, &spec)) {
                Ok(issued) => (issued.xml, issued.pretty),
                Err(e) => {
                    return error_page(tenant, StatusCode::INTERNAL_SERVER_ERROR, "Couldn't build the Response", &e);
                }
            }
        }
    };
    if !replay {
        state.last_responses.lock().unwrap().insert(
            pending.sp.clone(),
            LastResponse {
                acs_url: pending.acs_url.clone(),
                xml: xml.clone(),
                pretty: pretty.clone(),
                relay_state: pending.relay_state.clone(),
            },
        );
    }

    let kind = if pending.tampers.is_empty() {
        "Response".to_string()
    } else {
        format!("Response [{}]", pending.tampers.iter().map(|t| t.name()).collect::<Vec<_>>().join(", "))
    };
    let mut resp = deliver(state, tenant, pending, &xml, pretty, &kind, None, review);
    set_cookie(&mut resp, &session_cookie(tenant, &sid, state.config.session_ttl));
    resp
}

/// How long an artifact can be resolved for.
const ARTIFACT_TTL: i64 = 300;

/// Keep a Response for the HTTP-Artifact binding and return the artifact standing for it.
pub fn store_artifact(state: &AppState, tenant: &Tenant, sp: &str, xml: &str) -> String {
    let artifact = saml::new_artifact(&tenant.entity_id, 0);
    let stored = StoredArtifact { sp: sp.to_string(), xml: xml.to_string() };
    state.store.put(Table::Artifacts, &artifact, &stored, Some(state.now() + ARTIFACT_TTL));
    artifact
}

/// Send a Response to the service provider with the login's binding: auto-posted (HTTP-POST), or
/// a redirect carrying an artifact the SP resolves over SOAP (HTTP-Artifact); or show it first.
#[allow(clippy::too_many_arguments)]
fn deliver(
    state: &AppState,
    tenant: &Tenant,
    pending: &Pending,
    xml: &str,
    pretty: String,
    kind: &str,
    status: Option<&Status>,
    review: bool,
) -> Response {
    let (mut resp, binding) = if pending.response_binding == "paos" {
        let response = match crate::xml::parse(xml) {
            Ok(r) => r,
            Err(e) => return crate::soap::fault(false, &e),
        };
        let header = Element::new(saml::NS_ECP, "ecp", "Response")
            .ns_attr(crate::soap::NS_SOAP, "soap11", "mustUnderstand", "1")
            .ns_attr(crate::soap::NS_SOAP, "soap11", "actor", "http://schemas.xmlsoap.org/soap/actor/next")
            .attr("AssertionConsumerServiceURL", &pending.acs_url);
        let body = crate::soap::envelope_with_header(Some(header), response);
        let resp = (crate::soap::RESPONSE_HEADERS, body).into_response();
        (resp, "paos")
    } else if pending.response_binding == "artifact" {
        let artifact = store_artifact(state, tenant, &pending.sp, xml);
        let mut url = url::Url::parse(&pending.acs_url).expect("the ACS URL was checked");
        url.query_pairs_mut().append_pair("SAMLart", &artifact);
        if let Some(r) = pending.relay_state.as_deref().filter(|r| !r.is_empty()) {
            url.query_pairs_mut().append_pair("RelayState", r);
        }
        let resp = if review {
            review_page(
                tenant,
                pending,
                "redirected (with an artifact the service provider resolves over SOAP) to",
                Send::Link(url.to_string()),
                ("Artifact", &artifact),
                &pretty,
            )
        } else {
            crate::html::saml_redirect(url.as_str())
        };
        (resp, "artifact")
    } else {
        let encoded = b64_std(xml);
        let resp = if review {
            let mut fields = vec![("SAMLResponse".to_string(), encoded.clone())];
            if let Some(r) = &pending.relay_state {
                fields.push(("RelayState".to_string(), r.clone()));
            }
            review_page(tenant, pending, "posted to", Send::Post(fields), ("Base64 SAMLResponse", &encoded), &pretty)
        } else {
            saml_post(&pending.acs_url, "SAMLResponse", &encoded, pending.relay_state.as_deref()).into_response()
        };
        (resp, "post")
    };
    SamlNote::sent(&pending.sp, kind, binding, &pending.acs_url, pretty, status).attach(&mut resp);
    resp
}

/// How a reviewed Response is sent: a form posted to the ACS, or a link carrying an artifact.
enum Send {
    Post(Vec<(String, String)>),
    Link(String),
}

/// The Response, before it's sent (the login form's "Review the response before sending it").
fn review_page(
    tenant: &Tenant,
    pending: &Pending,
    how: &str,
    send: Send,
    detail: (&str, &str),
    pretty: &str,
) -> Response {
    let sp = pending.sp_name.as_deref().unwrap_or(&pending.sp);
    let (send_json, send_html) = match &send {
        Send::Post(fields) => {
            let inputs: String = fields
                .iter()
                .map(|(k, v)| format!(r#"<input type="hidden" name="{}" value="{}">"#, esc(k), esc(v)))
                .collect();
            (
                json!({
                    "kind": "post",
                    "action": pending.acs_url,
                    "fields": fields.iter().cloned().collect::<HashMap<_, _>>(),
                }),
                format!(
                    r#"<form method="POST" action="{}">{inputs}<button type="submit" {PRIMARY_BUTTON}>Send to the service provider</button></form>"#,
                    esc(&pending.acs_url)
                ),
            )
        }
        Send::Link(url) => (
            json!({ "kind": "link", "url": url }),
            format!(r#"<p><a href="{}" {PRIMARY_BUTTON}>Send the artifact to the service provider</a></p>"#, esc(url)),
        ),
    };
    let view = json!({
        "kind": "review",
        "sp": sp,
        "acs": pending.acs_url,
        "how": how,
        "send": send_json,
        "xml": pretty,
        "detail": { "label": detail.0, "value": detail.1 },
    });
    let fallback = card(&format!(
        r#"<div style="color:var(--muted-foreground);font-size:.75rem;font-weight:500">Review</div><h1>Response for {}</h1><p>This is what will be {} {}. Nothing has been sent yet.</p>{send_html}{}{}"#,
        esc(sp),
        esc(how),
        esc(&pending.acs_url),
        xml_block("SAML Response", pretty),
        xml_block(detail.0, detail.1),
    ));
    shell(tenant, StatusCode::OK, "Review response", view, &fallback)
}

// ---------------------------------------------------------------------------
// IdP-initiated SSO
// ---------------------------------------------------------------------------

/// `/sso/initiate?sp=<entity ID>[&RelayState=…][&acs=…]`: send an unsolicited Response.
pub async fn initiate(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let params = parse_form(query.unwrap_or_default().as_bytes());
    match sp_param(&params) {
        Some(sp) => start_idp_initiated(&state, &tenant, &headers, &sp, &params).await,
        None => pick_sp_page(&state, &tenant),
    }
}

/// IdP-initiated SSO with the service provider named in the path (Keycloak's
/// `/clients/{client}`): the SP declared with that `idp_initiated_name`.
pub async fn initiate_named(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    axum::extract::Path(path): axum::extract::Path<HashMap<String, String>>,
    RawQuery(query): RawQuery,
) -> Response {
    let name = path.get("client").cloned().unwrap_or_default();
    let params = parse_form(query.unwrap_or_default().as_bytes());
    let sp = state.service_providers().into_iter().find(|sp| sp.idp_initiated_name.as_deref() == Some(name.as_str()));
    match sp {
        Some(sp) => start_idp_initiated(&state, &tenant, &headers, &sp.entity_id, &params).await,
        None => saml_error_page(
            &tenant,
            "Unknown client",
            &format!("No service provider is declared with idp_initiated_name = \"{name}\"."),
        ),
    }
}

async fn start_idp_initiated(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    entity_id: &str,
    params: &HashMap<String, String>,
) -> Response {
    let bad = |title: &str, detail: &str| saml_error_page(tenant, title, detail);
    let sp = match find_sp(state, tenant, entity_id).await {
        Some(sp) => sp,
        None => match non_empty(params, "acs") {
            // Lenient: unknown SPs work too, given an ACS URL (which can't be verified).
            Some(acs) if state.config.lenient => ServiceProvider {
                entity_id: entity_id.into(),
                acs_urls: vec![acs],
                source: "request".into(),
                ..Default::default()
            },
            _ => match resolve_sp(state, tenant, entity_id).await {
                Ok(sp) => sp,
                Err(e) => return bad("Unknown service provider", &e),
            },
        },
    };
    let binding = non_empty(params, "binding").filter(|b| b == "post" || b == "artifact");
    // `shire` and `target` are Shibboleth's names for the ACS URL and RelayState, `TargetResource`
    // PingFederate's for the RelayState.
    let explicit_acs = non_empty(params, "acs").or_else(|| non_empty(params, "shire"));
    let acs_url = match explicit_acs
        .clone()
        .or_else(|| sp.default_acs(binding.as_deref().unwrap_or(sp.default_binding())).cloned())
    {
        Some(a) if !crate::util::is_web_url(&a) => {
            return bad("Invalid ACS URL", &format!("'{a}' is not an absolute http(s) URL."));
        }
        Some(a) if acs_allowed(state, &sp, &a) => a,
        Some(a) => return bad("Unregistered ACS URL", &format!("'{a}' isn't one of {}'s ACS URLs.", sp.label())),
        None => {
            return bad("No ACS URL", &format!("{} has no ACS URL to send an unsolicited Response to.", sp.label()));
        }
    };
    let relay_state = non_empty(params, "RelayState")
        .or_else(|| non_empty(params, "TargetResource"))
        .or_else(|| non_empty(params, "target"))
        .or(sp.default_relay_state.clone());
    if let Some(r) = relay_state.as_ref().filter(|r| r.len() > 80 && !state.config.lenient) {
        return bad(
            "RelayState too long",
            &format!("RelayState is {} bytes; the bindings allow at most 80 (Bindings 3.5.3).", r.len()),
        );
    }
    let response_binding = if explicit_acs.is_some() {
        binding.or_else(|| sp.acs_binding(&acs_url).map(String::from))
    } else {
        sp.acs_binding(&acs_url).map(String::from).or(binding)
    }
    .unwrap_or_else(|| sp.default_binding().to_string());
    let preset = preset_for(state, tenant, &sp);
    let pending = Pending {
        id: uuid::Uuid::new_v4().to_string(),
        created: state.now(),
        tenant: tenant.key().into(),
        sp: sp.entity_id.clone(),
        sp_name: sp.name.clone(),
        acs_url,
        audience: sp.audience(),
        request_id: None,
        relay_state,
        force_authn: false,
        is_passive: false,
        name_id_format: None,
        encrypt_name_id: false,
        sp_name_qualifier: None,
        requested_authn_contexts: vec![],
        authn_context: None,
        login_hint: non_empty(params, "login_hint"),
        subject: None,
        subject_format: None,
        binding: "idp-initiated".into(),
        response_binding,
        signature: "no request (IdP-initiated)".into(),
        warnings: vec![],
        tampers: vec![],
        request_xml: None,
    };
    proceed(state, tenant, headers, preset, &sp, pending, params).await
}

fn pick_sp_page(state: &AppState, tenant: &Tenant) -> Response {
    let mut sps = state.service_providers();
    sps.insert(0, crate::routes::testsp::service_provider(state, tenant));
    let sps: Vec<Value> = sps
        .iter()
        .filter(|sp| !sp.acs_urls.is_empty())
        .map(|sp| {
            json!({
                "label": sp.label(),
                "entity_id": sp.entity_id,
                "href": format!("{}?sp={}", tenant.path("/sso/initiate"), crate::dsig::urlencode(&sp.entity_id)),
            })
        })
        .collect();
    let text = |v: &Value, k: &str| esc(v[k].as_str().unwrap_or_default());
    let items: String = sps
        .iter()
        .map(|sp| {
            format!(
                r#"<li><a href="{}">{}</a> <code>{}</code></li>"#,
                text(sp, "href"),
                text(sp, "label"),
                text(sp, "entity_id")
            )
        })
        .collect();
    let detail = "Sends an unsolicited Response (no AuthnRequest) to the service provider's default ACS URL. Link here with ?sp=<entity ID> and optionally RelayState.";
    let fallback = crate::html::titled_card("IdP-initiated login", "Sign in to…", detail, &format!("<ul>{items}</ul>"));
    shell(tenant, StatusCode::OK, "IdP-initiated login", json!({ "kind": "pick-sp", "sps": sps }), &fallback)
}

// ---------------------------------------------------------------------------
// Login UI
// ---------------------------------------------------------------------------

/// Data for the identity wizard (login and assertion generator pages).
pub fn editor_data(
    state: &AppState,
    tenant: &Tenant,
    mode: &str,
    preset: &'static Preset,
    previous: Option<&Session>,
    extra: Value,
) -> Value {
    let mut data = json!({
        "mode": mode,
        "entityId": tenant.entity_id,
        "prefix": tenant.prefix,
        "presets": presets::all(),
        "defaultPreset": preset.id,
        "tenantPreset": tenant.preset.map(|p| p.id),
        "nameIdFormats": nameid::ALL,
        "previous": previous.map(|s| &s.identity),
        "users": state.config.users.iter().map(|u| u.to_json(preset)).collect::<Vec<_>>(),
    });
    if let (Value::Object(d), Value::Object(e)) = (&mut data, extra) {
        d.extend(e);
    }
    data
}

fn render_login(
    state: &AppState,
    tenant: &Tenant,
    pending: &Pending,
    preset: &'static Preset,
    previous: Option<Session>,
) -> Response {
    let mut chips = vec![json!({
        "label": if pending.binding == "idp-initiated" { "IdP-initiated" } else { &pending.binding },
        "tone": "",
    })];
    if pending.force_authn {
        chips.push(json!({ "label": "ForceAuthn", "tone": "warn" }));
    }
    if pending.signature.contains("verified") && !pending.signature.contains("not verified") {
        chips.push(json!({ "label": "signed", "tone": "ok" }));
    }
    // Code-like values are shown in a monospace font.
    let mut details = vec![
        json!({ "label": "Service provider", "value": pending.sp, "code": true }),
        json!({ "label": "ACS URL", "value": pending.acs_url, "code": true }),
        json!({ "label": "Binding", "value": pending.binding, "code": true }),
        json!({ "label": "Signature", "value": pending.signature, "code": false }),
    ];
    let contexts = pending.requested_authn_contexts.join(" ");
    for (label, value) in [
        ("Request ID", pending.request_id.as_ref()),
        ("NameIDPolicy", pending.name_id_format.as_ref()),
        ("AuthnContext", Some(&contexts).filter(|c| !c.is_empty())),
        ("RelayState", pending.relay_state.as_ref()),
        ("Subject", pending.subject.as_ref()),
        ("Login hint", pending.login_hint.as_ref()),
    ] {
        if let Some(v) = value {
            details.push(json!({ "label": label, "value": v, "code": true }));
        }
    }
    if !pending.tampers.is_empty() {
        let faults = pending.tampers.iter().map(|t| format!("{} ({})", t.name(), t.describe())).collect::<Vec<_>>();
        details.push(json!({ "label": "Faults", "value": faults.join(", "), "code": false }));
    }
    details.push(json!({ "label": "Issuer", "value": tenant.entity_id, "code": true }));

    let title = pending.sp_name.as_deref().unwrap_or(&pending.sp);
    let action = tenant.path("/login");
    let view = json!({
        "kind": "login",
        "action": action,
        "req": pending.id,
        "sp": title,
        "chips": chips,
        "details": details,
        "warnings": pending.warnings,
        "requestXml": pending.request_xml,
        "editor": editor_data(
            state,
            tenant,
            "login",
            preset,
            previous.as_ref(),
            json!({
                "loginHint": pending.login_hint,
                "subject": pending.subject.as_ref().map(|s| json!({ "nameId": s, "format": pending.subject_format })),
                "requestedNameIdFormat": pending.name_id_format,
            }),
        ),
    });
    // Without JavaScript (and for the interop harness and the conformance kit, which post it
    // unchanged), signing in uses the template's default identity.
    let form = format!(
        r#"<form method="post" action="{action}" id="lo-form"><input type="hidden" name="req" value="{req_id}"><input type="hidden" name="preset"><input type="hidden" name="identity">
<p style="display:flex;gap:.5rem;align-items:center;flex-wrap:wrap"><button type="submit" name="action" value="approve" {PRIMARY_BUTTON}>Sign in</button> <button type="submit" name="action" value="deny" {BUTTON}>Deny</button>
<label><input type="checkbox" name="review" value="1"> Review the response before sending it</label></p></form>"#,
        action = esc(&action),
        req_id = esc(&pending.id),
    );
    let fallback = crate::html::titled_card(
        "Authentication request",
        &format!("Sign in to {title}"),
        &format!(
            "Service provider {} · ACS {}. Signing in uses the template's default identity; the attribute editor needs JavaScript.",
            pending.sp, pending.acs_url
        ),
        &form,
    );
    shell(tenant, StatusCode::OK, "Sign in", view, &fallback)
}

/// Parse the wizard's hidden fields into an identity.
pub fn editor_submission(
    form: &HashMap<String, String>,
    fallback: &'static Preset,
) -> Result<(&'static Preset, Identity), String> {
    let preset = form.get("preset").and_then(|p| presets::get(p)).unwrap_or(fallback);
    let raw = form.get("identity").map(String::as_str).unwrap_or("").trim();
    if raw.is_empty() {
        return Ok((preset, preset.default_identity()));
    }
    let v = parse_json_object(raw)?;
    let attributes = match v.get("attributes") {
        Some(Value::Object(m)) => m.clone(),
        None => Map::new(),
        Some(_) => return Err("attributes must be a JSON object".into()),
    };
    validate_attributes(&attributes)?;
    let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::trim).unwrap_or("").to_string();
    let format = text("name_id_format");
    Ok((
        preset,
        Identity {
            preset: preset.id.into(),
            name_id: text("name_id"),
            name_id_format: if format.is_empty() { preset.name_id_format.into() } else { format },
            attributes,
        },
    ))
}

pub async fn login(State(state): State<AppState>, tenant: Tenant, headers: HeaderMap, body: Bytes) -> Response {
    let form = parse_form(&body);
    let req_id = form.get("req").cloned().unwrap_or_default();
    let Some(pending) = state.store.take::<Pending>(Table::Pending, &req_id) else {
        return saml_error_page(
            &tenant,
            "Login request expired",
            "This sign-in request is no longer valid. Start the login again from your application.",
        );
    };
    if pending.tenant != tenant.key() {
        return saml_error_page(
            &tenant,
            "Wrong identity provider",
            "This sign-in request was started at another of localsaml's identity providers. Start the login again.",
        );
    }
    let sp = match resolve_sp(&state, &tenant, &pending.sp).await {
        Ok(sp) => sp,
        Err(e) => return saml_error_page(&tenant, "Unknown service provider", &e),
    };
    let fallback = preset_for(&state, &tenant, &sp);
    if form.get("action").map(String::as_str) == Some("deny") {
        let status = Status::parse("RequestDenied", Some("the user denied the request".into())).unwrap();
        return respond_status(&state, &tenant, fallback, &sp, &pending, status);
    }
    let (preset, identity) = match editor_submission(&form, fallback) {
        Ok(v) => v,
        Err(e) => return saml_error_page(&tenant, "Invalid identity", &e),
    };
    let review = form.get("review").is_some_and(|v| v == "1");
    complete(&state, &tenant, &headers, &pending, preset, &sp, identity, None, review)
}

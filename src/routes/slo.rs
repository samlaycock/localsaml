//! Single logout. A LogoutRequest from one service provider (or `/slo/initiate`) ends the session,
//! then every other service provider that got an assertion during it is sent a LogoutRequest in
//! turn, over front-channel redirects, before the initiator gets its LogoutResponse. Service
//! providers with only a SOAP SingleLogoutService are logged out back-channel along the way, and
//! SOAP LogoutRequests (and `DELETE /dev/api/sessions/{sid}`) log everyone out back-channel.

use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};

use crate::faults::{self, Endpoint};
use crate::html::{esc, page, saml_error_page, saml_post};
use crate::inspector::{Message, SamlNote};
use crate::presets::{Preset, Style};
use crate::routes::sso::{
    Arrival, SigCheck, check_signature, clear_session_cookie, current_session, find_sp, resolve_sp, set_cookie,
};
use crate::saml::{self, LogoutRequest, LogoutRequestSpec, LogoutResponse, Status};
use crate::sp::ServiceProvider;
use crate::state::{AppState, Initiator, Logout, Participant, Session};
use crate::store::Table;
use crate::tenant::Tenant;
use crate::util::{b64_std, non_empty, parse_form};
use crate::xml::Element;

/// How long a logout may wait on a service provider before it's forgotten.
const LOGOUT_TTL: i64 = 600;

fn preset(state: &AppState, tenant: &Tenant) -> &'static Preset {
    tenant.default_preset(&state.config)
}

/// Send a logout message to a service provider with its SLO binding, signed.
#[allow(clippy::too_many_arguments)]
fn send(
    state: &AppState,
    style: &Style,
    sp: &ServiceProvider,
    location: &str,
    param: &str,
    mut message: Element,
    id: &str,
    relay_state: Option<&str>,
    status: Option<&Status>,
) -> Response {
    let alg = sp.signature_algorithm.unwrap_or(state.config.signature_algorithm);
    let kind = message.local.clone();
    let mut resp = if sp.slo_post() {
        if let Err(e) = state.keys.with_current(|key| saml::sign_message(&mut message, id, key, style, alg)) {
            return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
        }
        saml_post(location, param, &b64_std(message.to_xml()), relay_state).into_response()
    } else {
        let url = state
            .keys
            .with_current(|key| saml::redirect_url(location, param, &message.to_xml(), relay_state, Some((key, alg))));
        Redirect::to(&url).into_response()
    };
    let binding = if sp.slo_post() { "post" } else { "redirect" };
    SamlNote::sent(&sp.entity_id, &kind, binding, location, message.to_pretty(), status).attach(&mut resp);
    resp
}

/// Answer a service provider's LogoutRequest.
fn respond(
    state: &AppState,
    tenant: &Tenant,
    sp: &ServiceProvider,
    request_id: &str,
    relay_state: Option<&str>,
    status: Status,
) -> Response {
    let Some(location) = sp.slo_response_url.clone().or(sp.slo_url.clone()) else {
        let mut resp = saml_error_page(
            tenant,
            "Nowhere to send the LogoutResponse",
            &format!(
                "{} sent a LogoutRequest but has no SingleLogoutService. The session was ended; declare slo_url (or metadata) for the service provider to get a LogoutResponse.",
                sp.label()
            ),
        );
        set_cookie(&mut resp, &clear_session_cookie(tenant));
        return resp;
    };
    let style = &preset(state, tenant).style;
    let (message, id) =
        saml::logout_response(style, &tenant.entity_id, &location, Some(request_id), &status, state.now());
    send(state, style, sp, &location, "SAMLResponse", message, &id, relay_state, Some(&status))
}

/// Fill in a LogoutRequest's NameID from its `EncryptedID` (encrypted for localsaml's key).
fn decrypt_name_id(state: &AppState, req: &mut LogoutRequest, root: &Element) -> Result<(), String> {
    if !req.name_id_encrypted {
        return Ok(());
    }
    let encrypted = root
        .find_by_id(&req.id)
        .and_then(|m| m.find(saml::NS_ASSERTION, "EncryptedID"))
        .ok_or("the EncryptedID is missing")?;
    let name_id = saml::decrypt_id(encrypted, &state.keys.private_keys())
        .map_err(|e| format!("can't decrypt the EncryptedID: {e}"))?;
    req.name_id = Some(name_id.value());
    req.name_id_format = name_id.get_attr("Format").map(String::from);
    Ok(())
}

/// A LogoutRequest from a service provider.
pub async fn logout_request(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    mut req: LogoutRequest,
    root: &Element,
    arrival: Arrival,
) -> Response {
    let bad = |title: &str, detail: &str| saml_error_page(tenant, title, detail);
    let p = preset(state, tenant);
    if !p.single_logout {
        return bad("Single logout isn't supported", &format!("{} doesn't do SAML single logout.", p.name));
    }
    let Some(issuer) = req.issuer.clone() else {
        return bad("LogoutRequest has no Issuer", "The request must name the service provider in <saml:Issuer>.");
    };
    let sp = match resolve_sp(state, tenant, &issuer).await {
        Ok(sp) => sp,
        Err(e) => return bad("Unknown service provider", &e),
    };
    match check_signature(&sp, root, &req.id, arrival.query_signature.as_ref()) {
        SigCheck::Invalid(e) => return bad("Invalid LogoutRequest signature", &e),
        SigCheck::Unsigned if sp.want_logout_signed => {
            return bad(
                "Unsigned LogoutRequest",
                &format!("{} must sign its logout messages (want_logout_signed).", sp.label()),
            );
        }
        _ => {}
    }
    if let Err(e) = decrypt_name_id(state, &mut req, root) {
        let status = Status::parse("Requester", Some(e)).unwrap();
        return respond(state, tenant, &sp, &req.id, arrival.relay_state.as_deref(), status);
    }
    let target = faults::Target { endpoint: Endpoint::Slo, issuer: tenant.key(), sp: Some(&sp.entity_id) };
    if let Some(fault) = state.faults.take(&target) {
        fault.wait().await;
        if let Some(status) = fault.status_with_default_message() {
            return respond(state, tenant, &sp, &req.id, arrival.relay_state.as_deref(), status);
        }
    }

    // The browser's session, or the one the request's SessionIndex names.
    let session = current_session(state, tenant, headers).or_else(|| {
        state
            .store
            .entries::<Session>(Table::Sessions)
            .into_iter()
            .find(|(_, s, _)| {
                s.tenant == tenant.key()
                    && (req.session_indexes.contains(&s.session_index)
                        || s.participants.iter().any(|p| req.session_indexes.contains(&p.session_index)))
            })
            .map(|(sid, s, _)| (sid, s))
    });
    let Some((sid, session)) = session else {
        // Already logged out: that's still a successful logout.
        let mut resp = respond(state, tenant, &sp, &req.id, arrival.relay_state.as_deref(), Status::success());
        set_cookie(&mut resp, &clear_session_cookie(tenant));
        return resp;
    };
    state.store.remove(Table::Sessions, &sid);
    let logout = Logout {
        id: uuid::Uuid::new_v4().to_string(),
        tenant: tenant.key().into(),
        issuer: tenant.entity_id.clone(),
        who: session.identity.describe(),
        session_index: session.session_index.clone(),
        initiator: Some(Initiator {
            entity_id: sp.entity_id.clone(),
            request_id: req.id.clone(),
            relay_state: arrival.relay_state.clone(),
        }),
        remaining: session.participants.iter().filter(|p| p.entity_id != sp.entity_id).cloned().collect(),
        waiting_on: None,
        results: vec![],
        return_to: None,
    };
    let mut resp = advance(state, tenant, logout).await;
    set_cookie(&mut resp, &clear_session_cookie(tenant));
    resp
}

/// The LogoutRequest for a participant: the NameID (encrypted if theirs was) and SessionIndex
/// they were given.
fn participant_logout_request(
    state: &AppState,
    tenant: &Tenant,
    sp: &ServiceProvider,
    destination: &str,
    participant: &Participant,
    session_index: &str,
) -> Result<(Element, String), String> {
    let p = preset(state, tenant);
    let encryption =
        if participant.name_id_encrypted { Some(crate::routes::sso::name_id_encryption(p, sp)?) } else { None };
    saml::logout_request(&LogoutRequestSpec {
        style: &p.style,
        issuer: &tenant.entity_id,
        destination,
        name_id: &participant.name_id,
        name_id_format: &participant.name_id_format,
        sp_name_qualifier: participant.sp_name_qualifier.as_deref(),
        session_index: if participant.session_index.is_empty() { session_index } else { &participant.session_index },
        now: state.now(),
        encrypt: encryption.as_ref().map(|(key, alg)| (key, *alg)),
    })
}

/// Ask the next service provider to log out, or finish.
async fn advance(state: &AppState, tenant: &Tenant, mut logout: Logout) -> Response {
    while let Some(participant) = (!logout.remaining.is_empty()).then(|| logout.remaining.remove(0)) {
        let Some(sp) = find_sp(state, tenant, &participant.entity_id).await else {
            logout.results.push((participant.entity_id, "not notified: no longer registered".into()));
            continue;
        };
        let Some(location) = sp.slo_url.clone() else {
            // No front-channel endpoint: a SOAP one is called from here, while the browser waits.
            let outcome = match &sp.slo_soap_url {
                Some(url) => back_channel(state, tenant, &sp, url, &participant, &logout.session_index).await,
                None => "not notified: no SingleLogoutService".into(),
            };
            logout.results.push((participant.entity_id, outcome));
            continue;
        };
        let style = &preset(state, tenant).style;
        let (message, id) =
            match participant_logout_request(state, tenant, &sp, &location, &participant, &logout.session_index) {
                Ok(m) => m,
                Err(e) => {
                    logout.results.push((participant.entity_id, format!("failed: {e}")));
                    continue;
                }
            };
        logout.waiting_on = Some((sp.entity_id.clone(), id.clone()));
        state.store.put(Table::Logouts, &logout.id, &logout, Some(state.now() + LOGOUT_TTL));
        return send(state, style, &sp, &location, "SAMLRequest", message, &id, Some(&logout.id), None);
    }
    finish(state, tenant, logout).await
}

async fn finish(state: &AppState, tenant: &Tenant, logout: Logout) -> Response {
    state.store.remove(Table::Logouts, &logout.id);
    let partial = logout.results.iter().any(|(_, r)| !r.starts_with("logged out"));
    if let Some(initiator) = &logout.initiator {
        let sp = find_sp(state, tenant, &initiator.entity_id)
            .await
            .unwrap_or_else(|| ServiceProvider { entity_id: initiator.entity_id.clone(), ..Default::default() });
        let status = if partial {
            Status::parse("PartialLogout", Some("some service providers couldn't be logged out".into())).unwrap()
        } else {
            Status::success()
        };
        return respond(state, tenant, &sp, &initiator.request_id, initiator.relay_state.as_deref(), status);
    }
    let rows: String = logout
        .results
        .iter()
        .map(|(sp, outcome)| {
            let class = if outcome == "logged out" { "ok" } else { "muted" };
            format!(
                r#"<li><span><code>{}</code></span><span class="chip {class}">{}</span></li>"#,
                esc(sp),
                esc(outcome)
            )
        })
        .collect();
    let list = if rows.is_empty() {
        r#"<p class="muted">No other service providers were signed in.</p>"#.to_string()
    } else {
        format!(r#"<ul class="fault-list">{rows}</ul>"#)
    };
    let back = logout
        .return_to
        .as_ref()
        .map(|r| format!(r#"<div class="actions"><a class="btn" href="{}">Continue</a></div>"#, esc(r)))
        .unwrap_or_default();
    let body = format!(
        r#"<section class="card narrow"><div class="eyebrow">Single logout</div><h1>Signed out <span class="accent">{}</span></h1>{list}{back}</section>"#,
        esc(&logout.who)
    );
    page(tenant, "Signed out", &body).into_response()
}

/// A LogoutResponse from a service provider we asked to log out.
pub async fn logout_response(
    state: &AppState,
    tenant: &Tenant,
    resp: LogoutResponse,
    root: &Element,
    arrival: Arrival,
) -> Response {
    let logout =
        arrival.relay_state.as_deref().and_then(|id| state.store.get::<Logout>(Table::Logouts, id)).or_else(|| {
            state
                .store
                .list::<Logout>(Table::Logouts)
                .into_iter()
                .find(|l| l.waiting_on.as_ref().map(|(_, id)| Some(id)) == Some(resp.in_response_to.as_ref()))
        });
    let Some(mut logout) = logout else {
        return saml_error_page(
            tenant,
            "Unexpected LogoutResponse",
            &format!(
                "No logout in progress matches this LogoutResponse (InResponseTo {}). Status: {}.",
                resp.in_response_to.as_deref().unwrap_or("(none)"),
                resp.status.short()
            ),
        );
    };
    let Some((waiting, request_id)) = logout.waiting_on.take() else {
        return finish(state, tenant, logout).await;
    };
    let outcome = if resp.in_response_to.as_deref() != Some(&request_id) {
        "failed: InResponseTo doesn't match the LogoutRequest".to_string()
    } else if let Some(sp) = find_sp(state, tenant, &waiting).await
        && let Some(problem) = match check_signature(&sp, root, &resp.id, arrival.query_signature.as_ref()) {
            SigCheck::Invalid(e) => Some(format!("invalid signature ({e})")),
            SigCheck::Unsigned if sp.want_logout_signed => Some("unsigned, and want_logout_signed is on".into()),
            _ => None,
        }
    {
        format!("failed: {problem}")
    } else if resp.status.is_success() {
        "logged out".to_string()
    } else {
        format!("failed: {}", resp.status.short())
    };
    logout.results.push((waiting, outcome));
    advance(state, tenant, logout).await
}

/// `/slo/initiate[?sid=…][&return_to=…]`: IdP-initiated logout of the browser's session (or the
/// one named), notifying every service provider that used it.
pub async fn initiate(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> Response {
    let params = parse_form(q.unwrap_or_default().as_bytes());
    let named = non_empty(&params, "sid");
    let session = match &named {
        Some(sid) => state.store.get::<Session>(Table::Sessions, sid).map(|s| (sid.clone(), s)),
        None => current_session(&state, &tenant, &headers),
    };
    let Some((sid, session)) = session else {
        return crate::html::message_page(&tenant, "No active session", "There's no session to log out of.");
    };
    // A session from another issuer is logged out as that issuer.
    let tenant = match crate::presets::get(&session.tenant) {
        Some(p) if tenant.preset.map(|t| t.id) != Some(p.id) => {
            Tenant::new(&state.config.base_url, Some(p), &state.config)
        }
        None if tenant.preset.is_some() => Tenant::new(&state.config.base_url, None, &state.config),
        _ => tenant,
    };
    state.store.remove(Table::Sessions, &sid);
    let logout = Logout {
        id: uuid::Uuid::new_v4().to_string(),
        tenant: tenant.key().into(),
        issuer: tenant.entity_id.clone(),
        who: session.identity.describe(),
        session_index: session.session_index.clone(),
        initiator: None,
        remaining: session.participants.clone(),
        waiting_on: None,
        results: vec![],
        // A local path or an http(s) URL; anything else (javascript:, …) is dropped.
        return_to: non_empty(&params, "return_to")
            .filter(|r| (r.starts_with('/') && !r.starts_with("//")) || crate::util::is_web_url(r)),
    };
    let ours = crate::routes::sso::cookie_value(&headers, &tenant.cookie_name()).as_deref() == Some(sid.as_str());
    let mut resp = advance(&state, &tenant, logout).await;
    if ours {
        set_cookie(&mut resp, &clear_session_cookie(&tenant));
    }
    resp
}

/// Describe a session for the dev API and page.
pub fn describe(sid: &str, session: &Session, exp: Option<i64>) -> serde_json::Value {
    serde_json::json!({
        "sid": sid,
        "issuer": session.issuer,
        "tenant": session.tenant,
        "who": session.identity.describe(),
        "name_id": session.identity.name_id,
        "preset": session.identity.preset,
        "session_index": session.session_index,
        "auth_time": session.auth_time,
        "expires_at": exp,
        "service_providers": session.participants.iter().map(|p: &Participant| &p.entity_id).collect::<Vec<_>>(),
    })
}

// ---------------------------------------------------------------------------
// Back-channel (SOAP binding)
// ---------------------------------------------------------------------------

/// Log one service provider out over the SOAP binding: a signed LogoutRequest, and its
/// LogoutResponse checked like a front-channel one. Returns the outcome, `logged out (SOAP)` on
/// success.
pub async fn back_channel(
    state: &AppState,
    tenant: &Tenant,
    sp: &ServiceProvider,
    url: &str,
    participant: &Participant,
    session_index: &str,
) -> String {
    let started = std::time::Instant::now();
    let style = &preset(state, tenant).style;
    let (mut message, id) = match participant_logout_request(state, tenant, sp, url, participant, session_index) {
        Ok(m) => m,
        Err(e) => return format!("failed: {e}"),
    };
    let alg = sp.signature_algorithm.unwrap_or(state.config.signature_algorithm);
    if let Err(e) = state.keys.with_current(|key| saml::sign_message(&mut message, &id, key, style, alg)) {
        return format!("failed: signing the LogoutRequest: {e}");
    }
    let sent = Message {
        direction: "sent",
        kind: "LogoutRequest".into(),
        binding: "soap",
        destination: Some(url.into()),
        status: None,
        xml: message.to_pretty(),
    };
    let (outcome, received, error) = match crate::soap::call(url, message).await {
        Err(e) => (format!("failed: {e}"), None, Some(("back-channel logout failed".to_string(), e))),
        Ok((envelope, answer)) => {
            let received = Message {
                direction: "received",
                kind: answer.local.clone(),
                binding: "soap",
                destination: None,
                status: None,
                xml: envelope.to_pretty(),
            };
            let outcome = match saml::parse_element(&answer) {
                Ok(saml::Message::LogoutResponse(resp)) => {
                    let signature = check_signature(sp, &envelope, &resp.id, None);
                    if resp.in_response_to.as_deref() != Some(&id) {
                        "failed: InResponseTo doesn't match the LogoutRequest".to_string()
                    } else if let SigCheck::Invalid(e) = signature {
                        format!("failed: invalid signature ({e})")
                    } else if matches!(signature, SigCheck::Unsigned) && sp.want_logout_signed {
                        "failed: unsigned, and want_logout_signed is on".into()
                    } else if resp.status.is_success() {
                        "logged out (SOAP)".into()
                    } else {
                        format!("failed: {}", resp.status.short())
                    }
                }
                Ok(other) => format!("failed: expected a LogoutResponse, got {}", other.kind()),
                Err(e) => format!("failed: {e}"),
            };
            let error =
                outcome.strip_prefix("failed: ").map(|e| ("back-channel logout failed".to_string(), e.to_string()));
            (outcome, Some(received), error)
        }
    };
    state.inspector.record_outgoing(
        tenant.key(),
        url,
        &sp.entity_id,
        sent,
        received,
        if error.is_some() { 500 } else { 200 },
        error,
        format!("LogoutRequest → {url}: {outcome}"),
        started,
    );
    outcome
}

/// Log a session's service providers out back-channel, except `skip`. Returns (entity ID,
/// outcome) for each; ones without a SOAP endpoint are `not notified`.
pub async fn back_channel_all(
    state: &AppState,
    tenant: &Tenant,
    session: &Session,
    skip: Option<&str>,
) -> Vec<(String, String)> {
    let mut results = vec![];
    for participant in session.participants.iter().filter(|p| Some(p.entity_id.as_str()) != skip) {
        let outcome = match find_sp(state, tenant, &participant.entity_id).await {
            Some(sp) => match &sp.slo_soap_url {
                Some(url) => back_channel(state, tenant, &sp, url, participant, &session.session_index).await,
                None => "not notified: no SOAP SingleLogoutService".into(),
            },
            None => "not notified: no longer registered".into(),
        };
        results.push((participant.entity_id.clone(), outcome));
    }
    results
}

/// A LogoutRequest over the SOAP binding: end the session it names and log the other service
/// providers out back-channel (the browser isn't there to redirect).
pub async fn soap_logout_request(
    state: &AppState,
    tenant: &Tenant,
    envelope: &Element,
    mut req: LogoutRequest,
) -> Response {
    let fault = crate::soap::fault;
    let p = preset(state, tenant);
    if !p.single_logout {
        return fault(true, &format!("{} doesn't do SAML single logout", p.name));
    }
    let Some(issuer) = req.issuer.clone() else {
        return fault(true, "the LogoutRequest has no Issuer");
    };
    let sp = match resolve_sp(state, tenant, &issuer).await {
        Ok(sp) => sp,
        Err(e) => return fault(true, &e),
    };
    match check_signature(&sp, envelope, &req.id, None) {
        SigCheck::Invalid(e) => return fault(true, &format!("invalid LogoutRequest signature: {e}")),
        SigCheck::Unsigned if sp.want_logout_signed => {
            return fault(true, &format!("{} must sign its logout messages (want_logout_signed)", sp.label()));
        }
        _ => {}
    }
    if let Err(e) = decrypt_name_id(state, &mut req, envelope) {
        return fault(true, &e);
    }
    // No cookie on a back-channel request: find the session by SessionIndex, else by the NameID
    // this SP was given.
    let session = state.store.entries::<Session>(Table::Sessions).into_iter().find(|(_, s, _)| {
        s.tenant == tenant.key()
            && (req.session_indexes.contains(&s.session_index)
                || s.participants.iter().any(|p| {
                    p.entity_id == sp.entity_id
                        && (req.session_indexes.contains(&p.session_index)
                            || (req.session_indexes.is_empty() && Some(&p.name_id) == req.name_id.as_ref()))
                }))
    });
    let mut status = Status::success();
    if let Some((sid, session, _)) = session {
        state.store.remove(Table::Sessions, &sid);
        let results = back_channel_all(state, tenant, &session, Some(&sp.entity_id)).await;
        if results.iter().any(|(_, r)| !r.starts_with("logged out")) {
            status =
                Status::parse("PartialLogout", Some("some service providers couldn't be logged out".into())).unwrap();
        }
    }
    let style = &p.style;
    let (mut message, id) =
        saml::logout_response_to(style, &tenant.entity_id, None, Some(&req.id), &status, state.now());
    let alg = sp.signature_algorithm.unwrap_or(state.config.signature_algorithm);
    if let Err(e) = state.keys.with_current(|key| saml::sign_message(&mut message, &id, key, style, alg)) {
        return fault(false, &e);
    }
    let pretty = message.to_pretty();
    let mut resp = crate::soap::reply(message);
    SamlNote::sent(&sp.entity_id, "LogoutResponse", "soap", "(SOAP response)", pretty, Some(&status)).attach(&mut resp);
    resp
}

//! Single logout. A LogoutRequest from one service provider (or `/slo/initiate`) ends the session,
//! then every other service provider that got an assertion during it is sent a LogoutRequest in
//! turn, over front-channel redirects, before the initiator gets its LogoutResponse.

use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};

use crate::faults::{self, Endpoint};
use crate::html::{error_page, esc, page, saml_post};
use crate::inspector::SamlNote;
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
        let mut resp = error_page(
            tenant,
            StatusCode::BAD_REQUEST,
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

/// A LogoutRequest from a service provider.
pub async fn logout_request(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    req: LogoutRequest,
    root: &Element,
    arrival: Arrival,
) -> Response {
    let bad = |title: &str, detail: &str| error_page(tenant, StatusCode::BAD_REQUEST, title, detail);
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
    if let SigCheck::Invalid(e) = check_signature(&sp, root, &req.id, arrival.query_signature.as_ref()) {
        return bad("Invalid LogoutRequest signature", &e);
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
            .find(|(_, s, _)| s.tenant == tenant.key() && req.session_indexes.contains(&s.session_index))
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

/// Ask the next service provider to log out, or finish.
async fn advance(state: &AppState, tenant: &Tenant, mut logout: Logout) -> Response {
    while let Some(participant) = (!logout.remaining.is_empty()).then(|| logout.remaining.remove(0)) {
        let Some(sp) = find_sp(state, tenant, &participant.entity_id).await else {
            logout.results.push((participant.entity_id, "not notified: no longer registered".into()));
            continue;
        };
        let Some(location) = sp.slo_url.clone() else {
            logout.results.push((participant.entity_id, "not notified: no SingleLogoutService".into()));
            continue;
        };
        let style = &preset(state, tenant).style;
        let (message, id) = saml::logout_request(&LogoutRequestSpec {
            style,
            issuer: &tenant.entity_id,
            destination: &location,
            name_id: &participant.name_id,
            name_id_format: &participant.name_id_format,
            sp_name_qualifier: participant.sp_name_qualifier.as_deref(),
            session_index: &logout.session_index,
            now: state.now(),
        });
        logout.waiting_on = Some((sp.entity_id.clone(), id.clone()));
        state.store.put(Table::Logouts, &logout.id, &logout, Some(state.now() + LOGOUT_TTL));
        return send(state, style, &sp, &location, "SAMLRequest", message, &id, Some(&logout.id), None);
    }
    finish(state, tenant, logout).await
}

async fn finish(state: &AppState, tenant: &Tenant, logout: Logout) -> Response {
    state.store.remove(Table::Logouts, &logout.id);
    let partial = logout.results.iter().any(|(_, r)| r != "logged out");
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
        return error_page(
            tenant,
            StatusCode::BAD_REQUEST,
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
        && let SigCheck::Invalid(e) = check_signature(&sp, root, &resp.id, arrival.query_signature.as_ref())
    {
        format!("failed: invalid signature ({e})")
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

//! SAML messages over the SOAP binding: service providers calling the identity provider
//! directly, without the browser.

use axum::body::Bytes;
use axum::extract::State;
use axum::response::Response;

use crate::inspector::SamlNote;
use crate::routes::sso::{SigCheck, check_signature, preset_for, resolve_sp};
use crate::saml::{self, ArtifactResolve, Message, Status};
use crate::soap;
use crate::state::{AppState, StoredArtifact};
use crate::store::Table;
use crate::tenant::Tenant;
use crate::xml::{Element, parse};

/// The ArtifactResolutionService (and any other SOAP message).
pub async fn endpoint(State(state): State<AppState>, tenant: Tenant, body: Bytes) -> Response {
    dispatch(&state, &tenant, &body).await
}

/// Dispatch a SOAP request on a SAML endpoint by the message in its Body.
pub async fn dispatch(state: &AppState, tenant: &Tenant, body: &Bytes) -> Response {
    let xml = String::from_utf8_lossy(body);
    let (envelope, message) = match soap::unwrap(&xml) {
        Ok(m) => m,
        Err(e) => return soap::fault(true, &e),
    };
    match saml::parse_element(&message) {
        Ok(Message::LogoutRequest(req)) => crate::routes::slo::soap_logout_request(state, tenant, &envelope, req).await,
        Ok(Message::ArtifactResolve(req)) => artifact_resolve(state, tenant, &envelope, req).await,
        Ok(other) => soap::fault(true, &format!("{} isn't accepted over the SOAP binding here", other.kind())),
        Err(e) => soap::fault(true, &e),
    }
}

/// Resolve an artifact (HTTP-Artifact binding): answer with the Response it stands for, once,
/// and only to the service provider it was issued for.
async fn artifact_resolve(state: &AppState, tenant: &Tenant, envelope: &Element, req: ArtifactResolve) -> Response {
    let Some(issuer) = req.issuer.clone() else {
        return soap::fault(true, "the ArtifactResolve has no Issuer");
    };
    let sp = match resolve_sp(state, tenant, &issuer).await {
        Ok(sp) => sp,
        Err(e) => return soap::fault(true, &e),
    };
    if let SigCheck::Invalid(e) = check_signature(&sp, envelope, &req.id, None) {
        return soap::fault(true, &format!("invalid ArtifactResolve signature: {e}"));
    }
    // An unknown, used or someone else's artifact gets an ArtifactResponse without a message.
    let message = match saml::check_artifact(&req.artifact, &tenant.entity_id) {
        Err(e) => Err(e),
        Ok(()) => match state.store.get::<StoredArtifact>(Table::Artifacts, &req.artifact) {
            None => Err("unknown, expired or already resolved".to_string()),
            Some(stored) if stored.sp != sp.entity_id => Err(format!("issued for {}, not {}", stored.sp, sp.entity_id)),
            Some(stored) => {
                state.store.remove(Table::Artifacts, &req.artifact);
                parse(&stored.xml)
            }
        },
    };
    let preset = preset_for(state, tenant, &sp);
    let style = &preset.style;
    let (found, problem) = match message {
        Ok(m) => (Some(m), None),
        Err(e) => (None, Some(e)),
    };
    let (mut response, id) = saml::artifact_response(style, &tenant.entity_id, &req.id, found, state.now());
    let alg = sp.signature_algorithm.unwrap_or(state.config.signature_algorithm);
    if let Err(e) = state.keys.with_current(|key| saml::sign_message(&mut response, &id, key, style, alg)) {
        return soap::fault(false, &e);
    }
    let pretty = response.to_pretty();
    let mut resp = soap::reply(response);
    let kind = if problem.is_some() { "ArtifactResponse (no message)" } else { "ArtifactResponse" };
    SamlNote::sent(&sp.entity_id, kind, "soap", "(SOAP response)", pretty, Some(&Status::success())).attach(&mut resp);
    if let Some(p) = problem {
        crate::inspector::ErrorNote::attach(&mut resp, "artifact not resolved", p);
    }
    resp
}

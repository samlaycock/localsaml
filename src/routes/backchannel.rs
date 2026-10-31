//! SAML messages over the SOAP binding: service providers calling the identity provider
//! directly, without the browser.

use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::HeaderMap;
use axum::response::Response;

use crate::inspector::SamlNote;
use crate::presets::{Identity, Preset};
use crate::routes::sso::{
    SigCheck, check_signature, delivery, finish_name_id_for, name_id_encryption, preset_for, resolve_sp,
};
use crate::saml::{self, ArtifactResolve, AttributeQuery, Message, ResponseSpec, Status};
use crate::soap;
use crate::sp::ServiceProvider;
use crate::state::{AppState, Session, StoredArtifact};
use crate::store::Table;
use crate::tenant::Tenant;
use crate::xml::{Element, parse};

/// The ArtifactResolutionService (and any other SOAP message).
pub async fn endpoint(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Response {
    let url = format!("{}{}", crate::routes::sso::origin(&tenant.base), uri.path());
    dispatch(&state, &tenant, &headers, &url, &body).await
}

/// Dispatch a SOAP request on a SAML endpoint by the message in its Body.
pub async fn dispatch(state: &AppState, tenant: &Tenant, headers: &HeaderMap, url: &str, body: &Bytes) -> Response {
    let xml = String::from_utf8_lossy(body);
    let (envelope, message) = match soap::unwrap(&xml) {
        Ok(m) => m,
        Err(e) => return soap::fault(true, &e),
    };
    match saml::parse_element(&message) {
        // ECP: an AuthnRequest relayed by an enhanced client, which authenticates with HTTP Basic.
        Ok(Message::AuthnRequest(req)) => crate::routes::sso::ecp(state, tenant, headers, req, &message, url).await,
        Ok(Message::LogoutRequest(req)) => crate::routes::slo::soap_logout_request(state, tenant, &envelope, req).await,
        Ok(Message::ArtifactResolve(req)) => artifact_resolve(state, tenant, &envelope, req).await,
        Ok(Message::AttributeQuery(req)) => attribute_query(state, tenant, &envelope, req).await,
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

/// Answer an AttributeQuery (the attribute authority): a Response with an assertion about the
/// subject, holding the attributes asked for (or all of them).
async fn attribute_query(state: &AppState, tenant: &Tenant, envelope: &Element, mut req: AttributeQuery) -> Response {
    let Some(issuer) = req.issuer.clone() else {
        return soap::fault(true, "the AttributeQuery has no Issuer");
    };
    let sp = match resolve_sp(state, tenant, &issuer).await {
        Ok(sp) => sp,
        Err(e) => return soap::fault(true, &e),
    };
    if let SigCheck::Invalid(e) = check_signature(&sp, envelope, &req.id, None) {
        return soap::fault(true, &format!("invalid AttributeQuery signature: {e}"));
    }
    let preset = preset_for(state, tenant, &sp);
    // An error Response, signed (it has no assertion to carry a signature).
    let answer = |status: Status| {
        let identity = preset.default_identity();
        let now = state.now();
        let spec = ResponseSpec {
            preset,
            issuer: tenant.entity_id.clone(),
            identity: &identity,
            destination: String::new(),
            audience: sp.audience(),
            in_response_to: Some(req.id.clone()),
            session_index: String::new(),
            assertion_id: None,
            auth_time: now,
            now,
            sign_response: true,
            sign_assertion: false,
            sig_alg: sp.signature_algorithm.unwrap_or(state.config.signature_algorithm),
            encrypt: None,
            encrypt_name_id: None,
            encrypt_attributes: None,
            lifetime: None,
            authn_context: String::new(),
            sp_name_qualifier: None,
            status: Some(status.clone()),
            tampers: vec![],
            attribute_query: true,
        };
        reply(state.keys.with_current(|key| saml::build_response(key, &spec)), &sp, Some(&status))
    };
    if req.name_id_encrypted {
        let decrypted = envelope
            .find_by_id(&req.id)
            .and_then(|q| q.find(saml::NS_ASSERTION, "Subject"))
            .and_then(|s| s.find(saml::NS_ASSERTION, "EncryptedID"))
            .ok_or_else(|| "the EncryptedID is missing".to_string())
            .and_then(|e| saml::decrypt_id(e, &state.keys.private_keys()));
        match decrypted {
            Ok(n) => {
                req.name_id = Some(n.value());
                req.name_id_format = n.get_attr("Format").map(String::from);
            }
            Err(e) => {
                return answer(
                    Status::parse("Requester", Some(format!("can't decrypt the EncryptedID: {e}"))).unwrap(),
                );
            }
        }
    }
    let name_id = req.name_id.clone().unwrap_or_default();
    let Some(mut identity) = subject(state, tenant, preset, &sp, &name_id) else {
        let message = format!("no session or declared user has the NameID '{name_id}' at {}", sp.label());
        return answer(Status::parse("UnknownPrincipal", Some(message)).unwrap());
    };
    // The subject as the service provider named it (Core 3.3.4: the assertion's Subject must
    // match the query's).
    identity.name_id = name_id;
    if let Some(f) = &req.name_id_format {
        identity.name_id_format = f.clone();
    }
    if !req.attributes.is_empty() {
        let mut kept = serde_json::Map::new();
        for wanted in &req.attributes {
            let mut values = identity.values(&wanted.name);
            if !wanted.values.is_empty() {
                values.retain(|v| wanted.values.contains(v));
            }
            if !values.is_empty() {
                kept.insert(wanted.name.clone(), values.into_iter().map(serde_json::Value::String).collect());
            }
        }
        identity.attributes = kept;
    }

    let mut d = match delivery(state, preset, &sp) {
        Ok(d) => d,
        Err(e) => return soap::fault(false, &e),
    };
    if req.name_id_encrypted && d.encrypt_name_id.is_none() {
        d.encrypt_name_id = name_id_encryption(preset, &sp).ok();
    }
    let now = state.now();
    let spec = ResponseSpec {
        preset,
        issuer: tenant.entity_id.clone(),
        identity: &identity,
        destination: String::new(),
        audience: sp.audience(),
        in_response_to: Some(req.id.clone()),
        session_index: String::new(),
        assertion_id: None,
        auth_time: now,
        now,
        sign_response: d.sign_response,
        // An unsigned answer over plain HTTP would be worthless: sign the assertion at least.
        sign_assertion: d.sign_assertion || !d.sign_response,
        sig_alg: d.sig_alg,
        encrypt: d.encrypt,
        encrypt_name_id: d.encrypt_name_id,
        encrypt_attributes: d.encrypt_attributes,
        lifetime: state.config.assertion_ttl,
        authn_context: String::new(),
        sp_name_qualifier: None,
        status: None,
        tampers: vec![],
        attribute_query: true,
    };
    reply(state.keys.with_current(|key| saml::build_response(key, &spec)), &sp, None)
}

/// A Response to an AttributeQuery, in a SOAP envelope.
fn reply(issued: Result<saml::Issued, String>, sp: &ServiceProvider, status: Option<&Status>) -> Response {
    let issued = match issued {
        Ok(i) => i,
        Err(e) => return soap::fault(false, &e),
    };
    let response = match parse(&issued.xml) {
        Ok(r) => r,
        Err(e) => return soap::fault(false, &e),
    };
    let mut resp = soap::reply(response);
    SamlNote::sent(&sp.entity_id, "Response (attribute query)", "soap", "(SOAP response)", issued.pretty, status)
        .attach(&mut resp);
    resp
}

/// Who an AttributeQuery's NameID refers to: a session in which this service provider got that
/// NameID, else a declared user who would get it.
fn subject(
    state: &AppState,
    tenant: &Tenant,
    preset: &'static Preset,
    sp: &ServiceProvider,
    name_id: &str,
) -> Option<Identity> {
    if name_id.is_empty() {
        return None;
    }
    let from_session = state.store.entries::<Session>(Table::Sessions).into_iter().find_map(|(_, s, _)| {
        (s.tenant == tenant.key() && s.participants.iter().any(|p| p.entity_id == sp.entity_id && p.name_id == name_id))
            .then_some(s.identity)
    });
    from_session.or_else(|| {
        state.config.users.iter().find_map(|user| {
            let (p, mut identity) = user.resolve(None, preset);
            finish_name_id_for(&mut identity, p, &sp.entity_id, "");
            (identity.name_id == name_id || user.matches(name_id)).then_some(identity)
        })
    })
}

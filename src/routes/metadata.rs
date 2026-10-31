//! The identity provider's metadata and signing certificate.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::dsig::{NS_DS, SignOpts};
use crate::presets::nameid;
use crate::saml::{BINDING_POST, BINDING_REDIRECT, NS_MD, NS_PROTOCOL};
use crate::state::AppState;
use crate::tenant::Tenant;
use crate::xml::Element;

/// The `EntityDescriptor` for an issuer. Every certificate in the keyring is listed, so service
/// providers that refresh metadata keep trusting responses across a key rotation.
pub fn document(state: &AppState, tenant: &Tenant, signed: bool) -> Result<String, String> {
    let md = |local: &str| Element::new(NS_MD, "md", local);
    let preset = tenant.default_preset(&state.config);
    let mut idp =
        md("IDPSSODescriptor").attr("WantAuthnRequestsSigned", "false").attr("protocolSupportEnumeration", NS_PROTOCOL);
    for cert in state.keys.certs_b64() {
        idp = idp.child(md("KeyDescriptor").attr("use", "signing").child(Element::new(NS_DS, "ds", "KeyInfo").child(
            Element::new(NS_DS, "ds", "X509Data").child(Element::new(NS_DS, "ds", "X509Certificate").text(cert)),
        )));
    }
    if let Some(slo) = tenant.slo_url() {
        for binding in [BINDING_REDIRECT, BINDING_POST] {
            idp = idp.child(md("SingleLogoutService").attr("Binding", binding).attr("Location", &slo));
        }
    }
    let mut formats = vec![preset.name_id_format];
    formats.extend(nameid::ALL.iter().filter(|f| **f != preset.name_id_format && **f != nameid::ENTITY));
    for f in formats {
        idp = idp.child(md("NameIDFormat").text(f));
    }
    let sso = tenant.sso_url();
    for binding in [BINDING_REDIRECT, BINDING_POST] {
        idp = idp.child(md("SingleSignOnService").attr("Binding", binding).attr("Location", &sso));
    }
    let id = crate::util::saml_id("_");
    let mut entity = md("EntityDescriptor")
        .attr_opt("ID", signed.then(|| id.clone()))
        .attr("entityID", &tenant.entity_id)
        .declare("md", NS_MD)
        .declare("ds", NS_DS)
        .child(idp);
    entity.declare_namespaces();
    if signed {
        let opts = SignOpts { alg: state.config.signature_algorithm, ..Default::default() };
        state.keys.with_current(|key| crate::dsig::sign(&mut entity, &id, key, &opts))?;
    }
    Ok(entity.to_document())
}

pub async fn metadata(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let signed = q.get("signed").is_some_and(|v| v != "false" && v != "0");
    match document(&state, &tenant, signed) {
        Ok(xml) => {
            // Browsers render text/xml; SAML libraries don't mind either way.
            let browser =
                headers.get(header::ACCEPT).and_then(|a| a.to_str().ok()).is_some_and(|a| a.contains("text/html"));
            let content_type = if browser { "text/xml; charset=utf-8" } else { "application/samlmetadata+xml" };
            ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, "no-cache")], xml).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("signing metadata failed: {e}")).into_response(),
    }
}

/// The current signing certificate as PEM.
pub async fn certificate(State(state): State<AppState>) -> Response {
    let pem = state.keys.current_info().pem;
    (
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (header::CONTENT_DISPOSITION, "inline; filename=\"localsaml.pem\""),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        pem,
    )
        .into_response()
}

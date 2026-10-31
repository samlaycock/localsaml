//! SAML messages over the SOAP binding: service providers calling the identity provider
//! directly, without the browser.

use axum::body::Bytes;
use axum::response::Response;

use crate::saml::{self, Message};
use crate::soap;
use crate::state::AppState;
use crate::tenant::Tenant;

/// Dispatch a SOAP request on a SAML endpoint by the message in its Body.
pub async fn dispatch(state: &AppState, tenant: &Tenant, body: &Bytes) -> Response {
    let xml = String::from_utf8_lossy(body);
    let (envelope, message) = match soap::unwrap(&xml) {
        Ok(m) => m,
        Err(e) => return soap::fault(true, &e),
    };
    match saml::parse_element(&message) {
        Ok(Message::LogoutRequest(req)) => crate::routes::slo::soap_logout_request(state, tenant, &envelope, req).await,
        Ok(other) => soap::fault(true, &format!("{} isn't accepted over the SOAP binding here", other.kind())),
        Err(e) => soap::fault(true, &e),
    }
}

//! The SOAP binding (SAML Bindings §3.2): back-channel messages between the identity provider
//! and service providers, in a SOAP 1.1 envelope over HTTP POST.

use std::time::Duration;

use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::xml::{Element, Node, Scope, parse};

pub const NS_SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";

/// How long a service provider gets to answer a back-channel message.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// Does a request carry a SOAP envelope (rather than form or query parameters)?
pub fn is_soap(headers: &HeaderMap, body: &[u8]) -> bool {
    let content_type = crate::inspector::content_type(headers);
    let xml_body = body.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'<');
    xml_body && (content_type.contains("xml") || content_type.contains("soap") || content_type.is_empty())
}

/// Wrap a message (which declares its own namespaces) in an envelope.
pub fn envelope(message: Element) -> String {
    envelope_with_header(None, message)
}

/// An envelope with a SOAP Header block (ECP's `ecp:Response`).
pub fn envelope_with_header(header: Option<Element>, message: Element) -> String {
    let mut env = Element::new(NS_SOAP, "soap11", "Envelope")
        .child_opt(header.map(|h| Element::new(NS_SOAP, "soap11", "Header").child(h)))
        .child(Element::new(NS_SOAP, "soap11", "Body").child(message));
    env.declare_namespaces();
    env.to_document()
}

/// The parsed envelope and the message in its Body.
pub fn unwrap(xml: &str) -> Result<(Element, Element), String> {
    let root = parse(xml)?;
    if !root.is(NS_SOAP, "Envelope") {
        return Err(format!("expected a SOAP 1.1 Envelope, got <{}>", root.qname()));
    }
    let body = root.find(NS_SOAP, "Body").ok_or("the SOAP envelope has no Body")?;
    let mut message = body.elements().next().cloned().ok_or("the SOAP Body is empty")?;
    // The message on its own keeps the namespaces it inherited from the Envelope and Body, so
    // its signature (Exclusive C14N, perhaps with an InclusiveNamespaces list) still verifies.
    for (prefix, uri) in body.scope_within(&root.scope_within(&Scope::new())) {
        if !message.decls.iter().any(|(p, _)| *p == prefix) {
            message.decls.push((prefix, uri));
        }
    }
    if message.is(NS_SOAP, "Fault") {
        let reason = message.elements().find(|e| e.local == "faultstring").map(Element::value).unwrap_or_default();
        return Err(format!("SOAP fault: {reason}"));
    }
    Ok((root, message))
}

/// A SOAP response's headers: XML, not cached (Bindings 3.2.3.2).
pub const RESPONSE_HEADERS: [(header::HeaderName, &str); 3] = [
    (header::CONTENT_TYPE, "text/xml; charset=utf-8"),
    (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate, private"),
    (header::PRAGMA, "no-cache"),
];

/// A SOAP response carrying `message`.
pub fn reply(message: Element) -> Response {
    (RESPONSE_HEADERS, envelope(message)).into_response()
}

/// A SOAP fault (HTTP 500, as SOAP 1.1 requires). `client` blames the sender's message.
pub fn fault(client: bool, reason: &str) -> Response {
    let code = if client { "soap11:Client" } else { "soap11:Server" };
    let mut fault = Element::new(NS_SOAP, "soap11", "Fault");
    fault.children.push(Node::Element(Element::new("", "", "faultcode").text(code)));
    fault.children.push(Node::Element(Element::new("", "", "faultstring").text(reason)));
    let mut resp = (StatusCode::INTERNAL_SERVER_ERROR, RESPONSE_HEADERS, envelope(fault)).into_response();
    crate::inspector::ErrorNote::attach(&mut resp, "SOAP fault", reason);
    resp
}

/// Send a message to a service provider and return the parsed envelope and the message in its
/// answer.
pub async fn call(url: &str, message: Element) -> Result<(Element, Element), String> {
    let (status, body) = crate::fetch::post_xml(url, &envelope(message), TIMEOUT).await?;
    if !(200..300).contains(&status) && !body.contains("Fault") {
        return Err(format!("{url} answered HTTP {status}"));
    }
    unwrap(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelopes_round_trip() {
        let mut msg = Element::new("urn:x", "x", "Ping").attr("ID", "_1");
        msg.declare_namespaces();
        let (_, mut back) = unwrap(&envelope(msg.clone())).unwrap();
        // The message keeps the namespaces it inherited from the envelope.
        assert!(back.decls.contains(&(Some("soap11".into()), NS_SOAP.into())));
        back.decls.retain(|(p, _)| p.as_deref() != Some("soap11"));
        assert_eq!(back, msg);
        assert!(unwrap("<x/>").is_err());
        let mut fault_env =
            Element::new(NS_SOAP, "soap11", "Envelope").child(Element::new(NS_SOAP, "soap11", "Body").child(
                Element::new(NS_SOAP, "soap11", "Fault").child(Element::new("", "", "faultstring").text("nope")),
            ));
        fault_env.declare_namespaces();
        assert_eq!(unwrap(&fault_env.to_xml()).unwrap_err(), "SOAP fault: nope");
    }
}

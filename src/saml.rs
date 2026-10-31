//! SAML 2.0 protocol messages: decoding what service providers send (AuthnRequest, LogoutRequest,
//! LogoutResponse) and building what the identity provider sends back.

use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};

use crate::dsig::{self, SignOpts, urlencode};
use crate::keys::{KeyPair, SigAlg};
use crate::presets::{Identity, Preset, Style, nameid};
use crate::util::{b64_std, b64_std_decode_lenient, iso8601, parse_iso8601};
use crate::xml::{Element, parse};
use crate::xmlenc::{self, EncAlg};

pub const NS_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const NS_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const NS_XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
pub const NS_XS: &str = "http://www.w3.org/2001/XMLSchema";
pub const NS_MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";

pub const BINDING_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
pub const BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
pub const BINDING_ARTIFACT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
pub const BINDING_SOAP: &str = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
pub const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
/// The identity provider vouches for the subject (attribute query answers, sent back-channel).
pub const CM_SENDER_VOUCHES: &str = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";

pub mod status {
    pub const PREFIX: &str = "urn:oasis:names:tc:SAML:2.0:status:";
    pub const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
    pub const REQUESTER: &str = "urn:oasis:names:tc:SAML:2.0:status:Requester";
    pub const RESPONDER: &str = "urn:oasis:names:tc:SAML:2.0:status:Responder";
    pub const VERSION_MISMATCH: &str = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";

    /// Second-level status codes and the top-level code they're usually sent under.
    pub const SECOND_LEVEL: &[(&str, &str)] = &[
        ("AuthnFailed", "Responder"),
        ("NoPassive", "Responder"),
        ("RequestDenied", "Responder"),
        ("UnknownPrincipal", "Responder"),
        ("NoAuthnContext", "Responder"),
        ("PartialLogout", "Success"),
        ("InvalidNameIDPolicy", "Requester"),
        ("InvalidAttrNameOrValue", "Requester"),
        ("RequestUnsupported", "Requester"),
        ("UnsupportedBinding", "Requester"),
        ("NoAvailableIDP", "Responder"),
        ("NoSupportedIDP", "Responder"),
        ("ProxyCountExceeded", "Responder"),
        ("TooManyResponses", "Responder"),
        ("UnknownAttrProfile", "Requester"),
        ("ResourceNotRecognized", "Requester"),
        ("RequestVersionDeprecated", "VersionMismatch"),
        ("RequestVersionTooHigh", "VersionMismatch"),
        ("RequestVersionTooLow", "VersionMismatch"),
    ];
}

/// A SAML status: a top-level code, an optional second-level code and a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Status {
    pub fn success() -> Self {
        Self { code: status::SUCCESS.into(), sub_code: None, message: None }
    }

    /// Parse a short name (`NoPassive`, `Responder`) or a full status URN. Second-level codes get
    /// their usual top-level code.
    pub fn parse(name: &str, message: Option<String>) -> Result<Self, String> {
        let short = name.strip_prefix(status::PREFIX).unwrap_or(name);
        let full = |s: &str| format!("{}{s}", status::PREFIX);
        if ["Success", "Requester", "Responder", "VersionMismatch"].contains(&short) {
            return Ok(Self { code: full(short), sub_code: None, message });
        }
        match status::SECOND_LEVEL.iter().find(|(s, _)| *s == short) {
            Some((s, top)) => Ok(Self { code: full(top), sub_code: Some(full(s)), message }),
            None => Err(format!("unknown SAML status '{name}'")),
        }
    }

    pub fn is_success(&self) -> bool {
        self.code == status::SUCCESS && self.sub_code.as_deref().is_none_or(|s| !s.ends_with(":PartialLogout"))
    }

    /// The most specific code without its URN prefix, e.g. `NoPassive`.
    pub fn short(&self) -> String {
        let code = self.sub_code.as_ref().unwrap_or(&self.code);
        code.rsplit(':').next().unwrap_or(code).to_string()
    }

    fn element(&self, style: &Style) -> Element {
        let p = |local: &str| Element::new(NS_PROTOCOL, style.protocol_prefix, local);
        let mut code = p("StatusCode").attr("Value", &self.code);
        if let Some(sub) = &self.sub_code {
            code = code.child(p("StatusCode").attr("Value", sub));
        }
        p("Status").child(code).child_opt(self.message.as_ref().map(|m| p("StatusMessage").text(m)))
    }

    pub fn from_element(el: Option<&Element>) -> Self {
        let code = el.and_then(|s| s.find(NS_PROTOCOL, "StatusCode"));
        Self {
            code: code.and_then(|c| c.get_attr("Value")).unwrap_or_default().to_string(),
            sub_code: code
                .and_then(|c| c.find(NS_PROTOCOL, "StatusCode"))
                .and_then(|c| c.get_attr("Value"))
                .map(String::from),
            message: el.and_then(|s| s.find(NS_PROTOCOL, "StatusMessage")).map(Element::value),
        }
    }
}

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

/// Decode a `SAMLRequest`/`SAMLResponse` parameter: base64, DEFLATE-compressed for the Redirect
/// binding. Messages that aren't compressed when they should be (or vice versa) are accepted.
pub fn decode_message(value: &str, redirect: bool) -> Result<String, String> {
    let bytes = b64_std_decode_lenient(value).ok_or("the SAML message is not valid base64")?;
    let inflate = |b: &[u8]| -> Option<String> {
        let mut out = String::new();
        DeflateDecoder::new(b).take(4 << 20).read_to_string(&mut out).ok().map(|_| out)
    };
    let plain = || String::from_utf8(bytes.clone()).ok().filter(|s| s.trim_start().starts_with('<'));
    let xml = if redirect { inflate(&bytes).or_else(plain) } else { plain().or_else(|| inflate(&bytes)) };
    xml.ok_or_else(|| {
        if redirect {
            "the SAML message is not DEFLATE-compressed XML (Redirect binding)".into()
        } else {
            "the SAML message is not XML".into()
        }
    })
}

/// Encode a message for the Redirect binding (DEFLATE, then base64).
pub fn deflate_b64(xml: &str) -> String {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    let _ = encoder.write_all(xml.as_bytes());
    b64_std(encoder.finish().unwrap_or_default())
}

/// The URL to redirect to for the Redirect binding, signed when a key is given.
pub fn redirect_url(
    location: &str,
    param: &str,
    xml: &str,
    relay_state: Option<&str>,
    sign: Option<(&KeyPair, SigAlg)>,
) -> String {
    let mut query = format!("{param}={}", urlencode(&deflate_b64(xml)));
    if let Some(rs) = relay_state.filter(|r| !r.is_empty()) {
        query.push_str(&format!("&RelayState={}", urlencode(rs)));
    }
    if let Some((key, alg)) = sign {
        query = dsig::sign_query(&query, key, alg);
    }
    let sep = if location.contains('?') { '&' } else { '?' };
    format!("{location}{sep}{query}")
}

// ---------------------------------------------------------------------------
// Incoming messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthnRequest {
    pub id: String,
    pub version: String,
    pub issue_instant: Option<i64>,
    pub issuer: Option<String>,
    pub destination: Option<String>,
    pub acs_url: Option<String>,
    pub acs_index: Option<u32>,
    pub protocol_binding: Option<String>,
    pub force_authn: bool,
    pub is_passive: bool,
    pub provider_name: Option<String>,
    pub name_id_format: Option<String>,
    pub allow_create: Option<bool>,
    pub sp_name_qualifier: Option<String>,
    pub requested_authn_contexts: Vec<String>,
    pub authn_context_comparison: Option<String>,
    /// `Subject/NameID`: who the SP expects to sign in, like a login hint.
    pub subject: Option<String>,
    pub subject_format: Option<String>,
    /// Has an enveloped XML signature (POST binding).
    pub signed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogoutRequest {
    pub id: String,
    pub issuer: Option<String>,
    pub destination: Option<String>,
    pub name_id: Option<String>,
    pub name_id_format: Option<String>,
    pub session_indexes: Vec<String>,
    pub not_on_or_after: Option<i64>,
    pub signed: bool,
    /// The NameID is an `EncryptedID` (`name_id` is empty until it's decrypted).
    #[serde(default)]
    pub name_id_encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutResponse {
    pub id: String,
    pub issuer: Option<String>,
    pub in_response_to: Option<String>,
    pub destination: Option<String>,
    pub status: Status,
    pub signed: bool,
}

#[derive(Debug, Clone)]
pub enum Message {
    AuthnRequest(AuthnRequest),
    LogoutRequest(LogoutRequest),
    LogoutResponse(LogoutResponse),
    ArtifactResolve(ArtifactResolve),
    AttributeQuery(AttributeQuery),
}

/// A service provider asking for a subject's attributes (SOAP binding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeQuery {
    pub id: String,
    pub issuer: Option<String>,
    pub destination: Option<String>,
    /// Empty when the subject is an `EncryptedID` that hasn't been decrypted yet.
    pub name_id: Option<String>,
    pub name_id_format: Option<String>,
    pub name_id_encrypted: bool,
    /// The attributes asked for; none means all of them.
    pub attributes: Vec<RequestedAttribute>,
    pub signed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedAttribute {
    pub name: String,
    /// Only these values (none: every value).
    pub values: Vec<String>,
}

/// A service provider asking for the message behind an artifact (SOAP binding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactResolve {
    pub id: String,
    pub issuer: Option<String>,
    pub artifact: String,
    pub signed: bool,
}

impl Message {
    pub fn kind(&self) -> &'static str {
        match self {
            Message::AuthnRequest(_) => "AuthnRequest",
            Message::LogoutRequest(_) => "LogoutRequest",
            Message::LogoutResponse(_) => "LogoutResponse",
            Message::ArtifactResolve(_) => "ArtifactResolve",
            Message::AttributeQuery(_) => "AttributeQuery",
        }
    }
}

fn opt(el: &Element, name: &str) -> Option<String> {
    el.get_attr(name).map(str::trim).filter(|v| !v.is_empty()).map(String::from)
}

fn flag(el: &Element, name: &str) -> bool {
    matches!(el.get_attr(name).map(str::trim), Some("true" | "1"))
}

fn issuer_of(el: &Element) -> Option<String> {
    el.find(NS_ASSERTION, "Issuer").map(Element::value).filter(|v| !v.is_empty())
}

/// Parse a message a service provider sent to the SSO or SLO endpoint.
pub fn parse_message(xml: &str) -> Result<(Message, Element), String> {
    let root = parse(xml)?;
    let message = parse_element(&root)?;
    Ok((message, root))
}

/// Read a protocol message from an already parsed element (e.g. the Body of a SOAP envelope).
pub fn parse_element(root: &Element) -> Result<Message, String> {
    let root = root.clone();
    if root.ns.as_deref() != Some(NS_PROTOCOL) {
        return Err(format!("<{}> is not a SAML 2.0 protocol message", root.qname()));
    }
    let id = opt(&root, "ID").ok_or_else(|| format!("{} has no ID", root.local))?;
    let signed = dsig::signature_of(&root).is_some();
    let message = match root.local.as_str() {
        "AuthnRequest" => {
            let policy = root.find(NS_PROTOCOL, "NameIDPolicy");
            let requested = root.find(NS_PROTOCOL, "RequestedAuthnContext");
            Message::AuthnRequest(AuthnRequest {
                id,
                version: root.get_attr("Version").unwrap_or_default().to_string(),
                issue_instant: root.get_attr("IssueInstant").and_then(parse_iso8601),
                issuer: issuer_of(&root),
                destination: opt(&root, "Destination"),
                acs_url: opt(&root, "AssertionConsumerServiceURL"),
                acs_index: root.get_attr("AssertionConsumerServiceIndex").and_then(|i| i.trim().parse().ok()),
                protocol_binding: opt(&root, "ProtocolBinding"),
                force_authn: flag(&root, "ForceAuthn"),
                is_passive: flag(&root, "IsPassive"),
                provider_name: opt(&root, "ProviderName"),
                name_id_format: policy.and_then(|p| opt(p, "Format")),
                allow_create: policy.and_then(|p| p.get_attr("AllowCreate")).map(|v| matches!(v.trim(), "true" | "1")),
                sp_name_qualifier: policy.and_then(|p| opt(p, "SPNameQualifier")),
                requested_authn_contexts: requested
                    .map(|r| r.find_all(NS_ASSERTION, "AuthnContextClassRef").map(Element::value).collect())
                    .unwrap_or_default(),
                authn_context_comparison: requested.and_then(|r| opt(r, "Comparison")),
                subject: root
                    .path(&[(NS_ASSERTION, "Subject"), (NS_ASSERTION, "NameID")])
                    .map(Element::value)
                    .filter(|v| !v.is_empty()),
                subject_format: root
                    .path(&[(NS_ASSERTION, "Subject"), (NS_ASSERTION, "NameID")])
                    .and_then(|n| opt(n, "Format")),
                signed,
            })
        }
        "LogoutRequest" => {
            let name_id = root.find(NS_ASSERTION, "NameID");
            Message::LogoutRequest(LogoutRequest {
                id,
                issuer: issuer_of(&root),
                destination: opt(&root, "Destination"),
                name_id: name_id.map(Element::value),
                name_id_format: name_id.and_then(|n| opt(n, "Format")),
                session_indexes: root.find_all(NS_PROTOCOL, "SessionIndex").map(Element::value).collect(),
                not_on_or_after: root.get_attr("NotOnOrAfter").and_then(parse_iso8601),
                signed,
                name_id_encrypted: root.find(NS_ASSERTION, "EncryptedID").is_some(),
            })
        }
        "LogoutResponse" => Message::LogoutResponse(LogoutResponse {
            id,
            issuer: issuer_of(&root),
            in_response_to: opt(&root, "InResponseTo"),
            destination: opt(&root, "Destination"),
            status: Status::from_element(root.find(NS_PROTOCOL, "Status")),
            signed,
        }),
        "ArtifactResolve" => Message::ArtifactResolve(ArtifactResolve {
            id,
            issuer: issuer_of(&root),
            artifact: root
                .find(NS_PROTOCOL, "Artifact")
                .map(Element::value)
                .ok_or("ArtifactResolve has no Artifact")?,
            signed,
        }),
        "AttributeQuery" => {
            let subject = root.find(NS_ASSERTION, "Subject").ok_or("AttributeQuery has no Subject")?;
            let name_id = subject.find(NS_ASSERTION, "NameID");
            let name_id_encrypted = subject.find(NS_ASSERTION, "EncryptedID").is_some();
            if name_id.is_none() && !name_id_encrypted {
                return Err("the AttributeQuery's Subject has no NameID or EncryptedID".into());
            }
            Message::AttributeQuery(AttributeQuery {
                id,
                issuer: issuer_of(&root),
                destination: opt(&root, "Destination"),
                name_id: name_id.map(Element::value),
                name_id_format: name_id.and_then(|n| opt(n, "Format")),
                name_id_encrypted,
                attributes: root
                    .find_all(NS_ASSERTION, "Attribute")
                    .filter_map(|a| {
                        Some(RequestedAttribute {
                            name: opt(a, "Name")?,
                            // An empty AttributeValue asks for any value (pysaml2 sends one).
                            values: a
                                .find_all(NS_ASSERTION, "AttributeValue")
                                .map(Element::text_content)
                                .filter(|v| !v.is_empty())
                                .collect(),
                        })
                    })
                    .collect(),
                signed,
            })
        }
        other => return Err(format!("unexpected message <{other}>")),
    };
    Ok(message)
}

// ---------------------------------------------------------------------------
// Deliberate defects
// ---------------------------------------------------------------------------

/// Ways to break a Response on purpose, to check that a service provider rejects it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tamper {
    /// No signatures at all.
    Unsigned,
    /// Signed, then a signed value (the NameID) is changed.
    BadSignature,
    /// Signed by a certificate that isn't in the metadata.
    WrongCert,
    /// Signed with RSA-SHA1 and a SHA-1 digest.
    Sha1,
    /// The assertion expired an hour ago.
    Expired,
    /// The assertion only becomes valid in an hour.
    NotYetValid,
    WrongAudience,
    WrongIssuer,
    /// The Response's `Destination` is somewhere else.
    WrongDestination,
    /// `SubjectConfirmationData/@Recipient` is somewhere else.
    WrongRecipient,
    /// `InResponseTo` doesn't match the AuthnRequest.
    WrongInResponseTo,
    /// Re-send the last Response this service provider was sent, unchanged.
    Replay,
}

impl Tamper {
    pub const ALL: [Tamper; 12] = [
        Tamper::Unsigned,
        Tamper::BadSignature,
        Tamper::WrongCert,
        Tamper::Sha1,
        Tamper::Expired,
        Tamper::NotYetValid,
        Tamper::WrongAudience,
        Tamper::WrongIssuer,
        Tamper::WrongDestination,
        Tamper::WrongRecipient,
        Tamper::WrongInResponseTo,
        Tamper::Replay,
    ];

    pub fn name(self) -> String {
        serde_json::to_value(self).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
    }

    pub fn parse(name: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(name.trim().to_string())).ok()
    }

    pub fn describe(self) -> &'static str {
        match self {
            Tamper::Unsigned => "nothing is signed",
            Tamper::BadSignature => "signed content (the NameID) was changed after signing",
            Tamper::WrongCert => "signed by a certificate that isn't in the metadata",
            Tamper::Sha1 => "signed with RSA-SHA1",
            Tamper::Expired => "the assertion expired an hour ago",
            Tamper::NotYetValid => "the assertion isn't valid for another hour",
            Tamper::WrongAudience => "the Audience is another service provider",
            Tamper::WrongIssuer => "the Issuer is another identity provider",
            Tamper::WrongDestination => "the Destination is another URL",
            Tamper::WrongRecipient => "the Recipient is another URL",
            Tamper::WrongInResponseTo => "InResponseTo doesn't match the request",
            Tamper::Replay => "a replay of the previous response",
        }
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// Everything needed to issue a Response.
pub struct ResponseSpec<'a> {
    pub preset: &'static Preset,
    pub issuer: String,
    pub identity: &'a Identity,
    /// ACS URL: the Response's `Destination` and the `Recipient`.
    pub destination: String,
    pub audience: String,
    pub in_response_to: Option<String>,
    pub session_index: String,
    /// The assertion's ID, when the caller needs it up front (as a SessionIndex); else generated.
    pub assertion_id: Option<String>,
    pub auth_time: i64,
    pub now: i64,
    pub sign_response: bool,
    pub sign_assertion: bool,
    pub sig_alg: SigAlg,
    pub encrypt: Option<(RsaPublicKey, EncAlg)>,
    /// Send the NameID as an `EncryptedID` for this key.
    pub encrypt_name_id: Option<(RsaPublicKey, EncAlg)>,
    /// Send each attribute as an `EncryptedAttribute` for this key.
    pub encrypt_attributes: Option<(RsaPublicKey, EncAlg)>,
    /// Overrides the template's assertion lifetime.
    pub lifetime: Option<i64>,
    pub authn_context: String,
    pub sp_name_qualifier: Option<String>,
    /// A non-success status: the Response carries no assertion.
    pub status: Option<Status>,
    pub tampers: Vec<Tamper>,
    /// Answering an AttributeQuery: sender-vouches confirmation (for the audience) instead of
    /// bearer, no AuthnStatement, and (with an empty `destination`) no Destination.
    pub attribute_query: bool,
}

#[derive(Debug, Clone)]
pub struct Issued {
    /// The document to send (with an XML declaration).
    pub xml: String,
    /// Indented, for people. With an encrypted assertion, the plaintext follows as a comment.
    pub pretty: String,
    pub response_id: String,
    pub assertion_id: Option<String>,
    pub encrypted: bool,
}

const INVALID: &str = "localsaml.invalid";

pub fn build_response(key: &KeyPair, spec: &ResponseSpec) -> Result<Issued, String> {
    let style = &spec.preset.style;
    let has = |t: Tamper| spec.tampers.contains(&t);
    let a = |local: &str| Element::new(NS_ASSERTION, style.assertion_prefix, local);
    let p = |local: &str| Element::new(NS_PROTOCOL, style.protocol_prefix, local);
    let issuer_value =
        if has(Tamper::WrongIssuer) { format!("https://wrong-issuer.{INVALID}") } else { spec.issuer.clone() };
    let issuer = || a("Issuer").attr_opt("Format", style.issuer_format.then_some(nameid::ENTITY)).text(&issuer_value);
    let now = if has(Tamper::Expired) {
        spec.now - spec.lifetime.unwrap_or(spec.preset.assertion_lifetime) - spec.preset.not_before_skew - 3600
    } else if has(Tamper::NotYetValid) {
        spec.now + spec.preset.not_before_skew + 3600
    } else {
        spec.now
    };
    let lifetime = spec.lifetime.unwrap_or(spec.preset.assertion_lifetime);
    let in_response_to =
        if has(Tamper::WrongInResponseTo) { Some(crate::util::saml_id("_wrong")) } else { spec.in_response_to.clone() };
    let destination = if has(Tamper::WrongDestination) {
        format!("https://wrong-destination.{INVALID}/acs")
    } else {
        spec.destination.clone()
    };

    let response_id = style.id_style.generate();
    let mut response = p("Response")
        .attr("ID", &response_id)
        .attr("Version", "2.0")
        .attr("IssueInstant", iso8601(now))
        .attr_opt("Destination", Some(&destination).filter(|d| !d.is_empty()))
        .attr_opt("InResponseTo", in_response_to.clone())
        .declare(style.protocol_prefix, NS_PROTOCOL);
    if !style.assertion_prefix.is_empty() {
        response = response.declare(style.assertion_prefix, NS_ASSERTION);
    }
    response = response.child(issuer()).child(spec.status.clone().unwrap_or_else(Status::success).element(style));

    let mut sign_opts = SignOpts {
        alg: if has(Tamper::Sha1) { SigAlg::RsaSha1 } else { spec.sig_alg },
        prefix: style.dsig_prefix.into(),
        inclusive: style.xsi_type.map(|_| vec!["xs".to_string()]).unwrap_or_default(),
        key_info: true,
    };
    let untrusted;
    let key = if has(Tamper::WrongCert) {
        untrusted = crate::keys::untrusted();
        untrusted
    } else {
        key
    };
    let unsigned = has(Tamper::Unsigned);

    if spec.status.as_ref().is_some_and(|s| !s.is_success()) {
        response.declare_namespaces();
        if spec.sign_response && !unsigned {
            sign_opts.inclusive.clear();
            dsig::sign(&mut response, &response_id, key, &sign_opts)?;
        }
        return Ok(Issued {
            xml: response.to_document(),
            pretty: response.to_pretty(),
            response_id,
            assertion_id: None,
            encrypted: false,
        });
    }

    let assertion_id = spec.assertion_id.clone().unwrap_or_else(|| new_assertion_id(style));
    let (mut assertion, decrypted_notes) =
        build_assertion(spec, &assertion_id, &issuer(), now, lifetime, in_response_to.as_deref())?;
    let mut assertion_pretty = None;
    if let Some((recipient, alg)) = &spec.encrypt {
        assertion.declare_namespaces();
        if spec.sign_assertion && !unsigned {
            dsig::sign(&mut assertion, &assertion_id, key, &sign_opts)?;
        }
        // With an encrypted assertion, break its own signature before encryption; a response
        // signature is broken below.
        if has(Tamper::BadSignature) && spec.sign_assertion {
            tamper_signed(&mut assertion, now);
        }
        assertion_pretty = Some(assertion.to_pretty());
        let mut encrypted = a("EncryptedAssertion");
        let parts = xmlenc::encrypt(&assertion.to_xml(), recipient, *alg, spec.preset.encrypted_key)?;
        encrypted.children.extend(parts.into_iter().map(crate::xml::Node::Element));
        response = response.child(encrypted);
        response.declare_namespaces();
    } else {
        response = response.child(assertion);
        response.declare_namespaces();
        if spec.sign_assertion && !unsigned {
            dsig::sign(&mut response, &assertion_id, key, &sign_opts)?;
        }
    }
    if spec.sign_response && !unsigned {
        dsig::sign(&mut response, &response_id, key, &sign_opts)?;
    }
    if has(Tamper::BadSignature) {
        if spec.encrypt.is_none() {
            tamper_signed(&mut response, now);
        } else if spec.sign_response {
            // The NameID is inside the ciphertext, so change a signed value of the Response itself.
            response.set_attr("IssueInstant", iso8601(now + 1));
        }
    }
    let mut pretty = response.to_pretty();
    if let Some(plain) = assertion_pretty {
        pretty.push_str(&format!("\n<!-- The EncryptedAssertion, decrypted: -->\n{plain}"));
    }
    if let Some(plain) = decrypted_notes {
        pretty.push_str(&plain);
    }
    Ok(Issued {
        xml: response.to_document(),
        pretty,
        response_id,
        assertion_id: Some(assertion_id),
        encrypted: spec.encrypt.is_some(),
    })
}

/// A new assertion ID in a template's style.
pub fn new_assertion_id(style: &Style) -> String {
    style.assertion_id_style.unwrap_or(style.id_style).generate()
}

/// Change the NameID's text wherever it is (after signing, for `bad_signature`).
fn tamper_name_id(el: &mut Element) -> bool {
    if el.is(NS_ASSERTION, "NameID") {
        el.children = vec![crate::xml::Node::Text("tampered-after-signing".into())];
        return true;
    }
    el.elements_mut().any(tamper_name_id)
}

/// Change a signed value of an assertion (or the Response holding it): the NameID, or with an
/// EncryptedID, the assertion's IssueInstant.
fn tamper_signed(el: &mut Element, now: i64) {
    if tamper_name_id(el) {
        return;
    }
    let assertion = if el.is(NS_ASSERTION, "Assertion") { Some(el) } else { el.find_mut(NS_ASSERTION, "Assertion") };
    if let Some(a) = assertion {
        a.set_attr("IssueInstant", iso8601(now + 1));
    }
}

/// An `EncryptedID` holding `name_id` (Core 2.2.4), for `recipient`. The EncryptedKey is always
/// inside the EncryptedData's KeyInfo: some service providers (pysaml2) decrypt the EncryptedData
/// alone, and no template's IdP sends encrypted NameIDs the other way.
pub fn encrypted_id(
    style: &Style,
    name_id: &Element,
    recipient: &RsaPublicKey,
    alg: EncAlg,
) -> Result<Element, String> {
    encrypted_element(style, "EncryptedID", name_id, recipient, alg)
}

/// `el` encrypted inside an `EncryptedID`, `EncryptedAttribute` (…) element.
fn encrypted_element(
    style: &Style,
    local: &str,
    el: &Element,
    recipient: &RsaPublicKey,
    alg: EncAlg,
) -> Result<Element, String> {
    let mut plain = el.clone();
    plain.declare_namespaces();
    let mut encrypted = Element::new(NS_ASSERTION, style.assertion_prefix, local);
    encrypted.children.extend(
        xmlenc::encrypt(&plain.to_xml(), recipient, alg, xmlenc::KeyPlacement::Inline)?
            .into_iter()
            .map(crate::xml::Node::Element),
    );
    Ok(encrypted)
}

/// The NameID in an `EncryptedID`.
pub fn decrypt_id(encrypted: &Element, keys: &[rsa::RsaPrivateKey]) -> Result<Element, String> {
    let name_id = parse(&xmlenc::decrypt(encrypted, keys)?)?;
    if !name_id.is(NS_ASSERTION, "NameID") {
        return Err(format!("the EncryptedID holds <{}>, not a NameID", name_id.qname()));
    }
    Ok(name_id)
}

/// The assertion, and with an EncryptedID or EncryptedAttributes, what they hold (for people).
fn build_assertion(
    spec: &ResponseSpec,
    id: &str,
    issuer: &Element,
    now: i64,
    lifetime: i64,
    in_response_to: Option<&str>,
) -> Result<(Element, Option<String>), String> {
    let style = &spec.preset.style;
    let has = |t: Tamper| spec.tampers.contains(&t);
    let a = |local: &str| Element::new(NS_ASSERTION, style.assertion_prefix, local);
    let recipient = if has(Tamper::WrongRecipient) {
        format!("https://wrong-recipient.{INVALID}/acs")
    } else {
        spec.destination.clone()
    };
    let audience =
        if has(Tamper::WrongAudience) { format!("https://wrong-audience.{INVALID}") } else { spec.audience.clone() };

    let name_id = a("NameID")
        .attr_opt("SPNameQualifier", spec.sp_name_qualifier.clone())
        .attr("Format", &spec.identity.name_id_format)
        .text(&spec.identity.name_id);
    let mut plain = String::new();
    let name_id = match &spec.encrypt_name_id {
        Some((recipient, alg)) => {
            plain.push_str(&format!("\n<!-- The EncryptedID, decrypted: -->\n{}", name_id.to_pretty()));
            encrypted_id(style, &name_id, recipient, *alg)?
        }
        None => name_id,
    };
    // A query's answer goes back over SOAP: the identity provider vouches for the subject to the
    // service provider (the Recipient), rather than a browser bearing it to an ACS.
    let (method, recipient) =
        if spec.attribute_query { (CM_SENDER_VOUCHES, audience.clone()) } else { (CM_BEARER, recipient) };
    let confirmation = a("SubjectConfirmation").attr("Method", method).child(
        a("SubjectConfirmationData")
            .attr_opt("InResponseTo", in_response_to)
            .attr(
                "NotOnOrAfter",
                // An explicit lifetime applies to both; otherwise some templates confirm for
                // less (or longer) than the assertion is valid.
                iso8601(now + spec.lifetime.or(spec.preset.confirmation_lifetime).unwrap_or(lifetime)),
            )
            .attr("Recipient", recipient),
    );
    let subject = a("Subject").child(name_id).child(confirmation);
    let conditions = a("Conditions")
        .attr("NotBefore", iso8601(now - spec.preset.not_before_skew))
        .attr("NotOnOrAfter", iso8601(now + lifetime))
        .child(a("AudienceRestriction").child(a("Audience").text(audience)));
    let authn = a("AuthnStatement")
        .attr("AuthnInstant", iso8601(spec.auth_time))
        .attr("SessionIndex", &spec.session_index)
        .attr_opt("SessionNotOnOrAfter", spec.preset.session_lifetime.map(|s| iso8601(spec.auth_time + s)))
        .child(a("AuthnContext").child(a("AuthnContextClassRef").text(&spec.authn_context)));
    // An attribute authority answers with the values it has (no template's empty attributes).
    let mut attributes = attribute_statement(spec.preset, spec.identity, !spec.attribute_query);
    if let (Some((recipient, alg)), Some(statement)) = (&spec.encrypt_attributes, attributes.as_mut()) {
        plain.push_str(&format!("\n<!-- The EncryptedAttributes, decrypted: -->\n{}", statement.to_pretty()));
        for node in statement.children.iter_mut() {
            if let crate::xml::Node::Element(attribute) = node {
                *attribute = encrypted_element(style, "EncryptedAttribute", attribute, recipient, *alg)?;
            }
        }
    }

    let mut assertion = a("Assertion")
        .attr("ID", id)
        .attr("IssueInstant", iso8601(now))
        .attr("Version", "2.0")
        .child(issuer.clone())
        .child(subject)
        .child(conditions);
    if spec.attribute_query {
        assertion = assertion.child_opt(attributes);
    } else if style.attributes_first {
        assertion = assertion.child_opt(attributes).child(authn);
    } else {
        assertion = assertion.child(authn).child_opt(attributes);
    }
    Ok((assertion, Some(plain).filter(|p| !p.is_empty())))
}

fn attribute_statement(preset: &Preset, identity: &Identity, empty_attributes: bool) -> Option<Element> {
    let style = &preset.style;
    let send_empty = preset.send_empty_attributes && empty_attributes;
    let a = |local: &str| Element::new(NS_ASSERTION, style.assertion_prefix, local);
    let mut statement = a("AttributeStatement");
    // The template's attributes in its order, then any others.
    let known = preset.attributes.iter().map(|a| a.name).filter(|n| identity.attributes.contains_key(*n));
    let others = identity.attributes.keys().map(String::as_str).filter(|n| preset.attribute(n).is_none());
    let known: Vec<&str> =
        if send_empty { preset.attributes.iter().map(|a| a.name).collect() } else { known.collect() };
    for name in known.into_iter().chain(others) {
        let mut values = identity.values(name);
        if values.is_empty() {
            if !send_empty || preset.attribute(name).is_none() {
                continue;
            }
            values.push(String::new());
        }
        let known = preset.attribute(name);
        let attribute = || {
            a("Attribute")
                .attr("Name", name)
                .attr_opt("NameFormat", known.and_then(|k| k.name_format).or(style.name_format))
                .attr_opt("FriendlyName", known.and_then(|k| k.friendly_name))
        };
        let value = |value: String| {
            let mut v = a("AttributeValue");
            if let Some(t) = known.and_then(|k| k.xsi_type).or(style.xsi_type) {
                v = v.declare("xs", NS_XS).declare("xsi", NS_XSI).ns_attr(NS_XSI, "xsi", "type", t);
            }
            if value.is_empty() { v } else { v.text(value) }
        };
        if known.is_some_and(|k| k.split_values) {
            for v in values {
                statement = statement.child(attribute().child(value(v)));
            }
        } else {
            statement = statement.child(values.into_iter().fold(attribute(), |attr, v| attr.child(value(v))));
        }
    }
    (!statement.children.is_empty()).then_some(statement)
}

// ---------------------------------------------------------------------------
// Logout messages
// ---------------------------------------------------------------------------

pub struct LogoutRequestSpec<'a> {
    pub style: &'a Style,
    pub issuer: &'a str,
    pub destination: &'a str,
    pub name_id: &'a str,
    pub name_id_format: &'a str,
    pub sp_name_qualifier: Option<&'a str>,
    pub session_index: &'a str,
    pub now: i64,
    /// Send the NameID as an `EncryptedID`.
    pub encrypt: Option<(&'a RsaPublicKey, EncAlg)>,
}

/// A LogoutRequest and its ID.
pub fn logout_request(spec: &LogoutRequestSpec) -> Result<(Element, String), String> {
    let style = spec.style;
    let id = style.id_style.generate();
    let a = |local: &str| Element::new(NS_ASSERTION, style.assertion_prefix, local);
    let p = |local: &str| Element::new(NS_PROTOCOL, style.protocol_prefix, local);
    let mut el = p("LogoutRequest")
        .attr("ID", &id)
        .attr("Version", "2.0")
        .attr("IssueInstant", iso8601(spec.now))
        .attr("Destination", spec.destination)
        .attr("NotOnOrAfter", iso8601(spec.now + 300))
        .declare(style.protocol_prefix, NS_PROTOCOL)
        .child(a("Issuer").attr_opt("Format", style.issuer_format.then_some(nameid::ENTITY)).text(spec.issuer))
        .child({
            let name_id = a("NameID")
                .attr_opt("SPNameQualifier", spec.sp_name_qualifier)
                .attr("Format", spec.name_id_format)
                .text(spec.name_id);
            match spec.encrypt {
                Some((recipient, alg)) => encrypted_id(style, &name_id, recipient, alg)?,
                None => name_id,
            }
        })
        .child(p("SessionIndex").text(spec.session_index));
    el.declare_namespaces();
    Ok((el, id))
}

/// A LogoutResponse and its ID.
pub fn logout_response(
    style: &Style,
    issuer: &str,
    destination: &str,
    in_response_to: Option<&str>,
    status: &Status,
    now: i64,
) -> (Element, String) {
    logout_response_to(style, issuer, Some(destination), in_response_to, status, now)
}

/// A LogoutResponse and its ID; SOAP responses have no `Destination`.
pub fn logout_response_to(
    style: &Style,
    issuer: &str,
    destination: Option<&str>,
    in_response_to: Option<&str>,
    status: &Status,
    now: i64,
) -> (Element, String) {
    let id = style.id_style.generate();
    let a = |local: &str| Element::new(NS_ASSERTION, style.assertion_prefix, local);
    let p = |local: &str| Element::new(NS_PROTOCOL, style.protocol_prefix, local);
    let mut el = p("LogoutResponse")
        .attr("ID", &id)
        .attr("Version", "2.0")
        .attr("IssueInstant", iso8601(now))
        .attr_opt("Destination", destination)
        .attr_opt("InResponseTo", in_response_to)
        .declare(style.protocol_prefix, NS_PROTOCOL)
        .child(a("Issuer").attr_opt("Format", style.issuer_format.then_some(nameid::ENTITY)).text(issuer))
        .child(status.element(style));
    el.declare_namespaces();
    (el, id)
}

/// Sign a protocol message in place (for the POST binding).
pub fn sign_message(el: &mut Element, id: &str, key: &KeyPair, style: &Style, alg: SigAlg) -> Result<(), String> {
    dsig::sign(el, id, key, &SignOpts { alg, prefix: style.dsig_prefix.into(), inclusive: vec![], key_info: true })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presets;

    fn spec<'a>(preset: &'static Preset, identity: &'a Identity) -> ResponseSpec<'a> {
        ResponseSpec {
            preset,
            issuer: "http://idp.test/metadata".into(),
            identity,
            destination: "http://sp.test/acs".into(),
            audience: "http://sp.test".into(),
            in_response_to: Some("_req1".into()),
            session_index: "_s1".into(),
            assertion_id: None,
            auth_time: 1_793_451_600,
            now: 1_793_451_600,
            sign_response: preset.sign_response,
            sign_assertion: preset.sign_assertion,
            sig_alg: SigAlg::RsaSha256,
            encrypt: None,
            encrypt_name_id: None,
            encrypt_attributes: None,
            lifetime: None,
            authn_context: preset.authn_context.into(),
            sp_name_qualifier: None,
            status: None,
            tampers: vec![],
            attribute_query: false,
        }
    }

    #[test]
    fn encrypted_name_ids_decrypt_and_tampering_still_breaks_the_signature() {
        let key = crate::keys::untrusted();
        let preset = presets::generic();
        let identity = preset.default_identity();
        let mut s = spec(preset, &identity);
        s.sign_response = true;
        s.encrypt_name_id = Some((key.public.clone(), EncAlg::Aes256Gcm));
        let issued = build_response(key, &s).unwrap();
        let doc = parse(&issued.xml).unwrap();
        let subject = doc.find(NS_ASSERTION, "Assertion").unwrap().find(NS_ASSERTION, "Subject").unwrap();
        assert!(subject.find(NS_ASSERTION, "NameID").is_none());
        let name_id =
            decrypt_id(subject.find(NS_ASSERTION, "EncryptedID").unwrap(), std::slice::from_ref(&key.private)).unwrap();
        assert_eq!(name_id.value(), identity.name_id);
        assert!(issued.pretty.contains("The EncryptedID, decrypted"));
        dsig::verify(&doc, &issued.response_id, std::slice::from_ref(&key.public)).unwrap();

        s.tampers = vec![Tamper::BadSignature];
        let issued = build_response(key, &s).unwrap();
        let doc = parse(&issued.xml).unwrap();
        assert!(dsig::verify(&doc, &issued.response_id, std::slice::from_ref(&key.public)).is_err());
    }

    #[test]
    fn every_template_issues_responses_that_verify() {
        let key = crate::keys::untrusted();
        for preset in presets::all() {
            let identity = preset.default_identity();
            let issued = build_response(key, &spec(preset, &identity)).unwrap();
            let doc = parse(&issued.xml).unwrap();
            let keys = [key.public.clone()];
            if preset.sign_response {
                dsig::verify(&doc, &issued.response_id, &keys).unwrap_or_else(|e| panic!("{}: {e}", preset.id));
            }
            if preset.sign_assertion {
                dsig::verify(&doc, issued.assertion_id.as_ref().unwrap(), &keys)
                    .unwrap_or_else(|e| panic!("{}: {e}", preset.id));
            }
            let assertion = doc.find(NS_ASSERTION, "Assertion").expect("assertion");
            assert_eq!(assertion.prefix.as_deref().unwrap_or(""), preset.style.assertion_prefix, "{}", preset.id);
        }
    }

    #[test]
    fn encrypted_assertions_decrypt_and_verify() {
        let key = crate::keys::untrusted();
        let preset = presets::get("shibboleth").unwrap();
        let identity = preset.default_identity();
        let mut s = spec(preset, &identity);
        s.sign_assertion = true;
        s.encrypt = Some((key.public.clone(), EncAlg::Aes256Gcm));
        let issued = build_response(key, &s).unwrap();
        let doc = parse(&issued.xml).unwrap();
        let enc = doc.find(NS_ASSERTION, "EncryptedAssertion").unwrap();
        let plain = xmlenc::decrypt(enc, std::slice::from_ref(&key.private)).unwrap();
        let assertion = parse(&plain).unwrap();
        dsig::verify(&assertion, issued.assertion_id.as_ref().unwrap(), std::slice::from_ref(&key.public)).unwrap();
        dsig::verify(&doc, &issued.response_id, std::slice::from_ref(&key.public)).unwrap();
    }

    #[test]
    fn tampers_break_what_they_say() {
        let key = crate::keys::untrusted();
        let preset = presets::generic();
        let identity = preset.default_identity();
        let keys = [key.public.clone()];
        let mut s = spec(preset, &identity);
        s.tampers = vec![Tamper::BadSignature];
        let issued = build_response(key, &s).unwrap();
        let doc = parse(&issued.xml).unwrap();
        assert!(dsig::verify(&doc, &issued.response_id, &keys).unwrap_err().contains("digest"));
        // Encrypted, with only the Response signed (Shibboleth's defaults).
        let shib = presets::get("shibboleth").unwrap();
        let shib_identity = shib.default_identity();
        let mut e = spec(shib, &shib_identity);
        e.encrypt = Some((key.public.clone(), EncAlg::Aes256Gcm));
        e.tampers = vec![Tamper::BadSignature];
        let issued = build_response(key, &e).unwrap();
        let doc = parse(&issued.xml).unwrap();
        assert!(dsig::verify(&doc, &issued.response_id, &keys).unwrap_err().contains("digest"));
        s.tampers = vec![Tamper::Unsigned];
        let doc = parse(&build_response(key, &s).unwrap().xml).unwrap();
        assert!(dsig::signature_of(&doc).is_none());
        s.tampers = vec![Tamper::Expired];
        let xml = build_response(key, &s).unwrap().xml;
        let doc = parse(&xml).unwrap();
        let conditions = doc.path(&[(NS_ASSERTION, "Assertion"), (NS_ASSERTION, "Conditions")]).unwrap();
        assert!(parse_iso8601(conditions.get_attr("NotOnOrAfter").unwrap()).unwrap() < s.now);
    }

    #[test]
    fn statuses_and_messages() {
        let st = Status::parse("NoPassive", None).unwrap();
        assert_eq!(st.code, status::RESPONDER);
        assert_eq!(st.short(), "NoPassive");
        assert!(Status::parse("Bogus", None).is_err());
        let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-10-31T13:00:00Z" AssertionConsumerServiceURL="http://sp/acs" ForceAuthn="true"><saml:Issuer>http://sp</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>"#;
        let encoded = deflate_b64(xml);
        let decoded = decode_message(&encoded, true).unwrap();
        let (Message::AuthnRequest(req), _) = parse_message(&decoded).unwrap() else { panic!() };
        assert_eq!((req.id.as_str(), req.issuer.as_deref(), req.force_authn), ("_r1", Some("http://sp"), true));
        assert_eq!(req.name_id_format.as_deref(), Some(nameid::EMAIL));
        assert_eq!(decode_message(&b64_std(xml), false).unwrap(), xml);
    }
}

// ---------------------------------------------------------------------------
// Artifacts (HTTP-Artifact binding)
// ---------------------------------------------------------------------------

/// A type 0x0004 artifact (Bindings 3.6.4): the type code, the index of the
/// ArtifactResolutionService to ask, the SHA-1 of the issuer's entity ID and a random handle.
pub fn new_artifact(issuer: &str, endpoint_index: u16) -> String {
    use sha1::Digest;
    let mut bytes = vec![0x00, 0x04];
    bytes.extend(endpoint_index.to_be_bytes());
    bytes.extend(sha1::Sha1::digest(issuer.as_bytes()));
    bytes.extend((0..20).map(|_| rand::random::<u8>()));
    b64_std(bytes)
}

/// Check an artifact's shape and that it was issued by `issuer`.
pub fn check_artifact(artifact: &str, issuer: &str) -> Result<(), String> {
    use sha1::Digest;
    let bytes = b64_std_decode_lenient(artifact).ok_or("the artifact is not base64")?;
    if bytes.len() != 44 || bytes[..2] != [0x00, 0x04] {
        return Err("not a type 0x0004 artifact".into());
    }
    if bytes[4..24] != sha1::Sha1::digest(issuer.as_bytes())[..] {
        return Err("the artifact's SourceID isn't this identity provider's".into());
    }
    Ok(())
}

/// An ArtifactResponse carrying `message` (none when the artifact is unknown, used, or not the
/// requester's), and its ID.
pub fn artifact_response(
    style: &Style,
    issuer: &str,
    in_response_to: &str,
    message: Option<Element>,
    now: i64,
) -> (Element, String) {
    let id = style.id_style.generate();
    let a = |local: &str| Element::new(NS_ASSERTION, style.assertion_prefix, local);
    let p = |local: &str| Element::new(NS_PROTOCOL, style.protocol_prefix, local);
    let mut el = p("ArtifactResponse")
        .attr("ID", &id)
        .attr("Version", "2.0")
        .attr("IssueInstant", iso8601(now))
        .attr("InResponseTo", in_response_to)
        .declare(style.protocol_prefix, NS_PROTOCOL)
        .child(a("Issuer").attr_opt("Format", style.issuer_format.then_some(nameid::ENTITY)).text(issuer))
        .child(Status::success().element(style))
        .child_opt(message);
    el.declare_namespaces();
    (el, id)
}

/// An AttributeQuery (what a service provider sends) for a NameID, asking for `attributes` (all
/// of them when empty), and its ID.
pub fn attribute_query(
    issuer: &str,
    destination: &str,
    name_id: &str,
    name_id_format: &str,
    attributes: &[&str],
    now: i64,
) -> (Element, String) {
    let id = crate::util::saml_id("_");
    let a = |local: &str| Element::new(NS_ASSERTION, "saml", local);
    let mut el = Element::new(NS_PROTOCOL, "samlp", "AttributeQuery")
        .attr("ID", &id)
        .attr("Version", "2.0")
        .attr("IssueInstant", iso8601(now))
        .attr("Destination", destination)
        .declare("samlp", NS_PROTOCOL)
        .declare("saml", NS_ASSERTION)
        .child(a("Issuer").text(issuer))
        .child(a("Subject").child(a("NameID").attr("Format", name_id_format).text(name_id)));
    for name in attributes {
        el = el.child(a("Attribute").attr("Name", *name));
    }
    el.declare_namespaces();
    (el, id)
}

/// An ArtifactResolve (what a service provider sends), and its ID.
pub fn artifact_resolve(issuer: &str, destination: &str, artifact: &str, now: i64) -> (Element, String) {
    let id = crate::util::saml_id("_");
    let mut el = Element::new(NS_PROTOCOL, "samlp", "ArtifactResolve")
        .attr("ID", &id)
        .attr("Version", "2.0")
        .attr("IssueInstant", iso8601(now))
        .attr("Destination", destination)
        .declare("samlp", NS_PROTOCOL)
        .declare("saml", NS_ASSERTION)
        .child(Element::new(NS_ASSERTION, "saml", "Issuer").text(issuer))
        .child(Element::new(NS_PROTOCOL, "samlp", "Artifact").text(artifact));
    el.declare_namespaces();
    (el, id)
}

#[cfg(test)]
mod artifact_tests {
    use super::*;

    #[test]
    fn artifacts_name_their_issuer() {
        let art = new_artifact("http://idp.test/metadata", 0);
        assert_eq!(b64_std_decode_lenient(&art).unwrap().len(), 44);
        assert!(check_artifact(&art, "http://idp.test/metadata").is_ok());
        assert!(check_artifact(&art, "http://other.test/metadata").is_err());
        assert!(check_artifact("AAAA", "http://idp.test/metadata").is_err());
    }
}

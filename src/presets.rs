//! Identity provider templates: the attribute names, NameID, signing behaviour and XML style of
//! SAML identity providers commonly used in production, so an app can be developed against the
//! same shapes it will see there.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::util::value_to_string;
use crate::xmlenc::{EncAlg, KeyPlacement};

pub mod nameid {
    pub const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
    pub const EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    pub const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    pub const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
    pub const X509: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
    pub const WINDOWS: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";
    pub const KERBEROS: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";
    pub const ENTITY: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
    pub const ALL: &[&str] = &[UNSPECIFIED, EMAIL, PERSISTENT, TRANSIENT, X509, WINDOWS, KERBEROS, ENTITY];
}

pub mod authn {
    pub const PASSWORD_PROTECTED: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
    pub const PASSWORD: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
    pub const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
    pub const X509: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509";
    pub const KERBEROS: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos";
    pub const MFA: &str = "http://schemas.microsoft.com/claims/multipleauthn";
    pub const ALL: &[&str] = &[PASSWORD_PROTECTED, PASSWORD, UNSPECIFIED, X509, KERBEROS, MFA];
}

pub mod attrname {
    pub const BASIC: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
    pub const URI: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
    pub const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";
}

#[derive(Debug, Clone, Serialize)]
pub struct Attribute {
    /// The SAML `Name` of the attribute.
    pub name: &'static str,
    pub label: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<&'static str>,
    /// Overrides the template's `NameFormat` for this attribute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_format: Option<&'static str>,
    /// Overrides the template's `xsi:type` for this attribute's values (e.g. `xs:boolean`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xsi_type: Option<&'static str>,
    /// One `<Attribute>` per value instead of one with several values (Keycloak's role list
    /// mapper with "Single Role Attribute" off, its default).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub split_values: bool,
    /// `string` (one value) or `list` (any number of values).
    pub kind: &'static str,
    pub default: Value,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub help: &'static str,
    /// Less commonly needed attributes, tucked behind "Show all attributes" in the UI.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub advanced: bool,
    /// An identifier that must differ per user (object IDs, SIDs, ...): declared users get their
    /// own stable value shaped like the default.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unique: bool,
}

impl Attribute {
    fn help(mut self, help: &'static str) -> Self {
        self.help = help;
        self
    }
    fn advanced(mut self) -> Self {
        self.advanced = true;
        self
    }
    fn unique(mut self) -> Self {
        self.unique = true;
        self
    }
    fn friendly(mut self, name: &'static str) -> Self {
        self.friendly_name = Some(name);
        self
    }
    fn format(mut self, format: &'static str) -> Self {
        self.name_format = Some(format);
        self
    }
    fn split(mut self) -> Self {
        self.split_values = true;
        self
    }
    fn xsi(mut self, xsi_type: &'static str) -> Self {
        self.xsi_type = Some(xsi_type);
        self
    }
}

fn s(name: &'static str, label: &'static str, default: &str) -> Attribute {
    Attribute {
        name,
        label,
        friendly_name: None,
        name_format: None,
        xsi_type: None,
        split_values: false,
        kind: "string",
        default: json!(default),
        help: "",
        advanced: false,
        unique: false,
    }
}

fn l(name: &'static str, label: &'static str, default: &[&str]) -> Attribute {
    Attribute { kind: "list", default: json!(default), ..s(name, label, "") }
}

/// How `ID` attributes look.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdStyle {
    /// `_` followed by 40 hex digits.
    Hex,
    /// `_` followed by a UUID (Entra ID, AD FS).
    UnderscoreUuid,
    /// `id` followed by digits (Okta).
    OktaDigits,
    /// `ID_` followed by a UUID (Keycloak).
    KeycloakUuid,
    /// `pfx` followed by a UUID (OneLogin).
    PfxUuid,
    /// Random URL-safe characters starting with a letter (PingFederate).
    Alnum,
    /// `A` followed by 40 hex digits (OneLogin assertions).
    AHex,
    /// 40 upper-case letters and digits, starting with a letter (JumpCloud).
    Upper40,
}

impl IdStyle {
    pub fn generate(self) -> String {
        let uuid = || uuid::Uuid::new_v4().to_string();
        match self {
            IdStyle::Hex => crate::util::saml_id("_"),
            IdStyle::UnderscoreUuid => format!("_{}", uuid()),
            IdStyle::OktaDigits => {
                let digits: String = (0..25).map(|_| char::from(b'0' + rand::random::<u8>() % 10)).collect();
                format!("id{digits}")
            }
            IdStyle::KeycloakUuid => format!("ID_{}", uuid()),
            IdStyle::PfxUuid => format!("pfx{}", uuid()),
            IdStyle::AHex => crate::util::saml_id("A"),
            IdStyle::Upper40 => {
                const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                let rest: String =
                    (0..39).map(|_| ALPHABET[rand::random::<usize>() % ALPHABET.len()] as char).collect();
                format!("{}{rest}", (b'A' + rand::random::<u8>() % 26) as char)
            }
            IdStyle::Alnum => {
                const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                let rest: String =
                    (0..27).map(|_| ALPHABET[rand::random::<usize>() % ALPHABET.len()] as char).collect();
                format!("{}{rest}", (b'A' + rand::random::<u8>() % 26) as char)
            }
        }
    }
}

/// What a template uses as an AuthnStatement's `SessionIndex`.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionIndexStyle {
    /// One random value for the whole browser session.
    Session,
    /// The assertion's ID (Entra ID, AD FS, Google, Keycloak).
    AssertionId,
    /// The AuthnRequest's ID, or the session's for IdP-initiated logins (Okta).
    RequestId,
}

/// The XML a provider writes. Matching it catches code that depends on one provider's
/// prefixes or ordering (XPath with hard-coded prefixes, regexes over the XML, ...).
#[derive(Debug, Clone, Serialize)]
pub struct Style {
    /// Prefix for the protocol namespace (`samlp`, `saml2p`).
    pub protocol_prefix: &'static str,
    /// Prefix for the assertion namespace (`saml`, `saml2`, or empty for the default namespace).
    pub assertion_prefix: &'static str,
    /// Prefix for XML signatures (`ds`, `dsig`, or empty for the default namespace).
    pub dsig_prefix: &'static str,
    pub id_style: IdStyle,
    /// `NameFormat` on attributes, if any.
    pub name_format: Option<&'static str>,
    /// `xsi:type` on attribute values (`xs:string`, `xs:anyType`), if any.
    pub xsi_type: Option<&'static str>,
    /// Put the AttributeStatement before the AuthnStatement.
    pub attributes_first: bool,
    /// Write `Format="...:entity"` on Issuer elements.
    pub issuer_format: bool,
    /// How assertion IDs look, when not like the Response's.
    pub assertion_id_style: Option<IdStyle>,
}

const STD: Style = Style {
    protocol_prefix: "samlp",
    assertion_prefix: "saml",
    dsig_prefix: "ds",
    id_style: IdStyle::Hex,
    name_format: Some(attrname::BASIC),
    xsi_type: Some("xs:string"),
    attributes_first: false,
    issuer_format: false,
    assertion_id_style: None,
};

#[derive(Debug, Clone, Serialize)]
pub struct Preset {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub color: &'static str,
    /// The entity ID; `{base}` is replaced with the template's issuer URL
    /// (e.g. `http://localhost:9401/p/keycloak`).
    pub entity_id: &'static str,
    pub name_id_format: &'static str,
    /// Attribute whose (first) value becomes the NameID. Otherwise `name_id_example` is used,
    /// made unique per user.
    pub name_id_from: Option<&'static str>,
    pub name_id_example: &'static str,
    /// Attribute holding the user's email address (for `login_hint` and emailAddress NameIDs).
    pub email_attribute: Option<&'static str>,
    pub attributes: Vec<Attribute>,
    pub sign_response: bool,
    pub sign_assertion: bool,
    /// Encrypt assertions when the service provider has an encryption certificate.
    pub encrypt_when_possible: bool,
    /// Content encryption for assertions, unless the service provider sets its own.
    pub encryption: EncAlg,
    /// Where the encrypted key goes in an EncryptedAssertion.
    pub encrypted_key: KeyPlacement,
    /// Send every template attribute, with an empty value when the user has none (OneLogin sends
    /// all of a connector's parameters).
    pub send_empty_attributes: bool,
    pub authn_context: &'static str,
    /// Seconds from IssueInstant to `Conditions/@NotOnOrAfter`.
    pub assertion_lifetime: i64,
    /// Seconds before IssueInstant for `Conditions/@NotBefore`.
    pub not_before_skew: i64,
    /// `SessionNotOnOrAfter` on the AuthnStatement, in seconds from the login.
    pub session_lifetime: Option<i64>,
    /// Seconds from IssueInstant to `SubjectConfirmationData/@NotOnOrAfter`, when it differs from
    /// the assertion lifetime (AD FS, Keycloak).
    pub confirmation_lifetime: Option<i64>,
    pub session_index: SessionIndexStyle,
    pub style: Style,
    /// Provider-shaped endpoint aliases served under `/p/<id>`. The first SSO and SLO aliases
    /// are the ones the template's metadata advertises.
    pub endpoints: Vec<Endpoint>,
    pub single_logout: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    Sso,
    /// IdP-initiated SSO: names the service provider in a query parameter.
    Initiate,
    Slo,
    Metadata,
}

#[derive(Debug, Clone, Serialize)]
pub struct Endpoint {
    pub kind: EndpointKind,
    pub label: &'static str,
    /// Path relative to the template's issuer; `{name}` segments match anything.
    pub path: &'static str,
}

fn ep(kind: EndpointKind, label: &'static str, path: &'static str) -> Endpoint {
    Endpoint { kind, label, path }
}

/// Fill an alias path's `{placeholders}` with example values, for links and metadata.
pub fn fill_path(path: &str) -> String {
    path.replace("{tenant}", ENTRA_TENANT)
        .replace("{app}", "localsaml")
        .replace("{app_id}", "exk1fcia6d6EMsf331d8")
        .replace("{connector_id}", "6b7cf0a1-2d3e-4f50-9a1b-2c3d4e5f6a7b")
        .replace("{realm}", "example")
        .replace("{client_id}", "localsaml")
}

/// What a path within a template's issuer is, if it's one of the template aliases.
pub fn classify_alias(path: &str) -> Option<EndpointKind> {
    let segments: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    all().iter().flat_map(|p| &p.endpoints).find_map(|e| {
        let pattern: Vec<&str> = e.path.trim_end_matches('/').split('/').collect();
        let matches = pattern.len() == segments.len()
            && pattern.iter().zip(&segments).all(|(p, s)| p.starts_with('{') || p.eq_ignore_ascii_case(s));
        matches.then_some(e.kind)
    })
}

/// Who signs in: a NameID and attributes, shaped by a template.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Identity {
    pub preset: String,
    pub name_id: String,
    pub name_id_format: String,
    /// Attribute name to a string or a list of strings.
    #[serde(default)]
    pub attributes: Map<String, Value>,
}

impl Identity {
    /// Values of an attribute as strings.
    pub fn values(&self, name: &str) -> Vec<String> {
        match self.attributes.get(name) {
            Some(Value::Array(items)) => items.iter().filter(|v| !v.is_null()).map(value_to_string).collect(),
            Some(Value::Null) | None => vec![],
            Some(v) => vec![value_to_string(v)],
        }
    }

    /// Something to call this identity by in the UI.
    pub fn describe(&self) -> String {
        let preset = get_or_generic(&self.preset);
        preset
            .email_attribute
            .map(|a| self.values(a))
            .and_then(|v| v.into_iter().next())
            .unwrap_or_else(|| self.name_id.clone())
    }
}

impl Preset {
    pub fn entity_id(&self, base: &str) -> String {
        self.entity_id.replace("{base}", base.trim_end_matches('/'))
    }

    pub fn attribute(&self, name: &str) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.name == name)
    }

    pub fn default_attributes(&self) -> Map<String, Value> {
        let mut attrs = Map::new();
        for a in &self.attributes {
            let empty = match &a.default {
                Value::String(s) => s.is_empty(),
                Value::Array(v) => v.is_empty(),
                _ => false,
            };
            if !empty {
                attrs.insert(a.name.to_string(), a.default.clone());
            }
        }
        attrs
    }

    pub fn default_identity(&self) -> Identity {
        let attributes = self.default_attributes();
        let mut identity = Identity {
            preset: self.id.into(),
            name_id: String::new(),
            name_id_format: self.name_id_format.into(),
            attributes,
        };
        identity.name_id = self.derive_name_id(&identity).unwrap_or_else(|| self.name_id_example.to_string());
        identity
    }

    /// The NameID implied by the attributes (`name_id_from`), if the template has one.
    pub fn derive_name_id(&self, identity: &Identity) -> Option<String> {
        identity.values(self.name_id_from?).into_iter().next().filter(|v| !v.is_empty())
    }

    /// Apply a login hint (AuthnRequest `Subject`, or `login_hint` as Entra ID accepts): an email
    /// goes to the email attribute, and to the NameID when it's derived from that attribute.
    pub fn apply_login_hint(&self, identity: &mut Identity, hint: &str) {
        if hint.is_empty() {
            return;
        }
        if hint.contains('@')
            && let Some(attr) = self.email_attribute
        {
            identity.attributes.insert(attr.into(), json!(hint));
            if let Some(from) = self.name_id_from
                && from != attr
                && identity.values(from).iter().any(|v| v.contains('@'))
            {
                identity.attributes.insert(from.into(), json!(hint));
            }
        }
        identity.name_id = self.derive_name_id(identity).unwrap_or_else(|| hint.to_string());
    }

    /// Merge attribute overrides (`null` removes one) and, if the NameID follows an attribute
    /// that changed, re-derive it.
    pub fn apply_overrides(&self, identity: &mut Identity, overrides: &Map<String, Value>) {
        let follows =
            self.name_id_from.is_some() && self.derive_name_id(identity).as_deref() == Some(&identity.name_id);
        crate::util::merge_map(&mut identity.attributes, overrides);
        if follows && let Some(derived) = self.derive_name_id(identity) {
            identity.name_id = derived;
        }
    }
}

pub fn all() -> &'static [Preset] {
    static PRESETS: OnceLock<Vec<Preset>> = OnceLock::new();
    PRESETS.get_or_init(build)
}

pub fn get(id: &str) -> Option<&'static Preset> {
    all().iter().find(|p| p.id == id)
}

pub fn get_or_generic(id: &str) -> &'static Preset {
    get(id).unwrap_or_else(generic)
}

pub fn generic() -> &'static Preset {
    &all()[0]
}

const EMAIL: &str = "jane@example.com";
const NAME: &str = "Jane Developer";
pub const ENTRA_TENANT: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

fn build() -> Vec<Preset> {
    vec![
        Preset {
            id: "generic",
            name: "Custom (generic SAML)",
            description: "Plain attribute names (email, firstName, groups, …) with a signed response and assertion.",
            color: "#6366f1",
            entity_id: "{base}/metadata",
            name_id_format: nameid::EMAIL,
            name_id_from: Some("email"),
            name_id_example: EMAIL,
            email_attribute: Some("email"),
            attributes: vec![
                s("email", "Email", EMAIL),
                s("firstName", "First name", "Jane"),
                s("lastName", "Last name", "Developer"),
                s("displayName", "Display name", NAME),
                s("uid", "User ID", "jane"),
                l("groups", "Groups", &["developers"]),
                l("roles", "Roles", &["user"]),
                s("department", "Department", "Engineering").advanced(),
                s("title", "Job title", "Software Engineer").advanced(),
                s("employeeNumber", "Employee number", "100042").advanced().unique(),
            ],
            sign_response: true,
            sign_assertion: true,
            encrypt_when_possible: false,
            encryption: EncAlg::Aes256Gcm,
            encrypted_key: KeyPlacement::Inline,
            send_empty_attributes: false,
            authn_context: authn::PASSWORD_PROTECTED,
            assertion_lifetime: 300,
            not_before_skew: 0,
            session_lifetime: Some(8 * 3600),
            confirmation_lifetime: None,
            session_index: SessionIndexStyle::Session,
            style: STD,
            endpoints: vec![],
            single_logout: true,
        },
        Preset {
            id: "entra",
            name: "Microsoft Entra ID",
            description: "Azure AD enterprise apps: WS-Federation claim URIs, object and tenant IDs, assertion-only signing.",
            color: "#0078d4",
            entity_id: "https://sts.windows.net/9188040d-6c67-4c5b-b112-36a304b66dad/",
            name_id_format: nameid::EMAIL,
            name_id_from: Some("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"),
            name_id_example: EMAIL,
            email_attribute: Some("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"),
            attributes: vec![
                s("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "User principal name", EMAIL)
                    .help("user.userprincipalname; the default NameID source"),
                s("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "Email", EMAIL),
                s("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "Given name", "Jane"),
                s("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "Surname", "Developer"),
                s("http://schemas.microsoft.com/identity/claims/displayname", "Display name", NAME),
                s(
                    "http://schemas.microsoft.com/identity/claims/objectidentifier",
                    "Object ID",
                    "00000000-0000-0000-66f3-3332eca7ea81",
                )
                .unique(),
                l("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "App roles", &["User"]),
                l(
                    "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
                    "Groups",
                    &["5f1b2a3c-4d5e-4f60-8a7b-9c0d1e2f3a4b"],
                )
                .help("Group object IDs, when the app has a group claim configured"),
                s("http://schemas.microsoft.com/identity/claims/tenantid", "Tenant ID", ENTRA_TENANT).advanced(),
                s(
                    "http://schemas.microsoft.com/identity/claims/identityprovider",
                    "Identity provider",
                    "https://sts.windows.net/9188040d-6c67-4c5b-b112-36a304b66dad/",
                )
                .advanced(),
                l(
                    "http://schemas.microsoft.com/claims/authnmethodsreferences",
                    "Authentication methods",
                    &["http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password"],
                )
                .advanced(),
            ],
            sign_response: false,
            sign_assertion: true,
            encrypt_when_possible: false,
            encryption: EncAlg::Aes256Gcm,
            encrypted_key: KeyPlacement::Inline,
            send_empty_attributes: false,
            authn_context: authn::PASSWORD,
            assertion_lifetime: 3600,
            not_before_skew: 300,
            session_lifetime: None,
            confirmation_lifetime: None,
            session_index: SessionIndexStyle::AssertionId,
            style: Style {
                protocol_prefix: "samlp",
                assertion_prefix: "",
                dsig_prefix: "",
                id_style: IdStyle::UnderscoreUuid,
                name_format: None,
                xsi_type: None,
                attributes_first: true,
                issuer_format: false,
                assertion_id_style: None,
            },
            endpoints: vec![
                ep(EndpointKind::Sso, "SAML SSO and logout (GET/POST)", "/{tenant}/saml2"),
                ep(
                    EndpointKind::Metadata,
                    "Federation metadata",
                    "/{tenant}/federationmetadata/2007-06/federationmetadata.xml",
                ),
            ],
            single_logout: true,
        },
        Preset {
            id: "adfs",
            name: "AD FS",
            description: "Active Directory Federation Services: claim URIs, Windows account names and AD groups.",
            color: "#5c2d91",
            entity_id: "{base}/adfs/services/trust",
            name_id_format: nameid::EMAIL,
            name_id_from: Some("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"),
            name_id_example: EMAIL,
            email_attribute: Some("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"),
            attributes: vec![
                s("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", "UPN", EMAIL),
                s("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "Email", EMAIL),
                s("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "Given name", "Jane"),
                s("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "Surname", "Developer"),
                s("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "Name", NAME),
                l("http://schemas.xmlsoap.org/claims/Group", "Groups", &["Domain Users", "Developers"])
                    .help("Token-Groups: AD group names"),
                l("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "Roles", &["Developers"]).advanced(),
                s(
                    "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname",
                    "Windows account name",
                    "EXAMPLE\\jane",
                )
                .advanced(),
                s(
                    "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid",
                    "Primary SID",
                    "S-1-5-21-3623811015-3361044348-30300820-1013",
                )
                .advanced()
                .unique(),
            ],
            sign_response: false,
            sign_assertion: true,
            encrypt_when_possible: false,
            encryption: EncAlg::Aes256Gcm,
            encrypted_key: KeyPlacement::Inline,
            send_empty_attributes: false,
            authn_context: authn::PASSWORD_PROTECTED,
            assertion_lifetime: 3600,
            not_before_skew: 0,
            session_lifetime: None,
            confirmation_lifetime: Some(300),
            session_index: SessionIndexStyle::AssertionId,
            style: Style {
                protocol_prefix: "samlp",
                assertion_prefix: "",
                dsig_prefix: "ds",
                id_style: IdStyle::UnderscoreUuid,
                name_format: None,
                xsi_type: None,
                attributes_first: true,
                issuer_format: false,
                assertion_id_style: None,
            },
            endpoints: vec![
                ep(EndpointKind::Sso, "SAML SSO and logout (GET/POST)", "/adfs/ls/"),
                ep(EndpointKind::Metadata, "Federation metadata", "/FederationMetadata/2007-06/FederationMetadata.xml"),
            ],
            single_logout: true,
        },
        Preset {
            id: "okta",
            name: "Okta",
            description: "Okta SAML apps: saml2 prefixes, xs:string values, signed response and assertion, group attribute statements.",
            color: "#007dc1",
            entity_id: "http://www.okta.com/exk1fcia6d6EMsf331d8",
            name_id_format: nameid::UNSPECIFIED,
            name_id_from: Some("email"),
            name_id_example: EMAIL,
            email_attribute: Some("email"),
            attributes: vec![
                s("email", "Email", EMAIL),
                s("firstName", "First name", "Jane"),
                s("lastName", "Last name", "Developer"),
                l("groups", "Groups", &["Everyone", "Developers"]).help("A group attribute statement"),
                s("login", "Okta username", EMAIL).advanced(),
                s("displayName", "Display name", NAME).advanced(),
            ],
            sign_response: true,
            sign_assertion: true,
            encrypt_when_possible: false,
            encryption: EncAlg::Aes256Cbc,
            encrypted_key: KeyPlacement::Sibling,
            send_empty_attributes: false,
            authn_context: authn::PASSWORD_PROTECTED,
            assertion_lifetime: 300,
            not_before_skew: 300,
            session_lifetime: None,
            confirmation_lifetime: None,
            session_index: SessionIndexStyle::RequestId,
            style: Style {
                protocol_prefix: "saml2p",
                assertion_prefix: "saml2",
                dsig_prefix: "ds",
                id_style: IdStyle::OktaDigits,
                name_format: Some(attrname::UNSPECIFIED),
                xsi_type: Some("xs:string"),
                attributes_first: false,
                issuer_format: true,
                assertion_id_style: None,
            },
            endpoints: vec![
                ep(EndpointKind::Sso, "SAML SSO (GET/POST)", "/app/{app}/{app_id}/sso/saml"),
                ep(EndpointKind::Slo, "Single logout", "/app/{app}/{app_id}/slo/saml"),
                ep(EndpointKind::Metadata, "Metadata", "/app/{app_id}/sso/saml/metadata"),
            ],
            single_logout: true,
        },
        Preset {
            id: "google",
            name: "Google Workspace",
            description: "Google Workspace custom SAML apps: primary email NameID, mapped attributes, no single logout.",
            color: "#4285f4",
            entity_id: "https://accounts.google.com/o/saml2?idpid=C01a2b3c4",
            name_id_format: nameid::UNSPECIFIED,
            name_id_from: Some("email"),
            name_id_example: EMAIL,
            email_attribute: Some("email"),
            attributes: vec![
                s("email", "Primary email", EMAIL),
                s("firstName", "First name", "Jane"),
                s("lastName", "Last name", "Developer"),
                l("groups", "Groups", &["developers"])
                    .help("Group membership mapped to an app attribute (group names)"),
                s("department", "Department", "Engineering").advanced(),
            ],
            sign_response: false,
            sign_assertion: true,
            encrypt_when_possible: false,
            encryption: EncAlg::Aes256Gcm,
            encrypted_key: KeyPlacement::Inline,
            send_empty_attributes: false,
            authn_context: authn::UNSPECIFIED,
            assertion_lifetime: 300,
            not_before_skew: 300,
            session_lifetime: None,
            confirmation_lifetime: None,
            session_index: SessionIndexStyle::AssertionId,
            style: Style {
                protocol_prefix: "saml2p",
                assertion_prefix: "saml2",
                dsig_prefix: "ds",
                id_style: IdStyle::Hex,
                name_format: None,
                xsi_type: Some("xs:anyType"),
                attributes_first: true,
                issuer_format: false,
                assertion_id_style: None,
            },
            endpoints: vec![ep(EndpointKind::Sso, "SAML SSO (GET/POST)", "/o/saml2/idp")],
            single_logout: false,
        },
        Preset {
            id: "onelogin",
            name: "OneLogin",
            description: "OneLogin SAML custom connectors: User.* parameters, pfx IDs, SessionNotOnOrAfter.",
            color: "#1c1f2a",
            entity_id: "https://app.onelogin.com/saml/metadata/6b7cf0a1-2d3e-4f50-9a1b-2c3d4e5f6a7b",
            name_id_format: nameid::EMAIL,
            name_id_from: Some("User.email"),
            name_id_example: EMAIL,
            email_attribute: Some("User.email"),
            attributes: vec![
                s("User.email", "Email", EMAIL),
                s("User.FirstName", "First name", "Jane"),
                s("User.LastName", "Last name", "Developer"),
                l("memberOf", "Groups (memberOf)", &["Developers"]),
                s("User.Username", "Username", "jane").advanced(),
                s("PersonImmutableID", "Immutable ID", "jane").advanced().unique(),
            ],
            sign_response: true,
            sign_assertion: false,
            encrypt_when_possible: false,
            encryption: EncAlg::Aes256Gcm,
            encrypted_key: KeyPlacement::Inline,
            send_empty_attributes: true,
            authn_context: authn::PASSWORD_PROTECTED,
            assertion_lifetime: 180,
            not_before_skew: 180,
            session_lifetime: Some(24 * 3600),
            confirmation_lifetime: None,
            session_index: SessionIndexStyle::Session,
            style: Style { id_style: IdStyle::PfxUuid, assertion_id_style: Some(IdStyle::AHex), ..STD },
            endpoints: vec![
                ep(EndpointKind::Sso, "SAML SSO, Redirect binding", "/trust/saml2/http-redirect/sso/{connector_id}"),
                ep(EndpointKind::Sso, "SAML SSO, POST binding", "/trust/saml2/http-post/sso/{connector_id}"),
                ep(EndpointKind::Slo, "Single logout", "/trust/saml2/http-redirect/slo/{connector_id}"),
                ep(EndpointKind::Metadata, "Metadata", "/saml/metadata/{connector_id}"),
            ],
            single_logout: true,
        },
        Preset {
            id: "auth0",
            name: "Auth0",
            description: "Auth0's SAML2 web app addon: claim URIs with the Auth0 user_id as NameID.",
            color: "#eb5424",
            entity_id: "urn:dev-example.us.auth0.com",
            name_id_format: nameid::UNSPECIFIED,
            name_id_from: Some("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"),
            name_id_example: "auth0|64f1c0ffee0000000000abcd",
            email_attribute: Some("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"),
            attributes: vec![
                s(
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
                    "User ID",
                    "auth0|64f1c0ffee0000000000abcd",
                )
                .unique(),
                s("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "Email", EMAIL),
                s("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "Name", NAME),
                s("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "Given name", "Jane"),
                s("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "Surname", "Developer"),
                s("http://schemas.auth0.com/email_verified", "Email verified", "true").xsi("xs:boolean"),
                s("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", "UPN", EMAIL).advanced(),
                s("http://schemas.auth0.com/nickname", "Nickname", "jane").advanced(),
                s("http://schemas.auth0.com/picture", "Picture", "https://www.gravatar.com/avatar/?d=identicon")
                    .advanced(),
                s("http://schemas.auth0.com/identities/default/provider", "Identity provider", "auth0").advanced(),
                s(
                    "http://schemas.auth0.com/identities/default/connection",
                    "Connection",
                    "Username-Password-Authentication",
                )
                .advanced(),
                s("http://schemas.auth0.com/identities/default/isSocial", "Social login", "false")
                    .xsi("xs:boolean")
                    .advanced(),
                s("http://schemas.auth0.com/clientID", "Client ID", "localsaml").advanced(),
            ],
            sign_response: false,
            sign_assertion: true,
            encrypt_when_possible: false,
            encryption: EncAlg::Aes256Gcm,
            encrypted_key: KeyPlacement::Inline,
            send_empty_attributes: false,
            authn_context: authn::UNSPECIFIED,
            assertion_lifetime: 3600,
            not_before_skew: 0,
            session_lifetime: None,
            confirmation_lifetime: None,
            session_index: SessionIndexStyle::Session,
            style: Style { name_format: Some(attrname::URI), dsig_prefix: "", ..STD },
            endpoints: vec![
                ep(EndpointKind::Sso, "SAML SSO (GET/POST)", "/samlp/{client_id}"),
                ep(EndpointKind::Slo, "Single logout", "/samlp/{client_id}/logout"),
                ep(EndpointKind::Metadata, "Metadata", "/samlp/metadata/{client_id}"),
            ],
            single_logout: true,
        },
        Preset {
            id: "keycloak",
            name: "Keycloak",
            description: "Keycloak SAML clients: signed document, Role attributes, X.500 mappers, ID_ identifiers.",
            color: "#4d4d4d",
            entity_id: "{base}/realms/example",
            name_id_format: nameid::UNSPECIFIED,
            name_id_from: None,
            name_id_example: "jane",
            email_attribute: Some("urn:oid:1.2.840.113549.1.9.1"),
            attributes: vec![
                l(
                    "Role",
                    "Roles",
                    &[
                        "default-roles-example",
                        "offline_access",
                        "uma_authorization",
                        "manage-account",
                        "manage-account-links",
                        "view-profile",
                    ],
                )
                .help("The role list mapper (default client scope role_list): one Attribute per role")
                .split(),
                // The X.500 mappers are built in but not in a default client scope; they're the usual
                // first addition.
                s("urn:oid:1.2.840.113549.1.9.1", "Email (X500 email mapper)", EMAIL)
                    .friendly("email")
                    .format(attrname::URI),
                s("urn:oid:2.5.4.42", "Given name (X500 givenName mapper)", "Jane")
                    .friendly("givenName")
                    .format(attrname::URI),
                s("urn:oid:2.5.4.4", "Surname (X500 surname mapper)", "Developer")
                    .friendly("surname")
                    .format(attrname::URI),
            ],
            sign_response: true,
            sign_assertion: false,
            encrypt_when_possible: false,
            encryption: EncAlg::Aes256Gcm,
            encrypted_key: KeyPlacement::Inline,
            send_empty_attributes: false,
            authn_context: authn::UNSPECIFIED,
            assertion_lifetime: 60,
            not_before_skew: 0,
            session_lifetime: Some(10 * 3600),
            confirmation_lifetime: Some(300),
            session_index: SessionIndexStyle::AssertionId,
            style: Style { dsig_prefix: "dsig", id_style: IdStyle::KeycloakUuid, ..STD },
            endpoints: vec![
                ep(EndpointKind::Sso, "SAML SSO and logout (GET/POST)", "/realms/{realm}/protocol/saml"),
                ep(EndpointKind::Metadata, "Metadata (descriptor)", "/realms/{realm}/protocol/saml/descriptor"),
                ep(
                    EndpointKind::Initiate,
                    "IdP-initiated SSO (the client's IdP-initiated SSO URL name)",
                    "/realms/{realm}/protocol/saml/clients/{client}",
                ),
            ],
            single_logout: true,
        },
        Preset {
            id: "pingfederate",
            name: "PingFederate",
            description: "PingFederate SP connections: LDAP attribute names, startSSO.ping IdP-initiated links.",
            color: "#b3282d",
            entity_id: "localhost:default:entityId",
            name_id_format: nameid::UNSPECIFIED,
            name_id_from: None,
            name_id_example: "jane",
            email_attribute: Some("mail"),
            attributes: vec![
                s("mail", "Email (mail)", EMAIL),
                s("givenName", "Given name", "Jane"),
                s("sn", "Surname (sn)", "Developer"),
                l("memberOf", "Groups (memberOf)", &["CN=Developers,OU=Groups,DC=example,DC=com"]),
                s("uid", "User ID", "jane").advanced(),
            ],
            sign_response: true,
            sign_assertion: false,
            encrypt_when_possible: false,
            encryption: EncAlg::Aes256Gcm,
            encrypted_key: KeyPlacement::Inline,
            send_empty_attributes: false,
            authn_context: authn::UNSPECIFIED,
            assertion_lifetime: 300,
            not_before_skew: 300,
            session_lifetime: None,
            confirmation_lifetime: None,
            session_index: SessionIndexStyle::Session,
            style: Style { id_style: IdStyle::Alnum, ..STD },
            endpoints: vec![
                ep(EndpointKind::Sso, "SAML SSO (GET/POST)", "/idp/SSO.saml2"),
                ep(EndpointKind::Slo, "Single logout", "/idp/SLO.saml2"),
                ep(EndpointKind::Initiate, "IdP-initiated SSO (?PartnerSpId=)", "/idp/startSSO.ping"),
                ep(EndpointKind::Metadata, "Metadata", "/pf/federation_metadata.ping"),
            ],
            single_logout: true,
        },
        Preset {
            id: "jumpcloud",
            name: "JumpCloud",
            description: "JumpCloud SSO apps: the JumpCloud entity ID, memberOf group attribute.",
            color: "#00a698",
            entity_id: "JumpCloud",
            name_id_format: nameid::UNSPECIFIED,
            name_id_from: Some("email"),
            name_id_example: EMAIL,
            email_attribute: Some("email"),
            attributes: vec![
                s("email", "Email", EMAIL),
                s("firstname", "First name", "Jane"),
                s("lastname", "Last name", "Developer"),
                l("memberOf", "Groups (memberOf)", &["Developers"]),
                s("username", "Username", "jane").advanced(),
            ],
            sign_response: true,
            sign_assertion: false,
            encrypt_when_possible: false,
            encryption: EncAlg::Aes256Gcm,
            encrypted_key: KeyPlacement::Inline,
            send_empty_attributes: false,
            authn_context: authn::PASSWORD_PROTECTED,
            assertion_lifetime: 300,
            not_before_skew: 300,
            session_lifetime: None,
            confirmation_lifetime: None,
            session_index: SessionIndexStyle::Session,
            // From a captured JumpCloud response (moritzheiber/crowbar tests/fixtures/jumpcloud).
            style: Style {
                protocol_prefix: "saml2p",
                assertion_prefix: "saml2",
                id_style: IdStyle::Upper40,
                name_format: Some(attrname::UNSPECIFIED),
                attributes_first: true,
                issuer_format: true,
                ..STD
            },
            endpoints: vec![ep(EndpointKind::Sso, "SAML SSO (GET/POST)", "/saml2/{app}")],
            single_logout: true,
        },
        Preset {
            id: "shibboleth",
            name: "Shibboleth IdP",
            description: "Research & education federations: urn:oid attributes, eduPerson, transient NameIDs, encryption.",
            color: "#c8102e",
            entity_id: "{base}/idp/shibboleth",
            name_id_format: nameid::TRANSIENT,
            name_id_from: None,
            name_id_example: "AAdzZWNyZXQxGvVY5i7GSr5qjqJ6Tmb5V0B1fG2bJ9n4",
            email_attribute: Some("urn:oid:0.9.2342.19200300.100.1.3"),
            attributes: vec![
                s("urn:oid:1.3.6.1.4.1.5923.1.1.1.6", "eduPersonPrincipalName", "jane@example.edu")
                    .friendly("eduPersonPrincipalName"),
                s("urn:oid:0.9.2342.19200300.100.1.3", "Email (mail)", "jane@example.edu").friendly("mail"),
                s("urn:oid:2.16.840.1.113730.3.1.241", "Display name", NAME).friendly("displayName"),
                s("urn:oid:2.5.4.42", "Given name", "Jane").friendly("givenName"),
                s("urn:oid:2.5.4.4", "Surname (sn)", "Developer").friendly("sn"),
                l(
                    "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
                    "Scoped affiliation",
                    &["member@example.edu", "staff@example.edu"],
                )
                .friendly("eduPersonScopedAffiliation"),
                l("urn:oid:1.3.6.1.4.1.5923.1.1.1.1", "Affiliation", &["member", "staff"])
                    .friendly("eduPersonAffiliation")
                    .advanced(),
                l("urn:oid:1.3.6.1.4.1.5923.1.1.1.7", "Entitlement", &["urn:mace:dir:entitlement:common-lib-terms"])
                    .friendly("eduPersonEntitlement")
                    .advanced(),
                s("urn:oasis:names:tc:SAML:attribute:subject-id", "Subject ID", "jane@example.edu")
                    .friendly("subject-id")
                    .advanced(),
                s(
                    "urn:oasis:names:tc:SAML:attribute:pairwise-id",
                    "Pairwise ID",
                    "XZN7VBGNNR4PMVCLFBLMXEC5DNPVZJW3@example.edu",
                )
                .friendly("pairwise-id")
                .advanced()
                .unique(),
                s("urn:oid:0.9.2342.19200300.100.1.1", "uid", "jane").friendly("uid").advanced(),
                s("urn:oid:1.3.6.1.4.1.25178.1.2.9", "Home organization", "example.edu")
                    .friendly("schacHomeOrganization")
                    .advanced(),
            ],
            sign_response: true,
            sign_assertion: false,
            encrypt_when_possible: true,
            encryption: EncAlg::Aes128Gcm,
            encrypted_key: KeyPlacement::Inline,
            send_empty_attributes: false,
            authn_context: authn::PASSWORD_PROTECTED,
            assertion_lifetime: 300,
            not_before_skew: 0,
            session_lifetime: None,
            confirmation_lifetime: None,
            session_index: SessionIndexStyle::Session,
            style: Style {
                protocol_prefix: "saml2p",
                assertion_prefix: "saml2",
                name_format: Some(attrname::URI),
                ..STD
            },
            endpoints: vec![
                ep(EndpointKind::Sso, "SSO, Redirect binding", "/idp/profile/SAML2/Redirect/SSO"),
                ep(EndpointKind::Sso, "SSO, POST binding", "/idp/profile/SAML2/POST/SSO"),
                ep(
                    EndpointKind::Initiate,
                    "Unsolicited (IdP-initiated) SSO (?providerId=)",
                    "/idp/profile/SAML2/Unsolicited/SSO",
                ),
                ep(EndpointKind::Slo, "Single logout, Redirect binding", "/idp/profile/SAML2/Redirect/SLO"),
                ep(EndpointKind::Slo, "Single logout, POST binding", "/idp/profile/SAML2/POST/SLO"),
                ep(EndpointKind::Metadata, "Metadata", "/idp/shibboleth"),
            ],
            single_logout: true,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_are_consistent() {
        let mut ids = std::collections::HashSet::new();
        for p in all() {
            assert!(ids.insert(p.id), "duplicate preset {}", p.id);
            assert!(p.sign_response || p.sign_assertion, "{} signs nothing", p.id);
            if let Some(from) = p.name_id_from {
                assert!(p.attribute(from).is_some(), "{}: name_id_from {from} is not an attribute", p.id);
            }
            if let Some(email) = p.email_attribute {
                assert!(p.attribute(email).is_some(), "{}: email attribute {email} missing", p.id);
            }
            let identity = p.default_identity();
            assert!(!identity.name_id.is_empty(), "{}", p.id);
            for a in &p.attributes {
                assert!(a.kind == "string" || a.kind == "list", "{}: {}", p.id, a.name);
            }
            let id = p.style.id_style.generate();
            assert!(id.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'), "{id}");
        }
    }

    #[test]
    fn login_hints_and_overrides_follow_the_name_id() {
        let okta = get("okta").unwrap();
        let mut identity = okta.default_identity();
        okta.apply_login_hint(&mut identity, "bob@example.com");
        assert_eq!(identity.name_id, "bob@example.com");
        assert_eq!(identity.values("email"), ["bob@example.com"]);
        okta.apply_overrides(
            &mut identity,
            serde_json::from_value(json!({ "email": "carol@example.com" })).as_ref().unwrap(),
        );
        assert_eq!(identity.name_id, "carol@example.com");
        // A NameID that was set by hand doesn't follow the attribute.
        identity.name_id = "custom".into();
        okta.apply_overrides(
            &mut identity,
            serde_json::from_value(json!({ "email": "dan@example.com" })).as_ref().unwrap(),
        );
        assert_eq!(identity.name_id, "custom");
    }
}

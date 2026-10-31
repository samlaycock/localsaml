//! Service providers: declared in `localsaml.toml`, registered over the dev API, or (unless
//! `strict_service_providers` is on) accepted ad hoc from whatever an AuthnRequest says.
//! Settings can come from SP metadata (`metadata_url`, `metadata_file` or `metadata`).

use std::collections::BTreeMap;
use std::path::PathBuf;

use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};

use crate::keys::{PublicKey, SigAlg, cert_public_key, cert_verifying_key, parse_cert};
use crate::saml::{BINDING_POST, BINDING_REDIRECT, BINDING_SOAP, NS_MD};
use crate::xml::{Element, parse};
use crate::xmlenc::EncAlg;

const NS_DS: &str = crate::dsig::NS_DS;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ServiceProvider {
    pub entity_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Assertion consumer service URLs (HTTP-POST); the first is the default.
    pub acs_urls: Vec<String>,
    /// `AssertionConsumerServiceIndex` values from metadata.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub acs_indexes: BTreeMap<u32, String>,
    /// Where to send LogoutRequests (and LogoutResponses, unless `slo_response_url` is set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slo_response_url: Option<String>,
    /// A SOAP SingleLogoutService: logout reaches this SP back-channel, without the browser.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slo_soap_url: Option<String>,
    /// `redirect` (default) or `post`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slo_binding: Option<String>,
    /// The SP's signing certificate (PEM or base64 DER): verifies signed requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// The SP's encryption certificate; defaults to `certificate`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_certificate: Option<String>,
    /// Encrypt assertions. Default: the template's behaviour (Shibboleth encrypts when it can).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypt_assertions: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_algorithm: Option<EncAlg>,
    /// Override the template's signing behaviour.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_response: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_assertion: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<SigAlg>,
    /// Reject AuthnRequests that aren't signed (metadata: `AuthnRequestsSigned`).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub want_authn_requests_signed: bool,
    /// Reject LogoutRequests and LogoutResponses that aren't signed (SAML Profiles 4.4.4.2 wants
    /// front-channel logout messages signed; off by default for convenience).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub want_logout_signed: bool,
    /// NameID format to use when the request doesn't ask for one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_id_format: Option<String>,
    /// `Audience` (default: the entity ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// RelayState for IdP-initiated logins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_relay_state: Option<String>,
    /// The name in IdP-initiated URLs that name the SP in the path, like Keycloak's
    /// `/realms/{realm}/protocol/saml/clients/{name}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp_initiated_name: Option<String>,
    /// Template to sign in with when this SP starts a login on the root issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    /// Fetch settings from the SP's metadata. Fetched at startup, and again on the SP's next
    /// request if it wasn't reachable yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_file: Option<PathBuf>,
    /// Inline metadata XML.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    /// Where the settings came from: `config`, `api`, `builtin` or `request`.
    #[serde(skip_deserializing, skip_serializing_if = "String::is_empty")]
    pub source: String,
    /// The metadata URL couldn't be fetched yet.
    #[serde(skip_deserializing, skip_serializing_if = "std::ops::Not::not")]
    pub metadata_pending: bool,
}

impl ServiceProvider {
    pub fn label(&self) -> String {
        self.name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| {
            if self.entity_id.is_empty() {
                self.metadata_url.clone().unwrap_or_else(|| "(unnamed)".into())
            } else {
                self.entity_id.clone()
            }
        })
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.entity_id.trim().is_empty() {
            if self.metadata_url.is_some() {
                // Filled in once the metadata is fetched.
                return Ok(());
            }
            anyhow::bail!("entity_id is required (or metadata to read it from)");
        }
        for url in self.acs_urls.iter().chain(&self.slo_url).chain(&self.slo_response_url).chain(&self.slo_soap_url) {
            if !crate::util::is_web_url(url) {
                anyhow::bail!("'{url}' is not an absolute http(s) URL");
            }
        }
        if let Some(b) = &self.slo_binding
            && b != "redirect"
            && b != "post"
        {
            anyhow::bail!("slo_binding must be 'redirect' or 'post'");
        }
        for cert in self.certificate.iter().chain(&self.encryption_certificate) {
            parse_cert(cert).map_err(anyhow::Error::msg)?;
        }
        if let Some(p) = &self.preset
            && crate::presets::get(p).is_none()
        {
            anyhow::bail!("unknown preset '{p}'");
        }
        Ok(())
    }

    /// Apply `metadata` / `metadata_file` (not URLs, which need the network).
    pub fn load_local_metadata(&mut self) -> anyhow::Result<()> {
        let xml = match (&self.metadata, &self.metadata_file) {
            (Some(xml), _) => xml.clone(),
            (None, Some(path)) => std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("reading metadata {}: {e}", path.display()))?,
            (None, None) => return Ok(()),
        };
        self.metadata = None;
        let from = from_metadata(&xml, self.entity_id_hint()).map_err(anyhow::Error::msg)?;
        self.fill_from(from);
        Ok(())
    }

    fn entity_id_hint(&self) -> Option<&str> {
        Some(self.entity_id.as_str()).filter(|e| !e.is_empty())
    }

    /// Fetch `metadata_url` and fill in what isn't set explicitly.
    pub async fn load_remote_metadata(&mut self) -> Result<(), String> {
        let Some(url) = self.metadata_url.clone() else { return Ok(()) };
        let xml = crate::fetch::text(&url).await?;
        let from = from_metadata(&xml, self.entity_id_hint())?;
        self.fill_from(from);
        self.metadata_pending = false;
        Ok(())
    }

    /// Fill unset fields from settings read from metadata. Explicit settings win.
    fn fill_from(&mut self, m: ServiceProvider) {
        if self.entity_id.is_empty() {
            self.entity_id = m.entity_id;
        }
        if self.acs_urls.is_empty() {
            self.acs_urls = m.acs_urls;
            self.acs_indexes = m.acs_indexes;
        }
        self.slo_url = self.slo_url.take().or(m.slo_url);
        self.slo_response_url = self.slo_response_url.take().or(m.slo_response_url);
        self.slo_binding = self.slo_binding.take().or(m.slo_binding);
        self.slo_soap_url = self.slo_soap_url.take().or(m.slo_soap_url);
        self.certificate = self.certificate.take().or(m.certificate);
        self.encryption_certificate = self.encryption_certificate.take().or(m.encryption_certificate);
        self.want_authn_requests_signed |= m.want_authn_requests_signed;
        self.sign_assertion = self.sign_assertion.or(m.sign_assertion);
        self.name_id_format = self.name_id_format.take().or(m.name_id_format);
        self.name = self.name.take().or(m.name);
    }

    pub fn audience(&self) -> String {
        self.audience.clone().unwrap_or_else(|| self.entity_id.clone())
    }

    pub fn default_acs(&self) -> Option<&String> {
        self.acs_urls.first()
    }

    pub fn acs_by_index(&self, index: u32) -> Option<&String> {
        self.acs_indexes.get(&index).or_else(|| self.acs_urls.get(index as usize))
    }

    /// Is `url` one of this SP's ACS URLs? SPs without any accept everything (lenient mode).
    pub fn allows_acs(&self, url: &str) -> bool {
        self.acs_urls.is_empty() || self.acs_urls.iter().any(|a| a == url)
    }

    /// The key that checks this SP's signed messages (RSA or DSA).
    pub fn signing_key(&self) -> Option<Result<PublicKey, String>> {
        self.certificate.as_ref().map(|c| parse_cert(c).and_then(|der| cert_verifying_key(&der)))
    }

    pub fn encryption_key(&self) -> Option<Result<RsaPublicKey, String>> {
        self.encryption_certificate
            .as_ref()
            .or(self.certificate.as_ref())
            .map(|c| parse_cert(c).and_then(|der| cert_public_key(&der)))
    }

    pub fn slo_post(&self) -> bool {
        self.slo_binding.as_deref() == Some("post")
    }
}

/// Read SP settings from an `EntityDescriptor` (or the first one with an SPSSODescriptor in an
/// `EntitiesDescriptor`, or the one matching `entity_id`).
pub fn from_metadata(xml: &str, entity_id: Option<&str>) -> Result<ServiceProvider, String> {
    let root = parse(xml).map_err(|e| format!("invalid metadata: {e}"))?;
    let descriptors: Vec<&Element> = if root.is(NS_MD, "EntityDescriptor") {
        vec![&root]
    } else if root.is(NS_MD, "EntitiesDescriptor") {
        root.find_all(NS_MD, "EntityDescriptor").collect()
    } else {
        return Err(format!("metadata must be an EntityDescriptor, not <{}>", root.qname()));
    };
    let entity = descriptors
        .into_iter()
        .filter(|d| d.find(NS_MD, "SPSSODescriptor").is_some())
        .find(|d| entity_id.is_none_or(|e| d.get_attr("entityID") == Some(e)))
        .ok_or("the metadata has no SPSSODescriptor")?;
    let sp = entity.find(NS_MD, "SPSSODescriptor").ok_or("no SPSSODescriptor")?;

    let mut acs: Vec<(bool, u32, String)> = sp
        .find_all(NS_MD, "AssertionConsumerService")
        .filter(|a| a.get_attr("Binding") == Some(BINDING_POST))
        .filter_map(|a| {
            let index = a.get_attr("index").and_then(|i| i.trim().parse().ok()).unwrap_or(0);
            let default = a.get_attr("isDefault").map(str::trim) == Some("true");
            Some((!default, index, a.get_attr("Location")?.trim().to_string()))
        })
        .collect();
    acs.sort();
    let slo = |binding: &str| {
        sp.find_all(NS_MD, "SingleLogoutService").find(|s| s.get_attr("Binding") == Some(binding)).map(|s| {
            (
                s.get_attr("Location").unwrap_or_default().trim().to_string(),
                s.get_attr("ResponseLocation").map(|r| r.trim().to_string()),
            )
        })
    };
    let slo_soap_url = slo(BINDING_SOAP).map(|s| s.0);
    let (slo, slo_binding) = match (slo(BINDING_REDIRECT), slo(BINDING_POST)) {
        (Some(r), _) => (Some(r), None),
        (None, Some(p)) => (Some(p), Some("post".to_string())),
        (None, None) => (None, None),
    };
    let cert = |usage: &str| {
        sp.find_all(NS_MD, "KeyDescriptor")
            .filter(|k| k.get_attr("use").is_none_or(|u| u == usage))
            .find_map(|k| k.path(&[(NS_DS, "KeyInfo"), (NS_DS, "X509Data"), (NS_DS, "X509Certificate")]))
            .map(|c| c.value().split_whitespace().collect::<String>())
    };
    let name = entity
        .path(&[(NS_MD, "SPSSODescriptor")])
        .and_then(|d| {
            d.find_all(NS_MD, "AttributeConsumingService")
                .next()
                .and_then(|a| a.find(NS_MD, "ServiceName"))
                .map(Element::value)
        })
        .or_else(|| entity.path(&[(NS_MD, "Organization"), (NS_MD, "OrganizationDisplayName")]).map(Element::value));
    Ok(ServiceProvider {
        entity_id: entity.get_attr("entityID").ok_or("EntityDescriptor has no entityID")?.trim().to_string(),
        name: name.filter(|n| !n.is_empty()),
        acs_indexes: acs.iter().map(|(_, i, url)| (*i, url.clone())).collect(),
        acs_urls: acs.into_iter().map(|(_, _, url)| url).collect(),
        slo_url: slo.as_ref().map(|s| s.0.clone()),
        slo_response_url: slo.and_then(|s| s.1),
        slo_binding,
        slo_soap_url,
        certificate: cert("signing"),
        encryption_certificate: cert("encryption"),
        want_authn_requests_signed: sp.get_attr("AuthnRequestsSigned").map(str::trim) == Some("true"),
        sign_assertion: (sp.get_attr("WantAssertionsSigned").map(str::trim) == Some("true")).then_some(true),
        name_id_format: sp.find(NS_MD, "NameIDFormat").map(Element::value).filter(|f| !f.is_empty()),
        source: "metadata".into(),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_sp_metadata() {
        let cert = crate::keys::untrusted().cert_b64();
        let xml = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="http://sp.test/metadata">
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://sp.test/slo"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="http://sp.test/artifact" index="0"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://sp.test/acs2" index="2"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://sp.test/acs1" index="1" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"#
        );
        let sp = from_metadata(&xml, None).unwrap();
        assert_eq!(sp.entity_id, "http://sp.test/metadata");
        assert_eq!(sp.acs_urls, ["http://sp.test/acs1", "http://sp.test/acs2"]);
        assert_eq!(sp.acs_by_index(2).map(String::as_str), Some("http://sp.test/acs2"));
        assert_eq!((sp.slo_url.as_deref(), sp.slo_binding.as_deref()), (Some("http://sp.test/slo"), Some("post")));
        assert!(sp.want_authn_requests_signed && sp.sign_assertion == Some(true));
        assert!(sp.signing_key().unwrap().is_ok());
        // The signing certificate doubles as the encryption certificate.
        assert!(sp.encryption_key().unwrap().is_ok());
    }
}

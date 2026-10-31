//! XML Signature (enveloped, Exclusive C14N) for SAML messages and assertions, and the query-string
//! signatures of the HTTP-Redirect binding.

use rsa::RsaPublicKey;

use crate::keys::{KeyPair, SigAlg, digest_with};
use crate::util::{b64_std, b64_std_decode_lenient};
use crate::xml::{Element, Node};

pub const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const EXC_C14N_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// How to write a signature.
#[derive(Debug, Clone)]
pub struct SignOpts {
    pub alg: SigAlg,
    /// Prefix for the `ds` namespace; empty to declare it as the default namespace.
    pub prefix: String,
    /// InclusiveNamespaces PrefixList for the reference's c14n transform (e.g. `xs` when
    /// attribute values carry `xsi:type="xs:string"`).
    pub inclusive: Vec<String>,
    /// Include the certificate in `KeyInfo`.
    pub key_info: bool,
}

impl Default for SignOpts {
    fn default() -> Self {
        Self { alg: SigAlg::RsaSha256, prefix: "ds".into(), inclusive: vec![], key_info: true }
    }
}

fn ds(opts: &SignOpts, local: &str) -> Element {
    Element::new(NS_DS, &opts.prefix, local)
}

/// Sign the element whose `ID` is `id`, somewhere inside `root`, with an enveloped signature
/// inserted after its `Issuer` (where the SAML schema puts it). The digest is computed in the
/// element's place in `root`, so sign inner elements before outer ones.
pub fn sign(root: &mut Element, id: &str, key: &KeyPair, opts: &SignOpts) -> Result<(), String> {
    let (target, outer) = root.find_by_id_scoped(id).ok_or_else(|| format!("no element with ID '{id}'"))?;
    let digest = opts.alg.digest(target.exc_c14n(&outer, &opts.inclusive).as_bytes());
    let inside = target.scope_within(&outer);

    let mut c14n_transform = ds(opts, "Transform").attr("Algorithm", EXC_C14N);
    if !opts.inclusive.is_empty() {
        c14n_transform = c14n_transform
            .child(Element::new(EXC_C14N, "ec", "InclusiveNamespaces").attr("PrefixList", opts.inclusive.join(" ")));
    }
    let signed_info = ds(opts, "SignedInfo")
        .child(ds(opts, "CanonicalizationMethod").attr("Algorithm", EXC_C14N))
        .child(ds(opts, "SignatureMethod").attr("Algorithm", opts.alg.uri()))
        .child(
            ds(opts, "Reference")
                .attr("URI", format!("#{id}"))
                .child(
                    ds(opts, "Transforms")
                        .child(ds(opts, "Transform").attr("Algorithm", ENVELOPED))
                        .child(c14n_transform),
                )
                .child(ds(opts, "DigestMethod").attr("Algorithm", opts.alg.digest_uri()))
                .child(ds(opts, "DigestValue").text(b64_std(&digest))),
        );
    let mut signature = ds(opts, "Signature").child(signed_info);
    signature.declare_namespaces_in(&inside);
    let sig_scope = signature.scope_within(&inside);
    let signed_info = signature.find(NS_DS, "SignedInfo").ok_or("missing SignedInfo")?;
    let value = key.sign(opts.alg, signed_info.exc_c14n(&sig_scope, &[]).as_bytes());
    signature.children.push(Node::Element(ds(opts, "SignatureValue").text(b64_std(&value))));
    if opts.key_info {
        let mut key_info =
            ds(opts, "KeyInfo").child(ds(opts, "X509Data").child(ds(opts, "X509Certificate").text(key.cert_b64())));
        key_info.declare_namespaces_in(&sig_scope);
        signature.children.push(Node::Element(key_info));
    }

    let target = root.find_by_id_mut(id).ok_or("element vanished")?;
    let at = target
        .children
        .iter()
        .position(|n| matches!(n, Node::Element(e) if e.local == "Issuer"))
        .map(|i| i + 1)
        .unwrap_or(0);
    target.children.insert(at, Node::Element(signature));
    Ok(())
}

/// What a verified signature looked like.
#[derive(Debug, Clone)]
pub struct Verified {
    pub alg: SigAlg,
    /// The certificate in `KeyInfo`, if any (base64 DER).
    pub key_info_cert: Option<String>,
}

/// The direct `Signature` child of an element, if it has one.
pub fn signature_of(el: &Element) -> Option<&Element> {
    el.find(NS_DS, "Signature")
}

/// Verify the enveloped signature directly inside the element with `ID` `id` against any of
/// `keys`. The reference must point at that element, so a signature over some other part of the
/// document (signature wrapping) doesn't count.
pub fn verify(root: &Element, id: &str, keys: &[RsaPublicKey]) -> Result<Verified, String> {
    // With two elements sharing the ID, the one verified might not be the one the caller reads
    // (XML signature wrapping).
    if root.count_id(id) > 1 {
        return Err(format!("more than one element has ID '{id}' (signature wrapping?)"));
    }
    let (target, outer) = root.find_by_id_scoped(id).ok_or_else(|| format!("no element with ID '{id}'"))?;
    let signature = signature_of(target).ok_or("not signed")?;
    let inside = target.scope_within(&outer);
    let sig_scope = signature.scope_within(&inside);
    let signed_info = signature.find(NS_DS, "SignedInfo").ok_or("Signature has no SignedInfo")?;

    let c14n = signed_info.find(NS_DS, "CanonicalizationMethod").and_then(|e| e.get_attr("Algorithm"));
    if c14n != Some(EXC_C14N) && c14n != Some(EXC_C14N_COMMENTS) {
        return Err(format!("unsupported CanonicalizationMethod {}", c14n.unwrap_or("(none)")));
    }
    let alg_uri = signed_info.find(NS_DS, "SignatureMethod").and_then(|e| e.get_attr("Algorithm")).unwrap_or("");
    let alg = SigAlg::from_uri(alg_uri).ok_or_else(|| format!("unsupported SignatureMethod {alg_uri}"))?;
    let references: Vec<&Element> = signed_info.find_all(NS_DS, "Reference").collect();
    let [reference] = references.as_slice() else {
        return Err(format!("expected one Reference, found {}", references.len()));
    };
    let uri = reference.get_attr("URI").unwrap_or("");
    if uri != format!("#{id}") {
        return Err(format!("the signature references '{uri}', not this element (#{id})"));
    }
    let mut inclusive = vec![];
    if let Some(transforms) = reference.find(NS_DS, "Transforms") {
        for t in transforms.find_all(NS_DS, "Transform") {
            match t.get_attr("Algorithm").unwrap_or("") {
                ENVELOPED => {}
                EXC_C14N | EXC_C14N_COMMENTS => inclusive = inclusive_prefixes(t),
                other => return Err(format!("unsupported Transform {other}")),
            }
        }
    }
    let digest_uri = reference.find(NS_DS, "DigestMethod").and_then(|e| e.get_attr("Algorithm")).unwrap_or("");
    let expected = reference
        .find(NS_DS, "DigestValue")
        .and_then(|e| b64_std_decode_lenient(&e.text_content()))
        .ok_or("missing or invalid DigestValue")?;
    // The enveloped-signature transform: digest the element without this signature.
    let mut stripped = target.clone();
    stripped.children.retain(|n| !matches!(n, Node::Element(e) if std::ptr::eq(e, signature) || *e == *signature));
    let actual = digest_with(digest_uri, stripped.exc_c14n(&outer, &inclusive).as_bytes())
        .ok_or_else(|| format!("unsupported DigestMethod {digest_uri}"))?;
    if actual != expected {
        return Err("digest mismatch: the signed content was changed after signing".into());
    }
    let value = signature
        .find(NS_DS, "SignatureValue")
        .and_then(|e| b64_std_decode_lenient(&e.text_content()))
        .ok_or("missing or invalid SignatureValue")?;
    let si_inclusive = signed_info.find(NS_DS, "CanonicalizationMethod").map(inclusive_prefixes).unwrap_or_default();
    let canonical = signed_info.exc_c14n(&sig_scope, &si_inclusive);
    if !keys.iter().any(|k| alg.verify(k, canonical.as_bytes(), &value)) {
        return Err(if keys.is_empty() {
            "no certificate to verify against".into()
        } else {
            "the signature doesn't verify against the trusted certificate(s)".into()
        });
    }
    let key_info_cert = signature
        .path(&[(NS_DS, "KeyInfo"), (NS_DS, "X509Data"), (NS_DS, "X509Certificate")])
        .map(|e| e.value().split_whitespace().collect());
    Ok(Verified { alg, key_info_cert })
}

fn inclusive_prefixes(el: &Element) -> Vec<String> {
    el.find(EXC_C14N, "InclusiveNamespaces")
        .and_then(|e| e.get_attr("PrefixList"))
        .map(|l| l.split_whitespace().map(String::from).collect())
        .unwrap_or_default()
}

/// Remove every signature in a tree (used to send deliberately unsigned messages).
pub fn strip_signatures(el: &mut Element) {
    el.children.retain(|n| !matches!(n, Node::Element(e) if e.is(NS_DS, "Signature")));
    for child in el.elements_mut() {
        strip_signatures(child);
    }
}

/// HTTP-Redirect binding: sign `SAMLRequest=…&RelayState=…&SigAlg=…` (already URL-encoded) and
/// return the full query string with `Signature` appended.
pub fn sign_query(query: &str, key: &KeyPair, alg: SigAlg) -> String {
    let query = format!("{query}&SigAlg={}", urlencode(alg.uri()));
    let signature = key.sign(alg, query.as_bytes());
    format!("{query}&Signature={}", urlencode(&b64_std(signature)))
}

pub fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// The first SAML binding parameter that appears more than once in a raw query string. A
/// duplicate could make the message that's verified differ from the one that's processed.
pub fn duplicate_param(raw: &str) -> Option<&'static str> {
    ["SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature"]
        .into_iter()
        .find(|name| raw.split('&').filter(|p| p.split_once('=').map(|(k, _)| k).unwrap_or(p) == *name).count() > 1)
}

/// A redirect-binding signature found in a query string.
#[derive(Debug, Clone)]
pub struct QuerySignature {
    pub alg: Option<SigAlg>,
    pub alg_uri: String,
    /// The exact bytes that were signed, rebuilt from the raw (still encoded) query.
    pub signed: String,
    pub signature: Vec<u8>,
}

impl QuerySignature {
    /// Extract the signature from a raw query string, if there is one. Per SAML Bindings §3.4.4.1
    /// the signed string is rebuilt from the parameters exactly as they were encoded.
    pub fn from_query(raw: &str) -> Option<Self> {
        let pairs: Vec<(&str, &str)> = raw.split('&').filter_map(|p| p.split_once('=')).collect();
        let get = |k: &str| pairs.iter().find(|(key, _)| *key == k).map(|(_, v)| *v);
        let signature = get("Signature")?;
        let alg_raw = get("SigAlg")?;
        let message = ["SAMLRequest", "SAMLResponse"].into_iter().find_map(|k| get(k).map(|v| (k, v)))?;
        let mut signed = format!("{}={}", message.0, message.1);
        if let Some(relay) = get("RelayState") {
            signed.push_str(&format!("&RelayState={relay}"));
        }
        signed.push_str(&format!("&SigAlg={alg_raw}"));
        let decode =
            |v: &str| url::form_urlencoded::parse(format!("x={v}").as_bytes()).next().map(|(_, v)| v.into_owned());
        let alg_uri = decode(alg_raw)?;
        Some(Self {
            alg: SigAlg::from_uri(&alg_uri),
            alg_uri,
            signed,
            signature: b64_std_decode_lenient(&decode(signature)?)?,
        })
    }

    pub fn verify(&self, keys: &[RsaPublicKey]) -> Result<SigAlg, String> {
        let alg = self.alg.ok_or_else(|| format!("unsupported SigAlg {}", self.alg_uri))?;
        if keys.iter().any(|k| alg.verify(k, self.signed.as_bytes(), &self.signature)) {
            Ok(alg)
        } else {
            Err("the query signature doesn't verify against the service provider's certificate".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::parse;

    const P: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
    const A: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

    fn key() -> &'static KeyPair {
        crate::keys::untrusted()
    }

    fn doc() -> Element {
        let mut root = Element::new(P, "samlp", "Response").attr("ID", "_r").child(
            Element::new(A, "", "Assertion")
                .attr("ID", "_a")
                .child(Element::new(A, "", "Issuer").text("idp"))
                .child(Element::new(A, "", "Subject").text("jane & co")),
        );
        root.declare_namespaces();
        root
    }

    #[test]
    fn signs_and_verifies_nested_signatures_after_a_round_trip() {
        let mut root = doc();
        sign(&mut root, "_a", key(), &SignOpts { prefix: String::new(), ..Default::default() }).unwrap();
        sign(&mut root, "_r", key(), &SignOpts::default()).unwrap();
        let parsed = parse(&root.to_xml()).unwrap();
        let keys = [key().public.clone()];
        assert!(verify(&parsed, "_a", &keys).is_ok());
        assert!(verify(&parsed, "_r", &keys).is_ok());
        // Changing signed content breaks the digest.
        let tampered = parse(&root.to_xml().replace("jane &amp; co", "admin")).unwrap();
        assert!(verify(&tampered, "_a", &keys).unwrap_err().contains("digest"));
        assert!(verify(&tampered, "_r", &keys).unwrap_err().contains("digest"));
        // A second element with the same ID (a wrapping attack) is refused.
        let wrapped = root.to_xml().replacen("<Subject>", r#"<Subject><Assertion ID="_a"/>"#, 1);
        assert!(verify(&parse(&wrapped).unwrap(), "_a", &keys).unwrap_err().contains("more than one"));
        // An unrelated key doesn't verify.
        let other = crate::keys::KeyPair::generate().unwrap();
        assert!(verify(&parsed, "_a", &[other.public]).is_err());
    }

    #[test]
    fn query_signatures() {
        let query = sign_query("SAMLRequest=abc%2B&RelayState=x%20y", key(), SigAlg::RsaSha256);
        let sig = QuerySignature::from_query(&format!("{query}&extra=1")).unwrap();
        assert!(sig.signed.starts_with("SAMLRequest=abc%2B&RelayState=x%20y&SigAlg="));
        assert!(sig.verify(&[key().public.clone()]).is_ok());
        assert_eq!(duplicate_param(&query), None);
        assert_eq!(duplicate_param(&format!("{query}&SAMLRequest=other")), Some("SAMLRequest"));
        let bad = QuerySignature::from_query(&query.replace("abc", "abd")).unwrap();
        assert!(bad.verify(&[key().public.clone()]).is_err());
    }
}

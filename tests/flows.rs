use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use localsaml::config::Config;
use localsaml::dsig::{self, NS_DS, QuerySignature};
use localsaml::keys::{KeyPair, Keys, SigAlg};
use localsaml::presets::nameid;
use localsaml::saml::{self, NS_ASSERTION as A, NS_PROTOCOL as P, Status};
use localsaml::sp::ServiceProvider;
use localsaml::util::{b64_std, b64_std_decode_lenient, iso8601, parse_iso8601, wall_clock};
use localsaml::xml::{Element, parse};
use localsaml::{AppState, router, xmlenc};

const BASE: &str = "http://localhost:9401";
const SP: &str = "http://app.test/sp";
const ACS: &str = "http://app.test/acs";

fn keys() -> Arc<Keys> {
    static KEYS: OnceLock<Arc<Keys>> = OnceLock::new();
    KEYS.get_or_init(|| Arc::new(Keys::generate().unwrap())).clone()
}

/// The service providers' own key pair (not the IdP's).
fn sp_key() -> &'static KeyPair {
    localsaml::keys::untrusted()
}

fn app_with(config: Config) -> (Router, AppState) {
    let state = AppState::new(config, keys()).unwrap();
    (router(state.clone()), state)
}

fn app() -> (Router, AppState) {
    app_with(with_sps(vec![]))
}

fn sp(entity: &str, acs: &str) -> ServiceProvider {
    ServiceProvider { entity_id: entity.into(), acs_urls: vec![acs.into()], ..Default::default() }
}

/// The service providers to declare, plus the tests' usual one (`SP`, at `ACS`, signing with the
/// SPs' key): localsaml only answers declared service providers unless it's lenient.
fn with_sps(mut sps: Vec<ServiceProvider>) -> Config {
    if !sps.iter().any(|s| s.entity_id == SP) {
        sps.push(ServiceProvider { certificate: Some(sp_key().cert_b64()), ..sp(SP, ACS) });
    }
    Config { service_providers: sps, ..Default::default() }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// A tiny cookie jar for one browser.
#[derive(Default, Clone)]
struct Jar(HashMap<String, String>);

impl Jar {
    fn header(&self) -> String {
        self.0.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
    }
    fn update(&mut self, headers: &HeaderMap) {
        for v in headers.get_all(header::SET_COOKIE) {
            let v = v.to_str().unwrap();
            let pair = v.split(';').next().unwrap();
            let (k, val) = pair.split_once('=').unwrap();
            if v.contains("Max-Age=0") {
                self.0.remove(k);
            } else {
                self.0.insert(k.into(), val.into());
            }
        }
    }
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.body))
    }
    fn location(&self) -> url::Url {
        let loc = self
            .headers
            .get(header::LOCATION)
            .unwrap_or_else(|| panic!("no Location ({}): {}", self.status, self.body));
        url::Url::parse(loc.to_str().unwrap()).unwrap()
    }
    /// The value of a hidden form field.
    fn field(&self, name: &str) -> Option<String> {
        let marker = format!(r#"name="{name}" value=""#);
        let start = self.body.find(&marker)? + marker.len();
        let end = self.body[start..].find('"')?;
        Some(unescape(&self.body[start..start + end]))
    }
    fn title(&self) -> String {
        let start = self.body.find("<title>").map(|i| i + 7).unwrap_or(0);
        let end = self.body[start..].find("</title>").map(|i| start + i).unwrap_or(start);
        unescape(&self.body[start..end])
    }
}

fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

async fn send(app: &Router, req: Request<Body>, jar: Option<&mut Jar>) -> Resp {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    if let Some(jar) = jar {
        jar.update(&headers);
    }
    let body = String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    Resp { status, headers, body }
}

async fn get(app: &Router, uri: &str) -> Resp {
    send(app, Request::get(uri).body(Body::empty()).unwrap(), None).await
}

async fn get_jar(app: &Router, uri: &str, jar: &mut Jar) -> Resp {
    let req = Request::get(uri).header(header::COOKIE, jar.header()).body(Body::empty()).unwrap();
    send(app, req, Some(jar)).await
}

async fn post_form(app: &Router, uri: &str, form: &[(&str, &str)], jar: &mut Jar) -> Resp {
    let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(form).finish();
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, jar.header())
        .body(Body::from(body))
        .unwrap();
    send(app, req, Some(jar)).await
}

async fn post_body(app: &Router, method: Method, uri: &str, content_type: &str, body: &str) -> Resp {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body.to_string()))
        .unwrap();
    send(app, req, None).await
}

async fn post_json(app: &Router, uri: &str, body: Value) -> Resp {
    post_body(app, Method::POST, uri, "application/json", &body.to_string()).await
}

async fn delete(app: &Router, uri: &str) -> Resp {
    send(app, Request::delete(uri).body(Body::empty()).unwrap(), None).await
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn query_param(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v.into_owned())
}

// ---------------------------------------------------------------------------
// SAML helpers
// ---------------------------------------------------------------------------

fn authn_request(id: &str, issuer: &str, acs: Option<&str>, attrs: &str, children: &str) -> String {
    let acs = acs.map(|a| format!(r#" AssertionConsumerServiceURL="{a}""#)).unwrap_or_default();
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="{P}" xmlns:saml="{A}" ID="{id}" Version="2.0" IssueInstant="{}"{acs}{attrs}><saml:Issuer>{issuer}</saml:Issuer>{children}</samlp:AuthnRequest>"#,
        iso8601(wall_clock())
    )
}

fn simple_request(id: &str) -> String {
    authn_request(id, SP, Some(ACS), "", "")
}

/// The Redirect binding URL for a message, signed with `key` if given.
fn redirect(path: &str, param: &str, xml: &str, relay: Option<&str>, key: Option<&KeyPair>) -> String {
    saml::redirect_url(path, param, xml, relay, key.map(|k| (k, SigAlg::RsaSha256)))
}

/// Sign a protocol message for the POST binding.
fn signed_xml(xml: &str, id: &str, key: &KeyPair) -> String {
    let mut el = parse(xml).unwrap();
    saml::sign_message(&mut el, id, key, &localsaml::presets::generic().style, SigAlg::RsaSha256).unwrap();
    el.to_xml()
}

/// Approve a login page with an identity.
async fn approve(app: &Router, prefix: &str, page: &Resp, preset: &str, identity: Value, jar: &mut Jar) -> Resp {
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let req = page.field("req").unwrap_or_else(|| panic!("login form expected: {}", page.title()));
    let identity = identity.to_string();
    post_form(
        app,
        &format!("{prefix}/login"),
        &[("req", &req), ("action", "approve"), ("preset", preset), ("identity", &identity)],
        jar,
    )
    .await
}

/// A Response posted to an ACS by the HTTP-POST binding page.
struct Posted {
    action: String,
    relay: Option<String>,
    doc: Element,
}

impl Posted {
    fn status(&self) -> Status {
        Status::from_element(self.doc.find(P, "Status"))
    }
    fn assertion(&self) -> &Element {
        self.doc.find(A, "Assertion").expect("an Assertion")
    }
    fn name_id(&self) -> (String, String) {
        let n = self.assertion().path(&[(A, "Subject"), (A, "NameID")]).unwrap();
        (n.value(), n.get_attr("Format").unwrap_or_default().to_string())
    }
    fn attribute(&self, name: &str) -> Vec<String> {
        attr_values(self.assertion(), name)
    }
    fn id(&self) -> String {
        self.doc.get_attr("ID").unwrap().to_string()
    }
}

fn attr_values(assertion: &Element, name: &str) -> Vec<String> {
    assertion
        .find(A, "AttributeStatement")
        .into_iter()
        .flat_map(|s| s.find_all(A, "Attribute"))
        .filter(|a| a.get_attr("Name") == Some(name))
        .flat_map(|a| a.find_all(A, "AttributeValue").map(|v| v.text_content()).collect::<Vec<_>>())
        .collect()
}

fn posted(resp: &Resp) -> Posted {
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let b64 =
        resp.field("SAMLResponse").unwrap_or_else(|| panic!("expected a posted SAMLResponse, got {}", resp.title()));
    let xml = String::from_utf8(b64_std_decode_lenient(&b64).unwrap()).unwrap();
    let start = resp.body.find(r#"action=""#).unwrap() + 8;
    let end = resp.body[start..].find('"').unwrap();
    Posted {
        action: unescape(&resp.body[start..start + end]),
        relay: resp.field("RelayState"),
        doc: parse(&xml).unwrap(),
    }
}

/// A message sent by the Redirect binding (a Location with SAMLRequest/SAMLResponse).
fn redirected(resp: &Resp, param: &str) -> (url::Url, Element) {
    let loc = resp.location();
    let value = query_param(&loc, param).unwrap_or_else(|| panic!("no {param} in {loc}"));
    let xml = saml::decode_message(&value, true).unwrap();
    (loc, parse(&xml).unwrap())
}

fn verify(state: &AppState, doc: &Element, id: &str) {
    dsig::verify(doc, id, &state.keys.public_keys()).unwrap_or_else(|e| panic!("signature on {id}: {e}"));
}

/// Sign in straight away (dev_attributes) with an IdP-initiated login.
async fn quick_login(app: &Router, prefix: &str, sp: &str, jar: &mut Jar, extra: &str) -> Posted {
    let uri = format!("{prefix}/sso/initiate?sp={}&dev_attributes=%7B%7D{extra}", enc(sp));
    posted(&get_jar(app, &uri, jar).await)
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

#[tokio::test]
async fn metadata_for_root_and_templates() {
    let (app, state) = app();
    let md = |body: &str| parse(body).unwrap();
    let location = |doc: &Element, service: &str| -> Vec<String> {
        doc.find(saml::NS_MD, "IDPSSODescriptor")
            .unwrap()
            .find_all(saml::NS_MD, service)
            .map(|s| s.get_attr("Location").unwrap().to_string())
            .collect()
    };

    let root = md(&get(&app, "/metadata").await.body);
    assert_eq!(root.get_attr("entityID"), Some("http://localhost:9401/metadata"));
    assert_eq!(
        location(&root, "SingleSignOnService"),
        [format!("{BASE}/sso"), format!("{BASE}/sso"), format!("{BASE}/sso")]
    );
    assert_eq!(location(&root, "SingleLogoutService")[0], format!("{BASE}/slo"));

    let okta = md(&get(&app, "/p/okta/metadata").await.body);
    assert_eq!(okta.get_attr("entityID"), Some("http://www.okta.com/exk1fcia6d6EMsf331d8"));
    assert_eq!(
        location(&okta, "SingleSignOnService")[0],
        format!("{BASE}/p/okta/app/localsaml/exk1fcia6d6EMsf331d8/sso/saml")
    );
    assert_eq!(
        location(&okta, "SingleLogoutService")[0],
        format!("{BASE}/p/okta/app/localsaml/exk1fcia6d6EMsf331d8/slo/saml")
    );
    // The alias paths serve metadata too.
    let alias = get(&app, "/p/okta/app/exk1fcia6d6EMsf331d8/sso/saml/metadata").await;
    assert_eq!(md(&alias.body).get_attr("entityID"), okta.get_attr("entityID"));

    let keycloak = md(&get(&app, "/p/keycloak/metadata").await.body);
    assert_eq!(keycloak.get_attr("entityID"), Some("http://localhost:9401/p/keycloak/realms/example"));

    let google = md(&get(&app, "/p/google/metadata").await.body);
    assert!(location(&google, "SingleLogoutService").is_empty());

    let signed = md(&get(&app, "/metadata?signed=true").await.body);
    let id = signed.get_attr("ID").unwrap().to_string();
    verify(&state, &signed, &id);
    assert!(root.get_attr("ID").is_none());

    let pem = get(&app, "/certificate.pem").await;
    assert!(pem.body.starts_with("-----BEGIN CERTIFICATE-----"), "{}", pem.body);
    let cert_in_md = root
        .find(saml::NS_MD, "IDPSSODescriptor")
        .unwrap()
        .find(saml::NS_MD, "KeyDescriptor")
        .unwrap()
        .path(&[(NS_DS, "KeyInfo"), (NS_DS, "X509Data"), (NS_DS, "X509Certificate")])
        .unwrap()
        .value();
    assert_eq!(localsaml::keys::parse_cert(&pem.body).unwrap(), localsaml::keys::parse_cert(&cert_in_md).unwrap());
}

// ---------------------------------------------------------------------------
// SP-initiated SSO
// ---------------------------------------------------------------------------

#[tokio::test]
async fn redirect_binding_login_signed_by_the_test_sp() {
    let (app, state) = app();
    let mut jar = Jar::default();
    let sp = format!("{BASE}/sp");
    let acs = format!("{BASE}/sp/acs");
    let xml = authn_request("_req1", &sp, Some(&acs), "", "");
    let uri = state.keys.with_current(|k| redirect("/sso", "SAMLRequest", &xml, Some("/home"), Some(k)));
    let page = get_jar(&app, &uri, &mut jar).await;
    assert_eq!(page.title(), "Sign in · localsaml");
    assert!(page.body.contains("Redirect binding signature (rsa-sha256), verified"), "{}", page.body);

    let resp = approve(
        &app,
        "",
        &page,
        "generic",
        json!({ "name_id": "", "name_id_format": "", "attributes": { "email": "bob@example.com", "groups": ["a", "b"] } }),
        &mut jar,
    )
    .await;
    let p = posted(&resp);
    assert_eq!(p.action, acs);
    assert_eq!(p.relay.as_deref(), Some("/home"));
    // Not cached (Bindings 3.5.5.1).
    assert_eq!(resp.headers.get(header::CACHE_CONTROL).unwrap(), "no-cache, no-store");
    assert_eq!(resp.headers.get(header::PRAGMA).unwrap(), "no-cache");
    assert!(p.status().is_success());
    assert_eq!(p.doc.get_attr("InResponseTo"), Some("_req1"));
    assert_eq!(p.doc.get_attr("Destination"), Some(acs.as_str()));
    verify(&state, &p.doc, &p.id());
    let aid = p.assertion().get_attr("ID").unwrap().to_string();
    verify(&state, &p.doc, &aid);
    assert_eq!(p.name_id(), ("bob@example.com".to_string(), nameid::EMAIL.to_string()));
    assert_eq!(p.attribute("groups"), ["a", "b"]);
    let audience =
        p.assertion().path(&[(A, "Conditions"), (A, "AudienceRestriction"), (A, "Audience")]).unwrap().value();
    assert_eq!(audience, sp);
    let scd =
        p.assertion().path(&[(A, "Subject"), (A, "SubjectConfirmation"), (A, "SubjectConfirmationData")]).unwrap();
    assert_eq!((scd.get_attr("Recipient"), scd.get_attr("InResponseTo")), (Some(acs.as_str()), Some("_req1")));
    assert!(jar.0.contains_key("localsaml_sid_root"));

    // The test SP accepts it (it remembers the AuthnRequest it "sent" in a cookie).
    let mut sp_jar = Jar::default();
    sp_jar.0.insert("localsaml_testsp_req_root".into(), "_req1".into());
    let b64 = resp.field("SAMLResponse").unwrap();
    let accepted = post_form(&app, "/sp/acs", &[("SAMLResponse", &b64)], &mut sp_jar).await;
    assert_eq!(accepted.title(), "Test SP: signed in · localsaml", "{}", accepted.body);
}

#[tokio::test]
async fn unsigned_redirect_and_signed_post_bindings() {
    let mut declared = sp("http://signed.test/sp", "http://signed.test/acs");
    declared.certificate = Some(sp_key().cert_b64());
    let (app, state) = app_with(with_sps(vec![declared]));
    let mut jar = Jar::default();

    // Unsigned, from an SP nobody declared (lenient mode).
    let page = get_jar(&app, &redirect("/sso", "SAMLRequest", &simple_request("_u1"), None, None), &mut jar).await;
    assert!(page.body.contains("<dd>unsigned</dd>"), "{}", page.body);
    let p = posted(&approve(&app, "", &page, "generic", json!({}), &mut jar).await);
    assert_eq!((p.action.as_str(), p.doc.get_attr("InResponseTo")), (ACS, Some("_u1")));

    // POST binding with an enveloped signature, verified against the SP's certificate.
    let xml = authn_request("_p1", "http://signed.test/sp", Some("http://signed.test/acs"), "", "");
    let signed = signed_xml(&xml, "_p1", sp_key());
    let page = post_form(&app, "/sso", &[("SAMLRequest", &b64_std(&signed)), ("RelayState", "rs")], &mut jar).await;
    assert!(page.body.contains("XML signature (rsa-sha256), verified"), "{}", page.body);
    let p = posted(&approve(&app, "", &page, "generic", json!({}), &mut jar).await);
    assert_eq!((p.action.as_str(), p.relay.as_deref()), ("http://signed.test/acs", Some("rs")));
    verify(&state, &p.doc, &p.id());
}

#[tokio::test]
async fn declared_service_providers_are_enforced() {
    let mut strict_sp = sp("http://declared.test/sp", "http://declared.test/acs");
    strict_sp.want_authn_requests_signed = true;
    let mut cert_sp = sp("http://cert.test/sp", "http://cert.test/acs");
    cert_sp.certificate = Some(sp_key().cert_b64());
    let (app, state) = app_with(with_sps(vec![strict_sp, cert_sp]));

    // An ACS URL that isn't registered.
    let xml = authn_request("_a1", "http://declared.test/sp", Some("http://evil.test/acs"), "", "");
    let r = get(&app, &redirect("/sso", "SAMLRequest", &xml, None, Some(sp_key()))).await;
    assert_eq!(
        (r.status, r.title().as_str()),
        (StatusCode::OK, "Unregistered AssertionConsumerServiceURL · localsaml")
    );

    // Unsigned, but the SP wants signed requests.
    let xml = authn_request("_a2", "http://declared.test/sp", None, "", "");
    let r = get(&app, &redirect("/sso", "SAMLRequest", &xml, None, None)).await;
    // The ACS (the declared default) can be trusted, so the refusal is a RequestDenied Response
    // (Bindings 3.4.6).
    let p = posted(&r);
    assert_eq!(p.status().short(), "RequestDenied");
    assert!(p.status().message.unwrap().starts_with("Unsigned AuthnRequest"));

    // Signed by the wrong key (the IdP's, not the SP's certificate).
    let xml = authn_request("_a3", "http://cert.test/sp", None, "", "");
    let uri = state.keys.with_current(|k| redirect("/sso", "SAMLRequest", &xml, None, Some(k)));
    let r = get(&app, &uri).await;
    assert_eq!(posted(&r).status().short(), "RequestDenied");
    let signed = state.keys.with_current(|k| signed_xml(&xml, "_a3", k));
    let r = post_form(&app, "/sso", &[("SAMLRequest", &b64_std(&signed))], &mut Jar::default()).await;
    assert!(posted(&r).status().message.unwrap().starts_with("Invalid AuthnRequest signature"));
    // An unregistered ACS gets no Response, even to refuse: an error page (HTTP 200).
    let xml_evil = authn_request("_a4", "http://cert.test/sp", Some("http://evil.test/acs"), "", "");
    let uri = state.keys.with_current(|k| redirect("/sso", "SAMLRequest", &xml_evil, None, Some(k)));
    let r = get(&app, &uri).await;
    assert_eq!(
        (r.status, r.headers["x-localsaml-error"].to_str().unwrap()),
        (StatusCode::OK, "Unregistered AssertionConsumerServiceURL")
    );

    // With no ACS in the request, the declared default is used.
    let r = get(&app, &redirect("/sso", "SAMLRequest", &xml, None, Some(sp_key()))).await;
    assert!(r.body.contains("http://cert.test/acs"), "{}", r.title());

    // Strict mode: unknown service providers are refused.
    let (app, _) = app_with(Config::default());
    let r = get(&app, &redirect("/sso", "SAMLRequest", &simple_request("_s1"), None, None)).await;
    assert_eq!((r.status, r.title().as_str()), (StatusCode::OK, "Unknown service provider · localsaml"));
}

#[tokio::test]
async fn service_providers_from_inline_metadata_in_the_config_file() {
    let metadata = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://meta.test/sp">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://meta.test/slo"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://meta.test/acs" index="0"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"#;
    let path = std::env::temp_dir().join(format!("localsaml-test-{}.toml", uuid::Uuid::new_v4()));
    std::fs::write(&path, format!("[[service_providers]]\nname = \"Meta\"\nmetadata = '''{metadata}'''\n")).unwrap();
    let mut config =
        Config::load(&localsaml::config::ServerArgs { config: Some(path.clone()), ..Default::default() }).unwrap();
    std::fs::remove_file(&path).ok();
    config.data_dir = None;
    let sp = &config.service_providers[0];
    assert_eq!(
        (sp.entity_id.as_str(), sp.acs_urls.as_slice(), sp.slo_url.as_deref()),
        ("http://meta.test/sp", &["http://meta.test/acs".to_string()][..], Some("http://meta.test/slo"))
    );

    let (app, _) = app_with(config);
    let mut jar = Jar::default();
    let xml = authn_request("_m1", "http://meta.test/sp", None, "", "");
    let page = get_jar(&app, &redirect("/sso", "SAMLRequest", &xml, None, None), &mut jar).await;
    assert!(page.body.contains("Sign in to <span class=\"accent\">Meta</span>"), "{}", page.body);
    assert_eq!(posted(&approve(&app, "", &page, "generic", json!({}), &mut jar).await).action, "http://meta.test/acs");
}

#[tokio::test]
async fn passive_and_forced_authentication() {
    let (app, _) = app_with(Config { silent_sso: true, ..with_sps(vec![]) });
    let mut jar = Jar::default();
    let passive = authn_request("_ip1", SP, Some(ACS), r#" IsPassive="true""#, "");
    let p = posted(&get_jar(&app, &redirect("/sso", "SAMLRequest", &passive, None, None), &mut jar).await);
    assert_eq!(p.status().short(), "NoPassive");
    assert_eq!(p.status().code, saml::status::RESPONDER);
    assert!(p.doc.find(A, "Assertion").is_none());

    // Sign in, then the passive request succeeds from the session.
    let page = get_jar(&app, &redirect("/sso", "SAMLRequest", &simple_request("_ip2"), None, None), &mut jar).await;
    approve(&app, "", &page, "generic", json!({}), &mut jar).await;
    let passive = authn_request("_ip3", SP, Some(ACS), r#" IsPassive="true""#, "");
    let p = posted(&get_jar(&app, &redirect("/sso", "SAMLRequest", &passive, None, None), &mut jar).await);
    assert!(p.status().is_success());
    assert_eq!(p.doc.get_attr("InResponseTo"), Some("_ip3"));

    // silent_sso reuses the session without the login page...
    let r = get_jar(&app, &redirect("/sso", "SAMLRequest", &simple_request("_ip4"), None, None), &mut jar).await;
    assert!(posted(&r).status().is_success());
    // ...unless the SP forces a fresh login.
    let forced = authn_request("_ip5", SP, Some(ACS), r#" ForceAuthn="true""#, "");
    let r = get_jar(&app, &redirect("/sso", "SAMLRequest", &forced, None, None), &mut jar).await;
    assert!(r.field("req").is_some(), "{}", r.title());
    assert!(r.body.contains("ForceAuthn"));
}

fn policy(format: &str) -> String {
    format!(r#"<samlp:NameIDPolicy Format="{format}" AllowCreate="true"/>"#)
}

/// Sign in with dev_attributes and a NameIDPolicy, without a session.
async fn name_id_for(app: &Router, prefix: &str, sp: &str, format: &str) -> (String, String) {
    let xml = authn_request(&localsaml::util::saml_id("_n"), sp, Some(ACS), "", &policy(format));
    let uri = format!("{}&dev_attributes=%7B%7D", redirect(&format!("{prefix}/sso"), "SAMLRequest", &xml, None, None));
    posted(&get(app, &uri).await).name_id()
}

#[tokio::test]
async fn name_id_policies() {
    let (app, _) = app_with(with_sps(vec![sp("http://other.test/sp", ACS)]));
    // Keycloak's NameID is a username; asking for an email address uses the email attribute.
    assert_eq!(
        name_id_for(&app, "/p/keycloak", SP, nameid::EMAIL).await,
        ("jane@example.com".into(), nameid::EMAIL.into())
    );
    // Persistent IDs are pairwise: stable per SP, different between SPs.
    let a1 = name_id_for(&app, "", SP, nameid::PERSISTENT).await;
    let a2 = name_id_for(&app, "", SP, nameid::PERSISTENT).await;
    let b = name_id_for(&app, "", "http://other.test/sp", nameid::PERSISTENT).await;
    assert_eq!(a1.1, nameid::PERSISTENT);
    assert_eq!(a1, a2);
    assert_ne!(a1.0, b.0);
    assert_ne!(a1.0, "jane@example.com");
    // The emailAddress NameID follows an email set with dev_attributes, not the default.
    let xml = authn_request("_n_bob", SP, Some(ACS), "", &policy(nameid::EMAIL));
    let attrs = enc(r#"{"urn:oid:1.2.840.113549.1.9.1":"bob@example.com"}"#);
    let uri = format!("{}&dev_attributes={attrs}", redirect("/p/keycloak/sso", "SAMLRequest", &xml, None, None));
    assert_eq!(posted(&get(&app, &uri).await).name_id(), ("bob@example.com".into(), nameid::EMAIL.into()));
    // Transient IDs change with every session.
    let t1 = name_id_for(&app, "", SP, nameid::TRANSIENT).await;
    let t2 = name_id_for(&app, "", SP, nameid::TRANSIENT).await;
    assert_eq!(t1.1, nameid::TRANSIENT);
    assert_ne!(t1.0, t2.0);
}

// ---------------------------------------------------------------------------
// Automated logins
// ---------------------------------------------------------------------------

fn alice() -> localsaml::users::User {
    serde_json::from_value(json!({
        "id": "alice",
        "label": "Alice",
        "preset": "okta",
        "attributes": { "email": "alice@acme.dev", "groups": ["admins"] },
    }))
    .unwrap()
}

#[tokio::test]
async fn dev_parameters_sign_in_immediately() {
    let (app, _) = app_with(Config { users: vec![alice()], ..with_sps(vec![]) });
    let base = redirect("/sso", "SAMLRequest", &simple_request("_d1"), None, None);

    let p = posted(&get(&app, &format!("{base}&dev_user=alice")).await);
    assert_eq!(p.name_id().0, "alice@acme.dev");
    assert_eq!(p.attribute("groups"), ["admins"]);
    // alice uses the Okta template: saml2 prefixes.
    assert_eq!(p.doc.prefix.as_deref(), Some("saml2p"));

    let attrs = enc(r#"{"email":"carol@example.com","roles":["admin"],"groups":null}"#);
    let p = posted(&get(&app, &format!("{base}&dev_attributes={attrs}")).await);
    assert_eq!(p.name_id().0, "carol@example.com");
    assert_eq!(p.attribute("roles"), ["admin"]);
    assert!(p.attribute("groups").is_empty());

    let p = posted(&get(&app, &format!("{base}&dev_attributes=%7B%7D&dev_preset=entra")).await);
    assert_eq!(p.assertion().prefix, None);
    assert!(!p.attribute("http://schemas.microsoft.com/identity/claims/objectidentifier").is_empty());

    let p = posted(&get(&app, &format!("{base}&dev_status=AuthnFailed")).await);
    assert_eq!(p.status().short(), "AuthnFailed");

    let p = posted(&get(&app, &format!("{base}&dev_attributes=%7B%7D&dev_tamper=expired,wrong_audience")).await);
    let conditions = p.assertion().find(A, "Conditions").unwrap();
    assert!(parse_iso8601(conditions.get_attr("NotOnOrAfter").unwrap()).unwrap() < wall_clock());
    assert!(
        conditions.path(&[(A, "AudienceRestriction"), (A, "Audience")]).unwrap().value().contains("wrong-audience")
    );

    let r = get(&app, &format!("{base}&dev_user=nobody")).await;
    assert_eq!((r.status, r.title().as_str()), (StatusCode::OK, "Unknown dev_user · localsaml"));
    let r = get(&app, &format!("{base}&dev_tamper=nope")).await;
    assert_eq!(r.headers["x-localsaml-error"], "Invalid dev_tamper");
}

#[tokio::test]
async fn auto_login_uses_the_login_hint() {
    let (app, _) = app_with(Config { auto_login: true, users: vec![alice()], ..with_sps(vec![]) });
    let base = redirect("/sso", "SAMLRequest", &simple_request("_al1"), None, None);
    let p = posted(&get(&app, &format!("{base}&login_hint=alice")).await);
    assert_eq!(p.name_id().0, "alice@acme.dev");
    // A Subject in the AuthnRequest works as a hint too.
    let xml = authn_request(
        "_al2",
        SP,
        Some(ACS),
        "",
        r#"<saml:Subject><saml:NameID>alice@acme.dev</saml:NameID></saml:Subject>"#,
    );
    let p = posted(&get(&app, &redirect("/sso", "SAMLRequest", &xml, None, None)).await);
    assert_eq!(p.attribute("groups"), ["admins"]);
    // Without a hint: the template defaults.
    let p = posted(&get(&app, &base).await);
    assert_eq!(p.name_id().0, "jane@example.com");
}

// ---------------------------------------------------------------------------
// IdP-initiated SSO
// ---------------------------------------------------------------------------

#[tokio::test]
async fn idp_initiated_logins() {
    let (app, state) = app_with(with_sps(vec![sp("http://known.test/sp", "http://known.test/acs")]));
    let mut jar = Jar::default();
    let page = get_jar(&app, "/sso/initiate?sp=http%3A%2F%2Fknown.test%2Fsp&RelayState=%2Fdash", &mut jar).await;
    let p = posted(&approve(&app, "", &page, "generic", json!({}), &mut jar).await);
    assert_eq!((p.action.as_str(), p.relay.as_deref()), ("http://known.test/acs", Some("/dash")));
    assert!(p.doc.get_attr("InResponseTo").is_none());
    verify(&state, &p.doc, &p.id());

    // Unknown SPs are refused, even with an ACS URL: it can't be verified (Profiles 4.1.4.1).
    let r = get(&app, "/sso/initiate?sp=http%3A%2F%2Fnew.test%2Fsp").await;
    assert_eq!(r.title(), "Unknown service provider · localsaml");
    let r =
        get(&app, "/sso/initiate?sp=http%3A%2F%2Fnew.test%2Fsp&acs=http%3A%2F%2Fnew.test%2Facs&dev_attributes=%7B%7D")
            .await;
    assert_eq!(r.title(), "Unknown service provider · localsaml");
    // Lenient mode takes the ACS URL on trust.
    let (lenient, _) = app_with(Config { lenient: true, ..Default::default() });
    let p =
        quick_login(&lenient, "", "http://new.test/sp", &mut Jar::default(), "&acs=http%3A%2F%2Fnew.test%2Facs").await;
    assert_eq!(p.action, "http://new.test/acs");

    // No SP: a picker.
    assert!(get(&app, "/sso/initiate").await.body.contains("known.test"));

    // Okta-style links: the SSO URL with the SP named in the query.
    let r = get(
        &app,
        "/p/okta/app/localsaml/exk1fcia6d6EMsf331d8/sso/saml?sp=http%3A%2F%2Fknown.test%2Fsp&dev_attributes=%7B%7D",
    )
    .await;
    let p = posted(&r);
    assert_eq!(p.doc.find(A, "Issuer").unwrap().value(), "http://www.okta.com/exk1fcia6d6EMsf331d8");

    // Strict mode refuses unknown SPs even with an ACS URL.
    let (app, _) = app_with(Config::default());
    let r = get(&app, "/sso/initiate?sp=http%3A%2F%2Fnew.test%2Fsp&acs=http%3A%2F%2Fnew.test%2Facs").await;
    assert_eq!((r.status, r.title().as_str()), (StatusCode::OK, "Unknown service provider · localsaml"));
}

// ---------------------------------------------------------------------------
// Single logout
// ---------------------------------------------------------------------------

fn slo_sp(name: &str) -> ServiceProvider {
    ServiceProvider {
        entity_id: format!("http://{name}.test/sp"),
        acs_urls: vec![format!("http://{name}.test/acs")],
        slo_url: Some(format!("http://{name}.test/slo")),
        // Logout messages must be signed (Profiles 4.4.4.1); the tests sign with the SPs' key.
        certificate: Some(sp_key().cert_b64()),
        ..Default::default()
    }
}

fn logout_request(id: &str, issuer: &str, name_id: &str) -> String {
    format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{P}" xmlns:saml="{A}" ID="{id}" Version="2.0" IssueInstant="{}"><saml:Issuer>{issuer}</saml:Issuer><saml:NameID>{name_id}</saml:NameID></samlp:LogoutRequest>"#,
        iso8601(wall_clock())
    )
}

fn logout_response(id: &str, issuer: &str, in_response_to: &str) -> String {
    format!(
        r#"<samlp:LogoutResponse xmlns:samlp="{P}" xmlns:saml="{A}" ID="{id}" Version="2.0" IssueInstant="{}" InResponseTo="{in_response_to}"><saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>"#,
        iso8601(wall_clock())
    )
}

#[tokio::test]
async fn sp_initiated_logout_propagates_to_the_other_service_providers() {
    let (app, state) = app_with(with_sps(vec![slo_sp("a"), slo_sp("b")]));
    let mut jar = Jar::default();
    let a = quick_login(&app, "", "http://a.test/sp", &mut jar, "").await;
    let b = quick_login(&app, "", "http://b.test/sp", &mut jar, "").await;
    // Both logins share one session (and SessionIndex).
    let index =
        |p: &Posted| p.assertion().find(A, "AuthnStatement").unwrap().get_attr("SessionIndex").unwrap().to_string();
    assert_eq!(index(&a), index(&b));
    assert_eq!(get(&app, "/dev/api/sessions").await.json().as_array().unwrap().len(), 1);

    // A logs out: the IdP asks B first.
    let r = get_jar(
        &app,
        &redirect(
            "/slo",
            "SAMLRequest",
            &logout_request("_lo1", "http://a.test/sp", &a.name_id().0),
            Some("a-relay"),
            Some(sp_key()),
        ),
        &mut jar,
    )
    .await;
    assert!(!jar.0.contains_key("localsaml_sid_root"), "session cookie cleared");
    let (loc, to_b) = redirected(&r, "SAMLRequest");
    assert_eq!(format!("{}{}", loc.origin().ascii_serialization(), loc.path()), "http://b.test/slo");
    assert!(to_b.is(P, "LogoutRequest"));
    assert_eq!(to_b.find(A, "NameID").unwrap().value(), b.name_id().0);
    assert_eq!(to_b.find(P, "SessionIndex").unwrap().value(), index(&b));
    let sig = QuerySignature::from_query(loc.query().unwrap()).expect("signed redirect");
    sig.verify(&state.keys.public_keys()).unwrap();
    let logout_id = query_param(&loc, "RelayState").unwrap();
    let to_b_id = to_b.get_attr("ID").unwrap().to_string();

    // B answers; the IdP finishes by answering A.
    let r = get(
        &app,
        &redirect(
            "/slo",
            "SAMLResponse",
            &logout_response("_lr1", "http://b.test/sp", &to_b_id),
            Some(&logout_id),
            Some(sp_key()),
        ),
    )
    .await;
    let (loc, to_a) = redirected(&r, "SAMLResponse");
    assert!(loc.as_str().starts_with("http://a.test/slo?"));
    assert_eq!(query_param(&loc, "RelayState").as_deref(), Some("a-relay"));
    assert_eq!(to_a.get_attr("InResponseTo"), Some("_lo1"));
    assert!(Status::from_element(to_a.find(P, "Status")).is_success());
    assert!(get(&app, "/dev/api/sessions").await.json().as_array().unwrap().is_empty());
}

#[tokio::test]
async fn logout_without_a_session_and_idp_initiated_logout() {
    let (app, _) = app_with(with_sps(vec![slo_sp("a")]));
    // Nothing to log out of is still a success.
    let request = logout_request("_n1", "http://a.test/sp", "jane");
    let r = get(&app, &redirect("/slo", "SAMLRequest", &request, None, Some(sp_key()))).await;
    let (_, resp) = redirected(&r, "SAMLResponse");
    assert_eq!(resp.get_attr("InResponseTo"), Some("_n1"));
    assert!(Status::from_element(resp.find(P, "Status")).is_success());

    // IdP-initiated: A gets a LogoutRequest, then a "signed out" page.
    let mut jar = Jar::default();
    quick_login(&app, "", "http://a.test/sp", &mut jar, "").await;
    let r = get_jar(&app, "/slo/initiate", &mut jar).await;
    let (loc, req) = redirected(&r, "SAMLRequest");
    let relay = query_param(&loc, "RelayState").unwrap();
    let id = req.get_attr("ID").unwrap().to_string();
    let done = get(
        &app,
        &redirect(
            "/slo",
            "SAMLResponse",
            &logout_response("_r2", "http://a.test/sp", &id),
            Some(&relay),
            Some(sp_key()),
        ),
    )
    .await;
    assert_eq!(done.title(), "Signed out · localsaml");
    assert!(done.body.contains("logged out"));
    assert_eq!(get_jar(&app, "/slo/initiate", &mut jar).await.title(), "No active session · localsaml");

    // Google Workspace doesn't do single logout.
    let r = get(
        &app,
        &redirect("/p/google/slo", "SAMLRequest", &logout_request("_g1", "http://a.test/sp", "jane"), None, None),
    )
    .await;
    assert_eq!((r.status, r.title().as_str()), (StatusCode::OK, "Single logout isn't supported · localsaml"));
}

// ---------------------------------------------------------------------------
// Faults, clock, keys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn faults() {
    let (app, _) = app();
    let login = || async {
        posted(&get(&app, &format!("/sso/initiate?sp={}&acs={}&dev_attributes=%7B%7D", enc(SP), enc(ACS))).await)
    };

    let f = post_json(&app, "/dev/api/faults", json!({ "endpoint": "sso", "status": "AuthnFailed", "count": 2 })).await;
    assert_eq!(f.status, StatusCode::CREATED, "{}", f.body);
    assert_eq!(login().await.status().short(), "AuthnFailed");
    assert_eq!(login().await.status().short(), "AuthnFailed");
    assert!(login().await.status().is_success());

    post_json(&app, "/dev/api/faults", json!({ "endpoint": "sso", "tamper": ["wrong_audience"], "sp": SP })).await;
    let p = login().await;
    let audience =
        p.assertion().path(&[(A, "Conditions"), (A, "AudienceRestriction"), (A, "Audience")]).unwrap().value();
    assert!(audience.contains("wrong-audience"), "{audience}");
    assert_eq!(get(&app, "/dev/api/faults").await.json(), json!([]));

    post_json(&app, "/dev/api/faults", json!({ "endpoint": "metadata", "always": true })).await;
    let r = get(&app, "/metadata").await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(r.headers.contains_key("x-localsaml-fault"));
    assert_eq!(get(&app, "/p/okta/app/0oa1/sso/saml/metadata").await.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(delete(&app, "/dev/api/faults").await.status, StatusCode::NO_CONTENT);
    assert_eq!(get(&app, "/metadata").await.status, StatusCode::OK);

    let bad = post_json(&app, "/dev/api/faults", json!({ "endpoint": "metadata", "status": "Responder" })).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn clock_offset_shifts_timestamps() {
    let (app, _) = app();
    let r = post_json(&app, "/dev/api/clock", json!({ "advance": "1h" })).await;
    assert_eq!(r.json()["offset"], 3600);
    let xml = get(&app, "/dev/api/response?format=xml").await.body;
    let issued = parse_iso8601(parse(&xml).unwrap().get_attr("IssueInstant").unwrap()).unwrap();
    assert!((issued - wall_clock() - 3600).abs() < 60, "{issued}");
    assert_eq!(post_json(&app, "/dev/api/clock", json!({ "reset": true })).await.json()["offset"], 0);
    assert_eq!(post_json(&app, "/dev/api/clock", json!({ "advance": "nope" })).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn key_rotation_keeps_the_old_certificate_in_metadata() {
    let state = AppState::new(Config::default(), Arc::new(Keys::generate().unwrap())).unwrap();
    let app = router(state.clone());
    let count = |body: &str| {
        let md = parse(body).unwrap();
        md.find(saml::NS_MD, "IDPSSODescriptor").unwrap().find_all(saml::NS_MD, "KeyDescriptor").count()
    };
    let before = get(&app, "/metadata").await.body;
    assert_eq!(count(&before), 1);
    let old = state.keys.kid();
    let before_rotation = get(&app, "/dev/api/response").await.json();
    let r = post_body(&app, Method::POST, "/dev/api/rotate-keys", "application/json", "").await;
    assert_eq!(r.json()["retired_kids"], json!([old]));
    let after = get(&app, "/metadata").await.body;
    assert_eq!(count(&after), 2);
    // A response signed before the rotation still verifies against the published certificates.
    let doc = parse(before_rotation["xml"].as_str().unwrap()).unwrap();
    verify(&state, &doc, before_rotation["response_id"].as_str().unwrap());
    let cert = get(&app, "/dev/api/certificate").await.json();
    assert_eq!(cert["retired"][0]["kid"], json!(old));
}

// ---------------------------------------------------------------------------
// Dev API
// ---------------------------------------------------------------------------

#[tokio::test]
async fn response_api() {
    let mut encrypted = sp("http://enc.test/sp", "http://enc.test/acs");
    encrypted.certificate = Some(sp_key().cert_b64());
    let (app, state) = app_with(with_sps(vec![encrypted]));

    let r = get(&app, &format!("/dev/api/response?email=x@example.com&groups={}&relay_state=rs", enc(r#"["a","b"]"#)))
        .await;
    let v = r.json();
    assert_eq!(v["acs_url"], format!("{BASE}/sp/acs"));
    assert_eq!(v["name_id"], "x@example.com");
    assert_eq!(v["attributes"]["groups"], json!(["a", "b"]));
    assert!(v["curl"].as_str().unwrap().contains("RelayState=rs"));
    let doc = parse(&String::from_utf8(b64_std_decode_lenient(v["saml_response"].as_str().unwrap()).unwrap()).unwrap())
        .unwrap();
    verify(&state, &doc, v["response_id"].as_str().unwrap());

    let b64 = get(&app, "/dev/api/response?format=base64").await.body;
    assert!(String::from_utf8(b64_std_decode_lenient(&b64).unwrap()).unwrap().starts_with("<?xml"));
    let xml = get(&app, "/dev/api/response?format=xml&preset=okta").await;
    assert!(xml.body.contains("<saml2p:Response"));

    let r = post_json(
        &app,
        "/dev/api/response",
        json!({
            "sp": "http://enc.test/sp",
            "encrypt": true,
            "encryption_algorithm": "aes128-cbc",
            "in_response_to": "_x1",
            "attributes": { "email": "e@example.com" },
        }),
    )
    .await;
    let v = r.json();
    assert_eq!(v["encrypted"], true);
    let doc = parse(v["xml"].as_str().unwrap()).unwrap();
    assert_eq!(doc.get_attr("InResponseTo"), Some("_x1"));
    let plain =
        xmlenc::decrypt(doc.find(A, "EncryptedAssertion").unwrap(), std::slice::from_ref(&sp_key().private)).unwrap();
    let assertion = parse(&plain).unwrap();
    assert_eq!(attr_values(&assertion, "email"), ["e@example.com"]);
    verify(&state, &assertion, assertion.get_attr("ID").unwrap());

    let r = post_json(&app, "/dev/api/response", json!({ "preset": "nope" })).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.json()["error"], "invalid_request");
    let r = post_json(&app, "/dev/api/response", json!({ "sp": "http://plain.test/sp" })).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "an SP with no ACS needs acs_url");
    let r = post_json(&app, "/dev/api/response", json!({ "status": "NoPassive" })).await;
    assert!(r.json()["xml"].as_str().unwrap().contains("NoPassive"));
}

#[tokio::test]
async fn registering_service_providers() {
    let (app, _) = app();
    let metadata = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://reg.test/sp"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://reg.test/acs" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>"#;
    let r = post_body(&app, Method::POST, "/dev/api/service-providers", "application/xml", metadata).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    assert_eq!(r.json()["acs_urls"], json!(["http://reg.test/acs"]));
    let r = post_json(
        &app,
        "/dev/api/service-providers",
        json!({ "entity_id": "http://json.test/sp", "acs_urls": ["http://json.test/acs"] }),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let bad = post_json(&app, "/dev/api/service-providers", json!({ "acs_urls": ["nope"] })).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    let list = get(&app, "/dev/api/service-providers").await.json();
    let ids: Vec<&str> = list.as_array().unwrap().iter().map(|s| s["entity_id"].as_str().unwrap()).collect();
    assert_eq!(ids, [format!("{BASE}/sp").as_str(), SP, "http://reg.test/sp", "http://json.test/sp"]);

    // A registered SP's ACS URLs are enforced.
    let xml = authn_request("_r1", "http://reg.test/sp", Some("http://evil.test/acs"), "", "");
    assert_eq!(
        get(&app, &redirect("/sso", "SAMLRequest", &xml, None, None)).await.title(),
        "Unregistered AssertionConsumerServiceURL · localsaml"
    );

    assert_eq!(
        delete(&app, "/dev/api/service-providers?entity_id=http%3A%2F%2Freg.test%2Fsp").await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        delete(&app, "/dev/api/service-providers?entity_id=http%3A%2F%2Freg.test%2Fsp").await.status,
        StatusCode::NOT_FOUND
    );
    let list = get(&app, "/dev/api/service-providers").await.body;
    assert!(!list.contains("reg.test") && list.contains("json.test"));
}

#[tokio::test]
async fn sessions_api() {
    let (app, _) = app();
    let mut jar = Jar::default();
    quick_login(&app, "", SP, &mut jar, &format!("&acs={}", enc(ACS))).await;
    let sessions = get(&app, "/dev/api/sessions").await.json();
    let s = &sessions[0];
    assert_eq!(s["service_providers"], json!([SP]));
    assert!(s["logout_url"].as_str().unwrap().contains("/slo/initiate?sid="));
    let sid = s["sid"].as_str().unwrap();
    let r = delete(&app, &format!("/dev/api/sessions/{sid}")).await;
    assert_eq!(r.json()["not_notified"], json!([SP]));
    assert_eq!(delete(&app, &format!("/dev/api/sessions/{sid}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(get(&app, "/dev/api/sessions").await.json(), json!([]));
}

#[tokio::test]
async fn inspector_records_decoded_messages_and_errors() {
    let (app, _) = app_with(Config::default());
    let mut jar = Jar::default();
    let test_sp = format!("{BASE}/sp");
    let xml = authn_request("_i1", &test_sp, Some(&format!("{BASE}/sp/acs")), "", "");
    let page = get_jar(&app, &redirect("/sso", "SAMLRequest", &xml, None, None), &mut jar).await;
    approve(&app, "", &page, "generic", json!({}), &mut jar).await;
    get(&app, &redirect("/sso", "SAMLRequest", &simple_request("_i2"), None, None)).await;

    let entries = get(&app, "/dev/api/requests").await.json()["entries"].as_array().unwrap().clone();
    let sso = entries.iter().find(|e| e["endpoint"] == "/sso" && e["sp"] == json!(test_sp)).expect("the AuthnRequest");
    assert_eq!(sso["messages"][0]["kind"], "AuthnRequest");
    assert_eq!(sso["messages"][0]["direction"], "received");
    assert_eq!(sso["messages"][0]["binding"], "redirect");
    assert!(sso["messages"][0]["xml"].as_str().unwrap().contains("_i1"));
    let login = entries.iter().find(|e| e["endpoint"] == "/login").expect("the login");
    assert_eq!(login["messages"][0]["kind"], "Response");
    assert_eq!(login["messages"][0]["direction"], "sent");
    assert!(login["outcome"].as_str().unwrap().starts_with("Response → "), "{}", login["outcome"]);
    let refused = entries.iter().find(|e| e["sp"] == SP).expect("the refused request");
    assert_eq!(refused["error"], "Unknown service provider");
    // HTTP 200: the bindings forbid HTTP error codes for SAML failures (Bindings 3.4.6).
    assert_eq!(refused["status"], 200);

    let errors = get(&app, "/dev/api/requests?errors=true").await.json();
    assert!(
        errors["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["status"].as_u64().unwrap() >= 400 || e["error"].is_string())
    );
    assert_eq!(delete(&app, "/dev/api/requests").await.status, StatusCode::NO_CONTENT);
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn shibboleth_encrypts_and_entra_signs_only_the_assertion() {
    let mut with_cert = sp("http://enc.test/sp", "http://enc.test/acs");
    with_cert.certificate = Some(sp_key().cert_b64());
    let (app, state) = app_with(with_sps(vec![with_cert, sp("http://nocert.test/sp", "http://nocert.test/acs")]));

    let p = quick_login(&app, "/p/shibboleth", "http://enc.test/sp", &mut Jar::default(), "").await;
    assert!(p.doc.find(A, "Assertion").is_none());
    verify(&state, &p.doc, &p.id());
    let plain =
        xmlenc::decrypt(p.doc.find(A, "EncryptedAssertion").unwrap(), std::slice::from_ref(&sp_key().private)).unwrap();
    let assertion = parse(&plain).unwrap();
    assert_eq!(assertion.prefix.as_deref(), Some("saml2"));
    let name_id = assertion.path(&[(A, "Subject"), (A, "NameID")]).unwrap();
    assert_eq!(name_id.get_attr("Format"), Some(nameid::TRANSIENT));
    assert_eq!(attr_values(&assertion, "urn:oid:0.9.2342.19200300.100.1.3"), ["jane@example.edu"]);
    // An SP without a certificate gets a plain assertion.
    let p = quick_login(&app, "/p/shibboleth", "http://nocert.test/sp", &mut Jar::default(), "").await;
    assert!(p.doc.find(A, "Assertion").is_some());

    let p = quick_login(&app, "/p/entra", SP, &mut Jar::default(), &format!("&acs={}", enc(ACS))).await;
    assert!(dsig::signature_of(&p.doc).is_none(), "Entra ID doesn't sign the response");
    let assertion = p.assertion();
    assert_eq!(assertion.prefix, None);
    assert!(dsig::signature_of(assertion).is_some());
    verify(&state, &p.doc, assertion.get_attr("ID").unwrap());
    assert_eq!(
        assertion.find(A, "Issuer").unwrap().value(),
        "https://sts.windows.net/9188040d-6c67-4c5b-b112-36a304b66dad/"
    );
}

#[tokio::test]
async fn template_aliases_accept_authn_requests() {
    let (app, _) = app();
    let mut jar = Jar::default();
    for path in [
        "/p/okta/app/localsaml/exk1fcia6d6EMsf331d8/sso/saml",
        "/p/entra/9188040d-6c67-4c5b-b112-36a304b66dad/saml2",
        "/p/shibboleth/idp/profile/SAML2/Redirect/SSO",
        "/p/adfs/adfs/ls/",
        "/p/keycloak/realms/example/protocol/saml",
    ] {
        let page = get_jar(&app, &redirect(path, "SAMLRequest", &simple_request("_t1"), None, None), &mut jar).await;
        assert!(page.field("req").is_some(), "{path}: {}", page.title());
        let prefix = &path[..path[3..].find('/').unwrap() + 3];
        let p = posted(&approve(&app, prefix, &page, prefix.trim_start_matches("/p/"), json!({}), &mut jar).await);
        assert_eq!(p.doc.get_attr("InResponseTo"), Some("_t1"), "{path}");
    }
}

// ---------------------------------------------------------------------------
// Hardening and spec conformance
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hostile_messages_are_refused_not_fatal() {
    let (app, _) = app();
    // Deeply nested XML is refused (it used to overflow the stack), and the server keeps going.
    let deep = format!("{}{}", "<a>".repeat(50_000), "</a>".repeat(50_000));
    let r = get(&app, &redirect("/sso", "SAMLRequest", &deep, None, None)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("nested"), "{}", r.body);
    assert_eq!(get(&app, "/health").await.status, StatusCode::OK);

    // A second SAMLRequest could be processed instead of the one whose signature was checked.
    let signed = redirect("/sso", "SAMLRequest", &simple_request("_dup1"), None, Some(sp_key()));
    let extra = redirect("", "SAMLRequest", &simple_request("_evil"), None, None);
    let r = get(&app, &format!("{signed}&{}", &extra[1..])).await;
    assert_eq!((r.status, r.title()), (StatusCode::OK, "Duplicate parameter · localsaml".to_string()));

    // Script URLs are never posted or redirected to.
    let xml = authn_request("_js", SP, Some("javascript:alert(1)//"), "", "");
    let r = get(&app, &redirect("/sso", "SAMLRequest", &xml, None, None)).await;
    assert!(r.headers.contains_key("x-localsaml-error"));
    assert!(!r.body.contains(r#"action="javascript"#));
    let r = get(&app, &format!("/sso/initiate?sp={}&acs={}", enc(SP), enc("javascript:alert(1)"))).await;
    assert!(r.headers.contains_key("x-localsaml-error"));
    let r = post_json(&app, "/dev/api/response", json!({ "acs_url": "javascript:alert(1)" })).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // Page data can't close its <script> element, whatever the request says.
    let subject = r#"<saml:Subject><saml:NameID>&lt;/script&gt;&lt;!--&lt;script&gt;</saml:NameID></saml:Subject>"#;
    let xml = authn_request("_lh", SP, Some(ACS), "", subject);
    let r = get(&app, &redirect("/sso", "SAMLRequest", &xml, None, None)).await;
    let start = r.body.find(r#"id="lo-data">"#).unwrap() + 13;
    let data = &r.body[start..start + r.body[start..].find("</script>").unwrap()];
    assert!(!data.contains('<'), "{data}");
    assert_eq!(serde_json::from_str::<Value>(data).unwrap()["loginHint"], "</script><!--<script>");
}

#[tokio::test]
async fn the_test_sp_rejects_signature_wrapping() {
    let (app, _) = app();
    // Only the assertion is signed. Copy it into Extensions, then change the real one's NameID:
    // the signature still verifies, but over the copy, not the assertion the SP reads.
    let minted = post_json(&app, "/dev/api/response", json!({ "sign_response": false, "sign_assertion": true })).await;
    let minted = minted.json();
    let xml = minted["xml"].as_str().unwrap();
    let assertion = parse(xml).unwrap().find(A, "Assertion").unwrap().to_xml();
    assert!(xml.contains(&assertion));
    let name_id = minted["name_id"].as_str().unwrap();
    let wrapped = xml
        .replacen(&assertion, &assertion.replace(&format!(">{name_id}<"), ">admin@evil.test<"), 1)
        .replacen("<samlp:Status>", &format!("<samlp:Extensions>{assertion}</samlp:Extensions><samlp:Status>"), 1);
    let r = post_form(&app, "/sp/acs", &[("SAMLResponse", &b64_std(&wrapped))], &mut Jar::default()).await;
    assert_eq!(r.title(), "Test SP: rejected · localsaml");
    assert!(r.body.contains("more than one element has ID"), "{}", r.body);
    // The untouched response is accepted.
    let r =
        post_form(&app, "/sp/acs", &[("SAMLResponse", minted["saml_response"].as_str().unwrap())], &mut Jar::default())
            .await;
    assert_eq!(r.title(), "Test SP: signed in · localsaml");
}

#[tokio::test]
async fn requests_are_held_to_the_spec() {
    let (app, _) = app();
    let quick = |xml: &str| format!("{}&dev_attributes=%7B%7D", redirect("/sso", "SAMLRequest", xml, None, None));

    // A Destination that isn't where the request was sent: discarded with a Requester error.
    let xml = authn_request("_dst1", SP, Some(ACS), r#" Destination="http://elsewhere.test/sso""#, "");
    let p = posted(&get(&app, &quick(&xml)).await);
    assert_eq!((p.status().code.as_str(), p.action.as_str()), (saml::status::REQUESTER, ACS));
    let xml = authn_request("_dst2", SP, Some(ACS), &format!(r#" Destination="{BASE}/sso/""#), "");
    assert!(posted(&get(&app, &quick(&xml)).await).status().is_success());

    // A Subject in the request: signing in as someone else gets UnknownPrincipal and no
    // assertion (Profiles 4.1.4.1); signing in as that subject works.
    let mut jar = Jar::default();
    let subject = format!(
        r#"<saml:Subject><saml:NameID Format="{}">bob@example.com</saml:NameID></saml:Subject>"#,
        nameid::EMAIL
    );
    let xml = authn_request("_sub", SP, Some(ACS), "", &subject);
    let page = get_jar(&app, &redirect("/sso", "SAMLRequest", &xml, None, None), &mut jar).await;
    assert!(page.body.contains(r#""subject":{"format":"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress","nameId":"bob@example.com"}"#), "{}", page.body);
    let identity = json!({ "name_id": "someone-else", "name_id_format": nameid::UNSPECIFIED, "attributes": {} });
    let r = approve(&app, "", &page, "generic", identity, &mut jar).await;
    let p = posted(&r);
    assert_eq!(p.status().short(), "UnknownPrincipal");
    assert!(p.doc.find(A, "Assertion").is_none());
    let xml = authn_request("_sub2", SP, Some(ACS), "", &subject);
    let page = get_jar(&app, &redirect("/sso", "SAMLRequest", &xml, None, None), &mut jar).await;
    let identity = json!({ "name_id": "bob@example.com", "name_id_format": nameid::EMAIL, "attributes": {} });
    let r = approve(&app, "", &page, "generic", identity, &mut jar).await;
    assert_eq!(posted(&r).name_id(), ("bob@example.com".to_string(), nameid::EMAIL.to_string()));
    // The HTTP-POST binding form's method is literally POST (Bindings 3.5.4).
    assert!(r.body.contains(r#"<form method="POST""#));

    // A login form posted to another issuer than the one that started it is refused.
    let page =
        get_jar(&app, &redirect("/p/okta/sso", "SAMLRequest", &simple_request("_t1"), None, None), &mut jar).await;
    let r = approve(&app, "", &page, "okta", json!({}), &mut jar).await;
    assert_eq!((r.status, r.title()), (StatusCode::OK, "Wrong identity provider · localsaml".to_string()));

    // The mint API's NameID follows the given attributes when the defaults are dropped.
    let minted = post_json(
        &app,
        "/dev/api/response",
        json!({ "defaults": false, "attributes": { "email": "bob@example.com" } }),
    );
    assert_eq!(minted.await.json()["name_id"], "bob@example.com");
}

#[tokio::test]
async fn auto_login_answers_passive_requests() {
    let (app, _) = app_with(Config { auto_login: true, ..with_sps(vec![]) });
    let xml = authn_request("_pa", SP, Some(ACS), r#" IsPassive="true""#, "");
    assert!(posted(&get(&app, &redirect("/sso", "SAMLRequest", &xml, None, None)).await).status().is_success());
}

// ---------------------------------------------------------------------------
// Template details
// ---------------------------------------------------------------------------

fn session_index(p: &Posted) -> String {
    p.assertion().find(A, "AuthnStatement").unwrap().get_attr("SessionIndex").unwrap().to_string()
}

#[tokio::test]
async fn templates_shape_sessions_attributes_and_ids() {
    let (app, _) = app_with(with_sps(vec![ServiceProvider {
        idp_initiated_name: Some("my-app".into()),
        ..sp("http://kc.test/sp", "http://kc.test/acs")
    }]));
    let quick = |prefix: &str, id: &str| {
        format!(
            "{}&dev_attributes=%7B%7D",
            redirect(&format!("{prefix}/sso"), "SAMLRequest", &simple_request(id), None, None)
        )
    };

    // Keycloak: one Attribute per role, the confirmation outlives the 60 s Conditions, and the
    // SessionIndex is the assertion's ID.
    let p = posted(&get(&app, &quick("/p/keycloak", "_kc1")).await);
    let roles: Vec<&Element> = p
        .assertion()
        .find(A, "AttributeStatement")
        .unwrap()
        .find_all(A, "Attribute")
        .filter(|a| a.get_attr("Name") == Some("Role"))
        .collect();
    assert!(roles.len() > 1 && roles.iter().all(|r| r.find_all(A, "AttributeValue").count() == 1));
    let time = |el: &Element, attr: &str| parse_iso8601(el.get_attr(attr).unwrap()).unwrap();
    let conditions = p.assertion().find(A, "Conditions").unwrap();
    let confirmation =
        p.assertion().path(&[(A, "Subject"), (A, "SubjectConfirmation"), (A, "SubjectConfirmationData")]).unwrap();
    assert_eq!(time(confirmation, "NotOnOrAfter") - time(conditions, "NotOnOrAfter"), 240);
    assert_eq!(session_index(&p), p.assertion().get_attr("ID").unwrap());

    // Okta: the SessionIndex is the AuthnRequest's ID.
    assert_eq!(session_index(&posted(&get(&app, &quick("/p/okta", "_okta1")).await)), "_okta1");
    // OneLogin: assertion IDs differ from the Response's.
    let p = posted(&get(&app, &quick("/p/onelogin", "_ol1")).await);
    assert!(p.id().starts_with("pfx") && p.assertion().get_attr("ID").unwrap().starts_with('A'));
    // Auth0: boolean claims are typed as such.
    let p = posted(&get(&app, &quick("/p/auth0", "_a01")).await);
    let verified = p
        .assertion()
        .find(A, "AttributeStatement")
        .unwrap()
        .find_all(A, "Attribute")
        .find(|a| a.get_attr("Name") == Some("http://schemas.auth0.com/email_verified"))
        .unwrap()
        .find(A, "AttributeValue")
        .unwrap();
    assert_eq!(verified.get_ns_attr(saml::NS_XSI, "type"), Some("xs:boolean"));

    // Keycloak's IdP-initiated URL names the client in the path.
    let r = get(&app, "/p/keycloak/realms/example/protocol/saml/clients/my-app?dev_attributes=%7B%7D").await;
    let p = posted(&r);
    assert_eq!((p.action.as_str(), p.doc.get_attr("InResponseTo")), ("http://kc.test/acs", None));
    let r = get(&app, "/p/keycloak/realms/example/protocol/saml/clients/nope").await;
    assert_eq!(r.headers["x-localsaml-error"], "Unknown client");
}

#[tokio::test]
async fn dsa_signed_requests_are_verified() {
    use localsaml::dsig::urlencode;
    use rsa::signature::DigestSigner;
    use sha1::Digest;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::der::{Encode, EncodePem};
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    // A DSA key, in a certificate (issued by an RSA key: only the subject key matters here).
    #[allow(deprecated)]
    let components = dsa::Components::generate(&mut rand::thread_rng(), dsa::KeySize::DSA_1024_160);
    let dsa_key = dsa::SigningKey::generate(&mut rand::thread_rng(), components);
    let spki = SubjectPublicKeyInfoOwned::from_key(dsa_key.verifying_key().clone()).unwrap();
    let issuer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(sp_key().private.clone());
    let validity = x509_cert::time::Validity::from_now(std::time::Duration::from_secs(3600)).unwrap();
    let name: x509_cert::name::Name = "CN=dsa-sp".parse().unwrap();
    let serial = x509_cert::serial_number::SerialNumber::from(7u32);
    let cert = CertificateBuilder::new(Profile::Root, serial, validity, name, spki, &issuer)
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();
    assert!(cert.to_der().is_ok());
    let declared = ServiceProvider {
        certificate: Some(cert.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap()),
        want_authn_requests_signed: true,
        ..sp("http://dsa.test/sp", "http://dsa.test/acs")
    };
    let (app, _) = app_with(with_sps(vec![declared]));

    let sign = |xml: &str| {
        let alg = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
        let signed = format!("SAMLRequest={}&SigAlg={}", urlencode(&saml::deflate_b64(xml)), urlencode(alg));
        let sig: dsa::Signature = dsa_key.sign_digest(sha1::Sha1::new_with_prefix(signed.as_bytes()));
        let pad = |b: Vec<u8>| [vec![0; 20 - b.len()], b].concat();
        let raw = [pad(sig.r().to_bytes_be()), pad(sig.s().to_bytes_be())].concat();
        format!("/sso?{signed}&Signature={}", urlencode(&b64_std(&raw)))
    };
    let r = get(&app, &sign(&authn_request("_dsa1", "http://dsa.test/sp", Some("http://dsa.test/acs"), "", ""))).await;
    assert!(r.field("req").is_some(), "{}", r.title());
    assert!(r.body.contains("Redirect binding signature (dsa-sha1), verified"));
    // Changing the request after signing breaks it.
    let tampered = sign(&authn_request("_dsa2", "http://dsa.test/sp", Some("http://dsa.test/acs"), "", ""))
        .replace("SAMLRequest=", "SAMLRequest=x");
    assert_ne!(get(&app, &tampered).await.headers.get("x-localsaml-error"), None);
}

#[tokio::test]
async fn onelogin_sends_every_parameter() {
    let (app, _) = app();
    // Drop a parameter: OneLogin still sends it, empty.
    let r = post_json(&app, "/p/onelogin/dev/api/response", json!({ "attributes": { "memberOf": null } })).await.json();
    let doc = parse(r["xml"].as_str().unwrap()).unwrap();
    assert_eq!(attr_values(doc.find(A, "Assertion").unwrap(), "memberOf"), [""]);
}

#[tokio::test]
async fn logout_messages_can_be_required_signed() {
    let strict = |name: &str| ServiceProvider {
        certificate: Some(sp_key().cert_b64()),
        want_logout_signed: true,
        ..slo_sp(name)
    };
    let (app, _) = app_with(with_sps(vec![strict("a"), strict("b")]));
    let mut jar = Jar::default();
    let a = quick_login(&app, "", "http://a.test/sp", &mut jar, "").await;
    quick_login(&app, "", "http://b.test/sp", &mut jar, "").await;
    let request = logout_request("_ls1", "http://a.test/sp", &a.name_id().0);

    // Unsigned: refused with RequestDenied (Profiles 4.4.4.1, Bindings 3.4.6), and the session
    // stays.
    let r = get_jar(&app, &redirect("/slo", "SAMLRequest", &request, None, None), &mut jar).await;
    let (_, refused) = redirected(&r, "SAMLResponse");
    let status = Status::from_element(refused.find(P, "Status"));
    assert_eq!(status.short(), "RequestDenied");
    assert!(status.message.unwrap().starts_with("Unsigned LogoutRequest"));
    assert_eq!(get(&app, "/dev/api/sessions").await.json().as_array().unwrap().len(), 1);

    // Signed: B is asked, but its unsigned answer doesn't count, so A hears PartialLogout.
    let r = get_jar(&app, &redirect("/slo", "SAMLRequest", &request, None, Some(sp_key())), &mut jar).await;
    let (loc, to_b) = redirected(&r, "SAMLRequest");
    let answer = logout_response("_lr2", "http://b.test/sp", to_b.get_attr("ID").unwrap());
    let r =
        get(&app, &redirect("/slo", "SAMLResponse", &answer, query_param(&loc, "RelayState").as_deref(), None)).await;
    let (_, to_a) = redirected(&r, "SAMLResponse");
    let status = Status::from_element(to_a.find(P, "Status"));
    assert_eq!(status.short(), "PartialLogout");

    // Lenient mode takes unsigned logout messages, unless the SP sets want_logout_signed.
    let lax = ServiceProvider { want_logout_signed: false, ..strict("c") };
    let (app, _) = app_with(Config { lenient: true, ..with_sps(vec![lax, strict("d")]) });
    for (sp, ok) in [("c", true), ("d", false)] {
        let mut jar = Jar::default();
        let p = quick_login(&app, "", &format!("http://{sp}.test/sp"), &mut jar, "").await;
        let request = logout_request("_lx", &format!("http://{sp}.test/sp"), &p.name_id().0);
        let r = get_jar(&app, &redirect("/slo", "SAMLRequest", &request, None, None), &mut jar).await;
        let (_, answer) = redirected(&r, "SAMLResponse");
        assert_eq!(Status::from_element(answer.find(P, "Status")).is_success(), ok, "{sp}");
    }
}

// ---------------------------------------------------------------------------
// Back-channel (SOAP) logout
// ---------------------------------------------------------------------------

/// A service provider with a SOAP SingleLogoutService on a real port: it records each
/// LogoutRequest it gets and answers Success (or `status`).
async fn soap_sp(name: &str, status: &'static str) -> (ServiceProvider, Arc<std::sync::Mutex<Vec<Element>>>) {
    use axum::routing::post;
    let received: Arc<std::sync::Mutex<Vec<Element>>> = Arc::default();
    let log = received.clone();
    let entity = format!("http://{name}.test/sp");
    let issuer = entity.clone();
    let app = Router::new().route(
        "/soap",
        post(move |body: String| {
            let log = log.clone();
            let issuer = issuer.clone();
            async move {
                let (envelope, message) = localsaml::soap::unwrap(&body).unwrap();
                log.lock().unwrap().push(envelope);
                let id = message.get_attr("ID").unwrap().to_string();
                let style = &localsaml::presets::generic().style;
                let st = Status::parse(status, None).unwrap();
                let (mut resp, rid) = saml::logout_response_to(style, &issuer, None, Some(&id), &st, wall_clock());
                // The responder authenticates itself by signing (Profiles 4.4.4.2).
                saml::sign_message(&mut resp, &rid, sp_key(), style, SigAlg::RsaSha256).unwrap();
                ([(header::CONTENT_TYPE, "text/xml")], localsaml::soap::envelope(resp))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/soap", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let sp = ServiceProvider {
        entity_id: entity,
        acs_urls: vec![format!("http://{name}.test/acs")],
        slo_soap_url: Some(url),
        certificate: Some(sp_key().cert_b64()),
        ..Default::default()
    };
    (sp, received)
}

#[tokio::test]
async fn back_channel_logout_over_soap() {
    let (one, one_got) = soap_sp("one", "Success").await;
    let (two, two_got) = soap_sp("two", "Success").await;
    let (app, state) = app_with(with_sps(vec![one, two, slo_sp("front")]));
    let sid = |app: Router| async move {
        get(&app, "/dev/api/sessions").await.json()[0]["sid"].as_str().unwrap().to_string()
    };

    // Ending a session over the API logs the SOAP service providers out back-channel.
    let mut jar = Jar::default();
    let p = quick_login(&app, "", "http://one.test/sp", &mut jar, "").await;
    let r = delete(&app, &format!("/dev/api/sessions/{}", sid(app.clone()).await)).await.json();
    assert_eq!(r["deliveries"][0]["sp"], "http://one.test/sp");
    assert_eq!(r["deliveries"][0]["ok"], true, "{r}");
    let envelope = one_got.lock().unwrap().pop().expect("a LogoutRequest");
    let (_, request) =
        (envelope.clone(), envelope.find(localsaml::soap::NS_SOAP, "Body").unwrap().elements().next().unwrap().clone());
    assert_eq!(request.find(A, "NameID").unwrap().value(), p.name_id().0);
    dsig::verify(&envelope, request.get_attr("ID").unwrap(), &state.keys.public_keys()).unwrap();
    // The inspector shows the call localsaml made.
    let entries = get(&app, "/dev/api/requests").await.json();
    assert!(
        entries["entries"].as_array().unwrap().iter().any(|e| e["outgoing"] == true && e["sp"] == "http://one.test/sp")
    );

    // A front-channel logout reaches an SP with only a SOAP endpoint back-channel.
    let mut jar = Jar::default();
    let front = quick_login(&app, "", "http://front.test/sp", &mut jar, "").await;
    quick_login(&app, "", "http://one.test/sp", &mut jar, "").await;
    let r = get_jar(
        &app,
        &redirect(
            "/slo",
            "SAMLRequest",
            &logout_request("_bc1", "http://front.test/sp", &front.name_id().0),
            None,
            Some(sp_key()),
        ),
        &mut jar,
    )
    .await;
    let (_, to_front) = redirected(&r, "SAMLResponse");
    assert!(Status::from_element(to_front.find(P, "Status")).is_success());
    assert_eq!(one_got.lock().unwrap().len(), 1);

    // A SOAP LogoutRequest from one SP ends the session and logs the others out back-channel.
    let mut jar = Jar::default();
    let p = quick_login(&app, "", "http://one.test/sp", &mut jar, "").await;
    quick_login(&app, "", "http://two.test/sp", &mut jar, "").await;
    let request =
        parse(&signed_xml(&logout_request("_bc2", "http://one.test/sp", &p.name_id().0), "_bc2", sp_key())).unwrap();
    let r = post_body(&app, Method::POST, "/slo", "text/xml", &localsaml::soap::envelope(request)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let (envelope, answer) = localsaml::soap::unwrap(&r.body).unwrap();
    assert!(answer.is(P, "LogoutResponse") && answer.get_attr("InResponseTo") == Some("_bc2"));
    assert!(Status::from_element(answer.find(P, "Status")).is_success());
    dsig::verify(&envelope, answer.get_attr("ID").unwrap(), &state.keys.public_keys()).unwrap();
    assert_eq!(two_got.lock().unwrap().len(), 1);
    assert!(get(&app, "/dev/api/sessions").await.json().as_array().unwrap().is_empty());

    // A failing SP makes it a partial logout.
    let (bad, _) = soap_sp("bad", "Responder").await;
    let (app, _) = app_with(with_sps(vec![bad, slo_sp("front")]));
    let mut jar = Jar::default();
    let front = quick_login(&app, "", "http://front.test/sp", &mut jar, "").await;
    quick_login(&app, "", "http://bad.test/sp", &mut jar, "").await;
    let r = get_jar(
        &app,
        &redirect(
            "/slo",
            "SAMLRequest",
            &logout_request("_bc3", "http://front.test/sp", &front.name_id().0),
            None,
            Some(sp_key()),
        ),
        &mut jar,
    )
    .await;
    let (_, to_front) = redirected(&r, "SAMLResponse");
    assert_eq!(Status::from_element(to_front.find(P, "Status")).short(), "PartialLogout");
}

// ---------------------------------------------------------------------------
// HTTP-Artifact
// ---------------------------------------------------------------------------

/// Resolve an artifact at the ArtifactResolutionService as `issuer`, signed with the SPs' key:
/// the ArtifactResponse and the Response it carried, if any.
async fn resolve(app: &Router, state: &AppState, issuer: &str, artifact: &str) -> (Element, Option<Element>) {
    let (mut request, id) = saml::artifact_resolve(issuer, &format!("{BASE}/artifact"), artifact, wall_clock());
    saml::sign_message(&mut request, &id, sp_key(), &localsaml::presets::generic().style, SigAlg::RsaSha256).unwrap();
    resolve_message(app, state, request, &id).await
}

async fn resolve_message(app: &Router, state: &AppState, request: Element, id: &str) -> (Element, Option<Element>) {
    let r = post_body(app, Method::POST, "/artifact", "text/xml", &localsaml::soap::envelope(request)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let (_, answer) = localsaml::soap::unwrap(&r.body).unwrap();
    assert!(answer.is(P, "ArtifactResponse"), "{}", r.body);
    assert_eq!(answer.get_attr("InResponseTo"), Some(id));
    assert!(Status::from_element(answer.find(P, "Status")).is_success());
    verify(state, &answer, answer.get_attr("ID").unwrap());
    let inner = answer.find(P, "Response").cloned();
    (answer, inner)
}

#[tokio::test]
async fn artifact_binding() {
    let art_sp = ServiceProvider {
        entity_id: "http://art.test/sp".into(),
        acs_artifact_urls: vec!["http://art.test/acs".into()],
        certificate: Some(sp_key().cert_b64()),
        ..Default::default()
    };
    let (app, state) = app_with(with_sps(vec![art_sp]));

    let md = parse(&get(&app, "/metadata").await.body).unwrap();
    let ars = md.path(&[(saml::NS_MD, "IDPSSODescriptor"), (saml::NS_MD, "ArtifactResolutionService")]).unwrap();
    assert_eq!(ars.get_attr("Location"), Some(format!("{BASE}/artifact").as_str()));

    // ProtocolBinding HTTP-Artifact: the browser is redirected with an artifact, not a Response.
    let mut jar = Jar::default();
    let xml = authn_request("_art1", SP, Some(ACS), &format!(r#" ProtocolBinding="{}""#, saml::BINDING_ARTIFACT), "");
    let page = get_jar(&app, &redirect("/sso", "SAMLRequest", &xml, Some("/home"), None), &mut jar).await;
    let resp =
        approve(&app, "", &page, "generic", json!({ "attributes": { "email": "a@example.com" } }), &mut jar).await;
    assert_eq!(resp.status, StatusCode::SEE_OTHER, "{}", resp.body);
    let loc = resp.location();
    assert_eq!(format!("{}://{}{}", loc.scheme(), loc.host_str().unwrap(), loc.path()), ACS);
    assert_eq!(query_param(&loc, "RelayState").as_deref(), Some("/home"));
    let artifact = query_param(&loc, "SAMLart").unwrap();
    assert_eq!(b64_std_decode_lenient(&artifact).unwrap().len(), 44);

    // Without TLS, the assertion is encrypted for the SP (Profiles 4.1.4.4 wants the resolution
    // confidential). An unsigned resolution isn't authenticated (Bindings 3.6.5.2): no message,
    // and the artifact isn't used up.
    let (unsigned, uid) = saml::artifact_resolve(SP, &format!("{BASE}/artifact"), &artifact, wall_clock());
    assert!(resolve_message(&app, &state, unsigned, &uid).await.1.is_none());
    // Only the SP it was issued for can resolve it, and only once.
    let (_, none) = resolve(&app, &state, "http://art.test/sp", &artifact).await;
    assert!(none.is_none());
    let (answer, response) = resolve(&app, &state, SP, &artifact).await;
    let response = response.expect("the Response");
    assert_eq!(response.get_attr("InResponseTo"), Some("_art1"));
    assert!(response.find(A, "EncryptedAssertion").is_some());
    verify(&state, &answer, response.get_attr("ID").unwrap());
    assert!(resolve(&app, &state, SP, &artifact).await.1.is_none());
    // Garbage and front-channel resolution are refused.
    assert!(resolve(&app, &state, SP, "AAQAAA==").await.1.is_none());
    let (request, _) = saml::artifact_resolve(SP, "x", &artifact, wall_clock());
    let r = get(&app, &redirect("/sso", "SAMLRequest", &request.to_xml(), None, None)).await;
    assert_eq!(r.headers["x-localsaml-error"], "ArtifactResolve over the wrong binding");

    // An SP whose only (or default) ACS is HTTP-Artifact gets artifacts for IdP-initiated logins.
    let r = get_jar(&app, "/sso/initiate?sp=http%3A%2F%2Fart.test%2Fsp&dev_attributes=%7B%7D", &mut jar).await;
    let loc = r.location();
    assert!(loc.as_str().starts_with("http://art.test/acs?SAMLart="), "{loc}");
    let (_, response) = resolve(&app, &state, "http://art.test/sp", &query_param(&loc, "SAMLart").unwrap()).await;
    assert!(response.unwrap().get_attr("InResponseTo").is_none());

    // The response API can mint artifacts too.
    let minted = post_json(&app, "/dev/api/response", json!({ "sp": SP, "binding": "artifact" })).await.json();
    let artifact = minted["artifact"]["artifact"].as_str().unwrap();
    assert!(minted["artifact"]["url"].as_str().unwrap().starts_with(&format!("{ACS}?SAMLart=")));
    let (_, response) = resolve(&app, &state, SP, artifact).await;
    assert_eq!(response.unwrap().get_attr("ID"), minted["response_id"].as_str());
}

#[tokio::test]
async fn the_test_sp_resolves_artifacts() {
    let (app, _) = app();
    let mut jar = Jar::default();
    let r = get_jar(&app, "/sp/login?binding=redirect&response_binding=artifact&RelayState=%2Fx", &mut jar).await;
    let loc = r.location();
    let path_and_query = &loc.as_str()[BASE.len()..];
    let page = get_jar(&app, path_and_query, &mut jar).await;
    let resp =
        approve(&app, "", &page, "generic", json!({ "attributes": { "email": "a@example.com" } }), &mut jar).await;
    let loc = resp.location();
    assert!(loc.as_str().starts_with(&format!("{BASE}/sp/acs?SAMLart=")), "{loc}");
    let accepted = get_jar(&app, &loc.as_str()[BASE.len()..], &mut jar).await;
    assert_eq!(accepted.title(), "Test SP: signed in · localsaml", "{}", accepted.body);
    assert!(accepted.body.contains("ArtifactResponse signature"));
    // A second use of the artifact is refused.
    let again = get_jar(&app, &loc.as_str()[BASE.len()..], &mut jar).await;
    assert_eq!(again.title(), "Test SP: rejected · localsaml");
}

// ---------------------------------------------------------------------------
// Encrypted NameIDs
// ---------------------------------------------------------------------------

fn sp_keys() -> &'static [rsa::RsaPrivateKey] {
    std::slice::from_ref(&sp_key().private)
}

/// The NameID in an assertion's (or LogoutRequest's) EncryptedID.
fn decrypted_name_id(container: &Element, keys: &[rsa::RsaPrivateKey]) -> Element {
    let encrypted = container
        .find(A, "Subject")
        .unwrap_or(container)
        .find(A, "EncryptedID")
        .unwrap_or_else(|| panic!("no EncryptedID in {}", container.to_pretty()));
    saml::decrypt_id(encrypted, keys).unwrap()
}

#[tokio::test]
async fn encrypted_name_ids() {
    let secret = ServiceProvider { encrypt_name_id: true, certificate: Some(sp_key().cert_b64()), ..slo_sp("secret") };
    let (app, state) = app_with(with_sps(vec![secret, sp(SP, ACS)]));

    // A service provider with encrypt_name_id gets an EncryptedID, for its own key, and its
    // LogoutRequest carries one too.
    let mut jar = Jar::default();
    let p = quick_login(&app, "", "http://secret.test/sp", &mut jar, "&dev_name_id=jo%40example.com").await;
    verify(&state, &p.doc, &p.id());
    let assertion = p.assertion();
    assert!(assertion.path(&[(A, "Subject"), (A, "NameID")]).is_none());
    let name_id = decrypted_name_id(assertion, sp_keys());
    assert_eq!(name_id.value(), "jo@example.com");
    let r = get_jar(&app, "/slo/initiate", &mut jar).await;
    let (_, request) = redirected(&r, "SAMLRequest");
    assert!(request.find(A, "NameID").is_none());
    assert_eq!(decrypted_name_id(&request, sp_keys()).value(), "jo@example.com");

    // An AuthnRequest asking for an encrypted NameID needs an encryption certificate.
    let policy = format!(r#"<samlp:NameIDPolicy Format="{}"/>"#, nameid::ENCRYPTED);
    let xml = authn_request("_enc1", SP, Some(ACS), "", &policy);
    let r = get_jar(
        &app,
        &format!("{}&dev_attributes=%7B%7D", redirect("/sso", "SAMLRequest", &xml, None, None)),
        &mut jar,
    )
    .await;
    let p = posted(&r);
    assert_eq!(p.status().short(), "InvalidNameIDPolicy");

    // The test SP asks for one (it has the IdP's key), decrypts it, and encrypts the NameID in
    // its own LogoutRequest, which localsaml decrypts.
    let mut jar = Jar::default();
    let r = get_jar(&app, "/sp/login?binding=redirect&encrypt_name_id=1&name_id_format=ignored", &mut jar).await;
    let page = get_jar(&app, &r.location().as_str()[BASE.len()..], &mut jar).await;
    assert!(page.body.contains("Sign in"), "{}", page.title());
    let resp =
        approve(&app, "", &page, "generic", json!({ "attributes": { "email": "kim@example.com" } }), &mut jar).await;
    let p = posted(&resp);
    let name_id = decrypted_name_id(p.assertion(), &state.keys.private_keys());
    assert_eq!(name_id.get_attr("Format"), Some(nameid::EMAIL));
    let b64 = resp.field("SAMLResponse").unwrap();
    let accepted = post_form(&app, "/sp/acs", &[("SAMLResponse", &b64)], &mut jar).await;
    assert_eq!(accepted.title(), "Test SP: signed in · localsaml", "{}", accepted.body);
    assert!(accepted.body.contains("kim@example.com"));
    let r = post_form(&app, "/sp/logout", &[], &mut jar).await;
    let (loc, request) = redirected(&r, "SAMLRequest");
    assert!(request.find(A, "EncryptedID").is_some());
    let r = get_jar(&app, &loc.as_str()[BASE.len()..], &mut jar).await;
    let (_, answer) = redirected(&r, "SAMLResponse");
    assert!(Status::from_element(answer.find(P, "Status")).is_success(), "{}", answer.to_pretty());
    assert!(get(&app, "/dev/api/sessions").await.json().as_array().unwrap().is_empty());

    // The response API, with and without the service provider's setting.
    let minted = post_json(&app, "/dev/api/response", json!({ "sp": SP, "encrypt_name_id": true })).await;
    assert_eq!(minted.status, StatusCode::BAD_REQUEST, "no certificate for {SP}");
    let minted = post_json(&app, "/dev/api/response", json!({ "sp": "http://secret.test/sp" })).await.json();
    assert_eq!(minted["name_id_encrypted"], true);
    let doc = parse(minted["xml"].as_str().unwrap()).unwrap();
    decrypted_name_id(doc.find(A, "Assertion").unwrap(), sp_keys());
    let minted =
        post_json(&app, "/dev/api/response", json!({ "sp": "http://secret.test/sp", "encrypt_name_id": false }))
            .await
            .json();
    assert_eq!(minted["name_id_encrypted"], false);
}

// ---------------------------------------------------------------------------
// Attribute queries
// ---------------------------------------------------------------------------

/// Send an AttributeQuery over SOAP; the Response that answers it.
async fn query(app: &Router, query: Element) -> Element {
    let r = post_body(app, Method::POST, "/attribute", "text/xml", &localsaml::soap::envelope(query)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // Not cached (Bindings 3.2.3.2).
    assert_eq!(r.headers.get(header::CACHE_CONTROL).unwrap(), "no-cache, no-store, must-revalidate, private");
    let (_, response) = localsaml::soap::unwrap(&r.body).unwrap();
    assert!(response.is(P, "Response"), "{}", r.body);
    response
}

#[tokio::test]
async fn attribute_queries() {
    let aq =
        ServiceProvider { certificate: Some(sp_key().cert_b64()), ..sp("http://aq.test/sp", "http://aq.test/acs") };
    let config = Config { users: vec![alice()], ..with_sps(vec![aq]) };
    let (app, state) = app_with(config);
    let md = parse(&get(&app, "/metadata").await.body).unwrap();
    let service = md.path(&[(saml::NS_MD, "AttributeAuthorityDescriptor"), (saml::NS_MD, "AttributeService")]).unwrap();
    assert_eq!(service.get_attr("Location"), Some(format!("{BASE}/attribute").as_str()));

    // A subject from a session: the attributes it was given, about the NameID asked for.
    let mut jar = Jar::default();
    let attrs = enc(r#"{"email":"sam@example.com","groups":["a","b","c"]}"#);
    let uri =
        format!("/sso/initiate?sp={}&dev_name_id=sam%40example.com&dev_attributes={attrs}", enc("http://aq.test/sp"));
    let p = posted(&get_jar(&app, &uri, &mut jar).await);
    let (name_id, format) = p.name_id();
    let email = p.attribute("email");
    assert!(!email.is_empty());
    let signed = |q: (Element, String)| {
        let (mut el, id) = q;
        saml::sign_message(&mut el, &id, sp_key(), &localsaml::presets::generic().style, SigAlg::RsaSha256).unwrap();
        (el, id)
    };
    let (q, id) = signed(saml::attribute_query(
        "http://aq.test/sp",
        &format!("{BASE}/attribute"),
        &name_id,
        &format,
        &[],
        wall_clock(),
    ));
    let response = query(&app, q).await;
    assert_eq!(response.get_attr("InResponseTo"), Some(id.as_str()));
    assert!(response.get_attr("Destination").is_none());
    // The Response is signed (Profiles 6.4.2), as well as the assertion.
    verify(&state, &response, response.get_attr("ID").unwrap());
    assert!(Status::from_element(response.find(P, "Status")).is_success());
    let assertion = response.find(A, "Assertion").unwrap();
    verify(&state, &response, assertion.get_attr("ID").unwrap());
    assert_eq!(assertion.path(&[(A, "Subject"), (A, "NameID")]).unwrap().value(), name_id);
    let confirmation = assertion.path(&[(A, "Subject"), (A, "SubjectConfirmation")]).unwrap();
    assert_eq!(confirmation.get_attr("Method"), Some(saml::CM_SENDER_VOUCHES));
    assert!(assertion.find(A, "AuthnStatement").is_none());
    assert_eq!(attr_values(assertion, "email"), email);
    assert_eq!(attr_values(assertion, "groups"), ["a", "b", "c"]);

    // Only the attributes (and values) asked for.
    let (mut q, _) =
        saml::attribute_query("http://aq.test/sp", "x", &name_id, &format, &["email", "groups"], wall_clock());
    let groups = p.attribute("groups");
    q.elements_mut()
        .find(|e| e.get_attr("Name") == Some("groups"))
        .unwrap()
        .children
        .push(localsaml::xml::Node::Element(Element::new(A, "saml", "AttributeValue").text(&groups[0])));
    q.declare_namespaces();
    let assertion = query(&app, q).await.find(A, "Assertion").unwrap().clone();
    let names: Vec<_> = assertion
        .find(A, "AttributeStatement")
        .unwrap()
        .find_all(A, "Attribute")
        .map(|a| a.get_attr("Name").unwrap().to_string())
        .collect();
    assert_eq!(names, ["email", "groups"]);
    assert_eq!(attr_values(&assertion, "groups"), [groups[0].clone()]);
    assert_eq!(groups.len(), 3);

    // An empty AttributeValue asks for the empty value (Core 3.3.2.3), which nobody has.
    let (mut q, _) = saml::attribute_query("http://aq.test/sp", "x", &name_id, &format, &["email"], wall_clock());
    q.elements_mut()
        .find(|e| e.get_attr("Name") == Some("email"))
        .unwrap()
        .children
        .push(localsaml::xml::Node::Element(Element::new(A, "saml", "AttributeValue")));
    q.declare_namespaces();
    let assertion = query(&app, q).await.find(A, "Assertion").unwrap().clone();
    assert!(assertion.find(A, "AttributeStatement").is_none(), "{}", assertion.to_pretty());

    // A declared user without a session.
    let (q, _) = saml::attribute_query("http://aq.test/sp", "x", "alice@acme.dev", nameid::EMAIL, &[], wall_clock());
    let assertion = query(&app, q).await.find(A, "Assertion").unwrap().clone();
    assert_eq!(attr_values(&assertion, "groups"), ["admins"]);

    // Nobody: UnknownPrincipal, in a signed Response.
    let (q, _) = saml::attribute_query("http://aq.test/sp", "x", "nobody", nameid::UNSPECIFIED, &[], wall_clock());
    let response = query(&app, q).await;
    assert_eq!(Status::from_element(response.find(P, "Status")).short(), "UnknownPrincipal");
    verify(&state, &response, response.get_attr("ID").unwrap());

    // A query signed by the wrong key is refused.
    let (mut q, id) = saml::attribute_query("http://aq.test/sp", "x", &name_id, &format, &[], wall_clock());
    state
        .keys
        .with_current(|k| saml::sign_message(&mut q, &id, k, &localsaml::presets::generic().style, SigAlg::RsaSha256))
        .unwrap();
    let r = post_body(&app, Method::POST, "/attribute", "text/xml", &localsaml::soap::envelope(q)).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(r.body.contains("invalid AttributeQuery signature"), "{}", r.body);

    // The test SP queries for its signed-in user.
    let mut sp_jar = Jar::default();
    let p = quick_login(&app, "", &format!("{BASE}/sp"), &mut sp_jar, "").await;
    let b64 = b64_std(p.doc.to_xml());
    assert_eq!(
        post_form(&app, "/sp/acs", &[("SAMLResponse", &b64)], &mut sp_jar).await.title(),
        "Test SP: signed in · localsaml"
    );
    let r = post_form(&app, "/sp/attributes", &[], &mut sp_jar).await;
    assert_eq!(r.title(), "Test SP: attributes · localsaml", "{}", r.body);
}

#[tokio::test]
async fn encrypted_attributes() {
    let secret =
        ServiceProvider { encrypt_attributes: true, certificate: Some(sp_key().cert_b64()), ..slo_sp("secret") };
    let (app, state) = app_with(with_sps(vec![secret]));
    let mut jar = Jar::default();
    let attrs = enc(r#"{"email":"jo@example.com","groups":["a","b"]}"#);
    let p = posted(
        &get_jar(&app, &format!("/sso/initiate?sp={}&dev_attributes={attrs}", enc("http://secret.test/sp")), &mut jar)
            .await,
    );
    verify(&state, &p.doc, &p.id());
    let statement = p.assertion().find(A, "AttributeStatement").unwrap();
    assert_eq!(statement.find_all(A, "Attribute").count(), 0);
    let decrypted: Vec<Element> = statement
        .find_all(A, "EncryptedAttribute")
        .map(|e| parse(&xmlenc::decrypt(e, sp_keys()).unwrap()).unwrap())
        .collect();
    let groups = decrypted.iter().find(|a| a.get_attr("Name") == Some("groups")).unwrap();
    let values: Vec<String> = groups.find_all(A, "AttributeValue").map(Element::text_content).collect();
    assert_eq!(values, ["a", "b"]);

    // The response API, and the test SP decrypting them.
    let minted = post_json(
        &app,
        "/dev/api/response",
        json!({ "encrypt_attributes": true, "attributes": { "email": "kim@example.com" } }),
    )
    .await
    .json();
    assert_eq!(minted["attributes_encrypted"], true);
    let mut sp_jar = Jar::default();
    let accepted =
        post_form(&app, "/sp/acs", &[("SAMLResponse", minted["saml_response"].as_str().unwrap())], &mut sp_jar).await;
    assert_eq!(accepted.title(), "Test SP: signed in · localsaml", "{}", accepted.body);
    assert!(accepted.body.contains("kim@example.com"));
    assert!(accepted.body.contains("<b>EncryptedAttribute</b> <span>decrypted "), "{}", accepted.body);
}

#[tokio::test]
async fn scoping() {
    let (app, _) = app();
    let scoping = |idps: &[&str]| {
        let entries: String = idps.iter().map(|i| format!(r#"<samlp:IDPEntry ProviderID="{i}"/>"#)).collect();
        format!(
            r#"<samlp:Scoping ProxyCount="1"><samlp:IDPList>{entries}</samlp:IDPList><samlp:RequesterID>https://portal.test</samlp:RequesterID></samlp:Scoping>"#
        )
    };
    // An IDPList without localsaml: it doesn't proxy, so NoSupportedIDP.
    let xml = authn_request("_sc1", SP, Some(ACS), "", &scoping(&["https://other-idp.test"]));
    let p = posted(&get(&app, &redirect("/sso", "SAMLRequest", &xml, None, None)).await);
    assert_eq!(p.status().short(), "NoSupportedIDP");
    assert_eq!(p.doc.get_attr("InResponseTo"), Some("_sc1"));
    // With localsaml in the list, the login goes ahead, and the RequesterID is shown.
    let xml =
        authn_request("_sc2", SP, Some(ACS), "", &scoping(&["https://other-idp.test", &format!("{BASE}/metadata")]));
    let page = get(&app, &redirect("/sso", "SAMLRequest", &xml, None, None)).await;
    assert_eq!(page.title(), "Sign in · localsaml");
    assert!(page.body.contains("RequesterID https://portal.test"), "{}", page.body);
}

// ---------------------------------------------------------------------------
// ECP
// ---------------------------------------------------------------------------

async fn ecp(app: &Router, envelope: &str, login: Option<&str>) -> Resp {
    let mut req = Request::builder().method(Method::POST).uri("/sso").header(header::CONTENT_TYPE, "text/xml");
    if let Some(l) = login {
        req = req.header(header::AUTHORIZATION, format!("Basic {}", b64_std(format!("{l}:any-password"))));
    }
    send(app, req.body(Body::from(envelope.to_string())).unwrap(), None).await
}

#[tokio::test]
async fn ecp_logins() {
    let ecp_sp = ServiceProvider {
        acs_ecp_urls: vec!["http://ecp.test/ecp".into()],
        certificate: Some(sp_key().cert_b64()),
        ..sp("http://ecp.test/sp", "http://ecp.test/acs")
    };
    let (app, state) = app_with(Config { users: vec![alice()], ..with_sps(vec![ecp_sp]) });
    let paos = format!(r#" ProtocolBinding="{}""#, saml::BINDING_PAOS);
    let request = |id: &str, acs: &str, children: &str| {
        localsaml::soap::envelope(parse(&authn_request(id, "http://ecp.test/sp", Some(acs), &paos, children)).unwrap())
    };

    // No credentials: HTTP Basic is asked for.
    let r = ecp(&app, &request("_e1", "http://ecp.test/ecp", ""), None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.headers.get(header::WWW_AUTHENTICATE).is_some());

    // A declared user: the Response comes back in SOAP, with the ACS in an ecp:Response header.
    let r = ecp(&app, &request("_e2", "http://ecp.test/ecp", ""), Some("alice")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let envelope = parse(&r.body).unwrap();
    let ecp_header = envelope.path(&[(localsaml::soap::NS_SOAP, "Header"), (saml::NS_ECP, "Response")]).unwrap();
    assert_eq!(ecp_header.get_attr("AssertionConsumerServiceURL"), Some("http://ecp.test/ecp"));
    let (_, response) = localsaml::soap::unwrap(&r.body).unwrap();
    assert_eq!(response.get_attr("InResponseTo"), Some("_e2"));
    let assertion = response.find(A, "Assertion").unwrap();
    verify(&state, &response, assertion.get_attr("ID").unwrap());
    assert_eq!(attr_values(assertion, "groups"), ["admins"]);
    // The session it started can be ended like any other.
    assert_eq!(get(&app, "/dev/api/sessions").await.json().as_array().unwrap().len(), 1);

    // A signed request whose namespaces are declared on the Envelope (as some clients do) still
    // verifies: the message keeps the declarations it inherited.
    let signed = signed_xml(
        &authn_request("_e6", "http://ecp.test/sp", Some("http://ecp.test/ecp"), &paos, ""),
        "_e6",
        sp_key(),
    );
    let decls = format!(r#" xmlns:samlp="{P}" xmlns:saml="{A}""#);
    assert!(signed.contains(&decls), "{signed}");
    let hoisted = format!(
        r#"<S:Envelope xmlns:S="{}"{decls}><S:Body>{}</S:Body></S:Envelope>"#,
        localsaml::soap::NS_SOAP,
        signed.replacen(&decls, "", 1)
    );
    let r = ecp(&app, &hoisted, Some("alice")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // A tampered one doesn't: a RequestDenied Response, saying why (Bindings 3.4.6).
    let tampered = hoisted.replacen("<samlp:AuthnRequest ", r#"<samlp:AuthnRequest ProviderName="x" "#, 1);
    let r = ecp(&app, &tampered, Some("alice")).await;
    let (_, response) = localsaml::soap::unwrap(&r.body).unwrap();
    let status = Status::from_element(response.find(P, "Status"));
    assert_eq!(status.short(), "RequestDenied");
    assert!(status.message.unwrap().starts_with("Invalid AuthnRequest signature: "));

    // The Basic scheme is case-insensitive (RFC 7617).
    let lower = Request::builder()
        .method(Method::POST)
        .uri("/sso")
        .header(header::CONTENT_TYPE, "text/xml")
        .header(header::AUTHORIZATION, format!("basic {}", b64_std("alice:x")))
        .body(Body::from(request("_e7", "http://ecp.test/ecp", "")))
        .unwrap();
    assert_eq!(send(&app, lower, None).await.status, StatusCode::OK);

    // Any other login is taken as a login hint for the template's identity.
    let r = ecp(&app, &request("_e3", "http://ecp.test/ecp", &policy(nameid::EMAIL)), Some("sam@example.com")).await;
    let (_, response) = localsaml::soap::unwrap(&r.body).unwrap();
    assert_eq!(response.path(&[(A, "Assertion"), (A, "Subject"), (A, "NameID")]).unwrap().value(), "sam@example.com");

    // Errors the browser would see as a page are SOAP faults; error statuses stay Responses.
    let r = ecp(&app, &request("_e4", "http://evil.test/ecp", ""), Some("alice")).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(r.body.contains("Unregistered AssertionConsumerServiceURL"), "{}", r.body);
    let scoping = r#"<samlp:Scoping><samlp:IDPList><samlp:IDPEntry ProviderID="https://other.test"/></samlp:IDPList></samlp:Scoping>"#;
    let r = ecp(&app, &request("_e5", "http://ecp.test/ecp", scoping), Some("alice")).await;
    let (_, response) = localsaml::soap::unwrap(&r.body).unwrap();
    assert_eq!(Status::from_element(response.find(P, "Status")).short(), "NoSupportedIDP");
}

#[tokio::test]
async fn requested_authn_context_comparisons() {
    let (app, _) = app();
    let context = |comparison: &str, refs: &str| {
        format!(r#"<samlp:RequestedAuthnContext Comparison="{comparison}">{refs}</samlp:RequestedAuthnContext>"#)
    };
    let class = |c: &str| format!("<saml:AuthnContextClassRef>{c}</saml:AuthnContextClassRef>");
    let login = |xml: String| {
        let app = app.clone();
        async move {
            posted(
                &get(&app, &format!("{}&dev_attributes=%7B%7D", redirect("/sso", "SAMLRequest", &xml, None, None)))
                    .await,
            )
        }
    };
    let claimed = |p: &Posted| {
        p.assertion().path(&[(A, "AuthnStatement"), (A, "AuthnContext"), (A, "AuthnContextClassRef")]).unwrap().value()
    };
    // "better": stronger than every class asked for.
    let p = login(authn_request(
        "_ac1",
        SP,
        Some(ACS),
        "",
        &context("better", &class(localsaml::presets::authn::PASSWORD_PROTECTED)),
    ))
    .await;
    assert_eq!(claimed(&p), localsaml::presets::authn::KERBEROS);
    // Nothing is stronger than MFA, and declarations aren't supported: NoAuthnContext.
    let p = login(authn_request("_ac2", SP, Some(ACS), "", &context("better", &class(localsaml::presets::authn::MFA))))
        .await;
    assert_eq!(p.status().short(), "NoAuthnContext");
    let decl = "<saml:AuthnContextDeclRef>urn:decl</saml:AuthnContextDeclRef>";
    let p = login(authn_request("_ac3", SP, Some(ACS), "", &context("exact", decl))).await;
    assert_eq!(p.status().short(), "NoAuthnContext");
}

// ---------------------------------------------------------------------------
// Strict by default (the spec's MUSTs), and lenient mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn strict_by_default() {
    // An SP whose entity ID is its metadata URL, on a real port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let entity = format!("http://{}/metadata", listener.local_addr().unwrap());
    let md = format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://disc.test/acs" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>"#
    );
    let server = Router::new().route("/metadata", axum::routing::get(move || async move { md }));
    tokio::spawn(async move { axum::serve(listener, server).await.unwrap() });

    let no_acs = ServiceProvider { entity_id: "http://noacs.test/sp".into(), ..Default::default() };
    let unsigned = ServiceProvider {
        sign_response: Some(false),
        sign_assertion: Some(false),
        ..sp("http://unsigned.test/sp", "http://unsigned.test/acs")
    };
    let no_cert = ServiceProvider { certificate: None, ..slo_sp("nocert") };
    let (app, _) = app_with(with_sps(vec![no_acs, unsigned, no_cert]));
    let quick = |xml: &str| format!("{}&dev_attributes=%7B%7D", redirect("/sso", "SAMLRequest", xml, None, None));

    // Discovered from its metadata: its ACS is verified, and other URLs are refused.
    let p = posted(&get(&app, &quick(&authn_request("_d1", &entity, Some("http://disc.test/acs"), "", ""))).await);
    assert!(p.status().is_success());
    let r = get(&app, &quick(&authn_request("_d2", &entity, Some("http://evil.test/acs"), "", ""))).await;
    assert_eq!(r.headers["x-localsaml-error"], "Unregistered AssertionConsumerServiceURL");
    let list = get(&app, "/dev/api/service-providers").await.json();
    assert!(list.as_array().unwrap().iter().any(|s| s["entity_id"] == entity.as_str()));
    // Unknown, and nothing to discover.
    let r = get(&app, &quick(&authn_request("_d3", "urn:unknown", Some("http://x.test/acs"), "", ""))).await;
    assert_eq!(r.headers["x-localsaml-error"], "Unknown service provider");
    // Declared without ACS URLs: the request's can't be verified.
    let r = get(&app, &quick(&authn_request("_d4", "http://noacs.test/sp", Some("http://x.test/acs"), "", ""))).await;
    assert_eq!(r.headers["x-localsaml-error"], "Unregistered AssertionConsumerServiceURL");

    // RelayState over 80 bytes: a Requester error, without the RelayState (Bindings 3.4.3).
    let long = "r".repeat(81);
    let uri =
        format!("{}&dev_attributes=%7B%7D", redirect("/sso", "SAMLRequest", &simple_request("_r1"), Some(&long), None));
    let p = posted(&get(&app, &uri).await);
    assert_eq!((p.status().code.as_str(), p.relay.as_deref()), (saml::status::REQUESTER, None));

    // Nothing signed would leave a POSTed assertion unprotected (Profiles 4.1.3.5).
    let r = get(&app, "/sso/initiate?sp=http%3A%2F%2Funsigned.test%2Fsp&dev_attributes=%7B%7D").await;
    assert_eq!(r.headers["x-localsaml-error"], "Can't send the Response");

    // A signed LogoutRequest from an SP without a certificate can't be authenticated.
    let mut jar = Jar::default();
    let p = quick_login(&app, "", "http://nocert.test/sp", &mut jar, "").await;
    let request = logout_request("_l1", "http://nocert.test/sp", &p.name_id().0);
    let r = get_jar(&app, &redirect("/slo", "SAMLRequest", &request, None, Some(sp_key())), &mut jar).await;
    let (_, answer) = redirected(&r, "SAMLResponse");
    let status = Status::from_element(answer.find(P, "Status"));
    assert_eq!(status.short(), "RequestDenied");
    assert!(status.message.unwrap().starts_with("Unverifiable LogoutRequest signature"));

    // Lenient mode relaxes all of it.
    let (lenient, _) = app_with(Config { lenient: true, ..with_sps(vec![]) });
    let p =
        posted(&get(&lenient, &quick(&authn_request("_d5", "urn:unknown", Some("http://x.test/acs"), "", ""))).await);
    assert!(p.status().is_success());
    let uri =
        format!("{}&dev_attributes=%7B%7D", redirect("/sso", "SAMLRequest", &simple_request("_r2"), Some(&long), None));
    assert_eq!(posted(&get(&lenient, &uri).await).relay.as_deref(), Some(long.as_str()));
}

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};

use crate::html::{esc, page};
use crate::presets;
use crate::state::AppState;
use crate::tenant::Tenant;

// The assets are compiled in and can change with every upgrade, so browsers must not reuse a
// stale copy against newer HTML. They're small and served locally, so always revalidating is cheap.
pub async fn css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")],
        include_str!("../../assets/app.css"),
    )
}

pub async fn js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")],
        include_str!("../../assets/app.js"),
    )
}

pub async fn index(State(state): State<AppState>, tenant: Tenant) -> Response {
    let u = |p: &str| tenant.url(p);
    let mut endpoints = vec![
        ("Metadata", tenant.metadata_url()),
        ("Entity ID", tenant.entity_id.clone()),
        ("SSO (Redirect and POST bindings; SOAP for ECP)", tenant.sso_url()),
    ];
    if let Some(slo) = tenant.slo_url() {
        endpoints.push(("Single logout (Redirect, POST and SOAP bindings)", slo));
    }
    endpoints.push(("Artifact resolution (SOAP)", u("/artifact")));
    endpoints.push(("Attribute queries (SOAP)", u("/attribute")));
    endpoints.push(("IdP-initiated SSO (non-standard)", format!("{}?sp=<entity ID>", u("/sso/initiate"))));
    endpoints.push(("Signing certificate (PEM)", u("/certificate.pem")));
    endpoints.push(("Response API (non-standard)", u("/dev/api/response")));
    if let Some(p) = tenant.preset {
        for e in &p.endpoints {
            endpoints.push((e.label, u(e.path)));
        }
        if tenant.sso_url() != u("/sso") {
            endpoints.push(("SSO (generic path)", u("/sso")));
        }
    }
    let rows: String = endpoints
        .iter()
        .map(|(label, url)| format!("<tr><td>{}</td><td><code>{}</code></td></tr>", esc(label), esc(url)))
        .collect();

    let root = Tenant::new(&state.config.base_url, None, &state.config);
    let tenants: String = std::iter::once(format!(
        r#"<a class="tenant" href="{}/" style="--c:#64748b"><b>Root issuer</b><span>template chosen at login</span><code>{}</code></a>"#,
        root.prefix,
        esc(&root.entity_id)
    ))
    .chain(presets::all().iter().map(|p| {
        let t = Tenant::new(&state.config.base_url, Some(p), &state.config);
        format!(
            r#"<a class="tenant" href="{}/" style="--c:{}"><b>{}</b><span>{}</span><code>{}</code></a>"#,
            t.prefix,
            p.color,
            esc(p.name),
            esc(p.description),
            esc(&t.entity_id)
        )
    }))
    .collect();

    let cert = state.keys.current_info();
    let dev = esc(&u("/dev/api/response"));
    let accepted = if state.config.lenient {
        "Lenient mode: any service provider is accepted, with the ACS URL from its AuthnRequest."
    } else {
        "It answers the service providers it knows: declared in <code>localsaml.toml</code>, registered on the assertion generator page, or serving their metadata at their entity ID. (The SAML specification requires an identity provider to verify ACS URLs; <code>--lenient</code> accepts any.)"
    };
    let body = format!(
        r#"<section class="card hero">
  <div class="eyebrow">Local SAML identity provider</div>
  <h1>Entity ID <span class="accent">{entity}</span></h1>
  <p class="muted">Point your service provider at the metadata URL <code>{metadata}</code>. {accepted} Signing in shows an attribute editor instead of a password prompt.</p>
  <div class="actions"><a class="btn primary" href="{prefix}/sp">Try a login</a>
  <a class="btn ghost" href="{prefix}/dev">Open assertion generator</a></div>
</section>
<section class="card">
  <h2>Endpoints</h2>
  <table class="endpoints">{rows}</table>
</section>
<section class="card">
  <h2>Signing certificate</h2>
  <dl class="kv"><dt>SHA-1 fingerprint</dt><dd><code>{sha1}</code></dd><dt>SHA-256 fingerprint</dt><dd><code>{sha256}</code></dd><dt>Valid until</dt><dd>{not_after}</dd></dl>
  <p class="muted">The same key signs for every issuer. Download it as <a href="{prefix}/certificate.pem">PEM</a> for service providers that want the certificate rather than metadata.</p>
</section>
<section class="card">
  <h2>Quick start</h2>
  <pre class="code"># For a service provider localsaml knows (declared, registered or discovered):
curl -s '{dev}?sp=http://localhost:3000/saml/metadata&amp;email=me@example.com' | jq .
curl -s -X POST {dev} -H 'content-type: application/json' \
  -d '{{"preset":"okta","sp":"http://localhost:3000/saml/metadata","attributes":{{"groups":["admins"]}}}}'</pre>
</section>
<section class="card">
  <h2>Templates</h2>
  <p class="muted">Each template is also served as its own identity provider, with that provider's attribute names, NameID, signing behaviour, XML style and endpoint paths.</p>
  <div class="tenants">{tenants}</div>
</section>"#,
        entity = esc(&tenant.entity_id),
        metadata = esc(&tenant.metadata_url()),
        prefix = tenant.prefix,
        sha1 = esc(&cert.sha1_fingerprint),
        sha256 = esc(&cert.sha256_fingerprint),
        not_after = esc(&cert.not_after),
    );
    page(&tenant, "Home", &body).into_response()
}

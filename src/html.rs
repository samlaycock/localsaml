//! The web UI's pages. The UI is a React app in `ui/`, built into `ui/dist` (which is committed)
//! and compiled in; debug builds read `ui/dist` from disk, so a rebuilt UI shows on reload.
//!
//! The dev tools (`/`, `/dev`, `/dev/requests`, `/sp`) are pages of the app that load their data
//! from the `/dev/api/*` endpoints. The protocol's pages (sign-in, review, IdP-initiated pick,
//! sign-out, the test SP's verdicts and errors) are decided here: the server sends the app's page
//! with a description of what to show, plus a plain HTML version that works without JavaScript.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use serde_json::{Value, json};

use crate::tenant::Tenant;

#[derive(rust_embed::RustEmbed)]
#[folder = "ui/dist/"]
pub struct Dist;

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The app's page for `tenant`. `view` says which of the protocol's pages to show (`null` for
/// the dev tools, whose pages the app routes itself); `fallback` is the page's content until the
/// app starts, and all of it where JavaScript doesn't run (the interop harness, the SAML
/// conformance kit, scripts posting the login form).
pub fn shell(tenant: &Tenant, status: StatusCode, title: &str, view: Value, fallback: &str) -> Response {
    let Some(index) = Dist::get("index.html") else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "localsaml was built without its web UI (ui/dist)").into_response();
    };
    let cache = if view.is_null() { "no-cache" } else { "no-store" };
    let data = json!({ "entityId": tenant.entity_id, "prefix": tenant.prefix, "view": view });
    // `<` can't end the script element when escaped, and JSON reads `\u003c` back as `<`.
    let script = format!(
        r#"<script type="application/json" id="lo-page">{}</script>"#,
        data.to_string().replace('<', "\\u003c")
    );
    let html = String::from_utf8_lossy(&index.data)
        .replacen("<title>localsaml</title>", &format!("<title>{} · localsaml</title>", esc(title)), 1)
        .replacen("</head>", &format!("{script}\n  </head>"), 1)
        .replacen(r#"<div id="root"></div>"#, &format!(r#"<div id="root">{fallback}</div>"#), 1);
    let mut resp = (status, Html(html)).into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    resp
}

/// A page of the dev tools: the app routes it (and keeps the title current as it does).
pub fn app_page(tenant: &Tenant, title: &str) -> Response {
    let note = format!(
        r#"<noscript>{}</noscript>"#,
        card(&format!(
            r#"<h1>localsaml's pages need JavaScript</h1><p>The SAML endpoints and the JSON APIs work without it, for example <code>{}</code>.</p>"#,
            esc(&tenant.url("/dev/api/response"))
        ))
    );
    shell(tenant, StatusCode::OK, title, Value::Null, &note)
}

// The pages' plain HTML versions use the theme's colours (CSS variables), so they look like the
// app does for the moment before it starts. Headings and paragraphs stay bare: the interop
// harness reads `<h1>…</h1><p>…` from error pages.
pub const PRIMARY_BUTTON: &str = r#"style="background:var(--primary);color:var(--primary-foreground);border:0;border-radius:calc(var(--radius) - 2px);padding:.5rem .875rem;font:inherit;font-size:.875rem;font-weight:500;cursor:pointer;text-decoration:none""#;
pub const BUTTON: &str = r#"style="background:transparent;color:inherit;border:1px solid var(--border);border-radius:calc(var(--radius) - 2px);padding:.5rem .875rem;font:inherit;font-size:.875rem;font-weight:500;cursor:pointer;text-decoration:none""#;

/// A centred card for a page's plain HTML version.
pub fn card(inner: &str) -> String {
    format!(
        r#"<main style="max-width:40rem;margin:4rem auto;padding:0 1rem;font-family:var(--font-sans,system-ui,sans-serif);font-size:.875rem;line-height:1.5"><section style="border:1px solid var(--border);border-radius:var(--radius);background:var(--card);color:var(--card-foreground);padding:1.5rem;display:grid;gap:.75rem">{inner}</section></main>"#
    )
}

/// A titled card: an eyebrow line, a heading and a paragraph, then `extra`.
pub fn titled_card(eyebrow: &str, title: &str, detail: &str, extra: &str) -> String {
    card(&format!(
        r#"<div style="color:var(--muted-foreground);font-size:.75rem;font-weight:500">{}</div><h1>{}</h1><p>{}</p>{extra}"#,
        esc(eyebrow),
        esc(title),
        esc(detail)
    ))
}

pub fn error_page(tenant: &Tenant, status: StatusCode, title: &str, detail: &str) -> Response {
    // SAML errors are HTTP 200 (see `saml_error_page`), so only show a status that is an error.
    let label = if status.is_success() { "Error".to_string() } else { format!("Error {}", status.as_u16()) };
    let view = json!({ "kind": "error", "label": label, "title": title, "detail": detail });
    let mut resp = shell(tenant, status, title, view, &titled_card(&label, title, detail, ""));
    crate::inspector::ErrorNote::attach(&mut resp, title, detail);
    resp
}

/// An error page for a SAML message that can't be answered with a SAML error Response (no
/// trustworthy service provider or ACS to send one to). HTTP 200: the bindings forbid HTTP error
/// codes for SAML failures (Bindings 3.4.6, 3.5.6); the `x-localsaml-error` header names the
/// problem for tools.
pub fn saml_error_page(tenant: &Tenant, title: &str, detail: &str) -> Response {
    let mut resp = error_page(tenant, StatusCode::OK, title, detail);
    if let Ok(v) =
        axum::http::HeaderValue::from_str(&title.replace(|c: char| !c.is_ascii() || c.is_ascii_control(), "?"))
    {
        resp.headers_mut().insert("x-localsaml-error", v);
    }
    resp
}

pub fn message_page(tenant: &Tenant, title: &str, detail: &str) -> Response {
    let view = json!({ "kind": "message", "title": title, "detail": detail });
    shell(tenant, StatusCode::OK, title, view, &titled_card("localsaml", title, detail, ""))
}

/// The HTTP-POST binding: a page that posts a SAML message to the service provider.
/// Keep proxies and the browser from caching a SAML message (Bindings 3.4.5.1, 3.5.5.1, 3.6.5.1).
pub fn no_cache(mut resp: Response) -> Response {
    let headers = resp.headers_mut();
    headers.insert(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-cache, no-store"));
    headers.insert(axum::http::header::PRAGMA, axum::http::HeaderValue::from_static("no-cache"));
    resp
}

/// The HTTP-Redirect binding (or an artifact): a redirect carrying a SAML message, not cached.
pub fn saml_redirect(url: &str) -> Response {
    no_cache(axum::response::Redirect::to(url).into_response())
}

pub fn saml_post(action: &str, param: &str, message_b64: &str, relay_state: Option<&str>) -> Response {
    let relay = relay_state
        .filter(|r| !r.is_empty())
        .map(|r| format!(r#"<input type="hidden" name="RelayState" value="{}">"#, esc(r)))
        .unwrap_or_default();
    no_cache(Html(format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>Posting to the service provider · localsaml</title>
<style>body{{font:14px system-ui,sans-serif;color:#64748b;display:grid;place-items:center;height:90vh}}</style></head>
<body onload="document.forms[0].submit()"><form method="POST" action="{action}"><input type="hidden" name="{param}" value="{message}">{relay}
<p>Sending the SAML {kind} to <code>{action}</code>…</p><noscript><button type="submit">Continue</button></noscript></form></body></html>"#,
        action = esc(action),
        param = esc(param),
        message = esc(message_b64),
        kind = if param == "SAMLResponse" { "response" } else { "request" },
    ))
    .into_response())
}

/// Indented XML in a page's plain HTML version.
pub fn xml_block(title: &str, xml: &str) -> String {
    format!(
        r#"<details><summary>{}</summary><pre style="overflow:auto;font-size:.75rem;border:1px solid var(--border);border-radius:calc(var(--radius) - 2px);padding:.75rem">{}</pre></details>"#,
        esc(title),
        esc(xml)
    )
}

/// One of the app's files: hashed assets never change, everything else is revalidated.
pub fn asset(path: &str) -> Response {
    if path.split('/').any(|part| part == "..") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(file) = Dist::get(path) else { return StatusCode::NOT_FOUND.into_response() };
    let cache = if path.starts_with("assets/") { "public, max-age=31536000, immutable" } else { "no-cache" };
    let content_type = match path.rsplit_once('.').map(|(_, ext)| ext) {
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("png") => "image/png",
        _ => "application/octet-stream",
    };
    ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, cache)], file.data).into_response()
}

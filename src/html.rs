use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use serde_json::Value;

use crate::tenant::Tenant;

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

pub fn page(tenant: &Tenant, title: &str, body: &str) -> Html<String> {
    let p = &tenant.prefix;
    let badge = match tenant.preset {
        Some(preset) => {
            format!(r#"<span class="tenant-badge" style="--c:{}">emulating {}</span>"#, preset.color, esc(preset.name))
        }
        None => String::new(),
    };
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · localsaml</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<header class="topbar">
  <a class="brand" href="{p}/"><span class="logo">◈</span> local<b>saml</b></a>{badge}
  <nav>
    <a href="{p}/dev">Assertion generator</a>
    <a href="{p}/sp">Test SP</a>
    <a href="{p}/dev/requests">Requests</a>
    <a href="{p}/metadata">Metadata</a>
  </nav>
</header>
{clock}<main>
{body}
</main>
<script src="/assets/app.js"></script>
</body>
</html>"#,
        title = esc(title),
        clock = clock_banner(tenant) + &faults_banner(tenant),
    ))
}

/// Warn on every page while the clock is shifted: it's easy to forget and it changes everything.
fn clock_banner(tenant: &Tenant) -> String {
    if tenant.clock_offset == 0 {
        return String::new();
    }
    let p = &tenant.prefix;
    let (offset, direction) = (
        crate::util::format_duration(tenant.clock_offset),
        if tenant.clock_offset > 0 { "ahead of" } else { "behind" },
    );
    format!(
        r#"<div class="clock-banner" role="status">The localsaml clock is <b>{offset}</b> {direction} real time. Assertion timestamps and expiry checks use the shifted time. <a href="{p}/dev#clock">Change or reset it</a></div>
"#
    )
}

fn faults_banner(tenant: &Tenant) -> String {
    let n = tenant.faults_armed;
    if n == 0 {
        return String::new();
    }
    let p = &tenant.prefix;
    let what = if n == 1 { "1 fault is".to_string() } else { format!("{n} faults are") };
    format!(
        r#"<div class="faults-banner" role="status"><b>{what} armed</b>: matching requests will fail or slow down on purpose. <a href="{p}/dev#faults">Manage faults</a></div>
"#
    )
}

/// Embed JSON for the page script.
pub fn data_script(v: &Value) -> String {
    format!(
        r#"<script type="application/json" id="lo-data">{}</script>"#,
        v.to_string().replace('<', "\\u003c").replace('>', "\\u003e").replace('&', "\\u0026")
    )
}

pub fn error_page(tenant: &Tenant, status: StatusCode, title: &str, detail: &str) -> Response {
    let body = format!(
        r#"<section class="card narrow"><div class="eyebrow error">Error {}</div><h1>{}</h1><p>{}</p></section>"#,
        status.as_u16(),
        esc(title),
        esc(detail)
    );
    let mut resp = (status, page(tenant, title, &body)).into_response();
    crate::inspector::ErrorNote::attach(&mut resp, title, detail);
    resp
}

/// An error page for a SAML message that can't be answered with a SAML message (no trustworthy
/// service provider or ACS to send an error Response to). It's an HTTP 400: SAML Bindings 3.4.6
/// and 3.5.6 discourage HTTP error codes, but there's no SAML exchange left to stay inside, and
/// conformance tools and service providers alike treat a 4xx as the refusal. The title is also
/// in the `x-localsaml-error` header, for scripts.
pub fn saml_error_page(tenant: &Tenant, title: &str, detail: &str) -> Response {
    let mut resp = error_page(tenant, StatusCode::BAD_REQUEST, title, detail);
    if let Ok(v) =
        axum::http::HeaderValue::from_str(&title.replace(|c: char| !c.is_ascii() || c.is_ascii_control(), "?"))
    {
        resp.headers_mut().insert("x-localsaml-error", v);
    }
    resp
}

pub fn message_page(tenant: &Tenant, title: &str, detail: &str) -> Response {
    let body = format!(
        r#"<section class="card narrow"><div class="eyebrow">localsaml</div><h1>{}</h1><p>{}</p></section>"#,
        esc(title),
        esc(detail)
    );
    page(tenant, title, &body).into_response()
}

/// The HTTP-POST binding: a page that posts a SAML message to the service provider.
pub fn saml_post(action: &str, param: &str, message_b64: &str, relay_state: Option<&str>) -> Html<String> {
    let relay = relay_state
        .filter(|r| !r.is_empty())
        .map(|r| format!(r#"<input type="hidden" name="RelayState" value="{}">"#, esc(r)))
        .unwrap_or_default();
    Html(format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>Posting to the service provider · localsaml</title>
<style>body{{font:14px system-ui,sans-serif;color:#64748b;display:grid;place-items:center;height:90vh}}</style></head>
<body onload="document.forms[0].submit()"><form method="POST" action="{action}"><input type="hidden" name="{param}" value="{message}">{relay}
<p>Sending the SAML {kind} to <code>{action}</code>…</p><noscript><button type="submit">Continue</button></noscript></form></body></html>"#,
        action = esc(action),
        param = esc(param),
        message = esc(message_b64),
        kind = if param == "SAMLResponse" { "response" } else { "request" },
    ))
}

/// Render indented XML for a page, with a copy button.
pub fn xml_block(title: &str, xml: &str) -> String {
    format!(
        r#"<div class="snippet"><div class="token-head"><b>{}</b><button type="button" class="btn small" data-copy-next>Copy</button></div><pre class="code xml">{}</pre></div>"#,
        esc(title),
        esc(xml)
    )
}

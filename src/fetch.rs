//! Outbound HTTP: service provider metadata and SOAP back-channel messages.

use std::sync::OnceLock;
use std::time::Duration;

const MAX_BYTES: usize = 1 << 20;

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            // Local dev apps commonly serve these from self-signed HTTPS.
            .danger_accept_invalid_certs(true)
            .build()
            .expect("building HTTP client")
    })
}

pub async fn text(url: &str) -> Result<String, String> {
    let resp = client().get(url).send().await.map_err(|e| format!("GET {url} failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {url} returned {}", resp.status()));
    }
    let body = resp.bytes().await.map_err(|e| format!("reading {url}: {e}"))?;
    if body.len() > MAX_BYTES {
        return Err(format!("{url} returned more than {MAX_BYTES} bytes"));
    }
    String::from_utf8(body.to_vec()).map_err(|_| format!("{url} did not return UTF-8 text"))
}

/// POST an XML document (a SOAP envelope), without following redirects. Returns the status and
/// body.
pub async fn post_xml(url: &str, xml: &str, timeout: Duration) -> Result<(u16, String), String> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    let client = CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .build()
            .expect("building HTTP client")
    });
    let resp = client
        .post(url)
        .timeout(timeout)
        .header(reqwest::header::CONTENT_TYPE, "text/xml; charset=utf-8")
        .header("SOAPAction", "http://www.oasis-open.org/committees/security")
        // Bindings 3.2.3.2: requesters shouldn't let proxies cache SAML messages either.
        .header(reqwest::header::CACHE_CONTROL, "no-cache, no-store")
        .header(reqwest::header::PRAGMA, "no-cache")
        .body(xml.to_string())
        .send()
        .await
        .map_err(|e| format!("POST {url} failed: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.bytes().await.map_err(|e| format!("reading {url}: {e}"))?;
    if body.len() > MAX_BYTES {
        return Err(format!("{url} returned more than {MAX_BYTES} bytes"));
    }
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

//! Outbound HTTP: service provider metadata.

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

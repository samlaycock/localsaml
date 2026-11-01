//! Fault injection: make the next matching requests fail on purpose, respond slowly, or answer
//! with a deliberately defective Response, so an app's error handling and validation can be tested.
//! Faults are armed over HTTP (`/dev/api/faults` or `/dev`) and live in memory only.
//!
//! SSO and SLO faults are applied by those handlers, so errors go back to the service provider as
//! SAML Responses with an error status, like a real IdP's. Metadata faults are answered by a
//! middleware with an HTTP error.

use std::sync::Mutex;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::inspector::ErrorNote;
use crate::presets::{self, EndpointKind};
use crate::saml::{Status, Tamper};
use crate::state::AppState;

/// Longest delay a fault may add.
pub const MAX_DELAY_MS: u64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endpoint {
    /// Logins: SP-initiated and IdP-initiated.
    Sso,
    /// Single logout.
    Slo,
    Metadata,
}

impl Endpoint {
    /// The endpoint a path within an issuer belongs to, including template aliases.
    pub fn for_path(path: &str) -> Option<Endpoint> {
        let p = path.trim_end_matches('/');
        // localsaml's own tools and the built-in test SP are never faulted.
        if p == "/dev" || p.starts_with("/dev/") || p == "/sp" || p.starts_with("/sp/") {
            return None;
        }
        Some(match p {
            "/sso" | "/sso/initiate" => Endpoint::Sso,
            "/slo" | "/slo/initiate" => Endpoint::Slo,
            "/metadata" => Endpoint::Metadata,
            _ => match presets::classify_alias(p)? {
                EndpointKind::Sso | EndpointKind::Initiate => Endpoint::Sso,
                EndpointKind::Slo => Endpoint::Slo,
                EndpointKind::Metadata => Endpoint::Metadata,
            },
        })
    }
}

/// How to arm a fault (`POST /dev/api/faults`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultRequest {
    pub endpoint: Endpoint,
    /// Only requests to this issuer: `root` or a template id. Default: any.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Only requests from this service provider (entity ID). Default: any.
    #[serde(default)]
    pub sp: Option<String>,
    /// SAML status to answer with (`AuthnFailed`, `NoPassive`, `Responder`, or a full URN).
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub status_message: Option<String>,
    /// Defects to put in an otherwise successful Response (SSO only).
    #[serde(default)]
    pub tamper: Vec<Tamper>,
    /// HTTP status for metadata faults (default 503).
    #[serde(default)]
    pub http_status: Option<u16>,
    /// Wait this long before answering.
    #[serde(default)]
    pub delay_ms: u64,
    /// How many matching requests to affect. Default 1.
    #[serde(default)]
    pub count: Option<u32>,
    /// Affect every matching request until the fault is removed.
    #[serde(default)]
    pub always: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Fault {
    pub id: u64,
    pub endpoint: Endpoint,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tamper: Vec<Tamper>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    pub delay_ms: u64,
    /// Requests still to affect; `null` means until removed.
    pub remaining: Option<u32>,
}

impl Fault {
    pub fn from_request(req: FaultRequest) -> Result<Self, String> {
        if req.delay_ms > MAX_DELAY_MS {
            return Err(format!("delay_ms must be at most {MAX_DELAY_MS}"));
        }
        if req.count == Some(0) {
            return Err("count must be at least 1".into());
        }
        if req.always && req.count.is_some() {
            return Err("send count or always, not both".into());
        }
        let message = req.status_message.filter(|m| !m.is_empty());
        let mut status = match req.status.as_deref().filter(|s| !s.is_empty()) {
            Some(s) => Some(Status::parse(s, message.clone())?),
            None => None,
        };
        let mut http_status = req.http_status;
        match req.endpoint {
            Endpoint::Metadata => {
                if status.is_some() || !req.tamper.is_empty() {
                    return Err("metadata faults take http_status (and delay_ms), not a SAML status or tamper".into());
                }
                if req.sp.as_deref().is_some_and(|s| !s.is_empty()) {
                    return Err("metadata requests don't come from a service provider; drop sp".into());
                }
                if let Some(s) = http_status
                    && !(400..=599).contains(&s)
                {
                    return Err("http_status must be between 400 and 599".into());
                }
                if http_status.is_none() && req.delay_ms == 0 {
                    http_status = Some(503);
                }
            }
            Endpoint::Sso | Endpoint::Slo => {
                if http_status.is_some() {
                    return Err(
                        "http_status is for metadata faults; SSO and SLO faults answer with a SAML status".into()
                    );
                }
                if req.endpoint == Endpoint::Slo && !req.tamper.is_empty() {
                    return Err("tamper only applies to SSO responses".into());
                }
                if status.as_ref().is_some_and(Status::is_success) && req.tamper.is_empty() {
                    return Err("a Success status does nothing on its own; add tamper, or use an error status".into());
                }
                if status.is_none() && req.tamper.is_empty() && req.delay_ms == 0 {
                    status = Some(Status::parse("Responder", message)?);
                }
            }
        }
        if !req.tamper.is_empty() && status.as_ref().is_some_and(|s| !s.is_success()) {
            return Err("tamper needs a successful Response; drop status or tamper".into());
        }
        Ok(Self {
            id: 0,
            endpoint: req.endpoint,
            issuer: req.issuer.filter(|s| !s.is_empty()),
            sp: req.sp.filter(|s| !s.is_empty()),
            status: status.filter(|s| !s.is_success()),
            tamper: req.tamper,
            http_status,
            delay_ms: req.delay_ms,
            remaining: if req.always { None } else { Some(req.count.unwrap_or(1)) },
        })
    }

    /// A short summary, e.g. `Responder/AuthnFailed` or `tamper: expired`.
    pub fn summary(&self) -> String {
        let mut parts = vec![];
        if let Some(s) = &self.status {
            parts.push(s.short());
        }
        if !self.tamper.is_empty() {
            parts.push(format!("tamper: {}", self.tamper.iter().map(|t| t.name()).collect::<Vec<_>>().join(", ")));
        }
        if let Some(h) = self.http_status {
            parts.push(format!("HTTP {h}"));
        }
        if self.delay_ms > 0 {
            parts.push(format!("after {} ms", self.delay_ms));
        }
        parts.join(" · ")
    }

    pub fn status_with_default_message(&self) -> Option<Status> {
        self.status.clone().map(|mut s| {
            if s.message.is_none() {
                s.message = Some(format!("injected by localsaml (fault {})", self.id));
            }
            s
        })
    }

    pub async fn wait(&self) {
        if self.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        }
    }
}

/// What a request looks like to the matcher.
pub struct Target<'a> {
    pub endpoint: Endpoint,
    pub issuer: &'a str,
    pub sp: Option<&'a str>,
}

#[derive(Debug, Default)]
pub struct Faults {
    inner: Mutex<(u64, Vec<Fault>)>,
}

impl Faults {
    pub fn add(&self, mut fault: Fault) -> Fault {
        let mut inner = self.inner.lock().unwrap();
        inner.0 += 1;
        fault.id = inner.0;
        inner.1.push(fault.clone());
        fault
    }

    pub fn list(&self) -> Vec<Fault> {
        self.inner.lock().unwrap().1.clone()
    }

    pub fn remove(&self, id: u64) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.1.len();
        inner.1.retain(|f| f.id != id);
        inner.1.len() != before
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().1.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().1.is_empty()
    }

    /// The oldest fault matching `target`, used up by one if it has a count.
    pub fn take(&self, target: &Target) -> Option<Fault> {
        let mut inner = self.inner.lock().unwrap();
        let faults = &mut inner.1;
        let index = faults.iter().position(|f| {
            f.endpoint == target.endpoint
                && f.issuer.as_deref().is_none_or(|i| i == target.issuer)
                && f.sp.as_deref().is_none_or(|s| Some(s) == target.sp)
        })?;
        let fault = faults[index].clone();
        if let Some(remaining) = &mut faults[index].remaining {
            *remaining -= 1;
            if *remaining == 0 {
                faults.remove(index);
            }
        }
        Some(fault)
    }
}

/// Apply armed faults to metadata requests.
pub async fn apply(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if state.faults.is_empty() {
        return next.run(request).await;
    }
    let path = request.uri().path().to_string();
    let (issuer, within) = crate::inspector::strip_issuer(&path);
    if Endpoint::for_path(within) != Some(Endpoint::Metadata) {
        return next.run(request).await;
    }
    let Some(fault) = state.faults.take(&Target { endpoint: Endpoint::Metadata, issuer, sp: None }) else {
        return next.run(request).await;
    };
    fault.wait().await;
    let Some(code) = fault.http_status else {
        return next.run(request).await;
    };
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    let description = format!("injected by localsaml (fault {})", fault.id);
    let mut resp = (status, [(header::CACHE_CONTROL, "no-store")], description.clone()).into_response();
    if let Ok(v) = HeaderValue::from_str(&fault.id.to_string()) {
        resp.headers_mut().insert("x-localsaml-fault", v);
    }
    ErrorNote::attach(&mut resp, format!("HTTP {code}"), description);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fault(json: serde_json::Value) -> Result<Fault, String> {
        Fault::from_request(serde_json::from_value(json).unwrap())
    }

    #[test]
    fn classifies_paths_and_template_aliases() {
        use Endpoint::*;
        for (path, endpoint) in [
            ("/sso", Sso),
            ("/sso/initiate", Sso),
            ("/slo", Slo),
            ("/metadata", Metadata),
            ("/app/localsaml/0oa1/sso/saml", Sso),
            ("/app/0oa1/sso/saml/metadata", Metadata),
            ("/9188040d-6c67-4c5b-b112-36a304b66dad/saml2", Sso),
            ("/idp/profile/SAML2/Redirect/SLO", Slo),
            ("/idp/startSSO.ping", Sso),
            ("/adfs/ls/", Sso),
        ] {
            assert_eq!(Endpoint::for_path(path), Some(endpoint), "{path}");
        }
        for path in ["/dev/api/response", "/sp/acs", "/login", "/"] {
            assert_eq!(Endpoint::for_path(path), None, "{path}");
        }
    }

    #[test]
    fn defaults_and_validation() {
        let f = fault(json!({ "endpoint": "sso" })).unwrap();
        assert_eq!(f.status.as_ref().map(Status::short).as_deref(), Some("Responder"));
        let f = fault(json!({ "endpoint": "sso", "status": "NoPassive" })).unwrap();
        assert_eq!(f.summary(), "NoPassive");
        let f = fault(json!({ "endpoint": "sso", "tamper": ["expired", "wrong_audience"] })).unwrap();
        assert!(f.status.is_none() && f.tamper.len() == 2);
        let f = fault(json!({ "endpoint": "metadata" })).unwrap();
        assert_eq!(f.http_status, Some(503));
        let f = fault(json!({ "endpoint": "sso", "delay_ms": 2000 })).unwrap();
        assert!(f.status.is_none());
        assert!(fault(json!({ "endpoint": "sso", "status": "Bogus" })).is_err());
        assert!(fault(json!({ "endpoint": "metadata", "status": "Responder" })).is_err());
        assert!(fault(json!({ "endpoint": "metadata", "sp": "http://app.test/sp" })).is_err());
        assert!(fault(json!({ "endpoint": "slo", "tamper": ["expired"] })).is_err());
        assert!(fault(json!({ "endpoint": "sso", "status": "AuthnFailed", "tamper": ["expired"] })).is_err());
        assert!(fault(json!({ "endpoint": "sso", "delay_ms": 60_000 })).is_err());
        assert!(fault(json!({ "endpoint": "sso", "count": 2, "always": true })).is_err());
        assert!(serde_json::from_value::<FaultRequest>(json!({ "endpoint": "token" })).is_err());
        assert!(serde_json::from_value::<FaultRequest>(json!({ "endpoint": "sso", "tamper": ["nope"] })).is_err());
    }

    #[test]
    fn matching_counts_down_and_filters() {
        let faults = Faults::default();
        faults.add(fault(json!({ "endpoint": "sso", "sp": "a", "count": 2 })).unwrap());
        faults.add(fault(json!({ "endpoint": "sso", "issuer": "okta", "always": true })).unwrap());
        let target = |sp: &'static str, issuer: &'static str| Target { endpoint: Endpoint::Sso, issuer, sp: Some(sp) };
        assert_eq!(faults.take(&target("a", "root")).map(|f| f.id), Some(1));
        assert_eq!(faults.take(&target("b", "root")).map(|f| f.id), None);
        assert_eq!(faults.take(&target("a", "root")).map(|f| f.id), Some(1));
        assert_eq!(faults.take(&target("a", "root")).map(|f| f.id), None);
        for _ in 0..3 {
            assert_eq!(faults.take(&target("b", "okta")).map(|f| f.id), Some(2));
        }
        assert!(faults.remove(2) && faults.is_empty());
    }
}

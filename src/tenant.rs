use axum::extract::{FromRequestParts, OriginalUri};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::config::Config;
use crate::presets::{self, EndpointKind, Preset};
use crate::state::AppState;

/// An identity provider: either the root issuer, or a template issuer mounted at `/p/<preset>`
/// that looks like a particular production IdP.
#[derive(Debug, Clone)]
pub struct Tenant {
    pub preset: Option<&'static Preset>,
    /// Base URL of this issuer's endpoints, e.g. `http://localhost:9401/p/okta`.
    pub base: String,
    pub entity_id: String,
    /// Path prefix for links (e.g. "" or "/p/okta").
    pub prefix: String,
    /// The server clock's offset when the request arrived, so pages can warn about it.
    pub clock_offset: i64,
    /// How many faults were armed when the request arrived, so pages can warn about them.
    pub faults_armed: usize,
}

impl Tenant {
    pub fn new(base_url: &str, preset: Option<&'static Preset>, config: &Config) -> Self {
        let base_url = base_url.trim_end_matches('/');
        let base = match preset {
            Some(p) => format!("{base_url}/p/{}", p.id),
            None => base_url.to_string(),
        };
        let entity_id = match preset {
            Some(p) => p.entity_id(&base),
            None => config.entity_id.clone().unwrap_or_else(|| format!("{base}/metadata")),
        };
        let prefix = url::Url::parse(&base).map(|u| u.path().trim_end_matches('/').to_string()).unwrap_or_default();
        Self { preset, base, entity_id, prefix, clock_offset: 0, faults_armed: 0 }
    }

    /// `root` or the template id.
    pub fn key(&self) -> &'static str {
        self.preset.map(|p| p.id).unwrap_or("root")
    }

    /// The template used to sign in: this issuer's, or the configured default on the root issuer.
    pub fn default_preset(&self, config: &Config) -> &'static Preset {
        self.preset.unwrap_or_else(|| presets::get_or_generic(&config.default_preset))
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    pub fn path(&self, path: &str) -> String {
        format!("{}{}", self.prefix, path)
    }

    fn alias(&self, kind: EndpointKind) -> Option<String> {
        let preset = self.preset?;
        preset.endpoints.iter().find(|e| e.kind == kind).map(|e| self.url(&presets::fill_path(e.path)))
    }

    /// The SSO URL the metadata advertises: the template's alias, or `/sso`.
    pub fn sso_url(&self) -> String {
        self.alias(EndpointKind::Sso).unwrap_or_else(|| self.url("/sso"))
    }

    /// The SLO URL the metadata advertises, if the IdP does single logout. Templates whose SSO
    /// endpoint also handles logout (Entra ID, AD FS, Keycloak) advertise that.
    pub fn slo_url(&self) -> Option<String> {
        match self.preset {
            Some(p) if !p.single_logout => None,
            Some(_) => self
                .alias(EndpointKind::Slo)
                .or_else(|| self.alias(EndpointKind::Sso))
                .or_else(|| Some(self.url("/slo"))),
            None => Some(self.url("/slo")),
        }
    }

    pub fn metadata_url(&self) -> String {
        self.url("/metadata")
    }

    pub fn cookie_name(&self) -> String {
        format!("localsaml_sid_{}", self.key())
    }
}

impl FromRequestParts<AppState> for Tenant {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let path = parts
            .extensions
            .get::<OriginalUri>()
            .map(|u| u.0.path().to_owned())
            .unwrap_or_else(|| parts.uri.path().to_owned());

        let base = if state.config.dynamic_base_url {
            let host = parts
                .headers
                .get("x-forwarded-host")
                .or_else(|| parts.headers.get(header::HOST))
                .and_then(|h| h.to_str().ok())
                .unwrap_or("localhost");
            let proto = parts.headers.get("x-forwarded-proto").and_then(|h| h.to_str().ok()).unwrap_or("http");
            format!("{proto}://{host}")
        } else {
            state.config.base_url.clone()
        };

        let preset = match path.strip_prefix("/p/") {
            Some(rest) => {
                let id = rest.split('/').next().unwrap_or_default();
                match presets::get(id) {
                    Some(p) => Some(p),
                    None => {
                        return Err((StatusCode::NOT_FOUND, format!("unknown template '{id}'")).into_response());
                    }
                }
            }
            None => None,
        };
        Ok(Tenant {
            clock_offset: state.clock().offset(),
            faults_armed: state.faults.list().len(),
            ..Tenant::new(&base, preset, &state.config)
        })
    }
}

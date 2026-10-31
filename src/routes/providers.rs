//! Template endpoint aliases (Okta's `/app/…/sso/saml`, Entra ID's `/{tenant}/saml2`, Shibboleth's
//! `/idp/profile/SAML2/…`, …), mounted under `/p/<preset>`.

use std::collections::HashSet;

use axum::Router;
use axum::routing::{any, get};

use crate::presets::{self, EndpointKind};
use crate::routes::{metadata, sso};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    let mut router = Router::new();
    let mut seen = HashSet::new();
    for endpoint in presets::all().iter().flat_map(|p| &p.endpoints) {
        // `/adfs/ls/` is also reached as `/adfs/ls`.
        let trimmed = endpoint.path.trim_end_matches('/');
        let paths = if trimmed != endpoint.path { vec![endpoint.path, trimmed] } else { vec![endpoint.path] };
        for path in paths {
            if !seen.insert(path.to_ascii_lowercase()) {
                continue;
            }
            router = match endpoint.kind {
                EndpointKind::Sso | EndpointKind::Slo => router.route(path, any(sso::endpoint)),
                EndpointKind::Initiate if path.contains("{client}") => router.route(path, get(sso::initiate_named)),
                EndpointKind::Initiate => router.route(path, get(sso::initiate)),
                EndpointKind::Metadata => router.route(path, get(metadata::metadata)),
            };
        }
    }
    router
}

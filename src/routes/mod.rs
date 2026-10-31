pub mod dev;
pub mod metadata;
pub mod pages;
pub mod providers;
pub mod slo;
pub mod sso;
pub mod testsp;

use axum::routing::{any, delete, get, post};
use axum::{Router, middleware};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Standard endpoints, served at the root issuer and under every `/p/<preset>` issuer.
fn issuer_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(pages::index))
        .route("/metadata", get(metadata::metadata))
        .route("/certificate.pem", get(metadata::certificate))
        .route("/sso", any(sso::endpoint))
        .route("/sso/initiate", get(sso::initiate))
        .route("/login", post(sso::login))
        .route("/slo", any(sso::endpoint))
        .route("/slo/initiate", get(slo::initiate))
        .route("/sp", get(testsp::home))
        .route("/sp/login", any(testsp::login))
        .route("/sp/acs", post(testsp::acs))
        .route("/sp/slo", any(testsp::slo))
        .route("/sp/logout", post(testsp::logout))
        .route("/sp/metadata", get(testsp::metadata))
        .route("/dev", get(dev::page_handler))
        .route("/dev/api/response", get(dev::api_response_get).post(dev::api_response_post))
        .route("/dev/api/presets", get(dev::api_presets))
        .route("/dev/api/users", get(dev::api_users))
        .route("/dev/api/service-providers", get(dev::api_sps).post(dev::api_sps_add).delete(dev::api_sps_remove))
        .route("/dev/api/certificate", get(dev::api_certificate))
        .route("/dev/api/rotate-keys", post(dev::api_rotate_keys))
        .route("/dev/api/clock", get(dev::api_clock).post(dev::api_clock_set))
        .route("/dev/requests", get(dev::requests_page))
        .route("/dev/api/requests", get(dev::api_requests).delete(dev::api_requests_clear))
        .route("/dev/api/faults", get(dev::api_faults).post(dev::api_faults_add).delete(dev::api_faults_clear))
        .route("/dev/api/faults/{id}", delete(dev::api_faults_remove))
        .route("/dev/api/sessions", get(dev::api_sessions))
        .route("/dev/api/sessions/{sid}", delete(dev::api_sessions_end))
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(issuer_routes())
        .nest("/p/{preset}", issuer_routes().merge(providers::routes()))
        .route("/assets/app.css", get(pages::css))
        .route("/assets/app.js", get(pages::js))
        .route("/health", get(|| async { "ok" }))
        .layer(middleware::from_fn_with_state(state.clone(), crate::faults::apply))
        .layer(middleware::from_fn_with_state(state.clone(), crate::inspector::record))
        .layer(CorsLayer::very_permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

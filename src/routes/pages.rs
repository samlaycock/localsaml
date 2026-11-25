//! The identity provider's overview: the web UI's app shows it, with its data from
//! `/dev/api/info`.

use axum::response::Response;

use crate::html::app_page;
use crate::tenant::Tenant;

pub async fn index(tenant: Tenant) -> Response {
    app_page(&tenant, "Home")
}

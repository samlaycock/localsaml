pub mod clock;
pub mod config;
pub mod dsig;
pub mod faults;
pub mod fetch;
pub mod html;
pub mod inspector;
pub mod keys;
pub mod presets;
pub mod routes;
pub mod saml;
pub mod soap;
pub mod sp;
pub mod state;
pub mod store;
pub mod tenant;
pub mod users;
pub mod util;
pub mod xml;
pub mod xmlenc;

use std::sync::Arc;

use anyhow::Context;

pub use routes::router;
pub use state::AppState;

/// Load or create the signing key according to the config.
pub fn load_keys(config: &config::Config) -> anyhow::Result<Arc<keys::Keys>> {
    let keys = match (&config.data_dir, config.ephemeral_keys) {
        (Some(dir), false) => {
            keys::Keys::load_or_create(dir).with_context(|| format!("loading signing key from {}", dir.display()))?
        }
        _ => keys::Keys::generate()?,
    };
    Ok(Arc::new(keys))
}

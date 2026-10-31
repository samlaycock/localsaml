use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};

use crate::clock::Clock;
use crate::config::Config;
use crate::faults::Faults;
use crate::inspector::Inspector;
use crate::keys::Keys;
use crate::presets::Identity;
use crate::saml::Tamper;
use crate::sp::ServiceProvider;
use crate::store::{Store, Table};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub keys: Arc<Keys>,
    pub store: Arc<Store>,
    /// Recent requests, for `/dev/requests`.
    pub inspector: Arc<Inspector>,
    /// Armed faults, for `/dev/api/faults`.
    pub faults: Arc<Faults>,
    /// The last Response sent to each service provider, for the `replay` fault.
    pub last_responses: Arc<Mutex<HashMap<String, LastResponse>>>,
    /// Service providers declared in the config file, with their metadata applied once fetched.
    declared: Arc<RwLock<Vec<ServiceProvider>>>,
    /// When pending metadata was last fetched, so unreachable SPs don't slow every request.
    last_refresh: Arc<Mutex<Option<std::time::Instant>>>,
}

#[derive(Debug, Clone)]
pub struct LastResponse {
    pub acs_url: String,
    pub xml: String,
    pub pretty: String,
    pub relay_state: Option<String>,
}

impl AppState {
    /// Opens `<data_dir>/state.db`, or an in-memory SQLite database when there is no data dir.
    pub fn new(config: Config, keys: Arc<Keys>) -> anyhow::Result<Self> {
        let db = config.data_dir.as_ref().map(|d| d.join("state.db"));
        let store = Store::open(db.as_deref(), Clock::new(config.clock_offset))?;
        let declared = config
            .service_providers
            .iter()
            .cloned()
            .map(|mut sp| {
                sp.source = "config".into();
                sp.metadata_pending = sp.metadata_url.is_some();
                sp
            })
            .collect();
        Ok(Self {
            config: Arc::new(config),
            keys,
            store: Arc::new(store),
            inspector: Arc::default(),
            faults: Arc::default(),
            last_responses: Arc::default(),
            declared: Arc::new(RwLock::new(declared)),
            last_refresh: Arc::default(),
        })
    }

    /// Fetch the metadata of declared service providers that haven't got theirs yet. Called at
    /// startup and whenever a request comes from an unknown service provider (the SP may not have
    /// been running when localsaml started).
    pub async fn refresh_metadata(&self) {
        {
            let mut last = self.last_refresh.lock().unwrap();
            if last.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(5)) {
                return;
            }
            *last = Some(std::time::Instant::now());
        }
        let pending: Vec<(usize, ServiceProvider)> = self
            .declared
            .read()
            .unwrap()
            .iter()
            .enumerate()
            .filter(|(_, sp)| sp.metadata_pending)
            .map(|(i, sp)| (i, sp.clone()))
            .collect();
        for (i, mut sp) in pending {
            match sp.load_remote_metadata().await {
                Ok(()) => {
                    tracing::info!(
                        "loaded metadata for {} from {}",
                        sp.entity_id,
                        sp.metadata_url.as_deref().unwrap_or("")
                    );
                    sp.source = "config".into();
                    if let Some(slot) = self.declared.write().unwrap().get_mut(i) {
                        *slot = sp;
                    }
                }
                Err(e) => tracing::warn!("service provider metadata not loaded yet: {e}"),
            }
        }
    }

    pub fn has_pending_metadata(&self) -> bool {
        self.declared.read().unwrap().iter().any(|sp| sp.metadata_pending)
    }

    /// The server's clock, shifted by the configured or API-set offset.
    pub fn clock(&self) -> &Clock {
        self.store.clock()
    }

    /// Now, by the server's (possibly shifted) clock, in Unix seconds.
    pub fn now(&self) -> i64 {
        self.store.clock().now()
    }

    /// A declared or registered service provider. Declared ones win.
    pub fn service_provider(&self, entity_id: &str) -> Option<ServiceProvider> {
        let declared = self.declared.read().unwrap().iter().find(|sp| sp.entity_id == entity_id).cloned();
        declared.or_else(|| {
            self.store.get::<ServiceProvider>(Table::ServiceProviders, entity_id).map(|mut sp| {
                sp.source = "api".into();
                sp
            })
        })
    }

    /// Every declared and registered service provider.
    pub fn service_providers(&self) -> Vec<ServiceProvider> {
        let mut all = self.declared.read().unwrap().clone();
        for (_, mut sp, _) in self.store.entries::<ServiceProvider>(Table::ServiceProviders) {
            if all.iter().any(|s| s.entity_id == sp.entity_id) {
                continue;
            }
            sp.source = "api".into();
            all.push(sp);
        }
        all
    }

    pub fn register_service_provider(&self, sp: &ServiceProvider) {
        // `source` and `metadata_pending` are output-only: stored, they wouldn't deserialize.
        let stored = ServiceProvider { source: String::new(), metadata_pending: false, ..sp.clone() };
        self.store.put(Table::ServiceProviders, &sp.entity_id, &stored, None);
    }

    /// Drop expired sessions, pending logins and logouts.
    pub fn purge_expired(&self) {
        self.store.purge_expired();
    }
}

/// A browser session at one issuer, and the service providers it signed in to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// `root` or a template id.
    pub tenant: String,
    /// The issuer's entity ID.
    pub issuer: String,
    pub identity: Identity,
    pub auth_time: i64,
    pub session_index: String,
    #[serde(default)]
    pub participants: Vec<Participant>,
}

/// A service provider that received an assertion during a session, and the NameID it got:
/// a LogoutRequest to it must carry the same one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Participant {
    pub entity_id: String,
    pub name_id: String,
    pub name_id_format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sp_name_qualifier: Option<String>,
    /// The SessionIndex this service provider was given (templates differ in what they use).
    #[serde(default)]
    pub session_index: String,
}

/// An authentication request waiting for the login form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    pub id: String,
    pub created: i64,
    pub tenant: String,
    /// Service provider entity ID.
    pub sp: String,
    pub sp_name: Option<String>,
    pub acs_url: String,
    pub audience: String,
    /// The AuthnRequest ID (`InResponseTo`); none for IdP-initiated logins.
    pub request_id: Option<String>,
    pub relay_state: Option<String>,
    pub force_authn: bool,
    pub is_passive: bool,
    /// NameID format the request asked for (`NameIDPolicy/@Format`).
    pub name_id_format: Option<String>,
    pub sp_name_qualifier: Option<String>,
    pub requested_authn_contexts: Vec<String>,
    pub login_hint: Option<String>,
    /// The AuthnRequest's `Subject/NameID` (and its format): the assertion must be about it.
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub subject_format: Option<String>,
    /// `redirect`, `post` or `idp-initiated`.
    pub binding: String,
    /// How the request was signed, for the login page.
    pub signature: String,
    /// Things about the request worth knowing that didn't stop it.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Defects to put in the Response (from faults or `dev_tamper`).
    #[serde(default)]
    pub tampers: Vec<Tamper>,
    /// The request, indented, for the login page.
    #[serde(default)]
    pub request_xml: Option<String>,
}

/// A single logout in progress: the service providers still to log out, one at a time over
/// front-channel redirects, before answering whoever started it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Logout {
    pub id: String,
    pub tenant: String,
    pub issuer: String,
    pub who: String,
    pub session_index: String,
    /// The SP whose LogoutRequest started this, if an SP did.
    pub initiator: Option<Initiator>,
    pub remaining: Vec<Participant>,
    /// The SP we're waiting on: (entity ID, our LogoutRequest ID).
    pub waiting_on: Option<(String, String)>,
    /// (entity ID, outcome) for each SP asked so far.
    pub results: Vec<(String, String)>,
    /// Where to go when an IdP-initiated logout finishes.
    pub return_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Initiator {
    pub entity_id: String,
    pub request_id: String,
    pub relay_state: Option<String>,
}

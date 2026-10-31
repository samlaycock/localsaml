use std::path::PathBuf;

use anyhow::Context;
use clap::{Args, Parser};
use serde::Deserialize;

use crate::keys::SigAlg;
use crate::sp::ServiceProvider;
use crate::users::User;

/// The binary only runs the server; everything else happens over HTTP (the UI and `/dev/api`).
#[derive(Parser, Debug)]
#[command(name = "localsaml", version, about = "A local SAML 2.0 identity provider for offline development")]
pub struct Cli {
    #[command(flatten)]
    pub server: ServerArgs,
}

#[derive(Args, Debug, Clone, Default)]
pub struct ServerArgs {
    /// Path to a TOML config file (defaults to ./localsaml.toml if present).
    #[arg(long, env = "LOCALSAML_CONFIG")]
    pub config: Option<PathBuf>,
    /// Interface to bind.
    #[arg(long, env = "LOCALSAML_HOST")]
    pub host: Option<String>,
    /// Port to listen on.
    #[arg(long, short, env = "LOCALSAML_PORT")]
    pub port: Option<u16>,
    /// Public base URL (default http://localhost:<port>). Endpoints and entity IDs derive from it.
    #[arg(long, env = "LOCALSAML_BASE_URL")]
    pub base_url: Option<String>,
    /// Derive the base URL from each request's Host header instead of a fixed URL.
    #[arg(long)]
    pub dynamic_base_url: bool,
    /// Entity ID of the root identity provider (default <base_url>/metadata).
    #[arg(long, env = "LOCALSAML_ENTITY_ID")]
    pub entity_id: Option<String>,
    /// Skip the login UI and sign in immediately with the template's defaults.
    #[arg(long, env = "LOCALSAML_AUTO_LOGIN")]
    pub auto_login: bool,
    /// Reuse an existing session without showing the login page, like a production IdP.
    #[arg(long, env = "LOCALSAML_SILENT_SSO")]
    pub silent_sso: bool,
    /// Only accept service providers declared in the config file or registered over the API.
    #[arg(long)]
    pub strict_service_providers: bool,
    /// Identity provider template used on the root issuer (generic, entra, okta, ...).
    #[arg(long, env = "LOCALSAML_DEFAULT_PRESET")]
    pub default_preset: Option<String>,
    /// Directory where the signing key and state are kept (default ~/.localsaml).
    #[arg(long, env = "LOCALSAML_DATA_DIR")]
    pub data_dir: Option<PathBuf>,
    /// Generate a throwaway signing key on every start.
    #[arg(long)]
    pub ephemeral_keys: bool,
    /// Assertion lifetime in seconds (default: the template's).
    #[arg(long)]
    pub assertion_ttl: Option<i64>,
    /// Session lifetime in seconds.
    #[arg(long)]
    pub session_ttl: Option<i64>,
    /// Run the clock ahead (or, if negative, behind) real time, e.g. 31d, -5m, 3600. Shifts
    /// assertion timestamps and every expiry check. Can be changed at runtime with /dev/api/clock.
    #[arg(long, env = "LOCALSAML_CLOCK_OFFSET", allow_hyphen_values = true, value_parser = crate::util::parse_duration)]
    pub clock_offset: Option<i64>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    host: Option<String>,
    port: Option<u16>,
    base_url: Option<String>,
    dynamic_base_url: Option<bool>,
    entity_id: Option<String>,
    auto_login: Option<bool>,
    silent_sso: Option<bool>,
    strict_service_providers: Option<bool>,
    default_preset: Option<String>,
    data_dir: Option<PathBuf>,
    ephemeral_keys: Option<bool>,
    assertion_ttl: Option<i64>,
    session_ttl: Option<i64>,
    signature_algorithm: Option<SigAlg>,
    service_providers: Vec<ServiceProvider>,
    users: Vec<User>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub base_url: String,
    pub dynamic_base_url: bool,
    /// Entity ID of the root issuer; `None` means `<base_url>/metadata`.
    pub entity_id: Option<String>,
    pub auto_login: bool,
    pub silent_sso: bool,
    pub strict_service_providers: bool,
    pub default_preset: String,
    pub data_dir: Option<PathBuf>,
    pub ephemeral_keys: bool,
    /// Overrides every template's assertion lifetime.
    pub assertion_ttl: Option<i64>,
    pub session_ttl: i64,
    pub signature_algorithm: SigAlg,
    pub service_providers: Vec<ServiceProvider>,
    /// Named identities from `[[users]]`.
    pub users: Vec<User>,
    /// Initial clock offset in seconds (see `crate::clock`).
    pub clock_offset: i64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 9401,
            base_url: "http://localhost:9401".into(),
            dynamic_base_url: false,
            entity_id: None,
            auto_login: false,
            silent_sso: false,
            strict_service_providers: false,
            default_preset: "generic".into(),
            data_dir: None,
            ephemeral_keys: false,
            assertion_ttl: None,
            session_ttl: 8 * 3600,
            signature_algorithm: SigAlg::RsaSha256,
            service_providers: vec![],
            users: vec![],
            clock_offset: 0,
        }
    }
}

impl Config {
    pub fn load(args: &ServerArgs) -> anyhow::Result<Self> {
        let path = args.config.clone().or_else(|| {
            let p = PathBuf::from("localsaml.toml");
            p.exists().then_some(p)
        });
        let file: FileConfig = match &path {
            Some(p) => {
                let raw = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
                toml::from_str(&raw).with_context(|| format!("parsing {}", p.display()))?
            }
            None => FileConfig::default(),
        };
        // Relative metadata files are relative to the config file.
        let config_dir = path.as_ref().and_then(|p| p.parent()).map(PathBuf::from).unwrap_or_default();

        let d = Config::default();
        let port = args.port.or(file.port).unwrap_or(d.port);
        let base_url = args
            .base_url
            .clone()
            .or(file.base_url)
            .unwrap_or_else(|| format!("http://localhost:{port}"))
            .trim_end_matches('/')
            .to_string();
        let default_preset = args.default_preset.clone().or(file.default_preset).unwrap_or(d.default_preset);
        if crate::presets::get(&default_preset).is_none() {
            anyhow::bail!("unknown default preset '{default_preset}'");
        }
        crate::users::validate(&file.users)?;
        let mut service_providers = vec![];
        for mut sp in file.service_providers {
            if let Some(f) = &sp.metadata_file
                && f.is_relative()
            {
                sp.metadata_file = Some(config_dir.join(f));
            }
            sp.load_local_metadata().with_context(|| format!("service provider '{}'", sp.label()))?;
            sp.validate().with_context(|| format!("service provider '{}'", sp.label()))?;
            service_providers.push(sp);
        }
        let data_dir = args
            .data_dir
            .clone()
            .or(file.data_dir)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".localsaml")));

        Ok(Self {
            host: args.host.clone().or(file.host).unwrap_or(d.host),
            port,
            base_url,
            dynamic_base_url: args.dynamic_base_url || file.dynamic_base_url.unwrap_or(false),
            entity_id: args.entity_id.clone().or(file.entity_id),
            auto_login: args.auto_login || file.auto_login.unwrap_or(false),
            silent_sso: args.silent_sso || file.silent_sso.unwrap_or(false),
            strict_service_providers: args.strict_service_providers || file.strict_service_providers.unwrap_or(false),
            default_preset,
            data_dir,
            ephemeral_keys: args.ephemeral_keys || file.ephemeral_keys.unwrap_or(false),
            assertion_ttl: args.assertion_ttl.or(file.assertion_ttl),
            session_ttl: args.session_ttl.or(file.session_ttl).unwrap_or(d.session_ttl),
            signature_algorithm: file.signature_algorithm.unwrap_or_default(),
            service_providers,
            users: file.users,
            clock_offset: args.clock_offset.unwrap_or(0),
        })
    }

    pub fn user(&self, id: &str) -> Option<&User> {
        self.users.iter().find(|u| u.id == id)
    }

    /// The user a login hint refers to, by id, email or NameID.
    pub fn user_for_login(&self, login: &str) -> Option<&User> {
        self.users.iter().find(|u| u.matches(login))
    }
}

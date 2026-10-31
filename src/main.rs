use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use localsaml::config::{Cli, Config};
use localsaml::tenant::Tenant;
use localsaml::{AppState, load_keys, presets, router};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    serve(&Cli::parse().server).await
}

async fn serve(args: &localsaml::config::ServerArgs) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "localsaml=info,tower_http=info".into()))
        .init();

    let config = Config::load(args)?;
    let keys = load_keys(&config)?;
    let addr = format!("{}:{}", config.host, config.port);
    let root = Tenant::new(&config.base_url, None, &config);
    let db = config.data_dir.as_ref().map(|d| d.join("state.db"));
    let state = AppState::new(config, keys)?;
    state.refresh_metadata().await;

    let janitor = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            janitor.purge_expired();
        }
    });

    let listener = tokio::net::TcpListener::bind(&addr).await.with_context(|| format!("binding {addr}"))?;
    tracing::info!("localsaml listening on http://{addr}");
    tracing::info!("entity ID:        {}", root.entity_id);
    tracing::info!("metadata:         {}", root.metadata_url());
    tracing::info!("SSO:              {}", root.sso_url());
    if let Some(db) = db {
        tracing::info!("state:            {}", db.display());
    }
    tracing::info!("test SP:          {}", root.url("/sp"));
    tracing::info!("generator:        {}", root.url("/dev"));
    tracing::info!(
        "template issuers: {}/p/<{}>",
        root.base,
        presets::all().iter().map(|p| p.id).collect::<Vec<_>>().join("|")
    );
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

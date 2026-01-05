//! Main entry point for the adblocker proxy server

use proxy_core::{config::ProxyConfig, server::ProxyServer, Result};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    init_logging();

    info!("Starting adblocker proxy server v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config/default.toml".to_string());
    info!("Loading configuration from: {}", config_path);

    let config = ProxyConfig::from_file(&config_path).map_err(|e| {
        error!("Failed to load configuration: {}", e);
        e
    })?;

    // Create and start the proxy server
    let server = ProxyServer::new(config).map_err(|e| {
        error!("Failed to initialize proxy server: {}", e);
        e
    })?;

    info!("Proxy server initialized successfully");

    // Start the server (this will run until interrupted)
    server.start().await.map_err(|e| {
        error!("Proxy server error: {}", e);
        e
    })?;

    Ok(())
}

/// Initialize tracing subscriber for structured logging
fn init_logging() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_line_number(true)
                .with_file(true)
        )
        .init();
}

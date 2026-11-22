//! Main entry point for the adblocker proxy server

use std::sync::Arc;

use filter_engine::SharedEngine;
use list_service::{ListService, ListServiceConfig};
use proxy_core::{
    config::ProxyConfig, filtering::ProxyContext, server::ProxyServer, upstream::UpstreamOptions,
    Error, Result,
};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    init_logging();

    info!(
        "Starting adblocker proxy server v{}",
        env!("CARGO_PKG_VERSION")
    );

    // Load configuration
    let config_path =
        std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config/default.toml".to_string());
    info!("Loading configuration from: {}", config_path);

    let config = ProxyConfig::from_file(&config_path).map_err(|e| {
        error!("Failed to load configuration: {}", e);
        e
    })?;

    // Shared compiled filter engine. The real adblock engine is !Send, so it lives thread-locally
    // per worker; this handle shares the compiled rules as bytes between the proxy and the web API.
    let shared_engine = Arc::new(SharedEngine::new());
    shared_engine.set_enabled(config.adblock.enabled);

    // One pooled upstream client (connect/read timeouts from config, no redirect following).
    let ctx = Arc::new(ProxyContext::with_upstream(
        shared_engine.clone(),
        &UpstreamOptions::from_config(&config),
        config.adblock.enabled,
    )?);

    // Create the proxy server
    let server = ProxyServer::new(config.clone(), ctx.clone()).map_err(|e| {
        error!("Failed to initialize proxy server: {}", e);
        e
    })?;

    info!("Proxy server initialized successfully");

    // Filter lists: always on, independent of the web UI. Starts in the background (cached rules
    // first, then a refresh), so the proxy accepts connections immediately.
    let list_service = ListService::open(
        ListServiceConfig::from_adblock(&config.adblock),
        shared_engine.clone(),
    )
    .map_err(|e| Error::Config(format!("Failed to open filter list service: {e}")))?;
    list_service.start();

    // Start web UI server if enabled
    #[cfg(feature = "webui")]
    let webui_handle = if config.webui.enabled {
        Some(
            start_webui_server(
                &config,
                config_path.clone(),
                shared_engine.clone(),
                list_service,
                ctx.request_timeout_handle(),
            )
            .await?,
        )
    } else {
        info!("Web UI disabled in configuration");
        None
    };

    // Start the proxy server (this will run until interrupted)
    let proxy_result = server.start().await;

    // Cleanup web UI server if running
    #[cfg(feature = "webui")]
    if let Some(handle) = webui_handle {
        handle.abort();
    }

    proxy_result.map_err(|e| {
        error!("Proxy server error: {}", e);
        e
    })?;

    Ok(())
}

/// Start the Web UI API server
#[cfg(feature = "webui")]
async fn start_webui_server(
    config: &ProxyConfig,
    config_path: String,
    shared_engine: Arc<SharedEngine>,
    list_service: Arc<ListService>,
    request_timeout_ms: Arc<std::sync::atomic::AtomicU64>,
) -> Result<tokio::task::JoinHandle<()>> {
    use tracing::warn;
    use userscript_engine::{UserscriptManager, UserscriptRuntime};
    use web_api::{build_state, start_server, ApiConfig};

    info!("Initializing Web UI server...");

    // One database file per process: users, sessions, tokens, audit and userscripts share
    // `<adblock.data_dir>/adblocker.redb` with the filter lists.
    let data_dir = config.adblock.data_dir.clone();

    // Initialize userscript manager
    let userscript_manager = if config.userscripts.enabled {
        info!(
            "Initializing userscript manager with data dir: {:?}",
            data_dir
        );
        Arc::new(UserscriptManager::new(data_dir.clone()).map_err(|e| {
            proxy_core::Error::Config(format!("Failed to initialize userscript manager: {}", e))
        })?)
    } else {
        info!("Userscripts disabled, using empty userscript manager");
        Arc::new(UserscriptManager::new(data_dir.clone()).map_err(|e| {
            proxy_core::Error::Config(format!("Failed to initialize userscript manager: {}", e))
        })?)
    };

    // Load existing userscripts
    if let Err(e) = userscript_manager.load_all() {
        warn!("Failed to load userscripts: {}", e);
    }

    // Create userscript runtime
    let storage = userscript_manager.storage_arc();
    let userscript_runtime = Arc::new(UserscriptRuntime::new(
        Arc::clone(&userscript_manager),
        storage,
    ));

    // Build API configuration from proxy config
    let api_config = ApiConfig {
        server: web_api::config::ServerConfig {
            host: config.webui.host.clone(),
            port: config.webui.port,
            workers: 0, // Auto-detect
        },
        auth: web_api::config::AuthConfig {
            jwt_secret_path: config.webui.jwt_secret_path.clone(),
            access_token_expiry_seconds: 900,     // 15 minutes
            refresh_token_expiry_seconds: 604800, // 7 days
            bcrypt_cost: 12,
            issuer: "adblocker-api".to_string(),
            audience: "adblocker-ui".to_string(),
        },
        rate_limit: web_api::config::RateLimitConfig {
            global_requests_per_minute: config.webui.rate_limit_global_rpm,
            ip_requests_per_minute: config.webui.rate_limit_ip_rpm,
            user_requests_per_minute: config.webui.rate_limit_user_rpm,
        },
        security: web_api::config::SecurityConfig {
            enable_csrf: true,
            require_https: false,
            cors_origins: config.webui.cors_origins.clone(),
            cookie_secure: false,
        },
        session: web_api::config::SessionConfig {
            storage_path: data_dir.clone(),
            cleanup_interval_seconds: 3600,
        },
        webui: web_api::config::WebUiConfig {
            enabled: true,
            dist_path: std::env::var("WEBUI_DIST_PATH")
                .unwrap_or_else(|_| "webui".to_string())
                .into(),
        },
        ..Default::default()
    };

    // Build the application state
    let state = build_state(
        api_config.clone(),
        config.clone(),
        shared_engine,
        list_service,
        reqwest::Client::new(),
        userscript_manager,
        userscript_runtime,
        config_path.into(),
        request_timeout_ms,
    )
    .await
    .map_err(|e| proxy_core::Error::Config(format!("Failed to build web API state: {}", e)))?;

    info!(
        "Web UI API server starting on {}:{}",
        api_config.server.host, api_config.server.port
    );

    // Spawn the web server in a background task
    let handle = tokio::spawn(async move {
        if let Err(e) = start_server(state, api_config).await {
            error!("Web UI API server error: {}", e);
        }
    });

    Ok(handle)
}

/// Initialize tracing subscriber for structured logging
fn init_logging() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_line_number(true)
                .with_file(true),
        )
        .init();
}

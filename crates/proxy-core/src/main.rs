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
    // Held to the end of `main` so buffered log lines are flushed on exit.
    let _log_guard = init_logging();

    info!(
        "Starting adblocker proxy server v{}",
        env!("CARGO_PKG_VERSION")
    );

    // Load configuration
    let config_path =
        std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config/default.toml".to_string());
    // Raise the soft descriptor limit before anything derives a budget from it.
    common::config::raise_nofile_limit();
    info!("Loading configuration from: {}", config_path);

    let config = ProxyConfig::from_file(&config_path).map_err(|e| {
        error!("Failed to load configuration: {}", e);
        e
    })?;

    // Shared compiled filter engine. The real adblock engine is !Send, so it lives thread-locally
    // per worker; this handle shares the compiled rules as bytes between the proxy and the web API.
    let shared_engine = Arc::new(SharedEngine::new());
    shared_engine.set_enabled(config.adblock.enabled);
    shared_engine.set_recent_keep_query(config.adblock.recent_blocked_keep_query);

    // One pooled upstream client (connect/read timeouts from config, no redirect following).
    let ctx = Arc::new(ProxyContext::with_upstream(
        shared_engine.clone(),
        &UpstreamOptions::from_config(&config),
        config.adblock.enabled,
    )?);

    ctx.set_respect_no_transform(config.adblock.respect_no_transform);

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

    // Userscripts: one manager (one database, one live index) shared by the proxy's injection
    // and GM endpoints and by the management API. The proxy only uses it when enabled.
    #[cfg(feature = "webui")]
    let need_manager = config.userscripts.enabled || config.webui.enabled;
    #[cfg(not(feature = "webui"))]
    let need_manager = config.userscripts.enabled;
    let userscript_manager = if need_manager {
        let m = Arc::new(
            userscript_engine::UserscriptManager::new(config.adblock.data_dir.clone()).map_err(
                |e| Error::Config(format!("Failed to initialize userscript manager: {e}")),
            )?,
        );
        if let Err(e) = m.load_all() {
            tracing::warn!("Failed to load userscripts: {e}");
        }
        Some(m)
    } else {
        None
    };
    ctx.set_service_worker_policy(config.userscripts.service_worker_policy);
    if config.userscripts.enabled {
        ctx.set_userscripts(userscript_manager.clone());
    } else {
        info!("Userscripts disabled: scripts are managed but never injected");
    }

    // One database file per process; profiles, devices and script policy live in it.
    let db = common::db::Db::open(&config.adblock.data_dir)
        .map_err(|e| Error::Config(format!("Failed to open database: {e}")))?;
    let profile_store = Arc::new(
        common::profile_store::ProfileStore::open(&db)
            .map_err(|e| Error::Config(format!("Failed to open profile store: {e}")))?,
    );

    // In-page panel: reserved confirmation host, per-site blocking over the custom rules.
    {
        let sc = &config.script_control;
        let dashboard = if !sc.dashboard_url.is_empty() {
            sc.dashboard_url.clone()
        } else if config.webui.enabled
            && !matches!(config.webui.host.as_str(), "0.0.0.0" | "::" | "[::]")
        {
            format!("http://{}:{}", config.webui.host, config.webui.port)
        } else {
            String::new()
        };
        let host = proxy_core::authority::normalize_host(&sc.panel_host).ok_or_else(|| {
            Error::Config(format!(
                "script_control.panel_host '{}' is not a host name",
                sc.panel_host
            ))
        })?;
        if !host.ends_with(".invalid") {
            return Err(Error::Config(format!(
                "script_control.panel_host '{host}' must end in .invalid (a name no real site can claim)"
            )));
        }
        ctx.configure_panel(
            proxy_core::panel::PanelConfig {
                enabled: sc.panel_enabled,
                host,
                dashboard_url: dashboard,
            },
            Some(Arc::new(proxy_core::panel::ListSiteBlocking::new(
                list_service.clone(),
                Some(profile_store.clone()),
            ))),
        );
    }

    // Script control: rules live in the shared database; the proxy path reads a compiled snapshot
    // that is rebuilt on every edit and when a temporary grant expires.
    let policy_store = Arc::new(script_policy::store::PolicyStore::new(db.clone()));
    let script_control = proxy_core::scriptctl::ScriptControl::new(
        policy_store.clone(),
        script_policy::DEFAULT_PROFILE,
    );
    script_control.spawn_expiry();
    ctx.set_script_control(Some(script_control));

    // Per-device profiles: compiles stored profiles and devices into the live lookup table in
    // the background (also without the web UI). The web API reads them through
    // `ctx.profile_store()` / `ctx.profile_builder()`.
    let profile_builder = proxy_core::ProfileBuilder::start(proxy_core::BuilderDeps {
        ctx: ctx.clone(),
        store: profile_store.clone(),
        lists: list_service.clone(),
        manager: userscript_manager.clone(),
        policy: Some(policy_store.clone()),
        debounce: proxy_core::profile_build::DEFAULT_DEBOUNCE,
    });
    ctx.set_profile_service(profile_store.clone(), profile_builder.clone());

    // Start web UI server if enabled
    #[cfg(feature = "webui")]
    let webui_handle = if config.webui.enabled {
        Some(
            start_webui_server(
                &config,
                config_path.clone(),
                shared_engine.clone(),
                list_service,
                &ctx,
                userscript_manager
                    .clone()
                    .expect("manager exists when the web UI is enabled"),
                policy_store.clone(),
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
        // Wait for the task to wind down so it no longer holds the database.
        let _ = handle.await;
    }

    // Commit queued background writes and fsync before exiting; do not rely on the drop order
    // of `Arc`s held by aborted tasks.
    common::db::Db::sync_all();

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
    ctx: &Arc<ProxyContext>,
    userscript_manager: Arc<userscript_engine::UserscriptManager>,
    policy_store: Arc<script_policy::store::PolicyStore>,
) -> Result<tokio::task::JoinHandle<()>> {
    use web_api::{start_server, ApiConfig};

    info!("Initializing Web UI server...");

    // One database file per process: users, sessions, tokens, audit and userscripts share
    // `<adblock.data_dir>/adblocker.redb` with the filter lists.
    let data_dir = config.adblock.data_dir.clone();

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
            cookie_secure: config.webui.cookie_secure,
        },
        network: web_api::config::NetworkConfig {
            trusted_proxies: config.webui.trusted_proxies.clone(),
            ..Default::default()
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

    // Build the application state over the proxy's own stores (profiles, policy, userscripts).
    let state = proxy_core::webui::build_api_state(
        ctx,
        proxy_core::webui::ApiInputs {
            api_config: api_config.clone(),
            proxy_config: config.clone(),
            shared_engine,
            list_service,
            manager: userscript_manager,
            policy: policy_store,
            config_path: config_path.into(),
        },
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

/// Initialize tracing: formatted events go through a non-blocking writer, so a slow or blocked
/// stdout never stalls a request task (lines are dropped, not blocked on, if the buffer fills).
/// File, line and thread ids are off by default; set `ADBLOCKER_LOG_VERBOSE=1` to add them.
fn init_logging() -> tracing_appender::non_blocking::WorkerGuard {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let verbose = std::env::var_os("ADBLOCKER_LOG_VERBOSE").is_some_and(|v| v != "0");
    let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_target(true)
                .with_thread_ids(verbose)
                .with_line_number(verbose)
                .with_file(verbose),
        )
        .init();
    guard
}

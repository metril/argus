//! Main entry point for the argus proxy server

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
    // `argus --version`: lets image builds smoke-test that the binary loads and starts.
    if std::env::args()
        .nth(1)
        .is_some_and(|a| a == "--version" || a == "-V")
    {
        println!("argus {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Initialize logging
    // Held to the end of `main` so buffered log lines are flushed on exit.
    let _log_guard = init_logging();
    // Emits the one-time deprecation warning now that logging is up.
    let _ = common::env::var_os("LOG_VERBOSE");

    info!("Starting Argus proxy server v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config_path =
        std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config/default.toml".to_string());
    // Raise the soft descriptor limit before anything derives a budget from it.
    common::config::raise_nofile_limit();
    info!("Loading configuration from: {}", config_path);

    // The shipped file is the read-only base; settings saved from the web UI live in an overlay
    // on the data volume and win over it.
    let base_path = std::path::PathBuf::from(&config_path);
    let base = ProxyConfig::from_file(&config_path).map_err(|e| {
        error!("Failed to load configuration: {}", e);
        e
    })?;
    let overlay_path = common::config::default_overlay_path(&base.adblock.data_dir);
    let config = ProxyConfig::load_layered(&base_path, &overlay_path).map_err(|e| {
        error!("Failed to load settings overlay: {}", e);
        e
    })?;
    if overlay_path.exists() {
        info!("Applied saved settings from {}", overlay_path.display());
    }

    // Shared compiled filter engine. The real adblock engine is !Send, so it lives thread-locally
    // per worker; this handle shares the compiled rules as bytes between the proxy and the web API.
    let shared_engine = Arc::new(SharedEngine::new());
    shared_engine.set_enabled(config.adblock.enabled);
    shared_engine.set_recent_keep_query(config.adblock.recent_blocked_keep_query);

    // One pooled upstream client (connect/read timeouts from config, no redirect following).
    let upstream_opts = UpstreamOptions::from_config(&config);
    // The same caching resolver also serves the control plane (list and resource fetches); each
    // fetch still applies its own, stricter policy to the addresses.
    if let Some(dns) = &upstream_opts.dns {
        common::net_policy::install_shared_resolver(Arc::new(proxy_core::dns::DnsHandle(
            dns.clone(),
        )));
    }
    let ctx = Arc::new(ProxyContext::with_upstream(
        shared_engine.clone(),
        &upstream_opts,
        config.adblock.enabled,
    )?);

    ctx.set_respect_no_transform(config.adblock.respect_no_transform);
    ctx.set_guard_service_workers(config.adblock.guard_service_workers);
    ctx.set_guard_service_workers_exempt(config.adblock.guard_service_workers_exempt.clone());

    // Hosts excluded from interception / filtering: built-in categories plus the user's own
    // entries and subscriptions, persisted next to the settings overlay.
    let bypass_path = overlay_path
        .parent()
        .map_or_else(|| "bypass.json".into(), |p| p.join("bypass.json"));
    let bypass_engine = Arc::new(common::bypass::BypassEngine::load(bypass_path));
    #[cfg(feature = "webui")]
    let bypass_for_api = bypass_engine.clone();
    ctx.set_bypass(bypass_engine.clone());

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

    // First-party bypass lists: loaded from the verified cache, then fetched right away. Until
    // every enabled list has loaded once, HTTPS is tunnelled rather than decrypted.
    let argus = list_service::ArgusLists::new(
        bypass_engine.clone(),
        list_service.clone(),
        list_service::ArgusConfig::from_config(
            &config.bypass,
            bypass_engine.data_dir().map(|d| d.join("argus-lists")),
        ),
    );
    argus.start();

    // Signed catalogues of filter lists and userscripts (same release, same key).
    let catalogue_cfg = list_service::ArgusConfig::from_config(
        &config.bypass,
        bypass_engine.data_dir().map(|d| d.join("argus-lists")),
    );
    let filter_catalogue = list_service::SignedDoc::<list_service::FilterCatalogueEntry>::new(
        "filters",
        Some(list_service.clone()),
        catalogue_cfg.clone(),
    );
    filter_catalogue.start();
    let userscript_catalogue =
        list_service::SignedDoc::<list_service::UserscriptCatalogueEntry>::new(
            "userscripts",
            Some(list_service.clone()),
            catalogue_cfg,
        );
    userscript_catalogue.start();

    // Trusted roots: the compiled-in set until a signed one (same release, same key) has been
    // verified; then swapped in live.
    #[cfg_attr(not(feature = "webui"), allow(unused_variables))]
    let roots_manager = ctx.roots().map(|roots| {
        let m = proxy_core::roots::RootsManager::new(
            roots.clone(),
            list_service.clone(),
            &list_service::ArgusConfig::from_config(
                &config.bypass,
                bypass_engine.data_dir().map(|d| d.join("argus-lists")),
            ),
        );
        m.start();
        m
    });

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

    #[cfg(feature = "webui")]
    let control = server.control();

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
                control,
                bypass_for_api,
                argus.clone(),
                roots_manager,
                (filter_catalogue.clone(), userscript_catalogue.clone()),
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
    ctx.internal().gm.ext().persist_now();
    common::db::Db::sync_all();

    proxy_result.map_err(|e| {
        error!("Proxy server error: {}", e);
        e
    })?;

    Ok(())
}

/// Start the Web UI API server
#[cfg(feature = "webui")]
#[allow(clippy::too_many_arguments)]
async fn start_webui_server(
    config: &ProxyConfig,
    config_path: String,
    shared_engine: Arc<SharedEngine>,
    list_service: Arc<ListService>,
    ctx: &Arc<ProxyContext>,
    userscript_manager: Arc<userscript_engine::UserscriptManager>,
    policy_store: Arc<script_policy::store::PolicyStore>,
    control: Arc<proxy_core::server::ProxyControl>,
    bypass: Arc<common::bypass::BypassEngine>,
    argus: Arc<list_service::ArgusLists>,
    roots_manager: Option<Arc<proxy_core::roots::RootsManager>>,
    catalogues: (
        Arc<list_service::SignedDoc<list_service::FilterCatalogueEntry>>,
        Arc<list_service::SignedDoc<list_service::UserscriptCatalogueEntry>>,
    ),
) -> Result<tokio::task::JoinHandle<()>> {
    use web_api::{start_server, ApiConfig};

    info!("Initializing Web UI server...");

    // One database file per process: users, sessions, tokens, audit and userscripts share
    // `<adblock.data_dir>/argus.redb` with the filter lists.
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
            issuer: "argus-api".to_string(),
            audience: "argus-ui".to_string(),
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

    let _ = state
        .runtime
        .set(Arc::new(proxy_core::webui::ProxyRuntime(control)));
    let _ = state.bypass.set(bypass);
    let _ = state.argus.set(argus);
    let _ = state.filter_catalogue.set(catalogues.0);
    let _ = state.userscript_catalogue.set(catalogues.1);
    // The lists location and key follow the live config (editable in the UI), not the one read at
    // startup.
    state.follow_live_catalogue_config();
    if let Some(m) = roots_manager {
        let (w, fb) = (Arc::downgrade(&state), state.catalogue_cfg());
        m.set_config_source(move || {
            w.upgrade()
                .map_or_else(|| fb.clone(), |s| s.catalogue_cfg())
        });
        state.on_lists_config_changed(move || m.nudge());
    }

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

/// Initialize tracing. Info, debug and trace lines go through a lossy non-blocking writer, so a
/// slow or blocked stdout never stalls a request task (lines are dropped if the buffer fills).
/// Warnings and errors use a separate non-lossy writer: they are rare (and rate-limited at
/// their sources), and must not vanish under exactly the load that causes them.
/// File, line and thread ids are off by default; set `ARGUS_LOG_VERBOSE=1` to add them.
fn init_logging() -> Vec<tracing_appender::non_blocking::WorkerGuard> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let verbose = common::env::peek_os("LOG_VERBOSE").is_some_and(|v| v != "0");
    let (lossy, g1) = tracing_appender::non_blocking(std::io::stdout());
    let (strict, g2) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(false)
        .finish(std::io::stdout());
    build_subscriber(env_filter, lossy, strict, verbose).init();
    vec![g1, g2]
}

/// Whether a level goes to the lossy writer (everything below WARN).
fn is_lossy_level(level: &tracing::Level) -> bool {
    *level > tracing::Level::WARN
}

fn build_subscriber<L, S>(
    env_filter: EnvFilter,
    lossy: L,
    strict: S,
    verbose: bool,
) -> impl tracing::Subscriber + Send + Sync
where
    L: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
    S: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    use tracing_subscriber::filter::filter_fn;
    use tracing_subscriber::Layer;
    macro_rules! fmt {
        ($w:expr) => {
            tracing_subscriber::fmt::layer()
                .with_writer($w)
                .with_target(true)
                .with_thread_ids(verbose)
                .with_line_number(verbose)
                .with_file(verbose)
        };
    }
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt!(lossy).with_filter(filter_fn(|m| is_lossy_level(m.level()))))
        .with(fmt!(strict).with_filter(filter_fn(|m| !is_lossy_level(m.level()))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }
    /// A writer that loses everything, like a full lossy channel.
    #[derive(Clone)]
    struct Drop_;
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Drop_ {
        type Writer = std::io::Sink;
        fn make_writer(&'a self) -> std::io::Sink {
            std::io::sink()
        }
    }

    #[test]
    fn warnings_and_errors_never_use_the_lossy_writer() {
        let strict = Buf::default();
        let sub = build_subscriber(EnvFilter::new("debug"), Drop_, strict.clone(), false);
        tracing::subscriber::with_default(sub, || {
            tracing::info!("chatter");
            tracing::debug!("detail");
            tracing::warn!("rejected 5 connections");
            tracing::error!("boom");
        });
        let out = String::from_utf8(strict.0.lock().unwrap().clone()).unwrap();
        assert!(
            out.contains("rejected 5 connections") && out.contains("boom"),
            "{out}"
        );
        assert!(!out.contains("chatter") && !out.contains("detail"), "{out}");
    }
}

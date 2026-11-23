//! Axum web server setup: the versioned API, docs UI, static web UI and global middleware.

use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use axum::{
    extract::Request, middleware, middleware::Next, response::Response, routing::any, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::{
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use utoipa_axum::router::OpenApiRouter;
use utoipa_swagger_ui::{Config, SwaggerUi};

use crate::auth::authz::authorize;
use crate::config::ApiConfig;
use crate::error::{envelope, ApiError};
use crate::middleware::{audit_middleware, rate_limit_middleware, request_id_middleware};
use crate::openapi::{finalize, ApiDoc};
use crate::routes::{api_router, API_PREFIX};
use crate::state::AppState;

/// Build the OpenAPI document and route table for an assembled router. Exposed so tests can
/// exercise registration of arbitrary routers.
pub fn build_api(
    router: OpenApiRouter<Arc<AppState>>,
) -> (
    Router<Arc<AppState>>,
    serde_json::Value,
    crate::auth::authz::RouteTable,
) {
    let (router, spec) = OpenApiRouter::with_openapi(<ApiDoc as utoipa::OpenApi>::openapi())
        .nest(API_PREFIX, router)
        .split_for_parts();
    let (doc, table) = finalize(spec);
    (router, doc, table)
}

async fn api_not_found() -> ApiError {
    ApiError::NotFound("No such API route".into())
}

/// Give bodiless 405s the standard error envelope.
async fn normalize_errors(req: Request, next: Next) -> Response {
    let resp = next.run(req).await;
    if resp.status() == StatusCode::METHOD_NOT_ALLOWED
        && !resp.headers().contains_key(header::CONTENT_TYPE)
    {
        let allow = resp.headers().get(header::ALLOW).cloned();
        let mut r = envelope(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "Method not allowed",
        );
        if let Some(a) = allow {
            r.headers_mut().insert(header::ALLOW, a);
        }
        return r;
    }
    resp
}

/// Create the Axum router with all routes and middleware
pub fn create_router(state: Arc<AppState>, config: &ApiConfig) -> Router {
    create_router_with(state, config, api_router())
}

/// [`create_router`] over an explicit route set (tests add routes to prove deny-by-default).
pub fn create_router_with(
    state: Arc<AppState>,
    config: &ApiConfig,
    api: OpenApiRouter<Arc<AppState>>,
) -> Router {
    let (routes, doc, table) = build_api(api);
    if !table.undeclared.is_empty() || !table.invalid.is_empty() {
        tracing::error!(
            "Routes without a valid authorization declaration (denied by default): {:?} {:?}",
            table.undeclared,
            table.invalid
        );
    }
    let _ = state.spec_json.set(doc.to_string());
    let _ = state.route_auth.set(table);

    // Authorization is a `route_layer`: it only runs for matched routes and sees `MatchedPath`.
    let api = routes
        .route_layer(middleware::from_fn_with_state(state.clone(), authorize))
        .with_state(state.clone());

    let docs: Router = SwaggerUi::new(format!("{API_PREFIX}/docs"))
        .config(Config::from(format!("{API_PREFIX}/openapi.json")))
        .into();

    let mut router = Router::new()
        .merge(api)
        .merge(docs)
        .route("/api/{*rest}", any(api_not_found));

    if config.webui.enabled {
        let dist_path = &config.webui.dist_path;
        if dist_path.exists() {
            let index_file = dist_path.join("index.html");
            // Client-side routes (`/userscripts`, `/logs`, ...) have no file: they get the app
            // shell with 200 so a deep link or a reload works. A missing asset (a path with a
            // file extension) is still a real 404.
            let spa = ServeFile::new(&index_file);
            let serve_dir =
                ServeDir::new(dist_path).fallback(tower::service_fn(move |req: Request| {
                    let mut spa = spa.clone();
                    async move {
                        use tower::Service;
                        let last = req.uri().path().rsplit('/').next().unwrap_or("");
                        if last.contains('.') {
                            return Ok::<_, std::convert::Infallible>(
                                StatusCode::NOT_FOUND.into_response(),
                            );
                        }
                        let resp = spa.call(req).await.unwrap_or_else(|e| match e {});
                        Ok(resp.map(axum::body::Body::new))
                    }
                }));
            router = router.fallback_service(serve_dir);
            tracing::info!("WebUI static files enabled from {:?}", dist_path);
        } else {
            tracing::warn!(
                "WebUI dist path {:?} does not exist, static files disabled",
                dist_path
            );
        }
    }

    // Layers: last added = outermost.
    if let Some(cors) = build_cors_layer(&config.security.cors_origins) {
        router = router.layer(cors);
    }
    router
        .layer(middleware::from_fn_with_state(
            state.clone(),
            audit_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(middleware::from_fn(normalize_errors))
        .layer(middleware::from_fn_with_state(state, request_id_middleware))
}

/// How long the old web listener keeps answering after a rebind (the response that asked for
/// the move, and the page that is about to redirect).
const OLD_LISTENER_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// The web API's listener, replaceable at runtime.
pub struct WebServer {
    router: Router,
    current: tokio::sync::Mutex<Current>,
    /// Test hook: make restoring the old listener fail.
    #[cfg(any(test, feature = "test-hooks"))]
    fail_restore: std::sync::atomic::AtomicBool,
    /// Source of unique serve-task generations.
    gens: std::sync::atomic::AtomicU64,
    /// Finished serve tasks: `(generation, result)`.
    done_tx: tokio::sync::mpsc::UnboundedSender<(u64, Result<(), String>)>,
    done_rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<(u64, Result<(), String>)>>,
}

struct Current {
    gen: u64,
    addr: SocketAddr,
    /// Host and port as requested (to tell a no-op from a move).
    requested: (String, u16),
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    /// Nothing listens (a move failed and the old listener could not be restored).
    down: bool,
    /// The listener this one replaced, still serving until its grace period ends.
    previous: Option<Previous>,
}

/// The replaced listener, kept so a failed save can put it back.
struct Previous {
    gen: u64,
    addr: SocketAddr,
    requested: (String, u16),
    /// Shared with the timer that stops it after the grace period.
    stop: Arc<parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    timer: tokio::task::JoinHandle<()>,
}

impl Previous {
    /// Stop it now.
    fn end(self) {
        self.timer.abort();
        if let Some(tx) = self.stop.lock().take() {
            let _ = tx.send(());
        }
    }
}

fn spec_addr(host: &str, port: u16) -> String {
    let host = host.trim_matches(['[', ']']);
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Bind `addr`, retrying while it is still held (a just-stopped listener releases its socket
/// a moment after the stop signal).
async fn bind_retry(addr: &str, retry_in_use: bool) -> std::io::Result<tokio::net::TcpListener> {
    let mut bound = tokio::net::TcpListener::bind(addr).await;
    if retry_in_use {
        for _ in 0..50 {
            match &bound {
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    bound = tokio::net::TcpListener::bind(addr).await;
                }
                _ => break,
            }
        }
    }
    bound
}

impl WebServer {
    fn new(
        router: Router,
        listener: tokio::net::TcpListener,
        requested: (String, u16),
    ) -> Arc<Self> {
        let (done_tx, done_rx) = tokio::sync::mpsc::unbounded_channel();
        let srv = Arc::new(Self {
            router,
            current: tokio::sync::Mutex::new(Current {
                gen: 0,
                addr: listener
                    .local_addr()
                    .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))),
                requested,
                stop: None,
                down: false,
                previous: None,
            }),
            gens: std::sync::atomic::AtomicU64::new(1),
            #[cfg(any(test, feature = "test-hooks"))]
            fail_restore: std::sync::atomic::AtomicBool::new(false),
            done_tx,
            done_rx: tokio::sync::Mutex::new(done_rx),
        });
        let stop = srv.spawn_serve(listener, 0);
        srv.current.try_lock().expect("fresh lock").stop = Some(stop);
        srv
    }

    fn next_gen(&self) -> u64 {
        self.gens.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Serve on `listener` until the returned sender fires (graceful: in-flight requests finish,
    /// but a lingering stream is cut after [`OLD_LISTENER_GRACE`]).
    fn spawn_serve(
        self: &Arc<Self>,
        listener: tokio::net::TcpListener,
        gen: u64,
    ) -> tokio::sync::oneshot::Sender<()> {
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let app = self
            .router
            .clone()
            .into_make_service_with_connect_info::<SocketAddr>();
        let done = self.done_tx.clone();
        tokio::spawn(async move {
            let (grace_tx, grace_rx) = tokio::sync::oneshot::channel::<()>();
            let serve = axum::serve(listener, app).with_graceful_shutdown(async move {
                let _ = stop_rx.await;
                let _ = grace_tx.send(());
            });
            let result = tokio::select! {
                r = serve => r.map_err(|e| e.to_string()),
                // After a stop request, give the old listener its grace period, then drop it.
                _ = async { let _ = grace_rx.await; tokio::time::sleep(OLD_LISTENER_GRACE).await } => Ok(()),
            };
            let _ = done.send((gen, result));
        });
        stop_tx
    }

    /// Current listening address (the last one, while [`Self::is_down`]).
    pub async fn addr(&self) -> SocketAddr {
        self.current.lock().await.addr
    }

    /// Whether a restore must fail (test hook; always false in release builds).
    fn restore_fails(&self) -> bool {
        #[cfg(any(test, feature = "test-hooks"))]
        {
            self.fail_restore.load(std::sync::atomic::Ordering::Relaxed)
        }
        #[cfg(not(any(test, feature = "test-hooks")))]
        {
            false
        }
    }

    /// Test hook: make restoring the old listener after a failed move fail.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn __fail_restores(&self, on: bool) {
        self.fail_restore
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// Nothing is listening: a move failed and so did restoring the old listener. Another
    /// `rebind` brings it back.
    pub async fn is_down(&self) -> bool {
        self.current.lock().await.down
    }

    /// Listen on `host:port` instead. The new socket is bound first; on failure nothing
    /// changes. The old listener keeps serving for 30 seconds (or until [`Self::revert`]).
    pub async fn rebind(self: &Arc<Self>, host: &str, port: u16) -> Result<SocketAddr, String> {
        let mut cur = self.current.lock().await;
        if port != 0 && !cur.down && cur.requested == (host.to_string(), port) {
            return Ok(cur.addr);
        }
        let a = spec_addr(host, port);
        // Same port, other host: the old socket still holds the port, so it is closed first
        // (existing connections, including the one asking for this move, keep running) and
        // restored if the new bind fails.
        let colliding = port != 0 && !cur.down && cur.addr.port() == port;
        let old = (cur.addr, cur.requested.clone());
        if colliding {
            if let Some(tx) = cur.stop.take() {
                let _ = tx.send(());
            }
            // Its completion is a stop we asked for, not the server ending.
            cur.gen = self.next_gen();
            cur.down = true;
            if let Some(p) = cur.previous.take() {
                p.end();
            }
        }
        let listener = match bind_retry(&a, colliding).await {
            Ok(l) => l,
            Err(e) => {
                if colliding {
                    // Roll back: serve on the old address again.
                    let restored = if self.restore_fails() {
                        Err(std::io::Error::other("injected restore failure"))
                    } else {
                        bind_retry(&old.0.to_string(), true).await
                    };
                    match restored {
                        Ok(l) => {
                            cur.gen = self.next_gen();
                            let gen = cur.gen;
                            cur.stop = Some(self.spawn_serve(l, gen));
                            cur.down = false;
                        }
                        Err(re) => {
                            tracing::error!("could not restore web listener on {}: {re}", old.0);
                            // Marked down, with no stale request that would look like a no-op.
                            cur.requested = (String::new(), 0);
                            return Err(format!(
                                "cannot bind the web API to {a}: {e}; the old listener could not be restored, retry"
                            ));
                        }
                    }
                }
                return Err(format!("cannot bind the web API to {a}: {e}"));
            }
        };
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let gen = self.next_gen();
        let stop = self.spawn_serve(listener, gen);
        // The replaced listener keeps accepting for the grace period, then stops gracefully;
        // `revert` can take it back before that.
        if let Some(p) = cur.previous.take() {
            p.end();
        }
        if let Some(old_stop) = cur.stop.take().filter(|_| !colliding) {
            let shared = Arc::new(parking_lot::Mutex::new(Some(old_stop)));
            let s2 = shared.clone();
            let timer = tokio::spawn(async move {
                tokio::time::sleep(OLD_LISTENER_GRACE).await;
                if let Some(tx) = s2.lock().take() {
                    let _ = tx.send(());
                }
            });
            cur.previous = Some(Previous {
                gen: cur.gen,
                addr: cur.addr,
                requested: cur.requested.clone(),
                stop: shared,
                timer,
            });
        }
        cur.stop = Some(stop);
        cur.gen = gen;
        cur.addr = addr;
        cur.requested = (host.to_string(), port);
        cur.down = false;
        tracing::info!("Web API now listening on {addr}; the old listener closes after 30s");
        Ok(addr)
    }

    /// Undo the last [`Self::rebind`] (a save failed after it): cancel the pending stop of the
    /// old listener and make it current again, closing the new one. Returns `None` when the old
    /// listener is already gone, in which case the caller rebinds the old address instead.
    pub async fn revert(&self) -> Option<SocketAddr> {
        let mut cur = self.current.lock().await;
        let prev = cur.previous.take()?;
        prev.timer.abort();
        let tx = prev.stop.lock().take()?;
        if let Some(new_stop) = cur.stop.take() {
            let _ = new_stop.send(());
        }
        cur.stop = Some(tx);
        cur.gen = prev.gen;
        cur.addr = prev.addr;
        cur.requested = prev.requested;
        cur.down = false;
        Some(cur.addr)
    }

    /// Resolves when the current listener's server ends on its own (an error, or never).
    async fn wait(&self) -> crate::error::ApiResult<()> {
        let mut rx = self.done_rx.lock().await;
        while let Some((gen, result)) = rx.recv().await {
            let cur = self.current.lock().await;
            if gen == cur.gen && !cur.down {
                return result.map_err(ApiError::Internal);
            }
        }
        Ok(())
    }
}

/// Start the web server
pub async fn start_server(state: Arc<AppState>, config: ApiConfig) -> crate::error::ApiResult<()> {
    let addr = spec_addr(&config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Web API server listening on {}", addr);
    warn_if_exposed_without_tls(&config);

    let sessions = state.session_manager.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tick.tick().await;
            let s = sessions.clone();
            match tokio::task::spawn_blocking(move || s.purge_expired()).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => tracing::warn!("session purge failed: {e}"),
                Err(e) => tracing::warn!("session purge task failed: {e}"),
            }
        }
    });

    spawn_userscript_update_checks(state.clone());
    spawn_timeseries_sampler(state.clone());
    spawn_bypass_refresher(state.clone());

    let router = create_router(state.clone(), &config);
    let server = WebServer::new(
        router,
        listener,
        (config.server.host.clone(), config.server.port),
    );
    let _ = state.web_server.set(server.clone());
    server.wait().await
}

/// Refresh bypass subscriptions on the filter lists' schedule.
fn spawn_bypass_refresher(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(crate::handlers::bypass::REFRESH_TICK);
        loop {
            tick.tick().await;
            crate::handlers::bypass::refresh_due(&state).await;
        }
    });
}

/// Feed the request/block counters into the time series every 15 seconds.
fn spawn_timeseries_sampler(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            tick.tick().await;
            state.timeseries.sample(chrono::Utc::now().timestamp(), || {
                let s = state.filter_stats.snapshot();
                (s.total_requests, s.blocked_requests)
            });
        }
    });
}

/// Scheduled userscript update checks (`userscripts.update_check_interval_hours`, 0 = off).
/// Failures are logged, never fatal.
fn spawn_userscript_update_checks(state: Arc<AppState>) {
    let hours = state
        .proxy_state
        .config
        .read()
        .userscripts
        .update_check_interval_hours;
    if hours == 0 {
        return;
    }
    tracing::info!("Userscript update checks every {hours} h");
    tokio::spawn(async move {
        let period = std::time::Duration::from_secs(hours.saturating_mul(3600));
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        loop {
            tick.tick().await;
            let auto = state
                .proxy_state
                .config
                .read()
                .userscripts
                .auto_apply_updates;
            crate::userscript_ops::check_all(&state, auto).await;
        }
    });
}

/// The server speaks plain HTTP. Bound beyond loopback, logins and session cookies cross the
/// network in clear unless a TLS-terminating reverse proxy sits in front. Logged once at startup.
fn warn_if_exposed_without_tls(config: &ApiConfig) {
    let host = config.server.host.trim_matches(['[', ']']);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !loopback {
        tracing::warn!(
            "Web UI is bound to {host} without TLS: passwords and session cookies are sent in \
             clear text. Put a TLS-terminating reverse proxy in front (and list it under \
             network.trusted_proxies so cookies get the Secure flag) or bind to 127.0.0.1."
        );
    }
}

/// CORS: same-origin only unless origins are allowlisted (then credentials are allowed for
/// exactly those origins).
fn build_cors_layer(origins: &[String]) -> Option<CorsLayer> {
    use tower_http::cors::AllowOrigin;

    let allowed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();
    if allowed.is_empty() {
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(allowed))
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                header::ACCEPT,
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::IF_MATCH,
                header::HeaderName::from_static("x-csrf-token"),
                header::HeaderName::from_static("x-request-id"),
            ])
            .expose_headers([
                header::ETAG,
                header::HeaderName::from_static("x-request-id"),
            ])
            .allow_credentials(true)
            .max_age(std::time::Duration::from_secs(3600)),
    )
}

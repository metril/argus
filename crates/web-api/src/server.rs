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
use crate::webui_tls::TlsShared;

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
                        // `/userscripts/<id>` ids are URLs ("https://greasyfork.org/..." encoded),
                        // so a dot in the last segment is not an asset there.
                        let is_script_page = req.uri().path().starts_with("/userscripts/");
                        if last.contains('.') && !is_script_page {
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
    router = router.layer(build_cors_layer(&config.security.cors_origins));
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
    /// TLS configuration read by every new connection (swappable without rebinding).
    tls: Arc<TlsShared>,
    /// Where the bound port is recorded for tooling (`.webui_port`).
    port_file: parking_lot::Mutex<Option<std::path::PathBuf>>,
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
    /// Configured port that could not be bound at startup (we fell back to another).
    moved_from: Option<u16>,
    startup_error: Option<String>,
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

/// A stream with one already-read byte put back in front.
struct Rewind<S> {
    first: Option<u8>,
    inner: S,
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Rewind<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(b) = self.first.take() {
            buf.put_slice(&[b]);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Rewind<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        b: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl WebServer {
    /// In-process handoff of a stream the proxy accepted for the web UI endpoint: served exactly
    /// like a connection to the listener, with `peer` (the real client) as its address.
    pub fn handoff_stream<S>(self: &Arc<Self>, stream: S, peer: SocketAddr, local_port: u16)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use tokio::io::AsyncReadExt;
        let (router, tls) = (self.router.clone(), self.tls.clone());
        tokio::spawn(async move {
            let mut stream = stream;
            let mut b = [0u8; 1];
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read(&mut b)).await {
                Ok(Ok(1)) => {}
                _ => return,
            }
            // The sender lives as long as the connection: it is never signalled.
            let (_keep, sd) = tokio::sync::watch::channel(false);
            let io = Rewind {
                first: Some(b[0]),
                inner: stream,
            };
            serve_conn(io, b[0], local_port, peer, router, tls, sd).await;
        });
    }

    /// In-process handoff of one plain-HTTP request the proxy received for the web UI endpoint.
    pub async fn handoff_request(
        &self,
        req: hyper::Request<hyper::body::Incoming>,
        peer: SocketAddr,
        local_port: u16,
    ) -> Resp {
        use tower::ServiceExt;
        let mut req = req;
        let (cfg, redirect) = self.tls.snapshot();
        if cfg.is_some() && redirect {
            let proxied_https = crate::middleware::request_id::request_is_https(
                req.headers(),
                Some(peer.ip()),
                self.tls.trusted(),
            );
            if !proxied_https && !PLAIN_PATHS.contains(&req.uri().path()) {
                return redirect_response(&req, local_port);
            }
        }
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        match self
            .router
            .clone()
            .oneshot(req.map(axum::body::Body::new))
            .await
        {
            Ok(r) => r,
            Err(e) => match e {},
        }
    }

    fn new(
        router: Router,
        listener: tokio::net::TcpListener,
        requested: (String, u16),
        tls: Arc<TlsShared>,
    ) -> Arc<Self> {
        let (done_tx, done_rx) = tokio::sync::mpsc::unbounded_channel();
        let srv = Arc::new(Self {
            router,
            tls,
            port_file: parking_lot::Mutex::new(None),
            current: tokio::sync::Mutex::new(Current {
                gen: 0,
                addr: listener
                    .local_addr()
                    .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))),
                requested,
                stop: None,
                down: false,
                previous: None,
                moved_from: None,
                startup_error: None,
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

    /// Record the current bound port in the port file (if one is set).
    fn write_port(&self, addr: SocketAddr) {
        if let Some(p) = self.port_file.lock().as_ref() {
            let _ = std::fs::write(p, addr.port().to_string());
        }
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
        let (router, tls) = (self.router.clone(), self.tls.clone());
        let done = self.done_tx.clone();
        tokio::spawn(async move {
            let (grace_tx, grace_rx) = tokio::sync::oneshot::channel::<()>();
            let serve = serve_loop(listener, router, tls, async move {
                let _ = stop_rx.await;
                let _ = grace_tx.send(());
            });
            let result = tokio::select! {
                r = serve => r,
                // After a stop request, give the old listener its grace period, then drop it.
                _ = async { let _ = grace_rx.await; tokio::time::sleep(OLD_LISTENER_GRACE).await } => Ok(()),
            };
            let _ = done.send((gen, result));
        });
        stop_tx
    }

    /// Serve TLS with `cfg` from the next connection on (`None` = plain HTTP only). With
    /// `redirect`, plain-HTTP requests are answered with a redirect to HTTPS.
    pub fn set_tls(&self, cfg: Option<Arc<rustls::ServerConfig>>, redirect: bool) {
        self.tls.set(cfg, redirect);
    }

    /// Header-read timeout for new connections (default 30 s). Test hook.
    #[doc(hidden)]
    pub fn __set_header_timeout(&self, d: std::time::Duration) {
        self.tls.set_header_timeout(d);
    }

    /// The TLS configuration and redirect flag in effect.
    pub fn tls_snapshot(&self) -> (Option<Arc<rustls::ServerConfig>>, bool) {
        self.tls.snapshot()
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

    /// The configured port that failed at startup, until a `rebind` succeeds.
    pub async fn moved_from(&self) -> Option<u16> {
        self.current.lock().await.moved_from
    }

    /// Why the configured port failed at startup, until a `rebind` succeeds.
    pub async fn startup_error(&self) -> Option<String> {
        self.current.lock().await.startup_error.clone()
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
        if port != 0
            && !cur.down
            && cur.moved_from.is_none()
            && cur.requested == (host.to_string(), port)
        {
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
        cur.moved_from = None;
        cur.startup_error = None;
        tracing::info!("Web API now listening on {addr}; the old listener closes after 30s");
        self.write_port(addr);
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
        self.write_port(cur.addr);
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
    let (listener, fallback) = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => (l, None),
        Err(e) => {
            let configured = config.server.port;
            let mut found = None;
            let candidates = (1..=10u16)
                .filter_map(|i| configured.checked_add(i))
                .filter(|p| *p != 0)
                .chain(std::iter::once(0));
            for p in candidates {
                if let Ok(l) =
                    tokio::net::TcpListener::bind(spec_addr(&config.server.host, p)).await
                {
                    found = Some(l);
                    break;
                }
            }
            match found {
                Some(l) => (l, Some((configured, e.to_string()))),
                None => return Err(e.into()),
            }
        }
    };
    let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    match &fallback {
        None => tracing::info!("Web API server listening on {}", addr),
        Some((configured, err)) => tracing::warn!(
            "Web UI could not use configured port {configured} ({err}); it is available at http://{}:{bound_port}/ instead. The saved setting is unchanged; change the port in Settings.",
            config.server.host.trim_matches(['[', ']'])
        ),
    }
    let data_dir = state.proxy_state.config.read().adblock.data_dir.clone();
    let _ = std::fs::create_dir_all(&data_dir);
    let port_file = data_dir.join(".webui_port");
    let _ = std::fs::write(&port_file, bound_port.to_string());
    let tls_cfg = crate::webui_tls::initial(&state).await;
    if tls_cfg.is_none() {
        warn_if_exposed_without_tls(&config);
    }
    let redirect = state.proxy_state.config.read().webui.tls.redirect_http;
    let tls = Arc::new(TlsShared::new(
        tls_cfg,
        redirect,
        config.network.trusted_proxies.clone(),
    ));

    let sessions = state.session_manager.clone();
    let renew_state = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tick.tick().await;
            crate::webui_tls::renew_if_due(&renew_state).await;
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
        tls,
    );
    if let Some((configured, err)) = fallback {
        let mut cur = server.current.lock().await;
        cur.moved_from = Some(configured);
        cur.startup_error = Some(format!("port {configured} unavailable: {err}"));
    }
    *server.port_file.lock() = Some(port_file);
    if let Some(rt) = state.runtime.get() {
        let host = config.server.host.clone();
        rt.note_webui(&host, bound_port).await;
    }
    let _ = state.web_server.set(server.clone());
    if let Some(rt) = state.runtime.get() {
        rt.webui_handoff(server.clone());
    }
    // HTTPS configured but not served at startup (certificate not ready, runtime late): retry
    // soon instead of waiting for the hourly tick.
    let retry = state.clone();
    tokio::spawn(async move {
        for secs in [2u64, 5, 10, 30, 60, 120, 300] {
            if crate::webui_tls::not_served(&retry).is_none() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            crate::webui_tls::renew_if_due(&retry).await;
        }
    });
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
/// network in clear unless HTTPS is on or a TLS-terminating reverse proxy sits in front. Logged
/// once at startup (not when built-in HTTPS is active).
fn warn_if_exposed_without_tls(config: &ApiConfig) {
    let host = config.server.host.trim_matches(['[', ']']);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !loopback {
        tracing::warn!(
            "Web UI is bound to {host} without TLS: passwords and session cookies are sent in \
             clear text. Turn on HTTPS under Settings > HTTPS, put a TLS-terminating reverse \
             proxy in front (and list it under trusted proxies so cookies get the Secure flag), \
             or bind to 127.0.0.1."
        );
    }
}

/// How long a new connection may take to send its first byte and finish the TLS handshake.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Most simultaneous connections on the web listener; further ones are closed at accept.
const MAX_CONNECTIONS: usize = 1024;

/// Paths served over plain HTTP even when everything else is redirected: the public CA downloads
/// (a browser needs the CA before it can open the HTTPS page) and health probes (the container
/// healthcheck uses plain HTTP).
const PLAIN_PATHS: [&str; 4] = [
    "/api/v1/ca.crt",
    "/api/v1/ca.der",
    "/api/v1/health",
    "/health",
];

/// Accept connections until `shutdown` resolves, then stop accepting (the socket is released at
/// once) and let in-flight connections finish. Connection tasks live in a `JoinSet`, so dropping
/// this future (the caller's grace period ended) aborts whatever is left.
///
/// The first byte of each connection decides: a TLS ClientHello (0x16) goes to the TLS acceptor
/// built from the current [`TlsShared`] configuration; anything else is plain HTTP, redirected to
/// HTTPS when that is configured.
async fn serve_loop(
    listener: tokio::net::TcpListener,
    router: Router,
    tls: Arc<TlsShared>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), String> {
    let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let mut conns = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            // Reap finished connection tasks.
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        tracing::warn!("web listener at its connection limit; dropping {peer}");
                        continue;
                    };
                    conns.spawn(handle_conn(
                        stream,
                        peer,
                        router.clone(),
                        tls.clone(),
                        sd_rx.clone(),
                        permit,
                    ));
                }
                Err(e) => {
                    // Out of descriptors and the like: back off instead of spinning.
                    tracing::warn!("web listener accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            },
        }
    }
    drop(listener);
    let _ = sd_tx.send(true);
    while conns.join_next().await.is_some() {}
    Ok(())
}

async fn handle_conn(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    router: Router,
    tls: Arc<TlsShared>,
    sd: tokio::sync::watch::Receiver<bool>,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let mut first = [0u8; 1];
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut first)).await {
        Ok(Ok(1)) => {}
        _ => return,
    }
    let local = stream.local_addr().map(|a| a.port()).unwrap_or(0);
    serve_conn(stream, first[0], local, peer, router, tls, sd).await;
}

/// Serve one accepted byte stream (`first` is its first byte, still unread): TLS or plain HTTP.
async fn serve_conn<S>(
    stream: S,
    first: u8,
    local: u16,
    peer: SocketAddr,
    router: Router,
    tls: Arc<TlsShared>,
    sd: tokio::sync::watch::Receiver<bool>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut epoch = tls.subscribe();
    epoch.mark_unchanged();
    let (cfg, redirect) = tls.snapshot();
    let ctl = Ctl {
        sd,
        epoch,
        header_timeout: tls.header_timeout(),
    };
    if first == 0x16 {
        let Some(cfg) = cfg else { return };
        let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
        let tls_stream =
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(s)) => s,
                _ => return,
            };
        serve_io(tls_stream, app_service(router, peer, true), ctl).await;
    } else if cfg.is_some() && redirect {
        serve_io(
            stream,
            redirect_service(router, peer, local, tls.trusted().to_vec()),
            ctl,
        )
        .await;
    } else {
        serve_io(stream, app_service(router, peer, false), ctl).await;
    }
}

type Resp = axum::response::Response;

/// The router as a hyper service, with the peer address and (for native TLS) the secure marker.
fn app_service(
    router: Router,
    peer: SocketAddr,
    secure: bool,
) -> impl hyper::service::Service<
    hyper::Request<hyper::body::Incoming>,
    Response = Resp,
    Error = std::convert::Infallible,
    Future = impl Send + 'static,
> + Send
       + 'static {
    hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
        use tower::ServiceExt;
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        if secure {
            req.extensions_mut()
                .insert(crate::middleware::request_id::NativeTls);
        }
        router.clone().oneshot(req.map(axum::body::Body::new))
    })
}

/// Plain-HTTP requests answered with a redirect to the same path over HTTPS. Left alone: the CA
/// downloads and health probes, and requests a trusted reverse proxy says arrived over HTTPS.
fn redirect_service(
    router: Router,
    peer: SocketAddr,
    local_port: u16,
    trusted: Vec<std::net::IpAddr>,
) -> impl hyper::service::Service<
    hyper::Request<hyper::body::Incoming>,
    Response = Resp,
    Error = std::convert::Infallible,
    Future = impl Send + 'static,
> + Send
       + 'static {
    hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
        use tower::ServiceExt;
        let router = router.clone();
        let trusted = trusted.clone();
        async move {
            let proxied_https = crate::middleware::request_id::request_is_https(
                req.headers(),
                Some(peer.ip()),
                &trusted,
            );
            if proxied_https || PLAIN_PATHS.contains(&req.uri().path()) {
                req.extensions_mut()
                    .insert(axum::extract::ConnectInfo(peer));
                return router.oneshot(req.map(axum::body::Body::new)).await;
            }
            Ok(redirect_response(&req, local_port))
        }
    })
}

/// 307 to `https://<host>[:port]<path>`. The port is the one the client used (the `Host`
/// header, which survives container port mappings), else the local one. Never cached: the
/// redirect must not outlive turning HTTPS off.
fn redirect_response<B>(req: &hyper::Request<B>, local_port: u16) -> Resp {
    let hdr = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok());
    let (host, host_port) = match hdr {
        Some(h) if h.starts_with('[') => {
            let end = h.find(']').map_or(h.len(), |i| i + 1);
            (
                &h[..end],
                h[end..]
                    .strip_prefix(':')
                    .and_then(|p| p.parse::<u16>().ok()),
            )
        }
        Some(h) => match h.rsplit_once(':') {
            Some((n, p)) => (n, p.parse::<u16>().ok()),
            None => (h, None),
        },
        None => ("", None),
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_:[]".contains(&b))
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let port = host_port.unwrap_or(local_port);
    let port = if port == 443 || port == 0 {
        String::new()
    } else {
        format!(":{port}")
    };
    let pq = req.uri().path_and_query().map_or("/", |p| p.as_str());
    match HeaderValue::try_from(format!("https://{host}{port}{pq}")) {
        Ok(loc) => (
            StatusCode::TEMPORARY_REDIRECT,
            [
                (header::LOCATION, loc),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
        )
            .into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// What ends a connection early.
struct Ctl {
    sd: tokio::sync::watch::Receiver<bool>,
    epoch: tokio::sync::watch::Receiver<u64>,
    header_timeout: std::time::Duration,
}

/// Run one HTTP/1 or HTTP/2 connection until it ends. On listener shutdown or a TLS/redirect
/// change it is finished gracefully (idle keep-alives close at once) and cut after the grace
/// period.
async fn serve_io<I, S>(io: I, svc: S, mut ctl: Ctl)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: hyper::service::Service<
            hyper::Request<hyper::body::Incoming>,
            Response = Resp,
            Error = std::convert::Infallible,
        > + Send
        + 'static,
    S::Future: Send + 'static,
{
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(ctl.header_timeout)
        .keep_alive(true);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(std::time::Duration::from_secs(30))
        .keep_alive_timeout(std::time::Duration::from_secs(20))
        .max_concurrent_streams(128);
    let conn = builder.serve_connection_with_upgrades(TokioIo::new(io), svc);
    tokio::pin!(conn);
    tokio::select! {
        r = conn.as_mut() => {
            if let Err(e) = r {
                tracing::debug!("web connection ended: {e}");
            }
            return;
        }
        _ = ctl.sd.wait_for(|v| *v) => {}
        _ = ctl.epoch.changed() => {}
    }
    conn.as_mut().graceful_shutdown();
    let _ = tokio::time::timeout(OLD_LISTENER_GRACE, conn).await;
}

/// Path prefix whose responses browser extensions may read cross-origin.
const EXTENSION_CORS_PREFIX: &str = "/api/v1/certs/";

/// Whether `origin` is a browser-extension origin.
fn is_extension_origin(origin: &HeaderValue) -> bool {
    origin
        .to_str()
        .is_ok_and(|o| o.starts_with("chrome-extension://") || o.starts_with("moz-extension://"))
}

/// CORS: same-origin only unless origins are allowlisted (then credentials are allowed for
/// exactly those origins). Browser extensions (`chrome-extension://*`, `moz-extension://*`) are
/// additionally allowed, but only on `/api/v1/certs/*`.
fn build_cors_layer(origins: &[String]) -> CorsLayer {
    use tower_http::cors::AllowOrigin;

    let allowed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();
    {
        CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(move |origin, parts| {
                allowed.contains(origin)
                    || (is_extension_origin(origin)
                        && parts.uri.path().starts_with(EXTENSION_CORS_PREFIX))
            }))
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
            .max_age(std::time::Duration::from_secs(3600))
    }
}

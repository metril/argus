//! Main proxy server implementation

use crate::{
    ca::CertificateAuthority,
    config::ProxyConfig,
    connection::{ConnectionHandler, ConnectionShared, Timeouts},
    filtering::ProxyContext,
    load_manager::{AdmissionResult, ConnectionGuard, LoadManager, LoadManagerConfig},
    mitm::MitmHandler,
    policy::{ClientAcl, DestPolicy},
    transparent::{
        KernelOriginalDst, OriginalDst, TransparentEntry, KERNEL_ORIGINAL_DST_SUPPORTED,
    },
    Error, Result,
};
use arc_swap::{ArcSwap, ArcSwapOption};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{debug, info, trace, warn};

pub struct ProxyServer {
    config: ProxyConfig,
    mitm_handler: Option<Arc<MitmHandler>>,
    load_manager: Arc<LoadManager>,
    /// Shared filtering + upstream-forwarding context handed to each connection.
    ctx: Arc<ProxyContext>,
    /// Live-reconfigurable state: client ACL, listeners, passthrough hosts, destination rules.
    control: Arc<ProxyControl>,
}

/// Where the proxy's listeners are bound right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindInfo {
    pub proxy: SocketAddr,
    pub transparent: Option<SocketAddr>,
    /// The explicit listener is not listening (a move failed and so did restoring it); the
    /// address above is the last one it had. Another `rebind` brings it back.
    pub proxy_down: bool,
    pub transparent_down: bool,
    /// Why the explicit listener is down (bind failure), cleared once it is bound.
    pub proxy_error: Option<String>,
    pub transparent_error: Option<String>,
}

/// One running accept loop. Stopping it drops the listening socket; connections it already
/// accepted run to completion on their own tasks.
struct Listener {
    addr: SocketAddr,
    /// Port as configured (0 = ephemeral), to tell a no-op from a real change.
    requested: (String, u16),
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    /// Closed and not restored: nothing listens on `addr`.
    down: bool,
    /// Why it is down.
    error: Option<String>,
}

impl Listener {
    /// A listener that failed to bind: nothing listens on `addr` until a rebind succeeds.
    fn down(addr: SocketAddr, requested: (String, u16), error: String) -> Self {
        Self {
            addr,
            requested,
            stop: None,
            task: tokio::spawn(async {}),
            down: true,
            error: Some(error),
        }
    }

    /// Ask the loop to stop; resolves once the listening socket is closed.
    async fn stop(mut self) {
        self.close().await;
    }

    async fn close(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.task).await;
    }
}

impl Running {
    fn info(&self) -> BindInfo {
        BindInfo {
            proxy: self.explicit.addr,
            transparent: self.transparent.as_ref().map(|t| t.addr),
            proxy_down: self.explicit.down,
            transparent_down: self.transparent.as_ref().is_some_and(|t| t.down),
            proxy_error: self.explicit.error.clone(),
            transparent_error: self.transparent.as_ref().and_then(|t| t.error.clone()),
        }
    }
}

struct Running {
    shared: Arc<ConnectionShared>,
    shutdown_tx: broadcast::Sender<()>,
    explicit: Listener,
    transparent: Option<Listener>,
    entry: Option<Arc<TransparentEntry>>,
}

/// What a running server exposes for lazy setup.
struct LiveParts {
    shared: Arc<ConnectionShared>,
    shutdown_tx: broadcast::Sender<()>,
}

/// Config the lazy MITM setup reads (refreshed on every apply).
#[derive(Clone)]
struct LazyCfg {
    mitm: common::config::MitmSettings,
    max_cert_generations: usize,
}

impl LazyCfg {
    fn of(c: &ProxyConfig) -> Self {
        Self {
            mitm: c.mitm.clone(),
            max_cert_generations: c.performance.max_cert_generations,
        }
    }
}

/// Build the CA-backed MITM handler (loads or generates the CA).
fn build_mitm(c: &LazyCfg) -> Result<Arc<MitmHandler>> {
    let ca = Arc::new(CertificateAuthority::load_or_generate(
        &c.mitm.ca_cert_path,
        &c.mitm.ca_key_path,
    )?);
    // h2 is always offered by the handler's config; listeners with HTTP/2 off use its h1-only
    // variant, so the switch stays live.
    Ok(Arc::new(
        MitmHandler::new(
            ca,
            c.mitm.cert_cache_size,
            c.mitm.cert_ttl_days * 24 * 3600,
            c.max_cert_generations,
        )
        .with_http2(true),
    ))
}

/// Handle for changing a running proxy without restarting it. Cheap to clone via `Arc`.
pub struct ProxyControl {
    acl: Arc<ArcSwap<ClientAcl>>,
    ctx: Arc<ProxyContext>,
    load_manager: Arc<LoadManager>,
    original_dst: Option<Arc<dyn OriginalDst>>,
    /// The web API listener, for the destination policy's loop protection.
    webui_own: parking_lot::Mutex<Option<(u16, Option<IpAddr>)>>,
    /// Names that are Argus itself (web API host, panel host, dashboard host), from the live
    /// configuration (refreshed by every `apply_access`).
    own_names: parking_lot::Mutex<Vec<String>>,
    /// Switches of each listener, shared with its connections.
    explicit_flags: Arc<crate::listener_flags::ListenerFlags>,
    transparent_flags: Arc<crate::listener_flags::ListenerFlags>,
    /// Switches of the extension listener (the explicit listener's values).
    ext_flags: Arc<crate::listener_flags::ListenerFlags>,
    /// The extension-only listener (see [`Self::rebind_ext`]).
    ext: tokio::sync::Mutex<Option<Listener>>,
    /// The extension listener's bound address while it runs: an own listener the explicit
    /// proxy refuses to dial, like its own ports.
    ext_own: parking_lot::Mutex<Option<std::net::SocketAddr>>,
    /// Live time limits, shared with every connection.
    timeouts: Arc<ArcSwap<Timeouts>>,
    /// Set once the server runs: what a lazy MITM / WebSocket enable installs into.
    live: ArcSwapOption<LiveParts>,
    /// Settings the lazy setup needs (CA paths and cache sizes, extra upstream CAs).
    lazy_cfg: parking_lot::Mutex<LazyCfg>,
    /// The `tls_passthrough_hosts` last synced into the bypass entries.
    legacy_passthrough: parking_lot::Mutex<Vec<String>>,
    /// DNS settings currently in effect (a change rebuilds the resolver and flushes its cache).
    dns_cfg: parking_lot::Mutex<(common::config::DnsSettings, Vec<String>)>,
    /// The data directory (upstream-list files are read from its `dns` folder).
    dns_dir: std::path::PathBuf,
    /// Test hook: make restoring a closed listener fail.
    #[cfg(any(test, feature = "test-hooks"))]
    fail_restore: std::sync::atomic::AtomicBool,
    /// The proxy's own ports (explicit + transparent) for the transparent loop guard.
    entry_ports: Arc<parking_lot::RwLock<Vec<u16>>>,
    running: tokio::sync::Mutex<Option<Running>>,
}

/// The names that are Argus itself in `c`: the web API's host, the panel host and the dashboard
/// host (lowercase; IP literals and wildcard binds are not names).
fn own_names_of(c: &ProxyConfig) -> Vec<String> {
    let mut v = vec![c.webui.host.to_ascii_lowercase()];
    v.push(c.script_control.panel_host.to_ascii_lowercase());
    if let Some(h) = url::Url::parse(&c.script_control.dashboard_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
    {
        v.push(h);
    }
    v.retain(|n| !n.is_empty() && n.parse::<IpAddr>().is_err());
    v
}

/// Resolves a relay target at check time and compares it with the web API's bind address.
struct OwnResolver(std::sync::Weak<ProxyControl>);

#[async_trait::async_trait]
impl crate::ext_bridge::OwnResolve for OwnResolver {
    async fn resolves_to_own(&self, host: &str, port: u16) -> bool {
        let Some(c) = self.0.upgrade() else {
            return false;
        };
        let own = *c.webui_own.lock();
        let Some((p, Some(ip))) = own else {
            return false;
        };
        if p != port || ip.is_unspecified() {
            return false;
        }
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::lookup_host((host, port)),
        )
        .await
        {
            Ok(Ok(mut it)) => it.any(|a| a.ip() == ip),
            _ => false,
        }
    }
}

fn spec_addr(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

impl ProxyControl {
    /// Current bind addresses (`None` before the server runs).
    pub async fn bind_info(&self) -> Option<BindInfo> {
        self.running.lock().await.as_ref().map(Running::info)
    }

    /// Issue the web UI's HTTPS certificate from the Argus CA (397 days, one entry per name in
    /// `sans`). Returns `(certificate PEM, key PEM)`.
    pub async fn issue_webui_cert(&self, sans: Vec<String>) -> Result<(String, String)> {
        let (cert, key) = {
            let l = self.lazy_cfg.lock();
            (l.mitm.ca_cert_path.clone(), l.mitm.ca_key_path.clone())
        };
        tokio::task::spawn_blocking(move || {
            CertificateAuthority::load_or_generate(&cert, &key)?
                .generate_server_cert_pem(&sans, 397)
        })
        .await
        .map_err(|e| Error::Internal(e.to_string()))?
    }

    /// Note where the web API listens (own-listener loop protection); call after it rebinds.
    pub async fn set_webui_listener(&self, host: &str, port: u16) {
        // A name resolves to what it names (`localhost` is loopback, not "any address").
        let ip = match host.parse().ok() {
            Some(ip) => Some(ip),
            None => tokio::net::lookup_host((host, port))
                .await
                .ok()
                .and_then(|mut it| it.next())
                .map(|a| a.ip()),
        };
        *self.webui_own.lock() = Some((port, ip));
        let guard = self.running.lock().await;
        if let Some(r) = guard.as_ref() {
            self.publish_own(&r.explicit, r.transparent.as_ref());
        }
    }

    /// Test an upstream proxy configuration (see [`ProxyContext::test_upstream_proxy`]).
    pub async fn test_upstream_proxy(
        &self,
        cfg: &common::config::UpstreamProxy,
        host: &str,
        port: u16,
    ) -> std::result::Result<std::time::Duration, String> {
        self.ctx.test_upstream_proxy(cfg, host, port).await
    }

    /// Health and RTT of the upstream resolvers in force, and the cache counters.
    pub fn dns_stats(&self) -> Option<api_types::DnsStatsResponse> {
        let d = self.ctx.dns()?;
        let (hits, misses) = d.stats();
        Some(api_types::DnsStatsResponse {
            upstreams: d
                .upstream_stats()
                .into_iter()
                .map(|u| api_types::DnsUpstreamStat {
                    upstream: u.upstream,
                    role: u.role.into(),
                    transport: u.transport.into(),
                    queries: u.queries,
                    failures: u.failures,
                    consecutive_failures: u.consecutive_failures,
                    rtt_ms: u.rtt_ms,
                    last_rtt_ms: u.last_rtt_ms,
                    healthy: u.healthy,
                    last_error: u.last_error,
                    last_ok_secs_ago: u.last_ok_secs_ago,
                })
                .collect(),
            cached_names: d.cached_names_approx(),
            cache_hits: hits,
            cache_misses: misses,
        })
    }

    /// Probe every upstream of `settings` once (see [`crate::dns::test_upstreams`]).
    pub async fn test_dns(
        &self,
        settings: &common::config::DnsSettings,
    ) -> std::result::Result<Vec<api_types::DnsTestResult>, String> {
        let lines = crate::dns::load_upstream_lines(settings, &self.dns_dir).await?;
        let r = crate::dns::test_upstreams(settings, &lines).await?;
        Ok(r.into_iter()
            .map(|p| api_types::DnsTestResult {
                upstream: p.upstream,
                role: p.role.into(),
                ok: p.ok,
                latency_ms: p.latency_ms,
                error: p.error,
                answers: p.answers.iter().map(|a| a.to_string()).collect(),
            })
            .collect())
    }

    /// Apply the settings that need no rebind: client ACL, TLS passthrough hosts, destination
    /// rules, per-listener switches, DNS, time limits and the connection cap.
    ///
    /// Everything that can fail (CIDR and DNS validation, loading the CA, building the
    /// WebSocket client and the upstream clients) is done first; only then is anything swapped
    /// in, so an error changes nothing.
    pub async fn apply_access(&self, config: &ProxyConfig) -> Result<()> {
        // ---- prepare (fallible)
        let acl = ClientAcl::new(&config.proxy.allowed_clients)?;
        common::net_policy::parse_nets(&config.proxy.allowed_destinations)
            .map_err(|e| Error::Config(e.to_string()))?;
        config.dns.validate().map_err(Error::Config)?;
        // Upstream lines from the optional file or URL, read on every apply.
        let dns_lines = crate::dns::load_upstream_lines(&config.dns, &config.adblock.data_dir)
            .await
            .map_err(Error::Config)?;
        let lazy = LazyCfg::of(config);
        let t = Timeouts::from_config(&config.performance);
        let live = self.live.load_full();
        let mut new_mitm = None;
        if live
            .as_ref()
            .is_some_and(|l| l.shared.mitm.load().is_none())
            && config.any_listener(|f| f.mitm)
        {
            let c = lazy.clone();
            new_mitm = Some(
                tokio::task::spawn_blocking(move || build_mitm(&c))
                    .await
                    .map_err(|e| Error::Internal(e.to_string()))??,
            );
        }
        // A live change of the extra CAs takes effect for the next handshake (a broken file
        // rejects the change before anything is applied).
        let new_extras = match self.ctx.roots() {
            Some(roots) => {
                let (roots, paths) = (roots.clone(), config.proxy.extra_upstream_ca_paths.clone());
                Some(
                    tokio::task::spawn_blocking(move || roots.prepare_extras(&paths))
                        .await
                        .map_err(|e| Error::Internal(e.to_string()))??,
                )
            }
            None => None,
        };
        #[cfg(feature = "websockets")]
        let mut new_ws = None;
        #[cfg(feature = "websockets")]
        if let Some(l) = live
            .as_ref()
            .filter(|l| l.shared.ws.load().is_none() && config.any_listener(|f| f.websockets))
        {
            let shutdown = l.shutdown_tx.clone();
            new_ws = Some(Arc::new(
                crate::websocket::WsUpstream::new(t.handshake)
                    .with_lifecycle(t.tunnel_idle, shutdown),
            ));
        }
        let proxy = self.ctx.prepare_proxy(&config.proxy.upstream.proxy).await?;
        let upstream = self.ctx.prepare_upstream(
            t.handshake,
            t.header_read,
            config.proxy.upstream.browser_like,
            proxy,
        )?;
        // The old `tls_passthrough_hosts` setting lives on as `migrated` bypass entries. Last
        // fallible step: the commit below cannot fail.
        {
            let changed = *self.legacy_passthrough.lock() != config.proxy.tls_passthrough_hosts;
            if changed {
                // File I/O: off the async threads.
                let (bypass, hosts) = (
                    self.ctx.bypass().clone(),
                    config.proxy.tls_passthrough_hosts.clone(),
                );
                tokio::task::spawn_blocking(move || bypass.sync_legacy(&hosts))
                    .await
                    .map_err(|e| Error::Internal(e.to_string()))?
                    .map_err(Error::Config)?;
                *self.legacy_passthrough.lock() = config.proxy.tls_passthrough_hosts.clone();
            }
        }

        // ---- commit (infallible)
        *self.lazy_cfg.lock() = lazy;
        if let (Some(live), Some(m)) = (&live, new_mitm) {
            live.shared.mitm.store(Some(m));
        }
        #[cfg(feature = "websockets")]
        if let Some(live) = &live {
            if let Some(w) = new_ws {
                live.shared.ws.store(Some(w));
            }
            if let Some(ws) = live.shared.ws.load_full() {
                ws.set_idle_timeout(t.tunnel_idle);
            }
        }
        // Validated above, so this cannot fail.
        let _ = self.ctx.policy().set_rules(
            config.proxy.block_private_destinations,
            &config.proxy.allowed_destinations,
        );
        self.acl.store(Arc::new(acl));
        *self.own_names.lock() = own_names_of(config);
        self.explicit_flags.set(config.listener_flags(false));
        self.transparent_flags.set(config.listener_flags(true));
        self.ext_flags.set(config.listener_flags(false));
        {
            let mut cur = self.dns_cfg.lock();
            if format!("{:?}", cur.0) != format!("{:?}", config.dns) || cur.1 != dns_lines {
                if let Some(d) = self.ctx.dns() {
                    d.set_direct_probes(!config.proxy.upstream.proxy.enabled);
                    d.reconfigure_lines(&config.dns, &dns_lines);
                }
                *cur = (config.dns.clone(), dns_lines);
            }
        }
        self.timeouts.store(Arc::new(t));
        self.ctx
            .set_guard_service_workers(config.adblock.guard_service_workers);
        self.ctx.set_block_response(config.proxy.block_response);
        self.ctx.set_cname(&config.adblock.cname);
        self.ctx
            .set_guard_service_workers_exempt(config.adblock.guard_service_workers_exempt.clone());
        self.ctx.commit_upstream(upstream);
        if let (Some(roots), Some(extras)) = (self.ctx.roots(), new_extras) {
            roots.commit_extras(extras);
        }
        self.ctx.set_request_timeout(std::time::Duration::from_secs(
            config.performance.request_timeout_secs,
        ));
        self.load_manager
            .set_max_connections(match config.performance.max_connections {
                0 => crate::load_manager::derive_max_connections(),
                n => n,
            });
        Ok(())
    }

    /// Live counters of the explicit and transparent listeners.
    pub fn listener_counters(
        &self,
    ) -> (
        crate::listener_flags::ListenerCounters,
        crate::listener_flags::ListenerCounters,
    ) {
        (
            self.explicit_flags.counters(),
            self.transparent_flags.counters(),
        )
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

    /// Test hook: make restoring a listener after a failed move fail, to exercise the down state.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn __fail_restores(&self, on: bool) {
        self.fail_restore
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// The time limits connections currently use.
    pub fn timeouts(&self) -> Timeouts {
        **self.timeouts.load()
    }

    /// Whether the MITM handler (CA) is loaded.
    pub fn mitm_ready(&self) -> bool {
        self.live
            .load()
            .as_ref()
            .is_some_and(|l| l.shared.mitm.load().is_some())
    }

    /// The WebSocket client's idle timeout, once it is built.
    #[cfg(feature = "websockets")]
    pub fn ws_idle_timeout(&self) -> Option<std::time::Duration> {
        self.live
            .load()
            .as_ref()
            .and_then(|l| l.shared.ws.load_full())
            .map(|w| w.idle_timeout())
    }

    /// Whether the WebSocket client is built.
    #[cfg(feature = "websockets")]
    pub fn ws_ready(&self) -> bool {
        self.live
            .load()
            .as_ref()
            .is_some_and(|l| l.shared.ws.load().is_some())
    }

    /// Tell the destination policy which listeners are the proxy's own (loop protection).
    /// Register the web server for in-process handoff of requests to the web UI endpoint.
    pub fn set_web_server(&self, server: Arc<dyn crate::self_route::WebUiHandoff>) {
        self.ctx.set_web_server(server);
    }

    fn publish_own(&self, explicit: &Listener, transparent: Option<&Listener>) {
        let mut ports: Vec<u16> = Vec::new();
        let mut addrs: Vec<IpAddr> = Vec::new();
        for l in std::iter::once(explicit).chain(transparent) {
            ports.push(l.addr.port());
            addrs.push(l.addr.ip());
        }
        if let Some(a) = *self.ext_own.lock() {
            ports.push(a.port());
            addrs.push(a.ip());
        }
        // The web UI endpoint stays an own listener: whatever the in-process handoff did not
        // take (a miss) is refused like a proxy port. The handoff check runs before the policy.
        let webui = *self.webui_own.lock();
        if let Some((port, ip)) = webui {
            ports.push(port);
            addrs.extend(ip);
        }
        self.ctx.policy().set_web_ui(webui);
        self.ctx
            .policy()
            .set_explicit_port(Some(explicit.addr.port()));
        ports.sort_unstable();
        ports.dedup();
        *self.entry_ports.write() = std::iter::once(explicit)
            .chain(transparent)
            .map(|l| l.addr.port())
            .collect();
        self.ctx.policy().set_own_listeners(&ports, &addrs);
    }

    fn make_entry(&self) -> Result<Arc<TransparentEntry>> {
        let original_dst = match &self.original_dst {
            Some(d) => d.clone(),
            None if KERNEL_ORIGINAL_DST_SUPPORTED => Arc::new(KernelOriginalDst),
            None => {
                return Err(Error::Config(
                    "transparent mode is only supported on Linux".into(),
                ))
            }
        };
        Ok(Arc::new(TransparentEntry::with_ports(
            original_dst,
            self.entry_ports.clone(),
        )))
    }

    /// Move the listeners to `host:port` / `transparent_port` (`None` = off) without a restart.
    ///
    /// New sockets are bound first; if any bind fails nothing changes and the error says why.
    /// The old accept loops are then stopped (their sockets close) while connections they
    /// already accepted drain on their own tasks. A host-only change on an unchanged port
    /// cannot bind alongside the old socket, so there the old one is closed first and
    /// restored if the new bind fails.
    pub async fn rebind(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        transparent_port: Option<u16>,
    ) -> Result<BindInfo> {
        let mut guard = self.running.lock().await;
        let run = guard
            .as_mut()
            .ok_or_else(|| Error::Connection("proxy is not running".into()))?;

        let want_explicit = (host.to_string(), port);
        let want_t = transparent_port.map(|p| (host.to_string(), p));
        // A listener that is down never counts as "unchanged": a retry must bind again.
        let same_e = port != 0 && !run.explicit.down && run.explicit.requested == want_explicit;
        let same_t = match (&run.transparent, &want_t) {
            (None, None) => true,
            (Some(l), Some(w)) => w.1 != 0 && !l.down && &l.requested == w,
            _ => false,
        };
        if same_e && same_t {
            return Ok(run.info());
        }

        // Bind the replacements. When the new address collides with the old socket of the same
        // loop (same port, other host), close the old one first and keep its address to restore.
        type Closed = Option<(SocketAddr, (String, u16))>;
        let mut closed: [Closed; 2] = [None, None];
        let mut new_e: Option<TcpListener> = None;
        let mut new_t: Option<TcpListener> = None;
        let mut err: Option<Error> = None;
        // Slots whose own bind (or later restore) failed: only these carry the error.
        let mut failed = [false; 2];

        if !same_e {
            if port != 0 && !run.explicit.down && run.explicit.addr.port() == port {
                closed[0] = Some((run.explicit.addr, run.explicit.requested.clone()));
                run.explicit.close().await;
                run.explicit.down = true;
                run.explicit.requested = (String::new(), 0);
            }
            let a = spec_addr(host, port);
            match TcpListener::bind(&a).await {
                Ok(l) => new_e = Some(l),
                Err(e) => {
                    failed[0] = true;
                    err = Some(Error::Connection(format!("cannot bind proxy to {a}: {e}")))
                }
            }
        }
        if err.is_none() && !same_t {
            if let Some((h, p)) = &want_t {
                if let Some(t) = run
                    .transparent
                    .as_mut()
                    .filter(|t| *p != 0 && !t.down && t.addr.port() == *p)
                {
                    closed[1] = Some((t.addr, t.requested.clone()));
                    t.close().await;
                    t.down = true;
                    t.requested = (String::new(), 0);
                }
                let a = spec_addr(h, *p);
                match TcpListener::bind(&a).await {
                    Ok(l) => new_t = Some(l),
                    Err(e) => {
                        failed[1] = true;
                        err = Some(Error::Connection(format!(
                            "cannot bind transparent listener to {a}: {e}"
                        )))
                    }
                }
            }
        }
        if err.is_none() && new_t.is_some() && run.entry.is_none() {
            match self.make_entry() {
                Ok(e) => run.entry = Some(e),
                Err(e) => {
                    failed[1] = true;
                    err = Some(e)
                }
            }
        }

        if let Some(e) = err {
            // Roll back: re-open what was closed for the attempt, keep everything else.
            drop((new_e, new_t));
            let mut lost = false;
            for (i, addr) in closed.into_iter().enumerate() {
                let Some((addr, requested)) = addr else {
                    continue;
                };
                // The socket just dropped may take a moment to be free again.
                let mut restored = if self.restore_fails() {
                    Err(std::io::Error::other("injected restore failure"))
                } else {
                    TcpListener::bind(addr).await
                };
                for _ in 0..50 {
                    match &restored {
                        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                            restored = TcpListener::bind(addr).await;
                        }
                        _ => break,
                    }
                }
                match restored {
                    Ok(l) => {
                        let (slot, entry) = if i == 0 {
                            (&mut run.explicit, None)
                        } else {
                            (
                                run.transparent.as_mut().expect("closed listener"),
                                run.entry.clone(),
                            )
                        };
                        *slot = self.spawn_listener(
                            l,
                            run.shared.clone(),
                            entry,
                            &run.shutdown_tx,
                            requested,
                        );
                    }
                    Err(re) => {
                        lost = true;
                        failed[i] = true;
                        tracing::error!("could not restore listener on {addr}: {re}");
                    }
                }
            }
            // Whatever stays down carries the reason.
            let why = e.to_string();
            for (i, l) in std::iter::once(&mut run.explicit)
                .chain(run.transparent.as_mut())
                .enumerate()
            {
                if l.down && failed[i] {
                    l.error = Some(why.clone());
                }
            }
            return Err(if lost {
                Error::Connection(format!("{e}; the previous listener could not be restored"))
            } else {
                e
            });
        }

        // Commit: new loops first, then retire the old ones (their sockets close, accepted
        // connections keep running).
        let mut retired: Vec<Listener> = Vec::new();
        if let Some(l) = new_e {
            let new =
                self.spawn_listener(l, run.shared.clone(), None, &run.shutdown_tx, want_explicit);
            retired.push(std::mem::replace(&mut run.explicit, new));
        }
        if !same_t {
            retired.extend(run.transparent.take());
            if let (Some(l), Some(w)) = (new_t, want_t) {
                run.transparent = Some(self.spawn_listener(
                    l,
                    run.shared.clone(),
                    run.entry.clone(),
                    &run.shutdown_tx,
                    w,
                ));
            }
        }
        for old in retired {
            tokio::spawn(old.stop());
        }
        self.publish_own(&run.explicit, run.transparent.as_ref());
        info!(
            "Proxy listening on {}{}",
            run.explicit.addr,
            run.transparent
                .as_ref()
                .map(|t| format!(", transparent on {}", t.addr))
                .unwrap_or_default()
        );
        Ok(run.info())
    }

    /// Move the extension-only listener to `host:port` (`None` = off) without a restart. The new
    /// socket is bound first; on failure nothing changes. The listener answers `407` to anything
    /// without a live extension session's credentials; sessions learn the new port at once.
    pub async fn rebind_ext(self: &Arc<Self>, host: &str, port: Option<u16>) -> Result<()> {
        let hub = self.ctx.internal().gm.ext().clone();
        let run = self.running.lock().await;
        let run = run
            .as_ref()
            .ok_or_else(|| Error::Connection("proxy is not running".into()))?;
        let mut cur = self.ext.lock().await;
        let want = port.map(|p| (host.to_string(), p));
        let same = match (&*cur, &want) {
            (None, None) => true,
            (Some(l), Some(w)) => w.1 != 0 && !l.down && &l.requested == w,
            _ => false,
        };
        if same {
            return Ok(());
        }
        let mut new = None;
        if let Some((h, p)) = &want {
            // Same port, other host: the old socket must go first.
            if let Some(l) = cur.as_mut().filter(|l| *p != 0 && l.addr.port() == *p) {
                l.close().await;
            }
            let a = spec_addr(h, *p);
            let l = TcpListener::bind(&a).await.map_err(|e| {
                Error::Connection(format!("cannot bind extension listener to {a}: {e}"))
            })?;
            new = Some(l);
        }
        let old = cur.take();
        let (adv_host, adv_port) = match new {
            Some(l) => {
                let lst = self.spawn_listener_kind(
                    l,
                    run.shared.clone(),
                    None,
                    &run.shutdown_tx,
                    want.clone().expect("want"),
                    true,
                );
                let ip = lst.addr.ip();
                let h = (!ip.is_unspecified()).then(|| ip.to_string());
                let p = lst.addr.port();
                *cur = Some(lst);
                (h, p)
            }
            None => (None, 0),
        };
        if let Some(o) = old {
            tokio::spawn(o.stop());
        }
        *self.ext_own.lock() = cur.as_ref().filter(|l| !l.down).map(|l| l.addr);
        drop(cur);
        self.publish_own(&run.explicit, run.transparent.as_ref());
        hub.set_proxy(adv_host, adv_port);
        info!(
            "Extension listener {}",
            if adv_port == 0 {
                "off".to_string()
            } else {
                format!("on port {adv_port}")
            }
        );
        Ok(())
    }

    /// Start an accept loop on `listener`.
    fn spawn_listener(
        self: &Arc<Self>,
        listener: TcpListener,
        shared: Arc<ConnectionShared>,
        entry: Option<Arc<TransparentEntry>>,
        shutdown_tx: &broadcast::Sender<()>,
        requested: (String, u16),
    ) -> Listener {
        self.spawn_listener_kind(listener, shared, entry, shutdown_tx, requested, false)
    }

    /// [`Self::spawn_listener`]; `ext` makes it the extension-only listener.
    fn spawn_listener_kind(
        self: &Arc<Self>,
        listener: TcpListener,
        shared: Arc<ConnectionShared>,
        entry: Option<Arc<TransparentEntry>>,
        shutdown_tx: &broadcast::Sender<()>,
        requested: (String, u16),
        ext: bool,
    ) -> Listener {
        let addr = listener
            .local_addr()
            .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
        let (stop, stop_rx) = tokio::sync::oneshot::channel();
        let this = self.clone();
        let shutdown_tx = shutdown_tx.clone();
        let task = tokio::spawn(async move {
            this.accept_loop(listener, shared, entry, &shutdown_tx, stop_rx, ext)
                .await
        });
        Listener {
            addr,
            requested,
            stop: Some(stop),
            task,
            down: false,
            error: None,
        }
    }

    /// Accept connections on `listener` until shutdown or `stop`; `entry` selects the
    /// transparent entry layer (`None` = explicit proxy).
    async fn accept_loop(
        &self,
        listener: TcpListener,
        shared: Arc<ConnectionShared>,
        entry: Option<Arc<TransparentEntry>>,
        shutdown_tx: &broadcast::Sender<()>,
        mut stop: tokio::sync::oneshot::Receiver<()>,
        ext: bool,
    ) {
        let mut main_shutdown_rx = shutdown_tx.subscribe();
        let transparent = entry.is_some();
        let flags = if ext {
            self.ext_flags.clone()
        } else if transparent {
            self.transparent_flags.clone()
        } else {
            self.explicit_flags.clone()
        };

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, client_addr)) => {
                            // Access control first: nothing from a disallowed source is read.
                            if !self.acl.load().allows(client_addr.ip()) {
                                debug!("Connection from {} refused: not an allowed client", client_addr);
                                drop(stream);
                                continue;
                            }
                            // Check if connection should be admitted
                            match self.load_manager.check_admission() {
                                AdmissionResult::Admitted => {
                                    debug!("Connection from {} admitted", client_addr);
                                }
                                // Rejections are counted and summarized by the load manager.
                                AdmissionResult::RejectedMemoryPressure
                                | AdmissionResult::RejectedMaxConnections
                                | AdmissionResult::RejectedRateLimit => continue,
                            }

                            trace!("Accepted connection from {}", client_addr);

                            let shared = shared.clone();
                            let entry = entry.clone();
                            let flags = flags.clone();
                            let local_ip = stream.local_addr().ok().map(|a| a.ip());
                            let active = flags.open(client_addr.ip());
                            let mut shutdown_rx = shutdown_tx.subscribe();
                            // Spawn a new task to handle this connection; admission already
                            // counted it, and the guard releases it even if the task never runs.
                            spawn_admitted(&self.load_manager, async move {
                                let _active = active;
                                let mut handler = ConnectionHandler::with_listener(client_addr, shared, flags, transparent);
                                if let Some(ip) = local_ip {
                                    handler = handler.with_local_ip(ip);
                                }
                                if ext {
                                    handler = handler.on_ext_listener();
                                }
                                tokio::select! {
                                    // The extension's session ended (closed or revoked): its
                                    // tunnels and keep-alive connections end with it.
                                    _ = handler.ext_session_closed(), if ext => {
                                        debug!("Extension connection from {} closed with its session", client_addr);
                                    }
                                    result = async {
                                        match &entry {
                                            Some(entry) => entry.handle(&handler, stream).await,
                                            None => handler.handle(stream).await,
                                        }
                                    } => {
                                        if let Err(e) = result {
                                            debug!("Connection from {} ended with error: {}", client_addr, e);
                                        }
                                    }
                                    _ = shutdown_rx.recv() => {
                                        debug!("Connection from {} terminated due to shutdown", client_addr);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            warn!("Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = &mut stop => {
                    debug!("Listener on {:?} stopped", listener.local_addr());
                    break;
                }
                _ = main_shutdown_rx.recv() => {
                    info!("Shutting down proxy server...");
                    break;
                }
            }
        }
    }
}

impl ProxyServer {
    /// Create a new proxy server with the given configuration and filtering context.
    pub fn new(config: ProxyConfig, ctx: Arc<ProxyContext>) -> Result<Self> {
        // The extension bridge asks the proxy's EV probe before relaying to a host.
        ctx.internal()
            .gm
            .ext()
            .set_ev_gate(Arc::new(crate::ext_bridge::ProxyEvGate(Arc::downgrade(
                &ctx,
            ))));
        // Reject invalid CIDR lists at startup instead of silently ignoring entries.
        DestPolicy::from_config(&config)?;
        let client_acl = Arc::new(ArcSwap::from_pointee(ClientAcl::new(
            &config.proxy.allowed_clients,
        )?));
        // Old config key -> `migrated` bypass entries, once per persisted state.
        if let Err(e) = ctx
            .bypass()
            .migrate_legacy_once(&config.proxy.tls_passthrough_hosts)
        {
            tracing::warn!("could not migrate tls_passthrough_hosts: {e}");
        }
        ctx.set_require_device_token(config.proxy.require_device_token);
        ctx.set_block_response(config.proxy.block_response);
        ctx.set_cname(&config.adblock.cname);
        ctx.set_request_timeout(std::time::Duration::from_secs(
            config.performance.request_timeout_secs,
        ));

        // Initialize MITM handler if enabled
        let mitm_handler = if config.any_listener(|f| f.mitm) {
            info!("Initializing MITM support");

            // Load or generate CA
            let ca = Arc::new(CertificateAuthority::load_or_generate(
                &config.mitm.ca_cert_path,
                &config.mitm.ca_key_path,
            )?);

            // Create MITM handler with certificate caching
            let handler = MitmHandler::new(
                ca,
                config.mitm.cert_cache_size,
                config.mitm.cert_ttl_days * 24 * 3600, // Convert days to seconds
                config.performance.max_cert_generations,
            )
            .with_http2(true);

            Some(Arc::new(handler))
        } else {
            info!("MITM support disabled");
            None
        };

        // Initialize load manager with configuration from performance settings
        let load_manager_config = LoadManagerConfig {
            max_connections: match config.performance.max_connections {
                0 => crate::load_manager::derive_max_connections(),
                n => n,
            },
            connection_rate_limit: config.performance.effective_connection_rate_limit(),
            adaptive_concurrency: true,
            ..Default::default()
        };
        info!(
            "Load manager initialized: max_connections={}, rate_limit={}/s, fd_limit={}, \
             fds_per_connection={}, fd_reserve={}, pool_idle_per_host={}",
            load_manager_config.max_connections,
            load_manager_config.connection_rate_limit,
            match common::config::raise_nofile_limit() {
                Some(u64::MAX) => "unlimited".to_string(),
                Some(n) => n.to_string(),
                None => "unknown".to_string(),
            },
            common::config::FDS_PER_CONNECTION,
            common::config::FD_RESERVE,
            common::config::pool_idle_per_host(load_manager_config.max_connections),
        );
        let load_manager = Arc::new(LoadManager::new(load_manager_config));
        let control = Arc::new(ProxyControl {
            acl: client_acl,
            ctx: ctx.clone(),
            load_manager: load_manager.clone(),
            original_dst: None,
            own_names: parking_lot::Mutex::new(own_names_of(&config)),
            webui_own: parking_lot::Mutex::new(
                config
                    .webui
                    .enabled
                    .then(|| (config.webui.port, config.webui.host.parse().ok())),
            ),
            entry_ports: Arc::default(),
            explicit_flags: Arc::new(crate::listener_flags::ListenerFlags::new(
                config.listener_flags(false),
            )),
            transparent_flags: Arc::new(crate::listener_flags::ListenerFlags::new(
                config.listener_flags(true),
            )),
            ext_flags: Arc::new(crate::listener_flags::ListenerFlags::new(
                config.listener_flags(false),
            )),
            ext: tokio::sync::Mutex::new(None),
            ext_own: parking_lot::Mutex::new(None),
            timeouts: Arc::new(ArcSwap::from_pointee(Timeouts::from_config(
                &config.performance,
            ))),
            live: ArcSwapOption::empty(),
            #[cfg(any(test, feature = "test-hooks"))]
            fail_restore: std::sync::atomic::AtomicBool::new(false),
            lazy_cfg: parking_lot::Mutex::new(LazyCfg::of(&config)),
            dns_cfg: parking_lot::Mutex::new((config.dns.clone(), Vec::new())),
            dns_dir: config.adblock.data_dir.clone(),
            legacy_passthrough: parking_lot::Mutex::new(config.proxy.tls_passthrough_hosts.clone()),
            running: tokio::sync::Mutex::new(None),
        });

        Ok(Self {
            config,
            mitm_handler,
            load_manager,
            ctx,
            control,
        })
    }

    /// Handle for live changes (rebinding listeners, access lists). Take it before `start`.
    pub fn control(&self) -> Arc<ProxyControl> {
        self.control.clone()
    }

    /// Create a new proxy server with custom load manager configuration
    pub fn with_load_manager(
        config: ProxyConfig,
        load_manager_config: LoadManagerConfig,
        ctx: Arc<ProxyContext>,
    ) -> Result<Self> {
        let mut server = Self::new(config, ctx)?;
        server.load_manager = Arc::new(LoadManager::new(load_manager_config));
        Arc::get_mut(&mut server.control)
            .expect("control is not shared yet")
            .load_manager = server.load_manager.clone();
        Ok(server)
    }

    /// Use `original_dst` instead of the kernel lookup for the transparent listener (tests and
    /// controlled setups).
    pub fn with_original_dst(mut self, original_dst: Arc<dyn OriginalDst>) -> Self {
        Arc::get_mut(&mut self.control)
            .expect("control is not shared yet")
            .original_dst = Some(original_dst);
        self
    }

    /// Start the proxy server with graceful shutdown
    pub async fn start(&self) -> Result<()> {
        let host = &self.config.proxy.host;
        let bind = |port: u16, what: &'static str| async move {
            let a = spec_addr(host, port);
            TcpListener::bind(&a).await.map_err(|e| {
                let msg = format!("cannot bind {what} to {a}: {e}");
                tracing::error!("{msg}; starting without it, fix it in the web UI");
                msg
            })
        };
        let listener = bind(self.config.proxy.port, "proxy").await;
        let transparent = match self.config.proxy.transparent_port {
            Some(port) => Some(bind(port, "transparent listener").await),
            None => None,
        };

        // Create shutdown channel and spawn the signal handler.
        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        let shutdown_signal = shutdown_tx.clone();
        tokio::spawn(async move {
            shutdown_signal_handler().await;
            info!("Shutdown signal received, stopping server...");
            let _ = shutdown_signal.send(());
        });

        self.serve_parts(listener, transparent, shutdown_tx).await
    }

    /// Serve on an already-bound listener until `shutdown_tx` fires. Lets callers (and tests)
    /// bind port 0 and keep the listener, avoiding bind-then-drop races.
    pub async fn serve(
        &self,
        listener: TcpListener,
        shutdown_tx: broadcast::Sender<()>,
    ) -> Result<()> {
        self.serve_all(listener, None, shutdown_tx).await
    }

    /// Like [`Self::serve`], plus an optional already-bound transparent-gateway listener served
    /// with the same admission control, shared pipeline and shutdown signal.
    pub async fn serve_all(
        &self,
        listener: TcpListener,
        transparent: Option<TcpListener>,
        shutdown_tx: broadcast::Sender<()>,
    ) -> Result<()> {
        self.serve_parts(Ok(listener), transparent.map(Ok), shutdown_tx)
            .await
    }

    /// `serve_all` where a listener may have failed to bind (`Err` = reason): it starts down
    /// and a rebind can bring it up, so the process stays alive for the web UI.
    async fn serve_parts(
        &self,
        listener: std::result::Result<TcpListener, String>,
        transparent: Option<std::result::Result<TcpListener, String>>,
        shutdown_tx: broadcast::Sender<()>,
    ) -> Result<()> {
        match &listener {
            Ok(l) => info!(
                "Proxy server listening on {}",
                l.local_addr().map(|a| a.to_string()).unwrap_or_default()
            ),
            Err(_) => warn!("Proxy server is NOT listening (bind failed)"),
        }

        // The extension bridge relays only while the extension listener decrypts, and never to
        // Argus itself (its console, its panel and dashboard hosts).
        {
            let hub = self.ctx.internal().gm.ext();
            let w = Arc::downgrade(&self.control);
            hub.set_mitm_probe(Arc::new(move || {
                w.upgrade().is_some_and(|c| {
                    c.ext_flags.mitm()
                        && c.live
                            .load()
                            .as_ref()
                            .is_some_and(|l| l.shared.mitm.load().is_some())
                })
            }));
            let (wc, wx) = (Arc::downgrade(&self.control), Arc::downgrade(&self.ctx));
            hub.set_own_resolver(Arc::new(OwnResolver(Arc::downgrade(&self.control))));
            hub.set_own_guard(Arc::new(move |host: &str, port: u16| {
                let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
                if wx.upgrade().is_some_and(|x| x.is_panel_host(&host))
                    || wc
                        .upgrade()
                        .is_some_and(|c| c.own_names.lock().contains(&host))
                {
                    return true;
                }
                wc.upgrade().is_some_and(|c| {
                    c.webui_own.lock().is_some_and(|(p, ip)| {
                        p == port
                            && ip.is_none_or(|ip| {
                                ip.is_unspecified() || host.parse::<IpAddr>().ok() == Some(ip)
                            })
                    })
                })
            }));
        }

        let cfg_host = self.config.proxy.host.clone();
        for (name, t) in [("explicit", false), ("transparent", true)] {
            let f = self.config.listener_flags(t);
            info!(
                "{name} listener: MITM {}, HTTP/2 {}, WebSockets {}, ad blocking {}",
                f.mitm, f.http2, f.websockets, f.adblock
            );
        }

        if let Some(ref mitm) = self.mitm_handler {
            let stats = mitm.cache_stats();
            info!(
                "MITM cache initialized: {} entries, {} weighted size",
                stats.entry_count, stats.weighted_size
            );
        }

        // Start load manager monitoring
        let _monitoring_handle = self.load_manager.start_monitoring();
        info!("Load manager monitoring started");

        let timeouts = self.control.timeouts.clone();
        let t0 = **timeouts.load();
        let shared = Arc::new(ConnectionShared {
            mitm: ArcSwapOption::new(self.mitm_handler.clone()),
            enable_http2: self.config.any_listener(|f| f.http2),
            enable_websockets: self.config.any_listener(|f| f.websockets),
            ctx: self.ctx.clone(),
            timeouts,
            #[cfg(feature = "websockets")]
            ws: if self.config.any_listener(|f| f.websockets) {
                ArcSwapOption::new(Some(Arc::new(
                    crate::websocket::WsUpstream::new(t0.handshake)
                        .with_lifecycle(t0.tunnel_idle, shutdown_tx.clone()),
                )))
            } else {
                ArcSwapOption::empty()
            },
        });

        let mut shutdown_rx = shutdown_tx.subscribe();
        let ctl = &self.control;
        ctl.live.store(Some(Arc::new(LiveParts {
            shared: shared.clone(),
            shutdown_tx: shutdown_tx.clone(),
        })));
        let entry = match &transparent {
            Some(t) => {
                if let Ok(t) = t {
                    info!(
                        "Transparent listener on {}",
                        t.local_addr().map(|a| a.to_string()).unwrap_or_default()
                    );
                }
                Some(ctl.make_entry()?)
            }
            None => None,
        };
        let down_addr = |port: u16| {
            spec_addr(&cfg_host, port)
                .parse::<SocketAddr>()
                .unwrap_or(SocketAddr::from(([0, 0, 0, 0], port)))
        };
        let explicit_req = (cfg_host.clone(), self.config.proxy.port);
        let explicit = match listener {
            Ok(l) => ctl.spawn_listener(l, shared.clone(), None, &shutdown_tx, explicit_req),
            Err(e) => Listener::down(down_addr(explicit_req.1), explicit_req, e),
        };
        let transparent = transparent.map(|t| {
            let port = self.config.proxy.transparent_port.unwrap_or(0);
            match t {
                Ok(t) => {
                    let port = if port == 0 {
                        t.local_addr().map_or(0, |a| a.port())
                    } else {
                        port
                    };
                    ctl.spawn_listener(
                        t,
                        shared.clone(),
                        entry.clone(),
                        &shutdown_tx,
                        (cfg_host.clone(), port),
                    )
                }
                Err(e) => Listener::down(down_addr(port), (cfg_host.clone(), port), e),
            }
        });
        ctl.publish_own(&explicit, transparent.as_ref());
        let ext_port = self.config.proxy.ext_port;
        *ctl.running.lock().await = Some(Running {
            shared,
            shutdown_tx: shutdown_tx.clone(),
            explicit,
            transparent,
            entry,
        });

        if let Some(p) = ext_port {
            if let Err(e) = ctl.rebind_ext(&cfg_host, Some(p)).await {
                warn!("Extension listener is NOT listening: {e}");
            }
        }

        // Serve until shutdown; rebinds replace the loops in `running` meanwhile.
        let _ = shutdown_rx.recv().await;
        if let Some(l) = ctl.ext.lock().await.take() {
            l.stop().await;
        }
        if let Some(run) = ctl.running.lock().await.take() {
            run.explicit.stop().await;
            if let Some(t) = run.transparent {
                t.stop().await;
            }
        }

        // Log final statistics
        let stats = self.load_manager.stats();
        info!(
            "Proxy server stopped. Final stats: accepted={}, rejected={} (memory={}, max={}, rate={})",
            stats.connections_accepted,
            stats.connections_rejected,
            stats.connections_rejected_memory,
            stats.connections_rejected_max,
            stats.connections_rejected_rate
        );

        Ok(())
    }

    /// Get MITM handler
    pub fn mitm_handler(&self) -> Option<&Arc<MitmHandler>> {
        self.mitm_handler.as_ref()
    }

    /// Get load manager
    pub fn load_manager(&self) -> &Arc<LoadManager> {
        &self.load_manager
    }

    /// Get load manager statistics
    pub fn load_stats(&self) -> crate::load_manager::LoadManagerStatsSnapshot {
        self.load_manager.stats()
    }
}

/// Wait for shutdown signal (SIGINT or SIGTERM)
/// Spawn the task of an admitted connection. The guard is created here, before the spawn, so a
/// task dropped or aborted before its first poll still releases the admission it holds.
fn spawn_admitted<F>(load_manager: &Arc<LoadManager>, fut: F) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let guard = ConnectionGuard::new(load_manager.clone());
    tokio::spawn(async move {
        let _guard = guard;
        fut.await
    })
}

async fn shutdown_signal_handler() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal");
        }
        _ = terminate => {
            info!("Received SIGTERM signal");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn a_task_aborted_before_its_first_poll_releases_its_admission() {
        let lm = Arc::new(LoadManager::with_defaults());
        assert_eq!(lm.check_admission(), AdmissionResult::Admitted);
        assert_eq!(lm.stats().active_connections, 1);
        let h = spawn_admitted(&lm, std::future::pending());
        // Current-thread runtime: the spawned task has not been polled yet.
        h.abort();
        let _ = h.await;
        assert_eq!(lm.stats().active_connections, 0);
    }
}

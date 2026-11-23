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
}

impl Listener {
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
    /// Switches of each listener, shared with its connections.
    explicit_flags: Arc<crate::listener_flags::ListenerFlags>,
    transparent_flags: Arc<crate::listener_flags::ListenerFlags>,
    /// Live time limits, shared with every connection.
    timeouts: Arc<ArcSwap<Timeouts>>,
    /// Set once the server runs: what a lazy MITM / WebSocket enable installs into.
    live: ArcSwapOption<LiveParts>,
    /// Settings the lazy setup needs (CA paths and cache sizes, extra upstream CAs).
    lazy_cfg: parking_lot::Mutex<LazyCfg>,
    /// The `tls_passthrough_hosts` last synced into the bypass entries.
    legacy_passthrough: parking_lot::Mutex<Vec<String>>,
    /// DNS settings currently in effect (a change rebuilds the resolver and flushes its cache).
    dns_cfg: parking_lot::Mutex<common::config::DnsSettings>,
    /// Test hook: make restoring a closed listener fail.
    #[cfg(any(test, feature = "test-hooks"))]
    fail_restore: std::sync::atomic::AtomicBool,
    /// The proxy's own ports (explicit + transparent) for the transparent loop guard.
    entry_ports: Arc<parking_lot::RwLock<Vec<u16>>>,
    running: tokio::sync::Mutex<Option<Running>>,
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
        self.running.lock().await.as_ref().map(|r| BindInfo {
            proxy: r.explicit.addr,
            transparent: r.transparent.as_ref().map(|t| t.addr),
            proxy_down: r.explicit.down,
            transparent_down: r.transparent.as_ref().is_some_and(|t| t.down),
        })
    }

    /// Note where the web API listens (own-listener loop protection); call after it rebinds.
    pub async fn set_webui_listener(&self, host: &str, port: u16) {
        *self.webui_own.lock() = Some((port, host.parse().ok()));
        let guard = self.running.lock().await;
        if let Some(r) = guard.as_ref() {
            self.publish_own(&r.explicit, r.transparent.as_ref());
        }
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
            let (roots, policy, resolve) = (
                self.ctx
                    .roots_handle(&config.proxy.extra_upstream_ca_paths)?,
                self.ctx.policy().clone(),
                self.ctx.resolve_all_to(),
            );
            let shutdown = l.shutdown_tx.clone();
            new_ws = Some(Arc::new(
                tokio::task::spawn_blocking(move || {
                    crate::websocket::WsUpstream::new(roots, policy, resolve, t.handshake)
                        .map(|w| w.with_lifecycle(t.tunnel_idle, shutdown))
                })
                .await
                .map_err(|e| Error::Internal(e.to_string()))??,
            ));
        }
        let upstream = self
            .ctx
            .prepare_upstream_timeouts(t.handshake, t.header_read)?;
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
        self.explicit_flags.set(config.listener_flags(false));
        self.transparent_flags.set(config.listener_flags(true));
        {
            let mut cur = self.dns_cfg.lock();
            if format!("{:?}", *cur) != format!("{:?}", config.dns) {
                if let Some(d) = self.ctx.dns() {
                    d.reconfigure(&config.dns);
                }
                *cur = config.dns.clone();
            }
        }
        self.timeouts.store(Arc::new(t));
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
    fn publish_own(&self, explicit: &Listener, transparent: Option<&Listener>) {
        let mut ports: Vec<u16> = Vec::new();
        let mut addrs: Vec<IpAddr> = Vec::new();
        for l in std::iter::once(explicit).chain(transparent) {
            ports.push(l.addr.port());
            addrs.push(l.addr.ip());
        }
        if let Some((port, ip)) = *self.webui_own.lock() {
            ports.push(port);
            addrs.extend(ip);
        }
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
            return Ok(BindInfo {
                proxy: run.explicit.addr,
                transparent: run.transparent.as_ref().map(|t| t.addr),
                proxy_down: false,
                transparent_down: false,
            });
        }

        // Bind the replacements. When the new address collides with the old socket of the same
        // loop (same port, other host), close the old one first and keep its address to restore.
        type Closed = Option<(SocketAddr, (String, u16))>;
        let mut closed: [Closed; 2] = [None, None];
        let mut new_e: Option<TcpListener> = None;
        let mut new_t: Option<TcpListener> = None;
        let mut err: Option<Error> = None;

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
                Err(e) => err = Some(Error::Connection(format!("cannot bind proxy to {a}: {e}"))),
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
                Err(e) => err = Some(e),
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
                        tracing::error!("could not restore listener on {addr}: {re}");
                    }
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
        Ok(BindInfo {
            proxy: run.explicit.addr,
            transparent: run.transparent.as_ref().map(|t| t.addr),
            proxy_down: false,
            transparent_down: false,
        })
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
        let addr = listener
            .local_addr()
            .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
        let (stop, stop_rx) = tokio::sync::oneshot::channel();
        let this = self.clone();
        let shutdown_tx = shutdown_tx.clone();
        let task = tokio::spawn(async move {
            this.accept_loop(listener, shared, entry, &shutdown_tx, stop_rx)
                .await
        });
        Listener {
            addr,
            requested,
            stop: Some(stop),
            task,
            down: false,
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
    ) {
        let mut main_shutdown_rx = shutdown_tx.subscribe();
        let transparent = entry.is_some();
        let flags = if transparent {
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
                            let active = flags.open(client_addr.ip());
                            let mut shutdown_rx = shutdown_tx.subscribe();
                            // Spawn a new task to handle this connection; admission already
                            // counted it, and the guard releases it even if the task never runs.
                            spawn_admitted(&self.load_manager, async move {
                                let _active = active;
                                let handler = ConnectionHandler::with_listener(client_addr, shared, flags, transparent);
                                tokio::select! {
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
            timeouts: Arc::new(ArcSwap::from_pointee(Timeouts::from_config(
                &config.performance,
            ))),
            live: ArcSwapOption::empty(),
            #[cfg(any(test, feature = "test-hooks"))]
            fail_restore: std::sync::atomic::AtomicBool::new(false),
            lazy_cfg: parking_lot::Mutex::new(LazyCfg::of(&config)),
            dns_cfg: parking_lot::Mutex::new(config.dns.clone()),
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
        let addr = format!("{}:{}", self.config.proxy.host, self.config.proxy.port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| Error::Connection(format!("Failed to bind to {}: {}", addr, e)))?;

        let transparent = match self.config.proxy.transparent_port {
            Some(port) => {
                let taddr = format!("{}:{}", self.config.proxy.host, port);
                Some(TcpListener::bind(&taddr).await.map_err(|e| {
                    Error::Connection(format!("Failed to bind transparent listener {taddr}: {e}"))
                })?)
            }
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

        self.serve_all(listener, transparent, shutdown_tx).await
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
        let addr = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        info!("Proxy server listening on {}", addr);

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
                    crate::websocket::WsUpstream::new(
                        self.ctx
                            .roots_handle(&self.config.proxy.extra_upstream_ca_paths)?,
                        self.ctx.policy().clone(),
                        self.ctx.resolve_all_to(),
                        t0.handshake,
                    )?
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
                info!(
                    "Transparent listener on {}",
                    t.local_addr().map(|a| a.to_string()).unwrap_or_default()
                );
                Some(ctl.make_entry()?)
            }
            None => None,
        };
        let t_port = transparent
            .as_ref()
            .and_then(|t| t.local_addr().ok())
            .map_or(0, |a| a.port());
        let explicit = ctl.spawn_listener(
            listener,
            shared.clone(),
            None,
            &shutdown_tx,
            (cfg_host.clone(), self.config.proxy.port),
        );
        let transparent = transparent.map(|t| {
            ctl.spawn_listener(
                t,
                shared.clone(),
                entry.clone(),
                &shutdown_tx,
                (
                    cfg_host.clone(),
                    self.config.proxy.transparent_port.unwrap_or(t_port),
                ),
            )
        });
        ctl.publish_own(&explicit, transparent.as_ref());
        *ctl.running.lock().await = Some(Running {
            shared,
            shutdown_tx: shutdown_tx.clone(),
            explicit,
            transparent,
            entry,
        });

        // Serve until shutdown; rebinds replace the loops in `running` meanwhile.
        let _ = shutdown_rx.recv().await;
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

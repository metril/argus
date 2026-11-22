//! Main proxy server implementation

use crate::{
    ca::CertificateAuthority,
    config::ProxyConfig,
    connection::{ConnectionHandler, ConnectionShared, Timeouts},
    filtering::ProxyContext,
    load_manager::{AdmissionResult, ConnectionGuard, LoadManager, LoadManagerConfig},
    mitm::MitmHandler,
    passthrough::PassthroughList,
    policy::{ClientAcl, DestPolicy},
    transparent::{
        KernelOriginalDst, OriginalDst, TransparentEntry, KERNEL_ORIGINAL_DST_SUPPORTED,
    },
    Error, Result,
};
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
    /// Original-destination source for the transparent listener. Code-only (never from config);
    /// `None` means the kernel's `SO_ORIGINAL_DST`.
    original_dst: Option<Arc<dyn OriginalDst>>,
    /// Who may connect (checked at accept, before any parsing).
    client_acl: Arc<ClientAcl>,
}

impl ProxyServer {
    /// Create a new proxy server with the given configuration and filtering context.
    pub fn new(config: ProxyConfig, ctx: Arc<ProxyContext>) -> Result<Self> {
        // Reject invalid CIDR lists at startup instead of silently ignoring entries.
        DestPolicy::from_config(&config)?;
        let client_acl = Arc::new(ClientAcl::new(&config.proxy.allowed_clients)?);
        ctx.set_request_timeout(std::time::Duration::from_secs(
            config.performance.request_timeout_secs,
        ));

        // Initialize MITM handler if enabled
        let mitm_handler = if config.mitm.enabled {
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
            .with_http2(config.proxy.enable_http2);

            Some(Arc::new(handler))
        } else {
            info!("MITM support disabled");
            None
        };

        // Initialize load manager with configuration from performance settings
        let load_manager_config = LoadManagerConfig {
            max_connections: config.performance.max_connections,
            connection_rate_limit: config.performance.connection_rate_limit.unwrap_or(1000),
            adaptive_concurrency: true,
            ..Default::default()
        };
        let load_manager = Arc::new(LoadManager::new(load_manager_config));

        info!(
            "Load manager initialized: max_connections={}, rate_limit={}/s",
            config.performance.max_connections,
            config.performance.connection_rate_limit.unwrap_or(1000)
        );

        Ok(Self {
            config,
            mitm_handler,
            load_manager,
            ctx,
            original_dst: None,
            client_acl,
        })
    }

    /// Create a new proxy server with custom load manager configuration
    pub fn with_load_manager(
        config: ProxyConfig,
        load_manager_config: LoadManagerConfig,
        ctx: Arc<ProxyContext>,
    ) -> Result<Self> {
        let mut server = Self::new(config, ctx)?;
        server.load_manager = Arc::new(LoadManager::new(load_manager_config));
        Ok(server)
    }

    /// Use `original_dst` instead of the kernel lookup for the transparent listener (tests and
    /// controlled setups).
    pub fn with_original_dst(mut self, original_dst: Arc<dyn OriginalDst>) -> Self {
        self.original_dst = Some(original_dst);
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

        // Tell the destination policy which listeners are the proxy's own (loop protection).
        let mut own_ports: Vec<u16> = Vec::new();
        let mut own_addrs: Vec<std::net::IpAddr> = Vec::new();
        for l in std::iter::once(&listener).chain(transparent.as_ref()) {
            if let Ok(a) = l.local_addr() {
                own_ports.push(a.port());
                own_addrs.push(a.ip());
            }
        }
        if self.config.webui.enabled {
            own_ports.push(self.config.webui.port);
            if let Ok(ip) = self.config.webui.host.parse() {
                own_addrs.push(ip);
            }
        }
        own_ports.sort_unstable();
        own_ports.dedup();
        self.ctx.policy().set_own_listeners(&own_ports, &own_addrs);
        info!("HTTP/2: {}", self.config.proxy.enable_http2);
        info!("WebSockets: {}", self.config.proxy.enable_websockets);
        info!("MITM: {}", self.config.mitm.enabled);

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

        let timeouts = Timeouts::from_config(&self.config.performance);
        let shared = Arc::new(ConnectionShared {
            mitm: self.mitm_handler.clone(),
            enable_http2: self.config.proxy.enable_http2,
            enable_websockets: self.config.proxy.enable_websockets,
            ctx: self.ctx.clone(),
            timeouts,
            passthrough: PassthroughList::new(&self.config.proxy.tls_passthrough_hosts),
            #[cfg(feature = "websockets")]
            ws: if self.config.proxy.enable_websockets {
                Some(Arc::new(
                    crate::websocket::WsUpstream::new(
                        &self.config.proxy.extra_upstream_ca_paths,
                        self.ctx.policy().clone(),
                        self.ctx.resolve_all_to(),
                        timeouts.handshake,
                    )?
                    .with_lifecycle(timeouts.tunnel_idle, shutdown_tx.clone()),
                ))
            } else {
                None
            },
        });

        let entry = match &transparent {
            Some(t) => {
                let original_dst = match &self.original_dst {
                    Some(d) => d.clone(),
                    None if KERNEL_ORIGINAL_DST_SUPPORTED => Arc::new(KernelOriginalDst),
                    None => {
                        return Err(Error::Config(
                            "transparent mode is only supported on Linux".into(),
                        ))
                    }
                };
                let own_ports: Vec<u16> = [listener.local_addr(), t.local_addr()]
                    .into_iter()
                    .flatten()
                    .map(|a| a.port())
                    .collect();
                info!(
                    "Transparent listener on {}",
                    t.local_addr().map(|a| a.to_string()).unwrap_or_default()
                );
                Some(Arc::new(TransparentEntry::new(original_dst, own_ports)))
            }
            None => None,
        };

        let explicit_loop = self.accept_loop(listener, shared.clone(), None, &shutdown_tx);
        let transparent_loop = async {
            if let Some(t) = transparent {
                self.accept_loop(t, shared.clone(), entry, &shutdown_tx)
                    .await;
            }
        };
        tokio::join!(explicit_loop, transparent_loop);

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

    /// Accept connections on `listener` until shutdown; `entry` selects the transparent entry
    /// layer (`None` = explicit proxy).
    async fn accept_loop(
        &self,
        listener: TcpListener,
        shared: Arc<ConnectionShared>,
        entry: Option<Arc<TransparentEntry>>,
        shutdown_tx: &broadcast::Sender<()>,
    ) {
        let mut main_shutdown_rx = shutdown_tx.subscribe();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, client_addr)) => {
                            // Access control first: nothing from a disallowed source is read.
                            if !self.client_acl.allows(client_addr.ip()) {
                                debug!("Connection from {} refused: not an allowed client", client_addr);
                                drop(stream);
                                continue;
                            }
                            // Check if connection should be admitted
                            match self.load_manager.check_admission() {
                                AdmissionResult::Admitted => {
                                    debug!("Connection from {} admitted", client_addr);
                                }
                                AdmissionResult::RejectedMemoryPressure => {
                                    warn!("Connection from {} rejected: memory pressure", client_addr);
                                    // Connection is dropped automatically
                                    continue;
                                }
                                AdmissionResult::RejectedMaxConnections => {
                                    warn!("Connection from {} rejected: max connections reached", client_addr);
                                    continue;
                                }
                                AdmissionResult::RejectedRateLimit => {
                                    debug!("Connection from {} rejected: rate limit", client_addr);
                                    continue;
                                }
                            }

                            trace!("Accepted connection from {}", client_addr);

                            let shared = shared.clone();
                            let entry = entry.clone();
                            let mut shutdown_rx = shutdown_tx.subscribe();
                            let load_manager = self.load_manager.clone();

                            // Spawn a new task to handle this connection
                            tokio::spawn(async move {
                                // Create connection guard for automatic cleanup
                                let _guard = ConnectionGuard::new(load_manager);

                                let handler = ConnectionHandler::new(client_addr, shared);
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
                                // _guard is dropped here, releasing the connection
                            });
                        }
                        Err(e) => {
                            warn!("Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = main_shutdown_rx.recv() => {
                    info!("Shutting down proxy server...");
                    break;
                }
            }
        }
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

//! Main proxy server implementation

use crate::{
    ca::CertificateAuthority,
    config::ProxyConfig,
    connection::ConnectionHandler,
    filtering::ProxyContext,
    load_manager::{AdmissionResult, ConnectionGuard, LoadManager, LoadManagerConfig},
    mitm::MitmHandler,
    Error, Result,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

pub struct ProxyServer {
    config: ProxyConfig,
    mitm_handler: Option<Arc<MitmHandler>>,
    load_manager: Arc<LoadManager>,
    /// Shared filtering + upstream-forwarding context handed to each connection.
    ctx: Arc<ProxyContext>,
}

impl ProxyServer {
    /// Create a new proxy server with the given configuration and filtering context.
    pub fn new(config: ProxyConfig, ctx: Arc<ProxyContext>) -> Result<Self> {
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
            );

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

    /// Start the proxy server with graceful shutdown
    pub async fn start(&self) -> Result<()> {
        let addr = format!("{}:{}", self.config.proxy.host, self.config.proxy.port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| Error::Connection(format!("Failed to bind to {}: {}", addr, e)))?;

        info!("Proxy server listening on {}", addr);
        info!("HTTP/2: {}", self.config.proxy.enable_http2);
        info!("HTTP/3: {}", self.config.proxy.enable_http3);
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

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel::<()>(1);

        // Start HTTP/3 server if enabled
        #[cfg(feature = "http3")]
        if self.config.proxy.enable_http3 {
            self.start_http3_server(shutdown_tx.subscribe()).await?;
        }

        // Spawn signal handler
        let shutdown_signal = shutdown_tx.clone();
        tokio::spawn(async move {
            shutdown_signal_handler().await;
            info!("Shutdown signal received, stopping server...");
            let _ = shutdown_signal.send(());
        });

        // Subscribe to shutdown signal for the main loop
        let mut main_shutdown_rx = shutdown_tx.subscribe();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, client_addr)) => {
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

                            info!("Accepted connection from {}", client_addr);

                            // Clone the MITM handler, config, and load manager for this connection
                            let mitm_handler = self.mitm_handler.clone();
                            let enable_http2 = self.config.proxy.enable_http2;
                            let enable_websockets = self.config.proxy.enable_websockets;
                            let mut shutdown_rx = shutdown_tx.subscribe();
                            let load_manager = self.load_manager.clone();
                            let ctx = self.ctx.clone();

                            // Spawn a new task to handle this connection
                            tokio::spawn(async move {
                                // Create connection guard for automatic cleanup
                                let _guard = ConnectionGuard::new(load_manager);

                                let handler = ConnectionHandler::new(client_addr, mitm_handler, enable_http2, enable_websockets, ctx);
                                tokio::select! {
                                    result = handler.handle(stream) => {
                                        if let Err(e) = result {
                                            warn!("Error handling connection from {}: {}", client_addr, e);
                                        }
                                    }
                                    _ = shutdown_rx.recv() => {
                                        info!("Connection from {} terminated due to shutdown", client_addr);
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

    /// Start HTTP/3 server (optional feature)
    #[cfg(feature = "http3")]
    async fn start_http3_server(&self, shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        use proxy_http3::{Http3Filter, Http3Server, QuicConfig};

        // HTTP/3 requires MITM to be enabled for certificate generation
        let mitm_handler = self.mitm_handler.as_ref()
            .ok_or_else(|| Error::Config("HTTP/3 requires MITM to be enabled".to_string()))?;

        // Get CA reference for QUIC/TLS
        let _ca = mitm_handler.ca();
        let ca_cert_pem = std::fs::read_to_string(&self.config.mitm.ca_cert_path)
            .map_err(|e| Error::Tls(format!("Failed to read CA certificate: {}", e)))?;
        let ca_key_pem = std::fs::read_to_string(&self.config.mitm.ca_key_path)
            .map_err(|e| Error::Tls(format!("Failed to read CA key: {}", e)))?;

        // Parse CA certificate and key
        let ca_certs = rustls_pemfile::certs(&mut ca_cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Tls(format!("Failed to parse CA certificate: {}", e)))?;

        let ca_key = rustls_pemfile::private_key(&mut ca_key_pem.as_bytes())
            .map_err(|e| Error::Tls(format!("Failed to parse CA key: {}", e)))?
            .ok_or_else(|| Error::Tls("No private key found in CA key file".to_string()))?;

        // Create TLS config with ALPN for HTTP/3
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(ca_certs, ca_key)
            .map_err(|e| Error::Tls(format!("Failed to create TLS config: {}", e)))?;

        // HTTP/3 requires "h3" ALPN protocol
        tls_config.alpn_protocols = vec![b"h3".to_vec()];

        // Create QUIC configuration
        let udp_addr = format!("{}:{}", self.config.proxy.host, self.config.proxy.port)
            .parse()
            .map_err(|e| Error::Connection(format!("Invalid address: {}", e)))?;

        let quic_config = QuicConfig::new(udp_addr, Arc::new(tls_config));
        let endpoint = quic_config.create_endpoint()
            .map_err(|e| Error::Connection(format!("Failed to create QUIC endpoint: {}", e)))?;

        info!("HTTP/3 server will start on UDP {}", udp_addr);

        // Spawn HTTP/3 server in background, sharing the same filtering engine + upstream client.
        let h3_filter = Arc::new(Http3Filter::new(
            self.ctx.engine().clone(),
            self.ctx.client(),
            self.ctx.adblock_enabled(),
        ));
        let http3_server = Http3Server::new(endpoint, h3_filter);
        tokio::spawn(async move {
            if let Err(e) = http3_server.start(shutdown_rx).await {
                warn!("HTTP/3 server error: {}", e);
            }
        });

        Ok(())
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

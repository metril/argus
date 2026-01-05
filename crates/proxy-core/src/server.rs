//! Main proxy server implementation

use crate::{
    ca::CertificateAuthority, config::ProxyConfig, connection::ConnectionHandler, mitm::MitmHandler,
    Error, Result,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{info, warn};

pub struct ProxyServer {
    config: ProxyConfig,
    mitm_handler: Option<Arc<MitmHandler>>,
}

impl ProxyServer {
    /// Create a new proxy server with the given configuration
    pub fn new(config: ProxyConfig) -> Result<Self> {
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

        Ok(Self {
            config,
            mitm_handler,
        })
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

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel::<()>(1);

        // Spawn signal handler
        let shutdown_signal = shutdown_tx.clone();
        tokio::spawn(async move {
            shutdown_signal_handler().await;
            info!("Shutdown signal received, stopping server...");
            let _ = shutdown_signal.send(());
        });

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, client_addr)) => {
                            info!("Accepted connection from {}", client_addr);

                            // Clone the MITM handler and config for this connection
                            let mitm_handler = self.mitm_handler.clone();
                            let enable_http2 = self.config.proxy.enable_http2;
                            let mut shutdown_rx = shutdown_tx.subscribe();

                            // Spawn a new task to handle this connection
                            tokio::spawn(async move {
                                tokio::select! {
                                    result = ConnectionHandler::new(client_addr, mitm_handler, enable_http2).handle(stream) => {
                                        if let Err(e) = result {
                                            warn!("Error handling connection from {}: {}", client_addr, e);
                                        }
                                    }
                                    _ = shutdown_rx.recv() => {
                                        info!("Connection from {} terminated due to shutdown", client_addr);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            warn!("Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = shutdown_tx.subscribe().recv() => {
                    info!("Shutting down proxy server...");
                    break;
                }
            }
        }

        info!("Proxy server stopped");
        Ok(())
    }

    /// Get MITM handler
    pub fn mitm_handler(&self) -> Option<&Arc<MitmHandler>> {
        self.mitm_handler.as_ref()
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

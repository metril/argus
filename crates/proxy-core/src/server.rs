//! Main proxy server implementation

use crate::{config::ProxyConfig, Error, Result};
use tokio::net::TcpListener;
use tracing::{info, warn};

pub struct ProxyServer {
    config: ProxyConfig,
}

impl ProxyServer {
    /// Create a new proxy server with the given configuration
    pub fn new(config: ProxyConfig) -> Self {
        Self { config }
    }

    /// Start the proxy server
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

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("Accepted connection from {}", addr);
                    // TODO: Handle connection
                    drop(stream);
                }
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

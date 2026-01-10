//! QUIC configuration and endpoint management

use crate::{Error, Result};
use quinn::{Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info};

/// QUIC configuration for HTTP/3 support
#[derive(Clone)]
pub struct QuicConfig {
    /// Server address to bind to
    pub bind_addr: SocketAddr,
    /// TLS server configuration
    pub tls_config: Arc<rustls::ServerConfig>,
    /// Maximum concurrent bidirectional streams
    pub max_concurrent_bidi_streams: u64,
    /// Maximum concurrent unidirectional streams
    pub max_concurrent_uni_streams: u64,
}

impl QuicConfig {
    /// Create a new QUIC configuration
    pub fn new(bind_addr: SocketAddr, tls_config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            bind_addr,
            tls_config,
            max_concurrent_bidi_streams: 100,
            max_concurrent_uni_streams: 100,
        }
    }

    /// Build a Quinn ServerConfig from this configuration
    pub fn build_server_config(&self) -> Result<ServerConfig> {
        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from((*self.tls_config).clone())
            .map_err(|e| Error::QuicEndpoint(format!("Failed to create QUIC crypto config: {}", e)))?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));

        // Configure transport parameters
        let mut transport_config = quinn::TransportConfig::default();

        // Set stream limits
        transport_config
            .max_concurrent_bidi_streams(self.max_concurrent_bidi_streams.try_into().unwrap());
        transport_config
            .max_concurrent_uni_streams(self.max_concurrent_uni_streams.try_into().unwrap());

        // Set idle timeout to 30 seconds
        transport_config.max_idle_timeout(Some(
            std::time::Duration::from_secs(30)
                .try_into()
                .map_err(|e| Error::QuicEndpoint(format!("Invalid idle timeout: {}", e)))?,
        ));

        server_config.transport_config(Arc::new(transport_config));

        Ok(server_config)
    }

    /// Create a QUIC endpoint
    pub fn create_endpoint(&self) -> Result<Endpoint> {
        let server_config = self.build_server_config()?;

        let endpoint = Endpoint::server(server_config, self.bind_addr)
            .map_err(|e| Error::QuicEndpoint(format!("Failed to create endpoint: {}", e)))?;

        info!("QUIC endpoint created on {}", self.bind_addr);
        debug!(
            "Max concurrent streams: bidi={}, uni={}",
            self.max_concurrent_bidi_streams, self.max_concurrent_uni_streams
        );

        Ok(endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn create_test_tls_config() -> Arc<rustls::ServerConfig> {
        // Install ring crypto provider for tests
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Create a minimal TLS config for testing
        let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = certified_key.cert.der().clone();
        let key_der = certified_key.signing_key.serialize_der();

        let cert_chain = vec![cert_der];
        let key = rustls::pki_types::PrivateKeyDer::try_from(key_der).unwrap();

        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();

        // HTTP/3 requires ALPN
        config.alpn_protocols = vec![b"h3".to_vec()];

        Arc::new(config)
    }

    #[test]
    fn test_quic_config_creation() {
        let addr = "127.0.0.1:8443".parse().unwrap();
        let tls_config = create_test_tls_config();
        let quic_config = QuicConfig::new(addr, tls_config);

        assert_eq!(quic_config.bind_addr, addr);
        assert_eq!(quic_config.max_concurrent_bidi_streams, 100);
        assert_eq!(quic_config.max_concurrent_uni_streams, 100);
    }

    #[test]
    fn test_server_config_build() {
        let addr = "127.0.0.1:8443".parse().unwrap();
        let tls_config = create_test_tls_config();
        let quic_config = QuicConfig::new(addr, tls_config);

        let server_config = quic_config.build_server_config();
        assert!(server_config.is_ok(), "Failed to build server config");
    }
}

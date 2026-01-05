//! TLS utilities and helpers

use crate::{mitm::CertificateData, Error, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsAcceptor, TlsStream};
use tracing::debug;

/// Create a TLS server configuration from certificate data
pub fn create_server_config(cert_data: &CertificateData) -> Result<Arc<ServerConfig>> {
    debug!("Creating TLS server config");

    // Create certificate chain with just the server cert
    let cert_chain = vec![cert_data.cert.clone()];

    // Create server config
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, cert_data.key.clone_key())
        .map_err(|e| Error::Tls(format!("Failed to create TLS server config: {}", e)))?;

    Ok(Arc::new(config))
}

/// Accept a TLS connection
pub async fn accept_tls<IO>(acceptor: &TlsAcceptor, stream: IO) -> Result<TlsStream<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    debug!("Accepting TLS connection");

    acceptor
        .accept(stream)
        .await
        .map_err(|e| Error::Tls(format!("TLS handshake failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertificateAuthority;
    use std::env;

    #[test]
    fn test_server_config_creation() {
        let temp_dir = env::temp_dir();
        let cert_path = temp_dir.join("test-tls-ca.crt");
        let key_path = temp_dir.join("test-tls-ca.key");

        // Clean up any existing files
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);

        // Create CA
        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path)
            .expect("Failed to create CA");

        // Generate a certificate
        let (cert, key) = ca.generate_cert("test.com").expect("Failed to generate cert");

        let cert_data = CertificateData { cert, key };

        // Create server config
        let config = create_server_config(&cert_data);
        assert!(config.is_ok());

        // Clean up
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    }
}

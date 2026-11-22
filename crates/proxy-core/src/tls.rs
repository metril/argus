//! TLS utilities and helpers

use crate::{Error, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ProducesTickets;
use rustls::ServerConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// A session-ticket key rotator shared by every host config (enables TLS session resumption).
pub fn new_ticketer() -> Result<Arc<dyn ProducesTickets>> {
    rustls::crypto::ring::Ticketer::new()
        .map_err(|e| Error::Tls(format!("Failed to create session ticketer: {e}")))
}

/// Build the ready-to-use server config for one leaf certificate: ALPN, session cache and
/// (when a shared `ticketer` is given) stateless session tickets for resumption.
pub fn build_server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    enable_http2: bool,
    ticketer: Option<Arc<dyn ProducesTickets>>,
) -> Result<Arc<ServerConfig>> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Tls(format!("Failed to select TLS versions: {e}")))?
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| Error::Tls(format!("Failed to create TLS server config: {e}")))?;

    config.alpn_protocols = if enable_http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(1024);
    if let Some(t) = ticketer {
        config.ticketer = t;
    }
    Ok(Arc::new(config))
}

/// Accept a TLS connection, bounded by `timeout`.
pub async fn accept_tls<IO>(
    acceptor: &TlsAcceptor,
    stream: IO,
    timeout: Duration,
) -> Result<TlsStream<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::time::timeout(timeout, acceptor.accept(stream)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(Error::Tls(format!("TLS handshake failed: {}", e))),
        Err(_) => Err(Error::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertificateAuthority;

    #[test]
    fn test_server_config_creation() {
        let tmp = tempfile::tempdir().unwrap();
        let ca = CertificateAuthority::load_or_generate(
            tmp.path().join("ca.crt"),
            tmp.path().join("ca.key"),
        )
        .expect("Failed to create CA");
        let (cert, key) = ca
            .generate_cert("test.com")
            .expect("Failed to generate cert");

        let config = build_server_config(cert, key, true, Some(new_ticketer().unwrap())).unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }
}

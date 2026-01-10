//! Integration tests for HTTP/3 server

use proxy_http3::{Http3Server, QuicConfig};
use std::sync::Arc;
use tokio::sync::broadcast;

fn create_test_tls_config() -> Arc<rustls::ServerConfig> {
    // Install ring crypto provider for tests
    let _ = rustls::crypto::ring::default_provider().install_default();

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

#[tokio::test]
async fn test_http3_server_starts() {
    let tls_config = create_test_tls_config();
    let quic_config = QuicConfig::new("127.0.0.1:0".parse().unwrap(), tls_config);
    let endpoint = quic_config.create_endpoint().unwrap();

    let server = Http3Server::new(endpoint);
    let addr = server.local_addr().unwrap();

    // Verify server is bound
    assert!(addr.port() > 0);
}

#[tokio::test]
async fn test_http3_server_shutdown() {
    let tls_config = create_test_tls_config();
    let quic_config = QuicConfig::new("127.0.0.1:0".parse().unwrap(), tls_config);
    let endpoint = quic_config.create_endpoint().unwrap();

    let server = Http3Server::new(endpoint);
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    // Start server in background
    let handle = tokio::spawn(async move {
        server.start(shutdown_rx).await
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Send shutdown signal
    shutdown_tx.send(()).unwrap();

    // Wait for server to shut down
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        handle
    ).await;

    assert!(result.is_ok(), "Server should shut down gracefully");
}

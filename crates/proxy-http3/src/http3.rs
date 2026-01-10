//! HTTP/3 server implementation

use crate::{Error, Result};
use bytes::Bytes;
use h3::server::Connection;
use quinn::Endpoint;
use tokio::sync::broadcast;
use tracing::{debug, error, info};

/// HTTP/3 server that handles QUIC connections
pub struct Http3Server {
    endpoint: Endpoint,
}

impl Http3Server {
    /// Create a new HTTP/3 server
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// Start the HTTP/3 server with graceful shutdown
    pub async fn start(
        self,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        info!("HTTP/3 server started on {}", self.endpoint.local_addr()?);

        loop {
            tokio::select! {
                // Accept new QUIC connection
                Some(incoming) = self.endpoint.accept() => {
                    debug!("Incoming QUIC connection");

                    // Clone shutdown receiver for this connection
                    let conn_shutdown = shutdown_rx.resubscribe();

                    // Spawn task to handle this connection
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(incoming, conn_shutdown).await {
                            error!("Connection error: {}", e);
                        }
                    });
                }

                // Shutdown signal received
                _ = shutdown_rx.recv() => {
                    info!("HTTP/3 server shutting down...");
                    break;
                }
            }
        }

        // Close endpoint gracefully
        self.endpoint.wait_idle().await;
        info!("HTTP/3 server stopped");

        Ok(())
    }

    /// Get the local address of the server
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }
}

/// Handle a single QUIC connection
async fn handle_connection(
    incoming: quinn::Incoming,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    // Accept the QUIC connection
    let connection = incoming.await.map_err(Error::QuicConnection)?;

    debug!(
        "QUIC connection established from {}",
        connection.remote_address()
    );

    // Create HTTP/3 connection
    let mut h3_conn = Connection::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|e| Error::Http3Protocol(format!("Failed to create HTTP/3 connection: {}", e)))?;

    loop {
        tokio::select! {
            // Accept new HTTP/3 request stream
            result = h3_conn.accept() => {
                match result {
                    Ok(Some(resolver)) => {
                        // Spawn task to resolve and handle this request
                        tokio::spawn(async move {
                            match resolver.resolve_request().await {
                                Ok((req, stream)) => {
                                    debug!("HTTP/3 request: {} {}", req.method(), req.uri());
                                    if let Err(e) = handle_request(req, stream).await {
                                        error!("Request handling error: {}", e);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to resolve request: {}", e);
                                }
                            }
                        });
                    }
                    Ok(None) => {
                        debug!("Connection closed by client");
                        break;
                    }
                    Err(e) => {
                        error!("Error accepting request: {}", e);
                        break;
                    }
                }
            }

            // Shutdown signal
            _ = shutdown_rx.recv() => {
                debug!("Connection terminated due to shutdown");
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single HTTP/3 request
async fn handle_request(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<()> {
    debug!("Handling request: {} {}", req.method(), req.uri());

    // For now, just return a simple response
    // In the future, this will integrate with the proxy pipeline
    let response = http::Response::builder()
        .status(200)
        .header("content-type", "text/plain")
        .body(())
        .map_err(|e| Error::Http3Protocol(format!("Failed to build response: {}", e)))?;

    stream
        .send_response(response)
        .await
        .map_err(|e| Error::Http3Protocol(format!("Failed to send response: {}", e)))?;

    let body = Bytes::from("HTTP/3 Proxy - Coming Soon\n");
    stream
        .send_data(body)
        .await
        .map_err(|e| Error::Http3Protocol(format!("Failed to send data: {}", e)))?;

    stream
        .finish()
        .await
        .map_err(|e| Error::Http3Protocol(format!("Failed to finish stream: {}", e)))?;

    debug!("Request completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_http3_server_creation() {
        use std::sync::Arc;

        // Install ring crypto provider for tests
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Create a test TLS config
        let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = certified_key.cert.der().clone();
        let key_der = certified_key.signing_key.serialize_der();

        let cert_chain = vec![cert_der];
        let key = rustls::pki_types::PrivateKeyDer::try_from(key_der).unwrap();

        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();

        tls_config.alpn_protocols = vec![b"h3".to_vec()];

        // Create QUIC config
        let quic_config = crate::quic::QuicConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(tls_config),
        );

        let endpoint = quic_config.create_endpoint().unwrap();
        let server = Http3Server::new(endpoint);

        // Verify server was created
        assert!(server.local_addr().is_ok());
    }
}

//! HTTP/3 server implementation

use crate::filter::Http3Filter;
use crate::{Error, Result};
use bytes::{Buf, Bytes};
use h3::server::Connection;
use quinn::Endpoint;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info};

/// HTTP/3 server that handles QUIC connections, applying ad-block filtering and forwarding
/// requests upstream (over the shared pooled client) — the same engine the HTTP/1.1/2 paths use.
pub struct Http3Server {
    endpoint: Endpoint,
    filter: Arc<Http3Filter>,
}

impl Http3Server {
    /// Create a new HTTP/3 server with the shared filtering context.
    pub fn new(endpoint: Endpoint, filter: Arc<Http3Filter>) -> Self {
        Self { endpoint, filter }
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
                    let filter = self.filter.clone();

                    // Spawn task to handle this connection
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(incoming, conn_shutdown, filter).await {
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
    filter: Arc<Http3Filter>,
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
                        let filter = filter.clone();
                        tokio::spawn(async move {
                            match resolver.resolve_request().await {
                                Ok((req, stream)) => {
                                    debug!("HTTP/3 request: {} {}", req.method(), req.uri());
                                    if let Err(e) = handle_request(req, stream, &filter).await {
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

/// Handle a single HTTP/3 request: filter, then forward upstream and relay the response.
async fn handle_request(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    filter: &Http3Filter,
) -> Result<()> {
    let method = req.method().clone();
    let url = req.uri().to_string();

    // Read the (buffered) request body.
    let mut body = Vec::new();
    while let Some(mut buf) = stream
        .recv_data()
        .await
        .map_err(|e| Error::Http3Protocol(format!("recv body: {e}")))?
    {
        while buf.remaining() > 0 {
            let chunk = buf.chunk();
            body.extend_from_slice(chunk);
            let n = chunk.len();
            buf.advance(n);
        }
    }

    // Filter decision (network-level). Blocked requests get a 204 and never reach the origin.
    if filter.is_blocked(&method, &url, req.headers()) {
        debug!("HTTP/3 blocked {}", url);
        let response = http::Response::builder()
            .status(204)
            .header("x-adblock", "blocked")
            .body(())
            .map_err(|e| Error::Http3Protocol(format!("build response: {e}")))?;
        stream
            .send_response(response)
            .await
            .map_err(|e| Error::Http3Protocol(format!("send response: {e}")))?;
        stream
            .finish()
            .await
            .map_err(|e| Error::Http3Protocol(format!("finish: {e}")))?;
        return Ok(());
    }

    // Forward upstream and relay the response back over HTTP/3.
    match filter.forward(method, &url, req.headers(), body).await {
        Ok((status, headers, payload)) => {
            let mut builder = http::Response::builder().status(status);
            for (name, value) in headers.iter() {
                builder = builder.header(name, value);
            }
            let response = builder
                .body(())
                .map_err(|e| Error::Http3Protocol(format!("build response: {e}")))?;
            stream
                .send_response(response)
                .await
                .map_err(|e| Error::Http3Protocol(format!("send response: {e}")))?;
            if !payload.is_empty() {
                stream
                    .send_data(payload)
                    .await
                    .map_err(|e| Error::Http3Protocol(format!("send data: {e}")))?;
            }
        }
        Err(e) => {
            error!("HTTP/3 upstream error for {}: {}", url, e);
            let response = http::Response::builder()
                .status(502)
                .body(())
                .map_err(|e| Error::Http3Protocol(format!("build response: {e}")))?;
            stream
                .send_response(response)
                .await
                .map_err(|e| Error::Http3Protocol(format!("send response: {e}")))?;
        }
    }

    stream
        .finish()
        .await
        .map_err(|e| Error::Http3Protocol(format!("finish: {e}")))?;
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
        let filter = Arc::new(Http3Filter::new(
            Arc::new(filter_engine::SharedEngine::new()),
            reqwest::Client::new(),
            false,
        ));
        let server = Http3Server::new(endpoint, filter);

        // Verify server was created
        assert!(server.local_addr().is_ok());
    }
}

//! Connection handling and management

use crate::filtering::ProxyContext;
use crate::inject::{full_body, ProxyBody};
use crate::{mitm::MitmHandler, tls, Error, Result};
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

pub struct ConnectionHandler {
    client_addr: SocketAddr,
    mitm_handler: Option<Arc<MitmHandler>>,
    enable_http2: bool,
    #[allow(dead_code)] // Reserved for future WebSocket support
    enable_websockets: bool,
    /// Shared filtering + upstream-forwarding context (engine handle + pooled HTTP client).
    ctx: Arc<ProxyContext>,
}

impl ConnectionHandler {
    pub fn new(
        client_addr: SocketAddr,
        mitm_handler: Option<Arc<MitmHandler>>,
        enable_http2: bool,
        enable_websockets: bool,
        ctx: Arc<ProxyContext>,
    ) -> Self {
        Self {
            client_addr,
            mitm_handler,
            enable_http2,
            enable_websockets,
            ctx,
        }
    }

    /// Handle an incoming connection
    pub async fn handle(&self, stream: TcpStream) -> Result<()> {
        debug!("Handling connection from {}", self.client_addr);

        // Peek at the first line to check if it's a CONNECT request
        let mut peek_buffer = vec![0u8; 8];
        match stream.peek(&mut peek_buffer).await {
            Ok(n) if n >= 7 => {
                let peek_str = String::from_utf8_lossy(&peek_buffer[..n]);
                if peek_str.starts_with("CONNECT") {
                    // Handle CONNECT request separately
                    return self.handle_connect_request(stream).await;
                }
            }
            Ok(_) => {
                // Not enough data or not CONNECT
            }
            Err(e) => {
                error!("Error peeking at connection: {}", e);
                return Err(Error::Connection(format!("Peek error: {}", e)));
            }
        }

        // Regular HTTP request - use hyper
        let io = TokioIo::new(stream);
        let service = service_fn(move |req| self.handle_request(req));

        // Serve HTTP/1.1 over the connection
        if let Err(err) = http1::Builder::new()
            .serve_connection(io, service)
            .await
        {
            error!("Error serving connection: {}", err);
            return Err(Error::Connection(format!("Connection error: {}", err)));
        }

        Ok(())
    }

    /// Handle a single HTTP request
    async fn handle_request(&self, mut req: Request<Incoming>) -> Result<Response<ProxyBody>> {
        let method = req.method();
        let uri = req.uri().clone();
        let version = req.version();

        info!(
            "Request from {}: {} {} {:?}",
            self.client_addr, method, uri, version
        );

        // Check for WebSocket upgrade
        #[cfg(feature = "websockets")]
        if self.enable_websockets {
            use proxy_http3::{is_websocket_upgrade, extract_ws_target};

            if is_websocket_upgrade(req.headers()) {
                info!("WebSocket upgrade request detected from {}", self.client_addr);

                // Extract target WebSocket URL
                let target_url = match extract_ws_target(&uri, req.headers()) {
                    Ok(url) => url,
                    Err(e) => {
                        error!("Failed to extract WebSocket target: {}", e);
                        return Ok(Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(full_body(Bytes::from_static(b"Invalid WebSocket target")))
                            .unwrap());
                    }
                };

                // Spawn WebSocket proxy task with hyper upgrade
                tokio::spawn(async move {
                    match hyper::upgrade::on(&mut req).await {
                        Ok(upgraded) => {
                            let upgraded_io = hyper_util::rt::TokioIo::new(upgraded);
                            if let Err(e) = proxy_http3::proxy_websocket(upgraded_io, &target_url).await {
                                error!("WebSocket proxy error: {}", e);
                            }
                        }
                        Err(e) => error!("Upgrade error: {}", e),
                    }
                });

                // Return switching protocols response
                return Ok(Response::builder()
                    .status(StatusCode::SWITCHING_PROTOCOLS)
                    .header(hyper::header::UPGRADE, "websocket")
                    .header(hyper::header::CONNECTION, "Upgrade")
                    .body(full_body(Bytes::new()))
                    .unwrap());
            }
        }

        // Handle different request methods
        match *method {
            Method::CONNECT => {
                // CONNECT requests need special handling and cannot be processed here
                // They should be handled via handle_connect_request
                error!("CONNECT method reached handle_request - should use upgrade path");
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(full_body(Bytes::from_static(b"CONNECT must use upgrade path")))
                    .unwrap())
            }
            Method::GET | Method::POST | Method::PUT | Method::DELETE | Method::HEAD
            | Method::OPTIONS | Method::PATCH => {
                // Standard (plaintext) HTTP proxy: absolute-form URI carries scheme + host.
                self.ctx.forward(req, "http", None).await
            }
            _ => {
                warn!("Unsupported method: {}", method);
                Ok(Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(full_body(Bytes::from_static(b"Method not allowed")))
                    .unwrap())
            }
        }
    }

    /// Handle CONNECT request for HTTPS tunneling with MITM
    async fn handle_connect_request(&self, mut stream: TcpStream) -> Result<()> {
        debug!("Handling CONNECT request from {}", self.client_addr);

        // Read the HTTP request manually
        let mut buffer = vec![0u8; 8192];
        let n = stream.read(&mut buffer).await.map_err(|e| {
            Error::Connection(format!("Failed to read CONNECT request: {}", e))
        })?;

        let request_data = String::from_utf8_lossy(&buffer[..n]);
        let lines: Vec<&str> = request_data.lines().collect();

        if lines.is_empty() {
            return Err(Error::Connection("Empty CONNECT request".to_string()));
        }

        // Parse CONNECT line: "CONNECT host:port HTTP/1.1"
        let parts: Vec<&str> = lines[0].split_whitespace().collect();
        if parts.len() < 2 || parts[0] != "CONNECT" {
            return Err(Error::Connection("Invalid CONNECT request".to_string()));
        }

        let target = parts[1];
        let (domain, port) = match target.split_once(':') {
            Some((d, p)) => (d.to_string(), p.parse::<u16>().unwrap_or(443)),
            None => (target.to_string(), 443),
        };

        info!(
            "CONNECT request from {} to {}:{}",
            self.client_addr, domain, port
        );

        // Check if MITM is enabled
        match &self.mitm_handler {
            Some(mitm) => {
                // Get or generate certificate for the domain
                let cert_data = mitm.handle_connect(&domain, port).await?;

                // Send connection established response
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .map_err(|e| Error::Connection(format!("Failed to send 200 response: {}", e)))?;

                // Create TLS server config with ALPN
                let server_config = tls::create_server_config_with_alpn(&cert_data, self.enable_http2)?;
                let acceptor = TlsAcceptor::from(server_config);

                // Perform TLS handshake with client
                let tls_stream = match tls::accept_tls(&acceptor, stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("TLS handshake failed for {}: {}", domain, e);
                        return Err(e);
                    }
                };

                info!("TLS handshake complete for {}", domain);

                // Now we have a TLS connection with the client
                // We need to handle HTTP requests over this TLS connection
                self.handle_mitm_connection(tls_stream, &domain, port).await
            }
            None => {
                // No MITM - just tunnel the connection
                info!("MITM disabled, tunneling connection to {}:{}", domain, port);
                self.tunnel_connection(stream, &domain, port).await
            }
        }
    }

    /// Handle HTTP requests over MITM TLS connection
    async fn handle_mitm_connection<IO>(
        &self,
        tls_stream: tokio_rustls::server::TlsStream<IO>,
        domain: &str,
        port: u16,
    ) -> Result<()>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Check negotiated protocol via ALPN
        let (_, session) = tls_stream.get_ref();
        let negotiated_protocol = session.alpn_protocol();

        let use_http2 = if let Some(protocol) = negotiated_protocol {
            let is_h2 = crate::http2::is_http2_protocol(protocol);
            debug!(
                "ALPN negotiated protocol for {}:{}: {:?} (HTTP/2: {})",
                domain,
                port,
                String::from_utf8_lossy(protocol),
                is_h2
            );
            is_h2
        } else {
            debug!("No ALPN protocol negotiated for {}:{}, using HTTP/1.1", domain, port);
            false
        };

        // MITM traffic is decrypted HTTPS: the upstream scheme is https and the authority comes
        // from the CONNECT target (origin-form request URIs have no host of their own).
        let authority = (domain.to_string(), port);

        if use_http2 {
            info!("Using HTTP/2 for {}:{}", domain, port);
            let ctx = self.ctx.clone();
            let service = move |req| {
                let ctx = ctx.clone();
                let authority = authority.clone();
                async move { ctx.forward(req, "https", Some(authority)).await }
            };
            crate::http2::serve_http2(tls_stream, service).await
        } else {
            info!("Using HTTP/1.1 for {}:{}", domain, port);
            let io = TokioIo::new(tls_stream);
            let ctx = self.ctx.clone();
            let service = service_fn(move |req| {
                let ctx = ctx.clone();
                let authority = authority.clone();
                async move { ctx.forward(req, "https", Some(authority)).await }
            });

            // Serve HTTP/1.1 over the TLS connection
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                error!("Error serving MITM connection: {}", err);
                return Err(Error::Connection(format!("MITM connection error: {}", err)));
            }

            Ok(())
        }
    }

    /// Tunnel connection without MITM (direct passthrough)
    async fn tunnel_connection(
        &self,
        mut client_stream: TcpStream,
        domain: &str,
        port: u16,
    ) -> Result<()> {
        debug!("Tunneling connection to {}:{}", domain, port);

        // Connect to target server
        let target_addr = format!("{}:{}", domain, port);
        let mut server_stream = TcpStream::connect(&target_addr).await.map_err(|e| {
            Error::Connection(format!("Failed to connect to {}: {}", target_addr, e))
        })?;

        // Send connection established response
        client_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|e| Error::Connection(format!("Failed to send 200 response: {}", e)))?;

        // Bidirectional copy
        match tokio::io::copy_bidirectional(&mut client_stream, &mut server_stream).await {
            Ok((from_client, from_server)) => {
                debug!(
                    "Tunnel closed for {}:{} - sent: {} bytes, received: {} bytes",
                    domain, port, from_client, from_server
                );
                Ok(())
            }
            Err(e) => {
                error!("Tunnel error for {}:{}: {}", domain, port, e);
                Err(Error::Connection(format!("Tunnel error: {}", e)))
            }
        }
    }

}

//! Connection handling and management

use crate::{mitm::MitmHandler, Error, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

pub struct ConnectionHandler {
    client_addr: SocketAddr,
    mitm_handler: Option<Arc<MitmHandler>>,
}

impl ConnectionHandler {
    pub fn new(client_addr: SocketAddr, mitm_handler: Option<Arc<MitmHandler>>) -> Self {
        Self {
            client_addr,
            mitm_handler,
        }
    }

    /// Handle an incoming connection
    pub async fn handle(&self, stream: TcpStream) -> Result<()> {
        debug!("Handling connection from {}", self.client_addr);

        let io = TokioIo::new(stream);

        // Create a service to handle each request on this connection
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
    async fn handle_request(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        let method = req.method();
        let uri = req.uri();
        let version = req.version();

        info!(
            "Request from {}: {} {} {:?}",
            self.client_addr, method, uri, version
        );

        // Handle different request methods
        match *method {
            Method::CONNECT => {
                // HTTPS proxy - will be implemented with MITM support
                warn!("CONNECT method not yet implemented");
                Ok(Response::builder()
                    .status(StatusCode::NOT_IMPLEMENTED)
                    .body(Full::new(Bytes::from("CONNECT not yet implemented")))
                    .unwrap())
            }
            Method::GET | Method::POST | Method::PUT | Method::DELETE | Method::HEAD
            | Method::OPTIONS | Method::PATCH => {
                // Standard HTTP proxy
                self.proxy_request(req).await
            }
            _ => {
                warn!("Unsupported method: {}", method);
                Ok(Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Full::new(Bytes::from("Method not allowed")))
                    .unwrap())
            }
        }
    }

    /// Proxy a standard HTTP request
    async fn proxy_request(&self, mut req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        let uri = req.uri();

        // Extract host and port from the request
        let host = match uri.host() {
            Some(h) => h,
            None => {
                // Try to get host from headers
                match req.headers().get("host") {
                    Some(h) => match h.to_str() {
                        Ok(s) => s,
                        Err(_) => {
                            return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Full::new(Bytes::from("Invalid host header")))
                                .unwrap())
                        }
                    },
                    None => {
                        return Ok(Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Full::new(Bytes::from("Missing host")))
                            .unwrap())
                    }
                }
            }
        };

        let port = uri.port_u16().unwrap_or(80);

        debug!("Proxying request to {}:{}", host, port);

        // Create a client to forward the request
        let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

        // Forward the request
        match client.request(req).await {
            Ok(response) => {
                let status = response.status();
                debug!("Response status: {}", status);

                // Collect the response body
                let body = match response.collect().await {
                    Ok(collected) => collected.to_bytes(),
                    Err(e) => {
                        error!("Error collecting response body: {}", e);
                        return Ok(Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Full::new(Bytes::from("Error reading response")))
                            .unwrap());
                    }
                };

                Ok(Response::builder()
                    .status(status)
                    .body(Full::new(body))
                    .unwrap())
            }
            Err(e) => {
                error!("Error forwarding request: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(format!(
                        "Error forwarding request: {}",
                        e
                    ))))
                    .unwrap())
            }
        }
    }
}

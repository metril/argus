//! WebSocket proxying implementation
//!
//! This module provides WebSocket upgrade detection and bidirectional frame proxying.

use crate::{Error, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    accept_async, client_async, tungstenite::protocol::Message, WebSocketStream,
};
use tracing::{debug, error, info, warn};

/// Check if a request is a WebSocket upgrade request
pub fn is_websocket_upgrade(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
        && headers
            .get(hyper::header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase().contains("upgrade"))
            .unwrap_or(false)
}

/// Extract the target WebSocket URL from the request
pub fn extract_ws_target(uri: &hyper::Uri, headers: &hyper::HeaderMap) -> Result<String> {
    let host = uri
        .host()
        .or_else(|| {
            headers
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
        })
        .ok_or_else(|| Error::Http3Protocol("Missing host in WebSocket request".to_string()))?;

    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    // Determine scheme based on port or assume wss
    let scheme = if uri.port_u16().unwrap_or(443) == 80 {
        "ws"
    } else {
        "wss"
    };

    Ok(format!("{}://{}{}", scheme, host, path))
}

/// Proxy WebSocket connection between client and server
pub async fn proxy_websocket<S>(
    client_stream: S,
    target_url: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    info!("Establishing WebSocket proxy to {}", target_url);

    // Parse target URL to extract host and port
    let url = target_url.parse::<hyper::Uri>()
        .map_err(|e| Error::Http3Protocol(format!("Invalid WebSocket URL: {}", e)))?;

    let host = url.host()
        .ok_or_else(|| Error::Http3Protocol("Missing host in WebSocket URL".to_string()))?;

    let port = url.port_u16().unwrap_or_else(|| {
        if url.scheme_str() == Some("wss") { 443 } else { 80 }
    });

    // Connect to target server
    let target_addr = format!("{}:{}", host, port);
    let target_stream = TcpStream::connect(&target_addr)
        .await
        .map_err(|e| Error::Io(e))?;

    debug!("Connected to target WebSocket server at {}", target_addr);

    // Accept WebSocket connection from client
    let client_ws = accept_async(client_stream)
        .await
        .map_err(|e| Error::Http3Protocol(format!("Failed to accept WebSocket: {}", e)))?;

    debug!("Client WebSocket handshake complete");

    // Connect to target WebSocket server
    let (server_ws, _) = client_async(target_url, target_stream)
        .await
        .map_err(|e| Error::Http3Protocol(format!("Failed to connect to target WebSocket: {}", e)))?;

    debug!("Server WebSocket connection established");

    // Proxy messages bidirectionally
    proxy_messages(client_ws, server_ws).await
}

/// Bidirectionally proxy WebSocket messages
async fn proxy_messages<S1, S2>(
    client_ws: WebSocketStream<S1>,
    server_ws: WebSocketStream<S2>,
) -> Result<()>
where
    S1: AsyncRead + AsyncWrite + Unpin,
    S2: AsyncRead + AsyncWrite + Unpin,
{
    use futures_util::{SinkExt, StreamExt};

    let (mut client_sink, mut client_stream) = client_ws.split();
    let (mut server_sink, mut server_stream) = server_ws.split();

    let client_to_server = async {
        while let Some(msg) = client_stream.next().await {
            match msg {
                Ok(msg) => {
                    debug!("Client -> Server: {:?}", msg);
                    if let Err(e) = server_sink.send(msg).await {
                        error!("Error sending to server: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    warn!("Error receiving from client: {}", e);
                    break;
                }
            }
        }
    };

    let server_to_client = async {
        while let Some(msg) = server_stream.next().await {
            match msg {
                Ok(msg) => {
                    debug!("Server -> Client: {:?}", msg);
                    if let Err(e) = client_sink.send(msg).await {
                        error!("Error sending to client: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    warn!("Error receiving from server: {}", e);
                    break;
                }
            }
        }
    };

    // Run both directions concurrently
    tokio::select! {
        _ = client_to_server => {
            debug!("Client to server stream closed");
        }
        _ = server_to_client => {
            debug!("Server to client stream closed");
        }
    }

    info!("WebSocket proxy connection closed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;

    #[test]
    fn test_is_websocket_upgrade() {
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(hyper::header::CONNECTION, "Upgrade".parse().unwrap());

        assert!(is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_is_not_websocket_upgrade() {
        let headers = HeaderMap::new();
        assert!(!is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_extract_ws_target() {
        let uri = "https://example.com:443/ws".parse::<hyper::Uri>().unwrap();
        let headers = HeaderMap::new();

        let target = extract_ws_target(&uri, &headers).unwrap();
        assert_eq!(target, "wss://example.com:443/ws");
    }

    #[test]
    fn test_extract_ws_target_with_host_header() {
        let uri = "/ws".parse::<hyper::Uri>().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::HOST, "example.com".parse().unwrap());

        let target = extract_ws_target(&uri, &headers).unwrap();
        assert_eq!(target, "wss://example.com/ws");
    }
}

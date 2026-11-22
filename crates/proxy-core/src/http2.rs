//! HTTP/2 support and handling

use crate::{Error, Result};
use bytes::Bytes;
use hyper::body::{Body, Incoming};
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

/// Concurrent streams per client connection (browsers rarely exceed ~100).
pub const MAX_CONCURRENT_STREAMS: u32 = 128;
/// Per-stream flow-control window: 1 MiB (default 64 KiB throttles downloads on high-latency links).
pub const INITIAL_STREAM_WINDOW: u32 = 1024 * 1024;
/// Whole-connection flow-control window: 4 MiB.
pub const INITIAL_CONNECTION_WINDOW: u32 = 4 * 1024 * 1024;
/// PING cadence that detects dead peers and keeps NAT mappings alive.
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// How long to wait for a PING ack before closing.
pub const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);

/// Serve HTTP/2 over a connection
pub async fn serve_http2<IO, S, F, B>(io: IO, service: S) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Fn(Request<Incoming>) -> F + Clone + Send + 'static,
    F: std::future::Future<Output = Result<Response<B>>> + Send + 'static,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    debug!("Starting HTTP/2 connection");

    let io = TokioIo::new(io);
    let service = service_fn(service);

    http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .initial_stream_window_size(INITIAL_STREAM_WINDOW)
        .initial_connection_window_size(INITIAL_CONNECTION_WINDOW)
        .keep_alive_interval(KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(KEEP_ALIVE_TIMEOUT)
        .serve_connection(io, service)
        .await
        .map_err(|err| {
            debug!("HTTP/2 connection error: {}", err);
            Error::Connection(format!("HTTP/2 error: {}", err))
        })?;

    debug!("HTTP/2 connection closed");
    Ok(())
}

/// Check if a protocol is HTTP/2
pub fn is_http2_protocol(protocol: &[u8]) -> bool {
    protocol == b"h2"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_protocol_detection() {
        assert!(is_http2_protocol(b"h2"));
        assert!(!is_http2_protocol(b"http/1.1"));
        assert!(!is_http2_protocol(b"h3"));
    }
}

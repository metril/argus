//! HTTP/2 support and handling

use crate::{Error, Result};
use bytes::Bytes;
use hyper::body::{Body, Incoming};
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, error};

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

    if let Err(err) = http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, service)
        .await
    {
        error!("HTTP/2 connection error: {}", err);
        return Err(Error::Connection(format!("HTTP/2 error: {}", err)));
    }

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

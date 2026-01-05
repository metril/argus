//! Error types for HTTP/3 module

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("QUIC connection error: {0}")]
    QuicConnection(#[from] quinn::ConnectionError),

    #[error("QUIC endpoint error: {0}")]
    QuicEndpoint(String),

    #[error("HTTP/3 protocol error: {0}")]
    Http3Protocol(String),

    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Certificate error: {0}")]
    Certificate(String),
}

pub type Result<T> = std::result::Result<T, Error>;

//! Common error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

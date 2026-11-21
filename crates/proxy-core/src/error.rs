//! Error types for the proxy core

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Certificate generation error: {0}")]
    Certificate(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Connection error: {0}")]
    Connection(String),


    #[error("Timeout error")]
    Timeout,

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<common::Error> for Error {
    fn from(err: common::Error) -> Self {
        Error::Internal(err.to_string())
    }
}

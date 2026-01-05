//! Error types for the filter engine

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Filter parsing error: {0}")]
    FilterParsing(String),

    #[error("Filter list download error: {0}")]
    ListDownload(String),

    #[error("Filter list URL error: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("HTTP request error: {0}")]
    HttpRequest(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Engine initialization error: {0}")]
    EngineInit(String),

    #[error("Filter list not found: {0}")]
    ListNotFound(String),

    #[error("Invalid filter syntax: {0}")]
    InvalidSyntax(String),
}

pub type Result<T> = std::result::Result<T, Error>;

//! Error types for the userscript engine

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Metadata parsing error: {0}")]
    MetadataParsing(String),

    #[error("Script execution error: {0}")]
    ScriptExecution(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Script not found: {0}")]
    ScriptNotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid script: {0}")]
    InvalidScript(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP request error: {0}")]
    HttpRequest(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Database error: {0}")]
    Db(#[from] common::db::DbError),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
}

pub type Result<T> = std::result::Result<T, Error>;

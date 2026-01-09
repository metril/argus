//! Error types for the web API
//!
//! Provides custom error types with HTTP status code mapping for proper error responses.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Main error type for the web API
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),

    #[error("Invalid input: {0}")]
    ValidationError(String),

    #[error("Validation errors")]
    ValidationErrors(#[from] validator::ValidationErrors),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Resource already exists: {0}")]
    AlreadyExists(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("CSRF validation failed")]
    CsrfValidationFailed,

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Proxy error: {0}")]
    Proxy(#[from] proxy_core::Error),

    #[error("Filter engine error: {0}")]
    FilterEngine(#[from] filter_engine::Error),

    #[error("Userscript error: {0}")]
    Userscript(#[from] userscript_engine::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Database error: {0}")]
    Database(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("bcrypt error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            ApiError::AuthenticationFailed(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            ApiError::AuthorizationFailed(_) => (StatusCode::FORBIDDEN, self.to_string()),
            ApiError::ValidationError(_) | ApiError::ValidationErrors(_) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            ApiError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            ApiError::AlreadyExists(_) => (StatusCode::CONFLICT, self.to_string()),
            ApiError::RateLimitExceeded(_) => {
                (StatusCode::TOO_MANY_REQUESTS, self.to_string())
            }
            ApiError::CsrfValidationFailed => (StatusCode::FORBIDDEN, self.to_string()),
            ApiError::Internal(_)
            | ApiError::Proxy(_)
            | ApiError::FilterEngine(_)
            | ApiError::Userscript(_)
            | ApiError::Io(_)
            | ApiError::Json(_)
            | ApiError::Database(_)
            | ApiError::Jwt(_)
            | ApiError::Bcrypt(_) => {
                // Log internal errors but return generic message
                tracing::error!("Internal error: {}", self);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16(),
        }));

        (status, body).into_response()
    }
}

/// Result type using ApiError
pub type ApiResult<T> = std::result::Result<T, ApiError>;

/// Helper to convert sled errors to ApiError
impl From<sled::Error> for ApiError {
    fn from(err: sled::Error) -> Self {
        ApiError::Database(err.to_string())
    }
}

/// Helper to convert anyhow errors to ApiError
impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        ApiError::Internal(err.to_string())
    }
}

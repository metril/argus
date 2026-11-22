//! Error types for the web API.
//!
//! Every failure is rendered as the single envelope
//! `{ "error": { "code": "...", "message": "...", "details": [...] } }` with a stable
//! machine-readable `code`.

use api_types::{ErrorBody, ErrorEnvelope, FieldError};
use axum::{
    extract::{FromRequest, FromRequestParts, Request},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::de::DeserializeOwned;
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

    /// Any other client-visible failure with an explicit status and stable code.
    #[error("{message}")]
    Coded {
        status: StatusCode,
        code: &'static str,
        message: String,
    },

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Configuration error: {0}")]
    Config(#[from] common::ConfigError),

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

impl ApiError {
    pub fn coded(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError::Coded {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::coded(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::coded(StatusCode::CONFLICT, code, message)
    }

    /// `If-Match` was required but absent.
    pub fn precondition_required() -> Self {
        Self::coded(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "This update requires an If-Match header carrying the ETag from the last GET",
        )
    }

    /// `If-Match` did not match the current version.
    pub fn precondition_failed() -> Self {
        Self::coded(
            StatusCode::PRECONDITION_FAILED,
            "precondition_failed",
            "The resource changed since it was read; fetch it again and retry",
        )
    }

    /// Status, stable code, message and field details for the envelope.
    fn parts(&self) -> (StatusCode, &'static str, String, Vec<FieldError>) {
        match self {
            ApiError::AuthenticationFailed(m) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", m.clone(), vec![])
            }
            ApiError::AuthorizationFailed(m) => {
                (StatusCode::FORBIDDEN, "forbidden", m.clone(), vec![])
            }
            ApiError::ValidationError(m) => (
                StatusCode::BAD_REQUEST,
                "validation_failed",
                m.clone(),
                vec![],
            ),
            ApiError::ValidationErrors(e) => (
                StatusCode::BAD_REQUEST,
                "validation_failed",
                "Request validation failed".to_string(),
                field_errors(e),
            ),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, "not_found", m.clone(), vec![]),
            ApiError::AlreadyExists(m) => (
                StatusCode::CONFLICT,
                "already_exists",
                format!("{m} already exists"),
                vec![],
            ),
            ApiError::RateLimitExceeded(m) => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                m.clone(),
                vec![],
            ),
            ApiError::CsrfValidationFailed => (
                StatusCode::FORBIDDEN,
                "csrf_failed",
                "CSRF validation failed: send the X-CSRF-Token header".to_string(),
                vec![],
            ),
            ApiError::Coded {
                status,
                code,
                message,
            } => (*status, code, message.clone(), vec![]),
            other => {
                // Log internal errors but return a generic message.
                tracing::error!("Internal error: {}", other);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Internal server error".to_string(),
                    vec![],
                )
            }
        }
    }
}

fn field_errors(errors: &validator::ValidationErrors) -> Vec<FieldError> {
    let mut out: Vec<FieldError> = errors
        .field_errors()
        .into_iter()
        .flat_map(|(field, errs)| {
            errs.iter().map(move |e| FieldError {
                field: field.to_string(),
                code: e.code.to_string(),
                message: e
                    .message
                    .as_ref()
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| format!("invalid value ({})", e.code)),
            })
        })
        .collect();
    out.sort_by(|a, b| a.field.cmp(&b.field));
    out
}

/// Build the envelope response for a status and code (used by middleware too).
pub fn envelope(status: StatusCode, code: &str, message: &str) -> Response {
    let body = ErrorEnvelope {
        error: ErrorBody {
            code: code.to_string(),
            message: message.to_string(),
            details: vec![],
        },
    };
    (status, Json(body)).into_response()
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message, details) = self.parts();
        let body = ErrorEnvelope {
            error: ErrorBody {
                code: code.to_string(),
                message,
                details,
            },
        };
        (status, Json(body)).into_response()
    }
}

/// Result type using ApiError
pub type ApiResult<T> = std::result::Result<T, ApiError>;

impl From<sled::Error> for ApiError {
    fn from(err: sled::Error) -> Self {
        ApiError::Database(err.to_string())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        ApiError::Internal(err.to_string())
    }
}

impl From<list_service::Error> for ApiError {
    fn from(err: list_service::Error) -> Self {
        ApiError::Internal(err.to_string())
    }
}

/// JSON body extractor whose rejections use the error envelope.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(ApiJson(v)),
            Err(rej) => Err(ApiError::coded(
                rej.status(),
                "invalid_body",
                rej.body_text(),
            )),
        }
    }
}

/// Query-string extractor whose rejections use the error envelope.
pub struct ApiQuery<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Query::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Query(v)) => Ok(ApiQuery(v)),
            Err(rej) => Err(ApiError::coded(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                rej.body_text(),
            )),
        }
    }
}

/// Path-parameter extractor whose rejections use the error envelope.
pub struct ApiPath<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiPath<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Path::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Path(v)) => Ok(ApiPath(v)),
            Err(rej) => Err(ApiError::coded(
                StatusCode::BAD_REQUEST,
                "invalid_path",
                rej.body_text(),
            )),
        }
    }
}

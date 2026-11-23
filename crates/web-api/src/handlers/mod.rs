//! Request handlers, one module per resource. Each handler carries a `#[utoipa::path]` whose
//! `security(...)` is the route's single authorization declaration (see `auth::authz`).

use serde::Deserialize;
use utoipa::IntoParams;

pub mod audit;
pub mod auth;
pub mod bypass;
pub mod certificate;
pub mod devices;
pub mod health;
pub mod lists;
pub mod paging;
pub mod policy;
pub mod profiles;
pub mod proxy;
pub mod rules;
pub mod stats;
pub mod tokens;
pub mod users;
pub mod userscripts;

/// Pagination parameters shared by every list endpoint.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PageQuery {
    /// 1-based page number (default 1).
    pub page: Option<u32>,
    /// Items per page, 1..=200 (default 50).
    pub limit: Option<u32>,
}

/// Weak-validator `ETag` for a serialisable value (content hash).
pub fn etag_of(bytes: &[u8]) -> String {
    format!("\"{}\"", &blake3::hash(bytes).to_hex()[..32])
}

/// Enforce `If-Match` against the current ETag: 428 when absent, 412 on mismatch.
pub fn check_if_match(
    headers: &axum::http::HeaderMap,
    current: &str,
) -> crate::error::ApiResult<()> {
    let given = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(crate::error::ApiError::precondition_required)?;
    let matches = given.trim() == "*"
        || given
            .split(',')
            .any(|t| t.trim().trim_start_matches("W/") == current);
    if matches {
        Ok(())
    } else {
        Err(crate::error::ApiError::precondition_failed())
    }
}

/// Parse a UUID path/body value, mapping failure to a 400 envelope.
pub fn parse_uuid(s: &str) -> crate::error::ApiResult<uuid::Uuid> {
    s.parse()
        .map_err(|_| crate::error::ApiError::bad_request("Invalid id: expected a UUID"))
}

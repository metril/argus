//! Rate limiting.
//!
//! This layer covers the unauthenticated surface: a global bucket, a per-IP bucket and a much
//! stricter per-IP bucket for credential endpoints. The per-principal bucket (per user session or
//! per API token) is applied by the authorizer once the caller is known.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use super::request_id::ClientInfo;
use crate::error::ApiError;
use crate::state::AppState;

fn is_credential_endpoint(path: &str) -> bool {
    matches!(
        path.rsplit_once("/auth/"),
        Some((_, "login" | "register" | "refresh" | "extension-token"))
    )
}

pub async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    if !state.rate_limiters.check_global() {
        return ApiError::RateLimitExceeded("Server is under heavy load, try again later".into())
            .into_response();
    }
    if let Some(ip) = req.extensions().get::<ClientInfo>().and_then(|c| c.ip) {
        let limited = !state.rate_limiters.check_ip(ip)
            || (req.method() == axum::http::Method::POST
                && is_credential_endpoint(req.uri().path())
                && !state.rate_limiters.check_auth(ip));
        if limited {
            tracing::warn!("Rate limit exceeded for {ip}");
            return ApiError::RateLimitExceeded("Too many requests, slow down".into())
                .into_response();
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::RateLimiters;

    #[test]
    fn credential_endpoints_are_stricter() {
        assert!(is_credential_endpoint("/api/v1/auth/login"));
        assert!(is_credential_endpoint("/api/v1/auth/extension-token"));
        assert!(!is_credential_endpoint("/api/v1/auth/me"));
        let l = RateLimiters::new(1000, 1000, 1000, 2);
        let ip = "127.0.0.1".parse().unwrap();
        assert!(l.check_auth(ip) && l.check_auth(ip));
        assert!(!l.check_auth(ip));
        assert!(l.check_ip(ip));
    }

    #[test]
    fn principal_buckets_are_independent() {
        let l = RateLimiters::new(1000, 1000, 1, 10);
        assert!(l.check_principal("token:a"));
        assert!(!l.check_principal("token:a"));
        assert!(l.check_principal("token:b"));
    }
}

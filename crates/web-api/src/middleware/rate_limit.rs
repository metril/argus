//! Rate limiting middleware
//!
//! Multi-tier rate limiting:
//! - Global: Protects overall server capacity
//! - Per-IP: Prevents individual IP abuse
//! - Per-user: Prevents authenticated user abuse

use crate::auth::middleware::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use governor::{
    clock::DefaultClock,
    state::{direct::NotKeyed, InMemoryState},
    Quota, RateLimiter,
};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

/// Rate limit middleware
///
/// Checks global and per-IP rate limits.
/// If user is authenticated, also checks per-user rate limit.
pub async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Check global rate limit
    {
        let limiter = state.rate_limiters.global.read();
        if limiter.check().is_err() {
            tracing::warn!("Global rate limit exceeded");
            return Err(ApiError::RateLimitExceeded(
                "Server is under heavy load, please try again later".to_string(),
            ));
        }
    }

    // Check per-IP rate limit (extract from headers)
    if let Some(ip) = extract_client_ip(&req) {
        check_ip_rate_limit(&state, ip)?;
    }

    // Check per-user rate limit if authenticated
    if let Some(auth_user) = req.extensions().get::<AuthUser>() {
        check_user_rate_limit(&state, auth_user.user_id())?;
    }

    Ok(next.run(req).await)
}

/// Extract client IP from request headers
fn extract_client_ip(req: &Request) -> Option<IpAddr> {
    // Check X-Forwarded-For header
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            // Take the first IP (original client)
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(real_ip_str) = real_ip.to_str() {
            if let Ok(ip) = real_ip_str.trim().parse() {
                return Some(ip);
            }
        }
    }

    None
}

/// Check per-IP rate limit
fn check_ip_rate_limit(state: &AppState, ip: IpAddr) -> Result<(), ApiError> {
    let limiters = &state.rate_limiters.per_ip;

    // Get or create rate limiter for this IP
    let limiter = limiters.entry(ip).or_insert_with(|| {
        // Default: 60 requests per minute per IP
        let quota = Quota::per_minute(NonZeroU32::new(60).unwrap());
        RateLimiter::direct(quota)
    });

    if limiter.check().is_err() {
        tracing::warn!("IP rate limit exceeded for {}", ip);
        return Err(ApiError::RateLimitExceeded(
            "Too many requests from your IP, please slow down".to_string(),
        ));
    }

    Ok(())
}

/// Check per-user rate limit
fn check_user_rate_limit(state: &AppState, user_id: &str) -> Result<(), ApiError> {
    let limiters = &state.rate_limiters.per_user;

    // Get or create rate limiter for this user
    let limiter = limiters.entry(user_id.to_string()).or_insert_with(|| {
        // Default: 120 requests per minute per user
        let quota = Quota::per_minute(NonZeroU32::new(120).unwrap());
        RateLimiter::direct(quota)
    });

    if limiter.check().is_err() {
        tracing::warn!("User rate limit exceeded for {}", user_id);
        return Err(ApiError::RateLimitExceeded(
            "Too many requests, please slow down".to_string(),
        ));
    }

    Ok(())
}

/// Stricter rate limiter for auth endpoints (login, register)
///
/// More restrictive to prevent brute force attacks:
/// - 5 requests per minute per IP for login attempts
/// - 3 requests per minute per IP for registration
pub fn create_auth_limiter(
    requests_per_minute: u32,
) -> RateLimiter<NotKeyed, InMemoryState, DefaultClock> {
    let rpm = NonZeroU32::new(requests_per_minute.max(1)).unwrap();
    let quota = Quota::per_minute(rpm);
    RateLimiter::direct(quota)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_auth_limiter() {
        let limiter = create_auth_limiter(5);

        // Should allow first 5 requests
        for _ in 0..5 {
            assert!(limiter.check().is_ok());
        }

        // 6th should fail (burst exhausted)
        assert!(limiter.check().is_err());
    }
}

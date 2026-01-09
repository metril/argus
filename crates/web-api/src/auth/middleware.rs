//! Authentication middleware
//!
//! Extracts and validates JWT tokens from httpOnly cookies.
//! Provides role-based access control.

use crate::auth::jwt::validate_access_token;
use crate::auth::models::{Claims, UserRole};
use crate::error::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

/// Extension type for authenticated user claims
#[derive(Debug, Clone)]
pub struct AuthUser(pub Claims);

impl AuthUser {
    pub fn user_id(&self) -> &str {
        &self.0.sub
    }

    pub fn username(&self) -> &str {
        &self.0.username
    }

    pub fn role(&self) -> UserRole {
        self.0.role
    }

    pub fn jti(&self) -> &str {
        &self.0.jti
    }
}

/// Cookie name for access token
pub const ACCESS_TOKEN_COOKIE: &str = "access_token";
/// Cookie name for refresh token
pub const REFRESH_TOKEN_COOKIE: &str = "refresh_token";

/// Extract access token from cookies
fn extract_token_from_cookies(req: &Request) -> Option<String> {
    let cookie_header = req.headers().get("cookie")?;
    let cookie_str = cookie_header.to_str().ok()?;

    for cookie in cookie_str.split(';') {
        let cookie = cookie.trim();
        if let Some(token) = cookie.strip_prefix(&format!("{}=", ACCESS_TOKEN_COOKIE)) {
            return Some(token.to_string());
        }
    }

    None
}

/// Extract refresh token from cookies
pub fn extract_refresh_token_from_cookies(req: &Request) -> Option<String> {
    let cookie_header = req.headers().get("cookie")?;
    let cookie_str = cookie_header.to_str().ok()?;

    for cookie in cookie_str.split(';') {
        let cookie = cookie.trim();
        if let Some(token) = cookie.strip_prefix(&format!("{}=", REFRESH_TOKEN_COOKIE)) {
            return Some(token.to_string());
        }
    }

    None
}

/// Authentication middleware
///
/// Extracts JWT from httpOnly cookie and validates it.
/// Adds `AuthUser` extension to request if valid.
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Extract token from cookie
    let token = extract_token_from_cookies(&req).ok_or_else(|| {
        ApiError::AuthenticationFailed("No authentication token provided".to_string())
    })?;

    // Validate token
    let claims = validate_access_token(&token, &state.jwt_config)?;

    // Check if token is revoked
    if state.session_manager.is_token_revoked(&claims.jti) {
        return Err(ApiError::AuthenticationFailed("Token has been revoked".to_string()));
    }

    // Add authenticated user to request extensions
    req.extensions_mut().insert(AuthUser(claims));

    Ok(next.run(req).await)
}

/// Require specific role middleware factory
///
/// Creates middleware that requires the user to have at least the specified role.
pub async fn require_role(
    required_role: UserRole,
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // First run auth middleware logic
    let token = extract_token_from_cookies(&req).ok_or_else(|| {
        ApiError::AuthenticationFailed("No authentication token provided".to_string())
    })?;

    let claims = validate_access_token(&token, &state.jwt_config)?;

    if state.session_manager.is_token_revoked(&claims.jti) {
        return Err(ApiError::AuthenticationFailed("Token has been revoked".to_string()));
    }

    // Check role
    let has_permission = match required_role {
        UserRole::Viewer => true, // Everyone can view
        UserRole::User => claims.role.can_modify(),
        UserRole::Admin => claims.role.is_admin(),
    };

    if !has_permission {
        return Err(ApiError::AuthorizationFailed(format!(
            "Requires {} role or higher",
            match required_role {
                UserRole::Admin => "admin",
                UserRole::User => "user",
                UserRole::Viewer => "viewer",
            }
        )));
    }

    Ok(next.run(req).await)
}

/// Require admin role
pub async fn require_admin(
    state: State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    require_role(UserRole::Admin, state, req, next).await
}

/// Require user role (can modify settings)
pub async fn require_user(
    state: State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    require_role(UserRole::User, state, req, next).await
}

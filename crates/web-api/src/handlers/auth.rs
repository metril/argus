//! Authentication handlers
//!
//! Provides endpoints for:
//! - Register (POST /api/auth/register)
//! - Login (POST /api/auth/login)
//! - Logout (POST /api/auth/logout)
//! - Token refresh (POST /api/auth/refresh)
//! - Current user info (GET /api/auth/me)

use crate::auth::jwt::{generate_token_pair, validate_refresh_token};
use crate::auth::middleware::{AuthUser, ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE};
use crate::auth::models::{LoginRequest, LoginResponse, RegisterRequest, User, UserInfo, UserRole};
use crate::auth::password::{hash_password, validate_password_strength, verify_password};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::{
    extract::State,
    http::{header::SET_COOKIE, HeaderMap, HeaderValue},
    Extension, Json,
};
use cookie::time::Duration;
use cookie::{Cookie, SameSite};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;
use validator::Validate;

/// Create httpOnly cookie for access token
fn create_access_token_cookie(token: &str, max_age_secs: u64) -> String {
    Cookie::build((ACCESS_TOKEN_COOKIE, token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(Duration::seconds(max_age_secs as i64))
        .path("/api")
        .to_string()
}

/// Create httpOnly cookie for refresh token
fn create_refresh_token_cookie(token: &str, max_age_secs: u64) -> String {
    Cookie::build((REFRESH_TOKEN_COOKIE, token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(Duration::seconds(max_age_secs as i64))
        .path("/api/auth")
        .to_string()
}

/// Create cookie that expires immediately (for logout)
fn create_expired_cookie(name: &str, path: &str) -> String {
    Cookie::build((name, ""))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(Duration::seconds(0))
        .path(path)
        .to_string()
}

/// Register endpoint
///
/// POST /api/auth/register
///
/// Creates a new user account. First user becomes admin, subsequent users are regular users.
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<(HeaderMap, Json<LoginResponse>)> {
    // Validate request
    req.validate()
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;

    // Validate password strength
    validate_password_strength(&req.password)?;

    // Check if username already exists
    if state.session_store.username_exists(&req.username)? {
        return Err(ApiError::ValidationError(
            "Username already taken".to_string(),
        ));
    }

    // Hash password
    let password_hash = hash_password(&req.password)?;

    // Determine role: first user is admin, others are regular users
    let all_users = state.session_store.get_all_users()?;
    let role = if all_users.is_empty() {
        info!("Creating first user as admin: {}", req.username);
        UserRole::Admin
    } else {
        UserRole::User
    };

    // Create user
    let user = User::new(req.username.clone(), password_hash, role);

    // Store user
    state.session_store.store_user(&user)?;

    info!("New user registered: {} (role: {:?})", user.username, role);

    // Generate tokens
    let tokens = generate_token_pair(&user.id, &user.username, user.role, &state.jwt_config)?;

    // Create session
    let _session_id = state.session_manager.create_session(
        user.id,
        user.username.clone(),
        validate_refresh_token(&tokens.refresh_token, &state.jwt_config)?.jti,
        None,
        None,
    );

    // Set cookies
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&create_access_token_cookie(
            &tokens.access_token,
            tokens.access_expires_in,
        ))
        .unwrap(),
    );
    headers.append(
        SET_COOKIE,
        HeaderValue::from_str(&create_refresh_token_cookie(
            &tokens.refresh_token,
            tokens.refresh_expires_in,
        ))
        .unwrap(),
    );

    Ok((
        headers,
        Json(LoginResponse {
            user: UserInfo::from(&user),
            expires_in: tokens.access_expires_in,
        }),
    ))
}

/// Login endpoint
///
/// POST /api/auth/login
///
/// Authenticates user and sets httpOnly cookies with JWT tokens.
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<(HeaderMap, Json<LoginResponse>)> {
    // Validate request
    req.validate()
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;

    // Look up user (using session store's user lookup)
    let user = state
        .session_store
        .get_user_by_username(&req.username)?
        .ok_or_else(|| {
            warn!("Login attempt for unknown user: {}", req.username);
            ApiError::AuthenticationFailed("Invalid username or password".to_string())
        })?;

    // Verify password
    if !verify_password(&req.password, &user.password_hash)? {
        warn!("Failed login attempt for user: {}", req.username);
        return Err(ApiError::AuthenticationFailed(
            "Invalid username or password".to_string(),
        ));
    }

    // Check if account is enabled
    if !user.enabled {
        warn!("Login attempt for disabled account: {}", req.username);
        return Err(ApiError::AuthenticationFailed(
            "Account is disabled".to_string(),
        ));
    }

    // Generate tokens
    let tokens = generate_token_pair(&user.id, &user.username, user.role, &state.jwt_config)?;

    // Create session
    let _session_id = state.session_manager.create_session(
        user.id,
        user.username.clone(),
        // Extract JTI from refresh token for revocation tracking
        validate_refresh_token(&tokens.refresh_token, &state.jwt_config)?
            .jti,
        None, // TODO: Extract from request
        None, // TODO: Extract from request
    );

    // Update last login
    state.session_store.update_last_login(&user.id)?;

    info!("User logged in: {}", user.username);

    // Set cookies
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&create_access_token_cookie(
            &tokens.access_token,
            tokens.access_expires_in,
        ))
        .unwrap(),
    );
    headers.append(
        SET_COOKIE,
        HeaderValue::from_str(&create_refresh_token_cookie(
            &tokens.refresh_token,
            tokens.refresh_expires_in,
        ))
        .unwrap(),
    );

    Ok((
        headers,
        Json(LoginResponse {
            user: UserInfo::from(&user),
            expires_in: tokens.access_expires_in,
        }),
    ))
}

/// Logout endpoint
///
/// POST /api/auth/logout
///
/// Revokes the current session and clears auth cookies.
pub async fn logout(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
) -> ApiResult<(HeaderMap, Json<Value>)> {
    // Revoke the token
    state.session_manager.revoke_token(auth_user.jti());

    info!("User logged out: {}", auth_user.username());

    // Clear cookies
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&create_expired_cookie(ACCESS_TOKEN_COOKIE, "/api")).unwrap(),
    );
    headers.append(
        SET_COOKIE,
        HeaderValue::from_str(&create_expired_cookie(REFRESH_TOKEN_COOKIE, "/api/auth")).unwrap(),
    );

    Ok((headers, Json(json!({ "message": "Logged out successfully" }))))
}

/// Refresh token endpoint
///
/// POST /api/auth/refresh
///
/// Issues new access token using refresh token from cookie.
pub async fn refresh(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<(HeaderMap, Json<Value>)> {
    // Build a minimal request to extract cookie
    let refresh_token = headers
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|cookies| {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(token) = cookie.strip_prefix(&format!("{}=", REFRESH_TOKEN_COOKIE)) {
                    return Some(token.to_string());
                }
            }
            None
        })
        .ok_or_else(|| ApiError::AuthenticationFailed("No refresh token provided".to_string()))?;

    // Validate refresh token
    let claims = validate_refresh_token(&refresh_token, &state.jwt_config)?;

    // Check if token is revoked
    if state.session_manager.is_token_revoked(&claims.jti) {
        return Err(ApiError::AuthenticationFailed(
            "Refresh token has been revoked".to_string(),
        ));
    }

    // Parse user ID
    let user_id: Uuid = claims
        .sub
        .parse()
        .map_err(|_| ApiError::Internal("Invalid user ID in token".to_string()))?;

    // Generate new token pair
    let tokens = generate_token_pair(&user_id, &claims.username, claims.role, &state.jwt_config)?;

    // Revoke old refresh token
    state.session_manager.revoke_token(&claims.jti);

    // Update session with new refresh token JTI
    let new_jti = validate_refresh_token(&tokens.refresh_token, &state.jwt_config)?.jti;
    state.session_manager.create_session(
        user_id,
        claims.username.clone(),
        new_jti,
        None,
        None,
    );

    info!("Token refreshed for user: {}", claims.username);

    // Set new cookies
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&create_access_token_cookie(
            &tokens.access_token,
            tokens.access_expires_in,
        ))
        .unwrap(),
    );
    response_headers.append(
        SET_COOKIE,
        HeaderValue::from_str(&create_refresh_token_cookie(
            &tokens.refresh_token,
            tokens.refresh_expires_in,
        ))
        .unwrap(),
    );

    Ok((
        response_headers,
        Json(json!({
            "message": "Token refreshed",
            "expires_in": tokens.access_expires_in
        })),
    ))
}

/// Get current user info
///
/// GET /api/auth/me
///
/// Returns information about the currently authenticated user.
pub async fn me(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
) -> ApiResult<Json<UserInfo>> {
    let user_id: Uuid = auth_user
        .user_id()
        .parse()
        .map_err(|_| ApiError::Internal("Invalid user ID".to_string()))?;

    let user = state
        .session_store
        .get_user(&user_id)?
        .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

    Ok(Json(UserInfo::from(&user)))
}

/// List current user's sessions
///
/// GET /api/auth/sessions
pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
) -> ApiResult<Json<Value>> {
    let user_id: Uuid = auth_user
        .user_id()
        .parse()
        .map_err(|_| ApiError::Internal("Invalid user ID".to_string()))?;

    let sessions = state.session_manager.get_user_sessions(&user_id);

    let session_list: Vec<Value> = sessions
        .iter()
        .map(|(id, session)| {
            json!({
                "id": id.to_string(),
                "created_at": session.created_at.to_rfc3339(),
                "last_activity": session.last_activity.to_rfc3339(),
                "ip_address": session.ip_address.map(|ip| ip.to_string()),
            })
        })
        .collect();

    Ok(Json(json!({ "sessions": session_list })))
}

/// Revoke a specific session
///
/// DELETE /api/auth/sessions/:session_id
pub async fn revoke_session(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let user_id: Uuid = auth_user
        .user_id()
        .parse()
        .map_err(|_| ApiError::Internal("Invalid user ID".to_string()))?;

    // Verify session belongs to user
    let session = state
        .session_manager
        .get_session(&session_id)
        .ok_or_else(|| ApiError::NotFound("Session not found".to_string()))?;

    if session.user_id != user_id {
        return Err(ApiError::AuthorizationFailed(
            "Cannot revoke another user's session".to_string(),
        ));
    }

    state.session_manager.revoke_session(&session_id);

    info!(
        "User {} revoked session {}",
        auth_user.username(),
        session_id
    );

    Ok(Json(json!({ "message": "Session revoked" })))
}

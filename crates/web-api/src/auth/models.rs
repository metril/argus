//! Authentication models
//!
//! Defines user structures, claims, and request/response types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

/// User role for authorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    /// Full administrative access
    Admin,
    /// Read/write access to configurations
    User,
    /// Read-only access (dashboard viewing)
    Viewer,
}

impl Default for UserRole {
    fn default() -> Self {
        Self::Viewer
    }
}

impl UserRole {
    /// Check if role has admin privileges
    pub fn is_admin(&self) -> bool {
        matches!(self, Self::Admin)
    }

    /// Check if role can modify settings
    pub fn can_modify(&self) -> bool {
        matches!(self, Self::Admin | Self::User)
    }
}

/// User account (stored in database)
/// Note: password_hash is serialized for database storage but should never be
/// exposed in API responses. Use UserInfo for external responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique user ID
    pub id: Uuid,
    /// Username (unique)
    pub username: String,
    /// bcrypt hashed password (stored but not exposed in API)
    pub password_hash: String,
    /// User role
    pub role: UserRole,
    /// Account creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last login timestamp
    pub last_login: Option<DateTime<Utc>>,
    /// Whether account is enabled
    pub enabled: bool,
}

impl User {
    /// Create a new user
    pub fn new(username: String, password_hash: String, role: UserRole) -> Self {
        Self {
            id: Uuid::new_v4(),
            username,
            password_hash,
            role,
            created_at: Utc::now(),
            last_login: None,
            enabled: true,
        }
    }
}

/// JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Username
    pub username: String,
    /// User role
    pub role: UserRole,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Expiration (Unix timestamp)
    pub exp: i64,
    /// JWT ID (for revocation)
    pub jti: String,
    /// Token type (access or refresh)
    #[serde(rename = "type")]
    pub token_type: TokenType,
}

/// Token type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    Access,
    Refresh,
}

/// Login request payload
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct LoginRequest {
    #[validate(length(min = 3, max = 50, message = "Username must be 3-50 characters"))]
    pub username: String,

    #[validate(length(min = 8, max = 128, message = "Password must be 8-128 characters"))]
    pub password: String,
}

/// Register request payload
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RegisterRequest {
    #[validate(length(min = 3, max = 50, message = "Username must be 3-50 characters"))]
    #[validate(custom(function = "validate_username"))]
    pub username: String,

    #[validate(length(min = 8, max = 128, message = "Password must be 8-128 characters"))]
    pub password: String,

    #[validate(must_match(other = "password", message = "Passwords must match"))]
    pub password_confirm: String,
}

/// Validate username: must be alphanumeric with underscores only
fn validate_username(username: &str) -> Result<(), validator::ValidationError> {
    if username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        Ok(())
    } else {
        let mut err = validator::ValidationError::new("invalid_username");
        err.message = Some("Username must be alphanumeric with underscores only".into());
        Err(err)
    }
}

/// Login response with tokens
#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub user: UserInfo,
    pub expires_in: u64,
}

/// Safe user info (no sensitive data)
#[derive(Debug, Serialize, ToSchema)]
pub struct UserInfo {
    pub id: Uuid,
    pub username: String,
    pub role: UserRole,
}

impl From<&User> for UserInfo {
    fn from(user: &User) -> Self {
        Self {
            id: user.id,
            username: user.username.clone(),
            role: user.role,
        }
    }
}

/// Token refresh request
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    // Refresh token is read from httpOnly cookie, not request body
}

/// Change password request
#[derive(Debug, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    pub current_password: String,

    #[validate(length(min = 8, max = 128, message = "Password must be 8-128 characters"))]
    pub new_password: String,

    #[validate(must_match(other = "new_password", message = "Passwords must match"))]
    pub new_password_confirm: String,
}

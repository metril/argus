//! Authentication models
//!
//! Server-side user/token structures. The wire-facing request/response DTOs
//! (`UserRole`, `UserInfo`, `LoginRequest`, `RegisterRequest`, `LoginResponse`)
//! live in the shared `api-types` crate and are re-exported here so existing
//! paths (`crate::auth::models::UserInfo`, …) keep working.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

pub use api_types::{LoginRequest, LoginResponse, RegisterRequest, UserInfo, UserRole};

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

/// Build the safe, wire-facing `UserInfo` from an internal `User`.
impl From<&User> for UserInfo {
    fn from(user: &User) -> Self {
        Self {
            id: user.id.to_string(),
            username: user.username.clone(),
            role: user.role,
            created_at: user.created_at.to_rfc3339(),
            last_login: user.last_login.map(|t| t.to_rfc3339()),
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

//! Authentication models
//!
//! Server-side user/token structures. The wire-facing request/response DTOs
//! (`UserRole`, `UserInfo`, `LoginRequest`, `RegisterRequest`, `LoginResponse`)
//! live in the shared `api-types` crate and are re-exported here so existing
//! paths (`crate::auth::models::UserInfo`, …) keep working.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    /// Profile (decimal id) the account starts on in the UI.
    #[serde(default)]
    pub default_profile: Option<String>,
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
            default_profile: None,
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
    /// JWT ID (for refresh-token rotation)
    pub jti: String,
    /// Session this token belongs to; the token is dead once the session is revoked.
    pub sid: String,
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
            enabled: user.enabled,
            scopes: user.role.scopes(),
            default_profile: user.default_profile.clone(),
            session_count: 0,
        }
    }
}

//! Authentication API calls

use serde::{Deserialize, Serialize};

use super::client::{ApiClient, ApiError};

/// Login request
#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Registration request
#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub password_confirm: String,
}

/// User role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
    Viewer,
}

impl UserRole {
    /// Check if user can modify data
    pub fn can_modify(&self) -> bool {
        matches!(self, UserRole::Admin | UserRole::User)
    }

    /// Check if user is admin
    pub fn is_admin(&self) -> bool {
        matches!(self, UserRole::Admin)
    }
}

/// User info returned from API
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub role: UserRole,
    pub created_at: String,
    pub last_login: Option<String>,
}

/// Login response
#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    pub user: UserInfo,
    pub message: String,
}

/// Register response
#[derive(Debug, Deserialize)]
pub struct RegisterResponse {
    pub user: UserInfo,
    pub message: String,
}

/// Generic message response
#[derive(Debug, Deserialize)]
pub struct MessageResponse {
    pub message: String,
}

/// Session info
#[derive(Debug, Clone, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub created_at: String,
    pub last_used: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

/// Sessions list response
#[derive(Debug, Deserialize)]
pub struct SessionsResponse {
    pub sessions: Vec<SessionInfo>,
}

impl ApiClient {
    /// Register a new user
    pub async fn register(
        &self,
        username: &str,
        password: &str,
    ) -> Result<RegisterResponse, ApiError> {
        let req = RegisterRequest {
            username: username.to_string(),
            password: password.to_string(),
            password_confirm: password.to_string(),
        };
        self.post("/api/auth/register", &req).await
    }

    /// Login with username and password
    pub async fn login(&self, username: &str, password: &str) -> Result<LoginResponse, ApiError> {
        let req = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        };
        self.post("/api/auth/login", &req).await
    }

    /// Logout the current user
    pub async fn logout(&self) -> Result<MessageResponse, ApiError> {
        self.post("/api/auth/logout", &()).await
    }

    /// Refresh the access token
    pub async fn refresh(&self) -> Result<MessageResponse, ApiError> {
        self.post("/api/auth/refresh", &()).await
    }

    /// Get current user info
    pub async fn me(&self) -> Result<UserInfo, ApiError> {
        self.get("/api/auth/me").await
    }

    /// List active sessions
    pub async fn list_sessions(&self) -> Result<SessionsResponse, ApiError> {
        self.get("/api/auth/sessions").await
    }

    /// Revoke a session
    pub async fn revoke_session(&self, session_id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/api/auth/sessions/{}", session_id))
            .await
    }
}

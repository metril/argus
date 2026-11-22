//! Authentication API calls

use super::client::{ApiClient, ApiError};

// Wire DTOs come from the shared `api-types` crate (single source of truth).
pub use api_types::{
    LoginRequest, LoginResponse, MessageResponse, RegisterRequest, RegisterResponse, SessionInfo,
    UserInfo, UserRole,
};

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
        self.post("/auth/register", &req).await
    }

    /// Login with username and password
    pub async fn login(&self, username: &str, password: &str) -> Result<LoginResponse, ApiError> {
        let req = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        };
        self.post("/auth/login", &req).await
    }

    /// Logout the current user
    pub async fn logout(&self) -> Result<MessageResponse, ApiError> {
        self.post("/auth/logout", &()).await
    }

    /// Refresh the access token
    pub async fn refresh(&self) -> Result<MessageResponse, ApiError> {
        self.post("/auth/refresh", &()).await
    }

    /// Get current user info
    pub async fn me(&self) -> Result<UserInfo, ApiError> {
        self.get("/auth/me").await
    }

    /// List active sessions
    pub async fn list_sessions(&self) -> Result<api_types::Page<SessionInfo>, ApiError> {
        self.get("/auth/sessions").await
    }

    /// Revoke a session
    pub async fn revoke_session(&self, session_id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/auth/sessions/{}", session_id)).await
    }
}

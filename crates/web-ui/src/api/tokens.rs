//! API token management calls (`/api/v1/tokens`)

use super::auth::MessageResponse;
use super::client::{ApiClient, ApiError};

pub use api_types::{ApiTokenInfo, CreateTokenRequest, CreatedTokenResponse, Page, Scope};

impl ApiClient {
    /// List the current user's API tokens
    pub async fn list_tokens(&self) -> Result<Page<ApiTokenInfo>, ApiError> {
        self.get("/tokens?limit=200").await
    }

    /// Create a token; the returned secret is shown to the user once
    pub async fn create_token(
        &self,
        name: &str,
        scopes: Vec<Scope>,
        expires_in_days: Option<u32>,
    ) -> Result<CreatedTokenResponse, ApiError> {
        let req = CreateTokenRequest {
            name: name.to_string(),
            scopes,
            expires_in_days,
            profiles: None,
        };
        self.post("/tokens", &req).await
    }

    /// Revoke a token
    pub async fn revoke_token(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/tokens/{id}")).await
    }
}

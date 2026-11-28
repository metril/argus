//! API token management calls (`/api/v1/tokens`)

use super::auth::MessageResponse;
use super::client::{ApiClient, ApiError};

pub use api_types::{
    ApiTokenInfo, CreateTokenRequest, CreatedTokenResponse, Page, RegenerateTokenRequest, Scope,
    TokenPurpose, UpdateTokenRequest,
};

impl ApiClient {
    /// List the current user's API tokens
    pub async fn list_tokens(
        &self,
        cursor: Option<&str>,
        include_revoked: bool,
    ) -> Result<Page<ApiTokenInfo>, ApiError> {
        self.get(&format!(
            "/tokens?limit=40{}{}",
            super::admin::cur(cursor),
            if include_revoked {
                "&include_revoked=true"
            } else {
                ""
            }
        ))
        .await
    }

    /// Every token of the current user (revoked ones too), following the cursor to the end.
    pub async fn list_all_tokens(&self) -> Result<Vec<ApiTokenInfo>, ApiError> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page: Page<ApiTokenInfo> = self
                .get(&format!(
                    "/tokens?limit=200&include_revoked=true{}",
                    super::admin::cur(cursor.as_deref())
                ))
                .await?;
            out.extend(page.items);
            match page.next_cursor {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => return Ok(out),
            }
        }
    }

    /// Create a token; the returned secret is shown to the user once
    pub async fn create_token(
        &self,
        req: &CreateTokenRequest,
    ) -> Result<CreatedTokenResponse, ApiError> {
        self.post("/tokens", req).await
    }

    /// Change a token's name, access, profiles or expiry
    pub async fn update_token(
        &self,
        id: &str,
        req: &UpdateTokenRequest,
    ) -> Result<ApiTokenInfo, ApiError> {
        self.patch(&format!("/tokens/{id}"), req).await
    }

    /// Issue a new secret for a token; returned once
    pub async fn regenerate_token(
        &self,
        id: &str,
        req: &RegenerateTokenRequest,
    ) -> Result<CreatedTokenResponse, ApiError> {
        self.post(&format!("/tokens/{id}/regenerate"), req).await
    }

    /// Revoke a token
    pub async fn revoke_token(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/tokens/{id}")).await
    }
}

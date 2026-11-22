//! Userscript management API calls

use serde::Deserialize;

use super::auth::MessageResponse;
use super::client::{ApiClient, ApiError};

// Wire DTOs come from the shared `api-types` crate (single source of truth).
// Aliases preserve the names the UI pages already use.
pub use api_types::UserscriptResponse as Userscript;
pub use api_types::UserscriptStatsResponse as UserscriptStats;
pub use api_types::{InstallUserscriptRequest, SetEnabledRequest, UpdateUserscriptRequest};
pub type UserscriptsResponse = api_types::PaginatedResponse<Userscript>;

/// Userscript source response (server returns an ad-hoc `{id, source}` object)
#[derive(Debug, Deserialize)]
pub struct UserscriptSourceResponse {
    pub id: String,
    pub source: String,
}

impl ApiClient {
    /// List userscripts with pagination
    pub async fn list_userscripts(
        &self,
        page: u32,
        limit: u32,
        enabled: Option<bool>,
    ) -> Result<UserscriptsResponse, ApiError> {
        let mut url = format!("/api/userscripts?page={}&limit={}", page, limit);
        if let Some(enabled) = enabled {
            url.push_str(&format!("&enabled={}", enabled));
        }
        self.get(&url).await
    }

    /// Get a specific userscript
    pub async fn get_userscript(&self, id: &str) -> Result<Userscript, ApiError> {
        self.get(&format!("/api/userscripts/{}", id)).await
    }

    /// Get userscript source code
    pub async fn get_userscript_source(
        &self,
        id: &str,
    ) -> Result<UserscriptSourceResponse, ApiError> {
        self.get(&format!("/api/userscripts/{}/source", id)).await
    }

    /// Install a new userscript
    pub async fn install_userscript(&self, source: &str) -> Result<Userscript, ApiError> {
        let req = InstallUserscriptRequest {
            source: source.to_string(),
        };
        self.post("/api/userscripts", &req).await
    }

    /// Update a userscript
    pub async fn update_userscript(&self, id: &str, source: &str) -> Result<Userscript, ApiError> {
        let req = UpdateUserscriptRequest {
            source: source.to_string(),
        };
        self.put(&format!("/api/userscripts/{}", id), &req).await
    }

    /// Uninstall a userscript
    pub async fn uninstall_userscript(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/api/userscripts/{}", id)).await
    }

    /// Enable or disable a userscript
    pub async fn set_userscript_enabled(
        &self,
        id: &str,
        enabled: bool,
    ) -> Result<Userscript, ApiError> {
        let req = SetEnabledRequest { enabled };
        self.put(&format!("/api/userscripts/{}/enabled", id), &req)
            .await
    }

    /// Get userscript statistics
    pub async fn get_userscript_stats(&self) -> Result<UserscriptStats, ApiError> {
        self.get("/api/userscripts/stats").await
    }
}

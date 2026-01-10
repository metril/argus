//! Userscript management API calls

use serde::{Deserialize, Serialize};

use super::auth::MessageResponse;
use super::client::{ApiClient, ApiError};

/// Userscript info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Userscript {
    pub id: String,
    pub name: String,
    pub namespace: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub enabled: bool,
    pub execution_count: u64,
    pub last_executed: Option<String>,
    pub match_patterns: Vec<String>,
}

/// Request to install a userscript
#[derive(Debug, Serialize)]
pub struct InstallUserscriptRequest {
    pub source: String,
}

/// Request to update a userscript
#[derive(Debug, Serialize)]
pub struct UpdateUserscriptRequest {
    pub source: String,
}

/// Request to set enabled status
#[derive(Debug, Serialize)]
pub struct SetEnabledRequest {
    pub enabled: bool,
}

/// Paginated userscript response
#[derive(Debug, Deserialize)]
pub struct UserscriptsResponse {
    pub data: Vec<Userscript>,
    pub total: usize,
    pub page: u32,
    pub limit: u32,
}

/// Userscript source response
#[derive(Debug, Deserialize)]
pub struct UserscriptSourceResponse {
    pub id: String,
    pub source: String,
}

/// Userscript statistics
#[derive(Debug, Clone, Deserialize)]
pub struct UserscriptStats {
    pub total_scripts: usize,
    pub enabled_scripts: usize,
    pub disabled_scripts: usize,
    pub total_executions: u64,
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

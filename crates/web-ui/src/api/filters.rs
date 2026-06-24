//! Filter list management API calls

use serde::Deserialize;

use super::auth::MessageResponse;
use super::client::{ApiClient, ApiError};

// Wire DTOs come from the shared `api-types` crate (single source of truth).
// Aliases preserve the names the UI pages already use.
pub use api_types::{
    AddFilterListRequest, CustomRulesResponse, UpdateCustomRulesRequest, UpdateFilterListRequest,
};
pub use api_types::FilterListResponse as FilterList;
pub type FilterListsResponse = api_types::PaginatedResponse<FilterList>;

/// Filter blocking statistics (mirrors filter_engine::BlockingStats, server-only)
#[derive(Debug, Clone, Deserialize)]
pub struct FilterStats {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub allowed_requests: u64,
    #[serde(default)]
    pub blocked_by_type: std::collections::HashMap<String, u64>,
    #[serde(default)]
    pub top_blocked_domains: Vec<(String, u64)>,
}

impl ApiClient {
    /// List filter lists with pagination
    pub async fn list_filter_lists(
        &self,
        page: u32,
        limit: u32,
    ) -> Result<FilterListsResponse, ApiError> {
        self.get(&format!("/api/filters/lists?page={}&limit={}", page, limit))
            .await
    }

    /// Get a specific filter list
    pub async fn get_filter_list(&self, id: &str) -> Result<FilterList, ApiError> {
        self.get(&format!("/api/filters/lists/{}", id)).await
    }

    /// Add a new filter list
    pub async fn add_filter_list(
        &self,
        id: &str,
        name: &str,
        url: &str,
        enabled: bool,
    ) -> Result<FilterList, ApiError> {
        let req = AddFilterListRequest {
            id: id.to_string(),
            name: name.to_string(),
            url: url.to_string(),
            enabled: Some(enabled),
        };
        self.post("/api/filters/lists", &req).await
    }

    /// Update a filter list
    pub async fn update_filter_list(
        &self,
        id: &str,
        update: &UpdateFilterListRequest,
    ) -> Result<FilterList, ApiError> {
        self.put(&format!("/api/filters/lists/{}", id), update).await
    }

    /// Delete a filter list
    pub async fn delete_filter_list(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/api/filters/lists/{}", id)).await
    }

    /// Get filter statistics
    pub async fn get_filter_stats(&self) -> Result<FilterStats, ApiError> {
        self.get("/api/filters/stats").await
    }

    /// Reset filter statistics
    pub async fn reset_filter_stats(&self) -> Result<MessageResponse, ApiError> {
        self.post("/api/filters/stats/reset", &()).await
    }

    /// Get the user's custom filter rules
    pub async fn get_custom_rules(&self) -> Result<CustomRulesResponse, ApiError> {
        self.get("/api/filters/custom-rules").await
    }

    /// Replace the user's custom filter rules
    pub async fn update_custom_rules(
        &self,
        rules: &str,
    ) -> Result<CustomRulesResponse, ApiError> {
        let req = UpdateCustomRulesRequest {
            rules: rules.to_string(),
        };
        self.put("/api/filters/custom-rules", &req).await
    }
}

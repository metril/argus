//! Filter list management API calls

use super::auth::MessageResponse;
use super::client::{ApiClient, ApiError};

// Wire DTOs come from the shared `api-types` crate (single source of truth).
// Aliases preserve the names the UI pages already use.
pub use api_types::FilterListResponse as FilterList;
pub use api_types::{
    AddFilterListRequest, CustomRulesResponse, UpdateCustomRulesRequest, UpdateFilterListRequest,
};
pub type FilterListsResponse = api_types::Page<FilterList>;

/// Filter blocking statistics.
pub use api_types::FilterStatsResponse as FilterStats;

impl ApiClient {
    /// List filter lists with pagination
    pub async fn list_filter_lists(
        &self,
        page: u32,
        limit: u32,
    ) -> Result<FilterListsResponse, ApiError> {
        self.get(&format!("/lists?page={}&limit={}", page, limit))
            .await
    }

    /// Get a specific filter list
    pub async fn get_filter_list(&self, id: &str) -> Result<FilterList, ApiError> {
        self.get(&format!("/lists/{}", id)).await
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
        self.post("/lists", &req).await
    }

    /// Update a filter list
    pub async fn update_filter_list(
        &self,
        id: &str,
        update: &UpdateFilterListRequest,
    ) -> Result<FilterList, ApiError> {
        self.put(&format!("/lists/{}", id), update).await
    }

    /// Delete a filter list
    pub async fn delete_filter_list(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/lists/{}", id)).await
    }

    /// Get filter statistics
    pub async fn get_filter_stats(&self) -> Result<FilterStats, ApiError> {
        self.get("/stats/filter").await
    }

    /// Reset filter statistics
    pub async fn reset_filter_stats(&self) -> Result<MessageResponse, ApiError> {
        self.post("/stats/filter/reset", &()).await
    }

    /// Get the custom filter rules and their `ETag`
    pub async fn get_custom_rules(
        &self,
    ) -> Result<(CustomRulesResponse, Option<String>), ApiError> {
        self.get_etag("/rules/custom").await
    }

    /// Replace the custom filter rules; `etag` is the one from the last read (lost-update guard)
    pub async fn update_custom_rules(
        &self,
        rules: &str,
        etag: &str,
    ) -> Result<(CustomRulesResponse, Option<String>), ApiError> {
        let req = UpdateCustomRulesRequest {
            rules: rules.to_string(),
        };
        self.put_if_match("/rules/custom", &req, etag).await
    }
}

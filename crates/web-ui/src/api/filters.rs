//! Filter list management API calls

use super::auth::MessageResponse;
use super::client::{ApiClient, ApiError};

// Wire DTOs come from the shared `api-types` crate (single source of truth).
// Aliases preserve the names the UI pages already use.
pub use api_types::FilterListResponse as FilterList;
pub use api_types::{
    AddFilterListRequest, BlockedEntry, BuildState, BuildSummary, CatalogueEntryResponse,
    CustomRulesResponse, ListReport, RecentBlockedResponse, UpdateCustomRulesRequest,
    UpdateFilterListRequest,
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
        format: &str,
        allowlist: bool,
    ) -> Result<FilterList, ApiError> {
        let req = AddFilterListRequest {
            id: id.to_string(),
            name: name.to_string(),
            url: url.to_string(),
            enabled: Some(enabled),
            format: Some(format.to_string()),
            allowlist: Some(allowlist),
            trusted: None,
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

    /// Toggle enabled / allowlist of a list (only the given fields change)
    pub async fn set_list_flags(
        &self,
        id: &str,
        enabled: Option<bool>,
        allowlist: Option<bool>,
    ) -> Result<FilterList, ApiError> {
        let req = UpdateFilterListRequest {
            name: None,
            url: None,
            enabled,
            format: None,
            allowlist,
            trusted: None,
        };
        self.update_filter_list(id, &req).await
    }

    /// Trust or distrust a list's code-running extended rules (needs `lists:write`; audited)
    pub async fn set_list_trusted(&self, id: &str, trusted: bool) -> Result<FilterList, ApiError> {
        let req = UpdateFilterListRequest {
            name: None,
            url: None,
            enabled: None,
            format: None,
            allowlist: None,
            trusted: Some(trusted),
        };
        self.update_filter_list(id, &req).await
    }

    /// What the last build made of a list
    pub async fn get_list_report(&self, id: &str) -> Result<ListReport, ApiError> {
        self.get(&format!("/lists/{}/report", id)).await
    }

    /// Build state and totals of the installed engine
    pub async fn get_build_summary(&self) -> Result<BuildSummary, ApiError> {
        self.get("/engine/build").await
    }

    /// The catalogue of well-known lists
    pub async fn get_catalogue(&self) -> Result<Vec<CatalogueEntryResponse>, ApiError> {
        self.get("/lists/catalogue").await
    }

    /// Add a catalogue entry as a list
    pub async fn add_from_catalogue(&self, id: &str) -> Result<FilterList, ApiError> {
        self.post(&format!("/lists/catalogue/{}", id), &()).await
    }

    /// Recently blocked requests, newest first, with optional filters
    pub async fn get_recent_blocked(
        &self,
        limit: u32,
        client: &str,
        host: &str,
        list_id: &str,
    ) -> Result<RecentBlockedResponse, ApiError> {
        let mut path = format!("/stats/blocked/recent?limit={limit}");
        for (k, v) in [("client", client), ("host", host), ("list_id", list_id)] {
            if !v.trim().is_empty() {
                path.push_str(&format!("&{k}={}", js_sys::encode_uri_component(v.trim())));
            }
        }
        self.get(&path).await
    }
}

//! Userscript management API calls

use super::auth::MessageResponse;
use super::client::{ApiClient, ApiError};

// Wire DTOs come from the shared `api-types` crate (single source of truth).
// Aliases preserve the names the UI pages already use.
pub use api_types::UserscriptResponse as Userscript;
pub use api_types::UserscriptStatsResponse as UserscriptStats;
pub use api_types::{InstallUserscriptRequest, SetEnabledRequest};
pub type UserscriptsResponse = api_types::Page<Userscript>;

pub use api_types::UserscriptSourceResponse;
pub use api_types::{
    ApproveUpdateRequest, CheckUpdateRequest, CheckUpdateResponse, ConfirmPlanRequest,
    ImportUserscriptsResponse, PendingUpdateDto, PlanUserscriptRequest, UpdateDiffDto,
    UserscriptBundle, UserscriptPlanResponse, UserscriptStorageResponse,
};

pub use api_types::{
    UserscriptCatalogueEntryDto, UserscriptCatalogueResponse, UserscriptCounts, UserscriptsPage,
};

impl ApiClient {
    /// Cursor-paged list. `status`: "" | enabled | disabled | error; `sort`: name | updated;
    /// `from` seeks to a name prefix (name sort only).
    pub async fn list_userscripts_paged(
        &self,
        q: &str,
        status: &str,
        sort: &str,
        cursor: Option<&str>,
        from: Option<&str>,
        limit: u32,
    ) -> Result<UserscriptsPage, ApiError> {
        let enc = |s: &str| String::from(js_sys::encode_uri_component(s));
        let mut url = format!("/userscripts?limit={limit}&sort={sort}&q={}", enc(q.trim()));
        if !status.is_empty() {
            url.push_str(&format!("&status={status}"));
        }
        if let Some(c) = cursor {
            url.push_str(&format!("&cursor={}", enc(c)));
        }
        if let Some(f) = from {
            url.push_str(&format!("&from={}", enc(f)));
        }
        self.get(&url).await
    }

    /// List userscripts with pagination
    pub async fn list_userscripts(
        &self,
        page: u32,
        limit: u32,
        enabled: Option<bool>,
    ) -> Result<UserscriptsResponse, ApiError> {
        let mut url = format!("/userscripts?page={}&limit={}", page, limit);
        if let Some(enabled) = enabled {
            url.push_str(&format!("&enabled={}", enabled));
        }
        self.get(&url).await
    }

    /// Get a specific userscript
    pub async fn get_userscript(&self, id: &str) -> Result<Userscript, ApiError> {
        self.get(&format!("/userscripts/{}", id)).await
    }

    /// Get userscript source code
    pub async fn get_userscript_source(
        &self,
        id: &str,
    ) -> Result<UserscriptSourceResponse, ApiError> {
        self.get(&format!("/userscripts/{}/source", id)).await
    }

    /// Install a new userscript
    pub async fn install_userscript(&self, source: &str) -> Result<Userscript, ApiError> {
        let req = InstallUserscriptRequest {
            source: source.to_string(),
        };
        self.post("/userscripts", &req).await
    }

    /// Uninstall a userscript
    pub async fn uninstall_userscript(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/userscripts/{}", id)).await
    }

    /// Enable or disable a userscript
    pub async fn set_userscript_enabled(
        &self,
        id: &str,
        enabled: bool,
    ) -> Result<Userscript, ApiError> {
        let req = SetEnabledRequest { enabled };
        self.put(&format!("/userscripts/{}/enabled", id), &req)
            .await
    }

    /// Get userscript statistics
    pub async fn get_userscript_stats(&self) -> Result<UserscriptStats, ApiError> {
        self.get("/userscripts/stats").await
    }

    /// The signed catalogue of curated userscripts.
    pub async fn get_userscript_catalogue(&self) -> Result<UserscriptCatalogueResponse, ApiError> {
        self.get("/userscripts/catalogue").await
    }

    /// Plan an install from pasted source or a URL (nothing is installed yet).
    pub async fn plan_userscript(
        &self,
        source: Option<String>,
        url: Option<String>,
    ) -> Result<UserscriptPlanResponse, ApiError> {
        self.post("/userscripts/plan", &PlanUserscriptRequest { source, url })
            .await
    }

    /// Confirm a plan, installing the script.
    pub async fn confirm_userscript_plan(
        &self,
        plan_id: &str,
        allow_connect_all: bool,
    ) -> Result<Userscript, ApiError> {
        let req = ConfirmPlanRequest {
            allow_connect_all,
            enable: true,
        };
        self.post(&format!("/userscripts/plan/{}/confirm", plan_id), &req)
            .await
    }

    /// Check a script's update URL (never auto-applies from the UI).
    pub async fn check_userscript_update(&self, id: &str) -> Result<CheckUpdateResponse, ApiError> {
        self.post(
            &format!("/userscripts/{}/check-update", id),
            &CheckUpdateRequest { apply: false },
        )
        .await
    }

    /// Approve the pending update.
    pub async fn approve_userscript_update(
        &self,
        id: &str,
        allow_connect_all: bool,
    ) -> Result<Userscript, ApiError> {
        self.post(
            &format!("/userscripts/{}/update/approve", id),
            &ApproveUpdateRequest { allow_connect_all },
        )
        .await
    }

    /// Discard the pending update.
    pub async fn discard_userscript_update(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/userscripts/{}/update", id)).await
    }

    /// Stored GM values of a script.
    pub async fn get_userscript_storage(
        &self,
        id: &str,
        q: &str,
        cursor: Option<&str>,
    ) -> Result<UserscriptStorageResponse, ApiError> {
        self.get(&format!(
            "/userscripts/{}/storage?limit=40&q={}{}",
            id,
            encode_component(q.trim()),
            super::admin::cur(cursor)
        ))
        .await
    }

    /// Clear all stored values of a script.
    pub async fn clear_userscript_storage(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/userscripts/{}/storage", id)).await
    }

    /// Delete one stored value.
    pub async fn delete_userscript_value(
        &self,
        id: &str,
        name: &str,
    ) -> Result<MessageResponse, ApiError> {
        self.delete(&format!(
            "/userscripts/{}/storage/{}",
            id,
            encode_component(name)
        ))
        .await
    }

    /// Export all scripts as a bundle.
    pub async fn export_userscripts(&self, values: bool) -> Result<UserscriptBundle, ApiError> {
        self.get(&format!("/userscripts/export?values={}", values))
            .await
    }

    /// Import a bundle.
    pub async fn import_userscripts(
        &self,
        bundle: &UserscriptBundle,
    ) -> Result<ImportUserscriptsResponse, ApiError> {
        self.post("/userscripts/import", bundle).await
    }
}

/// Percent-encode a path segment.
pub fn encode_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::encode_component;

    #[test]
    fn encodes_segments() {
        assert_eq!(encode_component("a b/c"), "a%20b%2Fc");
        assert_eq!(encode_component("ok-1_.~"), "ok-1_.~");
    }
}

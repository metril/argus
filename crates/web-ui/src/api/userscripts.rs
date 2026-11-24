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
        self.get(&script_path(id, "")).await
    }

    /// Get userscript source code
    pub async fn get_userscript_source(
        &self,
        id: &str,
    ) -> Result<UserscriptSourceResponse, ApiError> {
        self.get(&script_path(id, "/source")).await
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
        self.delete(&script_path(id, "")).await
    }

    /// Enable or disable a userscript
    pub async fn set_userscript_enabled(
        &self,
        id: &str,
        enabled: bool,
    ) -> Result<Userscript, ApiError> {
        let req = SetEnabledRequest { enabled };
        self.put(&script_path(id, "/enabled"), &req).await
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
            &script_path(id, "/check-update"),
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
            &script_path(id, "/update/approve"),
            &ApproveUpdateRequest { allow_connect_all },
        )
        .await
    }

    /// Approve an imported script: enable it and, when asked, allow its `@connect *`.
    pub async fn approve_userscript(
        &self,
        id: &str,
        allow_connect_all: bool,
    ) -> Result<Userscript, ApiError> {
        self.post(
            &script_path(id, "/approve"),
            &ApproveUpdateRequest { allow_connect_all },
        )
        .await
    }

    /// Discard the pending update.
    pub async fn discard_userscript_update(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&script_path(id, "/update")).await
    }

    /// Stored GM values of a script.
    pub async fn get_userscript_storage(
        &self,
        id: &str,
        q: &str,
        cursor: Option<&str>,
    ) -> Result<UserscriptStorageResponse, ApiError> {
        self.get(&format!(
            "{}?limit=40&q={}{}",
            script_path(id, "/storage"),
            encode_component(q.trim()),
            super::admin::cur(cursor)
        ))
        .await
    }

    /// Clear all stored values of a script.
    pub async fn clear_userscript_storage(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&script_path(id, "/storage")).await
    }

    /// Delete one stored value.
    pub async fn delete_userscript_value(
        &self,
        id: &str,
        name: &str,
    ) -> Result<MessageResponse, ApiError> {
        self.delete(&script_path(
            id,
            &format!("/storage/{}", encode_component(name)),
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

/// `/userscripts/<id><tail>` with the id percent-encoded as one path segment. Ids are
/// `<namespace>:<name>` and namespaces are often URLs, so a raw id would split the route.
pub fn script_path(id: &str, tail: &str) -> String {
    format!("/userscripts/{}{}", encode_component(id), tail)
}

/// Percent-encode a path segment (`encodeURIComponent` semantics: "/" becomes %2F).
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
    use super::{encode_component, script_path};

    const ID: &str =
        "https://greasyfork.org/en/users/1375891-wibu-elite:Universal Anti Adblock Popup Remover";

    #[test]
    fn script_paths_encode_the_id() {
        let p = script_path(ID, "/source");
        assert_eq!(
            p,
            "/userscripts/https%3A%2F%2Fgreasyfork.org%2Fen%2Fusers%2F1375891-wibu-elite%3AUniversal%20Anti%20Adblock%20Popup%20Remover/source"
        );
        assert_eq!(p.matches('/').count(), 3);
        assert_eq!(script_path("a:b", ""), "/userscripts/a%3Ab");
        assert_eq!(
            script_path(ID, &format!("/storage/{}", encode_component("k/1")))
                .matches("%2F")
                .count(),
            5 + 1
        );
    }

    #[test]
    fn encodes_segments() {
        assert_eq!(encode_component("a b/c"), "a%20b%2Fc");
        assert_eq!(encode_component("ok-1_.~"), "ok-1_.~");
    }
}

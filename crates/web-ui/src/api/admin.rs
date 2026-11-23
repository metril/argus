//! Admin-only listings: all sessions, all tokens, audit log.

use super::auth::{MessageResponse, SessionInfo};
use super::client::{ApiClient, ApiError};

pub use api_types::{ApiTokenInfo, AuditEntry, Page};

impl ApiClient {
    pub async fn admin_list_sessions(&self) -> Result<Page<SessionInfo>, ApiError> {
        self.get("/admin/sessions?limit=200").await
    }

    pub async fn admin_revoke_session(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/admin/sessions/{id}")).await
    }

    pub async fn admin_list_tokens(&self) -> Result<Page<ApiTokenInfo>, ApiError> {
        self.get("/admin/tokens?limit=200").await
    }

    pub async fn admin_revoke_token(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/admin/tokens/{id}")).await
    }

    /// Audit log, newest first. `outcome` is `success`, `denied` or `error` (or empty for all).
    pub async fn list_audit(
        &self,
        page: u32,
        outcome: &str,
        actor: &str,
        route: &str,
    ) -> Result<Page<AuditEntry>, ApiError> {
        let mut path = format!("/audit?limit=100&page={page}");
        for (k, v) in [("outcome", outcome), ("actor", actor), ("route", route)] {
            if !v.trim().is_empty() {
                path.push_str(&format!("&{k}={}", js_sys::encode_uri_component(v.trim())));
            }
        }
        self.get(&path).await
    }
}

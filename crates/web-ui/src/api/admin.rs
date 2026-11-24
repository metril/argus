//! Admin-only listings: all sessions, all tokens, audit log.

use super::auth::{MessageResponse, SessionInfo};
use super::client::{ApiClient, ApiError};

pub use api_types::{ApiTokenInfo, AuditEntry, Page};

/// `&cursor=...` query suffix.
pub fn cur(cursor: Option<&str>) -> String {
    cursor
        .map(|c| format!("&cursor={}", js_sys::encode_uri_component(c)))
        .unwrap_or_default()
}

impl ApiClient {
    /// One page (newest first) of every user's sessions.
    pub async fn admin_list_sessions(
        &self,
        cursor: Option<&str>,
    ) -> Result<Page<SessionInfo>, ApiError> {
        self.get(&format!("/admin/sessions?limit=40{}", cur(cursor)))
            .await
    }

    pub async fn admin_revoke_session(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/admin/sessions/{id}")).await
    }

    /// One page (newest first) of every user's API tokens.
    pub async fn admin_list_tokens(
        &self,
        cursor: Option<&str>,
    ) -> Result<Page<ApiTokenInfo>, ApiError> {
        self.get(&format!("/admin/tokens?limit=40{}", cur(cursor)))
            .await
    }

    pub async fn admin_revoke_token(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/admin/tokens/{id}")).await
    }

    /// Audit log, newest first, filtered on the server. `outcome` is `success`, `denied` or
    /// `error` (or empty for all); `since` is RFC 3339 or empty.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_audit(
        &self,
        cursor: Option<&str>,
        outcome: &str,
        actor: &str,
        action: &str,
        q: &str,
        since: &str,
    ) -> Result<Page<AuditEntry>, ApiError> {
        let mut path = format!("/audit?limit=60{}", cur(cursor));
        for (k, v) in [
            ("outcome", outcome),
            ("actor", actor),
            ("action", action),
            ("q", q),
            ("since", since),
        ] {
            if !v.trim().is_empty() {
                path.push_str(&format!("&{k}={}", js_sys::encode_uri_component(v.trim())));
            }
        }
        self.get(&path).await
    }
}

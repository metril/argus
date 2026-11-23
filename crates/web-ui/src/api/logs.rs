//! Request log snapshot (`/api/v1/logs/requests`); live updates come from the SSE stream.

use super::client::{ApiClient, ApiError};

pub use api_types::{LogAction, LogMode, RequestLogEntry, RequestLogResponse};

impl ApiClient {
    /// Newest-first snapshot used to seed the Logs page before the stream connects.
    pub async fn get_request_log(&self, limit: u32) -> Result<RequestLogResponse, ApiError> {
        self.get(&format!("/logs/requests?limit={limit}")).await
    }

    /// Append a line to the custom rules (used by the log drawer's allow/block actions).
    pub async fn append_custom_rule(&self, rule: &str) -> Result<(), ApiError> {
        let (cur, etag) = self.get_custom_rules().await?;
        if cur.rules.lines().any(|l| l.trim() == rule) {
            return Ok(());
        }
        let mut rules = cur.rules;
        if !rules.is_empty() && !rules.ends_with('\n') {
            rules.push('\n');
        }
        rules.push_str(rule);
        rules.push('\n');
        let etag = etag.ok_or_else(|| ApiError::Parse("missing ETag".into()))?;
        self.update_custom_rules(&rules, &etag).await.map(|_| ())
    }
}

impl ApiClient {
    /// Real upstream certificate recorded for a request (`cert_fp` on the log entry).
    /// `host` selects whose verification verdict is reported (the host the request went to).
    pub async fn get_cert(&self, fp: &str, host: &str) -> Result<api_types::CertInfo, ApiError> {
        if host.is_empty() {
            return self.get(&format!("/certs/{fp}")).await;
        }
        self.get(&format!("/certs/{fp}?host={host}")).await
    }
}

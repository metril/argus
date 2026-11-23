//! Proxy management API calls

use super::auth::MessageResponse;
use super::client::{ApiClient, ApiError};

// Wire DTOs come from the shared `api-types` crate (single source of truth).
pub use api_types::{
    ConnectionStats, MitmStats, ProxyConfigResponse, ProxyStatsResponse, RequestStats,
    UpdateProxyConfigRequest,
};

impl ApiClient {
    /// Get proxy configuration
    pub async fn get_proxy_config(&self) -> Result<ProxyConfigResponse, ApiError> {
        self.get("/config").await
    }

    /// Update proxy configuration (partial; omitted fields are left unchanged)
    pub async fn update_proxy_config(
        &self,
        config: &UpdateProxyConfigRequest,
    ) -> Result<ProxyConfigResponse, ApiError> {
        // The update is partial and guarded by `If-Match`; read the current version first.
        let (_, etag): (ProxyConfigResponse, _) = self.get_etag("/config").await?;
        let etag = etag.ok_or_else(|| ApiError::Parse("missing ETag".into()))?;
        let (updated, _) = self
            .put_if_match::<api_types::UpdateProxyConfigResponse, _>("/config", config, &etag)
            .await?;
        Ok(updated.config)
    }

    /// Partial config update returning the full response: the new config plus which fields
    /// `applied` live, which need a restart, and the per-listener bind outcome.
    pub async fn update_proxy_config_full(
        &self,
        config: &UpdateProxyConfigRequest,
    ) -> Result<api_types::UpdateProxyConfigResponse, ApiError> {
        let (_, etag): (ProxyConfigResponse, _) = self.get_etag("/config").await?;
        let etag = etag.ok_or_else(|| ApiError::Parse("missing ETag".into()))?;
        let (updated, _) = self
            .put_if_match::<api_types::UpdateProxyConfigResponse, _>("/config", config, &etag)
            .await?;
        Ok(updated)
    }

    /// Get proxy statistics
    pub async fn get_proxy_stats(&self) -> Result<ProxyStatsResponse, ApiError> {
        self.get("/stats/proxy").await
    }

    /// Reload proxy configuration from file
    pub async fn reload_proxy_config(&self) -> Result<MessageResponse, ApiError> {
        self.post("/config/reload", &()).await
    }
}

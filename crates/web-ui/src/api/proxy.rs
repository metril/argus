//! Proxy management API calls

use super::client::{ApiClient, ApiError};
use super::auth::MessageResponse;

// Wire DTOs come from the shared `api-types` crate (single source of truth).
pub use api_types::{
    ConnectionStats, MitmStats, ProxyConfigResponse, ProxyStatsResponse, RequestStats,
    UpdateProxyConfigRequest,
};

impl ApiClient {
    /// Get proxy configuration
    pub async fn get_proxy_config(&self) -> Result<ProxyConfigResponse, ApiError> {
        self.get("/api/proxy/config").await
    }

    /// Update proxy configuration (partial; omitted fields are left unchanged)
    pub async fn update_proxy_config(
        &self,
        config: &UpdateProxyConfigRequest,
    ) -> Result<ProxyConfigResponse, ApiError> {
        self.put("/api/proxy/config", config).await
    }

    /// Get proxy statistics
    pub async fn get_proxy_stats(&self) -> Result<ProxyStatsResponse, ApiError> {
        self.get("/api/proxy/stats").await
    }

    /// Reload proxy configuration from file
    pub async fn reload_proxy_config(&self) -> Result<MessageResponse, ApiError> {
        self.post("/api/proxy/reload-config", &()).await
    }
}

//! Proxy management API calls

use serde::{Deserialize, Serialize};

use super::client::{ApiClient, ApiError};
use super::auth::MessageResponse;

/// Proxy configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyConfig {
    pub port: u16,
    pub host: String,
    pub connection_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub max_connections: usize,
    pub enable_mitm: bool,
    pub enable_http2: bool,
}

/// Proxy configuration response (matches backend flat structure)
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfigResponse {
    pub host: String,
    pub port: u16,
    pub max_connections: u32,
    pub enable_http2: bool,
    pub enable_http3: bool,
    pub enable_websockets: bool,
    pub enable_mitm: bool,
    pub connection_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub enable_adblock: bool,
}

/// Connection statistics
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionStats {
    pub total: u64,
    pub active: u64,
}

/// Request statistics
#[derive(Debug, Clone, Deserialize)]
pub struct RequestStats {
    pub total: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub errors: u64,
}

/// MITM statistics
#[derive(Debug, Clone, Deserialize)]
pub struct MitmStats {
    pub cached_certificates: usize,
}

/// Proxy stats response (matches backend nested structure)
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyStatsResponse {
    pub connections: ConnectionStats,
    pub requests: RequestStats,
    pub mitm: Option<MitmStats>,
}

impl ApiClient {
    /// Get proxy configuration
    pub async fn get_proxy_config(&self) -> Result<ProxyConfigResponse, ApiError> {
        self.get("/api/proxy/config").await
    }

    /// Update proxy configuration
    pub async fn update_proxy_config(
        &self,
        config: &ProxyConfig,
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

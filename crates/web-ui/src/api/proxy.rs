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

/// Proxy statistics
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyStats {
    pub connections_total: u64,
    pub connections_active: u64,
    pub requests_total: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub uptime_seconds: u64,
}

/// Proxy stats response
#[derive(Debug, Deserialize)]
pub struct ProxyStatsResponse {
    pub stats: ProxyStats,
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

//! Proxy management handlers
//!
//! Provides endpoints for:
//! - GET /api/proxy/config - Get proxy configuration
//! - PUT /api/proxy/config - Update proxy configuration
//! - GET /api/proxy/stats - Get proxy statistics
//! - POST /api/proxy/reload-config - Reload configuration from file

use crate::auth::middleware::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::{extract::State, Extension, Json};
use proxy_core::config::ProxyConfig;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::info;
use utoipa::ToSchema;
use validator::Validate;

/// Proxy configuration response (sanitized, without sensitive paths)
#[derive(Debug, Serialize, ToSchema)]
pub struct ProxyConfigResponse {
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Enable HTTP/2
    pub enable_http2: bool,
    /// Enable HTTP/3
    pub enable_http3: bool,
    /// Enable WebSockets
    pub enable_websockets: bool,
    /// Enable MITM
    pub enable_mitm: bool,
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
    /// Enable adblock filtering
    pub enable_adblock: bool,
}

impl From<&ProxyConfig> for ProxyConfigResponse {
    fn from(config: &ProxyConfig) -> Self {
        Self {
            host: config.proxy.host.clone(),
            port: config.proxy.port,
            max_connections: config.proxy.max_connections as u32,
            enable_http2: config.proxy.enable_http2,
            enable_http3: config.proxy.enable_http3,
            enable_websockets: config.proxy.enable_websockets,
            enable_mitm: config.mitm.enabled,
            connection_timeout_secs: config.performance.connection_timeout_secs,
            request_timeout_secs: config.performance.request_timeout_secs,
            enable_adblock: config.adblock.enabled,
        }
    }
}

/// Proxy configuration update request
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateProxyConfigRequest {
    /// Server host
    #[validate(length(min = 1, max = 255))]
    pub host: Option<String>,

    /// Server port (1-65535)
    #[validate(range(min = 1, max = 65535))]
    pub port: Option<u16>,

    /// Maximum concurrent connections (1-100000)
    #[validate(range(min = 1, max = 100000))]
    pub max_connections: Option<u32>,

    /// Enable HTTP/2
    pub enable_http2: Option<bool>,

    /// Enable HTTP/3
    pub enable_http3: Option<bool>,

    /// Enable WebSockets
    pub enable_websockets: Option<bool>,

    /// Enable MITM
    pub enable_mitm: Option<bool>,

    /// Connection timeout in seconds (1-300)
    #[validate(range(min = 1, max = 300))]
    pub connection_timeout_secs: Option<u64>,

    /// Request timeout in seconds (1-600)
    #[validate(range(min = 1, max = 600))]
    pub request_timeout_secs: Option<u64>,

    /// Enable adblock filtering
    pub enable_adblock: Option<bool>,
}

/// Proxy statistics response
#[derive(Debug, Serialize)]
pub struct ProxyStatsResponse {
    /// Connection statistics
    pub connections: ConnectionStats,
    /// Request statistics
    pub requests: RequestStats,
    /// MITM statistics (if enabled)
    pub mitm: Option<MitmStats>,
}

#[derive(Debug, Serialize)]
pub struct ConnectionStats {
    pub total: u64,
    pub active: u64,
}

#[derive(Debug, Serialize)]
pub struct RequestStats {
    pub total: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub errors: u64,
}

#[derive(Debug, Serialize)]
pub struct MitmStats {
    pub cached_certificates: usize,
}

/// Get proxy configuration
///
/// GET /api/proxy/config
///
/// Returns sanitized proxy configuration (no sensitive paths).
pub async fn get_config(
    State(state): State<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
) -> ApiResult<Json<ProxyConfigResponse>> {
    let config = state.proxy_state.config.read();
    Ok(Json(ProxyConfigResponse::from(&*config)))
}

/// Update proxy configuration
///
/// PUT /api/proxy/config
///
/// Updates proxy configuration. Requires User or Admin role.
/// Note: Some changes may require a restart to take effect.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<UpdateProxyConfigRequest>,
) -> ApiResult<Json<ProxyConfigResponse>> {
    // Check authorization (User or Admin role required)
    if !auth_user.role().can_modify() {
        return Err(ApiError::AuthorizationFailed(
            "Requires user or admin role to modify proxy configuration".to_string(),
        ));
    }

    // Validate request
    req.validate()
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;

    // Update configuration and prepare response (all sync, in a block to release lock)
    let (config_str, config_path, response) = {
        let mut config = state.proxy_state.config.write();

        if let Some(host) = req.host {
            config.proxy.host = host;
        }

        if let Some(port) = req.port {
            config.proxy.port = port;
        }

        if let Some(max_connections) = req.max_connections {
            config.proxy.max_connections = max_connections as usize;
        }

        if let Some(enable_http2) = req.enable_http2 {
            config.proxy.enable_http2 = enable_http2;
        }

        if let Some(enable_http3) = req.enable_http3 {
            config.proxy.enable_http3 = enable_http3;
        }

        if let Some(enable_websockets) = req.enable_websockets {
            config.proxy.enable_websockets = enable_websockets;
        }

        if let Some(enable_mitm) = req.enable_mitm {
            config.mitm.enabled = enable_mitm;
        }

        if let Some(connection_timeout_secs) = req.connection_timeout_secs {
            config.performance.connection_timeout_secs = connection_timeout_secs;
        }

        if let Some(request_timeout_secs) = req.request_timeout_secs {
            config.performance.request_timeout_secs = request_timeout_secs;
        }

        if let Some(enable_adblock) = req.enable_adblock {
            config.adblock.enabled = enable_adblock;
        }

        let config_str =
            toml::to_string_pretty(&*config).map_err(|e| ApiError::Internal(e.to_string()))?;
        let config_path = state.config_path.read().clone();
        let response = ProxyConfigResponse::from(&*config);

        (config_str, config_path, response)
    }; // config lock released here

    info!(
        "Proxy configuration updated by user: {}",
        auth_user.username()
    );

    // Save configuration to file (async)
    tokio::fs::write(&config_path, config_str)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to save config: {}", e)))?;

    Ok(Json(response))
}

/// Get proxy statistics
///
/// GET /api/proxy/stats
///
/// Returns proxy runtime statistics.
pub async fn get_stats(
    State(state): State<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
) -> ApiResult<Json<ProxyStatsResponse>> {
    let stats = state.proxy_state.stats.snapshot();

    // Get MITM stats if available
    let mitm_stats = state.proxy_state.mitm_handler.as_ref().map(|_handler| {
        // TODO: Expose certificate cache count from MitmHandler
        MitmStats {
            cached_certificates: 0,
        }
    });

    Ok(Json(ProxyStatsResponse {
        connections: ConnectionStats {
            total: stats.connections_total,
            active: stats.connections_active,
        },
        requests: RequestStats {
            total: stats.requests_total,
            bytes_received: stats.bytes_received,
            bytes_sent: stats.bytes_sent,
            errors: stats.errors_total,
        },
        mitm: mitm_stats,
    }))
}

/// Reload proxy configuration from file
///
/// POST /api/proxy/reload-config
///
/// Reloads configuration from the config file. Requires Admin role.
pub async fn reload_config(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
) -> ApiResult<Json<Value>> {
    // Check authorization (Admin role required)
    if !auth_user.role().is_admin() {
        return Err(ApiError::AuthorizationFailed(
            "Requires admin role to reload configuration".to_string(),
        ));
    }

    let config_path = state.config_path.read().clone();

    // Read and parse config file
    let config_str = tokio::fs::read_to_string(&config_path)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to read config file: {}", e)))?;

    let new_config: ProxyConfig =
        toml::from_str(&config_str).map_err(|e| ApiError::Internal(format!("Invalid config: {}", e)))?;

    // Update configuration
    {
        let mut config = state.proxy_state.config.write();
        *config = new_config;
    }

    info!(
        "Proxy configuration reloaded by admin: {}",
        auth_user.username()
    );

    Ok(Json(json!({ "message": "Configuration reloaded successfully" })))
}

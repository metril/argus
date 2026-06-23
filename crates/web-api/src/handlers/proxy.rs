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
use common::config::ProxyConfig;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tracing::info;
use validator::Validate;

// Wire-facing DTOs live in the shared `api-types` crate.
pub use api_types::{
    ConnectionStats, MitmStats, ProxyConfigResponse, ProxyStatsResponse, RequestStats,
    UpdateProxyConfigRequest,
};

/// Build the sanitized config response (no sensitive paths) from the full config.
fn proxy_config_response(config: &ProxyConfig) -> ProxyConfigResponse {
    ProxyConfigResponse {
        host: config.proxy.host.clone(),
        port: config.proxy.port,
        max_connections: config.performance.max_connections as u32,
        enable_http2: config.proxy.enable_http2,
        enable_http3: config.proxy.enable_http3,
        enable_websockets: config.proxy.enable_websockets,
        enable_mitm: config.mitm.enabled,
        connection_timeout_secs: config.performance.connection_timeout_secs,
        request_timeout_secs: config.performance.request_timeout_secs,
        enable_adblock: config.adblock.enabled,
    }
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
    Ok(Json(proxy_config_response(&config)))
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
            config.performance.max_connections = max_connections as usize;
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
        let response = proxy_config_response(&config);

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

    // Get MITM stats if enabled
    let mitm_stats = if state.proxy_state.mitm_enabled {
        Some(MitmStats {
            cached_certificates: state.proxy_state.mitm_cached_certs.load(Ordering::Relaxed) as usize,
        })
    } else {
        None
    };

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

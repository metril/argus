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
use std::time::Duration;
use tracing::info;
use validator::Validate;

// Wire-facing DTOs live in the shared `api-types` crate.
pub use api_types::{
    ConnectionStats, MitmStats, ProxyConfigResponse, ProxyStatsResponse, RequestStats,
    UpdateProxyConfigRequest, UpdateProxyConfigResponse,
};

/// Build the sanitized config response (no sensitive paths) from the full config.
fn proxy_config_response(config: &ProxyConfig) -> ProxyConfigResponse {
    ProxyConfigResponse {
        host: config.proxy.host.clone(),
        port: config.proxy.port,
        max_connections: config.performance.max_connections as u32,
        enable_http2: config.proxy.enable_http2,
        enable_websockets: config.proxy.enable_websockets,
        enable_mitm: config.mitm.enabled,
        connection_timeout_secs: config.performance.connection_timeout_secs,
        request_timeout_secs: config.performance.request_timeout_secs,
        enable_adblock: config.adblock.enabled,
        auto_update: config.adblock.auto_update,
        update_interval_hours: config.adblock.update_interval_hours,
    }
}

/// Push the settings that can change at runtime into the running proxy.
fn apply_live(state: &AppState, config: &ProxyConfig) {
    state.shared_engine.set_enabled(config.adblock.enabled);
    state.proxy_state.request_timeout_ms.store(
        config.performance.request_timeout_secs.saturating_mul(1000),
        Ordering::Relaxed,
    );
    state.list_service.set_schedule(
        config.adblock.auto_update,
        Duration::from_secs(config.adblock.update_interval_hours.max(1) * 3600),
    );
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
/// Updates proxy configuration. Requires User or Admin role. The response lists which fields took
/// effect immediately (`applied`: adblock on/off, request timeout, list auto-update schedule) and
/// which were only saved (`restart_required`: ports, MITM/CA, protocol toggles, limits).
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<UpdateProxyConfigRequest>,
) -> ApiResult<Json<UpdateProxyConfigResponse>> {
    // Check authorization (User or Admin role required)
    if !auth_user.role().can_modify() {
        return Err(ApiError::AuthorizationFailed(
            "Requires user or admin role to modify proxy configuration".to_string(),
        ));
    }

    // Validate request
    req.validate()
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;

    // Update the in-memory config and note what changed (sync, lock released before any await).
    let mut applied: Vec<String> = Vec::new();
    let mut restart_required: Vec<String> = Vec::new();
    let (config_str, config_path, response, new_config) = {
        let mut config = state.proxy_state.config.write();

        // Needs a restart: only reported when the value actually changes.
        macro_rules! restart_field {
            ($name:literal, $slot:expr, $val:expr) => {
                if let Some(v) = $val {
                    if $slot != v {
                        $slot = v;
                        restart_required.push($name.to_string());
                    }
                }
            };
        }
        restart_field!("host", config.proxy.host, req.host);
        restart_field!("port", config.proxy.port, req.port);
        restart_field!(
            "max_connections",
            config.performance.max_connections,
            req.max_connections.map(|v| v as usize)
        );
        restart_field!("enable_http2", config.proxy.enable_http2, req.enable_http2);
        restart_field!(
            "enable_websockets",
            config.proxy.enable_websockets,
            req.enable_websockets
        );
        restart_field!("enable_mitm", config.mitm.enabled, req.enable_mitm);
        restart_field!(
            "connection_timeout_secs",
            config.performance.connection_timeout_secs,
            req.connection_timeout_secs
        );

        // Live: applied to the running proxy below, after the file is saved.
        if let Some(v) = req.request_timeout_secs {
            config.performance.request_timeout_secs = v;
            applied.push("request_timeout_secs".into());
        }
        if let Some(v) = req.enable_adblock {
            config.adblock.enabled = v;
            applied.push("enable_adblock".into());
        }
        if let Some(v) = req.auto_update {
            config.adblock.auto_update = v;
            applied.push("auto_update".into());
        }
        if let Some(v) = req.update_interval_hours {
            config.adblock.update_interval_hours = v;
            applied.push("update_interval_hours".into());
        }

        let config_str =
            toml::to_string_pretty(&*config).map_err(|e| ApiError::Internal(e.to_string()))?;
        let config_path = state.config_path.read().clone();
        let response = proxy_config_response(&config);

        (config_str, config_path, response, config.clone())
    }; // config lock released here

    info!(
        "Proxy configuration updated by user: {}",
        auth_user.username()
    );

    // Save configuration to file (async)
    tokio::fs::write(&config_path, config_str)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to save config: {}", e)))?;

    apply_live(&state, &new_config);

    Ok(Json(UpdateProxyConfigResponse {
        config: response,
        applied,
        restart_required,
    }))
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
            cached_certificates: state.proxy_state.mitm_cached_certs.load(Ordering::Relaxed)
                as usize,
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

    let new_config: ProxyConfig = toml::from_str(&config_str)
        .map_err(|e| ApiError::Internal(format!("Invalid config: {}", e)))?;

    // Update configuration
    apply_live(&state, &new_config);
    {
        let mut config = state.proxy_state.config.write();
        *config = new_config;
    }

    info!(
        "Proxy configuration reloaded by admin: {}",
        auth_user.username()
    );

    Ok(Json(
        json!({ "message": "Configuration reloaded successfully" }),
    ))
}

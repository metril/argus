//! Proxy configuration handlers: read, update (with `ETag`/`If-Match`) and reload from file.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use api_types::{
    MessageResponse, ProxyConfigResponse, UpdateProxyConfigRequest, UpdateProxyConfigResponse,
};
use axum::{
    extract::State,
    http::{header::ETAG, HeaderMap},
    Extension, Json,
};
use common::config::ProxyConfig;
use tracing::info;
use validator::Validate;

use super::{check_if_match, etag_of};
use crate::auth::authz::Principal;
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::state::AppState;

pub fn proxy_config_response(config: &ProxyConfig) -> ProxyConfigResponse {
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
        transparent_port: config.proxy.transparent_port,
        tls_passthrough_hosts: config.proxy.tls_passthrough_hosts.clone(),
        block_private_destinations: config.proxy.block_private_destinations,
        allowed_destinations: config.proxy.allowed_destinations.clone(),
        allowed_clients: config.proxy.allowed_clients.clone(),
    }
}

fn config_etag(r: &ProxyConfigResponse) -> String {
    etag_of(&serde_json::to_vec(r).unwrap_or_default())
}

fn valid_cidr(s: &str) -> bool {
    let (addr, prefix) = match s.trim().split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s.trim(), None),
    };
    let max = match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => 32,
        Ok(std::net::IpAddr::V6(_)) => 128,
        Err(_) => return false,
    };
    prefix.is_none_or(|p| p.parse::<u8>().is_ok_and(|n| n <= max))
}

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

/// The proxy configuration. The `ETag` header must be echoed in `If-Match` when updating.
#[utoipa::path(
    get, path = "/config", tag = "config",
    security(("bearer_auth" = ["config:read"])),
    responses((status = 200, description = "Configuration (with ETag header)", body = ProxyConfigResponse))
)]
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> ApiResult<(
    [(axum::http::HeaderName, String); 1],
    Json<ProxyConfigResponse>,
)> {
    let r = proxy_config_response(&state.proxy_state.config.read());
    Ok(([(ETAG, config_etag(&r))], Json(r)))
}

/// Apply a partial update: validate, mutate, persist to the config file and apply live settings.
/// `applied` lists settings in effect now; `restart_required` those needing a restart.
pub async fn apply_update(
    state: &AppState,
    req: UpdateProxyConfigRequest,
    who: &str,
) -> ApiResult<UpdateProxyConfigResponse> {
    req.validate()?;
    for (name, list) in [
        ("allowed_destinations", &req.allowed_destinations),
        ("allowed_clients", &req.allowed_clients),
    ] {
        if let Some(bad) = list.iter().flatten().find(|c| !valid_cidr(c)) {
            return Err(ApiError::ValidationError(format!(
                "{name}: invalid CIDR {bad:?}"
            )));
        }
    }

    let mut applied: Vec<String> = Vec::new();
    let mut restart_required: Vec<String> = Vec::new();
    let (config_str, config_path, response, new_config) = {
        let mut config = state.proxy_state.config.write();

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
            "transparent_port",
            config.proxy.transparent_port,
            req.transparent_port.map(|p| (p != 0).then_some(p))
        );
        restart_field!(
            "tls_passthrough_hosts",
            config.proxy.tls_passthrough_hosts,
            req.tls_passthrough_hosts
        );
        restart_field!(
            "block_private_destinations",
            config.proxy.block_private_destinations,
            req.block_private_destinations
        );
        restart_field!(
            "allowed_destinations",
            config.proxy.allowed_destinations,
            req.allowed_destinations
        );
        restart_field!(
            "allowed_clients",
            config.proxy.allowed_clients,
            req.allowed_clients
        );
        restart_field!(
            "connection_timeout_secs",
            config.performance.connection_timeout_secs,
            req.connection_timeout_secs
        );

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
        (
            config_str,
            config_path,
            proxy_config_response(&config),
            config.clone(),
        )
    };

    info!("Proxy configuration updated by {who}");
    tokio::fs::write(&config_path, config_str)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to save config: {e}")))?;
    apply_live(state, &new_config);

    Ok(UpdateProxyConfigResponse {
        config: response,
        applied,
        restart_required,
    })
}

/// Update the configuration (partial). Requires `If-Match` (428 if absent, 412 if the
/// configuration changed since it was read).
#[utoipa::path(
    put, path = "/config", tag = "config",
    security(("bearer_auth" = ["config:write"])),
    params(("If-Match" = String, Header, description = "ETag from the last GET")),
    request_body = UpdateProxyConfigRequest,
    responses(
        (status = 200, description = "Updated (with new ETag header)", body = UpdateProxyConfigResponse),
        (status = 412, description = "Configuration changed since it was read"),
        (status = 428, description = "If-Match missing"),
    )
)]
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    headers: HeaderMap,
    ApiJson(req): ApiJson<UpdateProxyConfigRequest>,
) -> ApiResult<(
    [(axum::http::HeaderName, String); 1],
    Json<UpdateProxyConfigResponse>,
)> {
    let current = config_etag(&proxy_config_response(&state.proxy_state.config.read()));
    check_if_match(&headers, &current)?;
    let r = apply_update(&state, req, &p.username).await?;
    Ok(([(ETAG, config_etag(&r.config))], Json(r)))
}

/// Reload the configuration from its file.
#[utoipa::path(
    post, path = "/config/reload", tag = "config",
    security(("bearer_auth" = ["config:write"])),
    responses((status = 200, description = "Reloaded", body = MessageResponse))
)]
pub async fn reload_config(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Json<MessageResponse>> {
    let config_path = state.config_path.read().clone();
    let config_str = tokio::fs::read_to_string(&config_path)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to read config file: {e}")))?;
    let new_config: ProxyConfig = toml::from_str(&config_str)
        .map_err(|e| ApiError::ValidationError(format!("Invalid config file: {e}")))?;
    apply_live(&state, &new_config);
    *state.proxy_state.config.write() = new_config;
    info!("Proxy configuration reloaded by {}", p.username);
    Ok(Json(MessageResponse {
        message: "Configuration reloaded successfully".into(),
    }))
}

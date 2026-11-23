//! Proxy configuration handlers: read, update (with `ETag`/`If-Match`) and reload from file.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use api_types::{
    BindResult, DnsDto, ListenerFlagsView, MessageResponse, ProxyConfigResponse,
    UpdateProxyConfigRequest, UpdateProxyConfigResponse,
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
        // 0 means auto: report the effective derived limit, not the sentinel.
        max_connections: match config.performance.max_connections {
            0 => common::config::derive_max_connections() as u32,
            n => n as u32,
        },
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
        dns: DnsDto {
            servers: config.dns.servers.clone(),
            cache_size: config.dns.cache_size,
            min_ttl_secs: config.dns.min_ttl_secs,
            max_ttl_secs: config.dns.max_ttl_secs,
            negative_ttl_secs: config.dns.negative_ttl_secs,
        },
        explicit: flags_view(config, false),
        transparent: flags_view(config, true),
        webui_host: config.webui.host.clone(),
        webui_port: config.webui.port,
        bind: None,
    }
}

fn flags_view(config: &ProxyConfig, transparent: bool) -> ListenerFlagsView {
    let f = config.listener_flags(transparent);
    ListenerFlagsView {
        enable_mitm: f.mitm,
        enable_http2: f.http2,
        enable_websockets: f.websockets,
        enable_adblock: f.adblock,
    }
}

/// The ETag covers the configuration only, not where the sockets happen to be bound.
fn config_etag(r: &ProxyConfigResponse) -> String {
    let mut r = r.clone();
    r.bind = None;
    etag_of(&serde_json::to_vec(&r).unwrap_or_default())
}

fn fmt_addr(a: std::net::SocketAddr) -> String {
    a.to_string()
}

/// Actual listener addresses (`None` without a running proxy).
pub async fn bind_result(state: &AppState) -> Option<BindResult> {
    let rt = state.runtime.get()?;
    let b = rt.proxy_bind().await?;
    let (webui, webui_down, webui_moved_to, webui_error) = match state.web_server.get() {
        Some(w) => {
            let addr = w.addr().await;
            let moved = w.moved_from().await.map(|_| fmt_addr(addr));
            (
                Some(fmt_addr(addr)),
                w.is_down().await,
                moved,
                w.startup_error().await,
            )
        }
        None => (None, false, None, None),
    };
    Some(BindResult {
        proxy: Some(fmt_addr(b.proxy)),
        transparent: b.transparent.map(fmt_addr),
        proxy_down: b.proxy_down,
        transparent_down: b.transparent_down,
        webui_down,
        webui,
        webui_moved_to,
        webui_error,
        proxy_error: b.proxy_error,
        transparent_error: b.transparent_error,
    })
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
    // Master switch; each listener additionally gates on its own `enable_adblock`.
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
    let mut r = proxy_config_response(&state.proxy_state.config.read());
    let etag = config_etag(&r);
    r.bind = bind_result(&state).await;
    Ok(([(ETAG, etag)], Json(r)))
}

/// Apply a partial update: validate, move listeners and apply access lists live, persist the
/// changes to the settings overlay and apply live settings. `applied` lists settings in effect
/// now; `restart_required` those needing a restart.
pub async fn apply_update(
    state: &AppState,
    req: UpdateProxyConfigRequest,
    who: &str,
) -> ApiResult<UpdateProxyConfigResponse> {
    let _g = state.config_lock.lock().await;
    apply_update_locked(state, req, who).await
}

/// [`apply_update`] for a caller that already holds `state.config_lock`.
async fn apply_update_locked(
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
    for (name, h) in [("host", &req.host), ("webui_host", &req.webui_host)] {
        if let Some(h) = h {
            let h = h.trim().trim_matches(['[', ']']);
            if h.parse::<std::net::IpAddr>().is_err() && !h.eq_ignore_ascii_case("localhost") {
                return Err(ApiError::ValidationError(format!(
                    "{name}: {h:?} is not an IP address"
                )));
            }
        }
    }

    let mut applied: Vec<String> = Vec::new();
    let mut restart_required: Vec<String> = Vec::new();
    let runtime = state.runtime.get().cloned();
    let web = state.web_server.get().cloned();
    // Work on a copy: nothing is committed until every fallible step has succeeded.
    let old = state.proxy_state.config.read().clone();
    let mut config = old.clone();
    // Fields that are live when a running proxy / web server can apply them.
    let mut live = |name: &str, changed: bool, can: bool, applied: &mut Vec<String>| {
        if changed {
            if can {
                applied.push(name.to_string());
            } else {
                restart_required.push(name.to_string());
            }
        }
    };
    macro_rules! field {
        ($name:literal, $slot:expr, $val:expr, $can:expr) => {
            if let Some(v) = $val {
                let changed = $slot != v;
                $slot = v;
                live($name, changed, $can, &mut applied);
            }
        };
    }
    let can_proxy = runtime.is_some();
    let can_web = web.is_some();
    field!(
        "host",
        config.proxy.host,
        req.host.map(|h| h.trim().to_string()),
        can_proxy
    );
    field!("port", config.proxy.port, req.port, can_proxy);
    field!(
        "transparent_port",
        config.proxy.transparent_port,
        req.transparent_port.map(|p| (p != 0).then_some(p)),
        can_proxy
    );
    field!(
        "tls_passthrough_hosts",
        config.proxy.tls_passthrough_hosts,
        req.tls_passthrough_hosts,
        can_proxy
    );
    field!(
        "block_private_destinations",
        config.proxy.block_private_destinations,
        req.block_private_destinations,
        can_proxy
    );
    field!(
        "allowed_destinations",
        config.proxy.allowed_destinations,
        req.allowed_destinations,
        can_proxy
    );
    field!(
        "allowed_clients",
        config.proxy.allowed_clients,
        req.allowed_clients,
        can_proxy
    );
    field!(
        "webui_host",
        config.webui.host,
        req.webui_host.map(|h| h.trim().to_string()),
        can_web
    );
    field!("webui_port", config.webui.port, req.webui_port, can_web);
    field!(
        "max_connections",
        config.performance.max_connections,
        // The UI echoes the effective value back; keep "auto" (0) if it is unchanged.
        req.max_connections.map(|v| {
            let v = v as usize;
            if config.performance.max_connections == 0
                && v == common::config::derive_max_connections()
            {
                0
            } else {
                v
            }
        }),
        can_proxy
    );
    field!(
        "enable_http2",
        config.proxy.enable_http2,
        req.enable_http2,
        can_proxy
    );
    field!(
        "enable_websockets",
        config.proxy.enable_websockets,
        req.enable_websockets,
        can_proxy
    );
    field!(
        "enable_mitm",
        config.mitm.enabled,
        req.enable_mitm,
        can_proxy
    );
    if let Some(d) = req.dns {
        let before = config.dns.clone();
        if let Some(v) = d.servers {
            config.dns.servers = v.into_iter().map(|s| s.trim().to_string()).collect();
        }
        if let Some(v) = d.cache_size {
            config.dns.cache_size = v;
        }
        if let Some(v) = d.min_ttl_secs {
            config.dns.min_ttl_secs = v;
        }
        if let Some(v) = d.max_ttl_secs {
            config.dns.max_ttl_secs = v;
        }
        if let Some(v) = d.negative_ttl_secs {
            config.dns.negative_ttl_secs = v;
        }
        config.dns.validate().map_err(ApiError::ValidationError)?;
        let changed = format!("{before:?}") != format!("{:?}", config.dns);
        live("dns", changed, can_proxy, &mut applied);
    }
    // Per-listener switches: each writes that listener's own override.
    for (name, transparent, upd) in [
        ("explicit", false, req.explicit),
        ("transparent", true, req.transparent),
    ] {
        let Some(u) = upd else { continue };
        let before = config.listener_flags(transparent);
        let o = if transparent {
            &mut config.proxy.transparent
        } else {
            &mut config.proxy.explicit
        };
        for (key, cur, new, slot) in [
            (
                "enable_mitm",
                before.mitm,
                u.enable_mitm,
                &mut o.enable_mitm,
            ),
            (
                "enable_http2",
                before.http2,
                u.enable_http2,
                &mut o.enable_http2,
            ),
            (
                "enable_websockets",
                before.websockets,
                u.enable_websockets,
                &mut o.enable_websockets,
            ),
            (
                "enable_adblock",
                before.adblock,
                u.enable_adblock,
                &mut o.enable_adblock,
            ),
        ] {
            if let Some(v) = new {
                *slot = Some(v);
                live(&format!("{name}.{key}"), cur != v, can_proxy, &mut applied);
            }
        }
    }
    field!(
        "connection_timeout_secs",
        config.performance.connection_timeout_secs,
        req.connection_timeout_secs,
        can_proxy
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

    let moved_to = apply_runtime(state, &old, &config).await?;

    let overlay_path = state.overlay_path.read().clone();
    let base_path = state.config_path.read().clone();
    let c2 = config.clone();
    let save = tokio::task::spawn_blocking(move || c2.save_overlay(&base_path, &overlay_path))
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    if let Err(e) = save {
        // Put the listeners back: the change was not saved. The old web listener is still up
        // (its stop is only pending), so it is reinstated rather than bound again.
        if let Some(web) = state.web_server.get() {
            if (old.webui.host.as_str(), old.webui.port)
                != (config.webui.host.as_str(), config.webui.port)
                && web.revert().await.is_none()
            {
                let _ = web.rebind(&old.webui.host, old.webui.port).await;
            }
        }
        if let Some(rt) = state.runtime.get() {
            if (&old.proxy.host, old.proxy.port, old.proxy.transparent_port)
                != (
                    &config.proxy.host,
                    config.proxy.port,
                    config.proxy.transparent_port,
                )
            {
                let _ = rt
                    .rebind_proxy(&old.proxy.host, old.proxy.port, old.proxy.transparent_port)
                    .await;
            }
            let _ = rt.apply_access(&old).await;
        }
        return Err(ApiError::Internal(format!("Failed to save settings: {e}")));
    }

    info!("Proxy configuration updated by {who}");
    apply_live(state, &config);
    let mut response = proxy_config_response(&config);
    *state.proxy_state.config.write() = config;
    response.bind = bind_result(state).await;
    if let (Some(b), Some(m)) = (response.bind.as_mut(), moved_to) {
        b.webui_moved_to = Some(m);
    }

    Ok(UpdateProxyConfigResponse {
        config: response,
        applied,
        restart_required,
    })
}

/// Make the running proxy and web server match `new` (relative to `old`): rebind moved
/// listeners and swap access lists. Returns the web API's new address when it moved. On failure
/// everything is back as it was and the error names the reason (409).
async fn apply_runtime(
    state: &AppState,
    old: &ProxyConfig,
    new: &ProxyConfig,
) -> ApiResult<Option<String>> {
    let bind_err = |m: String| ApiError::Coded {
        status: axum::http::StatusCode::CONFLICT,
        code: "bind_failed",
        message: m,
    };
    let mut proxy_moved = false;
    if let Some(rt) = state.runtime.get() {
        let listeners_changed = old.proxy.host != new.proxy.host
            || old.proxy.port != new.proxy.port
            || old.proxy.transparent_port != new.proxy.transparent_port;
        let down = rt
            .proxy_bind()
            .await
            .is_some_and(|b| b.proxy_down || b.transparent_down);
        if listeners_changed || down {
            rt.rebind_proxy(&new.proxy.host, new.proxy.port, new.proxy.transparent_port)
                .await
                .map_err(&bind_err)?;
            proxy_moved = true;
        }
        match rt.apply_access(new).await {
            Ok(()) => {}
            Err(e) => {
                if proxy_moved {
                    let _ = rt
                        .rebind_proxy(&old.proxy.host, old.proxy.port, old.proxy.transparent_port)
                        .await;
                }
                return Err(ApiError::ValidationError(e));
            }
        }
    }
    let mut moved_to = None;
    if let Some(web) = state.web_server.get() {
        if old.webui.host != new.webui.host
            || old.webui.port != new.webui.port
            || web.is_down().await
            || web.moved_from().await.is_some()
        {
            match web.rebind(&new.webui.host, new.webui.port).await {
                Ok(addr) => {
                    moved_to = Some(addr.to_string());
                    if let Some(rt) = state.runtime.get() {
                        rt.note_webui(&new.webui.host, new.webui.port).await;
                    }
                }
                Err(e) => {
                    if let Some(rt) = state.runtime.get() {
                        // Undo the proxy side, then the access lists.
                        if proxy_moved {
                            let _ = rt
                                .rebind_proxy(
                                    &old.proxy.host,
                                    old.proxy.port,
                                    old.proxy.transparent_port,
                                )
                                .await;
                        }
                        let _ = rt.apply_access(old).await;
                    }
                    return Err(bind_err(e));
                }
            }
        }
    }
    Ok(moved_to)
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
    // One writer at a time from the ETag check through save and commit.
    let _g = state.config_lock.lock().await;
    let current = config_etag(&proxy_config_response(&state.proxy_state.config.read()));
    check_if_match(&headers, &current)?;
    let r = apply_update_locked(&state, req, &p.username).await?;
    Ok(([(ETAG, config_etag(&r.config))], Json(r)))
}

/// The built-in default of every setting, in the shape of `GET /config` (what "reset to
/// default" in the UI restores). The shipped `config/default.toml` and the settings overlay are
/// not consulted.
#[utoipa::path(
    get, path = "/config/defaults", tag = "config",
    security(("bearer_auth" = ["config:read"])),
    responses((status = 200, description = "Built-in defaults", body = ProxyConfigResponse))
)]
pub async fn get_config_defaults() -> Json<ProxyConfigResponse> {
    Json(proxy_config_response(&ProxyConfig::default()))
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
    let _g = state.config_lock.lock().await;
    let base = state.config_path.read().clone();
    let overlay = state.overlay_path.read().clone();
    let new_config =
        tokio::task::spawn_blocking(move || ProxyConfig::load_layered(&base, &overlay))
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .map_err(|e| ApiError::ValidationError(format!("Invalid config: {e}")))?;
    let old = state.proxy_state.config.read().clone();
    apply_runtime(&state, &old, &new_config).await?;
    apply_live(&state, &new_config);
    *state.proxy_state.config.write() = new_config;
    info!("Proxy configuration reloaded by {}", p.username);
    Ok(Json(MessageResponse {
        message: "Configuration reloaded successfully".into(),
    }))
}

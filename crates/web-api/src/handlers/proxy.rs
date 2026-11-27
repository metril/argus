//! Proxy configuration handlers: read, update (with `ETag`/`If-Match`) and reload from file.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use api_types::{
    BindResult, DnsDto, ListenerFlagsView, MessageResponse, ProxyConfigResponse,
    UpdateProxyConfigRequest, UpdateProxyConfigResponse, UpstreamProxyDto, UpstreamProxyTestResult,
    UpstreamProxyUpdate,
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
        ext_port: config.proxy.ext_port,
        block_response: config.proxy.block_response.as_str().to_string(),
        tls_passthrough_hosts: config.proxy.tls_passthrough_hosts.clone(),
        block_private_destinations: config.proxy.block_private_destinations,
        browser_like_upstream: config.proxy.upstream.browser_like,
        guard_service_workers: config.adblock.guard_service_workers,
        guard_service_workers_exempt: config.adblock.guard_service_workers_exempt.clone(),
        upstream_proxy: upstream_proxy_dto(&config.proxy.upstream.proxy),
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
        bypass: api_types::BypassSourceDto {
            lists_base_url: config.bypass.lists_base_url.clone(),
            lists_public_key: config.bypass.lists_public_key.clone(),
        },
        stealth: stealth_dto(&config.stealth),
        request_log_capacity: config.adblock.request_log_capacity as u32,
        bind: None,
    }
}

fn stealth_dto(s: &common::config::StealthSettings) -> api_types::StealthDto {
    api_types::StealthDto {
        enabled: s.enabled,
        hide_search_queries: s.hide_search_queries,
        send_dnt: s.send_dnt,
        strip_tracking_params: s.strip_tracking_params,
        hide_referer: s.hide_referer,
        referer_custom: s.referer_custom.clone(),
        hide_user_agent: s.hide_user_agent,
        user_agent_custom: s.user_agent_custom.clone(),
        mask_ip: s.mask_ip,
        mask_ip_address: s.mask_ip_address.clone(),
        remove_x_client_data: s.remove_x_client_data,
        third_party_cookies: s.third_party_cookies,
        third_party_cookie_minutes: s.third_party_cookie_minutes,
        first_party_cookies: s.first_party_cookies,
        first_party_cookie_minutes: s.first_party_cookie_minutes,
        block_etag: s.block_etag,
        block_third_party_auth: s.block_third_party_auth,
        block_webrtc: s.block_webrtc,
        block_push: s.block_push,
        block_location: s.block_location,
        block_flash: s.block_flash,
        block_java: s.block_java,
    }
}

/// Merge an update into the settings; the result is validated by the caller.
fn merge_stealth(s: &mut common::config::StealthSettings, u: api_types::StealthUpdate) {
    if let Some(v) = u.enabled {
        s.enabled = v;
    }
    if let Some(v) = u.hide_search_queries {
        s.hide_search_queries = v;
    }
    if let Some(v) = u.send_dnt {
        s.send_dnt = v;
    }
    if let Some(v) = u.strip_tracking_params {
        s.strip_tracking_params = v;
    }
    if let Some(v) = u.hide_referer {
        s.hide_referer = v;
    }
    if let Some(v) = u.referer_custom {
        s.referer_custom = v;
    }
    if let Some(v) = u.hide_user_agent {
        s.hide_user_agent = v;
    }
    if let Some(v) = u.user_agent_custom {
        s.user_agent_custom = v;
    }
    if let Some(v) = u.mask_ip {
        s.mask_ip = v;
    }
    if let Some(v) = u.mask_ip_address {
        s.mask_ip_address = v;
    }
    if let Some(v) = u.remove_x_client_data {
        s.remove_x_client_data = v;
    }
    if let Some(v) = u.third_party_cookies {
        s.third_party_cookies = v;
    }
    if let Some(v) = u.third_party_cookie_minutes {
        s.third_party_cookie_minutes = v;
    }
    if let Some(v) = u.first_party_cookies {
        s.first_party_cookies = v;
    }
    if let Some(v) = u.first_party_cookie_minutes {
        s.first_party_cookie_minutes = v;
    }
    if let Some(v) = u.block_etag {
        s.block_etag = v;
    }
    if let Some(v) = u.block_third_party_auth {
        s.block_third_party_auth = v;
    }
    if let Some(v) = u.block_webrtc {
        s.block_webrtc = v;
    }
    if let Some(v) = u.block_push {
        s.block_push = v;
    }
    if let Some(v) = u.block_location {
        s.block_location = v;
    }
    if let Some(v) = u.block_flash {
        s.block_flash = v;
    }
    if let Some(v) = u.block_java {
        s.block_java = v;
    }
}

fn kind_dto(k: common::config::UpstreamProxyKind) -> api_types::UpstreamProxyKind {
    match k {
        common::config::UpstreamProxyKind::Http => api_types::UpstreamProxyKind::Http,
        common::config::UpstreamProxyKind::Socks5 => api_types::UpstreamProxyKind::Socks5,
    }
}

/// The upstream proxy for the API: the password is reported as `set` / `unset`, never its value.
fn upstream_proxy_dto(p: &common::config::UpstreamProxy) -> UpstreamProxyDto {
    UpstreamProxyDto {
        enabled: p.enabled,
        kind: kind_dto(p.kind),
        host: p.host.clone(),
        port: p.port,
        username: p.username.clone(),
        password: if p.password.is_empty() {
            "unset"
        } else {
            "set"
        }
        .into(),
    }
}

/// `cur` with the fields `u` sets. The saved username and password are reused only while the
/// type, host and port are the saved ones: sent to another address they would reach whoever
/// runs it, so then they must be supplied again. An empty password keeps the saved one; an
/// emptied username drops the password with it.
fn merge_upstream_proxy(
    cur: &common::config::UpstreamProxy,
    u: &UpstreamProxyUpdate,
) -> common::config::UpstreamProxy {
    let mut n = cur.clone();
    if let Some(v) = u.enabled {
        n.enabled = v;
    }
    if let Some(k) = u.kind {
        n.kind = match k {
            api_types::UpstreamProxyKind::Http => common::config::UpstreamProxyKind::Http,
            api_types::UpstreamProxyKind::Socks5 => common::config::UpstreamProxyKind::Socks5,
        };
    }
    if let Some(h) = &u.host {
        n.host = h.trim().to_string();
    }
    if let Some(p) = u.port {
        n.port = p;
    }
    if n.kind != cur.kind || n.host != cur.host || n.port != cur.port {
        n.username.clear();
        n.password.clear();
    }
    if let Some(name) = &u.username {
        n.username = name.trim().to_string();
        if n.username.is_empty() {
            n.password.clear();
        }
    }
    if let Some(p) = u.password.as_ref().filter(|p| !p.is_empty()) {
        n.password = p.clone();
    }
    n
}

/// Whether the upstream proxy points at one of Argus's own listeners (known from the settings
/// alone; the running proxy also checks the machine's real addresses).
fn upstream_proxy_is_own(config: &ProxyConfig) -> bool {
    let p = &config.proxy.upstream.proxy;
    if !p.enabled {
        return false;
    }
    let host = p.bare_host();
    let ports = [
        Some(config.proxy.port),
        config.proxy.transparent_port,
        config.proxy.ext_port,
        Some(config.webui.port),
    ];
    if !ports.contains(&Some(p.port)) {
        return false;
    }
    let same_host = |other: &str| {
        other
            .trim()
            .trim_matches(['[', ']'])
            .eq_ignore_ascii_case(host)
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
        || same_host(&config.proxy.host)
        || same_host(&config.webui.host)
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
    if state.shared_engine.recent_blocked_capacity() != config.adblock.request_log_capacity {
        state
            .shared_engine
            .set_event_capacity(config.adblock.request_log_capacity);
    }
    state.proxy_state.request_timeout_ms.store(
        config.performance.request_timeout_secs.saturating_mul(1000),
        Ordering::Relaxed,
    );
    if let Some(h) = state.stealth.get() {
        h.store(Arc::new(config.stealth.clone()));
    }
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

/// Short fingerprint of a lists key for the audit trail (never the key itself in full).
fn key_fingerprint(key: &str) -> String {
    use sha2::{Digest, Sha256};
    if key.trim().is_empty() {
        return "built-in".into();
    }
    Sha256::digest(key.trim().as_bytes())
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Record a change of the lists location or key as its own audit entry: who, old -> new URL and
/// old -> new key fingerprint. It decides what the proxy trusts, so the generic entry for the
/// route is not enough.
fn audit_lists_source(
    state: &AppState,
    who: &str,
    old: &common::config::BypassConfig,
    new: &common::config::BypassConfig,
) {
    let show = |u: &str| {
        if u.is_empty() {
            "built-in".to_string()
        } else {
            u.to_string()
        }
    };
    let entry = api_types::AuditEntry {
        id: String::new(),
        at: chrono::Utc::now().to_rfc3339(),
        actor_type: "user".into(),
        actor_id: None,
        actor_name: Some(who.to_string()),
        method: "PUT".into(),
        route: "/api/v1/config#bypass.lists_source".into(),
        scope: "config:write".into(),
        target: Some(format!(
            "url {} -> {}; key {} -> {}",
            show(&old.lists_base_url),
            show(&new.lists_base_url),
            key_fingerprint(&old.lists_public_key),
            key_fingerprint(&new.lists_public_key)
        )),
        status: 200,
        outcome: "success".into(),
        ip: None,
        user_agent: None,
        request_id: None,
    };
    if let Err(e) = state.audit.append(entry) {
        tracing::error!("Failed to write audit entry: {e}");
    }
}

/// Record a change of the upstream proxy as its own audit entry. Never the password.
fn audit_upstream_proxy(
    state: &AppState,
    who: &str,
    old: &common::config::UpstreamProxy,
    new: &common::config::UpstreamProxy,
) {
    let show = |p: &common::config::UpstreamProxy| {
        if p.enabled {
            format!("{:?} {}:{}", p.kind, p.host, p.port)
        } else {
            "off".to_string()
        }
    };
    let entry = api_types::AuditEntry {
        id: String::new(),
        at: chrono::Utc::now().to_rfc3339(),
        actor_type: "user".into(),
        actor_id: None,
        actor_name: Some(who.to_string()),
        method: "PUT".into(),
        route: "/api/v1/config#proxy.upstream.proxy".into(),
        scope: "config:write".into(),
        target: Some(format!(
            "{} -> {}; credentials {}",
            show(old),
            show(new),
            if (&old.username, &old.password) == (&new.username, &new.password) {
                "unchanged"
            } else {
                "changed"
            }
        )),
        status: 200,
        outcome: "success".into(),
        ip: None,
        user_agent: None,
        request_id: None,
    };
    if let Err(e) = state.audit.append(entry) {
        tracing::error!("Failed to write audit entry: {e}");
    }
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
        "ext_port",
        config.proxy.ext_port,
        req.ext_port.map(|p| (p != 0).then_some(p)),
        can_proxy
    );
    if let Some(v) = &req.block_response {
        let next: common::config::BlockResponse = v.parse().map_err(ApiError::ValidationError)?;
        let changed = next != config.proxy.block_response;
        config.proxy.block_response = next;
        live("block_response", changed, can_proxy, &mut applied);
    }
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
        "browser_like_upstream",
        config.proxy.upstream.browser_like,
        req.browser_like_upstream,
        can_proxy
    );
    field!(
        "guard_service_workers",
        config.adblock.guard_service_workers,
        req.guard_service_workers,
        can_proxy
    );
    if let Some(list) = req.guard_service_workers_exempt {
        let mut next: Vec<String> = Vec::new();
        for h in list {
            let h = h.trim().to_ascii_lowercase();
            let body = h.strip_prefix("*.").unwrap_or(&h);
            if body.is_empty()
                || body.contains(|c: char| c.is_whitespace() || matches!(c, '/' | '*' | ':'))
            {
                return Err(ApiError::ValidationError(format!(
                    "guard_service_workers_exempt: `{h}` is not a host (use example.com or *.example.com)"
                )));
            }
            if !next.contains(&h) {
                next.push(h);
            }
        }
        let changed = next != config.adblock.guard_service_workers_exempt;
        config.adblock.guard_service_workers_exempt = next;
        live(
            "guard_service_workers_exempt",
            changed,
            can_proxy,
            &mut applied,
        );
    }
    field!(
        "request_log_capacity",
        config.adblock.request_log_capacity,
        req.request_log_capacity.map(|v| v as usize),
        true
    );
    if let Some(u) = &req.upstream_proxy {
        let next = merge_upstream_proxy(&config.proxy.upstream.proxy, u);
        next.validate().map_err(ApiError::ValidationError)?;
        let changed = next != config.proxy.upstream.proxy;
        config.proxy.upstream.proxy = next;
        if upstream_proxy_is_own(&config) {
            return Err(ApiError::ValidationError(
                "upstream proxy: that is one of Argus's own listeners; Argus never chains to itself"
                    .into(),
            ));
        }
        live("upstream_proxy", changed, can_proxy, &mut applied);
    }
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
    if let Some(u) = req.stealth {
        let mut next = config.stealth.clone();
        merge_stealth(&mut next, u);
        next.validate()
            .map_err(|e| ApiError::ValidationError(format!("stealth: {e}")))?;
        if next != config.stealth {
            config.stealth = next;
            applied.push("stealth".into());
        }
    }
    if let Some(b) = req.bypass {
        if let Some(u) = b.lists_base_url {
            let u = u.trim().trim_end_matches('/').to_string();
            if !u.is_empty() {
                let ok = url::Url::parse(&u)
                    .is_ok_and(|p| matches!(p.scheme(), "http" | "https") && p.host().is_some());
                if !ok {
                    return Err(ApiError::ValidationError(
                        "bypass.lists_base_url: use an http:// or https:// URL with a host".into(),
                    ));
                }
            }
            config.bypass.lists_base_url = u;
        }
        if let Some(k) = b.lists_public_key {
            let k = k.trim().to_string();
            if !k.is_empty() {
                list_service::check_public_key(&k).map_err(|e| {
                    ApiError::ValidationError(format!(
                        "bypass.lists_public_key: expected the base64 line of a minisign public key ({e})"
                    ))
                })?;
            }
            config.bypass.lists_public_key = k;
        }
        if config.bypass != old.bypass {
            applied.push("bypass".into());
        }
    }
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
            let _ = rt.rebind_ext(&old.proxy.host, old.proxy.ext_port).await;
            let _ = rt.apply_access(&old).await;
        }
        return Err(ApiError::Internal(format!("Failed to save settings: {e}")));
    }

    info!("Proxy configuration updated by {who}");
    if old.proxy.upstream.proxy != config.proxy.upstream.proxy {
        audit_upstream_proxy(
            state,
            who,
            &old.proxy.upstream.proxy,
            &config.proxy.upstream.proxy,
        );
    }
    apply_live(state, &config);
    let mut response = proxy_config_response(&config);
    let lists_changed = old.bypass != config.bypass;
    *state.proxy_state.config.write() = config;
    if lists_changed {
        audit_lists_source(
            state,
            who,
            &old.bypass,
            &state.proxy_state.config.read().bypass,
        );
        // The lists, roots and catalogues read the new location and key and check right away.
        state.lists_config_changed();
    }
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
        if listeners_changed || old.proxy.ext_port != new.proxy.ext_port {
            if let Err(e) = rt.rebind_ext(&new.proxy.host, new.proxy.ext_port).await {
                if proxy_moved {
                    let _ = rt
                        .rebind_proxy(&old.proxy.host, old.proxy.port, old.proxy.transparent_port)
                        .await;
                }
                return Err(bind_err(e));
            }
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

/// The HTTPS host the upstream proxy test connects to.
const PROXY_TEST_HOST: &str = "www.cloudflare.com";

/// Connect through an upstream proxy (the saved one with the given fields applied; nothing is
/// saved) to a well-known HTTPS host. Argus resolves the host itself, as it does for any
/// upstream connection.
#[utoipa::path(
    post, path = "/config/upstream-proxy/test", tag = "config",
    security(("bearer_auth" = ["config:write"])),
    request_body = UpstreamProxyUpdate,
    responses((status = 200, description = "Outcome of the test", body = UpstreamProxyTestResult))
)]
pub async fn test_upstream_proxy(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiJson(req): ApiJson<UpstreamProxyUpdate>,
) -> ApiResult<Json<UpstreamProxyTestResult>> {
    // At most one test at a time and a few a minute per caller: each one makes Argus connect
    // out, so this is not a port scanner.
    let _slot = state.upstream_tests.admit(&p)?;
    let mut cfg = merge_upstream_proxy(&state.proxy_state.config.read().proxy.upstream.proxy, &req);
    cfg.enabled = true;
    cfg.validate().map_err(ApiError::ValidationError)?;
    let fail = |e: String| {
        Json(UpstreamProxyTestResult {
            ok: false,
            latency_ms: None,
            error: Some(e),
            target: PROXY_TEST_HOST.into(),
        })
    };
    let Some(rt) = state.runtime.get() else {
        return Ok(fail(
            "Argus is not running its proxy, so there is nothing to test with".into(),
        ));
    };
    Ok(
        match rt.test_upstream_proxy(&cfg, PROXY_TEST_HOST, 443).await {
            Ok(d) => Json(UpstreamProxyTestResult {
                ok: true,
                latency_ms: Some(d.as_millis() as u64),
                error: None,
                target: PROXY_TEST_HOST.into(),
            }),
            Err(e) => {
                // The detail (refused, timed out, bad credentials...) stays in the log: the
                // caller must not be able to map what the server can reach.
                tracing::warn!("upstream proxy test failed: {e}");
                fail("Could not connect through the proxy. See the server log for why.".into())
            }
        },
    )
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
    let lists_changed = old.bypass != new_config.bypass;
    *state.proxy_state.config.write() = new_config;
    if lists_changed {
        audit_lists_source(
            &state,
            &p.username,
            &old.bypass,
            &state.proxy_state.config.read().bypass,
        );
        state.lists_config_changed();
    }
    info!("Proxy configuration reloaded by {}", p.username);
    Ok(Json(MessageResponse {
        message: "Configuration reloaded successfully".into(),
    }))
}

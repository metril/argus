//! Upstream DNS: settings mapping, live health figures and the "Test upstreams" probe. The
//! settings themselves are read and written through `GET`/`PUT /config` like every other setting.

use std::sync::Arc;

use api_types::{DnsDto, DnsStatsResponse, DnsTestResponse, DnsUpdate};
use axum::{extract::State, Extension, Json};
use common::config::{DnsEcs, DnsMode, DnsSettings};

use crate::auth::authz::Principal;
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::state::AppState;

fn mode_name(m: DnsMode) -> &'static str {
    match m {
        DnsMode::LoadBalance => "load_balance",
        DnsMode::Parallel => "parallel",
        DnsMode::FastestIp => "fastest_ip",
    }
}

fn ecs_name(e: DnsEcs) -> &'static str {
    match e {
        DnsEcs::Off => "off",
        DnsEcs::Auto => "auto",
        DnsEcs::Custom => "custom",
    }
}

pub fn dns_dto(d: &DnsSettings) -> DnsDto {
    DnsDto {
        servers: d.servers.clone(),
        upstreams_source: d.upstreams_source.clone(),
        mode: mode_name(d.mode).into(),
        bootstrap: d.bootstrap.clone(),
        fallback: d.fallback.clone(),
        private_rdns: d.private_rdns,
        private_resolvers: d.private_resolvers.clone(),
        cache_size: d.cache_size,
        min_ttl_secs: d.min_ttl_secs,
        max_ttl_secs: d.max_ttl_secs,
        negative_ttl_secs: d.negative_ttl_secs,
        optimistic_cache: d.optimistic_cache,
        dnssec: d.dnssec,
        ipv6: d.ipv6,
        ecs: ecs_name(d.ecs).into(),
        ecs_subnet: d.ecs_subnet.clone(),
        timeout_ms: d.timeout_ms,
    }
}

/// Lines as saved: trimmed, empty ones dropped.
fn lines(v: &[String]) -> Vec<String> {
    v.iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Apply `u` to `d` and validate the result.
pub fn merge_dns(d: &mut DnsSettings, u: DnsUpdate) -> Result<(), String> {
    if let Some(v) = u.servers {
        d.servers = lines(&v);
    }
    if let Some(v) = u.upstreams_source {
        d.upstreams_source = v.trim().to_string();
    }
    if let Some(v) = u.mode {
        d.mode = match v.as_str() {
            "load_balance" => DnsMode::LoadBalance,
            "parallel" => DnsMode::Parallel,
            "fastest_ip" => DnsMode::FastestIp,
            _ => return Err("dns.mode must be load_balance, parallel or fastest_ip".into()),
        };
    }
    if let Some(v) = u.bootstrap {
        d.bootstrap = lines(&v);
    }
    if let Some(v) = u.fallback {
        d.fallback = lines(&v);
    }
    if let Some(v) = u.private_rdns {
        d.private_rdns = v;
    }
    if let Some(v) = u.private_resolvers {
        d.private_resolvers = lines(&v);
    }
    if let Some(v) = u.cache_size {
        d.cache_size = v;
    }
    if let Some(v) = u.min_ttl_secs {
        d.min_ttl_secs = v;
    }
    if let Some(v) = u.max_ttl_secs {
        d.max_ttl_secs = v;
    }
    if let Some(v) = u.negative_ttl_secs {
        d.negative_ttl_secs = v;
    }
    if let Some(v) = u.optimistic_cache {
        d.optimistic_cache = v;
    }
    if let Some(v) = u.dnssec {
        d.dnssec = v;
    }
    if let Some(v) = u.ipv6 {
        d.ipv6 = v;
    }
    if let Some(v) = u.ecs {
        d.ecs = match v.as_str() {
            "off" => DnsEcs::Off,
            "auto" => DnsEcs::Auto,
            "custom" => DnsEcs::Custom,
            _ => return Err("dns.ecs must be off, auto or custom".into()),
        };
    }
    if let Some(v) = u.ecs_subnet {
        d.ecs_subnet = v.trim().to_string();
    }
    if let Some(v) = u.timeout_ms {
        d.timeout_ms = v;
    }
    d.validate()
}

/// The settings a test probes: the saved ones with the request's fields applied, except the
/// upstreams source, which is always the saved one (a test must not make Argus read an
/// arbitrary file or URL).
pub fn merge_for_test(d: &mut DnsSettings, mut u: DnsUpdate) -> Result<(), String> {
    u.upstreams_source = None;
    merge_dns(d, u)
}

/// Health and RTT of every configured upstream, plus the cache counters.
#[utoipa::path(
    get, path = "/config/dns/stats", tag = "config",
    security(("bearer_auth" = ["config:read"])),
    responses((status = 200, description = "Per-upstream figures", body = DnsStatsResponse))
)]
pub async fn get_dns_stats(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<DnsStatsResponse>> {
    let stats = state
        .runtime
        .get()
        .and_then(|rt| rt.dns_stats())
        .unwrap_or_default();
    Ok(Json(stats))
}

/// Probe every upstream once, for the saved settings with the given fields applied (nothing is
/// saved). Reports each upstream's latency or why it failed.
#[utoipa::path(
    post, path = "/config/dns/test", tag = "config",
    security(("bearer_auth" = ["config:write"])),
    request_body = DnsUpdate,
    responses((status = 200, description = "One result per upstream", body = DnsTestResponse))
)]
pub async fn test_dns(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiJson(req): ApiJson<DnsUpdate>,
) -> ApiResult<Json<DnsTestResponse>> {
    // One probe at a time and a few a minute per caller: each one makes Argus send queries out.
    let _slot = state.upstream_tests.admit(&p)?;
    let mut cfg = state.proxy_state.config.read().dns.clone();
    merge_for_test(&mut cfg, req).map_err(ApiError::ValidationError)?;
    let Some(rt) = state.runtime.get() else {
        return Err(ApiError::ValidationError(
            "Argus is not running its proxy, so there is nothing to test with".into(),
        ));
    };
    let results = rt.test_dns(&cfg).await.map_err(|e| {
        tracing::warn!("dns test failed: {e}");
        ApiError::ValidationError(e)
    })?;
    Ok(Json(DnsTestResponse {
        name: "example.com".into(),
        results,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_request_cannot_change_the_upstreams_source() {
        let mut d = DnsSettings {
            upstreams_source: "saved.txt".into(),
            ..Default::default()
        };
        let u = DnsUpdate {
            upstreams_source: Some("/etc/passwd".into()),
            servers: Some(vec!["1.1.1.1".into()]),
            ..Default::default()
        };
        merge_for_test(&mut d, u).unwrap();
        assert_eq!(d.upstreams_source, "saved.txt");
        assert_eq!(d.servers, ["1.1.1.1"]);
    }

    #[test]
    fn validation_errors_name_the_line_not_its_text() {
        let mut d = DnsSettings::default();
        let u = DnsUpdate {
            servers: Some(vec!["1.1.1.1".into(), "SECRET-FILE-CONTENT".into()]),
            ..Default::default()
        };
        let e = merge_dns(&mut d, u).unwrap_err();
        assert!(e.contains("line 2") && !e.contains("SECRET"), "{e}");
    }
}

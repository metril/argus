//! Statistics handlers.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use api_types::{
    BlockedEntry, ConnectionStats, DomainCount, FilterStatsResponse, MessageResponse, MitmStats,
    Page, ProxyStatsResponse, RecentBlockedResponse, RequestStats,
};
use axum::{extract::State, Extension, Json};
use serde::Deserialize;
use tracing::info;
use utoipa::IntoParams;

use crate::auth::authz::Principal;
use crate::error::{ApiQuery, ApiResult};
use crate::state::AppState;

pub fn filter_stats(state: &AppState) -> FilterStatsResponse {
    let s = state.filter_stats.snapshot();
    FilterStatsResponse {
        total_requests: s.total_requests,
        blocked_requests: s.blocked_requests,
        allowed_requests: s.allowed_requests,
        blocked_by_type: s.blocked_by_type,
        top_blocked_domains: s
            .top_blocked_domains
            .into_iter()
            .map(|(domain, count)| DomainCount { domain, count })
            .collect(),
    }
}

pub fn proxy_stats(state: &AppState) -> ProxyStatsResponse {
    let s = state.proxy_state.stats.snapshot();
    ProxyStatsResponse {
        connections: ConnectionStats {
            total: s.connections_total,
            active: s.connections_active,
        },
        requests: RequestStats {
            total: s.requests_total,
            bytes_received: s.bytes_received,
            bytes_sent: s.bytes_sent,
            errors: s.errors_total,
        },
        mitm: state.proxy_state.mitm_enabled.then(|| MitmStats {
            cached_certificates: state.proxy_state.mitm_cached_certs.load(Ordering::Relaxed)
                as usize,
        }),
    }
}

/// Blocking statistics.
#[utoipa::path(
    get, path = "/stats/filter", tag = "stats",
    security(("bearer_auth" = ["stats:read"])),
    responses((status = 200, description = "Blocking statistics", body = FilterStatsResponse))
)]
pub async fn get_filter_stats(State(state): State<Arc<AppState>>) -> Json<FilterStatsResponse> {
    Json(filter_stats(&state))
}

/// Reset blocking statistics.
#[utoipa::path(
    post, path = "/stats/filter/reset", tag = "stats",
    security(("bearer_auth" = ["stats:reset"])),
    responses((status = 200, description = "Reset", body = MessageResponse))
)]
pub async fn reset_filter_stats(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
) -> Json<MessageResponse> {
    state.filter_stats.reset();
    info!("Filter statistics reset by {}", p.username);
    Json(MessageResponse {
        message: "Statistics reset successfully".into(),
    })
}

/// Proxy connection and traffic statistics.
#[utoipa::path(
    get, path = "/stats/proxy", tag = "stats",
    security(("bearer_auth" = ["stats:read"])),
    responses((status = 200, description = "Proxy statistics", body = ProxyStatsResponse))
)]
pub async fn get_proxy_stats(State(state): State<Arc<AppState>>) -> Json<ProxyStatsResponse> {
    Json(proxy_stats(&state))
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RecentQuery {
    pub page: Option<u32>,
    /// Page size (1..=200, default 50).
    pub limit: Option<u32>,
    /// Only blocks attributed to this client / profile label.
    pub client: Option<String>,
    /// Only requests to this host or its subdomains.
    pub host: Option<String>,
    /// Only blocks from this list id.
    pub list_id: Option<String>,
}

/// Recently blocked requests from the engine's bounded ring, newest first, filterable by client
/// label, host and list id.
#[utoipa::path(
    get, path = "/stats/blocked/recent", tag = "stats",
    security(("bearer_auth" = ["stats:read"])),
    params(RecentQuery),
    responses((status = 200, description = "Recent blocks", body = RecentBlockedResponse))
)]
pub async fn get_recent_blocked(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<RecentQuery>,
) -> ApiResult<Json<RecentBlockedResponse>> {
    let capacity = state.shared_engine.recent_blocked_capacity();
    let host = q.host.as_deref().map(|h| h.trim().to_ascii_lowercase());
    let events: Vec<BlockedEntry> = state
        .shared_engine
        .recent_blocked(capacity)
        .into_iter()
        .filter(|e| {
            q.client
                .as_deref()
                .is_none_or(|c| e.client.as_deref() == Some(c))
        })
        .filter(|e| {
            q.list_id
                .as_deref()
                .is_none_or(|l| e.list_id.as_deref() == Some(l))
        })
        .filter(|e| {
            host.as_deref().is_none_or(|h| {
                let eh = filter_engine::RequestMatcher::host_of(&e.url).to_ascii_lowercase();
                eh == h || eh.strip_suffix(h).is_some_and(|p| p.ends_with('.'))
            })
        })
        .map(|e| BlockedEntry {
            time: e.timestamp.to_rfc3339(),
            url: e.url,
            source_host: (!e.source_host.is_empty()).then_some(e.source_host),
            resource_type: e.request_type,
            rule: (!e.rule.is_empty()).then_some(e.rule),
            list_id: e.list_id,
            client: e.client,
        })
        .collect();
    let p = Page::from_vec(events, q.page, q.limit);
    Ok(Json(RecentBlockedResponse {
        capacity,
        total: p.total,
        page: p.page,
        limit: p.limit,
        has_more: p.has_more,
        entries: p.items,
    }))
}

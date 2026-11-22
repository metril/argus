//! Statistics handlers.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use api_types::{
    ConnectionStats, DomainCount, FilterStatsResponse, MessageResponse, MitmStats,
    ProxyStatsResponse, RecentBlockedResponse, RequestStats,
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
    /// Maximum entries, newest first (default 100).
    pub limit: Option<usize>,
}

/// Recently blocked requests (bounded in-memory ring, newest first). `available` is false until
/// the filter engine feeds the buffer.
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
    let ring = &state.recent_blocked;
    Ok(Json(RecentBlockedResponse {
        available: ring.is_fed(),
        capacity: ring.capacity(),
        entries: ring.recent(q.limit.unwrap_or(100).min(ring.capacity())),
    }))
}

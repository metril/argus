//! Health check and metrics handlers

use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::state::AppState;

/// Health check endpoint
///
/// GET /api/health
///
/// Returns the health status and version of the API.
#[utoipa::path(
    get,
    path = "/api/health",
    tag = "health",
    responses(
        (status = 200, description = "API is healthy", body = Value)
    )
)]
pub async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Metrics endpoint
///
/// GET /api/metrics
///
/// Returns proxy and filter statistics.
#[utoipa::path(
    get,
    path = "/api/metrics",
    tag = "health",
    responses(
        (status = 200, description = "Current metrics", body = Value)
    )
)]
pub async fn metrics(State(state): State<Arc<AppState>>) -> Json<Value> {
    let proxy_stats = state.proxy_state.stats.snapshot();
    let filter_stats = state.filter_stats.snapshot();

    Json(json!({
        "proxy": {
            "connections": {
                "total": proxy_stats.connections_total,
                "active": proxy_stats.connections_active,
            },
            "requests": {
                "total": proxy_stats.requests_total,
            },
            "bytes": {
                "received": proxy_stats.bytes_received,
                "sent": proxy_stats.bytes_sent,
            },
            "errors": {
                "total": proxy_stats.errors_total,
            },
        },
        "filter": {
            "total_requests": filter_stats.total_requests,
            "blocked_requests": filter_stats.blocked_requests,
            "allowed_requests": filter_stats.allowed_requests,
        },
    }))
}

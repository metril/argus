//! Health, system status and metrics handlers.

use std::fmt::Write;
use std::sync::Arc;

use api_types::{HealthResponse, MetricsResponse, SystemStatusResponse};
use axum::{extract::State, http::header, response::IntoResponse, Json};

use super::lists::engine_status;
use super::stats::{filter_stats, proxy_stats};
use crate::state::AppState;

/// Liveness probe (public; no internals).
#[utoipa::path(
    get, path = "/health", tag = "system",
    security(()),
    responses((status = 200, description = "API is healthy", body = HealthResponse))
)]
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

/// The OpenAPI document for this API.
#[utoipa::path(
    get, path = "/openapi.json", tag = "system",
    security(()),
    responses((status = 200, description = "OpenAPI 3.1 document", body = serde_json::Value))
)]
pub async fn openapi_json(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json")],
        state.spec_json.get().cloned().unwrap_or_default(),
    )
}

/// Version, uptime and engine state.
#[utoipa::path(
    get, path = "/system/status", tag = "system",
    security(("bearer_auth" = ["system:read"])),
    responses((status = 200, description = "System status", body = SystemStatusResponse))
)]
pub async fn system_status(State(state): State<Arc<AppState>>) -> Json<SystemStatusResponse> {
    Json(SystemStatusResponse {
        version: env!("CARGO_PKG_VERSION").into(),
        uptime_secs: state.started_at.elapsed().as_secs(),
        mitm_enabled: state.proxy_state.mitm_enabled,
        active_sessions: state.session_manager.active_session_count(),
        engine: engine_status(&state).await,
        tls_error: crate::webui_tls::not_served(&state),
    })
}

/// Proxy and filter metrics as JSON.
#[utoipa::path(
    get, path = "/system/metrics", tag = "system",
    security(("bearer_auth" = ["system:read"])),
    responses((status = 200, description = "Metrics", body = MetricsResponse))
)]
pub async fn metrics(State(state): State<Arc<AppState>>) -> Json<MetricsResponse> {
    Json(MetricsResponse {
        proxy: proxy_stats(&state),
        filter: filter_stats(&state),
        storage: storage_metrics(&state),
    })
}

fn storage_metrics(state: &AppState) -> api_types::StorageMetrics {
    let s = state.session_store.db().deferred_stats();
    api_types::StorageMetrics {
        deferred_dropped: s.dropped,
        deferred_failed: s.failed,
        deferred_queued: s.queued,
    }
}

/// The same metrics in Prometheus text exposition format.
#[utoipa::path(
    get, path = "/system/metrics/prometheus", tag = "system",
    security(("bearer_auth" = ["system:read"])),
    responses((status = 200, description = "Prometheus text format", content_type = "text/plain", body = String))
)]
pub async fn metrics_prometheus(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let p = proxy_stats(&state);
    let f = filter_stats(&state);
    let mut out = String::new();
    let mut metric = |name: &str, kind: &str, help: &str, v: u64| {
        let _ = writeln!(
            out,
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {v}"
        );
    };
    metric(
        "argus_proxy_connections_total",
        "counter",
        "Connections accepted.",
        p.connections.total,
    );
    metric(
        "argus_proxy_connections_active",
        "gauge",
        "Open connections.",
        p.connections.active,
    );
    metric(
        "argus_proxy_requests_total",
        "counter",
        "Requests processed.",
        p.requests.total,
    );
    metric(
        "argus_proxy_received_bytes_total",
        "counter",
        "Bytes received.",
        p.requests.bytes_received,
    );
    metric(
        "argus_proxy_sent_bytes_total",
        "counter",
        "Bytes sent.",
        p.requests.bytes_sent,
    );
    metric(
        "argus_proxy_errors_total",
        "counter",
        "Proxy errors.",
        p.requests.errors,
    );
    metric(
        "argus_filter_requests_total",
        "counter",
        "Requests checked by the filter.",
        f.total_requests,
    );
    metric(
        "argus_filter_blocked_total",
        "counter",
        "Requests blocked.",
        f.blocked_requests,
    );
    metric(
        "argus_filter_allowed_total",
        "counter",
        "Requests allowed.",
        f.allowed_requests,
    );
    let st = storage_metrics(&state);
    metric(
        "argus_db_deferred_dropped_total",
        "counter",
        "Telemetry database writes dropped because the queue was full.",
        st.deferred_dropped,
    );
    metric(
        "argus_db_deferred_failed_total",
        "counter",
        "Deferred database writes that failed or panicked.",
        st.deferred_failed,
    );
    metric(
        "argus_db_deferred_queued",
        "gauge",
        "Deferred database writes waiting to be committed.",
        st.deferred_queued,
    );
    metric(
        "argus_uptime_seconds",
        "gauge",
        "Seconds since API start.",
        state.started_at.elapsed().as_secs(),
    );
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
}

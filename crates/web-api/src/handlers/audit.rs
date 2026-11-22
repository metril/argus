//! Audit log read endpoint.

use std::sync::Arc;

use api_types::{AuditEntry, Page};
use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::audit::AuditFilter;
use crate::error::{ApiQuery, ApiResult};
use crate::state::AppState;

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AuditQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    /// Actor user id, token id or username.
    pub actor: Option<String>,
    /// HTTP method.
    pub method: Option<String>,
    /// `success`, `denied` or `error`.
    pub outcome: Option<String>,
    /// Substring of the route template, e.g. `/lists`.
    pub route: Option<String>,
    /// Target id (the route's path parameter).
    pub target: Option<String>,
    /// RFC 3339 lower bound.
    #[param(value_type = Option<String>)]
    pub since: Option<DateTime<Utc>>,
    /// RFC 3339 upper bound.
    #[param(value_type = Option<String>)]
    pub until: Option<DateTime<Utc>>,
}

/// Read the audit log, newest first.
#[utoipa::path(
    get, path = "/audit", tag = "audit",
    security(("bearer_auth" = ["audit:read"])),
    params(AuditQuery),
    responses((status = 200, description = "Audit entries", body = Page<AuditEntry>))
)]
pub async fn list_audit(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<AuditQuery>,
) -> ApiResult<Json<Page<AuditEntry>>> {
    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let filter = AuditFilter {
        actor: q.actor,
        method: q.method,
        outcome: q.outcome,
        route: q.route,
        target: q.target,
        since: q.since,
        until: q.until,
    };
    let offset = (page as usize - 1) * limit as usize;
    let (items, total) = state.audit.query(&filter, offset, limit as usize);
    Ok(Json(Page {
        has_more: offset + items.len() < total,
        items,
        total,
        page,
        limit,
    }))
}

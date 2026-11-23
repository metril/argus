//! Audit log read endpoint.

use std::sync::Arc;

use api_types::{AuditEntry, Page};
use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::audit::{AuditFilter, AuditStore};
use crate::error::{ApiError, ApiQuery, ApiResult};
use crate::state::{blocking, AppState};

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AuditQuery {
    /// Deprecated: use `cursor`.
    pub page: Option<u32>,
    pub limit: Option<u32>,
    /// `next_cursor` of the previous page (newest first; stable while entries are appended).
    pub cursor: Option<String>,
    /// Case-insensitive substring of `METHOD route`, e.g. `delete /lists`.
    pub action: Option<String>,
    /// Case-insensitive substring of actor, route, target or address.
    pub q: Option<String>,
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
        action: q.action.filter(|s| !s.trim().is_empty()),
        q: q.q.filter(|s| !s.trim().is_empty()),
    };
    if q.cursor.as_deref().is_some_and(|c| !c.is_empty()) {
        let before = AuditStore::entry_key(q.cursor.as_deref().unwrap_or_default())
            .ok_or_else(|| ApiError::ValidationError("invalid cursor".into()))?;
        let st = state.clone();
        let (items, more) =
            blocking(move || Ok(st.audit.query_before(&filter, Some(before), limit as usize)))
                .await?;
        let next_cursor = more.then(|| items.last().map(|e| e.id.clone())).flatten();
        return Ok(Json(Page {
            total: items.len() + usize::from(more),
            items,
            page,
            limit,
            has_more: more,
            next_cursor,
        }));
    }
    let offset = (page as usize - 1) * limit as usize;
    // The query waits for the deferred-write flush and reads the table: never on an async worker.
    let st = state.clone();
    let (items, total) =
        blocking(move || Ok(st.audit.query(&filter, offset, limit as usize))).await?;
    let has_more = offset + items.len() < total;
    let next_cursor = has_more
        .then(|| items.last().map(|e| e.id.clone()))
        .flatten();
    Ok(Json(Page {
        has_more,
        items,
        total,
        page,
        limit,
        next_cursor,
    }))
}

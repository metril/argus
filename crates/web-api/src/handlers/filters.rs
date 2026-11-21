//! Filter management handlers
//!
//! Provides endpoints for:
//! - GET /api/filters/lists - List all filter lists
//! - POST /api/filters/lists - Add a new filter list
//! - GET /api/filters/lists/:id - Get filter list details
//! - PUT /api/filters/lists/:id - Update filter list
//! - DELETE /api/filters/lists/:id - Delete filter list
//! - GET /api/filters/stats - Get blocking statistics

use crate::auth::middleware::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::filter_service::trigger_reload;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use filter_engine::BlockingStats;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::info;
use validator::Validate;

// Wire-facing DTOs live in the shared `api-types` crate.
pub use api_types::{
    AddFilterListRequest, CustomRulesResponse, FilterListResponse, PaginatedResponse,
    UpdateCustomRulesRequest, UpdateFilterListRequest,
};

/// Build a wire response from an engine filter list.
fn filter_list_response(list: &filter_engine::FilterList) -> FilterListResponse {
    FilterListResponse {
        id: list.id.clone(),
        name: list.name.clone(),
        url: list.url.clone(),
        enabled: list.enabled,
        last_updated: list.last_updated.map(|dt| dt.to_rfc3339()),
        rule_count: list.rule_count,
    }
}

/// Query params for listing filter lists
#[derive(Debug, Deserialize)]
pub struct ListFiltersQuery {
    pub enabled: Option<bool>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

/// List all filter lists
///
/// GET /api/filters/lists
pub async fn list_filter_lists(
    State(state): State<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Query(query): Query<ListFiltersQuery>,
) -> ApiResult<Json<PaginatedResponse<FilterListResponse>>> {
    let lists = state.filter_store.get_all()?;

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).clamp(1, 100);

    // Filter by enabled status if specified
    let filtered: Vec<FilterListResponse> = lists
        .into_iter()
        .filter(|l| query.enabled.is_none_or(|e| l.enabled == e))
        .map(|l| filter_list_response(&l))
        .collect();

    let total = filtered.len();

    // Paginate
    let start = ((page - 1) * limit) as usize;
    let paginated: Vec<_> = filtered
        .into_iter()
        .skip(start)
        .take(limit as usize)
        .collect();

    Ok(Json(PaginatedResponse {
        data: paginated,
        total,
        page,
        limit,
    }))
}

/// Add a new filter list
///
/// POST /api/filters/lists
pub async fn add_filter_list(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<AddFilterListRequest>,
) -> ApiResult<Json<FilterListResponse>> {
    // Check authorization
    if !auth_user.role().can_modify() {
        return Err(ApiError::AuthorizationFailed(
            "Requires user or admin role to add filter lists".to_string(),
        ));
    }

    // Validate request
    req.validate()
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;

    // Validate URL for SSRF protection
    validate_filter_url(&req.url)?;

    // Reject duplicate ids so an add can't silently clobber an existing list.
    if state.filter_store.exists(&req.id)? {
        return Err(ApiError::AlreadyExists(format!("Filter list '{}'", req.id)));
    }

    // Create and persist the filter list.
    let mut list =
        filter_engine::FilterList::new(req.id.clone(), req.name.clone(), req.url.clone());
    list.enabled = req.enabled.unwrap_or(true);
    state.filter_store.upsert(&list)?;

    info!(
        "Filter list added by {}: {} ({})",
        auth_user.username(),
        req.name,
        req.id
    );

    // Recompile the engine in the background so the new list takes effect (and downloads).
    trigger_reload(&state);

    Ok(Json(filter_list_response(&list)))
}

/// Get a specific filter list
///
/// GET /api/filters/lists/:id
pub async fn get_filter_list(
    State(state): State<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> ApiResult<Json<FilterListResponse>> {
    match state.filter_store.get(&id)? {
        Some(list) => Ok(Json(filter_list_response(&list))),
        None => Err(ApiError::NotFound(format!(
            "Filter list '{}' not found",
            id
        ))),
    }
}

/// Update a filter list
///
/// PUT /api/filters/lists/:id
pub async fn update_filter_list(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdateFilterListRequest>,
) -> ApiResult<Json<FilterListResponse>> {
    // Check authorization
    if !auth_user.role().can_modify() {
        return Err(ApiError::AuthorizationFailed(
            "Requires user or admin role to update filter lists".to_string(),
        ));
    }

    // Validate request
    req.validate()
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;

    // Validate URL if provided
    if let Some(ref url) = req.url {
        validate_filter_url(url)?;
    }

    let mut list = state
        .filter_store
        .get(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("Filter list '{}' not found", id)))?;

    // Apply changes. A changed URL invalidates the cached content/etag.
    if let Some(name) = req.name {
        list.name = name;
    }
    if let Some(url) = req.url {
        if url != list.url {
            list.url = url;
            list.etag = None;
            list.last_updated = None;
            list.rule_count = 0;
        }
    }
    if let Some(enabled) = req.enabled {
        list.enabled = enabled;
    }

    state.filter_store.upsert(&list)?;
    info!("Filter list '{}' updated by {}", id, auth_user.username());

    trigger_reload(&state);

    Ok(Json(filter_list_response(&list)))
}

/// Delete a filter list
///
/// DELETE /api/filters/lists/:id
pub async fn delete_filter_list(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    // Check authorization
    if !auth_user.role().can_modify() {
        return Err(ApiError::AuthorizationFailed(
            "Requires user or admin role to delete filter lists".to_string(),
        ));
    }

    if !state.filter_store.remove(&id)? {
        return Err(ApiError::NotFound(format!(
            "Filter list '{}' not found",
            id
        )));
    }

    info!("Filter list '{}' deleted by {}", id, auth_user.username());

    trigger_reload(&state);

    Ok(Json(
        json!({ "message": format!("Filter list '{}' deleted", id) }),
    ))
}

/// Get the user's custom filter rules
///
/// GET /api/filters/custom-rules
pub async fn get_custom_rules(
    State(state): State<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
) -> ApiResult<Json<CustomRulesResponse>> {
    let rules = state.filter_store.get_custom_rules()?;
    Ok(Json(CustomRulesResponse { rules }))
}

/// Replace the user's custom filter rules
///
/// PUT /api/filters/custom-rules
pub async fn update_custom_rules(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<UpdateCustomRulesRequest>,
) -> ApiResult<Json<CustomRulesResponse>> {
    if !auth_user.role().can_modify() {
        return Err(ApiError::AuthorizationFailed(
            "Requires user or admin role to edit custom rules".to_string(),
        ));
    }
    req.validate()
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;

    state.filter_store.set_custom_rules(&req.rules)?;
    info!("Custom filter rules updated by {}", auth_user.username());

    // Recompile so the new rules take effect immediately.
    trigger_reload(&state);

    Ok(Json(CustomRulesResponse { rules: req.rules }))
}

/// Get blocking statistics
///
/// GET /api/filters/stats
pub async fn get_stats(
    State(state): State<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
) -> ApiResult<Json<BlockingStats>> {
    let stats = state.filter_stats.snapshot();
    Ok(Json(stats))
}

/// Reset statistics
///
/// POST /api/filters/stats/reset
pub async fn reset_stats(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
) -> ApiResult<Json<Value>> {
    // Check authorization (admin only)
    if !auth_user.role().is_admin() {
        return Err(ApiError::AuthorizationFailed(
            "Requires admin role to reset statistics".to_string(),
        ));
    }

    state.filter_stats.reset();
    info!("Filter statistics reset by {}", auth_user.username());

    Ok(Json(json!({ "message": "Statistics reset successfully" })))
}

/// Validate filter list URL for SSRF protection
fn validate_filter_url(url: &str) -> ApiResult<()> {
    // Parse URL
    let parsed =
        url::Url::parse(url).map_err(|_| ApiError::ValidationError("Invalid URL".to_string()))?;

    // Only allow HTTPS
    if parsed.scheme() != "https" {
        return Err(ApiError::ValidationError(
            "Only HTTPS URLs are allowed for security".to_string(),
        ));
    }

    // Block private IPs
    if let Some(host) = parsed.host_str() {
        // Block localhost
        if host == "localhost" || host == "127.0.0.1" || host == "::1" {
            return Err(ApiError::ValidationError(
                "Local addresses are not allowed".to_string(),
            ));
        }

        // Block private IP ranges
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if is_private_ip(&ip) {
                return Err(ApiError::ValidationError(
                    "Private IP addresses are not allowed".to_string(),
                ));
            }
        }

        // Block common internal hostnames
        let internal_patterns = ["internal", "intranet", "local", "private", "corp", "lan"];
        let host_lower = host.to_lowercase();
        for pattern in internal_patterns {
            if host_lower.contains(pattern) {
                return Err(ApiError::ValidationError(
                    "Internal hostnames are not allowed".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Check if an IP address is private
fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            ipv4.is_private()
                || ipv4.is_loopback()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_documentation()
                || ipv4.is_unspecified()
        }
        std::net::IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified(),
    }
}

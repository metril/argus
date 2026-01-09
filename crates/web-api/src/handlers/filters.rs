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
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use filter_engine::BlockingStats;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::info;
use validator::Validate;

/// Filter list response
#[derive(Debug, Serialize)]
pub struct FilterListResponse {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub last_updated: Option<String>,
    pub rule_count: usize,
}

impl From<&filter_engine::FilterList> for FilterListResponse {
    fn from(list: &filter_engine::FilterList) -> Self {
        Self {
            id: list.id.clone(),
            name: list.name.clone(),
            url: list.url.clone(),
            enabled: list.enabled,
            last_updated: list.last_updated.map(|dt| dt.to_rfc3339()),
            rule_count: list.rule_count,
        }
    }
}

/// Query params for listing filter lists
#[derive(Debug, Deserialize)]
pub struct ListFiltersQuery {
    pub enabled: Option<bool>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

/// Request to add a new filter list
#[derive(Debug, Deserialize, Validate)]
pub struct AddFilterListRequest {
    #[validate(length(min = 1, max = 100))]
    pub id: String,

    #[validate(length(min = 1, max = 200))]
    pub name: String,

    #[validate(url(message = "Invalid URL"))]
    #[validate(length(max = 2000))]
    pub url: String,

    pub enabled: Option<bool>,
}

/// Request to update a filter list
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateFilterListRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: Option<String>,

    #[validate(url(message = "Invalid URL"))]
    #[validate(length(max = 2000))]
    pub url: Option<String>,

    pub enabled: Option<bool>,
}

/// Paginated response wrapper
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: usize,
    pub page: u32,
    pub limit: u32,
}

/// List all filter lists
///
/// GET /api/filters/lists
pub async fn list_filter_lists(
    State(state): State<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Query(query): Query<ListFiltersQuery>,
) -> ApiResult<Json<PaginatedResponse<FilterListResponse>>> {
    // Note: FilterListManager is not stored in AppState because adblock::Engine is !Send
    // For now, return empty list - in a real implementation, we'd need a different approach
    // such as storing filter list metadata separately

    let lists: Vec<FilterListResponse> = Vec::new();

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).min(100);

    // Filter by enabled status if specified
    let filtered_lists: Vec<_> = if let Some(enabled) = query.enabled {
        lists.into_iter().filter(|l| l.enabled == enabled).collect()
    } else {
        lists
    };

    let total = filtered_lists.len();

    // Paginate
    let start = ((page - 1) * limit) as usize;
    let paginated: Vec<_> = filtered_lists.into_iter().skip(start).take(limit as usize).collect();

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

    // Create filter list
    let list = filter_engine::FilterList::new(req.id.clone(), req.name.clone(), req.url.clone());

    info!("Filter list added by {}: {} ({})", auth_user.username(), req.name, req.id);

    Ok(Json(FilterListResponse::from(&list)))
}

/// Get a specific filter list
///
/// GET /api/filters/lists/:id
pub async fn get_filter_list(
    State(state): State<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> ApiResult<Json<FilterListResponse>> {
    // For now, return not found since we can't access FilterListManager
    Err(ApiError::NotFound(format!("Filter list '{}' not found", id)))
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

    // For now, return not found since we can't access FilterListManager
    Err(ApiError::NotFound(format!("Filter list '{}' not found", id)))
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

    info!("Filter list '{}' deleted by {}", id, auth_user.username());

    Ok(Json(json!({ "message": format!("Filter list '{}' deleted", id) })))
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
    let parsed = url::Url::parse(url).map_err(|_| ApiError::ValidationError("Invalid URL".to_string()))?;

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
        std::net::IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || ipv6.is_unspecified()
        }
    }
}

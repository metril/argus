//! Userscript management handlers
//!
//! Provides endpoints for:
//! - GET /api/userscripts - List all userscripts
//! - POST /api/userscripts - Install new userscript
//! - GET /api/userscripts/:id - Get userscript details
//! - PUT /api/userscripts/:id - Update userscript
//! - DELETE /api/userscripts/:id - Uninstall userscript
//! - PUT /api/userscripts/:id/enabled - Enable/disable userscript
//! - GET /api/userscripts/stats - Get userscript statistics

use crate::auth::middleware::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::info;

/// Userscript response
#[derive(Debug, Serialize)]
pub struct UserscriptResponse {
    pub id: String,
    pub name: String,
    pub namespace: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub enabled: bool,
    pub execution_count: u64,
    pub last_executed: Option<String>,
    pub match_patterns: Vec<String>,
}

impl From<&userscript_engine::Userscript> for UserscriptResponse {
    fn from(script: &userscript_engine::Userscript) -> Self {
        Self {
            id: script.id.clone(),
            name: script.metadata.name.clone(),
            namespace: script.metadata.namespace.clone(),
            version: script.metadata.version.clone(),
            description: script.metadata.description.clone(),
            author: script.metadata.author.clone(),
            enabled: script.enabled,
            execution_count: script.execution_count,
            last_executed: script.last_executed.map(|dt| dt.to_rfc3339()),
            match_patterns: script.metadata.matches.clone(),
        }
    }
}

/// Query params for listing userscripts
#[derive(Debug, Deserialize)]
pub struct ListUserscriptsQuery {
    pub enabled: Option<bool>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

/// Request to install a new userscript
#[derive(Debug, Deserialize)]
pub struct InstallUserscriptRequest {
    pub source: String,
}

/// Request to update a userscript
#[derive(Debug, Deserialize)]
pub struct UpdateUserscriptRequest {
    pub source: String,
}

/// Request to set enabled status
#[derive(Debug, Deserialize)]
pub struct SetEnabledRequest {
    pub enabled: bool,
}

/// Paginated response wrapper
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: usize,
    pub page: u32,
    pub limit: u32,
}

/// Statistics response
#[derive(Debug, Serialize)]
pub struct UserscriptStatsResponse {
    pub total_scripts: usize,
    pub enabled_scripts: usize,
    pub disabled_scripts: usize,
    pub total_executions: u64,
}

/// List all userscripts
///
/// GET /api/userscripts
pub async fn list_userscripts(
    State(state): State<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Query(query): Query<ListUserscriptsQuery>,
) -> ApiResult<Json<PaginatedResponse<UserscriptResponse>>> {
    let scripts = state.userscript_manager.get_all();

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).min(100);

    // Convert to responses
    let script_responses: Vec<UserscriptResponse> = scripts.iter().map(UserscriptResponse::from).collect();

    // Filter by enabled status if specified
    let filtered: Vec<_> = if let Some(enabled) = query.enabled {
        script_responses.into_iter().filter(|s| s.enabled == enabled).collect()
    } else {
        script_responses
    };

    let total = filtered.len();

    // Paginate
    let start = ((page - 1) * limit) as usize;
    let paginated: Vec<_> = filtered.into_iter().skip(start).take(limit as usize).collect();

    Ok(Json(PaginatedResponse {
        data: paginated,
        total,
        page,
        limit,
    }))
}

/// Install a new userscript
///
/// POST /api/userscripts
pub async fn install_userscript(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<InstallUserscriptRequest>,
) -> ApiResult<Json<UserscriptResponse>> {
    // Check authorization
    if !auth_user.role().can_modify() {
        return Err(ApiError::AuthorizationFailed(
            "Requires user or admin role to install userscripts".to_string(),
        ));
    }

    // Validate source not empty
    if req.source.trim().is_empty() {
        return Err(ApiError::ValidationError(
            "Userscript source cannot be empty".to_string(),
        ));
    }

    // Install the userscript
    let script_id = state
        .userscript_manager
        .install(req.source)
        .map_err(|e| ApiError::ValidationError(format!("Invalid userscript: {}", e)))?;

    // Get the installed script
    let script = state
        .userscript_manager
        .get(&script_id)
        .ok_or_else(|| ApiError::Internal("Failed to get installed script".to_string()))?;

    info!(
        "Userscript installed by {}: {} ({})",
        auth_user.username(),
        script.metadata.name,
        script_id
    );

    Ok(Json(UserscriptResponse::from(&script)))
}

/// Get a specific userscript
///
/// GET /api/userscripts/:id
pub async fn get_userscript(
    State(state): State<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> ApiResult<Json<UserscriptResponse>> {
    let script = state
        .userscript_manager
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Userscript '{}' not found", id)))?;

    Ok(Json(UserscriptResponse::from(&script)))
}

/// Get userscript source code
///
/// GET /api/userscripts/:id/source
pub async fn get_userscript_source(
    State(state): State<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let script = state
        .userscript_manager
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("Userscript '{}' not found", id)))?;

    Ok(Json(json!({
        "id": script.id,
        "source": script.source
    })))
}

/// Update a userscript
///
/// PUT /api/userscripts/:id
pub async fn update_userscript(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserscriptRequest>,
) -> ApiResult<Json<UserscriptResponse>> {
    // Check authorization
    if !auth_user.role().can_modify() {
        return Err(ApiError::AuthorizationFailed(
            "Requires user or admin role to update userscripts".to_string(),
        ));
    }

    // Validate source not empty
    if req.source.trim().is_empty() {
        return Err(ApiError::ValidationError(
            "Userscript source cannot be empty".to_string(),
        ));
    }

    // Update the userscript
    state
        .userscript_manager
        .update(&id, req.source)
        .map_err(|e| match e {
            userscript_engine::Error::ScriptNotFound(_) => {
                ApiError::NotFound(format!("Userscript '{}' not found", id))
            }
            _ => ApiError::ValidationError(format!("Invalid userscript: {}", e)),
        })?;

    // Get the updated script
    let script = state
        .userscript_manager
        .get(&id)
        .ok_or_else(|| ApiError::Internal("Failed to get updated script".to_string()))?;

    info!(
        "Userscript updated by {}: {} ({})",
        auth_user.username(),
        script.metadata.name,
        id
    );

    Ok(Json(UserscriptResponse::from(&script)))
}

/// Uninstall a userscript
///
/// DELETE /api/userscripts/:id
pub async fn uninstall_userscript(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    // Check authorization
    if !auth_user.role().can_modify() {
        return Err(ApiError::AuthorizationFailed(
            "Requires user or admin role to uninstall userscripts".to_string(),
        ));
    }

    // Uninstall the userscript
    state.userscript_manager.uninstall(&id).map_err(|e| match e {
        userscript_engine::Error::ScriptNotFound(_) => {
            ApiError::NotFound(format!("Userscript '{}' not found", id))
        }
        _ => ApiError::Internal(format!("Failed to uninstall: {}", e)),
    })?;

    info!("Userscript uninstalled by {}: {}", auth_user.username(), id);

    Ok(Json(json!({ "message": format!("Userscript '{}' uninstalled", id) })))
}

/// Enable or disable a userscript
///
/// PUT /api/userscripts/:id/enabled
pub async fn set_enabled(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<SetEnabledRequest>,
) -> ApiResult<Json<UserscriptResponse>> {
    // Check authorization
    if !auth_user.role().can_modify() {
        return Err(ApiError::AuthorizationFailed(
            "Requires user or admin role to modify userscripts".to_string(),
        ));
    }

    // Set enabled status
    state
        .userscript_manager
        .set_enabled(&id, req.enabled)
        .map_err(|e| match e {
            userscript_engine::Error::ScriptNotFound(_) => {
                ApiError::NotFound(format!("Userscript '{}' not found", id))
            }
            _ => ApiError::Internal(format!("Failed to update: {}", e)),
        })?;

    // Get the updated script
    let script = state
        .userscript_manager
        .get(&id)
        .ok_or_else(|| ApiError::Internal("Failed to get updated script".to_string()))?;

    info!(
        "Userscript {} {} by {}",
        if req.enabled { "enabled" } else { "disabled" },
        script.metadata.name,
        auth_user.username()
    );

    Ok(Json(UserscriptResponse::from(&script)))
}

/// Get userscript statistics
///
/// GET /api/userscripts/stats
pub async fn get_stats(
    State(state): State<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
) -> ApiResult<Json<UserscriptStatsResponse>> {
    let stats = state.userscript_manager.stats();

    Ok(Json(UserscriptStatsResponse {
        total_scripts: stats.total_scripts,
        enabled_scripts: stats.enabled_scripts,
        disabled_scripts: stats.disabled_scripts,
        total_executions: stats.total_executions,
    }))
}

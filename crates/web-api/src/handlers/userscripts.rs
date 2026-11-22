//! Userscript management handlers.

use std::sync::Arc;

use api_types::{
    InstallUserscriptRequest, MessageResponse, Page, SetEnabledRequest, UpdateUserscriptRequest,
    UserscriptResponse, UserscriptSourceResponse, UserscriptStatsResponse,
};
use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::Deserialize;
use tracing::info;
use utoipa::IntoParams;

use crate::auth::authz::Principal;
use crate::error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult};
use crate::state::AppState;

fn userscript_response(script: &userscript_engine::Userscript) -> UserscriptResponse {
    UserscriptResponse {
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

fn not_found(id: &str) -> ApiError {
    ApiError::NotFound(format!("Userscript '{id}' not found"))
}

fn get_script(state: &AppState, id: &str) -> ApiResult<userscript_engine::Userscript> {
    state
        .userscript_manager
        .get(id)
        .ok_or_else(|| not_found(id))
}

fn require_source(source: &str) -> ApiResult<()> {
    if source.trim().is_empty() {
        return Err(ApiError::ValidationError(
            "Userscript source cannot be empty".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListUserscriptsQuery {
    /// Only enabled / only disabled scripts.
    pub enabled: Option<bool>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

/// List userscripts.
#[utoipa::path(
    get, path = "/userscripts", tag = "userscripts",
    security(("bearer_auth" = ["scripts:read"])),
    params(ListUserscriptsQuery),
    responses((status = 200, description = "Userscripts", body = Page<UserscriptResponse>))
)]
pub async fn list_userscripts(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<ListUserscriptsQuery>,
) -> ApiResult<Json<Page<UserscriptResponse>>> {
    let all = state
        .userscript_manager
        .get_all()
        .iter()
        .map(userscript_response)
        .filter(|s| q.enabled.is_none_or(|e| s.enabled == e))
        .collect();
    Ok(Json(Page::from_vec(all, q.page, q.limit)))
}

/// Install a userscript from its source.
#[utoipa::path(
    post, path = "/userscripts", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    request_body = InstallUserscriptRequest,
    responses((status = 201, description = "Installed", body = UserscriptResponse))
)]
pub async fn install_userscript(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiJson(req): ApiJson<InstallUserscriptRequest>,
) -> ApiResult<(StatusCode, Json<UserscriptResponse>)> {
    require_source(&req.source)?;
    let id = state
        .userscript_manager
        .install(req.source)
        .map_err(|e| ApiError::ValidationError(format!("Invalid userscript: {e}")))?;
    let script = get_script(&state, &id)?;
    info!("Userscript {} installed by {}", id, p.username);
    Ok((StatusCode::CREATED, Json(userscript_response(&script))))
}

/// Userscript statistics.
#[utoipa::path(
    get, path = "/userscripts/stats", tag = "userscripts",
    security(("bearer_auth" = ["scripts:read"])),
    responses((status = 200, description = "Statistics", body = UserscriptStatsResponse))
)]
pub async fn get_stats(State(state): State<Arc<AppState>>) -> Json<UserscriptStatsResponse> {
    let s = state.userscript_manager.stats();
    Json(UserscriptStatsResponse {
        total_scripts: s.total_scripts,
        enabled_scripts: s.enabled_scripts,
        disabled_scripts: s.disabled_scripts,
        total_executions: s.total_executions,
    })
}

/// Get one userscript.
#[utoipa::path(
    get, path = "/userscripts/{id}", tag = "userscripts",
    security(("bearer_auth" = ["scripts:read"])),
    params(("id" = String, Path, description = "Userscript id")),
    responses((status = 200, description = "Userscript", body = UserscriptResponse))
)]
pub async fn get_userscript(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<UserscriptResponse>> {
    Ok(Json(userscript_response(&get_script(&state, &id)?)))
}

/// Get a userscript's source.
#[utoipa::path(
    get, path = "/userscripts/{id}/source", tag = "userscripts",
    security(("bearer_auth" = ["scripts:read"])),
    params(("id" = String, Path, description = "Userscript id")),
    responses((status = 200, description = "Source", body = UserscriptSourceResponse))
)]
pub async fn get_userscript_source(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<UserscriptSourceResponse>> {
    let s = get_script(&state, &id)?;
    Ok(Json(UserscriptSourceResponse {
        id: s.id,
        source: s.source,
    }))
}

/// Replace a userscript's source.
#[utoipa::path(
    put, path = "/userscripts/{id}", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    params(("id" = String, Path, description = "Userscript id")),
    request_body = UpdateUserscriptRequest,
    responses((status = 200, description = "Updated", body = UserscriptResponse))
)]
pub async fn update_userscript(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<UpdateUserscriptRequest>,
) -> ApiResult<Json<UserscriptResponse>> {
    require_source(&req.source)?;
    state
        .userscript_manager
        .update(&id, req.source)
        .map_err(|e| match e {
            userscript_engine::Error::ScriptNotFound(_) => not_found(&id),
            _ => ApiError::ValidationError(format!("Invalid userscript: {e}")),
        })?;
    info!("Userscript {id} updated by {}", p.username);
    Ok(Json(userscript_response(&get_script(&state, &id)?)))
}

/// Uninstall a userscript.
#[utoipa::path(
    delete, path = "/userscripts/{id}", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    params(("id" = String, Path, description = "Userscript id")),
    responses((status = 200, description = "Uninstalled", body = MessageResponse))
)]
pub async fn uninstall_userscript(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<MessageResponse>> {
    state
        .userscript_manager
        .uninstall(&id)
        .map_err(|e| match e {
            userscript_engine::Error::ScriptNotFound(_) => not_found(&id),
            _ => ApiError::Internal(format!("Failed to uninstall: {e}")),
        })?;
    info!("Userscript {id} uninstalled by {}", p.username);
    Ok(Json(MessageResponse {
        message: format!("Userscript '{id}' uninstalled"),
    }))
}

/// Enable or disable a userscript.
#[utoipa::path(
    put, path = "/userscripts/{id}/enabled", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    params(("id" = String, Path, description = "Userscript id")),
    request_body = SetEnabledRequest,
    responses((status = 200, description = "Updated", body = UserscriptResponse))
)]
pub async fn set_enabled(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<SetEnabledRequest>,
) -> ApiResult<Json<UserscriptResponse>> {
    state
        .userscript_manager
        .set_enabled(&id, req.enabled)
        .map_err(|e| match e {
            userscript_engine::Error::ScriptNotFound(_) => not_found(&id),
            _ => ApiError::Internal(format!("Failed to update: {e}")),
        })?;
    info!("Userscript {id} enabled={} by {}", req.enabled, p.username);
    Ok(Json(userscript_response(&get_script(&state, &id)?)))
}

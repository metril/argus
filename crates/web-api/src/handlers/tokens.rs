//! API token handlers.

use std::sync::Arc;

use api_types::{ApiTokenInfo, CreateTokenRequest, CreatedTokenResponse, MessageResponse, Page};
use axum::{extract::State, http::StatusCode, Extension, Json};
use chrono::{Duration, Utc};
use tracing::info;
use validator::Validate;

use super::PageQuery;
use crate::auth::authz::Principal;
use crate::error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult};
use crate::state::AppState;

/// Create an API token. The secret is returned once and cannot be retrieved again. Requested
/// scopes must all be held by the caller (a token can never mint more than it has).
#[utoipa::path(
    post, path = "/tokens", tag = "tokens",
    security(("bearer_auth" = ["tokens:self"])),
    request_body = CreateTokenRequest,
    responses((status = 201, description = "Created; `secret` is shown only here", body = CreatedTokenResponse))
)]
pub async fn create_token(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiJson(req): ApiJson<CreateTokenRequest>,
) -> ApiResult<(StatusCode, Json<CreatedTokenResponse>)> {
    req.validate()?;
    if req.scopes.is_empty() {
        return Err(ApiError::ValidationError(
            "A token needs at least one scope".into(),
        ));
    }
    if let Some(s) = req.scopes.iter().find(|s| !p.has(**s)) {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "scope_escalation",
            format!("Cannot grant scope '{s}' that you do not hold"),
        ));
    }
    let mut scopes = req.scopes.clone();
    scopes.sort();
    scopes.dedup();
    // A token cannot widen its own profile restriction either.
    if let (Some(mine), Some(wanted)) = (&p.profiles, &req.profiles) {
        if wanted.iter().any(|w| !mine.contains(w)) {
            return Err(ApiError::coded(
                StatusCode::FORBIDDEN,
                "scope_escalation",
                "Cannot grant access to profiles you are not restricted to",
            ));
        }
    }
    let profiles = req.profiles.or_else(|| p.profiles.clone());
    let expires = req
        .expires_in_days
        .map(|d| Utc::now() + Duration::days(d as i64));
    let (token, secret) = state.tokens.create(
        req.name,
        scopes,
        profiles,
        p.user_id,
        p.username.clone(),
        expires,
    )?;
    info!("API token {} created for {}", token.id, p.username);
    Ok((
        StatusCode::CREATED,
        Json(CreatedTokenResponse { token, secret }),
    ))
}

/// List your own API tokens (never includes secrets).
#[utoipa::path(
    get, path = "/tokens", tag = "tokens",
    security(("bearer_auth" = ["tokens:self"])),
    params(PageQuery),
    responses((status = 200, description = "Your tokens", body = Page<ApiTokenInfo>))
)]
pub async fn list_tokens(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<ApiTokenInfo>>> {
    Ok(Json(Page::from_vec(
        state.tokens.list(Some(&p.user_id)),
        q.page,
        q.limit,
    )))
}

/// Revoke one of your own tokens; it stops working immediately.
#[utoipa::path(
    delete, path = "/tokens/{id}", tag = "tokens",
    security(("bearer_auth" = ["tokens:self"])),
    params(("id" = String, Path, description = "Token id")),
    responses((status = 200, description = "Revoked", body = MessageResponse))
)]
pub async fn revoke_token(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<MessageResponse>> {
    match state.tokens.get(&id) {
        Some(t) if t.stored.created_by == p.user_id => {
            state.tokens.revoke(&id)?;
            Ok(Json(MessageResponse {
                message: "Token revoked".into(),
            }))
        }
        _ => Err(ApiError::NotFound("Token not found".into())),
    }
}

/// List every user's API tokens.
#[utoipa::path(
    get, path = "/admin/tokens", tag = "tokens",
    security(("bearer_auth" = ["tokens:admin"])),
    params(PageQuery),
    responses((status = 200, description = "All tokens", body = Page<ApiTokenInfo>))
)]
pub async fn admin_list_tokens(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<ApiTokenInfo>>> {
    Ok(Json(Page::from_vec(
        state.tokens.list(None),
        q.page,
        q.limit,
    )))
}

/// Revoke any user's token.
#[utoipa::path(
    delete, path = "/admin/tokens/{id}", tag = "tokens",
    security(("bearer_auth" = ["tokens:admin"])),
    params(("id" = String, Path, description = "Token id")),
    responses((status = 200, description = "Revoked", body = MessageResponse))
)]
pub async fn admin_revoke_token(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<MessageResponse>> {
    if state.tokens.revoke(&id)? {
        Ok(Json(MessageResponse {
            message: "Token revoked".into(),
        }))
    } else {
        Err(ApiError::NotFound("Token not found".into()))
    }
}

//! API token handlers.

use std::sync::Arc;

use api_types::{ApiTokenInfo, CreateTokenRequest, CreatedTokenResponse, MessageResponse, Page};
use axum::{extract::State, http::StatusCode, Extension, Json};
use chrono::{Duration, Utc};
use tracing::info;
use validator::Validate;

use super::paging::{page_of, ts_key_desc, Keyed};
use super::CursorQuery;
use crate::auth::authz::Principal;
use crate::error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult};
use crate::state::{blocking, AppState};

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
    let st = state.clone();
    let (user_id, username) = (p.user_id, p.username.clone());
    let (token, secret) = blocking(move || {
        st.tokens
            .create(req.name, scopes, profiles, user_id, username, expires)
    })
    .await?;
    info!("API token {} created for {}", token.id, p.username);
    Ok((
        StatusCode::CREATED,
        Json(CreatedTokenResponse { token, secret }),
    ))
}

/// Tokens as paging rows, newest first.
fn token_rows(all: Vec<ApiTokenInfo>) -> Vec<Keyed<ApiTokenInfo>> {
    all.into_iter()
        .map(|t| Keyed {
            key: ts_key_desc(&t.created_at),
            id: t.id.clone(),
            label: t.name.clone(),
            item: t,
        })
        .collect()
}

/// List your own API tokens (never includes secrets).
#[utoipa::path(
    get, path = "/tokens", tag = "tokens",
    security(("bearer_auth" = ["tokens:self"])),
    params(CursorQuery),
    responses((status = 200, description = "Your tokens", body = Page<ApiTokenInfo>))
)]
pub async fn list_tokens(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiQuery(q): ApiQuery<CursorQuery>,
) -> ApiResult<Json<Page<ApiTokenInfo>>> {
    let (st, uid) = (state.clone(), p.user_id);
    let tokens = blocking(move || Ok(st.tokens.list(Some(&uid)))).await?;
    Ok(Json(page_of(token_rows(tokens), &q)?))
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
            let st = state.clone();
            blocking(move || st.tokens.revoke(&id)).await?;
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
    params(CursorQuery),
    responses((status = 200, description = "All tokens", body = Page<ApiTokenInfo>))
)]
pub async fn admin_list_tokens(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<CursorQuery>,
) -> ApiResult<Json<Page<ApiTokenInfo>>> {
    let st = state.clone();
    let tokens = blocking(move || Ok(st.tokens.list(None))).await?;
    Ok(Json(page_of(token_rows(tokens), &q)?))
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
    let st = state.clone();
    if blocking(move || st.tokens.revoke(&id)).await? {
        Ok(Json(MessageResponse {
            message: "Token revoked".into(),
        }))
    } else {
        Err(ApiError::NotFound("Token not found".into()))
    }
}

//! User management handlers.

use std::sync::Arc;

use api_types::{CreateUserRequest, MessageResponse, Page, UpdateUserRequest, UserInfo, UserRole};
use axum::{extract::State, http::StatusCode, Extension, Json};
use tracing::info;
use validator::Validate;

use super::{parse_uuid, PageQuery};
use crate::auth::authz::Principal;
use crate::auth::models::User;
use crate::auth::password::{hash_password, validate_password_strength};
use crate::error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult};
use crate::state::{blocking, AppState};

fn last_admin() -> ApiError {
    ApiError::conflict(
        "last_admin",
        "At least one enabled administrator must remain",
    )
}

fn load(state: &AppState, id: &str) -> ApiResult<User> {
    state
        .session_store
        .get_user(&parse_uuid(id)?)?
        .ok_or_else(|| ApiError::NotFound("User not found".into()))
}

/// List user accounts.
#[utoipa::path(
    get, path = "/users", tag = "users",
    security(("bearer_auth" = ["users:read"])),
    params(PageQuery),
    responses((status = 200, description = "Users", body = Page<UserInfo>))
)]
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<UserInfo>>> {
    let mut users = state.session_store.get_all_users()?;
    users.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    let all = users.iter().map(UserInfo::from).collect();
    Ok(Json(Page::from_vec(all, q.page, q.limit)))
}

/// Create a user account.
#[utoipa::path(
    post, path = "/users", tag = "users",
    security(("bearer_auth" = ["users:admin"])),
    request_body = CreateUserRequest,
    responses((status = 201, description = "Created", body = UserInfo))
)]
pub async fn create_user(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<CreateUserRequest>,
) -> ApiResult<(StatusCode, Json<UserInfo>)> {
    req.validate()?;
    validate_password_strength(&req.password)?;
    if state.session_store.username_exists(&req.username)? {
        return Err(ApiError::AlreadyExists(format!("User '{}'", req.username)));
    }
    let pw = req.password.clone();
    let cost = state.api_config.auth.bcrypt_cost;
    let hash = tokio::task::spawn_blocking(move || hash_password(&pw, cost))
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))??;
    let user = User::new(req.username, hash, req.role);
    // The username index is claimed atomically inside `store_user`, so a concurrent create of
    // the same name fails there with `AlreadyExists`.
    let (st, u) = (state.clone(), user.clone());
    blocking(move || st.session_store.store_user(&u)).await?;
    info!("User {} created with role {:?}", user.username, user.role);
    Ok((StatusCode::CREATED, Json(UserInfo::from(&user))))
}

/// Get one user.
#[utoipa::path(
    get, path = "/users/{id}", tag = "users",
    security(("bearer_auth" = ["users:read"])),
    params(("id" = String, Path, description = "User id (UUID)")),
    responses((status = 200, description = "User", body = UserInfo))
)]
pub async fn get_user(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<UserInfo>> {
    Ok(Json(UserInfo::from(&load(&state, &id)?)))
}

/// Change a user's role or enabled flag. The last enabled administrator cannot be demoted or
/// disabled. Disabling signs the user out everywhere and disables their tokens.
#[utoipa::path(
    patch, path = "/users/{id}", tag = "users",
    security(("bearer_auth" = ["users:admin"])),
    params(("id" = String, Path, description = "User id (UUID)")),
    request_body = UpdateUserRequest,
    responses((status = 200, description = "Updated", body = UserInfo))
)]
pub async fn update_user(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<UpdateUserRequest>,
) -> ApiResult<Json<UserInfo>> {
    let st = state.clone();
    let user = blocking(move || {
        let _g = st.session_store.admin_lock.lock();
        let mut user = load(&st, &id)?;
        let was_admin = user.enabled && user.role == UserRole::Admin;
        if let Some(r) = req.role {
            user.role = r;
        }
        if let Some(e) = req.enabled {
            user.enabled = e;
        }
        let is_admin = user.enabled && user.role == UserRole::Admin;
        if was_admin && !is_admin && st.session_store.enabled_admin_count()? <= 1 {
            return Err(last_admin());
        }
        st.session_store.store_user(&user)?;
        // Roles are re-resolved on every request; a disabled account is also signed out
        // everywhere.
        if !user.enabled {
            st.session_manager.revoke_user_sessions(&user.id, None)?;
        }
        Ok(user)
    })
    .await?;
    Ok(Json(UserInfo::from(&user)))
}

/// Delete a user, their sessions and their tokens.
#[utoipa::path(
    delete, path = "/users/{id}", tag = "users",
    security(("bearer_auth" = ["users:admin"])),
    params(("id" = String, Path, description = "User id (UUID)")),
    responses((status = 200, description = "Deleted", body = MessageResponse))
)]
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Extension(_p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<MessageResponse>> {
    let st = state.clone();
    let user = blocking(move || {
        let _g = st.session_store.admin_lock.lock();
        let user = load(&st, &id)?;
        if user.enabled
            && user.role == UserRole::Admin
            && st.session_store.enabled_admin_count()? <= 1
        {
            return Err(last_admin());
        }
        st.session_store.delete_user(&user.id)?;
        st.session_manager.revoke_user_sessions(&user.id, None)?;
        st.tokens.revoke_all_for_user(&user.id)?;
        Ok(user)
    })
    .await?;
    Ok(Json(MessageResponse {
        message: format!("User '{}' deleted", user.username),
    }))
}

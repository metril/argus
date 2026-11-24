//! Profile handlers: named sets of enabled lists plus overlay rules. Profile `0` is the built-in
//! default profile (the global lists and custom rules); it cannot be renamed or deleted.
//!
//! A profile-restricted token sees and edits only its own profiles and cannot create new ones.

use std::sync::Arc;

use api_types::{CreateProfileRequest, MessageResponse, Page, ProfileDto, UpdateProfileRequest};
use axum::{extract::State, http::StatusCode, Extension, Json};
use chrono::Utc;
use common::profile_store::ProfileRecord;
use tracing::info;
use validator::Validate;

use super::paging::{natural_key, page_of, Keyed};
use super::CursorQuery;
use crate::auth::authz::Principal;
use crate::auth::profile::ProfileParam;
use crate::error::{ApiError, ApiJson, ApiQuery, ApiResult};
use crate::state::{blocking, AppState};

pub fn profile_dto(state: &AppState, p: &ProfileRecord) -> ProfileDto {
    let build = state
        .profile_runtime
        .as_ref()
        .and_then(|r| r.build_info(p.id))
        .unwrap_or_default();
    ProfileDto {
        id: p.id.to_string(),
        name: p.name.clone(),
        description: p.description.clone(),
        lists: p.lists.clone(),
        rules: p.rules.clone(),
        created_at: p.created_at.to_rfc3339(),
        updated_at: p.updated_at.to_rfc3339(),
        last_error: build.last_error,
        last_built: build.last_built.map(|t| t.to_rfc3339()),
    }
}

fn default_protected(what: &str) -> ApiError {
    ApiError::coded(
        StatusCode::BAD_REQUEST,
        "default_profile_protected",
        format!("The default profile cannot be {what}"),
    )
}

/// Every enabled list id must name an existing list.
fn check_lists(state: &AppState, lists: &[String]) -> ApiResult<()> {
    for id in lists {
        if !state.filter_store.exists(id)? {
            return Err(ApiError::ValidationError(format!(
                "Unknown filter list '{id}'"
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ProfilesQuery {
    /// Deprecated: use `cursor`.
    pub page: Option<u32>,
    /// Items per page, 1..=200 (default 50).
    pub limit: Option<u32>,
    pub cursor: Option<String>,
    /// Case-insensitive substring of the name.
    pub q: Option<String>,
}

/// List the profiles the caller may access, A-Z.
#[utoipa::path(
    get, path = "/profiles", tag = "profiles",
    security(("bearer_auth" = ["profiles:read"])),
    params(ProfilesQuery),
    responses((status = 200, description = "Profiles", body = Page<ProfileDto>))
)]
pub async fn list_profiles(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiQuery(q): ApiQuery<ProfilesQuery>,
) -> ApiResult<Json<Page<ProfileDto>>> {
    let st = state.clone();
    let all = blocking(move || Ok(st.profiles.list()?)).await?;
    let needle = q.q.as_deref().unwrap_or("").trim().to_lowercase();
    let rows = all
        .iter()
        .filter(|r| p.may_access_profile(&r.id.to_string()))
        .map(|r| profile_dto(&state, r))
        .filter(|d| needle.is_empty() || d.name.to_lowercase().contains(&needle))
        .map(|d| Keyed {
            key: natural_key(&d.name),
            id: format!("{:020}", d.id.parse::<u64>().unwrap_or(0)),
            label: d.name.clone(),
            item: d,
        })
        .collect();
    let cq = CursorQuery {
        page: q.page,
        limit: q.limit,
        cursor: q.cursor,
    };
    Ok(Json(page_of(rows, &cq)?))
}

/// Create a profile. Not available to profile-restricted tokens.
#[utoipa::path(
    post, path = "/profiles", tag = "profiles",
    security(("bearer_auth" = ["profiles:write"])),
    request_body = CreateProfileRequest,
    responses(
        (status = 201, description = "Created", body = ProfileDto),
        (status = 400, description = "Invalid name, lists or rules"),
        (status = 403, description = "Token is restricted to specific profiles"),
        (status = 409, description = "Name already in use"),
    )
)]
pub async fn create_profile(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiJson(req): ApiJson<CreateProfileRequest>,
) -> ApiResult<(StatusCode, Json<ProfileDto>)> {
    if p.profiles.is_some() {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "profile_restricted",
            "A profile-restricted token cannot create profiles",
        ));
    }
    req.validate()?;
    let st = state.clone();
    let rec = blocking(move || {
        check_lists(&st, &req.lists)?;
        let now = Utc::now();
        Ok(st.profiles.put(ProfileRecord {
            id: 0,
            name: req.name,
            description: req.description,
            lists: req.lists,
            rules: req.rules,
            created_at: now,
            updated_at: now,
        })?)
    })
    .await?;
    info!("Profile {} created by {}", rec.id, p.username);
    Ok((StatusCode::CREATED, Json(profile_dto(&state, &rec))))
}

/// Get one profile.
#[utoipa::path(
    get, path = "/profiles/{profile_id}", tag = "profiles",
    security(("bearer_auth" = ["profiles:read"])),
    params(("profile_id" = String, Path, description = "Profile id (decimal; 0 is the default profile)")),
    responses(
        (status = 200, description = "Profile", body = ProfileDto),
        (status = 403, description = "Token is not allowed to access this profile"),
        (status = 404, description = "No such profile"),
    )
)]
pub async fn get_profile(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
) -> ApiResult<Json<ProfileDto>> {
    let st = state.clone();
    let rec = blocking(move || Ok(st.profiles.get(profile.id)?)).await?;
    let rec = rec.ok_or_else(|| ApiError::NotFound("Profile not found".into()))?;
    Ok(Json(profile_dto(&state, &rec)))
}

/// Update a profile; omitted fields are unchanged. The default profile cannot be changed here
/// (its lists and rules are the global ones).
#[utoipa::path(
    put, path = "/profiles/{profile_id}", tag = "profiles",
    security(("bearer_auth" = ["profiles:write"])),
    params(("profile_id" = String, Path, description = "Profile id (decimal)")),
    request_body = UpdateProfileRequest,
    responses(
        (status = 200, description = "Updated", body = ProfileDto),
        (status = 400, description = "Invalid input, or the default profile"),
        (status = 403, description = "Token is not allowed to access this profile"),
        (status = 404, description = "No such profile"),
        (status = 409, description = "Name already in use"),
    )
)]
pub async fn update_profile(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    profile: ProfileParam,
    ApiJson(req): ApiJson<UpdateProfileRequest>,
) -> ApiResult<Json<ProfileDto>> {
    if profile.id == 0 {
        return Err(default_protected("changed"));
    }
    req.validate()?;
    let st = state.clone();
    let id = profile.id;
    let rec = blocking(move || {
        if let Some(l) = &req.lists {
            check_lists(&st, l)?;
        }
        Ok(st.profiles.modify(id, |rec| {
            if let Some(n) = req.name {
                rec.name = n;
            }
            if let Some(d) = req.description {
                rec.description = d;
            }
            if let Some(l) = req.lists {
                rec.lists = l;
            }
            if let Some(r) = req.rules {
                rec.rules = r;
            }
            Ok(())
        })?)
    })
    .await?;
    info!("Profile {id} updated by {}", p.username);
    Ok(Json(profile_dto(&state, &rec)))
}

/// Delete a profile. Refused (409) while devices are assigned to it.
#[utoipa::path(
    delete, path = "/profiles/{profile_id}", tag = "profiles",
    security(("bearer_auth" = ["profiles:write"])),
    params(("profile_id" = String, Path, description = "Profile id (decimal)")),
    responses(
        (status = 200, description = "Deleted", body = MessageResponse),
        (status = 400, description = "The default profile cannot be deleted"),
        (status = 403, description = "Token is not allowed to access this profile"),
        (status = 404, description = "No such profile"),
        (status = 409, description = "Devices are assigned to the profile"),
    )
)]
pub async fn delete_profile(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    profile: ProfileParam,
) -> ApiResult<Json<MessageResponse>> {
    if profile.id == 0 {
        return Err(default_protected("deleted"));
    }
    let st = state.clone();
    let id = profile.id;
    if !blocking(move || Ok(st.profiles.delete(id)?)).await? {
        return Err(ApiError::NotFound("Profile not found".into()));
    }
    info!("Profile {id} deleted by {}", p.username);
    Ok(Json(MessageResponse {
        message: "Profile deleted".into(),
    }))
}

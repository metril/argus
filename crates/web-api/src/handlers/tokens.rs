//! API token handlers.

use std::sync::Arc;

use api_types::{
    ApiTokenInfo, CreateTokenRequest, CreatedTokenResponse, MessageResponse, Page,
    RegenerateTokenRequest, Scope, UpdateTokenRequest,
};
use axum::{extract::State, http::StatusCode, Extension, Json};
use chrono::{DateTime, Duration, Utc};
use tracing::info;
use uuid::Uuid;
use validator::Validate;

use super::paging::{page_of, ts_key_desc, Keyed};
use super::CursorQuery;
use crate::auth::authz::{Actor, Principal};
use crate::auth::profile::parse_profile_id;
use crate::auth::tokens::{StoredToken, TokenUpdate};
use crate::error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult};
use crate::state::{blocking, AppState};

/// Validated token settings: the sorted, de-duplicated scopes and the profile restriction.
type Grant = (Vec<Scope>, Option<Vec<String>>);

/// The one grant check, shared by creation and edit: every scope must be held by the caller, a
/// restricted caller cannot widen the profile restriction, and every profile id must exist.
/// Narrowing always passes. `profiles: None` inherits the caller's own restriction.
async fn check_grant(
    state: &Arc<AppState>,
    p: &Principal,
    scopes: &[Scope],
    profiles: Option<Vec<String>>,
) -> ApiResult<Grant> {
    if scopes.is_empty() {
        return Err(ApiError::ValidationError(
            "A token needs at least one scope".into(),
        ));
    }
    if let Some(s) = scopes.iter().find(|s| !p.has(**s)) {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "scope_escalation",
            format!("Cannot grant scope '{s}' that you do not hold"),
        ));
    }
    let mut scopes = scopes.to_vec();
    scopes.sort();
    scopes.dedup();
    let profiles = check_profiles(state, p, profiles).await?;
    Ok((scopes, profiles))
}

/// The profile half of [`check_grant`].
async fn check_profiles(
    state: &Arc<AppState>,
    p: &Principal,
    wanted: Option<Vec<String>>,
) -> ApiResult<Option<Vec<String>>> {
    // A token cannot widen its own profile restriction either.
    if let (Some(mine), Some(wanted)) = (&p.profiles, &wanted) {
        if wanted.iter().any(|w| !mine.contains(w)) {
            return Err(profile_escalation());
        }
    }
    if let Some(ids) = &wanted {
        for raw in ids {
            let id = parse_profile_id(raw)?;
            let st = state.clone();
            if blocking(move || Ok(st.profiles.get(id)?)).await?.is_none() {
                return Err(ApiError::ValidationError(format!(
                    "Profile {id} does not exist"
                )));
            }
        }
    }
    Ok(wanted.or_else(|| p.profiles.clone()))
}

fn profile_escalation() -> ApiError {
    ApiError::coded(
        StatusCode::FORBIDDEN,
        "scope_escalation",
        "Cannot grant access to profiles you are not restricted to",
    )
}

/// Parse the expiry options. `None`: no option given; `Some(None)`: never expires.
fn parse_expiry(
    in_days: Option<u32>,
    at: Option<&str>,
    never: bool,
) -> ApiResult<Option<Option<DateTime<Utc>>>> {
    if usize::from(in_days.is_some()) + usize::from(at.is_some()) + usize::from(never) > 1 {
        return Err(ApiError::ValidationError(
            "Give only one of expires_in_days, expires_at and never_expires".into(),
        ));
    }
    Ok(match (in_days, at) {
        (Some(d), _) => Some(Some(Utc::now() + Duration::days(d as i64))),
        (None, Some(at)) => {
            let at = DateTime::parse_from_rfc3339(at)
                .map_err(|_| ApiError::ValidationError("expires_at must be RFC 3339".into()))?
                .with_timezone(&Utc);
            if at <= Utc::now() {
                return Err(ApiError::ValidationError(
                    "expires_at must be in the future".into(),
                ));
            }
            Some(Some(at))
        }
        (None, None) => never.then_some(None),
    })
}

/// Create an API token. The secret is returned once and cannot be retrieved again. Requested
/// scopes must all be held by the caller (a token can never mint more than it has), and
/// `profiles` must name existing profiles within the caller's own restriction.
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
    let (scopes, profiles) = check_grant(&state, &p, &req.scopes, req.profiles).await?;
    let expires = parse_expiry(req.expires_in_days, req.expires_at.as_deref(), false)?.flatten();
    let purpose = req.purpose.unwrap_or_default();
    let st = state.clone();
    let (user_id, username) = (p.user_id, p.username.clone());
    let (token, secret) = blocking(move || {
        st.tokens.create(
            req.name, scopes, profiles, user_id, username, expires, purpose,
        )
    })
    .await?;
    info!("API token {} created for {}", token.id, p.username);
    Ok((
        StatusCode::CREATED,
        Json(CreatedTokenResponse { token, secret }),
    ))
}

fn outside_grant() -> ApiError {
    ApiError::coded(
        StatusCode::FORBIDDEN,
        "token_outside_grant",
        "That token holds more than the token you are using; use a session or a broader token",
    )
}

/// A token caller may only act on a token whose current grant is within its own: every scope
/// held, no scope this release does not know, and, for a profile-restricted caller, a profile
/// restriction that is a subset of its own. Sessions are bounded by [`check_grant`] alone.
fn require_within(p: &Principal, target: &StoredToken) -> ApiResult<()> {
    if !p.is_token() {
        return Ok(());
    }
    let scopes_ok = target.unknown_scopes.is_empty() && target.scopes.iter().all(|s| p.has(*s));
    let profiles_ok = match (&p.profiles, &target.profiles) {
        (None, _) => true,
        (Some(mine), Some(theirs)) => theirs.iter().all(|t| mine.contains(t)),
        (Some(_), None) => false,
    };
    if scopes_ok && profiles_ok {
        Ok(())
    } else {
        Err(outside_grant())
    }
}

/// A token caller may not give a token a lifetime beyond its own: `resulting` must be a date no
/// later than the caller token's expiry, and "never" is refused when the caller expires.
fn require_expiry_bound(
    state: &Arc<AppState>,
    p: &Principal,
    resulting: Option<DateTime<Utc>>,
) -> ApiResult<()> {
    let Actor::Token { token_id } = &p.actor else {
        return Ok(());
    };
    let Some(mine) = state.tokens.get(token_id).and_then(|t| t.stored.expires_at) else {
        return Ok(());
    };
    if resulting.is_some_and(|r| r <= mine) {
        Ok(())
    } else {
        Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "expiry_outside_grant",
            "A token cannot outlive the token you are using",
        ))
    }
}

/// The target of an edit: it must exist and belong to `owner` when one is given.
fn find_target(
    state: &Arc<AppState>,
    id: &str,
    owner: Option<Uuid>,
) -> ApiResult<Arc<crate::auth::tokens::CachedToken>> {
    match state.tokens.get(id) {
        Some(t) if owner.is_none_or(|o| t.stored.created_by == o) => Ok(t),
        _ => Err(ApiError::NotFound("Token not found".into())),
    }
}

/// Apply an edit after the grant checks. `owner` limits it to one user's tokens.
async fn apply_update(
    state: &Arc<AppState>,
    p: &Principal,
    id: String,
    req: UpdateTokenRequest,
    owner: Option<Uuid>,
) -> ApiResult<Json<ApiTokenInfo>> {
    req.validate()?;
    let target = find_target(state, &id, owner)?;
    require_within(p, &target.stored)?;
    let scopes = match req.scopes {
        Some(s) => Some(check_grant(state, p, &s, None).await?.0),
        None => None,
    };
    let profiles = if req.clear_profiles {
        if req.profiles.is_some() {
            return Err(ApiError::ValidationError(
                "Give either profiles or clear_profiles, not both".into(),
            ));
        }
        if p.profiles.is_some() {
            return Err(profile_escalation());
        }
        Some(None)
    } else if let Some(wanted) = req.profiles {
        Some(check_profiles(state, p, Some(wanted)).await?)
    } else {
        None
    };
    let expires_at = parse_expiry(
        req.expires_in_days,
        req.expires_at.as_deref(),
        req.never_expires,
    )?;
    if let Some(e) = expires_at {
        require_expiry_bound(state, p, e)?;
    }
    // Widening a token must not leave the extra access alive past the caller's own expiry.
    let cur = &target.stored;
    let widens_scopes = scopes
        .as_ref()
        .is_some_and(|s| s.iter().any(|x| !cur.scopes.contains(x)));
    let widens_profiles = match (&profiles, &cur.profiles) {
        (Some(None), Some(_)) => true,
        (Some(Some(new)), Some(old)) => new.iter().any(|n| !old.contains(n)),
        _ => false,
    };
    if widens_scopes || widens_profiles {
        require_expiry_bound(state, p, expires_at.unwrap_or(cur.expires_at))?;
    }
    let changes = TokenUpdate {
        name: req.name,
        scopes,
        profiles,
        purpose: req.purpose,
        expires_at,
    };
    let st = state.clone();
    let tid = id.clone();
    let info = blocking(move || st.tokens.update(&tid, changes)).await?;
    info!("API token {id} updated by {}", p.username);
    Ok(Json(info))
}

/// Change one of your own tokens: name, scopes, profiles or expiry. Scopes and profiles are
/// checked like on creation; a token can be narrowed but never widened beyond what you hold.
/// A token caller can only edit tokens within its own grant and cannot extend a lifetime past
/// its own. An expired token cannot be edited (409): regenerate it with a new expiry.
#[utoipa::path(
    patch, path = "/tokens/{id}", tag = "tokens",
    security(("bearer_auth" = ["tokens:self"])),
    params(("id" = String, Path, description = "Token id")),
    request_body = UpdateTokenRequest,
    responses((status = 200, description = "Updated", body = ApiTokenInfo))
)]
pub async fn update_token(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<UpdateTokenRequest>,
) -> ApiResult<Json<ApiTokenInfo>> {
    let owner = p.user_id;
    apply_update(&state, &p, id, req, Some(owner)).await
}

/// Change any user's token. Scopes and profiles are still limited to what the caller holds.
#[utoipa::path(
    patch, path = "/admin/tokens/{id}", tag = "tokens",
    security(("bearer_auth" = ["tokens:admin"])),
    params(("id" = String, Path, description = "Token id")),
    request_body = UpdateTokenRequest,
    responses((status = 200, description = "Updated", body = ApiTokenInfo))
)]
pub async fn admin_update_token(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<UpdateTokenRequest>,
) -> ApiResult<Json<ApiTokenInfo>> {
    apply_update(&state, &p, id, req, None).await
}

/// Issue a new secret for one of your own tokens (same id and settings). The new secret is
/// returned once. The old secret keeps working for `grace_secs` (0 to 7 days, default 0), then
/// stops; revoking the token ends both. An expired token needs a new expiry in the request
/// (`expires_in_days`, `expires_at` or `never_expires`), else 409; on a live token they are
/// optional and replace the expiry. A token caller can only regenerate a token within its own
/// grant, with a lifetime no longer than its own.
#[utoipa::path(
    post, path = "/tokens/{id}/regenerate", tag = "tokens",
    security(("bearer_auth" = ["tokens:self"])),
    params(("id" = String, Path, description = "Token id")),
    request_body = RegenerateTokenRequest,
    responses((status = 200, description = "New secret; shown only here", body = CreatedTokenResponse))
)]
pub async fn regenerate_token(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<RegenerateTokenRequest>,
) -> ApiResult<Json<CreatedTokenResponse>> {
    req.validate()?;
    let target = find_target(&state, &id, Some(p.user_id))?;
    require_within(&p, &target.stored)?;
    let new_expiry = parse_expiry(
        req.expires_in_days,
        req.expires_at.as_deref(),
        req.never_expires,
    )?;
    let now = Utc::now();
    let resulting = new_expiry.unwrap_or(target.stored.expires_at);
    // Only a live, still-valid lifetime is bounded here; the store refuses an expired token
    // without a new expiry.
    if new_expiry.is_some() || resulting.is_none_or(|t| t > now) {
        require_expiry_bound(&state, &p, resulting)?;
    }
    let st = state.clone();
    let tid = id.clone();
    let (token, secret) =
        blocking(move || st.tokens.regenerate(&tid, req.grace_secs, now, new_expiry)).await?;
    info!("API token {id} regenerated by {}", p.username);
    Ok(Json(CreatedTokenResponse { token, secret }))
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

/// Paging plus the revoked-token switch.
#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TokensQuery {
    /// Deprecated: use `cursor`.
    pub page: Option<u32>,
    /// Items per page, 1..=200 (default 50).
    pub limit: Option<u32>,
    /// `next_cursor` of the previous page.
    pub cursor: Option<String>,
    /// Also list revoked tokens (default false).
    #[serde(default)]
    pub include_revoked: bool,
}

impl TokensQuery {
    fn cursor(&self) -> CursorQuery {
        CursorQuery {
            page: self.page,
            limit: self.limit,
            cursor: self.cursor.clone(),
        }
    }
}

/// List your own API tokens (never includes secrets). Revoked tokens only with
/// `include_revoked=true`.
#[utoipa::path(
    get, path = "/tokens", tag = "tokens",
    security(("bearer_auth" = ["tokens:self"])),
    params(TokensQuery),
    responses((status = 200, description = "Your tokens", body = Page<ApiTokenInfo>))
)]
pub async fn list_tokens(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiQuery(q): ApiQuery<TokensQuery>,
) -> ApiResult<Json<Page<ApiTokenInfo>>> {
    let (st, uid, all) = (state.clone(), p.user_id, q.include_revoked);
    let tokens = blocking(move || Ok(st.tokens.list(Some(&uid), all))).await?;
    Ok(Json(page_of(token_rows(tokens), &q.cursor())?))
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
            let tid = id.clone();
            blocking(move || st.tokens.revoke(&tid)).await?;
            state.close_ext_tokens(&[id]);
            Ok(Json(MessageResponse {
                message: "Token revoked".into(),
            }))
        }
        _ => Err(ApiError::NotFound("Token not found".into())),
    }
}

/// Revoke the token making this request (the extension's sign out). Cookie sessions have no
/// token to revoke; they use `/auth/logout`.
#[utoipa::path(
    delete, path = "/tokens/self", tag = "tokens",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Revoked; the token stops working at once", body = MessageResponse),
        (status = 400, description = "The caller is a cookie session, not an API token")
    )
)]
pub async fn revoke_self(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Json<MessageResponse>> {
    let Actor::Token { token_id } = p.actor else {
        return Err(ApiError::bad_request(
            "Only an API token can revoke itself; use /auth/logout for a session",
        ));
    };
    let (st, id) = (state.clone(), token_id.clone());
    blocking(move || st.tokens.revoke(&id)).await?;
    state.close_ext_tokens(&[token_id]);
    Ok(Json(MessageResponse {
        message: "Token revoked".into(),
    }))
}

/// List every user's API tokens. Revoked tokens only with `include_revoked=true`.
#[utoipa::path(
    get, path = "/admin/tokens", tag = "tokens",
    security(("bearer_auth" = ["tokens:admin"])),
    params(TokensQuery),
    responses((status = 200, description = "All tokens", body = Page<ApiTokenInfo>))
)]
pub async fn admin_list_tokens(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<TokensQuery>,
) -> ApiResult<Json<Page<ApiTokenInfo>>> {
    let (st, all) = (state.clone(), q.include_revoked);
    let tokens = blocking(move || Ok(st.tokens.list(None, all))).await?;
    Ok(Json(page_of(token_rows(tokens), &q.cursor())?))
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
    let tid = id.clone();
    if blocking(move || st.tokens.revoke(&tid)).await? {
        state.close_ext_tokens(&[id]);
        Ok(Json(MessageResponse {
            message: "Token revoked".into(),
        }))
    } else {
        Err(ApiError::NotFound("Token not found".into()))
    }
}

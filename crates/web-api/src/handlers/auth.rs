//! Authentication, password change and session handlers.

use std::sync::Arc;

use api_types::{
    ChangePasswordRequest, ExtensionTokenRequest, ExtensionTokenResponse, LoginRequest,
    LoginResponse, MessageResponse, Page, RegisterRequest, RegistrationStatus, SessionInfo,
    UserInfo, UserRole,
};
use axum::{
    extract::State,
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    Extension,
};
use cookie::time::Duration;
use cookie::{Cookie, SameSite};
use tracing::{info, warn};
use uuid::Uuid;
use validator::Validate;

use super::paging::{page_of, ts_key_desc, Keyed};
use super::{parse_uuid, CursorQuery};
use crate::auth::authz::{refresh_cookie, AuditActor, Principal};
use crate::auth::csrf::{token_for, CSRF_COOKIE};
use crate::auth::jwt::{generate_token_pair, validate_refresh_token};
use crate::auth::middleware::{ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE};
use crate::auth::models::User;
use crate::auth::password::{hash_password, validate_password_strength, verify_password};
use crate::auth::session::{RotateOutcome, SessionData};
use crate::error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult};
use crate::middleware::ClientInfo;
use crate::state::{blocking, AppState};

fn cookie_string(
    name: &'static str,
    value: &str,
    max_age: u64,
    secure: bool,
    http_only: bool,
) -> String {
    Cookie::build((name, value))
        .http_only(http_only)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(max_age as i64))
        .path("/")
        .to_string()
}

fn set_cookie(headers: &mut HeaderMap, value: String) {
    if let Ok(v) = HeaderValue::from_str(&value) {
        headers.append(SET_COOKIE, v);
    }
}

/// Run bcrypt off the async executor threads.
async fn hash_blocking(password: String, cost: u32) -> ApiResult<String> {
    tokio::task::spawn_blocking(move || hash_password(&password, cost))
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
}

async fn verify_blocking(password: String, hash: String) -> ApiResult<bool> {
    tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
}

/// Start a session for `user`: persist it and build the cookie headers (access, refresh, CSRF).
fn start_session(
    state: &AppState,
    user: &User,
    client: &ClientInfo,
) -> ApiResult<(HeaderMap, u64)> {
    let sid = Uuid::new_v4();
    let tokens = generate_token_pair(&user.id, &user.username, user.role, &sid, &state.jwt_config)?;
    state.session_manager.create_session(
        sid,
        user.id,
        user.username.clone(),
        tokens.refresh_jti.clone(),
        client.ip,
        client.user_agent.clone(),
        tokens.refresh_expires_in,
    )?;
    Ok((
        session_cookies(state, client, &tokens, &sid),
        tokens.access_expires_in,
    ))
}

/// [`start_session`] on the blocking pool (the session is committed to disk).
async fn start_session_blocking(
    state: &Arc<AppState>,
    user: User,
    client: ClientInfo,
) -> ApiResult<(HeaderMap, u64)> {
    let st = state.clone();
    blocking(move || start_session(&st, &user, &client)).await
}

/// Cookie names keep their plain spelling: the `__Host-` prefix needs `Secure`, which is off for
/// plain-HTTP access, and the SPA reads `csrf_token` by name, so the names stay as they are.
fn session_cookies(
    state: &AppState,
    client: &ClientInfo,
    t: &crate::auth::TokenPair,
    sid: &Uuid,
) -> HeaderMap {
    let secure = state
        .api_config
        .security
        .cookie_secure
        .applies(client.https);
    let mut h = HeaderMap::new();
    set_cookie(
        &mut h,
        cookie_string(
            ACCESS_TOKEN_COOKIE,
            &t.access_token,
            t.access_expires_in,
            secure,
            true,
        ),
    );
    set_cookie(
        &mut h,
        cookie_string(
            REFRESH_TOKEN_COOKIE,
            &t.refresh_token,
            t.refresh_expires_in,
            secure,
            true,
        ),
    );
    // Readable by the SPA, which echoes it in `X-CSRF-Token`.
    set_cookie(
        &mut h,
        cookie_string(
            CSRF_COOKIE,
            &token_for(&state.jwt_config.secret, sid),
            t.refresh_expires_in,
            secure,
            false,
        ),
    );
    h
}

fn expired_cookies(secure: bool) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (name, http_only) in [
        (ACCESS_TOKEN_COOKIE, true),
        (REFRESH_TOKEN_COOKIE, true),
        (CSRF_COOKIE, false),
    ] {
        set_cookie(&mut h, cookie_string(name, "", 0, secure, http_only));
    }
    h
}

fn msg(m: &str) -> axum::Json<MessageResponse> {
    axum::Json(MessageResponse {
        message: m.to_string(),
    })
}

type Authed = (Extension<AuditActor>, HeaderMap, axum::Json<LoginResponse>);

/// Whether first-run registration is still open. Public: the login page uses it to offer
/// "create admin account" or "registration closed".
#[utoipa::path(
    get, path = "/auth/registration", tag = "auth",
    security(()),
    responses((status = 200, description = "Registration status", body = RegistrationStatus))
)]
pub async fn registration_status(
    State(state): State<Arc<AppState>>,
) -> ApiResult<axum::Json<RegistrationStatus>> {
    let st = state.clone();
    let none = blocking(move || Ok(st.session_store.get_all_users()?.is_empty())).await?;
    Ok(axum::Json(RegistrationStatus {
        open: none,
        first_run: none,
    }))
}

/// Register the first account (it becomes the administrator). Closed once any user exists;
/// further accounts are created by an administrator via `POST /users`.
#[utoipa::path(
    post, path = "/auth/register", tag = "auth",
    security(()),
    request_body = RegisterRequest,
    responses(
        (status = 200, description = "Registered and logged in", body = LoginResponse),
        (status = 403, description = "Registration is closed"),
    )
)]
pub async fn register(
    State(state): State<Arc<AppState>>,
    Extension(client): Extension<ClientInfo>,
    ApiJson(req): ApiJson<RegisterRequest>,
) -> ApiResult<Authed> {
    req.validate()?;
    validate_password_strength(&req.password)?;
    let hash = hash_blocking(req.password.clone(), state.api_config.auth.bcrypt_cost).await?;

    let user = {
        let st = state.clone();
        let username = req.username.clone();
        blocking(move || {
            let _g = st.session_store.admin_lock.lock();
            if !st.session_store.get_all_users()?.is_empty() {
                return Err(ApiError::coded(
                    StatusCode::FORBIDDEN,
                    "registration_closed",
                    "Registration is closed; ask an administrator to create your account",
                ));
            }
            let user = User::new(username, hash, UserRole::Admin);
            st.session_store.store_user(&user)?;
            Ok(user)
        })
        .await?
    };
    info!("First user registered as admin: {}", user.username);

    let (headers, expires_in) = start_session_blocking(&state, user.clone(), client).await?;
    Ok((
        Extension(AuditActor {
            id: Some(user.id.to_string()),
            name: user.username.clone(),
        }),
        headers,
        axum::Json(LoginResponse {
            user: UserInfo::from(&user),
            expires_in,
            message: "Registration successful".into(),
        }),
    ))
}

/// Log in with a username and password; sets session cookies.
#[utoipa::path(
    post, path = "/auth/login", tag = "auth",
    security(()),
    request_body = LoginRequest,
    responses((status = 200, description = "Logged in; sets access_token, refresh_token and csrf_token cookies", body = LoginResponse))
)]
pub async fn login(
    State(state): State<Arc<AppState>>,
    Extension(client): Extension<ClientInfo>,
    ApiJson(req): ApiJson<LoginRequest>,
) -> ApiResult<Authed> {
    req.validate()?;
    let bad = || ApiError::AuthenticationFailed("Invalid username or password".into());
    let (st, name) = (state.clone(), req.username.clone());
    let found = blocking(move || st.session_store.get_user_by_username(&name)).await?;
    // Always run one bcrypt verification (against a dummy hash when the account is missing or
    // disabled) so response time does not reveal which usernames exist, and answer every
    // failure identically.
    let user = found.filter(|u| u.enabled);
    let hash = user
        .as_ref()
        .map_or_else(|| state.dummy_hash.clone(), |u| u.password_hash.clone());
    let ok = verify_blocking(req.password.clone(), hash).await?;
    let Some(user) = user.filter(|_| ok) else {
        warn!("Failed login attempt");
        return Err(bad());
    };
    let (headers, expires_in) = start_session_blocking(&state, user.clone(), client).await?;
    state.session_store.update_last_login(&user.id)?;
    info!("User logged in: {}", user.username);
    Ok((
        Extension(AuditActor {
            id: Some(user.id.to_string()),
            name: user.username.clone(),
        }),
        headers,
        axum::Json(LoginResponse {
            user: UserInfo::from(&user),
            expires_in,
            message: "Login successful".into(),
        }),
    ))
}

/// Scopes of an extension token: what the popup and the userscript bridge need, nothing else.
const EXTENSION_SCOPES: [api_types::Scope; 5] = [
    api_types::Scope::LogsRead,
    api_types::Scope::UserscriptsBridge,
    api_types::Scope::StatsRead,
    api_types::Scope::RulesSite,
    api_types::Scope::RulesExt,
];

/// Sign in from the browser extension: the same credential check and rate limit as login, but no
/// session or cookies. Mints a token named `Extension · {browser}` (no expiry) with just the
/// scopes the extension needs, and revokes `replace_token_id` if it is the caller's own.
#[utoipa::path(
    post, path = "/auth/extension-token", tag = "auth",
    security(()),
    request_body = ExtensionTokenRequest,
    responses(
        (status = 200, description = "Token minted; `token` is shown only here", body = ExtensionTokenResponse),
        (status = 403, description = "Code `insufficient_role`: the account's role cannot use the extension. Wrong credentials answer 401 like login.")
    )
)]
pub async fn extension_token(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<ExtensionTokenRequest>,
) -> ApiResult<(Extension<AuditActor>, axum::Json<ExtensionTokenResponse>)> {
    req.validate()?;
    let browser = req.browser.trim().to_string();
    if browser.is_empty()
        || !browser
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '.' | '-' | '_'))
    {
        return Err(ApiError::ValidationError(
            "Browser may only contain letters, digits, spaces, . - and _".into(),
        ));
    }
    let (st, name) = (state.clone(), req.username.clone());
    let found = blocking(move || st.session_store.get_user_by_username(&name)).await?;
    // Same constant-work credential check as `login`.
    let user = found.filter(|u| u.enabled);
    let hash = user
        .as_ref()
        .map_or_else(|| state.dummy_hash.clone(), |u| u.password_hash.clone());
    let ok = verify_blocking(req.password.clone(), hash).await?;
    let Some(user) = user.filter(|_| ok) else {
        warn!("Failed extension sign-in attempt");
        return Err(ApiError::AuthenticationFailed(
            "Invalid username or password".into(),
        ));
    };
    let held = user.role.scopes();
    if EXTENSION_SCOPES.iter().any(|s| !held.contains(s)) {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "insufficient_role",
            "Your role can't use the browser extension. Ask an admin for the User role.",
        ));
    }
    let (st, uid, uname) = (state.clone(), user.id, user.username.clone());
    let replace = req.replace_token_id.clone();
    let (info, secret, replaced) = blocking(move || {
        // Create first, so a failure never leaves the user without a token.
        let (info, secret) = st.tokens.create(
            format!("Extension · {browser}"),
            EXTENSION_SCOPES.to_vec(),
            None,
            uid,
            uname,
            None,
        )?;
        // Only the caller's own extension tokens may be replaced.
        let want = EXTENSION_SCOPES.to_vec();
        let replaced = match replace {
            Some(id)
                if st.tokens.get(&id).is_some_and(|t| {
                    // A subset: tokens minted by an older version (fewer scopes) upgrade here.
                    t.stored.created_by == uid
                        && t.stored.name.starts_with("Extension · ")
                        && t.stored.scopes.iter().all(|s| want.contains(s))
                }) =>
            {
                st.tokens.revoke(&id)?;
                Some(id)
            }
            _ => None,
        };
        Ok((info, secret, replaced))
    })
    .await?;
    if let Some(id) = replaced {
        state.close_ext_tokens(&[id]);
    }
    state.session_store.update_last_login(&user.id)?;
    info!("Extension token {} created for {}", info.id, user.username);
    Ok((
        Extension(AuditActor {
            id: Some(user.id.to_string()),
            name: user.username.clone(),
        }),
        axum::Json(ExtensionTokenResponse {
            token: secret,
            token_id: info.id,
            user: UserInfo::from(&user),
        }),
    ))
}

/// Exchange the refresh cookie for a new token pair (rotating the refresh token).
#[utoipa::path(
    post, path = "/auth/refresh", tag = "auth",
    security(()),
    responses((status = 200, description = "Tokens refreshed", body = MessageResponse))
)]
pub async fn refresh(
    State(state): State<Arc<AppState>>,
    Extension(client): Extension<ClientInfo>,
    headers: HeaderMap,
) -> ApiResult<(HeaderMap, axum::Json<MessageResponse>)> {
    let token = refresh_cookie(&headers)
        .ok_or_else(|| ApiError::AuthenticationFailed("No refresh token provided".into()))?;
    let claims = validate_refresh_token(&token, &state.jwt_config)?;
    let sid = parse_uuid(&claims.sid)
        .map_err(|_| ApiError::AuthenticationFailed("Invalid session".into()))?;
    let user_id = parse_uuid(&claims.sub)
        .map_err(|_| ApiError::AuthenticationFailed("Invalid token".into()))?;
    let user = state
        .session_store
        .get_user(&user_id)?
        .filter(|u| u.enabled)
        .ok_or_else(|| ApiError::AuthenticationFailed("Account is disabled or deleted".into()))?;

    let tokens = generate_token_pair(&user.id, &user.username, user.role, &sid, &state.jwt_config)?;
    let outcome = {
        let st = state.clone();
        let (jti, new_jti) = (claims.jti.clone(), tokens.refresh_jti.clone());
        blocking(move || st.session_manager.rotate(&sid, &jti, new_jti)).await?
    };
    match outcome {
        RotateOutcome::Rotated => {}
        RotateOutcome::Reused => {
            warn!(
                "Refresh token replay for user {}; session revoked",
                user.username
            );
            return Err(ApiError::AuthenticationFailed(
                "Refresh token was already used".into(),
            ));
        }
        RotateOutcome::Missing => {
            return Err(ApiError::AuthenticationFailed("Session has ended".into()));
        }
    }
    Ok((
        session_cookies(&state, &client, &tokens, &sid),
        msg("Token refreshed"),
    ))
}

/// End the current session (both its tokens stop working immediately).
#[utoipa::path(
    post, path = "/auth/logout", tag = "auth",
    security(("bearer_auth" = ["sessions:self"])),
    responses((status = 200, description = "Logged out", body = MessageResponse))
)]
pub async fn logout(
    State(state): State<Arc<AppState>>,
    Extension(client): Extension<ClientInfo>,
    Extension(p): Extension<Principal>,
) -> ApiResult<(HeaderMap, axum::Json<MessageResponse>)> {
    let sid = p.session_id().ok_or_else(|| {
        ApiError::bad_request(
            "Logout applies to cookie sessions; revoke API tokens via DELETE /tokens/{id}",
        )
    })?;
    let st = state.clone();
    blocking(move || st.session_manager.revoke_session(&sid)).await?;
    let secure = state
        .api_config
        .security
        .cookie_secure
        .applies(client.https);
    Ok((expired_cookies(secure), msg("Logged out successfully")))
}

/// The authenticated caller, with its effective scopes.
#[utoipa::path(
    get, path = "/auth/me", tag = "auth",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "Current user", body = UserInfo))
)]
pub async fn me(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
) -> ApiResult<axum::Json<UserInfo>> {
    let user = state
        .session_store
        .get_user(&p.user_id)?
        .ok_or_else(|| ApiError::NotFound("User not found".into()))?;
    let mut info = UserInfo::from(&user);
    info.scopes = p.scopes.iter().copied().collect();
    Ok(axum::Json(info))
}

/// Change your password; all your other sessions are revoked.
#[utoipa::path(
    post, path = "/auth/password", tag = "auth",
    security(("bearer_auth" = ["sessions:self"])),
    request_body = ChangePasswordRequest,
    responses((status = 200, description = "Password changed", body = MessageResponse))
)]
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiJson(req): ApiJson<ChangePasswordRequest>,
) -> ApiResult<axum::Json<MessageResponse>> {
    req.validate()?;
    validate_password_strength(&req.new_password)?;
    let mut user = state
        .session_store
        .get_user(&p.user_id)?
        .ok_or_else(|| ApiError::NotFound("User not found".into()))?;
    if !verify_blocking(req.current_password.clone(), user.password_hash.clone()).await? {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "invalid_credentials",
            "Current password is incorrect",
        ));
    }
    user.password_hash = hash_blocking(req.new_password, state.api_config.auth.bcrypt_cost).await?;
    let sid = p.session_id();
    let st = state.clone();
    blocking(move || {
        st.session_store.store_user(&user)?;
        st.session_manager
            .revoke_user_sessions(&user.id, sid.as_ref())
    })
    .await?;
    Ok(msg("Password changed; other sessions were signed out"))
}

fn session_info(id: &Uuid, s: &SessionData, current: Option<Uuid>) -> SessionInfo {
    SessionInfo {
        id: id.to_string(),
        created_at: s.created_at.to_rfc3339(),
        last_activity: s.last_activity.to_rfc3339(),
        user_agent: s.user_agent.clone(),
        ip_address: s.ip_address.map(|ip| ip.to_string()),
        user_id: s.user_id.to_string(),
        username: s.username.clone(),
        current: current == Some(*id),
    }
}

/// Sessions as paging rows, newest first.
fn session_rows(all: Vec<SessionInfo>) -> Vec<Keyed<SessionInfo>> {
    all.into_iter()
        .map(|s| Keyed {
            key: ts_key_desc(&s.created_at),
            id: s.id.clone(),
            label: s.username.clone(),
            item: s,
        })
        .collect()
}

/// List your own sessions.
#[utoipa::path(
    get, path = "/auth/sessions", tag = "sessions",
    security(("bearer_auth" = ["sessions:self"])),
    params(CursorQuery),
    responses((status = 200, description = "Your sessions", body = Page<SessionInfo>))
)]
pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiQuery(q): ApiQuery<CursorQuery>,
) -> ApiResult<axum::Json<Page<SessionInfo>>> {
    let cur = p.session_id();
    let all = state
        .session_manager
        .get_user_sessions(&p.user_id)
        .iter()
        .map(|(id, s)| session_info(id, s, cur))
        .collect();
    Ok(axum::Json(page_of(session_rows(all), &q)?))
}

/// Revoke one of your own sessions.
#[utoipa::path(
    delete, path = "/auth/sessions/{id}", tag = "sessions",
    security(("bearer_auth" = ["sessions:self"])),
    params(("id" = String, Path, description = "Session id")),
    responses((status = 200, description = "Revoked", body = MessageResponse))
)]
pub async fn revoke_session(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<axum::Json<MessageResponse>> {
    let sid = parse_uuid(&id)?;
    match state.session_manager.get_session(&sid) {
        Some(s) if s.user_id == p.user_id => {
            let st = state.clone();
            blocking(move || st.session_manager.revoke_session(&sid)).await?;
            Ok(msg("Session revoked"))
        }
        _ => Err(ApiError::NotFound("Session not found".into())),
    }
}

#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AdminSessionsQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
    /// Only this user's sessions.
    pub user_id: Option<String>,
}

/// List every user's sessions.
#[utoipa::path(
    get, path = "/admin/sessions", tag = "sessions",
    security(("bearer_auth" = ["sessions:admin"])),
    params(AdminSessionsQuery),
    responses((status = 200, description = "Sessions", body = Page<SessionInfo>))
)]
pub async fn admin_list_sessions(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiQuery(q): ApiQuery<AdminSessionsQuery>,
) -> ApiResult<axum::Json<Page<SessionInfo>>> {
    let cur = p.session_id();
    let only = q.user_id.as_deref().map(parse_uuid).transpose()?;
    let all = state
        .session_manager
        .all_sessions()
        .iter()
        .filter(|(_, s)| only.is_none_or(|u| s.user_id == u))
        .map(|(id, s)| session_info(id, s, cur))
        .collect();
    let cq = CursorQuery {
        page: q.page,
        limit: q.limit,
        cursor: q.cursor,
    };
    Ok(axum::Json(page_of(session_rows(all), &cq)?))
}

/// Revoke any session.
#[utoipa::path(
    delete, path = "/admin/sessions/{id}", tag = "sessions",
    security(("bearer_auth" = ["sessions:admin"])),
    params(("id" = String, Path, description = "Session id")),
    responses((status = 200, description = "Revoked", body = MessageResponse))
)]
pub async fn admin_revoke_session(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<axum::Json<MessageResponse>> {
    let sid = parse_uuid(&id)?;
    let st = state.clone();
    if blocking(move || st.session_manager.revoke_session(&sid)).await? {
        Ok(msg("Session revoked"))
    } else {
        Err(ApiError::NotFound("Session not found".into()))
    }
}

//! Authentication and authorization, deny by default.
//!
//! Each route declares its requirement once, in its `#[utoipa::path(security(...))]` attribute:
//!
//! - `security(("bearer_auth" = ["lists:write"]))` - requires that scope,
//! - `security(("bearer_auth" = []))` - any authenticated principal,
//! - `security(())` - explicitly public.
//!
//! [`RouteTable::from_spec`] reads those declarations back out of the generated OpenAPI
//! document, so the document and the enforcement cannot disagree. A route with no declaration is
//! refused with `403` at runtime and reported by [`RouteTable::undeclared`] (a test fails on it).

use api_types::{Scope, UserRole};
use axum::{
    extract::{MatchedPath, Request, State},
    http::{header, HeaderMap, Method},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use uuid::Uuid;

use super::csrf;
use super::jwt::validate_access_token;
use super::middleware::{ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE};
use crate::error::ApiError;
use crate::state::AppState;

/// Who is making the request.
#[derive(Debug, Clone)]
pub enum Actor {
    /// A cookie login session.
    Session { session_id: Uuid },
    /// A personal access token.
    Token { token_id: String },
}

/// An authenticated caller and what it may do.
#[derive(Debug, Clone)]
pub struct Principal {
    pub user_id: Uuid,
    pub username: String,
    pub role: UserRole,
    /// Effective scopes: the role bundle (for sessions) or token scopes limited to what the
    /// creator can still do (for tokens).
    pub scopes: BTreeSet<Scope>,
    pub actor: Actor,
    /// Profile restriction (tokens only). `None` = unrestricted. Profile-scoped routes are
    /// enforced by `ProfileParam` through [`Principal::may_access_profile`]; global routes by
    /// [`restricted_may_use`].
    pub profiles: Option<Vec<String>>,
}

impl Principal {
    pub fn has(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }

    pub fn is_token(&self) -> bool {
        matches!(self.actor, Actor::Token { .. })
    }

    pub fn session_id(&self) -> Option<Uuid> {
        match self.actor {
            Actor::Session { session_id } => Some(session_id),
            Actor::Token { .. } => None,
        }
    }

    /// May this principal touch `profile_id` (decimal id)?
    pub fn may_access_profile(&self, profile_id: &str) -> bool {
        self.profiles
            .as_ref()
            .is_none_or(|p| p.iter().any(|x| x == profile_id))
    }

    /// Key for per-principal rate limiting.
    pub fn rate_key(&self) -> String {
        match &self.actor {
            Actor::Token { token_id } => format!("token:{token_id}"),
            Actor::Session { .. } => format!("user:{}", self.user_id),
        }
    }
}

/// What a route requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAuth {
    Public,
    Authenticated,
    /// Every listed scope.
    Scopes(Vec<Scope>),
    /// At least one of the listed scopes (several single-scope `security` alternatives).
    AnyOf(Vec<Scope>),
}

impl RouteAuth {
    pub fn describe(&self) -> String {
        match self {
            RouteAuth::Public => String::new(),
            RouteAuth::Authenticated => "authenticated".into(),
            RouteAuth::Scopes(s) => s.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(","),
            RouteAuth::AnyOf(s) => s.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("|"),
        }
    }
}

/// `(METHOD, route template) -> requirement`, built from the OpenAPI document.
#[derive(Debug, Default)]
pub struct RouteTable {
    map: HashMap<(String, String), RouteAuth>,
    /// Operations that carry no `security` declaration (must be empty).
    pub undeclared: Vec<String>,
    /// Operations naming a scope that does not exist (must be empty).
    pub invalid: Vec<String>,
    /// Operations that bind to a profile (a `profile` query or `profile_id` path parameter), or
    /// whose scope family (`profiles:*`, `devices:*`) checks the profile itself.
    profile_aware: std::collections::HashSet<(String, String)>,
}

/// Global (not profile-scoped) reads a profile-restricted token may make.
const RESTRICTED_GLOBAL_READS: [Scope; 6] = [
    Scope::ListsRead,
    Scope::LogsRead,
    Scope::StatsRead,
    Scope::SystemRead,
    Scope::CaRead,
    Scope::ConfigRead,
];

/// Rule for a profile-restricted token on a route that is not profile-aware (global state).
///
/// - own-token and own-session management and plain authenticated routes: allowed (a token can
///   never mint more than its parent holds, restriction included);
/// - global reads of lists, stats, system status, CA info and the config: allowed;
/// - custom rules are the default profile's overlay: readable only with access to profile `0`;
/// - everything else (any write to global state, users, audit, admin routes): refused.
pub fn restricted_may_use(p: &Principal, rule: &RouteAuth, method: &Method) -> bool {
    if let RouteAuth::AnyOf(any) = rule {
        return any
            .iter()
            .any(|s| restricted_may_use(p, &RouteAuth::Scopes(vec![*s]), method));
    }
    let RouteAuth::Scopes(required) = rule else {
        return true;
    };
    if required.iter().all(|s| {
        matches!(
            s,
            Scope::TokensSelf | Scope::SessionsSelf | Scope::UserscriptsBridge
        )
    }) {
        return true;
    }
    if is_unsafe(method) {
        return false;
    }
    required.iter().all(|s| {
        RESTRICTED_GLOBAL_READS.contains(s) || (*s == Scope::RulesRead && p.may_access_profile("0"))
    })
}

const METHODS: [&str; 7] = ["get", "put", "post", "delete", "patch", "head", "options"];

impl RouteTable {
    pub fn from_spec(spec: &Value) -> Self {
        let mut t = RouteTable::default();
        let Some(paths) = spec.get("paths").and_then(Value::as_object) else {
            return t;
        };
        for (path, item) in paths {
            for m in METHODS {
                let Some(op) = item.get(m) else { continue };
                let label = format!("{} {}", m.to_uppercase(), path);
                let Some(sec) = op.get("security").and_then(Value::as_array) else {
                    t.undeclared.push(label);
                    continue;
                };
                if sec.is_empty() {
                    // `security: []` is not the explicit public marker (`security(())`).
                    t.undeclared.push(label);
                    continue;
                }
                let public = sec
                    .iter()
                    .any(|r| r.as_object().is_some_and(|o| o.is_empty()));
                let mut scopes = Vec::new();
                for req in sec {
                    for list in req.as_object().into_iter().flat_map(|o| o.values()) {
                        for sc in list.as_array().into_iter().flatten() {
                            match sc.as_str().map(str::parse::<Scope>) {
                                Some(Ok(s)) => {
                                    if !scopes.contains(&s) {
                                        scopes.push(s)
                                    }
                                }
                                _ => t.invalid.push(format!("{label}: {sc}")),
                            }
                        }
                    }
                }
                let profile_scoped = scopes
                    .iter()
                    .any(|s| matches!(s.resource(), "profiles" | "devices"));
                let auth = if public {
                    RouteAuth::Public
                } else if scopes.is_empty() {
                    RouteAuth::Authenticated
                } else if sec.len() > 1
                    && sec.iter().all(|r| {
                        r.as_object().is_some_and(|o| {
                            o.values()
                                .map(|v| v.as_array().map_or(0, Vec::len))
                                .sum::<usize>()
                                == 1
                        })
                    })
                {
                    // Alternatives (OpenAPI: any one requirement object suffices).
                    RouteAuth::AnyOf(scopes)
                } else {
                    RouteAuth::Scopes(scopes)
                };
                let has_param = op
                    .get("parameters")
                    .and_then(Value::as_array)
                    .is_some_and(|ps| {
                        ps.iter().any(|p| {
                            matches!(
                                p.get("name").and_then(Value::as_str),
                                Some("profile") | Some("profile_id")
                            )
                        })
                    });
                if has_param || profile_scoped {
                    t.profile_aware.insert((m.to_uppercase(), path.clone()));
                }
                t.map.insert((m.to_uppercase(), path.clone()), auth);
            }
        }
        t
    }

    pub fn get(&self, method: &str, path: &str) -> Option<&RouteAuth> {
        self.map.get(&(method.to_string(), path.to_string()))
    }

    /// Whether the route binds itself to a profile (see the field docs).
    pub fn is_profile_aware(&self, method: &str, path: &str) -> bool {
        self.profile_aware
            .contains(&(method.to_string(), path.to_string()))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&(String, String), &RouteAuth)> {
        self.map.iter()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// How the request authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Cookie,
    Bearer,
}

/// Facts about the request recorded for the audit log; attached to the response extensions.
#[derive(Debug, Clone, Default)]
pub struct AuditMeta {
    pub route: String,
    pub required: String,
    pub principal: Option<Principal>,
}

/// Actor named by a handler when there is no principal (login, register).
#[derive(Debug, Clone)]
pub struct AuditActor {
    pub id: Option<String>,
    pub name: String,
}

fn unauthorized(msg: &str) -> ApiError {
    ApiError::AuthenticationFailed(msg.to_string())
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|s| s.split(';'))
        .find_map(|c| c.trim().strip_prefix(&prefix).map(str::to_string))
}

pub fn refresh_cookie(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, REFRESH_TOKEN_COOKIE)
}

/// Resolve credentials to a principal. `Authorization: Bearer` wins; no fallback to cookies when
/// a bearer credential is present but invalid.
pub fn resolve(state: &Arc<AppState>, headers: &HeaderMap) -> Result<(Principal, Via), ApiError> {
    if let Some(h) = headers.get(header::AUTHORIZATION) {
        let raw = h
            .to_str()
            .map_err(|_| unauthorized("Invalid Authorization header"))?;
        let token = raw
            .split_once(' ')
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, t)| t.trim())
            .ok_or_else(|| unauthorized("Authorization must use the Bearer scheme"))?;
        let cached = state
            .tokens
            .verify(token)
            .map_err(|_| unauthorized("Invalid, expired or revoked API token"))?;
        let user = state
            .session_store
            .get_user(&cached.stored.created_by)?
            .filter(|u| u.enabled)
            .ok_or_else(|| unauthorized("Token owner is disabled or deleted"))?;
        let creator = user.role.scopes();
        let scopes = cached
            .stored
            .scopes
            .iter()
            .copied()
            .filter(|s| creator.contains(s))
            .collect();
        state.tokens.mark_used(&cached);
        return Ok((
            Principal {
                user_id: user.id,
                username: user.username,
                role: user.role,
                scopes,
                actor: Actor::Token {
                    token_id: cached.stored.id.clone(),
                },
                profiles: cached.stored.profiles.clone(),
            },
            Via::Bearer,
        ));
    }

    let token = cookie_value(headers, ACCESS_TOKEN_COOKIE)
        .ok_or_else(|| unauthorized("No authentication token provided"))?;
    let claims = validate_access_token(&token, &state.jwt_config)?;
    let sid: Uuid = claims
        .sid
        .parse()
        .map_err(|_| unauthorized("Invalid session"))?;
    if !state.session_manager.is_active(&sid) {
        return Err(unauthorized("Session has ended"));
    }
    let user_id: Uuid = claims
        .sub
        .parse()
        .map_err(|_| unauthorized("Invalid token"))?;
    let user = state
        .session_store
        .get_user(&user_id)?
        .filter(|u| u.enabled)
        .ok_or_else(|| unauthorized("Account is disabled or deleted"))?;
    state.session_manager.touch_session(&sid);
    Ok((
        Principal {
            user_id: user.id,
            username: user.username,
            role: user.role,
            scopes: user.role.scopes().into_iter().collect(),
            actor: Actor::Session { session_id: sid },
            profiles: None,
        },
        Via::Cookie,
    ))
}

fn is_unsafe(m: &Method) -> bool {
    !matches!(*m, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn check(
    state: &Arc<AppState>,
    req: &Request,
    rule: Option<&RouteAuth>,
    aware: bool,
    meta: &mut AuditMeta,
) -> Result<Option<Principal>, ApiError> {
    let rule = rule.ok_or_else(|| {
        tracing::error!(
            "Route {} has no authorization declaration; denying",
            meta.route
        );
        ApiError::AuthorizationFailed("Route has no authorization declaration".to_string())
    })?;
    meta.required = rule.describe();
    if *rule == RouteAuth::Public {
        return Ok(None);
    }
    let (principal, via) = resolve(state, req.headers())?;
    meta.principal = Some(principal.clone());

    if via == Via::Cookie && is_unsafe(req.method()) && state.api_config.security.enable_csrf {
        let sid = principal.session_id().unwrap_or_default();
        if !csrf::verify(
            req.headers(),
            &state.jwt_config.secret,
            &sid,
            &state.api_config.security.cors_origins,
        ) {
            return Err(ApiError::CsrfValidationFailed);
        }
    }

    if !state.rate_limiters.check_principal(&principal.rate_key()) {
        return Err(ApiError::RateLimitExceeded(
            "Too many requests, please slow down".to_string(),
        ));
    }

    if let RouteAuth::AnyOf(any) = rule {
        if !any.iter().any(|s| principal.has(*s)) {
            return Err(ApiError::coded(
                axum::http::StatusCode::FORBIDDEN,
                "insufficient_scope",
                format!(
                    "Missing required scope: one of {}",
                    any.iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
    }
    if let RouteAuth::Scopes(required) = rule {
        if let Some(missing) = required.iter().find(|s| !principal.has(**s)) {
            return Err(ApiError::coded(
                axum::http::StatusCode::FORBIDDEN,
                "insufficient_scope",
                format!("Missing required scope: {missing}"),
            ));
        }
    }
    // Profile-restricted tokens: global routes are refused here; profile-aware routes check the
    // profile themselves (`ProfileParam`).
    if principal.profiles.is_some() && !aware && !restricted_may_use(&principal, rule, req.method())
    {
        return Err(ApiError::coded(
            axum::http::StatusCode::FORBIDDEN,
            "profile_restricted",
            "This token is restricted to specific profiles and cannot use this global route",
        ));
    }
    Ok(Some(principal))
}

/// The single enforcement point, installed as a `route_layer` over every API route.
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    let method = if req.method() == Method::HEAD {
        "GET".to_string()
    } else {
        req.method().as_str().to_string()
    };
    let rule = state
        .route_auth
        .get()
        .and_then(|t| t.get(&method, &route))
        .cloned();
    let aware = state
        .route_auth
        .get()
        .is_some_and(|t| t.is_profile_aware(&method, &route));
    let mut meta = AuditMeta {
        route,
        ..Default::default()
    };

    let mut response = match check(&state, &req, rule.as_ref(), aware, &mut meta) {
        Ok(principal) => {
            if let Some(p) = principal {
                req.extensions_mut().insert(p);
            }
            next.run(req).await
        }
        Err(e) => e.into_response(),
    };
    response.extensions_mut().insert(meta);
    response
}

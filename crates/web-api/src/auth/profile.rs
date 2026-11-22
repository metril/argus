//! `ProfileParam`: the one place a request is bound to a profile and a profile-restricted
//! token is enforced.
//!
//! The profile comes from the `{profile_id}` path segment when the route has one, otherwise from
//! `?profile=<id>`, otherwise it is the default profile (id 0). Ids are decimal strings on the
//! wire. The extractor refuses (403) a principal whose token is restricted to other profiles,
//! then resolves the profile (404 when it does not exist) and yields its id and name. Every
//! route that reads or writes profile-scoped data takes one, and declares `ProfileQuery` (or the
//! path parameter) in its `#[utoipa::path]`; a test fails when a profile-scoped route lacks it.

use std::sync::Arc;

use axum::extract::{FromRequestParts, RawPathParams};
use axum::http::request::Parts;
use axum::http::StatusCode;
use serde::Deserialize;
use utoipa::IntoParams;

use super::authz::Principal;
use crate::error::ApiError;
use crate::state::{blocking, AppState};

/// Name of the path parameter that carries a profile id.
pub const PATH_PARAM: &str = "profile_id";

/// `?profile=<id>`: the profile a request operates on (default profile when omitted).
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ProfileQuery {
    /// Profile id (decimal). Omitted: the default profile, `0`.
    pub profile: Option<String>,
}

/// A resolved profile the caller may access.
#[derive(Debug, Clone)]
pub struct ProfileParam {
    pub id: u64,
    /// Storage namespace of the profile (script policy, userscripts, GM values).
    pub name: String,
}

/// Parse a wire profile id.
pub fn parse_profile_id(raw: &str) -> Result<u64, ApiError> {
    raw.parse::<u64>().map_err(|_| {
        ApiError::coded(
            StatusCode::BAD_REQUEST,
            "invalid_profile",
            "Invalid profile id: expected a decimal number",
        )
    })
}

/// 403 for a token restricted away from `id`.
pub fn forbidden_profile(id: u64) -> ApiError {
    ApiError::coded(
        StatusCode::FORBIDDEN,
        "profile_forbidden",
        format!("This token is not allowed to access profile {id}"),
    )
}

/// Check the restriction, then load the profile.
pub async fn resolve(
    state: &Arc<AppState>,
    principal: &Principal,
    id: u64,
) -> Result<ProfileParam, ApiError> {
    if !principal.may_access_profile(&id.to_string()) {
        return Err(forbidden_profile(id));
    }
    let st = state.clone();
    let rec = blocking(move || Ok(st.profiles.get(id)?)).await?;
    let rec = rec.ok_or_else(|| ApiError::NotFound(format!("Profile {id} not found")))?;
    Ok(ProfileParam {
        id: rec.id,
        name: common::profile_store::namespace(rec.id),
    })
}

impl FromRequestParts<Arc<AppState>> for ProfileParam {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let principal = parts
            .extensions
            .get::<Principal>()
            .cloned()
            .ok_or_else(|| ApiError::AuthorizationFailed("No principal".into()))?;

        let mut raw: Option<String> = None;
        if let Ok(params) = RawPathParams::from_request_parts(parts, state).await {
            raw = params
                .iter()
                .find(|(k, _)| *k == PATH_PARAM)
                .map(|(_, v)| v.to_string());
        }
        if raw.is_none() {
            raw = parts.uri.query().and_then(|q| {
                url::form_urlencoded::parse(q.as_bytes())
                    .find(|(k, _)| k == "profile")
                    .map(|(_, v)| v.into_owned())
            });
        }
        let id = match raw.as_deref() {
            Some(s) => parse_profile_id(s)?,
            None => 0,
        };
        resolve(state, &principal, id).await
    }
}

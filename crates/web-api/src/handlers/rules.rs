//! Custom rules: read/replace (with `ETag`/`If-Match`), dry-run validation and URL testing.

use std::sync::Arc;

use api_types::{
    CustomRulesResponse, ListReport, RuleLineResult, TestUrlRequest, TestUrlResponse,
    UpdateCustomRulesRequest, ValidateRulesRequest, ValidateRulesResponse,
};
use axum::{
    extract::State,
    http::{header::ETAG, HeaderMap},
    Extension, Json,
};
use tracing::info;
use validator::Validate;

use super::{check_if_match, etag_of};
use crate::auth::authz::Principal;
use crate::auth::profile::{ProfileParam, ProfileQuery};
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::state::{blocking, AppState};

type WithEtag<T> = ([(axum::http::HeaderName, String); 1], Json<T>);

fn rules_response(rules: String) -> WithEtag<CustomRulesResponse> {
    (
        [(ETAG, etag_of(rules.as_bytes()))],
        Json(CustomRulesResponse { rules }),
    )
}

/// The custom rules. The `ETag` header must be echoed in `If-Match` when replacing them.
#[utoipa::path(
    get, path = "/rules/custom", tag = "rules",
    security(("bearer_auth" = ["rules:read"])),
    responses((status = 200, description = "Custom rules (with ETag header)", body = CustomRulesResponse))
)]
pub async fn get_custom_rules(
    State(state): State<Arc<AppState>>,
) -> ApiResult<WithEtag<CustomRulesResponse>> {
    Ok(rules_response(state.filter_store.get_custom_rules()?))
}

/// Replace the custom rules and rebuild the engine. Requires `If-Match` (428 if absent, 412 if
/// the rules changed since they were read).
#[utoipa::path(
    put, path = "/rules/custom", tag = "rules",
    security(("bearer_auth" = ["rules:write"])),
    params(("If-Match" = String, Header, description = "ETag from the last GET")),
    request_body = UpdateCustomRulesRequest,
    responses(
        (status = 200, description = "Replaced (with new ETag header)", body = CustomRulesResponse),
        (status = 412, description = "Rules changed since they were read"),
        (status = 428, description = "If-Match missing"),
    )
)]
pub async fn update_custom_rules(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    headers: HeaderMap,
    ApiJson(req): ApiJson<UpdateCustomRulesRequest>,
) -> ApiResult<WithEtag<CustomRulesResponse>> {
    req.validate()?;
    let current = state.filter_store.get_custom_rules()?;
    check_if_match(&headers, &etag_of(current.as_bytes()))?;
    let (st, rules) = (state.clone(), req.rules.clone());
    blocking(move || Ok(st.filter_store.set_custom_rules(&rules)?)).await?;
    info!("Custom filter rules updated by {}", p.username);
    state.list_service.trigger();
    Ok(rules_response(req.rules))
}

/// Max rule lines dry-run in one request.
const MAX_VALIDATE_LINES: usize = 20_000;

/// Run each line through the real conversion pipeline for `format` (detected from the whole text
/// when `Auto`) and the engine's rule compiler, without installing anything. Each non-comment
/// line is reported as translated, accepted, handed off, skipped or rejected.
pub fn validate_rules(
    text: &str,
    format: filter_engine::ListFormat,
    allowlist: bool,
) -> ValidateRulesResponse {
    use filter_engine::{compile_lists, convert, detect, ConvertOptions, ListFormat};
    let used = if format == ListFormat::Auto {
        detect(text)
    } else {
        format
    };
    let opts = ConvertOptions {
        format: used,
        allowlist,
        includes: Default::default(),
    };
    struct Row<'a> {
        line: usize,
        raw: &'a str,
        conv: filter_engine::Converted,
    }
    let rows: Vec<Row> = text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .take(MAX_VALIDATE_LINES)
        .map(|(i, l)| Row {
            line: i + 1,
            raw: l.trim(),
            conv: convert(l, &opts),
        })
        .collect();
    let texts: Vec<&str> = rows.iter().map(|r| r.conv.rules.as_str()).collect();
    let compiled = compile_lists(&texts);
    let mut lines = Vec::new();
    for (r, cs) in rows.iter().zip(&compiled.per_list) {
        let st = &r.conv.stats;
        let (outcome, error): (&str, Option<String>) = if st.error_count > 0 {
            (
                "rejected",
                st.errors
                    .first()
                    .map(|e| e.1.clone())
                    .or(Some("invalid rule".into())),
            )
        } else if let Some(e) = r.conv.ext.first() {
            ("handed_off", Some(e.kind.as_str().to_string()))
        } else if cs.rejected > 0 {
            (
                "rejected",
                cs.errors
                    .first()
                    .map(|e| e.1.clone())
                    .or(Some("rejected by the engine".into())),
            )
        } else if let Some(e) = cs.ext_rules.first() {
            ("handed_off", Some(e.kind.as_str().to_string()))
        } else if !r.conv.ip_block.is_empty() || !r.conv.ip_allow.is_empty() {
            ("accepted", None)
        } else if r.conv.rules.trim().is_empty() {
            if st.skipped == 0 {
                continue; // comment or header line
            }
            ("skipped", st.skipped_reasons.keys().next().cloned())
        } else if st.translated > 0 {
            ("translated", None)
        } else {
            ("accepted", None)
        };
        lines.push(RuleLineResult {
            line: r.line,
            rule: r.raw.to_string(),
            outcome: outcome.to_string(),
            accepted: outcome != "rejected",
            error,
        });
    }
    let count = |o: &str| lines.iter().filter(|l| l.outcome == o).count();
    ValidateRulesResponse {
        format: used.as_str().to_string(),
        translated: count("translated"),
        handed_off: count("handed_off"),
        skipped: count("skipped"),
        rejected: count("rejected"),
        accepted: lines.len() - count("rejected"),
        lines,
    }
}

/// Dry-run through the real conversion pipeline for `format`: per-line translated / handed off /
/// skipped / rejected. Nothing is stored or installed.
#[utoipa::path(
    post, path = "/rules/validate", tag = "rules",
    security(("bearer_auth" = ["rules:read"])),
    request_body = ValidateRulesRequest,
    responses((status = 200, description = "Per-line results", body = ValidateRulesResponse))
)]
pub async fn validate(
    ApiJson(req): ApiJson<ValidateRulesRequest>,
) -> ApiResult<Json<ValidateRulesResponse>> {
    if req.rules.len() > 1_000_000 {
        return Err(ApiError::ValidationError("Rules exceed 1 MB".into()));
    }
    let format = req
        .format
        .as_deref()
        .map(str::parse::<filter_engine::ListFormat>)
        .transpose()
        .map_err(ApiError::ValidationError)?
        .unwrap_or_default();
    let allow = req.allowlist.unwrap_or(false);
    let out = blocking(move || Ok(validate_rules(&req.rules, format, allow))).await?;
    Ok(Json(out))
}

/// What the last build made of the custom rules.
#[utoipa::path(
    get, path = "/rules/custom/report", tag = "rules",
    security(("bearer_auth" = ["rules:read"])),
    responses((status = 200, description = "Build report of the custom rules", body = ListReport))
)]
pub async fn get_custom_report(State(state): State<Arc<AppState>>) -> ApiResult<Json<ListReport>> {
    let r = state
        .list_service
        .custom_rules_report()
        .ok_or_else(|| ApiError::NotFound("No custom rules have been built yet".into()))?;
    Ok(Json(super::lists::report_dto("custom", &r, None)))
}

/// Would this request be blocked, and by which rule? Uses the live engine; statistics are not
/// affected.
#[utoipa::path(
    post, path = "/rules/test", tag = "rules",
    security(("bearer_auth" = ["rules:read"])),
    request_body = TestUrlRequest,
    responses((status = 200, description = "Verdict", body = TestUrlResponse))
)]
pub async fn test_url(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<TestUrlRequest>,
) -> ApiResult<Json<TestUrlResponse>> {
    req.validate()?;
    let source = req.source_url.clone().unwrap_or_else(|| req.url.clone());
    let kind = req.resource_type.clone().unwrap_or_else(|| "other".into());
    let engine = state.shared_engine.engine();
    let r = filter_engine::RequestMatcher::check_request(&engine, &req.url, &source, &kind)
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;
    Ok(Json(TestUrlResponse {
        blocked: r.blocked,
        important: r.important,
        matched_rule: r.matched_rule,
        exception_rule: r.exception_rule,
        redirected: r.redirect.is_some(),
        rewritten_url: r.rewritten_url,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_per_line() {
        let r = validate_rules(
            "! comment\n\n||ads.example.com^\nexample.com##.banner\n||bad$unknownoption=1\n",
            filter_engine::ListFormat::Auto,
            false,
        );
        assert_eq!(r.accepted + r.rejected, r.lines.len());
        assert!(r.lines[0].accepted);
        assert_eq!(r.lines[0].line, 3);
        assert!(r
            .lines
            .iter()
            .any(|l| l.rule.contains("##.banner") && l.accepted));
    }
}

// ---- per-site ad blocking off (document exceptions in the custom rules) ----

fn site_exception_message(site: &str) -> String {
    format!("'{site}' is not a plain lowercase host name (letters, digits, '-' and '.')")
}

fn site_exception_error(site: &str) -> ApiError {
    ApiError::ValidationError(site_exception_message(site))
}

/// Sites for which ad blocking is switched off. These are `@@||site^$document` lines in the
/// custom rules, so they also show up (and can be edited) there.
#[utoipa::path(
    get, path = "/rules/site-exceptions", tag = "rules",
    security(("bearer_auth" = ["rules:read"])),
    params(ProfileQuery),
    responses((status = 200, description = "Sites with ad blocking off", body = api_types::SiteExceptionsResponse))
)]
pub async fn list_site_exceptions(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
) -> ApiResult<Json<api_types::SiteExceptionsResponse>> {
    let st = state.clone();
    let rules = blocking(move || profile_rules(&st, profile.id)).await?;
    Ok(Json(api_types::SiteExceptionsResponse {
        sites: list_service::site_exceptions::list(&rules),
    }))
}

/// Whether ad blocking is switched off for one site (readable with `rules:site`, so the browser
/// extension needs no access to the rest of the rules).
#[utoipa::path(
    get, path = "/rules/site-exceptions/{site}", tag = "rules",
    security(("bearer_auth" = ["rules:site"]), ("bearer_auth" = ["rules:write"]), ("bearer_auth" = ["rules:read"])),
    params(ProfileQuery, ("site" = String, Path, description = "Host name, lowercase punycode")),
    responses((status = 200, description = "State of the site", body = api_types::SiteExceptionState))
)]
pub async fn get_site_exception(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    crate::error::ApiPath(site): crate::error::ApiPath<String>,
) -> ApiResult<Json<api_types::SiteExceptionState>> {
    let st = state.clone();
    let rules = blocking(move || profile_rules(&st, profile.id)).await?;
    let disabled = list_service::site_exceptions::list(&rules).contains(&site);
    Ok(Json(api_types::SiteExceptionState { site, disabled }))
}

/// The rules text exceptions live in: the global custom rules for the default profile, the
/// profile's overlay rules otherwise.
fn profile_rules(st: &AppState, id: u64) -> ApiResult<String> {
    if id == 0 {
        return Ok(st.filter_store.get_custom_rules()?);
    }
    let rec = st
        .profiles
        .get(id)?
        .ok_or_else(|| ApiError::NotFound("Profile not found".into()))?;
    Ok(rec.rules)
}

async fn set_site_exception(
    state: Arc<AppState>,
    p: Principal,
    profile: ProfileParam,
    site: String,
    disabled: bool,
) -> ApiResult<Json<api_types::SiteExceptionsResponse>> {
    let st = state.clone();
    let s = site.clone();
    let id = profile.id;
    blocking(move || {
        if id == 0 {
            let rules = st.filter_store.get_custom_rules()?;
            let new = list_service::site_exceptions::set(&rules, &s, disabled)
                .ok_or_else(|| site_exception_error(&s))?;
            if new != rules {
                st.filter_store.set_custom_rules(&new)?;
            }
            return Ok(());
        }
        st.profiles.modify(id, |rec| {
            rec.rules =
                list_service::site_exceptions::set(&rec.rules, &s, disabled).ok_or_else(|| {
                    common::profile_store::ProfileError::Invalid(site_exception_message(&s))
                })?;
            Ok(())
        })?;
        Ok(())
    })
    .await?;
    info!(
        "Ad blocking {} for {site} in profile {} by {}",
        if disabled { "disabled" } else { "enabled" },
        profile.id,
        p.username
    );
    if id == 0 {
        state.list_service.trigger();
    }
    list_site_exceptions(State(state), profile).await
}

/// Switch ad blocking off for a site (document exception in the custom rules).
#[utoipa::path(
    put, path = "/rules/site-exceptions/{site}", tag = "rules",
    security(("bearer_auth" = ["rules:site"]), ("bearer_auth" = ["rules:write"])),
    params(ProfileQuery, ("site" = String, Path, description = "Host name, lowercase punycode")),
    responses(
        (status = 200, description = "Sites with ad blocking off", body = api_types::SiteExceptionsResponse),
        (status = 400, description = "Not a plain host name"),
    )
)]
pub async fn put_site_exception(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    profile: ProfileParam,
    crate::error::ApiPath(site): crate::error::ApiPath<String>,
) -> ApiResult<Json<api_types::SiteExceptionsResponse>> {
    set_site_exception(state, p, profile, site, true).await
}

/// Switch ad blocking back on for a site.
#[utoipa::path(
    delete, path = "/rules/site-exceptions/{site}", tag = "rules",
    security(("bearer_auth" = ["rules:site"]), ("bearer_auth" = ["rules:write"])),
    params(ProfileQuery, ("site" = String, Path, description = "Host name, lowercase punycode")),
    responses(
        (status = 200, description = "Sites with ad blocking off", body = api_types::SiteExceptionsResponse),
        (status = 400, description = "Not a plain host name"),
    )
)]
pub async fn delete_site_exception(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    profile: ProfileParam,
    crate::error::ApiPath(site): crate::error::ApiPath<String>,
) -> ApiResult<Json<api_types::SiteExceptionsResponse>> {
    set_site_exception(state, p, profile, site, false).await
}

//! Custom rules: read/replace (with `ETag`/`If-Match`), dry-run validation and URL testing.

use std::sync::Arc;

use api_types::{
    CustomRulesResponse, RuleLineResult, TestUrlRequest, TestUrlResponse, UpdateCustomRulesRequest,
    ValidateRulesRequest, ValidateRulesResponse,
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

fn is_comment(line: &str) -> bool {
    line.starts_with('!') || (line.starts_with('[') && line.ends_with(']'))
}

/// Parse each line exactly as the engine would, without installing anything.
pub fn validate_rules(text: &str) -> ValidateRulesResponse {
    let mut lines = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || is_comment(line) {
            continue;
        }
        let res =
            adblock::lists::parse_filter(line, false, adblock::lists::ParseOptions::default());
        lines.push(RuleLineResult {
            line: i + 1,
            rule: line.to_string(),
            accepted: res.is_ok(),
            error: res.err().map(|e| e.to_string()),
        });
    }
    let accepted = lines.iter().filter(|l| l.accepted).count();
    ValidateRulesResponse {
        accepted,
        rejected: lines.len() - accepted,
        lines,
    }
}

/// Dry-run: report per-line accept/reject for a block of rules. Nothing is stored or installed.
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
    Ok(Json(validate_rules(&req.rules)))
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

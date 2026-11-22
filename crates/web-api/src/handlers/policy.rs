//! Script policy (NoScript-style) endpoints. Writes are audited by the audit middleware like
//! every other state-changing call. Everything operates on the default profile until profiles
//! land (`script_policy::DEFAULT_PROFILE`).

use std::sync::Arc;

use api_types::{
    BlockedItemDto, CspDirectiveDto, ExplainResponse, HtmlActionsDto, HtmlRuleDto, MessageResponse,
    Page, PolicyExportDto, PolicyImportRequest, PolicyProfileDto, PolicyReportDto,
    PolicySettingsDto, PolicySettingsResponse, PresetDto, PreviewRequest, PreviewResponse,
    SiteRuleDto, SiteRuleInput, SiteRuleUpdate, SourceRuleDto, SourceRuleInput, SourceRuleUpdate,
    SuggestedAllowDto, TempGrantDto, TempGrantInput,
};
use axum::{extract::State, http::StatusCode, Json};
use script_policy as sp;
use script_policy::store::StoreError;
use serde::Deserialize;
use utoipa::IntoParams;

use crate::error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult};
use crate::state::{blocking, AppState};

const PROFILE: &str = sp::DEFAULT_PROFILE;
const MAX_NOTE: usize = 500;

// ---- conversions ----

fn store_err(e: StoreError) -> ApiError {
    match e {
        StoreError::Conflict(m) => ApiError::AlreadyExists(m),
        StoreError::NotFound(m) => ApiError::NotFound(m),
        StoreError::Rule(e) => ApiError::ValidationError(e.to_string()),
        StoreError::Db(e) => ApiError::Internal(e.to_string()),
        StoreError::Corrupt(m) => ApiError::Internal(m),
    }
}

fn scope_in(s: &str) -> ApiResult<sp::Scope> {
    sp::Scope::parse(s).map_err(|e| ApiError::ValidationError(format!("scope '{s}': {e}")))
}

fn caps_out(c: sp::CapSet) -> Vec<String> {
    c.iter().map(|c| c.as_str().to_string()).collect()
}

fn caps_in(v: &[String]) -> ApiResult<sp::CapSet> {
    v.iter().try_fold(sp::CapSet::EMPTY, |s, n| {
        sp::Capability::parse(n)
            .map(|c| s.with(c))
            .ok_or_else(|| ApiError::ValidationError(format!("unknown capability '{n}'")))
    })
}

fn profile_out(p: &sp::Profile) -> PolicyProfileDto {
    PolicyProfileDto {
        page: caps_out(p.page),
        first_party: caps_out(p.first_party),
        third_party: caps_out(p.third_party),
    }
}

fn profile_in(p: &PolicyProfileDto) -> ApiResult<sp::Profile> {
    let page = caps_in(&p.page)?;
    let (first_party, third_party) = (caps_in(&p.first_party)?, caps_in(&p.third_party)?);
    if !page.minus(sp::CapSet::PAGE_LEVEL).is_empty()
        || !first_party.minus(sp::CapSet::SOURCE_KEYED).is_empty()
        || !third_party.minus(sp::CapSet::SOURCE_KEYED).is_empty()
    {
        return Err(ApiError::ValidationError(
            "profile: `page` takes page-level capabilities, the source lists source-keyed ones"
                .into(),
        ));
    }
    Ok(sp::Profile {
        page,
        first_party,
        third_party,
    })
}

fn preset_out(p: &sp::Preset) -> PresetDto {
    PresetDto {
        kind: p.name().into(),
        profile: match p {
            sp::Preset::Custom { profile } => Some(profile_out(profile)),
            _ => None,
        },
    }
}

fn preset_in(p: &PresetDto) -> ApiResult<sp::Preset> {
    Ok(match p.kind.as_str() {
        "default" => sp::Preset::Default,
        "trusted" => sp::Preset::Trusted,
        "untrusted" => sp::Preset::Untrusted,
        "custom" => sp::Preset::Custom {
            profile: profile_in(p.profile.as_ref().ok_or_else(|| {
                ApiError::ValidationError("custom preset needs a profile".into())
            })?)?,
        },
        other => {
            return Err(ApiError::ValidationError(format!(
                "unknown preset '{other}' (default, trusted, untrusted, custom)"
            )))
        }
    })
}

fn settings_out(s: &sp::Settings) -> PolicySettingsDto {
    PolicySettingsDto {
        enabled: s.enabled,
        global: preset_out(&s.global),
        default_profile: profile_out(&s.default_profile),
        strip_blocked_scripts: s.strip_blocked_scripts,
        strip_meta_refresh: s.strip_meta_refresh,
        network_hints: s.network_hints,
    }
}

fn settings_in(s: &PolicySettingsDto) -> ApiResult<sp::Settings> {
    Ok(sp::Settings {
        enabled: s.enabled,
        global: preset_in(&s.global)?,
        default_profile: profile_in(&s.default_profile)?,
        strip_blocked_scripts: s.strip_blocked_scripts,
        strip_meta_refresh: s.strip_meta_refresh,
        network_hints: s.network_hints,
    })
}

fn site_out(r: &sp::SiteRule) -> SiteRuleDto {
    SiteRuleDto {
        id: r.id.clone(),
        scope: r.scope.to_string(),
        preset: preset_out(&r.preset),
        note: r.note.clone(),
    }
}

fn effect_in(s: &str) -> ApiResult<sp::Effect> {
    match s {
        "allow" => Ok(sp::Effect::Allow),
        "deny" => Ok(sp::Effect::Deny),
        o => Err(ApiError::ValidationError(format!(
            "unknown effect '{o}' (allow, deny)"
        ))),
    }
}

fn effect_out(e: sp::Effect) -> String {
    match e {
        sp::Effect::Allow => "allow",
        sp::Effect::Deny => "deny",
    }
    .into()
}

fn source_out(r: &sp::SourceRule) -> SourceRuleDto {
    SourceRuleDto {
        id: r.id.clone(),
        page: r.page.to_string(),
        source: r.source.to_string(),
        caps: caps_out(r.caps),
        effect: effect_out(r.effect),
        note: r.note.clone(),
    }
}

fn temp_out(t: &sp::TempGrant, now: u64) -> TempGrantDto {
    let (kind, preset, source, caps) = match &t.kind {
        sp::GrantKind::Site { preset } => ("site", Some(preset_out(preset)), None, vec![]),
        sp::GrantKind::Source { source, caps } => {
            ("source", None, Some(source.to_string()), caps_out(*caps))
        }
    };
    TempGrantDto {
        id: t.id.clone(),
        page: t.page.to_string(),
        kind: kind.into(),
        preset,
        source,
        caps,
        expires_at: t.expires_at,
        remaining_secs: t.expires_at.map(|e| e.saturating_sub(now)),
        until_restart: t.until_restart,
        persist: t.persist,
        created_at: t.created_at,
    }
}

fn check_note(n: &Option<String>) -> ApiResult<()> {
    if n.as_ref().is_some_and(|n| n.len() > MAX_NOTE) {
        return Err(ApiError::ValidationError(format!(
            "note is longer than {MAX_NOTE} bytes"
        )));
    }
    Ok(())
}

fn temp_parts(i: &TempGrantInput) -> ApiResult<(sp::Scope, sp::GrantKind)> {
    let page = scope_in(&i.page)?;
    let kind = match i.kind.as_str() {
        "site" => sp::GrantKind::Site {
            preset: preset_in(i.preset.as_ref().ok_or_else(|| {
                ApiError::ValidationError("a `site` grant needs a preset".into())
            })?)?,
        },
        "source" => sp::GrantKind::Source {
            source: scope_in(i.source.as_deref().ok_or_else(|| {
                ApiError::ValidationError("a `source` grant needs a source".into())
            })?)?,
            caps: caps_in(&i.caps)?,
        },
        o => {
            return Err(ApiError::ValidationError(format!(
                "unknown grant kind '{o}' (site, source)"
            )))
        }
    };
    Ok((page, kind))
}

fn contains_ci(hay: &str, needle: &str) -> bool {
    needle.is_empty()
        || hay
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
}

async fn settings_response(state: &Arc<AppState>) -> ApiResult<PolicySettingsResponse> {
    let st = state.policy.clone();
    blocking(move || {
        let rules = st.rules(PROFILE).map_err(store_err)?;
        let generation = st.generation(PROFILE).map_err(store_err)?;
        Ok(PolicySettingsResponse {
            settings: settings_out(&rules.settings),
            generation,
        })
    })
    .await
}

// ---- settings ----

/// Get the global policy settings.
#[utoipa::path(
    get, path = "/policy/settings", tag = "policy",
    security(("bearer_auth" = ["policy:read"])),
    responses((status = 200, description = "Settings", body = PolicySettingsResponse))
)]
pub async fn get_settings(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<PolicySettingsResponse>> {
    Ok(Json(settings_response(&state).await?))
}

/// Replace the global policy settings (master switch, global default preset, default profile).
#[utoipa::path(
    put, path = "/policy/settings", tag = "policy",
    security(("bearer_auth" = ["policy:write"])),
    request_body = PolicySettingsDto,
    responses((status = 200, description = "Saved", body = PolicySettingsResponse))
)]
pub async fn put_settings(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<PolicySettingsDto>,
) -> ApiResult<Json<PolicySettingsResponse>> {
    let settings = settings_in(&req)?;
    let st = state.policy.clone();
    blocking(move || st.set_settings(PROFILE, settings).map_err(store_err)).await?;
    Ok(Json(settings_response(&state).await?))
}

// ---- site rules ----

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SiteRulesQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    /// Case-insensitive substring of the scope (e.g. a site name).
    pub q: Option<String>,
    /// `default`, `trusted`, `untrusted` or `custom`.
    pub preset: Option<String>,
}

/// List site rules, sorted by scope.
#[utoipa::path(
    get, path = "/policy/site-rules", tag = "policy",
    security(("bearer_auth" = ["policy:read"])),
    params(SiteRulesQuery),
    responses((status = 200, description = "Site rules", body = Page<SiteRuleDto>))
)]
pub async fn list_site_rules(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<SiteRulesQuery>,
) -> ApiResult<Json<Page<SiteRuleDto>>> {
    let st = state.policy.clone();
    let rules = blocking(move || st.rules(PROFILE).map_err(store_err)).await?;
    let mut all: Vec<SiteRuleDto> = rules
        .site_rules
        .values()
        .map(site_out)
        .filter(|r| contains_ci(&r.scope, q.q.as_deref().unwrap_or("")))
        .filter(|r| q.preset.as_ref().is_none_or(|p| &r.preset.kind == p))
        .collect();
    all.sort_by(|a, b| a.scope.cmp(&b.scope));
    Ok(Json(Page::from_vec(all, q.page, q.limit)))
}

/// Create a site rule (409 if the scope already has one).
#[utoipa::path(
    post, path = "/policy/site-rules", tag = "policy",
    security(("bearer_auth" = ["policy:write"])),
    request_body = SiteRuleInput,
    responses((status = 201, description = "Created", body = SiteRuleDto))
)]
pub async fn create_site_rule(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<SiteRuleInput>,
) -> ApiResult<(StatusCode, Json<SiteRuleDto>)> {
    check_note(&req.note)?;
    let (scope, preset) = (scope_in(&req.scope)?, preset_in(&req.preset)?);
    let st = state.policy.clone();
    let r = blocking(move || {
        st.create_site_rule(PROFILE, scope, preset, req.note)
            .map_err(store_err)
    })
    .await?;
    Ok((StatusCode::CREATED, Json(site_out(&r))))
}

/// Change a site rule's preset or note.
#[utoipa::path(
    put, path = "/policy/site-rules/{id}", tag = "policy",
    security(("bearer_auth" = ["policy:write"])),
    params(("id" = String, Path, description = "Site rule id")),
    request_body = SiteRuleUpdate,
    responses((status = 200, description = "Updated", body = SiteRuleDto))
)]
pub async fn update_site_rule(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<SiteRuleUpdate>,
) -> ApiResult<Json<SiteRuleDto>> {
    check_note(&req.note)?;
    let preset = preset_in(&req.preset)?;
    let st = state.policy.clone();
    let r = blocking(move || {
        st.update_site_rule(PROFILE, &id, preset, req.note)
            .map_err(store_err)
    })
    .await?;
    Ok(Json(site_out(&r)))
}

/// Delete a site rule.
#[utoipa::path(
    delete, path = "/policy/site-rules/{id}", tag = "policy",
    security(("bearer_auth" = ["policy:write"])),
    params(("id" = String, Path, description = "Site rule id")),
    responses((status = 200, description = "Deleted", body = MessageResponse))
)]
pub async fn delete_site_rule(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<MessageResponse>> {
    let st = state.policy.clone();
    let rid = id.clone();
    blocking(move || st.delete_site_rule(PROFILE, &rid).map_err(store_err)).await?;
    Ok(Json(MessageResponse {
        message: format!("Site rule '{id}' deleted"),
    }))
}

// ---- source rules ----

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SourceRulesQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    /// Case-insensitive substring of the page scope or the source scope.
    pub site: Option<String>,
    /// Exact page scope (e.g. `site:example.com`).
    pub page_scope: Option<String>,
    /// `allow` or `deny`.
    pub effect: Option<String>,
}

/// List third-party source rules (the matrix cells), sorted by page then source scope.
#[utoipa::path(
    get, path = "/policy/source-rules", tag = "policy",
    security(("bearer_auth" = ["policy:read"])),
    params(SourceRulesQuery),
    responses((status = 200, description = "Source rules", body = Page<SourceRuleDto>))
)]
pub async fn list_source_rules(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<SourceRulesQuery>,
) -> ApiResult<Json<Page<SourceRuleDto>>> {
    let st = state.policy.clone();
    let rules = blocking(move || st.rules(PROFILE).map_err(store_err)).await?;
    let needle = q.site.as_deref().unwrap_or("");
    let mut all: Vec<SourceRuleDto> = rules
        .source_rules
        .values()
        .map(source_out)
        .filter(|r| contains_ci(&r.page, needle) || contains_ci(&r.source, needle))
        .filter(|r| q.page_scope.as_ref().is_none_or(|p| &r.page == p))
        .filter(|r| q.effect.as_ref().is_none_or(|e| &r.effect == e))
        .collect();
    all.sort_by(|a, b| (&a.page, &a.source, &a.effect).cmp(&(&b.page, &b.source, &b.effect)));
    Ok(Json(Page::from_vec(all, q.page, q.limit)))
}

/// Create a source rule (409 if page + source + effect already has one).
#[utoipa::path(
    post, path = "/policy/source-rules", tag = "policy",
    security(("bearer_auth" = ["policy:write"])),
    request_body = SourceRuleInput,
    responses((status = 201, description = "Created", body = SourceRuleDto))
)]
pub async fn create_source_rule(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<SourceRuleInput>,
) -> ApiResult<(StatusCode, Json<SourceRuleDto>)> {
    check_note(&req.note)?;
    let (page, source) = (scope_in(&req.page)?, scope_in(&req.source)?);
    let (caps, effect) = (caps_in(&req.caps)?, effect_in(&req.effect)?);
    let st = state.policy.clone();
    let r = blocking(move || {
        st.create_source_rule(PROFILE, page, source, caps, effect, req.note)
            .map_err(store_err)
    })
    .await?;
    Ok((StatusCode::CREATED, Json(source_out(&r))))
}

/// Change a source rule's capabilities or note.
#[utoipa::path(
    put, path = "/policy/source-rules/{id}", tag = "policy",
    security(("bearer_auth" = ["policy:write"])),
    params(("id" = String, Path, description = "Source rule id")),
    request_body = SourceRuleUpdate,
    responses((status = 200, description = "Updated", body = SourceRuleDto))
)]
pub async fn update_source_rule(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<SourceRuleUpdate>,
) -> ApiResult<Json<SourceRuleDto>> {
    check_note(&req.note)?;
    let caps = caps_in(&req.caps)?;
    let st = state.policy.clone();
    let r = blocking(move || {
        st.update_source_rule(PROFILE, &id, caps, req.note)
            .map_err(store_err)
    })
    .await?;
    Ok(Json(source_out(&r)))
}

/// Delete a source rule.
#[utoipa::path(
    delete, path = "/policy/source-rules/{id}", tag = "policy",
    security(("bearer_auth" = ["policy:write"])),
    params(("id" = String, Path, description = "Source rule id")),
    responses((status = 200, description = "Deleted", body = MessageResponse))
)]
pub async fn delete_source_rule(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<MessageResponse>> {
    let st = state.policy.clone();
    let rid = id.clone();
    blocking(move || st.delete_source_rule(PROFILE, &rid).map_err(store_err)).await?;
    Ok(Json(MessageResponse {
        message: format!("Source rule '{id}' deleted"),
    }))
}

// ---- temporary permissions ----

/// List active temporary permissions.
#[utoipa::path(
    get, path = "/policy/temp", tag = "policy",
    security(("bearer_auth" = ["policy:read"])),
    responses((status = 200, description = "Active grants", body = Vec<TempGrantDto>))
)]
pub async fn list_temp(State(state): State<Arc<AppState>>) -> ApiResult<Json<Vec<TempGrantDto>>> {
    let st = state.policy.clone();
    let (rules, now) = blocking(move || {
        let r = st.rules(PROFILE).map_err(store_err)?;
        Ok((r, st.now()))
    })
    .await?;
    let mut v: Vec<_> = rules.temps.values().map(|t| temp_out(t, now)).collect();
    v.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
    Ok(Json(v))
}

/// Grant a temporary permission (needs `ttl_secs` or `until_restart`).
#[utoipa::path(
    post, path = "/policy/temp", tag = "policy",
    security(("bearer_auth" = ["policy:write"])),
    request_body = TempGrantInput,
    responses((status = 201, description = "Granted", body = TempGrantDto))
)]
pub async fn grant_temp(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<TempGrantInput>,
) -> ApiResult<(StatusCode, Json<TempGrantDto>)> {
    let (page, kind) = temp_parts(&req)?;
    let st = state.policy.clone();
    let g = blocking(move || {
        st.grant_temp(
            PROFILE,
            page,
            kind,
            req.ttl_secs,
            req.until_restart,
            req.persist,
        )
        .map(|g| temp_out(&g, st.now()))
        .map_err(store_err)
    })
    .await?;
    Ok((StatusCode::CREATED, Json(g)))
}

/// Revoke every temporary permission.
#[utoipa::path(
    delete, path = "/policy/temp", tag = "policy",
    security(("bearer_auth" = ["policy:write"])),
    responses((status = 200, description = "Revoked", body = MessageResponse))
)]
pub async fn revoke_all_temp(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<MessageResponse>> {
    let st = state.policy.clone();
    let n = blocking(move || st.revoke_all_temps(PROFILE).map_err(store_err)).await?;
    Ok(Json(MessageResponse {
        message: format!("{n} temporary permission(s) revoked"),
    }))
}

/// Revoke one temporary permission.
#[utoipa::path(
    delete, path = "/policy/temp/{id}", tag = "policy",
    security(("bearer_auth" = ["policy:write"])),
    params(("id" = String, Path, description = "Grant id")),
    responses((status = 200, description = "Revoked", body = MessageResponse))
)]
pub async fn revoke_temp(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<MessageResponse>> {
    let st = state.policy.clone();
    let rid = id.clone();
    blocking(move || st.revoke_temp(PROFILE, &rid).map_err(store_err)).await?;
    Ok(Json(MessageResponse {
        message: format!("Temporary permission '{id}' revoked"),
    }))
}

// ---- explain / preview ----

fn html_rule_out(r: &sp::HtmlRule) -> HtmlRuleDto {
    HtmlRuleDto {
        selector: r.selector.into(),
        op: match r.op {
            sp::HtmlOp::UnwrapKeepContent => "unwrap".into(),
            sp::HtmlOp::Remove => "remove".into(),
            sp::HtmlOp::RemoveAttribute(a) => format!("remove-attribute:{a}"),
        },
        when: match r.when {
            sp::HtmlWhen::Always => "always".into(),
            sp::HtmlWhen::UrlDenied { attr, cap } => {
                format!("url-denied:{attr}:{}", cap.as_str())
            }
        },
    }
}

fn explain_url(
    rules: &sp::RuleSet,
    compiled: &sp::CompiledPolicy,
    url: &str,
    now: u64,
) -> ApiResult<ExplainResponse> {
    let (scheme, host, port) = sp::parse_origin(url)
        .ok_or_else(|| ApiError::ValidationError("url must be an absolute http(s) URL".into()))?;
    let page = compiled.decide(scheme.as_str(), &host, port);
    let px = sp::ProxyInject {
        nonce: Some("PROXY_NONCE"),
        path: Some("/__adblock__/"),
    };
    let csp = page.csp_with_notes(Some(&px));
    let html = page.html_actions();
    let m = rules.matching(Some(scheme), &host, now);
    let mut temps: Vec<_> = m.temps.iter().map(|t| temp_out(t, now)).collect();
    temps.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
    Ok(ExplainResponse {
        url: url.to_string(),
        host: host.clone(),
        site: page.site().to_string(),
        enabled: page.is_active(),
        matched_site_rules: m.site_rules.iter().map(|r| site_out(r)).collect(),
        matched_source_rules: m.source_rules.iter().map(|r| source_out(r)).collect(),
        active_temps: temps,
        effective: profile_out(&page.profile()),
        csp: csp
            .directives
            .iter()
            .map(|d| CspDirectiveDto {
                name: d.name.into(),
                sources: d.sources.clone(),
            })
            .collect(),
        csp_header: (!csp.directives.is_empty()).then(|| sp::render_header(&csp.directives)),
        permissions_policy: page.permissions_policy(),
        html_actions: HtmlActionsDto {
            unwrap_noscript: html.unwrap_noscript,
            strip_scripts: html.strip_scripts,
            rules: html.rules.iter().map(html_rule_out).collect(),
        },
        network_enforce: caps_out(page.network_hints().enforce),
        notes: csp.notes,
        generation: compiled.generation(),
    })
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExplainQuery {
    /// Absolute http(s) URL of the page.
    pub url: String,
}

/// Explain what the policy does to a page URL: matched rules, effective capabilities, the exact
/// CSP that would be added, and the HTML rewriter's instructions.
#[utoipa::path(
    get, path = "/policy/explain", tag = "policy",
    security(("bearer_auth" = ["policy:read"])),
    params(ExplainQuery),
    responses((status = 200, description = "Explanation", body = ExplainResponse))
)]
pub async fn explain(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<ExplainQuery>,
) -> ApiResult<Json<ExplainResponse>> {
    let st = state.policy.clone();
    let out = blocking(move || {
        let rules = st.rules(PROFILE).map_err(store_err)?;
        let compiled = st.snapshot(PROFILE).map_err(store_err)?;
        explain_url(&rules, &compiled, &q.url, st.now())
    })
    .await?;
    Ok(Json(out))
}

/// Evaluate a proposed change against a page URL without saving it.
#[utoipa::path(
    post, path = "/policy/preview", tag = "policy",
    security(("bearer_auth" = ["policy:read"])),
    request_body = PreviewRequest,
    responses((status = 200, description = "Before/after", body = PreviewResponse))
)]
pub async fn preview(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<PreviewRequest>,
) -> ApiResult<Json<PreviewResponse>> {
    check_note(&req.add_site_rule.as_ref().and_then(|r| r.note.clone()))?;
    let st = state.policy.clone();
    let out = blocking(move || {
        let now = st.now();
        let rules = st.rules(PROFILE).map_err(store_err)?;
        let before_c = st.snapshot(PROFILE).map_err(store_err)?;
        let mut m = rules.clone();
        for id in &req.remove_ids {
            m.site_rules.remove(id);
            m.source_rules.remove(id);
            m.temps.remove(id);
        }
        if let Some(i) = &req.add_site_rule {
            let r = sp::SiteRule {
                id: "preview-site".into(),
                scope: scope_in(&i.scope)?,
                preset: preset_in(&i.preset)?,
                note: None,
            };
            r.validate()
                .map_err(|e| ApiError::ValidationError(e.to_string()))?;
            m.site_rules.retain(|_, x| x.scope != r.scope);
            m.site_rules.insert(r.id.clone(), r);
        }
        if let Some(i) = &req.add_source_rule {
            let r = sp::SourceRule {
                id: "preview-source".into(),
                page: scope_in(&i.page)?,
                source: scope_in(&i.source)?,
                caps: caps_in(&i.caps)?,
                effect: effect_in(&i.effect)?,
                note: None,
            };
            r.validate()
                .map_err(|e| ApiError::ValidationError(e.to_string()))?;
            m.source_rules
                .retain(|_, x| !(x.page == r.page && x.source == r.source && x.effect == r.effect));
            m.source_rules.insert(r.id.clone(), r);
        }
        if let Some(i) = &req.add_temp {
            let (page, kind) = temp_parts(i)?;
            let g = sp::TempGrant {
                id: "preview-temp".into(),
                page,
                kind,
                expires_at: i.ttl_secs.map(|t| now.saturating_add(t)),
                until_restart: i.until_restart,
                persist: i.persist,
                created_at: now,
            };
            g.validate()
                .map_err(|e| ApiError::ValidationError(e.to_string()))?;
            m.temps.insert(g.id.clone(), g);
        }
        let after_c = sp::CompiledPolicy::compile(&m, before_c.generation(), now);
        let before = explain_url(&rules, &before_c, &req.url, now)?;
        let after = explain_url(&m, &after_c, &req.url, now)?;
        let render = |e: &ExplainResponse| -> Vec<String> {
            e.csp
                .iter()
                .map(|d| format!("{} {}", d.name, d.sources.join(" ")))
                .collect()
        };
        let (rb, ra) = (render(&before), render(&after));
        let csp_added = ra.iter().filter(|d| !rb.contains(d)).cloned().collect();
        let csp_removed = rb.iter().filter(|d| !ra.contains(d)).cloned().collect();
        let changed = {
            let (mut b, mut a) = (before.clone(), after.clone());
            // Ignore fields that differ only because the two evaluations ran separately.
            b.generation = 0;
            a.generation = 0;
            b != a
        };
        Ok(PreviewResponse {
            before,
            after,
            changed,
            csp_added,
            csp_removed,
        })
    })
    .await?;
    Ok(Json(out))
}

// ---- import / export ----

/// Export the policy (settings, site rules, source rules) as a portable document.
#[utoipa::path(
    get, path = "/policy/export", tag = "policy",
    security(("bearer_auth" = ["policy:read"])),
    responses((status = 200, description = "Policy document", body = PolicyExportDto))
)]
pub async fn export(State(state): State<Arc<AppState>>) -> ApiResult<Json<PolicyExportDto>> {
    let st = state.policy.clone();
    let rules = blocking(move || st.rules(PROFILE).map_err(store_err)).await?;
    let doc = rules.export();
    Ok(Json(PolicyExportDto {
        version: doc.version,
        settings: settings_out(&doc.settings),
        site_rules: doc
            .site_rules
            .iter()
            .map(|r| SiteRuleInput {
                scope: r.scope.to_string(),
                preset: preset_out(&r.preset),
                note: r.note.clone(),
            })
            .collect(),
        source_rules: doc
            .source_rules
            .iter()
            .map(|r| SourceRuleInput {
                page: r.page.to_string(),
                source: r.source.to_string(),
                caps: caps_out(r.caps),
                effect: effect_out(r.effect),
                note: r.note.clone(),
            })
            .collect(),
    }))
}

/// Import a policy document, replacing or merging into the current rules.
#[utoipa::path(
    post, path = "/policy/import", tag = "policy",
    security(("bearer_auth" = ["policy:write"])),
    request_body = PolicyImportRequest,
    responses((status = 200, description = "Imported", body = MessageResponse))
)]
pub async fn import(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<PolicyImportRequest>,
) -> ApiResult<Json<MessageResponse>> {
    let replace = match req.mode.as_str() {
        "replace" => true,
        "merge" => false,
        o => {
            return Err(ApiError::ValidationError(format!(
                "unknown mode '{o}' (replace, merge)"
            )))
        }
    };
    let d = req.document;
    let mut site_rules = Vec::new();
    for r in &d.site_rules {
        check_note(&r.note)?;
        site_rules.push(sp::model::ExportedSiteRule {
            scope: scope_in(&r.scope)?,
            preset: preset_in(&r.preset)?,
            note: r.note.clone(),
        });
    }
    let mut source_rules = Vec::new();
    for r in &d.source_rules {
        check_note(&r.note)?;
        source_rules.push(sp::model::ExportedSourceRule {
            page: scope_in(&r.page)?,
            source: scope_in(&r.source)?,
            caps: caps_in(&r.caps)?,
            effect: effect_in(&r.effect)?,
            note: r.note.clone(),
        });
    }
    let doc = sp::PolicyExport {
        version: d.version,
        settings: settings_in(&d.settings)?,
        site_rules,
        source_rules,
    };
    let (ns, nr) = (doc.site_rules.len(), doc.source_rules.len());
    let st = state.policy.clone();
    blocking(move || st.import(PROFILE, doc, replace).map_err(store_err)).await?;
    Ok(Json(MessageResponse {
        message: format!("Imported {ns} site rule(s) and {nr} source rule(s)"),
    }))
}

// ---- reports ----

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ReportsQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    /// Only pages of this site (registrable domain or host).
    pub site: Option<String>,
}

fn report_out(r: &sp::PageReport) -> PolicyReportDto {
    PolicyReportDto {
        page: r.page.clone(),
        dropped: r.dropped,
        events: r.events,
        last_seen: r.last_seen,
        items: r
            .items
            .iter()
            .map(|i| BlockedItemDto {
                capability: i.cap.as_str().into(),
                source: i.source.clone(),
                count: i.count,
                first_seen: i.first_seen,
                last_seen: i.last_seen,
                via_network: i.via_network,
                via_csp: i.via_csp,
                sample: i.sample.clone(),
                suggested_allow: i.suggested_allow().map(|(s, c)| SuggestedAllowDto {
                    source: s.to_string(),
                    caps: caps_out(c),
                }),
            })
            .collect(),
    }
}

/// Recently blocked sources per page, for one-click allow. Fed by the proxy's network blocks and
/// by the CSP violation reports the in-page code forwards; empty until the proxy records them.
#[utoipa::path(
    get, path = "/policy/reports", tag = "policy",
    security(("bearer_auth" = ["policy:read"])),
    params(ReportsQuery),
    responses((status = 200, description = "Per-page blocked sources", body = Page<PolicyReportDto>))
)]
pub async fn reports(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<ReportsQuery>,
) -> ApiResult<Json<Page<PolicyReportDto>>> {
    let want = q
        .site
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    let all: Vec<PolicyReportDto> = state
        .policy
        .report_pages(PROFILE)
        .iter()
        .filter(|r| {
            want.as_ref()
                .is_none_or(|w| r.page == *w || sp::site_of(&r.page) == sp::site_of(w))
        })
        .map(report_out)
        .collect();
    Ok(Json(Page::from_vec(all, q.page, q.limit)))
}

// ---- in-page panel settings ----

fn panel_out(p: &script_policy::panel::PanelSettings) -> api_types::PanelSettingsDto {
    api_types::PanelSettingsDto {
        enabled: p.enabled,
        hotkey: p.hotkey.clone(),
        auth: match p.auth {
            script_policy::panel::PanelAuth::Session => "session",
            script_policy::panel::PanelAuth::Pin => "pin",
            script_policy::panel::PanelAuth::None => "none",
        }
        .into(),
        pin_set: p.pin_hash.is_some(),
        reserved_host: String::new(),
    }
}

/// The in-page panel settings of the default profile.
#[utoipa::path(
    get, path = "/policy/panel", tag = "policy",
    security(("bearer_auth" = ["policy:read"])),
    responses((status = 200, description = "Panel settings", body = api_types::PanelSettingsDto))
)]
pub async fn get_panel(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<api_types::PanelSettingsDto>> {
    let st = state.policy.clone();
    let p = blocking(move || st.panel_settings(PROFILE).map_err(store_err)).await?;
    let mut dto = panel_out(&p);
    dto.reserved_host = state
        .proxy_state
        .config
        .read()
        .script_control
        .panel_host
        .clone();
    Ok(Json(dto))
}

/// Change the in-page panel settings (enable, hotkey, authentication mode, PIN). The panel is
/// read-only in the page; the authentication mode decides how a change is confirmed on the proxy's
/// reserved host. A PIN is required for `pin` mode before changes can be applied from the panel.
#[utoipa::path(
    put, path = "/policy/panel", tag = "policy",
    security(("bearer_auth" = ["policy:write"])),
    request_body = api_types::PanelSettingsInput,
    responses(
        (status = 200, description = "Saved", body = api_types::PanelSettingsDto),
        (status = 400, description = "Invalid hotkey, auth mode or PIN"),
    )
)]
pub async fn put_panel(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<api_types::PanelSettingsInput>,
) -> ApiResult<Json<api_types::PanelSettingsDto>> {
    use script_policy::panel::{hash_pin, valid_hotkey, PanelAuth};
    let st = state.policy.clone();
    let out = blocking(move || {
        let mut p = st.panel_settings(PROFILE).map_err(store_err)?;
        if let Some(e) = req.enabled {
            p.enabled = e;
        }
        if let Some(h) = &req.hotkey {
            if !valid_hotkey(h) {
                return Err(ApiError::ValidationError(
                    "hotkey must be modifiers plus one key, with Alt, Ctrl or Meta, e.g. Alt+Shift+A".into(),
                ));
            }
            p.hotkey = h.clone();
        }
        if let Some(a) = &req.auth {
            p.auth = match a.as_str() {
                "pin" => PanelAuth::Pin,
                "session" => PanelAuth::Session,
                "none" => PanelAuth::None,
                _ => return Err(ApiError::ValidationError("auth must be pin, session or none".into())),
            };
        }
        if req.clear_pin {
            p.pin_hash = None;
        }
        if let Some(pin) = &req.pin {
            let salt = uuid::Uuid::new_v4().simple().to_string();
            p.pin_hash = Some(hash_pin(pin, &salt).map_err(|e| ApiError::ValidationError(e.into()))?);
        }
        st.set_panel_settings(PROFILE, &p).map_err(store_err)?;
        Ok(p)
    })
    .await?;
    let mut dto = panel_out(&out);
    dto.reserved_host = state
        .proxy_state
        .config
        .read()
        .script_control
        .panel_host
        .clone();
    Ok(Json(dto))
}

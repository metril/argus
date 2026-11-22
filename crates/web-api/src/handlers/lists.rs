//! Filter-list handlers: CRUD, per-list status, refresh, update schedule and engine rebuilds.

use std::collections::BTreeMap;
use std::sync::Arc;

use api_types::{
    AddFilterListRequest, BuildState, BuildSummary, CatalogueEntryResponse, EngineStatusResponse,
    ExtRuleResponse, FilterListResponse, ListMetaDto, ListReport, ListStatusResponse,
    MessageResponse, Page, ReportIssueDto, ScheduleResponse, UpdateFilterListRequest,
    UpdateProxyConfigRequest, UpdateScheduleRequest,
};
use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::Deserialize;
use tracing::info;
use utoipa::IntoParams;
use validator::Validate;

use super::proxy::apply_update;
use crate::auth::authz::Principal;
use crate::error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult};
use crate::state::{blocking, AppState};

fn filter_list_response(state: &AppState, list: &filter_engine::FilterList) -> FilterListResponse {
    let status = state.filter_store.get_status(&list.id).unwrap_or_default();
    FilterListResponse {
        id: list.id.clone(),
        name: list.name.clone(),
        url: list.url.clone(),
        enabled: list.enabled,
        last_updated: list.last_updated.map(|dt| dt.to_rfc3339()),
        rule_count: list.rule_count,
        last_error: status.last_error,
        last_checked: status.last_checked.map(|dt| dt.to_rfc3339()),
        format: list.format.as_str().to_string(),
        allowlist: list.allowlist,
    }
}

fn parse_format(f: &str) -> ApiResult<filter_engine::ListFormat> {
    f.parse::<filter_engine::ListFormat>()
        .map_err(ApiError::ValidationError)
}

/// Engine build state.
pub async fn engine_status(state: &AppState) -> EngineStatusResponse {
    EngineStatusResponse {
        building: state.list_service.is_building(),
        build_count: state.list_service.build_count(),
        enabled: state.shared_engine.is_enabled(),
        scriptlets_ready: *state.list_service.scriptlets_ready().borrow(),
    }
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListFiltersQuery {
    /// Only enabled / only disabled lists.
    pub enabled: Option<bool>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

/// List filter lists.
#[utoipa::path(
    get, path = "/lists", tag = "lists",
    security(("bearer_auth" = ["lists:read"])),
    params(ListFiltersQuery),
    responses((status = 200, description = "Filter lists", body = Page<FilterListResponse>))
)]
pub async fn list_filter_lists(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<ListFiltersQuery>,
) -> ApiResult<Json<Page<FilterListResponse>>> {
    let all = state
        .filter_store
        .get_all()?
        .into_iter()
        .filter(|l| q.enabled.is_none_or(|e| l.enabled == e))
        .map(|l| filter_list_response(&state, &l))
        .collect();
    Ok(Json(Page::from_vec(all, q.page, q.limit)))
}

/// Add a filter list and rebuild the engine.
#[utoipa::path(
    post, path = "/lists", tag = "lists",
    security(("bearer_auth" = ["lists:write"])),
    request_body = AddFilterListRequest,
    responses((status = 201, description = "Added", body = FilterListResponse))
)]
pub async fn add_filter_list(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiJson(req): ApiJson<AddFilterListRequest>,
) -> ApiResult<(StatusCode, Json<FilterListResponse>)> {
    req.validate()?;
    validate_filter_url(&req.url)?;
    if state.filter_store.exists(&req.id)? {
        return Err(ApiError::AlreadyExists(format!("Filter list '{}'", req.id)));
    }
    let mut list =
        filter_engine::FilterList::new(req.id.clone(), req.name.clone(), req.url.clone());
    list.enabled = req.enabled.unwrap_or(true);
    if let Some(f) = &req.format {
        list.format = parse_format(f)?;
    }
    list.allowlist = req.allowlist.unwrap_or(false);
    let (st, l) = (state.clone(), list.clone());
    blocking(move || Ok(st.filter_store.upsert_durable(&l)?)).await?;
    info!("Filter list '{}' added by {}", req.id, p.username);
    state.list_service.trigger();
    Ok((
        StatusCode::CREATED,
        Json(filter_list_response(&state, &list)),
    ))
}

/// Get one filter list.
#[utoipa::path(
    get, path = "/lists/{id}", tag = "lists",
    security(("bearer_auth" = ["lists:read"])),
    params(("id" = String, Path, description = "List id")),
    responses((status = 200, description = "Filter list", body = FilterListResponse))
)]
pub async fn get_filter_list(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<FilterListResponse>> {
    match state.filter_store.get(&id)? {
        Some(list) => Ok(Json(filter_list_response(&state, &list))),
        None => Err(ApiError::NotFound(format!("Filter list '{id}' not found"))),
    }
}

/// Update a filter list (a changed URL discards the cached copy) and rebuild the engine.
#[utoipa::path(
    put, path = "/lists/{id}", tag = "lists",
    security(("bearer_auth" = ["lists:write"])),
    params(("id" = String, Path, description = "List id")),
    request_body = UpdateFilterListRequest,
    responses((status = 200, description = "Updated", body = FilterListResponse))
)]
pub async fn update_filter_list(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<UpdateFilterListRequest>,
) -> ApiResult<Json<FilterListResponse>> {
    req.validate()?;
    if let Some(url) = &req.url {
        validate_filter_url(url)?;
    }
    let format = req.format.as_deref().map(parse_format).transpose()?;
    let mut list = state
        .filter_store
        .get(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("Filter list '{id}' not found")))?;
    if let Some(name) = req.name {
        list.name = name;
    }
    if let Some(url) = req.url {
        if url != list.url {
            list.url = url;
            list.etag = None;
            list.last_updated = None;
            list.rule_count = 0;
            let _ = state.filter_store.set_status(&id, &Default::default());
        }
    }
    if let Some(enabled) = req.enabled {
        list.enabled = enabled;
    }
    if let Some(f) = format {
        list.format = f;
    }
    if let Some(a) = req.allowlist {
        list.allowlist = a;
    }
    let (st, l) = (state.clone(), list.clone());
    blocking(move || Ok(st.filter_store.upsert_durable(&l)?)).await?;
    info!("Filter list '{id}' updated by {}", p.username);
    state.list_service.trigger();
    Ok(Json(filter_list_response(&state, &list)))
}

/// Delete a filter list and rebuild the engine.
#[utoipa::path(
    delete, path = "/lists/{id}", tag = "lists",
    security(("bearer_auth" = ["lists:write"])),
    params(("id" = String, Path, description = "List id")),
    responses((status = 200, description = "Deleted", body = MessageResponse))
)]
pub async fn delete_filter_list(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<MessageResponse>> {
    let (st, rid) = (state.clone(), id.clone());
    if !blocking(move || Ok(st.filter_store.remove(&rid)?)).await? {
        return Err(ApiError::NotFound(format!("Filter list '{id}' not found")));
    }
    info!("Filter list '{id}' deleted by {}", p.username);
    state.list_service.trigger();
    Ok(Json(MessageResponse {
        message: format!("Filter list '{id}' deleted"),
    }))
}

/// Fetch outcome of one list: last check, last success and last error.
#[utoipa::path(
    get, path = "/lists/{id}/status", tag = "lists",
    security(("bearer_auth" = ["lists:read"])),
    params(("id" = String, Path, description = "List id")),
    responses((status = 200, description = "List status", body = ListStatusResponse))
)]
pub async fn get_list_status(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<ListStatusResponse>> {
    let list = state
        .filter_store
        .get(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("Filter list '{id}' not found")))?;
    let s = state.filter_store.get_status(&id).unwrap_or_default();
    Ok(Json(ListStatusResponse {
        id: list.id,
        enabled: list.enabled,
        rule_count: list.rule_count,
        last_updated: list.last_updated.map(|t| t.to_rfc3339()),
        last_checked: s.last_checked.map(|t| t.to_rfc3339()),
        last_success: s.last_success.map(|t| t.to_rfc3339()),
        last_error: s.last_error,
    }))
}

/// Re-download one list now (ignoring its cached validators) and rebuild the engine.
#[utoipa::path(
    post, path = "/lists/{id}/refresh", tag = "lists",
    security(("bearer_auth" = ["lists:write"])),
    params(("id" = String, Path, description = "List id")),
    responses((status = 202, description = "Refresh started", body = EngineStatusResponse))
)]
pub async fn refresh_list(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<(StatusCode, Json<EngineStatusResponse>)> {
    let mut list = state
        .filter_store
        .get(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("Filter list '{id}' not found")))?;
    list.etag = None;
    state.filter_store.upsert(&list)?;
    let mut status = state.filter_store.get_status(&id).unwrap_or_default();
    status.last_modified = None;
    let _ = state.filter_store.set_status(&id, &status);
    state.list_service.trigger();
    let mut st = engine_status(&state).await;
    st.building = true;
    Ok((StatusCode::ACCEPTED, Json(st)))
}

/// Refresh every list now (conditional requests; unchanged lists are not re-downloaded).
#[utoipa::path(
    post, path = "/lists/refresh", tag = "lists",
    security(("bearer_auth" = ["lists:write"])),
    responses((status = 202, description = "Refresh started", body = EngineStatusResponse))
)]
pub async fn refresh_all_lists(
    State(state): State<Arc<AppState>>,
) -> ApiResult<(StatusCode, Json<EngineStatusResponse>)> {
    state.list_service.trigger();
    let mut st = engine_status(&state).await;
    st.building = true;
    Ok((StatusCode::ACCEPTED, Json(st)))
}

fn schedule_response(state: &AppState) -> ScheduleResponse {
    let (auto, interval) = state.list_service.schedule();
    ScheduleResponse {
        auto_update: auto,
        interval_hours: interval.as_secs() / 3600,
    }
}

/// The automatic list-update schedule.
#[utoipa::path(
    get, path = "/lists/schedule", tag = "lists",
    security(("bearer_auth" = ["lists:read"])),
    responses((status = 200, description = "Schedule", body = ScheduleResponse))
)]
pub async fn get_schedule(State(state): State<Arc<AppState>>) -> Json<ScheduleResponse> {
    Json(schedule_response(&state))
}

/// Change the schedule; applied immediately and persisted to the proxy configuration.
#[utoipa::path(
    put, path = "/lists/schedule", tag = "lists",
    security(("bearer_auth" = ["lists:write"])),
    request_body = UpdateScheduleRequest,
    responses((status = 200, description = "Updated schedule", body = ScheduleResponse))
)]
pub async fn put_schedule(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiJson(req): ApiJson<UpdateScheduleRequest>,
) -> ApiResult<Json<ScheduleResponse>> {
    req.validate()?;
    apply_update(
        &state,
        UpdateProxyConfigRequest {
            auto_update: req.auto_update,
            update_interval_hours: req.interval_hours,
            ..Default::default()
        },
        &p.username,
    )
    .await?;
    Ok(Json(schedule_response(&state)))
}

/// Trigger an engine rebuild from the current lists and custom rules.
#[utoipa::path(
    post, path = "/engine/reload", tag = "engine",
    security(("bearer_auth" = ["engine:reload"])),
    responses((status = 202, description = "Rebuild started", body = EngineStatusResponse))
)]
pub async fn reload_engine(
    State(state): State<Arc<AppState>>,
) -> ApiResult<(StatusCode, Json<EngineStatusResponse>)> {
    state.list_service.trigger();
    let mut st = engine_status(&state).await;
    st.building = true;
    Ok((StatusCode::ACCEPTED, Json(st)))
}

/// Engine build status.
#[utoipa::path(
    get, path = "/engine/status", tag = "engine",
    security(("bearer_auth" = ["stats:read"])),
    responses((status = 200, description = "Build status", body = EngineStatusResponse))
)]
pub async fn get_engine_status(State(state): State<Arc<AppState>>) -> Json<EngineStatusResponse> {
    Json(engine_status(&state).await)
}

pub(crate) fn report_dto(
    id: &str,
    r: &filter_engine::ListReport,
    content_sha: Option<String>,
) -> ListReport {
    ListReport {
        id: id.to_string(),
        format: r.format.as_str().into(),
        format_override: r.format_override.as_str().into(),
        allowlist: r.allowlist,
        total_lines: r.total_lines,
        network: r.network,
        cosmetic: r.cosmetic,
        ext: r.ext,
        skipped: r.skipped,
        deduped: r.duplicates,
        translated: r.translated,
        rejected: r.rejected,
        ip_ranges: r.ip_ranges,
        error_count: r.error_count,
        issues: r
            .errors
            .iter()
            .map(|e| ReportIssueDto {
                line: e.line,
                reason: e.reason.clone(),
            })
            .collect(),
        ext_counts: r.ext_counts.clone(),
        skipped_reasons: r.skipped_reasons.clone(),
        meta: ListMetaDto {
            title: r.meta.title.clone(),
            homepage: r.meta.homepage.clone(),
            version: r.meta.version.clone(),
            expires_secs: r.meta.expires_secs,
            redirect: r.meta.redirect.clone(),
        },
        content_sha,
    }
}

/// What the last build made of one list: detected format, rule counts, first parse issues,
/// header metadata and content digest.
#[utoipa::path(
    get, path = "/lists/{id}/report", tag = "lists",
    security(("bearer_auth" = ["lists:read"])),
    params(("id" = String, Path, description = "List id")),
    responses((status = 200, description = "Build report of the list", body = ListReport))
)]
pub async fn get_list_report(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<ListReport>> {
    if !state.filter_store.exists(&id)? {
        return Err(ApiError::NotFound(format!("Filter list '{id}' not found")));
    }
    let r = state
        .list_service
        .report(&id)
        .ok_or_else(|| ApiError::NotFound(format!("No build report for '{id}' yet (not built)")))?;
    let sha = state
        .filter_store
        .get_status(&id)
        .ok()
        .and_then(|s| s.content_sha);
    Ok(Json(report_dto(&id, &r, sha)))
}

/// Build state and totals of the installed engine.
#[utoipa::path(
    get, path = "/engine/build", tag = "engine",
    security(("bearer_auth" = ["stats:read"])),
    responses((status = 200, description = "Build summary", body = BuildSummary))
)]
pub async fn get_build_summary(State(state): State<Arc<AppState>>) -> Json<BuildSummary> {
    let s = state.list_service.summary();
    let mut ext_counts: BTreeMap<String, usize> = BTreeMap::new();
    for r in state.shared_engine.ext_rules().iter() {
        *ext_counts.entry(r.kind.as_str().to_string()).or_default() += 1;
    }
    use list_service::BuildState as S;
    Json(BuildSummary {
        state: match s.state {
            S::Idle => BuildState::Idle,
            S::Fetching { done, total } => BuildState::Fetching { done, total },
            S::Compiling => BuildState::Compiling,
            S::Failed { error } => BuildState::Failed { error },
        },
        building: state.list_service.is_building(),
        built_at: s.built_at.map(|t| t.to_rfc3339()),
        compile_ms: s.duration_ms,
        last_build_ms: s.last_build_ms,
        last_build_at: s.last_build_at.map(|t| t.to_rfc3339()),
        lists: s.lists,
        network: s.network,
        cosmetic: s.cosmetic,
        ext: s.ext,
        rejected: s.rejected,
        ip_ranges: s.ip_ranges,
        domain_set: s.domain_set,
        duplicates: s.duplicates,
        from_persisted: s.from_persisted,
        ext_counts,
    })
}

/// The default-disabled catalogue of well-known lists (hosts, domain and IP lists).
#[utoipa::path(
    get, path = "/lists/catalogue", tag = "lists",
    security(("bearer_auth" = ["lists:read"])),
    responses((status = 200, description = "Catalogue", body = Vec<CatalogueEntryResponse>))
)]
pub async fn get_catalogue(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<Vec<CatalogueEntryResponse>>> {
    let have: std::collections::HashSet<String> = state
        .filter_store
        .get_all()?
        .into_iter()
        .map(|l| l.id)
        .collect();
    Ok(Json(
        filter_engine::catalogue()
            .into_iter()
            .map(|e| CatalogueEntryResponse {
                added: have.contains(e.id),
                id: e.id.into(),
                name: e.name.into(),
                url: e.url.into(),
                format: e.format.as_str().into(),
                category: e.category.into(),
                licence: e.licence.into(),
            })
            .collect(),
    ))
}

/// Add a catalogue entry as an enabled list and rebuild the engine.
#[utoipa::path(
    post, path = "/lists/catalogue/{id}", tag = "lists",
    security(("bearer_auth" = ["lists:write"])),
    params(("id" = String, Path, description = "Catalogue id")),
    responses((status = 201, description = "Added", body = FilterListResponse))
)]
pub async fn add_from_catalogue(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<(StatusCode, Json<FilterListResponse>)> {
    let entry = filter_engine::catalogue()
        .into_iter()
        .find(|e| e.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("Catalogue entry '{id}' not found")))?;
    if state.filter_store.exists(&id)? {
        return Err(ApiError::AlreadyExists(format!("Filter list '{id}'")));
    }
    let mut list = entry.to_filter_list();
    list.enabled = true;
    let (st, l) = (state.clone(), list.clone());
    blocking(move || Ok(st.filter_store.upsert_durable(&l)?)).await?;
    info!(
        "Filter list '{id}' added from the catalogue by {}",
        p.username
    );
    state.list_service.trigger();
    Ok((
        StatusCode::CREATED,
        Json(filter_list_response(&state, &list)),
    ))
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExtRulesQuery {
    /// Only this kind (`replace`, `cookie`, `html-filter`, ...).
    pub kind: Option<String>,
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

/// Rules that parsed but are not enforced yet (handed off), read-only.
#[utoipa::path(
    get, path = "/rules/ext", tag = "rules",
    security(("bearer_auth" = ["rules:read"])),
    params(ExtRulesQuery),
    responses((status = 200, description = "Handed-off rules", body = Page<ExtRuleResponse>))
)]
pub async fn list_ext_rules(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<ExtRulesQuery>,
) -> Json<Page<ExtRuleResponse>> {
    let rules = state.shared_engine.ext_rules();
    let total_matching = rules
        .iter()
        .filter(|r| q.kind.as_deref().is_none_or(|k| r.kind.as_str() == k))
        .count();
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let page = q.page.unwrap_or(1).max(1);
    let items: Vec<ExtRuleResponse> = rules
        .iter()
        .filter(|r| q.kind.as_deref().is_none_or(|k| r.kind.as_str() == k))
        .skip((page as usize - 1).saturating_mul(limit as usize))
        .take(limit as usize)
        .map(|r| ExtRuleResponse {
            kind: r.kind.as_str().into(),
            raw: r.raw.clone(),
            domains: r.domains.clone(),
        })
        .collect();
    Json(Page {
        has_more: (page as usize - 1) * limit as usize + items.len() < total_matching,
        items,
        total: total_matching,
        page,
        limit,
    })
}

fn validate_filter_url(url: &str) -> ApiResult<()> {
    let parsed =
        url::Url::parse(url).map_err(|_| ApiError::ValidationError("Invalid URL".to_string()))?;
    if parsed.scheme() != "https" {
        return Err(ApiError::ValidationError(
            "Only HTTPS URLs are allowed for security".to_string(),
        ));
    }
    if let Some(host) = parsed.host_str() {
        if host == "localhost" || host == "127.0.0.1" || host == "::1" {
            return Err(ApiError::ValidationError(
                "Local addresses are not allowed".to_string(),
            ));
        }
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if is_private_ip(&ip) {
                return Err(ApiError::ValidationError(
                    "Private IP addresses are not allowed".to_string(),
                ));
            }
        }
        let host_lower = host.to_lowercase();
        for pattern in ["internal", "intranet", "local", "private", "corp", "lan"] {
            if host_lower.contains(pattern) {
                return Err(ApiError::ValidationError(
                    "Internal hostnames are not allowed".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

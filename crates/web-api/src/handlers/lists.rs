//! Filter-list handlers: CRUD, per-list status, refresh, update schedule and engine rebuilds.

use std::collections::BTreeMap;
use std::sync::Arc;

use api_types::{
    AddFilterListRequest, ApplyCollectionRequest, ApplyCollectionResponse, BuildState,
    BuildSummary, CatalogueEntryResponse, CatalogueResponse, CatalogueStatus, CollectionConflict,
    CollectionResponse, DisableCollectionResponse, EngineStatusResponse, ExtRuleResponse,
    FilterListCounts, FilterListResponse, FilterListsPage, ListMetaDto, ListReport,
    ListStatusResponse, MessageResponse, Page, ReportIssueDto, ScheduleResponse,
    UpdateFilterListRequest, UpdateProxyConfigRequest, UpdateScheduleRequest,
};
use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::Deserialize;
use tracing::info;
use utoipa::IntoParams;
use validator::Validate;

use super::paging::{desc_key, natural_key, paginate, Keyed};
use super::proxy::apply_update;
use crate::auth::authz::Principal;
use crate::error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult};
use crate::state::{blocking, AppState};

fn filter_list_response(state: &AppState, list: &filter_engine::FilterList) -> FilterListResponse {
    let status = state.filter_store.get_status(&list.id).unwrap_or_default();
    let attention = needs_attention(list, status.last_error.is_some()) || list.report_attention;
    FilterListResponse {
        id: list.id.clone(),
        name: list.name.clone(),
        url: list.url.clone(),
        enabled: list.enabled,
        last_updated: list.last_updated.map(|dt| dt.to_rfc3339()),
        rule_count: list.rule_count,
        duplicate_count: list.duplicate_count,
        last_error: status.last_error,
        last_checked: status.last_checked.map(|dt| dt.to_rfc3339()),
        format: list.format.as_str().to_string(),
        allowlist: list.allowlist,
        trusted: list.trusted,
        attention,
        redundant: list.redundant,
    }
}

/// A fetch error, or an enabled list that was never fetched / is over 7 days old. (The caller
/// also flags a list whose last build found too many problems in it, see
/// `filter_engine::ListReport::attention`.)
fn needs_attention(list: &filter_engine::FilterList, has_error: bool) -> bool {
    has_error
        || (list.enabled
            && list
                .last_updated
                .is_none_or(|t| chrono::Utc::now() - t > chrono::Duration::days(7)))
}

fn parse_format(f: &str) -> ApiResult<filter_engine::ListFormat> {
    f.parse::<filter_engine::ListFormat>()
        .map_err(ApiError::ValidationError)
}

/// Engine build state.
pub async fn engine_status(state: &AppState) -> EngineStatusResponse {
    let report = state.shared_engine.resource_report();
    EngineStatusResponse {
        scriptlet_resources: report.loaded,
        scriptlet_resources_dropped: report
            .dropped
            .iter()
            .map(|d| api_types::DroppedScriptletResource {
                name: d.name.clone(),
                reason: d.reason.clone(),
            })
            .collect(),
        building: state.list_service.is_building(),
        build_count: state.list_service.build_count(),
        enabled: state.shared_engine.is_enabled(),
        scriptlets_ready: *state.list_service.scriptlets_ready().borrow(),
    }
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListFiltersQuery {
    /// Only enabled / only disabled lists (same as `status=on|off`).
    pub enabled: Option<bool>,
    /// Case-insensitive substring of the name or URL.
    pub q: Option<String>,
    /// `on` (enabled), `off` (disabled) or `attn` (fetch error or stale).
    pub status: Option<String>,
    /// `name` (default), `rules` (most rules first) or `updated` (most recently updated first).
    pub sort: Option<String>,
    /// Deprecated: use `cursor`.
    pub page: Option<u32>,
    /// Page size (1..=200, default 40).
    pub limit: Option<u32>,
    /// Opaque `next_cursor` of the previous page (stable while lists change).
    pub cursor: Option<String>,
    /// With `sort=name`: start at the first name at or after this prefix (natural order).
    pub from: Option<String>,
}

/// List filter lists, filtered by text and status and sorted. `counts` covers every status for
/// the current `q`, whatever `status` is.
#[utoipa::path(
    get, path = "/lists", tag = "lists",
    security(("bearer_auth" = ["lists:read"])),
    params(ListFiltersQuery),
    responses((status = 200, description = "Filter lists", body = FilterListsPage))
)]
pub async fn list_filter_lists(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<ListFiltersQuery>,
) -> ApiResult<Json<FilterListsPage>> {
    let status = match q.status.as_deref() {
        None => None,
        Some(s @ ("on" | "off" | "attn")) => Some(s),
        Some(o) => {
            return Err(ApiError::ValidationError(format!(
                "unknown status '{o}' (on, off, attn)"
            )))
        }
    };
    let sort = q.sort.as_deref().unwrap_or("name");
    if !["name", "rules", "updated"].contains(&sort) {
        return Err(ApiError::ValidationError(format!(
            "unknown sort '{sort}' (name, rules, updated)"
        )));
    }
    let needle = q.q.as_deref().unwrap_or("").trim().to_lowercase();
    let matching: Vec<(filter_engine::FilterList, FilterListResponse)> = state
        .filter_store
        .get_all()?
        .into_iter()
        .filter(|l| {
            needle.is_empty()
                || l.name.to_lowercase().contains(&needle)
                || l.url.to_lowercase().contains(&needle)
        })
        .map(|l| {
            let r = filter_list_response(&state, &l);
            (l, r)
        })
        .collect();
    let mut counts = FilterListCounts {
        all: matching.len(),
        on: matching.iter().filter(|(l, _)| l.enabled).count(),
        off: matching.iter().filter(|(l, _)| !l.enabled).count(),
        attn: matching.iter().filter(|(_, r)| r.attention).count(),
        letters: Vec::new(),
    };
    if q.from.is_some() && sort != "name" {
        return Err(ApiError::ValidationError("`from` needs sort=name".into()));
    }
    let rows: Vec<Keyed<FilterListResponse>> = matching
        .into_iter()
        .filter(|(l, r)| match status {
            Some("on") => l.enabled,
            Some("off") => !l.enabled,
            Some(_) => r.attention,
            None => q.enabled.is_none_or(|e| l.enabled == e),
        })
        .map(|(l, r)| {
            let name = natural_key(&r.name);
            let key = match sort {
                "rules" => format!("{}{name}", desc_key(r.rule_count as u64)),
                // Lists never updated sort last.
                "updated" => format!(
                    "{}{name}",
                    desc_key(
                        l.last_updated
                            .map_or(0, |t| t.timestamp_millis().max(0) as u64)
                    )
                ),
                _ => name,
            };
            Keyed {
                key,
                id: r.id.clone(),
                label: r.name.clone(),
                item: r,
            }
        })
        .collect();
    let from = q.from.as_deref().map(natural_key);
    let p = paginate(rows, q.limit, q.cursor.as_deref(), from.as_deref(), q.page)?;
    counts.letters = p.letters;
    Ok(Json(FilterListsPage {
        items: p.items,
        next_cursor: p.next_cursor,
        total: p.total,
        counts,
        limit: p.limit,
        has_more: p.has_more,
        page: p.page,
    }))
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
    validate_filter_url(&state, &req.url).await?;
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
    list.trusted = req.trusted.unwrap_or(false);
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

/// Record a trust change as its own audit entry (the generic entry for the route does not say
/// what was changed). Needs `lists:write`, like the route itself.
fn audit_trust_change(state: &AppState, p: &Principal, list_id: &str, trusted: bool) {
    use crate::auth::authz::Actor;
    let (actor_type, actor_id) = match &p.actor {
        Actor::Token { token_id } => ("token", token_id.clone()),
        Actor::Session { .. } => ("user", p.user_id.to_string()),
    };
    let entry = api_types::AuditEntry {
        id: String::new(),
        at: chrono::Utc::now().to_rfc3339(),
        actor_type: actor_type.into(),
        actor_id: Some(actor_id),
        actor_name: Some(p.username.clone()),
        method: "PUT".into(),
        route: format!("/api/v1/lists/{{id}}#trusted={trusted}"),
        scope: "lists:write".into(),
        target: Some(list_id.to_string()),
        status: 200,
        outcome: "success".into(),
        ip: None,
        user_agent: None,
        request_id: None,
    };
    if let Err(e) = state.audit.append(entry) {
        tracing::error!("Failed to write audit entry: {e}");
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
        validate_filter_url(&state, url).await?;
    }
    let format = req.format.as_deref().map(parse_format).transpose()?;
    let mut list = state
        .filter_store
        .get(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("Filter list '{id}' not found")))?;
    if let Some(name) = req.name {
        list.name = name;
    }
    let mut reset_status = false;
    if let Some(url) = req.url {
        if url != list.url {
            list.url = url;
            list.etag = None;
            list.last_updated = None;
            list.rule_count = 0;
            list.duplicate_count = None;
            reset_status = true;
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
    let trust_change = req.trusted.filter(|t| *t != list.trusted);
    if let Some(t) = req.trusted {
        list.trusted = t;
    }
    let (st, l, rid) = (state.clone(), list.clone(), id.clone());
    blocking(move || {
        st.filter_store.upsert_durable(&l)?;
        if reset_status {
            let _ = st.filter_store.set_status(&rid, &Default::default());
        }
        Ok(())
    })
    .await?;
    info!("Filter list '{id}' updated by {}", p.username);
    if let Some(t) = trust_change {
        audit_trust_change(&state, &p, &id, t);
    }
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
    let st = state.clone();
    let rid = id.clone();
    blocking(move || {
        let mut list = st
            .filter_store
            .get(&rid)?
            .ok_or_else(|| ApiError::NotFound(format!("Filter list '{rid}' not found")))?;
        list.etag = None;
        st.filter_store.upsert(&list)?;
        let mut status = st.filter_store.get_status(&rid).unwrap_or_default();
        status.last_modified = None;
        let _ = st.filter_store.set_status(&rid, &status);
        Ok(())
    })
    .await?;
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
        ext_enforced: r.ext_enforced,
        ext_unsupported: r.ext_unsupported,
        ext_invalid: r.ext_invalid,
        ext_needs_trust: r.ext_needs_trust,
        ext_states: r.ext_states.clone(),
        skipped: r.skipped,
        deduped: r.duplicates,
        compressed: r.compressed,
        translated: r.translated,
        rejected: r.rejected,
        disabled: r.disabled,
        ip_ranges: r.ip_ranges,
        error_count: r.error_count + r.rejected,
        conversion_errors: r.error_count,
        redundant_count: r.redundant_count,
        redundant: r.redundant,
        attention: r.attention,
        issues: r
            .errors
            .iter()
            .map(|e| ReportIssueDto {
                line: e.line,
                rule: e.rule.clone(),
                reason: e.reason.clone(),
                stage: match e.stage {
                    filter_engine::IssueStage::Conversion => "conversion",
                    filter_engine::IssueStage::Compile => "compile",
                }
                .into(),
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
        compressed: s.compressed,
        from_persisted: s.from_persisted,
        ext_counts,
        ext_stats: s.ext_stats.as_ref().map(ext_stats_dto),
    })
}

fn ext_stats_dto(s: &ext_rules::ExtStats) -> api_types::ExtStatsDto {
    api_types::ExtStatsDto {
        total: s.total,
        per_kind: s
            .per_kind
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    api_types::ExtKindStatsDto {
                        parsed: v.parsed,
                        active: v.active,
                        dropped_untrusted: v.dropped_untrusted,
                        unsupported: v.unsupported,
                        parse_errors: v.parse_errors,
                        badfiltered: v.badfiltered,
                        not_enforced: v.not_enforced,
                        not_applicable: v.not_applicable,
                    },
                )
            })
            .collect(),
        dropped_untrusted_by_list: s.dropped_untrusted_by_list.clone(),
        issues: s
            .issues
            .iter()
            .map(|i| api_types::ExtIssueDto {
                kind: i.kind.clone(),
                list: i.list.clone(),
                raw: i.raw.clone(),
                reason: i.reason.clone(),
                unsupported: i.unsupported,
            })
            .collect(),
        issues_truncated: s.issues_truncated,
    }
}

/// The catalogue of well-known lists, from the verified signed argus-lists release (or the
/// signed snapshot shipped with the binary); empty only if none has verified.
#[utoipa::path(
    get, path = "/lists/catalogue", tag = "lists",
    security(("bearer_auth" = ["lists:read"])),
    responses((status = 200, description = "Catalogue", body = CatalogueResponse))
)]
pub async fn get_catalogue(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<CatalogueResponse>> {
    let all = state.filter_store.get_all()?;
    let have: std::collections::HashSet<String> = all.iter().map(|l| l.id.clone()).collect();
    let doc = state.filter_catalogue().get();
    // A collection counts an installed list only if it is the catalogue's (same id and URL).
    let entry_url: std::collections::HashMap<&str, &str> = doc
        .iter()
        .flat_map(|d| d.entries.iter())
        .map(|e| (e.id.as_str(), e.url.as_str()))
        .collect();
    let ours: std::collections::HashMap<&str, bool> = all
        .iter()
        .filter(|l| {
            entry_url
                .get(l.id.as_str())
                .is_some_and(|u| same_url(u, &l.url))
        })
        .map(|l| (l.id.as_str(), l.enabled))
        .collect();
    let collections = doc
        .iter()
        .flat_map(|d| d.collections.iter())
        .map(|c| {
            let installed = c
                .lists
                .iter()
                .filter(|i| ours.contains_key(i.as_str()))
                .count();
            let enabled = c
                .lists
                .iter()
                .filter(|i| ours.get(i.as_str()) == Some(&true))
                .count();
            CollectionResponse {
                id: c.id.clone(),
                name: c.name.clone(),
                description: c.description.clone(),
                warning: c.warning.clone(),
                lists: c.lists.clone(),
                installed,
                enabled,
                total: c.lists.len(),
            }
        })
        .collect();
    let entries = doc
        .iter()
        .flat_map(|d| d.entries.iter())
        // An entry whose format we cannot add is not offered.
        .filter(|e| e.list_format().is_some())
        .map(|e| CatalogueEntryResponse {
            installed: have.contains(&e.id),
            id: e.id.clone(),
            name: e.name.clone(),
            url: e.url.clone(),
            format: e.format.clone(),
            category: e.category.clone(),
            licence: e.licence.clone(),
            description: e.description.clone(),
            homepage: e.homepage.clone(),
            region: e.region.clone(),
            noncommercial: e.noncommercial,
            licence_note: e.licence_note.clone(),
            trusted: e.trusted,
            default_enabled: e.default_enabled,
        })
        .collect();
    Ok(Json(CatalogueResponse {
        source: if doc.as_ref().is_some_and(|d| d.embedded) {
            "snapshot"
        } else {
            "signed"
        }
        .into(),
        fetched_at: doc.as_ref().and_then(|d| d.fetched_at.clone()),
        version: doc.as_ref().map(|d| d.version.clone()),
        entries,
        status: catalogue_status(&state),
        collections,
    }))
}

fn catalogue_status(state: &AppState) -> CatalogueStatus {
    use list_service::Origin;
    let s = state.filter_catalogue().status();
    CatalogueStatus {
        url: s.url,
        version: s.version,
        origin: s.origin.map(|o| {
            match o {
                Origin::Snapshot => "snapshot",
                Origin::Cache => "cache",
                Origin::Fetched => "fetched",
            }
            .to_string()
        }),
        fetched_at: s.fetched_at,
        last_checked: s.last_checked,
        next_check: s.next_check,
        last_ok: s.last_ok,
        last_error: s.last_error,
    }
}

/// Check the signed catalogue now (it is otherwise checked every six hours). A failed check is
/// not an HTTP error: it is reported in `last_error` of the returned status.
#[utoipa::path(
    post, path = "/lists/catalogue/refresh", tag = "lists",
    security(("bearer_auth" = ["lists:write"])),
    responses((status = 200, description = "Status after the check", body = CatalogueStatus))
)]
pub async fn refresh_catalogue(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Json<CatalogueStatus>> {
    info!("Catalogue check requested by {}", p.username);
    let _ = state.filter_catalogue().refresh().await;
    Ok(Json(catalogue_status(&state)))
}

/// A new, enabled list for a catalogue entry.
fn list_from_entry(e: &list_service::FilterCatalogueEntry) -> ApiResult<filter_engine::FilterList> {
    let format = e.list_format().ok_or_else(|| {
        ApiError::ValidationError(format!("Unsupported list format '{}'", e.format))
    })?;
    let mut l = filter_engine::FilterList::new(e.id.clone(), e.name.clone(), e.url.clone());
    l.format = format;
    l.trusted = e.trusted;
    l.enabled = true;
    Ok(l)
}

/// One list a collection apply may write: the catalogue's id, URL and trust, and the list to
/// create if it is missing.
struct Change {
    id: String,
    url: String,
    trusted: bool,
    new_list: Option<filter_engine::FilterList>,
}

/// What applying a collection would change (a preview; the write re-reads every list).
struct CollectionPlan {
    add: Vec<Change>,
    enable: Vec<Change>,
    trust: Vec<String>,
    already: Vec<String>,
    conflict: Vec<CollectionConflict>,
}

/// Whether two list URLs are the same address: parsed (scheme and host case, default port and
/// empty path normalised), or equal as text when either does not parse.
fn same_url(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

fn url_conflict(id: &str) -> CollectionConflict {
    CollectionConflict {
        id: id.to_string(),
        reason: "A list with this id but another URL is installed; it is left unchanged".into(),
    }
}

fn plan_collection(state: &AppState, id: &str) -> ApiResult<CollectionPlan> {
    let not_found = || ApiError::NotFound(format!("Collection '{id}' not found"));
    let doc = state.filter_catalogue().get().ok_or_else(not_found)?;
    let c = doc
        .collections
        .iter()
        .find(|c| c.id == id)
        .ok_or_else(not_found)?;
    let mut plan = CollectionPlan {
        add: vec![],
        enable: vec![],
        trust: vec![],
        already: vec![],
        conflict: vec![],
    };
    for lid in &c.lists {
        let Some(e) = doc.entries.iter().find(|e| &e.id == lid) else {
            continue;
        };
        let change = |new_list| Change {
            id: e.id.clone(),
            url: e.url.clone(),
            trusted: e.trusted,
            new_list,
        };
        match state.filter_store.get(lid)? {
            None => {
                let l = list_from_entry(e)?;
                if l.trusted {
                    plan.trust.push(l.id.clone());
                }
                plan.add.push(change(Some(l)));
            }
            Some(l) if !same_url(&l.url, &e.url) => plan.conflict.push(url_conflict(lid)),
            Some(l) if !l.enabled => {
                if l.trusted != e.trusted {
                    plan.trust.push(lid.clone());
                }
                plan.enable.push(change(None));
            }
            Some(_) => plan.already.push(lid.clone()),
        }
    }
    Ok(plan)
}

/// What one write did.
struct Written {
    id: String,
    added: bool,
    /// The new trust value, when it changed.
    trust: Option<bool>,
}

/// Apply the changes one by one, re-reading each list so that only `enabled` and `trusted` of a
/// list that still is the catalogue's are touched. Stops at the first failure and returns what
/// was written before it, and the lists found to clash with the catalogue's.
fn write_changes(
    store: &list_service::ListStore,
    changes: &[Change],
    fail_at: Option<usize>,
) -> (Vec<Written>, Vec<CollectionConflict>, Option<String>) {
    enum Out {
        Skip,
        Conflict,
        Enabled(Option<bool>),
    }
    let mut done = Vec::new();
    let mut clash = Vec::new();
    for (n, c) in changes.iter().enumerate() {
        if fail_at == Some(n) {
            return (done, clash, Some("write failed".into()));
        }
        let mut out = Out::Skip;
        let r = store.update_list_durable(&c.id, |l| {
            if !same_url(&l.url, &c.url) {
                out = Out::Conflict;
            } else if !l.enabled {
                l.enabled = true;
                out = Out::Enabled((l.trusted != c.trusted).then_some(c.trusted));
                l.trusted = c.trusted;
            }
        });
        match r {
            Ok(true) => match out {
                Out::Enabled(trust) => done.push(Written {
                    id: c.id.clone(),
                    added: false,
                    trust,
                }),
                Out::Conflict => clash.push(url_conflict(&c.id)),
                Out::Skip => {}
            },
            // Deleted since the plan: recreated only if the plan said add, and only if the id is
            // still free (one transaction); a list created in the gap is left alone.
            Ok(false) => {
                if let Some(l) = &c.new_list {
                    match store.insert_if_absent_durable(l) {
                        Ok(true) => done.push(Written {
                            id: c.id.clone(),
                            added: true,
                            trust: l.trusted.then_some(true),
                        }),
                        Ok(false) => clash.push(url_conflict(&c.id)),
                        Err(e) => return (done, clash, Some(e.to_string())),
                    }
                }
            }
            Err(e) => return (done, clash, Some(e.to_string())),
        }
    }
    (done, clash, None)
}

fn fail_hook(state: &AppState) -> Option<usize> {
    #[cfg(any(test, feature = "test-hooks"))]
    {
        let n = state
            .fail_collection_write_at
            .load(std::sync::atomic::Ordering::Relaxed);
        return (n != usize::MAX).then_some(n);
    }
    #[allow(unreachable_code)]
    {
        let _ = state;
        None
    }
}

/// The error for a write that failed midway: it names the lists that were changed.
fn partial_error(changed: &[String], err: &str) -> ApiError {
    ApiError::coded(
        StatusCode::INTERNAL_SERVER_ERROR,
        "collection_partial",
        format!("{err}; lists changed before the failure: {changed:?}"),
    )
}

/// Add the collection's missing lists, turn on the disabled ones and align their trust with the
/// catalogue, with one engine rebuild; or, with `dry_run`, only report that.
#[utoipa::path(
    post, path = "/lists/catalogue/collections/{id}/apply", tag = "lists",
    security(("bearer_auth" = ["lists:write"])),
    params(("id" = String, Path, description = "Collection id")),
    request_body = ApplyCollectionRequest,
    responses((status = 200, description = "What changes", body = ApplyCollectionResponse))
)]
pub async fn apply_collection(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<ApplyCollectionRequest>,
) -> ApiResult<Json<ApplyCollectionResponse>> {
    let plan = plan_collection(&state, &id)?;
    let ids = |v: &[Change]| v.iter().map(|c| c.id.clone()).collect::<Vec<_>>();
    if req.dry_run {
        return Ok(Json(ApplyCollectionResponse {
            dry_run: true,
            add: ids(&plan.add),
            enable: ids(&plan.enable),
            trust: plan.trust,
            already: plan.already,
            conflict: plan.conflict,
        }));
    }
    for c in &plan.add {
        if let Some(l) = &c.new_list {
            validate_filter_url(&state, &l.url).await?;
        }
    }
    let changes: Vec<Change> = plan.add.into_iter().chain(plan.enable).collect();
    let (st, fail_at) = (state.clone(), fail_hook(&state));
    let (written, clash, err) =
        blocking(move || Ok(write_changes(&st.filter_store, &changes, fail_at))).await?;
    let mut conflict = plan.conflict;
    for c in clash {
        if !conflict.iter().any(|x| x.id == c.id) {
            conflict.push(c);
        }
    }
    // Whatever the outcome, what was written is logged, audited and rebuilt once.
    if !written.is_empty() {
        let ids_of = |added: bool| {
            written
                .iter()
                .filter(|w| w.added == added)
                .map(|w| w.id.clone())
                .collect::<Vec<_>>()
        };
        info!(
            "Collection '{id}' applied by {}: added {:?}, enabled {:?}",
            p.username,
            ids_of(true),
            ids_of(false)
        );
        for w in &written {
            if let Some(t) = w.trust {
                audit_trust_change(&state, &p, &w.id, t);
            }
        }
        state.list_service.trigger();
    }
    if let Some(e) = err {
        let changed: Vec<String> = written.iter().map(|w| w.id.clone()).collect();
        return Err(partial_error(&changed, &e));
    }
    Ok(Json(ApplyCollectionResponse {
        dry_run: false,
        add: written
            .iter()
            .filter(|w| w.added)
            .map(|w| w.id.clone())
            .collect(),
        enable: written
            .iter()
            .filter(|w| !w.added)
            .map(|w| w.id.clone())
            .collect(),
        trust: written
            .iter()
            .filter(|w| w.trust.is_some())
            .map(|w| w.id.clone())
            .collect(),
        already: plan.already,
        conflict,
    }))
}

/// Turn off every list of a collection that is on; the lists stay installed.
#[utoipa::path(
    post, path = "/lists/catalogue/collections/{id}/disable", tag = "lists",
    security(("bearer_auth" = ["lists:write"])),
    params(("id" = String, Path, description = "Collection id")),
    responses((status = 200, description = "Lists turned off", body = DisableCollectionResponse))
)]
pub async fn disable_collection(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<DisableCollectionResponse>> {
    let not_found = || ApiError::NotFound(format!("Collection '{id}' not found"));
    let doc = state.filter_catalogue().get().ok_or_else(not_found)?;
    let c = doc
        .collections
        .iter()
        .find(|c| c.id == id)
        .ok_or_else(not_found)?;
    let targets: Vec<(String, String)> = c
        .lists
        .iter()
        .filter_map(|l| doc.entries.iter().find(|e| &e.id == l))
        .map(|e| (e.id.clone(), e.url.clone()))
        .collect();
    let (st, fail_at) = (state.clone(), fail_hook(&state));
    let (disabled, err) = blocking(move || {
        let mut off = Vec::new();
        for (n, (lid, url)) in targets.iter().enumerate() {
            if fail_at == Some(n) {
                return Ok((off, Some("write failed".to_string())));
            }
            let mut did = false;
            let r = st.filter_store.update_list_durable(lid, |l| {
                if same_url(&l.url, url) && l.enabled {
                    l.enabled = false;
                    did = true;
                }
            });
            match r {
                Ok(_) => {
                    if did {
                        off.push(lid.clone());
                    }
                }
                Err(e) => return Ok((off, Some(e.to_string()))),
            }
        }
        Ok((off, None))
    })
    .await?;
    if !disabled.is_empty() {
        info!(
            "Collection '{id}' turned off by {}: {disabled:?}",
            p.username
        );
        state.list_service.trigger();
    }
    if let Some(e) = err {
        return Err(partial_error(&disabled, &e));
    }
    Ok(Json(DisableCollectionResponse { disabled }))
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
    let not_found = || ApiError::NotFound(format!("Catalogue entry '{id}' not found"));
    let list = {
        let doc = state.filter_catalogue().get().ok_or_else(not_found)?;
        let e = doc
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(not_found)?;
        list_from_entry(e)?
    };
    if state.filter_store.exists(&id)? {
        return Err(ApiError::AlreadyExists(format!("Filter list '{id}'")));
    }
    validate_filter_url(&state, &list.url).await?;
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
    /// Case-insensitive substring of the rule text or its list.
    pub q: Option<String>,
    /// Only rules of this filter list id.
    pub list: Option<String>,
    /// Deprecated: use `cursor`.
    pub page: Option<u32>,
    /// Page size (1..=200, default 50).
    pub limit: Option<u32>,
    /// `next_cursor` of the previous page.
    pub cursor: Option<String>,
}

/// Rules the network engine cannot run (handed off) and what the extended-rule index did with
/// each, read-only.
#[utoipa::path(
    get, path = "/rules/ext", tag = "rules",
    security(("bearer_auth" = ["rules:read"])),
    params(ExtRulesQuery),
    responses((status = 200, description = "Handed-off rules", body = Page<ExtRuleResponse>))
)]
pub async fn list_ext_rules(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<ExtRulesQuery>,
) -> ApiResult<Json<Page<ExtRuleResponse>>> {
    let generation = state.shared_engine.generation();
    let index = generation.aux::<ext_rules::ExtIndex>();
    let rules = state.shared_engine.ext_rules();
    // The rule list and the index are installed together; if a rebuild slipped in between the
    // two reads, say `unknown` instead of mislabelling.
    let index = index.filter(|i| i.stats().total == rules.len());
    let needle = q.q.as_deref().unwrap_or("").trim().to_ascii_lowercase();
    let limit = q.limit.unwrap_or(50).clamp(1, 200) as usize;
    let gen_id = generation.id;
    // The cursor is the index of the last rule served plus the build it came from; a rebuild
    // renumbers the rules, so a cursor from another build is refused.
    let after = match q.cursor.as_deref().filter(|c| !c.is_empty()) {
        Some(c) => {
            let (g, i) = decode_ext_cursor(c)?;
            if g != gen_id {
                return Err(ApiError::conflict(
                    "ext_rules_changed",
                    "The rule set was rebuilt since this cursor was issued; restart from the first page",
                ));
            }
            Some(i)
        }
        None => None,
    };
    let mut skip = match (after, q.page) {
        (None, Some(p)) => (p.max(1) as usize - 1).saturating_mul(limit),
        _ => 0,
    };
    // One pass, no per-row allocation: count every match, collect the page (plus one row to
    // know whether more follow).
    let key = (
        q.list.clone().unwrap_or_default(),
        q.kind.clone().unwrap_or_default(),
        needle.clone(),
    );
    let cached = state.ext_totals.lock().get(gen_id, &key);
    let mut total = 0usize;
    let mut picked: Vec<usize> = Vec::with_capacity(limit + 1);
    for (i, r) in rules.iter().enumerate() {
        if q.kind.as_deref().is_some_and(|k| r.kind.as_str() != k)
            || q.list.as_deref().is_some_and(|l| r.list != l)
            || !(needle.is_empty()
                || super::paging::ci_contains(&r.raw, &needle)
                || super::paging::ci_contains(&r.list, &needle))
        {
            continue;
        }
        total += 1;
        if after.is_some_and(|a| i <= a) {
            continue;
        }
        if skip > 0 {
            skip -= 1;
        } else if picked.len() <= limit {
            picked.push(i);
        } else if cached.is_some() {
            // The total is known; the page and "more follow" are settled.
            break;
        }
    }
    match cached {
        Some(t) => total = t,
        None => state.ext_totals.lock().put(gen_id, key, total),
    }
    let has_more = picked.len() > limit;
    picked.truncate(limit);
    let next_cursor = has_more
        .then(|| picked.last().map(|&i| encode_ext_cursor(gen_id, i)))
        .flatten();
    let items: Vec<ExtRuleResponse> = picked
        .iter()
        .map(|&i| {
            let r = &rules[i];
            let st = index.and_then(|x| x.state_of(i));
            ExtRuleResponse {
                index: i,
                kind: r.kind.as_str().into(),
                raw: r.raw.clone(),
                domains: r.domains.clone(),
                list: r.list.clone(),
                state: st.map_or("unknown", |s| s.as_str()).into(),
                reason: st.and_then(|s| s.reason()).map(str::to_string),
            }
        })
        .collect();
    Ok(Json(Page {
        items,
        total,
        page: q.page.filter(|_| after.is_none()).unwrap_or(1).max(1),
        limit: limit as u32,
        has_more,
        next_cursor,
    }))
}

/// Counted `/rules/ext` totals for the current engine generation, so paging does not recount.
/// One per `AppState` (generation ids are per engine).
const EXT_TOTALS_CAP: usize = 64;

type ExtKey = (String, String, String);

#[derive(Default)]
pub struct ExtTotals {
    gen: u64,
    map: Option<std::collections::HashMap<ExtKey, usize>>,
}

impl ExtTotals {
    fn get(&mut self, gen: u64, k: &ExtKey) -> Option<usize> {
        if self.gen != gen {
            return None;
        }
        self.map.as_ref()?.get(k).copied()
    }

    fn put(&mut self, gen: u64, k: ExtKey, total: usize) {
        if self.gen != gen || self.map.is_none() {
            self.gen = gen;
            self.map = Some(Default::default());
        }
        let m = self.map.as_mut().expect("set above");
        if m.len() >= EXT_TOTALS_CAP {
            m.clear();
        }
        m.insert(k, total);
    }
}

fn encode_ext_cursor(gen: u64, index: usize) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{gen}:{index}"))
}

fn decode_ext_cursor(c: &str) -> ApiResult<(u64, usize)> {
    use base64::Engine;
    let bad = || ApiError::ValidationError("invalid cursor".into());
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(c)
        .map_err(|_| bad())?;
    let s = String::from_utf8(raw).map_err(|_| bad())?;
    let (g, i) = s.split_once(':').ok_or_else(bad)?;
    Ok((g.parse().map_err(|_| bad())?, i.parse().map_err(|_| bad())?))
}

/// Stable error code for a fetch URL that is not an allowed destination.
pub const FETCH_DESTINATION_CODE: &str = "fetch_destination_not_allowed";

/// Check a list URL against the control-plane fetch policy (the same one the fetcher enforces,
/// again at fetch time since DNS can change): http(s) only, no refused literal address, and a
/// name must not resolve only to refused addresses.
pub(crate) async fn validate_filter_url(state: &AppState, url: &str) -> ApiResult<()> {
    let policy = match state.list_service.fetch_policy() {
        Some(p) => p.clone(),
        None => Arc::new(
            common::net_policy::NetPolicy::control_plane(&[])
                .map_err(|e| ApiError::Internal(e.to_string()))?,
        ),
    };
    use common::net_policy::UrlRefusal;
    match policy.check_url(url).await {
        Ok(_) => Ok(()),
        Err(e @ (UrlRefusal::Invalid | UrlRefusal::Scheme | UrlRefusal::NoHost)) => Err(
            ApiError::coded(StatusCode::BAD_REQUEST, "invalid_fetch_url", e.to_string()),
        ),
        Err(e) => Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            FETCH_DESTINATION_CODE,
            e.to_string(),
        )),
    }
}

#[cfg(test)]
mod ext_totals_tests {
    use super::*;

    #[test]
    fn a_total_is_reused_and_dropped_when_the_generation_changes() {
        let mut c = ExtTotals::default();
        let k: ExtKey = ("l".into(), "k".into(), "q".into());
        assert_eq!(c.get(1, &k), None);
        c.put(1, k.clone(), 7);
        assert_eq!(c.get(1, &k), Some(7));
        assert_eq!(c.get(1, &("l".into(), "k".into(), "other".into())), None);
        assert_eq!(c.get(2, &k), None, "new generation");
        c.put(2, k.clone(), 9);
        assert_eq!(c.get(1, &k), None);
        assert_eq!(c.get(2, &k), Some(9));
    }

    #[test]
    fn the_cache_stays_bounded() {
        let mut c = ExtTotals::default();
        for i in 0..200 {
            c.put(1, (i.to_string(), String::new(), String::new()), i);
        }
        assert!(c.map.as_ref().unwrap().len() <= EXT_TOTALS_CAP);
    }
}

#[cfg(test)]
mod collection_write_tests {
    use super::*;

    fn store() -> (tempfile::TempDir, list_service::ListStore) {
        let d = tempfile::tempdir().unwrap();
        let s = list_service::ListStore::new(d.path()).unwrap();
        (d, s)
    }

    fn list(id: &str, url: &str, enabled: bool) -> filter_engine::FilterList {
        let mut l = filter_engine::FilterList::new(id.into(), format!("name {id}"), url.into());
        l.enabled = enabled;
        l
    }

    fn change(id: &str, url: &str, trusted: bool, new: bool) -> Change {
        Change {
            id: id.into(),
            url: url.into(),
            trusted,
            new_list: new.then(|| {
                let mut l = list(id, url, true);
                l.trusted = trusted;
                l
            }),
        }
    }

    #[test]
    fn a_write_changes_only_enabled_and_trusted_of_a_freshly_read_list() {
        let (_d, s) = store();
        // The list was disabled when planned; a concurrent edit has since renamed it.
        let mut l = list("a", "https://x/a", false);
        l.name = "renamed meanwhile".into();
        l.allowlist = true;
        s.upsert(&l).unwrap();
        let (w, _, e) = write_changes(&s, &[change("a", "https://x/a", true, false)], None);
        assert!(e.is_none());
        assert_eq!((w.len(), w[0].trust), (1, Some(true)));
        let got = s.get("a").unwrap().unwrap();
        assert!(got.enabled && got.trusted);
        assert_eq!(got.name, "renamed meanwhile");
        assert!(got.allowlist);
    }

    #[test]
    fn a_list_deleted_in_the_gap_is_recreated_only_if_the_plan_said_add() {
        let (_d, s) = store();
        let (w, _, _) = write_changes(&s, &[change("gone", "https://x/g", true, false)], None);
        assert!(w.is_empty() && s.get("gone").unwrap().is_none());
        let (w, _, _) = write_changes(&s, &[change("new", "https://x/n", true, true)], None);
        assert!(w[0].added && s.get("new").unwrap().unwrap().trusted);
    }

    #[test]
    fn a_list_created_in_the_gap_is_never_overwritten_by_an_add() {
        let (_d, s) = store();
        // Planned as add; by the write someone has created their own list under that id.
        s.upsert(&list("new", "https://mine/n", false)).unwrap();
        let c = change("new", "https://x/n", true, true);
        let (w, clash, e) = write_changes(&s, &[c], None);
        assert!(w.is_empty() && e.is_none());
        assert_eq!(clash.len(), 1);
        let got = s.get("new").unwrap().unwrap();
        assert_eq!(got.url, "https://mine/n");
        assert!(!got.enabled && !got.trusted);
        // The store primitive itself refuses to overwrite.
        let again = list("new", "https://x/n", true);
        assert!(!s.insert_if_absent_durable(&again).unwrap());
        assert_eq!(s.get("new").unwrap().unwrap().url, "https://mine/n");
    }

    #[test]
    fn urls_compare_normalised_and_fall_back_to_text() {
        assert!(same_url(
            "HTTPS://Example.COM:443/a.txt",
            "https://example.com/a.txt"
        ));
        assert!(same_url("https://example.com", "https://example.com/"));
        assert!(!same_url(
            "https://example.com/a.txt",
            "https://example.com/b.txt"
        ));
        assert!(!same_url("https://example.com/a", "http://example.com/a"));
        assert!(same_url("not a url", "not a url"));
        assert!(!same_url("not a url", "not  a url"));
    }

    #[test]
    fn a_cosmetically_different_url_is_still_the_catalogues_list() {
        let (_d, s) = store();
        s.upsert(&list("a", "HTTPS://X.example:443/a", false))
            .unwrap();
        let c = change("a", "https://x.example/a", false, false);
        let (w, clash, _) = write_changes(&s, &[c], None);
        assert_eq!(w.len(), 1);
        assert!(clash.is_empty() && s.get("a").unwrap().unwrap().enabled);
    }

    #[test]
    fn a_list_whose_url_changed_in_the_gap_is_left_alone() {
        let (_d, s) = store();
        s.upsert(&list("a", "https://elsewhere/a", false)).unwrap();
        let (w, clash, e) = write_changes(&s, &[change("a", "https://x/a", true, false)], None);
        assert!(w.is_empty() && e.is_none() && clash.len() == 1);
        let got = s.get("a").unwrap().unwrap();
        assert!(!got.enabled && !got.trusted);
    }
}

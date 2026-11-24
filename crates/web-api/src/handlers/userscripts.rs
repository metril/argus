//! Userscript management handlers.

use std::sync::Arc;

use std::collections::BTreeMap;

use api_types::{
    ApproveUpdateRequest, CheckUpdateRequest, CheckUpdateResponse, ConfirmPlanRequest,
    ExportedAssets, ExportedRequire, ExportedResource, ExportedUserscript, ImportResultDto,
    ImportUserscriptsResponse, InstallUserscriptRequest, MessageResponse, PendingUpdateDto,
    PlanRequireDto, PlanResourceDto, PlanUpdateDto, PlanUserscriptRequest, Scope,
    SetEnabledRequest, StorageValueDto, UpdateDiffDto, UserscriptBundle,
    UserscriptCatalogueEntryDto, UserscriptCatalogueResponse, UserscriptCounts,
    UserscriptPlanResponse, UserscriptResponse, UserscriptSourceResponse, UserscriptStatsResponse,
    UserscriptStorageResponse, UserscriptsPage, LEGACY_USERSCRIPT_BUNDLE_FORMAT,
    USERSCRIPT_BUNDLE_FORMAT,
};
use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::Deserialize;
use tracing::info;
use url::Url;
use userscript_engine::install::{self, Approvals};
use userscript_engine::storage::ns;
use utoipa::IntoParams;

use super::paging::{desc_key, natural_key, paginate, paginate_max, Keyed};
use crate::auth::authz::Principal;
use crate::auth::profile::{ProfileParam, ProfileQuery};
use crate::error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult};
use crate::state::AppState;
use crate::userscript_ops::{self as ops, CheckOutcome, StoredPlan};

/// Largest import bundle accepted.
pub const MAX_IMPORT_BYTES: usize = 16 * 1024 * 1024;
const MAX_IMPORT_SCRIPTS: usize = 500;

fn diff_dto(d: &install::UpdateDiff) -> UpdateDiffDto {
    UpdateDiffDto {
        added_matches: d.added_matches.clone(),
        added_connect: d.added_connect.clone(),
        added_grants: d.added_grants.clone(),
        removed_matches: d.removed_matches.clone(),
        removed_connect: d.removed_connect.clone(),
        removed_grants: d.removed_grants.clone(),
        widened: d.widened.clone(),
    }
}

fn storage_bytes_of(state: &AppState, profile: &str, id: &str) -> u64 {
    state
        .userscript_manager
        .storage()
        .list_sizes(&ns(profile, id))
        .map(|v| v.iter().map(|(_, n)| *n as u64).sum())
        .unwrap_or(0)
}

fn userscript_response(
    script: &userscript_engine::Userscript,
    storage_bytes: u64,
) -> UserscriptResponse {
    let m = &script.metadata;
    UserscriptResponse {
        pending_update: script.pending_update.as_ref().map(|p| PendingUpdateDto {
            new_version: p.new_version.clone(),
            diff: diff_dto(&p.diff),
            needs_reapproval: p.diff.needs_reapproval(),
            found_at: p.found_at.to_rfc3339(),
        }),
        last_update_check: script.last_update_check.map(|t| t.to_rfc3339()),
        grants: m.effective_grants(),
        connect: m.connect.clone(),
        connect_all_approved: script.allow_connect_all,
        unsupported: m.unsupported().iter().map(|w| w.message.clone()).collect(),
        warnings: m.warnings.iter().map(|w| w.message.clone()).collect(),
        run_at: serde_json::to_value(m.run_at)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string)),
        noframes: m.noframes,
        storage_bytes,
        update_url: m.update_url.clone().or_else(|| m.download_url.clone()),
        homepage: m.homepage.clone(),
        require_count: script.assets.requires.len(),
        resource_count: script.assets.resources.len(),
        id: script.id.clone(),
        name: script.metadata.name.clone(),
        namespace: script.metadata.namespace.clone(),
        version: script.metadata.version.clone(),
        description: script.metadata.description.clone(),
        author: script.metadata.author.clone(),
        enabled: script.enabled,
        execution_count: script.execution_count,
        last_executed: script.last_executed.map(|dt| dt.to_rfc3339()),
        match_patterns: script.metadata.matches.clone(),
        updated_at: script.updated_at.to_rfc3339(),
        error: !m.unsupported().is_empty(),
    }
}

fn respond(state: &AppState, script: &userscript_engine::Userscript) -> UserscriptResponse {
    userscript_response(script, storage_bytes_of(state, &script.profile, &script.id))
}

fn not_found(id: &str) -> ApiError {
    ApiError::NotFound(format!("Userscript '{id}' not found"))
}

fn get_script(
    state: &AppState,
    profile: &str,
    id: &str,
) -> ApiResult<userscript_engine::Userscript> {
    state
        .userscript_manager
        .get_in(profile, id)
        .ok_or_else(|| not_found(id))
}

fn require_source(source: &str) -> ApiResult<()> {
    if source.trim().is_empty() {
        return Err(ApiError::ValidationError(
            "Userscript source cannot be empty".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListUserscriptsQuery {
    /// Only enabled / only disabled scripts (same as `status=enabled|disabled`).
    pub enabled: Option<bool>,
    /// Case-insensitive substring of the name, namespace or description.
    pub q: Option<String>,
    /// `enabled`, `disabled` or `error` (unsupported features).
    pub status: Option<String>,
    /// `name` (natural order, default) or `updated` (most recent first).
    pub sort: Option<String>,
    /// Deprecated: use `cursor`.
    pub page: Option<u32>,
    /// Page size (1..=200, default 40).
    pub limit: Option<u32>,
    /// Opaque `next_cursor` of the previous page.
    pub cursor: Option<String>,
    /// With `sort=name`: start at the first name at or after this prefix.
    pub from: Option<String>,
}

/// List userscripts.
#[utoipa::path(
    get, path = "/userscripts", tag = "userscripts",
    security(("bearer_auth" = ["scripts:read"])),
    params(ProfileQuery, ListUserscriptsQuery),
    responses((status = 200, description = "Userscripts", body = UserscriptsPage))
)]
pub async fn list_userscripts(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    ApiQuery(q): ApiQuery<ListUserscriptsQuery>,
) -> ApiResult<Json<UserscriptsPage>> {
    let status = match q.status.as_deref() {
        None => None,
        Some(s @ ("enabled" | "disabled" | "error")) => Some(s),
        Some(o) => {
            return Err(ApiError::ValidationError(format!(
                "unknown status '{o}' (enabled, disabled, error)"
            )))
        }
    };
    let sort = q.sort.as_deref().unwrap_or("name");
    if !["name", "updated"].contains(&sort) {
        return Err(ApiError::ValidationError(format!(
            "unknown sort '{sort}' (name, updated)"
        )));
    }
    if q.from.is_some() && sort != "name" {
        return Err(ApiError::ValidationError("`from` needs sort=name".into()));
    }
    let needle = q.q.as_deref().unwrap_or("").trim().to_lowercase();
    let usage = state
        .userscript_manager
        .storage()
        .profile_usage(&profile.name)
        .unwrap_or_default();
    let matching: Vec<UserscriptResponse> = state
        .userscript_manager
        .get_all_in(&profile.name)
        .iter()
        .filter(|s| {
            needle.is_empty()
                || s.metadata.name.to_lowercase().contains(&needle)
                || s.metadata
                    .namespace
                    .as_deref()
                    .is_some_and(|n| n.to_lowercase().contains(&needle))
                || s.metadata
                    .description
                    .as_deref()
                    .is_some_and(|d| d.to_lowercase().contains(&needle))
        })
        .map(|s| {
            let used = usage.get(&ns(&s.profile, &s.id)).copied().unwrap_or(0);
            userscript_response(s, used as u64)
        })
        .collect();
    let mut counts = UserscriptCounts {
        all: matching.len(),
        enabled: matching.iter().filter(|s| s.enabled).count(),
        disabled: matching.iter().filter(|s| !s.enabled).count(),
        error: matching.iter().filter(|s| s.error).count(),
        letters: Vec::new(),
    };
    let rows: Vec<Keyed<UserscriptResponse>> = matching
        .into_iter()
        .filter(|s| match status {
            Some("enabled") => s.enabled,
            Some("disabled") => !s.enabled,
            Some(_) => s.error,
            None => q.enabled.is_none_or(|e| s.enabled == e),
        })
        .map(|s| {
            let name = natural_key(&s.name);
            let key = if sort == "updated" {
                let ts = chrono::DateTime::parse_from_rfc3339(&s.updated_at)
                    .map_or(0, |t| t.timestamp_millis().max(0) as u64);
                format!("{}{name}", desc_key(ts))
            } else {
                name
            };
            Keyed {
                key,
                id: s.id.clone(),
                label: s.name.clone(),
                item: s,
            }
        })
        .collect();
    let from = q.from.as_deref().map(natural_key);
    let p = paginate(rows, q.limit, q.cursor.as_deref(), from.as_deref(), q.page)?;
    counts.letters = p.letters;
    Ok(Json(UserscriptsPage {
        items: p.items,
        next_cursor: p.next_cursor,
        total: p.total,
        counts,
        limit: p.limit,
        has_more: p.has_more,
        page: p.page,
    }))
}

/// Install a userscript from its source.
#[utoipa::path(
    post, path = "/userscripts", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    params(ProfileQuery),
    request_body = InstallUserscriptRequest,
    responses((status = 201, description = "Installed", body = UserscriptResponse))
)]
pub async fn install_userscript(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    Extension(p): Extension<Principal>,
    ApiJson(req): ApiJson<InstallUserscriptRequest>,
) -> ApiResult<(StatusCode, Json<UserscriptResponse>)> {
    require_source(&req.source)?;
    // Same fetch and integrity checks as plan/confirm, with no `@connect *` approval.
    let sp = ops::build_plan(&state, req.source, None).await?;
    let script = install::finish_install(sp.plan, sp.fetched, Approvals::default())
        .map_err(|e| ApiError::ValidationError(format!("Invalid userscript: {e}")))?;
    let id = state
        .userscript_manager
        .install_script(&profile.name, script)
        .map_err(|e| ApiError::ValidationError(format!("Invalid userscript: {e}")))?;
    let script = get_script(&state, &profile.name, &id)?;
    info!("Userscript {} installed by {}", id, p.username);
    Ok((StatusCode::CREATED, Json(respond(&state, &script))))
}

/// Userscript statistics.
#[utoipa::path(
    get, path = "/userscripts/stats", tag = "userscripts",
    security(("bearer_auth" = ["scripts:read"])),
    params(ProfileQuery),
    responses((status = 200, description = "Statistics", body = UserscriptStatsResponse))
)]
pub async fn get_stats(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
) -> Json<UserscriptStatsResponse> {
    let all = state.userscript_manager.get_all_in(&profile.name);
    let enabled = all.iter().filter(|s| s.enabled).count();
    Json(UserscriptStatsResponse {
        total_scripts: all.len(),
        enabled_scripts: enabled,
        disabled_scripts: all.len() - enabled,
        total_executions: all.iter().map(|s| s.execution_count).sum(),
    })
}

/// Get one userscript.
#[utoipa::path(
    get, path = "/userscripts/{id}", tag = "userscripts",
    security(("bearer_auth" = ["scripts:read"])),
    params(ProfileQuery, ("id" = String, Path, description = "Userscript id")),
    responses((status = 200, description = "Userscript", body = UserscriptResponse))
)]
pub async fn get_userscript(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<UserscriptResponse>> {
    Ok(Json(respond(
        &state,
        &get_script(&state, &profile.name, &id)?,
    )))
}

/// Get a userscript's source.
#[utoipa::path(
    get, path = "/userscripts/{id}/source", tag = "userscripts",
    security(("bearer_auth" = ["scripts:read"])),
    params(ProfileQuery, ("id" = String, Path, description = "Userscript id")),
    responses((status = 200, description = "Source", body = UserscriptSourceResponse))
)]
pub async fn get_userscript_source(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<UserscriptSourceResponse>> {
    let s = get_script(&state, &profile.name, &id)?;
    Ok(Json(UserscriptSourceResponse {
        id: s.id,
        source: s.source,
    }))
}

/// Uninstall a userscript.
#[utoipa::path(
    delete, path = "/userscripts/{id}", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    params(ProfileQuery, ("id" = String, Path, description = "Userscript id")),
    responses((status = 200, description = "Uninstalled", body = MessageResponse))
)]
pub async fn uninstall_userscript(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<MessageResponse>> {
    state
        .userscript_manager
        .uninstall_in(&profile.name, &id)
        .map_err(|e| match e {
            userscript_engine::Error::ScriptNotFound(_) => not_found(&id),
            _ => ApiError::Internal(format!("Failed to uninstall: {e}")),
        })?;
    info!("Userscript {id} uninstalled by {}", p.username);
    Ok(Json(MessageResponse {
        message: format!("Userscript '{id}' uninstalled"),
    }))
}

/// Enable or disable a userscript.
#[utoipa::path(
    put, path = "/userscripts/{id}/enabled", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    params(ProfileQuery, ("id" = String, Path, description = "Userscript id")),
    request_body = SetEnabledRequest,
    responses((status = 200, description = "Updated", body = UserscriptResponse))
)]
pub async fn set_enabled(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<SetEnabledRequest>,
) -> ApiResult<Json<UserscriptResponse>> {
    state
        .userscript_manager
        .set_enabled_in(&profile.name, &id, req.enabled)
        .map_err(|e| match e {
            userscript_engine::Error::ScriptNotFound(_) => not_found(&id),
            _ => ApiError::Internal(format!("Failed to update: {e}")),
        })?;
    info!("Userscript {id} enabled={} by {}", req.enabled, p.username);
    Ok(Json(respond(
        &state,
        &get_script(&state, &profile.name, &id)?,
    )))
}

// ------------------------------------------------------------------ two-step install

fn plan_response(state: &AppState, plan_id: String, sp: &StoredPlan) -> UserscriptPlanResponse {
    let p = &sp.plan;
    let g = &p.grants_summary;
    let m = &p.metadata;
    let existing = state.userscript_manager.get(&m.unique_id());
    UserscriptPlanResponse {
        plan_id,
        expires_in_secs: ops::PLAN_TTL.as_secs(),
        name: m.name.clone(),
        namespace: m.namespace.clone(),
        version: m.version.clone(),
        description: m.description.clone(),
        grants: g.grants.clone(),
        connect: g.connect.clone(),
        broad_match: g.matches.is_empty() || g.matches.iter().any(|x| ops::is_broad_match(x)),
        matches: g.matches.clone(),
        connect_all: g.connect_all,
        network: g.network,
        cookies: g.cookies,
        downloads: g.downloads,
        clipboard: g.clipboard,
        notifications: g.notifications,
        unsupported: g.unsupported.clone(),
        warnings: p.warnings.clone(),
        high_warnings: p.high_warnings.clone(),
        requires: p
            .requires
            .iter()
            .map(|r| PlanRequireDto {
                url: r.url.to_string(),
                size_bytes: sp.fetched.requires.get(r.url.as_str()).map_or(0, Vec::len),
                sri_verified: !r.sri.is_empty(),
            })
            .collect(),
        resources: p
            .resources
            .iter()
            .map(|r| PlanResourceDto {
                name: r.name.clone(),
                url: r.url.to_string(),
                size_bytes: sp
                    .fetched
                    .resources
                    .get(&r.name)
                    .map_or(0, |(b, _)| b.len()),
                sri_verified: !r.sri.is_empty(),
            })
            .collect(),
        already_installed: existing.is_some(),
        update: existing.as_ref().and_then(|e| {
            let mut up = install::plan_update(e, &p.source, p.origin_url.as_ref()).ok()?;
            up.absorb_fetched(e, &sp.fetched);
            Some(PlanUpdateDto {
                needs_reapproval: up.diff.needs_reapproval(),
                diff: diff_dto(&up.diff),
                is_newer: up.is_newer,
            })
        }),
        installed_version: existing.and_then(|s| s.metadata.version),
    }
}

/// The signed catalogue of curated userscripts (installs still go through plan and confirm).
#[utoipa::path(
    get, path = "/userscripts/catalogue", tag = "userscripts",
    security(("bearer_auth" = ["scripts:read"])),
    params(ProfileQuery),
    responses((status = 200, description = "Catalogue", body = UserscriptCatalogueResponse))
)]
pub async fn get_userscript_catalogue(
    State(state): State<Arc<AppState>>,
    // The catalogue is the same for every profile; the parameter keeps the scope's profile rule.
    _profile: ProfileParam,
) -> ApiResult<Json<UserscriptCatalogueResponse>> {
    let Some(doc) = state.userscript_catalogue().get() else {
        return Ok(Json(UserscriptCatalogueResponse {
            source: "unavailable".into(),
            fetched_at: None,
            version: None,
            entries: Vec::new(),
        }));
    };
    let entries = doc
        .entries
        .iter()
        .map(|e| UserscriptCatalogueEntryDto {
            id: e.id.clone(),
            name: e.name.clone(),
            description: e.description.clone(),
            install_url: e.install_url.clone(),
            homepage: e.homepage.clone(),
            sites: e.sites.clone(),
            category: e.category.clone(),
            licence: e.licence.clone(),
            licence_note: e.licence_note.clone(),
            needs_gm: e.needs_gm.clone(),
            connect: e.connect.clone(),
            requires: e.requires.clone(),
        })
        .collect();
    Ok(Json(UserscriptCatalogueResponse {
        source: "signed".into(),
        fetched_at: Some(doc.fetched_at.clone()),
        version: Some(doc.version.clone()),
        entries,
    }))
}

/// Plan an install from source or URL.
///
/// Parses the script, fetches its `@require`/`@resource` dependencies (integrity hashes
/// verified, size capped, control-plane fetch policy) and returns what installing would grant.
/// Nothing is installed until `confirm`.
#[utoipa::path(
    post, path = "/userscripts/plan", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    params(ProfileQuery),
    request_body = PlanUserscriptRequest,
    responses((status = 200, description = "Plan", body = UserscriptPlanResponse))
)]
pub async fn plan_userscript(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    Extension(p): Extension<Principal>,
    ApiJson(req): ApiJson<PlanUserscriptRequest>,
) -> ApiResult<Json<UserscriptPlanResponse>> {
    let (source, origin) = match (req.source, req.url) {
        (Some(s), None) => {
            require_source(&s)?;
            (s, None)
        }
        (None, Some(u)) => {
            let url = Url::parse(u.trim()).map_err(|_| {
                ApiError::coded(StatusCode::BAD_REQUEST, "invalid_fetch_url", "invalid URL")
            })?;
            (ops::fetch_source(&state, &url).await?, Some(url))
        }
        _ => {
            return Err(ApiError::ValidationError(
                "Provide exactly one of `source` or `url`".into(),
            ))
        }
    };
    let mut sp = ops::build_plan(&state, source, origin.as_ref()).await?;
    sp.profile = profile.name.clone();
    sp.base = state
        .userscript_manager
        .get_in(&profile.name, &sp.plan.metadata.unique_id())
        .map(|e| ops::source_fingerprint(&e));
    let name = sp.plan.metadata.name.clone();
    let resp_plan = plan_response(&state, String::new(), &sp);
    let id = state.userscript_plans.insert(sp);
    info!("Userscript install planned for '{name}' by {}", p.username);
    Ok(Json(UserscriptPlanResponse {
        plan_id: id,
        ..resp_plan
    }))
}

/// Confirm a plan and install the script.
#[utoipa::path(
    post, path = "/userscripts/plan/{plan_id}/confirm", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    params(ProfileQuery, ("plan_id" = String, Path, description = "Plan id")),
    request_body = ConfirmPlanRequest,
    responses(
        (status = 201, description = "Installed", body = UserscriptResponse),
        (status = 200, description = "Updated an installed script", body = UserscriptResponse),
        (status = 404, description = "Unknown or expired plan"),
        (status = 409, description = "The installed script changed since the plan")
    )
)]
pub async fn confirm_plan(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    Extension(p): Extension<Principal>,
    ApiPath(plan_id): ApiPath<String>,
    ApiJson(req): ApiJson<ConfirmPlanRequest>,
) -> ApiResult<(StatusCode, Json<UserscriptResponse>)> {
    let sp = state
        .userscript_plans
        .get(&plan_id)
        .filter(|sp| sp.profile == profile.name)
        .ok_or_else(|| {
            ApiError::coded(
                StatusCode::NOT_FOUND,
                "plan_not_found",
                "Plan not found or expired",
            )
        })?;
    if req.allow_connect_all && !sp.plan.grants_summary.connect_all {
        return Err(ApiError::ValidationError(
            "allow_connect_all given but the script does not declare @connect *".into(),
        ));
    }
    let id = sp.plan.metadata.unique_id();
    if let Some(existing) = state.userscript_manager.get_in(&profile.name, &id) {
        // Updating: confirming is the approval of the diff the plan showed, provided the
        // installed script is still the one that diff was computed against.
        if sp.base.as_deref() != Some(ops::source_fingerprint(&existing).as_str()) {
            return Err(ApiError::conflict(
                "plan_stale",
                "The installed script changed since this plan; plan again",
            ));
        }
        let origin = sp.plan.origin_url.clone();
        let mut up = install::plan_update(&existing, &sp.plan.source, origin.as_ref())
            .map_err(|e| ApiError::ValidationError(format!("Invalid userscript: {e}")))?;
        up.absorb_fetched(&existing, &sp.fetched);
        let mut new = install::finish_update(
            &existing,
            up,
            sp.fetched_clone(),
            true,
            req.allow_connect_all,
        )
        .map_err(|e| ApiError::ValidationError(format!("Invalid userscript: {e}")))?;
        new.pending_update = None;
        state
            .userscript_manager
            .replace_script(&profile.name, new)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        state.userscript_plans.remove(&plan_id);
        info!(
            "Userscript {id} updated from plan by {} (connect_all={})",
            p.username, req.allow_connect_all
        );
        let script = get_script(&state, &profile.name, &id)?;
        return Ok((StatusCode::OK, Json(respond(&state, &script))));
    }
    let mut script = install::finish_install(
        sp.plan.clone(),
        sp.fetched_clone(),
        Approvals {
            allow_connect_all: req.allow_connect_all,
        },
    )
    .map_err(|e| ApiError::ValidationError(format!("Invalid userscript: {e}")))?;
    script.enabled = req.enable;
    state
        .userscript_manager
        .install_script(&profile.name, script)
        .map_err(|e| ApiError::ValidationError(format!("Invalid userscript: {e}")))?;
    state.userscript_plans.remove(&plan_id);
    info!(
        "Userscript {id} installed from plan by {} (connect_all={})",
        p.username, req.allow_connect_all
    );
    let script = get_script(&state, &profile.name, &id)?;
    Ok((StatusCode::CREATED, Json(respond(&state, &script))))
}

// ------------------------------------------------------------------ updates

/// Check a script for a newer version.
///
/// A newer version that widens `@match`/`@connect`/`@grant` (or any newer version when `apply`
/// is false) is stored as the script's pending update for approval.
#[utoipa::path(
    post, path = "/userscripts/{id}/check-update", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    params(ProfileQuery, ("id" = String, Path, description = "Userscript id")),
    request_body = CheckUpdateRequest,
    responses((status = 200, description = "Result", body = CheckUpdateResponse))
)]
pub async fn check_update(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<CheckUpdateRequest>,
) -> ApiResult<Json<CheckUpdateResponse>> {
    let before = get_script(&state, &profile.name, &id)?;
    let outcome = ops::check_update(&state, &profile.name, &id, req.apply).await?;
    let script = get_script(&state, &profile.name, &id)?;
    let (status, new_version, diff) = match &outcome {
        CheckOutcome::UpToDate => ("up_to_date", None, None),
        CheckOutcome::Updated => ("updated", script.metadata.version.clone(), None),
        CheckOutcome::Pending(u) => (
            "pending_approval",
            u.new_version.clone(),
            Some(diff_dto(&u.diff)),
        ),
    };
    info!("Userscript {id} update check by {}: {status}", p.username);
    Ok(Json(CheckUpdateResponse {
        status: status.into(),
        current_version: before.metadata.version,
        new_version,
        diff,
        script: respond(&state, &script),
    }))
}

/// Apply a script's pending update.
#[utoipa::path(
    post, path = "/userscripts/{id}/update/approve", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    params(ProfileQuery, ("id" = String, Path, description = "Userscript id")),
    request_body = ApproveUpdateRequest,
    responses((status = 200, description = "Updated", body = UserscriptResponse))
)]
pub async fn approve_update(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<ApproveUpdateRequest>,
) -> ApiResult<Json<UserscriptResponse>> {
    ops::approve_pending(&state, &profile.name, &id, req.allow_connect_all)?;
    info!("Userscript {id} update approved by {}", p.username);
    Ok(Json(respond(
        &state,
        &get_script(&state, &profile.name, &id)?,
    )))
}

/// Discard a script's pending update.
#[utoipa::path(
    delete, path = "/userscripts/{id}/update", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    params(ProfileQuery, ("id" = String, Path, description = "Userscript id")),
    responses((status = 200, description = "Discarded", body = UserscriptResponse))
)]
pub async fn discard_update(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<UserscriptResponse>> {
    get_script(&state, &profile.name, &id)?;
    state
        .userscript_manager
        .modify_script(&profile.name, &id, |s| s.pending_update = None)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    info!("Userscript {id} pending update discarded by {}", p.username);
    Ok(Json(respond(
        &state,
        &get_script(&state, &profile.name, &id)?,
    )))
}

// ------------------------------------------------------------------ storage

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct StorageQuery {
    /// Case-insensitive substring of the value name.
    pub q: Option<String>,
    /// Page size (1..=1000, default 1000).
    pub limit: Option<u32>,
    /// `next_cursor` of the previous page.
    pub cursor: Option<String>,
}

/// A script's stored GM values.
#[utoipa::path(
    get, path = "/userscripts/{id}/storage", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    params(ProfileQuery, StorageQuery, ("id" = String, Path, description = "Userscript id")),
    responses((status = 200, description = "Values", body = UserscriptStorageResponse))
)]
pub async fn get_storage(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<StorageQuery>,
) -> ApiResult<Json<UserscriptStorageResponse>> {
    get_script(&state, &profile.name, &id)?;
    let space = ns(&profile.name, &id);
    let storage = state.userscript_manager.storage();
    let mut sizes = storage
        .list_sizes(&space)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    sizes.sort();
    let used: usize = sizes.iter().map(|(_, n)| n).sum();
    let needle = q.q.as_deref().unwrap_or("").trim().to_lowercase();
    let rows = sizes
        .into_iter()
        .filter(|(n, _)| needle.is_empty() || n.to_lowercase().contains(&needle))
        .map(|(name, size)| Keyed {
            key: name.clone(),
            id: String::new(),
            label: name.clone(),
            item: (name, size),
        })
        .collect();
    // Without a cursor or limit the old behaviour holds: up to 1000 values in one response.
    let p = paginate_max(
        rows,
        Some(q.limit.unwrap_or(1000)),
        q.cursor.as_deref(),
        None,
        None,
        1000,
    )?;
    let values = p
        .items
        .into_iter()
        .map(|(name, size)| {
            let preview = storage
                .get_raw(&space, &name)
                .ok()
                .flatten()
                .map(|v| v.to_string().chars().take(200).collect())
                .unwrap_or_default();
            StorageValueDto {
                name,
                size_bytes: size,
                preview,
            }
        })
        .collect();
    Ok(Json(UserscriptStorageResponse {
        used_bytes: used as u64,
        quota_bytes: state.userscript_manager.gm().quotas().per_script as u64,
        values,
        total: p.total,
        next_cursor: p.next_cursor,
        has_more: p.has_more,
    }))
}

/// Delete all of a script's stored values.
#[utoipa::path(
    delete, path = "/userscripts/{id}/storage", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    params(ProfileQuery, ("id" = String, Path, description = "Userscript id")),
    responses((status = 200, description = "Cleared", body = MessageResponse))
)]
pub async fn clear_storage(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<MessageResponse>> {
    get_script(&state, &profile.name, &id)?;
    state
        .userscript_manager
        .clear_values(&profile.name, &id)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    info!("Userscript {id} storage cleared by {}", p.username);
    Ok(Json(MessageResponse {
        message: format!("Storage of '{id}' cleared"),
    }))
}

/// Delete one stored value.
#[utoipa::path(
    delete, path = "/userscripts/{id}/storage/{name}", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    params(ProfileQuery,
        ("id" = String, Path, description = "Userscript id"),
        ("name" = String, Path, description = "Value name")
    ),
    responses((status = 200, description = "Deleted", body = MessageResponse))
)]
pub async fn delete_storage_value(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    Extension(p): Extension<Principal>,
    ApiPath((id, name)): ApiPath<(String, String)>,
) -> ApiResult<Json<MessageResponse>> {
    get_script(&state, &profile.name, &id)?;
    let space = ns(&profile.name, &id);
    let storage = state.userscript_manager.storage();
    let exists = storage
        .get_raw(&space, &name)
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .is_some();
    if !exists {
        return Err(ApiError::NotFound(format!("Value '{name}' not found")));
    }
    storage
        .delete_raw(&space, &name)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    // Quota accounting is reloaded from storage on next use.
    state
        .userscript_manager
        .gm()
        .forget_script(&profile.name, &id);
    info!("Userscript {id} value '{name}' deleted by {}", p.username);
    Ok(Json(MessageResponse {
        message: format!("Value '{name}' deleted"),
    }))
}

// ------------------------------------------------------------------ export / import

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExportQuery {
    /// Include stored GM values. Values may hold secrets and need `scripts:write`.
    pub values: Option<bool>,
}

/// Export all userscripts as a JSON bundle.
///
/// `values=true` also exports each script's stored values (possibly sensitive; requires
/// `scripts:write`). JSON only (no zip).
#[utoipa::path(
    get, path = "/userscripts/export", tag = "userscripts",
    security(("bearer_auth" = ["scripts:read"])),
    params(ProfileQuery, ExportQuery),
    responses((status = 200, description = "Bundle", body = UserscriptBundle))
)]
pub async fn export_userscripts(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    Extension(p): Extension<Principal>,
    ApiQuery(q): ApiQuery<ExportQuery>,
) -> ApiResult<Json<UserscriptBundle>> {
    let with_values = q.values.unwrap_or(false);
    if with_values && !p.has(Scope::ScriptsWrite) {
        return Err(ApiError::AuthorizationFailed(
            "Exporting values requires the scripts:write scope".into(),
        ));
    }
    let storage = state.userscript_manager.storage();
    let mut scripts = Vec::new();
    for s in state.userscript_manager.get_all_in(&profile.name) {
        let values = if with_values {
            let space = ns(&profile.name, &s.id);
            let mut m = BTreeMap::new();
            for (name, _) in storage
                .list_sizes(&space)
                .map_err(|e| ApiError::Internal(e.to_string()))?
            {
                if let Ok(Some(v)) = storage.get_raw(&space, &name) {
                    m.insert(name, v);
                }
            }
            Some(m)
        } else {
            None
        };
        scripts.push(ExportedUserscript {
            source: s.source,
            enabled: s.enabled,
            allow_connect_all: s.allow_connect_all,
            assets: ExportedAssets {
                requires: s
                    .assets
                    .requires
                    .into_iter()
                    .map(|r| ExportedRequire {
                        url: r.url,
                        content: r.content,
                    })
                    .collect(),
                resources: s
                    .assets
                    .resources
                    .into_iter()
                    .map(|r| ExportedResource {
                        name: r.name,
                        url: r.url,
                        mime: r.mime,
                        data_b64: r.data_b64,
                    })
                    .collect(),
            },
            values,
        });
    }
    info!(
        "Userscripts exported by {} ({} scripts, values={with_values})",
        p.username,
        scripts.len()
    );
    Ok(Json(UserscriptBundle {
        format: USERSCRIPT_BUNDLE_FORMAT.into(),
        scripts,
        on_conflict: None,
        approve: false,
    }))
}

/// Import a bundle produced by export (JSON, up to 16 MiB).
///
/// `on_conflict` is `skip` (default) or `replace`. Each script is validated like an install;
/// one bad script does not stop the others.
#[utoipa::path(
    post, path = "/userscripts/import", tag = "userscripts",
    security(("bearer_auth" = ["scripts:write"])),
    params(ProfileQuery),
    request_body = UserscriptBundle,
    responses((status = 200, description = "Per-script results", body = ImportUserscriptsResponse))
)]
pub async fn import_userscripts(
    State(state): State<Arc<AppState>>,
    profile: ProfileParam,
    Extension(p): Extension<Principal>,
    ApiJson(bundle): ApiJson<UserscriptBundle>,
) -> ApiResult<Json<ImportUserscriptsResponse>> {
    if bundle.format != USERSCRIPT_BUNDLE_FORMAT && bundle.format != LEGACY_USERSCRIPT_BUNDLE_FORMAT
    {
        return Err(ApiError::ValidationError(format!(
            "Unsupported bundle format '{}'",
            bundle.format
        )));
    }
    let replace = match bundle.on_conflict.as_deref().unwrap_or("skip") {
        "skip" => false,
        "replace" => true,
        o => {
            return Err(ApiError::ValidationError(format!(
                "on_conflict must be 'skip' or 'replace', got '{o}'"
            )))
        }
    };
    if bundle.scripts.len() > MAX_IMPORT_SCRIPTS {
        return Err(ApiError::ValidationError(format!(
            "Too many scripts (max {MAX_IMPORT_SCRIPTS})"
        )));
    }
    let mgr = &state.userscript_manager;
    let quotas = *mgr.gm().quotas();
    let mut results = Vec::new();
    for entry in bundle.scripts {
        let mut script =
            match ops::build_from_bundle(&entry.source, &entry.assets, entry.allow_connect_all) {
                Ok(s) => s,
                Err(e) => {
                    results.push(ImportResultDto {
                        id: None,
                        name: None,
                        status: "error".into(),
                        error: Some(e.to_string()),
                        pending_approval: false,
                    });
                    continue;
                }
            };
        let (id, name) = (script.id.clone(), script.metadata.name.clone());
        let result = |status: &str, error: Option<String>| ImportResultDto {
            id: Some(id.clone()),
            name: Some(name.clone()),
            status: status.into(),
            error,
            pending_approval: !bundle.approve,
        };
        let existing = mgr.get(&id);
        if existing.is_some() && !replace {
            results.push(result("skipped", None));
            continue;
        }
        // Validate values up front so a bad entry leaves nothing half-imported.
        let mut total = 0usize;
        let mut bad = None;
        for (n, v) in entry.values.iter().flatten() {
            let sz = n.len() + v.to_string().len();
            total += sz;
            if sz > quotas.per_value || total > quotas.per_script {
                bad = Some("stored values exceed the storage quota".to_string());
                break;
            }
        }
        if let Some(e) = bad {
            results.push(result("error", Some(e)));
            continue;
        }
        // A file cannot approve itself: without `approve`, scripts arrive disabled and without
        // `@connect *` approval, whatever the bundle says.
        script.enabled = entry.enabled && bundle.approve;
        if !bundle.approve {
            script.allow_connect_all = false;
        }
        let status = if let Some(old) = existing {
            script.installed_at = old.installed_at;
            script.execution_count = old.execution_count;
            script.last_executed = old.last_executed;
            mgr.replace_script(&profile.name, script)
                .map(|_| "replaced")
        } else {
            mgr.install_script(&profile.name, script)
                .map(|_| "installed")
        };
        match status {
            Ok(st) => {
                if let Some(values) = entry.values {
                    let _ = mgr.clear_values(&profile.name, &id);
                    let space = ns(&profile.name, &id);
                    for (n, v) in values {
                        if let Err(e) = mgr.storage().set_raw(&space, &n, v) {
                            tracing::warn!("import value {id}/{n}: {e}");
                        }
                    }
                    mgr.gm().forget_script(&profile.name, &id);
                }
                results.push(result(st, None));
            }
            Err(e) => results.push(result("error", Some(e.to_string()))),
        }
    }
    let n = |s: &str| results.iter().filter(|r| r.status == s).count();
    info!(
        "Userscripts imported by {}: {} installed, {} replaced, {} skipped, {} failed",
        p.username,
        n("installed"),
        n("replaced"),
        n("skipped"),
        n("error")
    );
    Ok(Json(ImportUserscriptsResponse { results }))
}

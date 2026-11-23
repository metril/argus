//! Bypass handlers: built-in categories, custom entries and subscribed exclusion lists. Every
//! change is applied live (the lookup set is rebuilt and swapped) and audited like any write.

use std::sync::Arc;
use std::time::Duration;

use api_types::{
    ArgusCategoryDto, ArgusListsStatus, BypassCategoryDto, BypassCheckResponse, BypassEntriesPage,
    BypassEntryCounts, BypassEntryDto, BypassHostsResponse, BypassMode, BypassSettings,
    BypassSubscriptionDto, CreateBypassEntry, CreateBypassSubscription, FailsafeDto,
    MessageResponse, SuggestedSubscription, UpdateBypassCategory, UpdateBypassEntry,
    UpdateBypassSettings, UpdateBypassSubscription,
};
use axum::{extract::State, http::StatusCode, Json};
use common::bypass as core;
use serde::Deserialize;
use utoipa::IntoParams;

use super::paging::{desc_key, natural_key, paginate, Keyed};
use crate::error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult};
use crate::state::AppState;

fn mode_out(m: core::BypassMode) -> BypassMode {
    match m {
        core::BypassMode::NoDecrypt => BypassMode::NoDecrypt,
        core::BypassMode::Full => BypassMode::Full,
    }
}

fn mode_in(m: BypassMode) -> core::BypassMode {
    match m {
        BypassMode::NoDecrypt => core::BypassMode::NoDecrypt,
        BypassMode::Full => core::BypassMode::Full,
    }
}

fn bad(m: String) -> ApiError {
    ApiError::ValidationError(m)
}

fn entry_out(e: &core::Entry) -> BypassEntryDto {
    BypassEntryDto {
        id: e.id.clone(),
        pattern: e.pattern.clone(),
        mode: mode_out(e.mode),
        source: e.source.clone(),
        note: e.note.clone(),
        updated_at: e.updated_at,
    }
}

fn sub_out(s: &core::Subscription) -> BypassSubscriptionDto {
    BypassSubscriptionDto {
        id: s.id.clone(),
        name: s.name.clone(),
        url: s.url.clone(),
        mode: mode_out(s.mode),
        enabled: s.enabled,
        host_count: s.host_count,
        skipped_lines: s.skipped_lines,
        skipped_sample: s.skipped_sample.clone(),
        last_fetched: s
            .last_fetched
            .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
            .map(|t| t.to_rfc3339()),
        last_error: s.last_error.clone(),
    }
}

fn contains_ci(hay: &str, needle: &str) -> bool {
    needle.is_empty() || hay.to_lowercase().contains(needle)
}

// ---- categories (first-party lists) ----

fn category_dto(s: &core::BypassState, cat: &str, title: &str) -> BypassCategoryDto {
    let sub = s.first_party(cat);
    let info = s.argus.categories.get(cat);
    BypassCategoryDto {
        id: cat.to_string(),
        title: info.map_or_else(|| title.to_string(), |i| i.name.clone()),
        description: info.map(|i| i.description.clone()).unwrap_or_default(),
        host_count: sub.map_or(0, |x| x.host_count),
        enabled: sub.is_some_and(|x| x.enabled),
        mode: mode_out(sub.map_or(core::BypassMode::NoDecrypt, |x| x.mode)),
        default_mode: mode_out(info.map_or(core::BypassMode::NoDecrypt, |i| i.default_mode)),
        loaded: sub.is_some_and(|x| x.last_fetched.is_some()),
    }
}

/// The first-party categories (backed by the Argus lists) with their switch, mode and state.
#[utoipa::path(
    get, path = "/bypass/categories", tag = "bypass",
    security(("bearer_auth" = ["config:read"])),
    responses((status = 200, description = "Categories", body = Vec<BypassCategoryDto>))
)]
pub async fn list_categories(State(state): State<Arc<AppState>>) -> Json<Vec<BypassCategoryDto>> {
    Json(state.bypass().read(|s| {
        core::FIRST_PARTY
            .iter()
            .map(|(cat, title)| category_dto(s, cat, title))
            .collect()
    }))
}

fn category(id: &str) -> ApiResult<(&'static str, &'static str)> {
    core::FIRST_PARTY
        .iter()
        .find(|(c, _)| *c == id)
        .copied()
        .ok_or_else(|| ApiError::NotFound(format!("Bypass category '{id}'")))
}

/// Enable, disable or change the mode of a category (its first-party subscription).
#[utoipa::path(
    put, path = "/bypass/categories/{id}", tag = "bypass",
    security(("bearer_auth" = ["config:write"])),
    params(("id" = String, Path, description = "Category id")),
    request_body = UpdateBypassCategory,
    responses((status = 200, description = "Updated", body = BypassCategoryDto))
)]
pub async fn update_category(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<UpdateBypassCategory>,
) -> ApiResult<Json<BypassCategoryDto>> {
    let (cat, title) = category(&id)?;
    let sub_id = core::argus_id(cat);
    let (dto, needs_list) = state
        .bypass()
        .update_async(move |s| {
            let sub = s
                .subscriptions
                .iter_mut()
                .find(|x| x.id == sub_id)
                .ok_or_else(|| "the category has no subscription".to_string())?;
            if let Some(e) = req.enabled {
                sub.enabled = e;
            }
            if let Some(m) = req.mode {
                sub.mode = mode_in(m);
            }
            let needs = sub.enabled && sub.last_fetched.is_none();
            Ok((category_dto(s, cat, title), needs))
        })
        .await
        .map_err(ApiError::Internal)?;
    if needs_list {
        // Enabled but never loaded: fetch it now rather than at the next scheduled check.
        state.argus().nudge();
    }
    Ok(Json(dto))
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HostsQuery {
    /// Case-insensitive substring.
    pub q: Option<String>,
    /// Most domains returned (default 200, max 1000).
    pub limit: Option<u32>,
}

/// The domains of a category, optionally filtered.
#[utoipa::path(
    get, path = "/bypass/categories/{id}/hosts", tag = "bypass",
    security(("bearer_auth" = ["config:read"])),
    params(("id" = String, Path, description = "Category id"), HostsQuery),
    responses((status = 200, description = "Domains", body = BypassHostsResponse))
)]
pub async fn category_hosts(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<HostsQuery>,
) -> ApiResult<Json<BypassHostsResponse>> {
    let (cat, _) = category(&id)?;
    let needle = q.q.as_deref().unwrap_or("").trim().to_lowercase();
    let mut all: Vec<String> = state.bypass().read(|s| {
        s.sub_hosts
            .get(&core::argus_id(cat))
            .map(|h| h.as_slice())
            .unwrap_or_default()
            .iter()
            .filter(|d| contains_ci(d, &needle))
            .cloned()
            .collect()
    });
    all.sort_by_key(|d| natural_key(d.trim_start_matches("*.")));
    let total = all.len();
    all.truncate(q.limit.unwrap_or(200).clamp(1, 1000) as usize);
    Ok(Json(BypassHostsResponse { items: all, total }))
}

// ---- custom entries ----

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EntriesQuery {
    /// Case-insensitive substring of the pattern or note.
    pub q: Option<String>,
    /// `no_decrypt` or `full`.
    pub mode: Option<String>,
    /// `az` (natural order, default) or `recent`.
    pub sort: Option<String>,
    /// Deprecated: use `cursor`.
    pub page: Option<u32>,
    /// Page size (1..=200, default 40).
    pub limit: Option<u32>,
    pub cursor: Option<String>,
    /// With `sort=az`: start at the first pattern at or after this prefix.
    pub from: Option<String>,
}

/// Custom entries (including those migrated from `tls_passthrough_hosts`).
#[utoipa::path(
    get, path = "/bypass/entries", tag = "bypass",
    security(("bearer_auth" = ["config:read"])),
    params(EntriesQuery),
    responses((status = 200, description = "Entries", body = BypassEntriesPage))
)]
pub async fn list_entries(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<EntriesQuery>,
) -> ApiResult<Json<BypassEntriesPage>> {
    let mode = match q.mode.as_deref() {
        None => None,
        Some("no_decrypt") => Some(core::BypassMode::NoDecrypt),
        Some("full") => Some(core::BypassMode::Full),
        Some(o) => return Err(bad(format!("unknown mode '{o}' (no_decrypt, full)"))),
    };
    let recent = match q.sort.as_deref() {
        None | Some("az") => false,
        Some("recent") => true,
        Some(o) => return Err(bad(format!("unknown sort '{o}' (az, recent)"))),
    };
    if q.from.is_some() && recent {
        return Err(bad("`from` needs sort=az".into()));
    }
    let needle = q.q.as_deref().unwrap_or("").trim().to_lowercase();
    let matching: Vec<core::Entry> = state.bypass().read(|s| {
        s.entries
            .iter()
            .filter(|e| {
                contains_ci(&e.pattern, &needle)
                    || e.note.as_deref().is_some_and(|n| contains_ci(n, &needle))
            })
            .cloned()
            .collect()
    });
    let mut counts = BypassEntryCounts {
        all: matching.len(),
        no_decrypt: matching
            .iter()
            .filter(|e| e.mode == core::BypassMode::NoDecrypt)
            .count(),
        full: matching
            .iter()
            .filter(|e| e.mode == core::BypassMode::Full)
            .count(),
        letters: Vec::new(),
    };
    let rows: Vec<Keyed<BypassEntryDto>> = matching
        .iter()
        .filter(|e| mode.is_none_or(|m| e.mode == m))
        .map(|e| {
            let label = e.pattern.trim_start_matches("*.").to_string();
            let name = natural_key(&label);
            Keyed {
                key: if recent {
                    format!("{}{name}", desc_key(e.updated_at.max(0) as u64))
                } else {
                    name
                },
                id: e.id.clone(),
                label,
                item: entry_out(e),
            }
        })
        .collect();
    let from = q.from.as_deref().map(natural_key);
    let p = paginate(rows, q.limit, q.cursor.as_deref(), from.as_deref(), q.page)?;
    counts.letters = p.letters;
    Ok(Json(BypassEntriesPage {
        items: p.items,
        next_cursor: p.next_cursor,
        total: p.total,
        counts,
        limit: p.limit,
        has_more: p.has_more,
        page: p.page,
    }))
}

fn check_note(n: &Option<String>) -> ApiResult<()> {
    match n {
        Some(n) if n.len() > 200 => Err(bad("note: at most 200 characters".into())),
        _ => Ok(()),
    }
}

/// Add a custom entry (409 if the pattern already has one).
#[utoipa::path(
    post, path = "/bypass/entries", tag = "bypass",
    security(("bearer_auth" = ["config:write"])),
    request_body = CreateBypassEntry,
    responses((status = 201, description = "Created", body = BypassEntryDto))
)]
pub async fn create_entry(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<CreateBypassEntry>,
) -> ApiResult<(StatusCode, Json<BypassEntryDto>)> {
    let pattern = core::normalize_pattern(&req.pattern).map_err(bad)?;
    check_note(&req.note)?;
    let entry = state
        .bypass()
        .update_async(move |s| {
            if s.entries.iter().any(|e| e.pattern == pattern) {
                return Err(format!("conflict: an entry for {pattern} already exists"));
            }
            let e = core::Entry {
                id: core::new_id(),
                pattern,
                mode: req.mode.map_or(core::BypassMode::Full, mode_in),
                source: "custom".into(),
                note: req.note.filter(|n| !n.is_empty()),
                updated_at: core::now(),
            };
            s.entries.push(e.clone());
            Ok(e)
        })
        .await
        .map_err(|m| match m.strip_prefix("conflict: ") {
            Some(c) => ApiError::AlreadyExists(c.to_string()),
            None => ApiError::Internal(m),
        })?;
    Ok((StatusCode::CREATED, Json(entry_out(&entry))))
}

/// Change a custom entry.
#[utoipa::path(
    put, path = "/bypass/entries/{id}", tag = "bypass",
    security(("bearer_auth" = ["config:write"])),
    params(("id" = String, Path, description = "Entry id")),
    request_body = UpdateBypassEntry,
    responses((status = 200, description = "Updated", body = BypassEntryDto))
)]
pub async fn update_entry(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<UpdateBypassEntry>,
) -> ApiResult<Json<BypassEntryDto>> {
    let pattern = req
        .pattern
        .as_deref()
        .map(core::normalize_pattern)
        .transpose()
        .map_err(bad)?;
    check_note(&req.note)?;
    let entry = state
        .bypass()
        .update_async(move |s| {
            if let Some(p) = &pattern {
                if s.entries.iter().any(|e| &e.pattern == p && e.id != id) {
                    return Err(format!("conflict: an entry for {p} already exists"));
                }
            }
            let e = s
                .entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| format!("missing: {id}"))?;
            if let Some(p) = pattern {
                e.pattern = p;
                // A hand-edited entry is no longer "migrated".
                e.source = "custom".into();
            }
            if let Some(m) = req.mode {
                e.mode = mode_in(m);
            }
            if let Some(n) = req.note {
                e.note = (!n.is_empty()).then_some(n);
            }
            e.updated_at = core::now();
            Ok(e.clone())
        })
        .await
        .map_err(|m| {
            if let Some(c) = m.strip_prefix("conflict: ") {
                ApiError::AlreadyExists(c.to_string())
            } else if m.starts_with("missing: ") {
                ApiError::NotFound("Bypass entry".into())
            } else {
                ApiError::Internal(m)
            }
        })?;
    Ok(Json(entry_out(&entry)))
}

/// Delete a custom entry.
#[utoipa::path(
    delete, path = "/bypass/entries/{id}", tag = "bypass",
    security(("bearer_auth" = ["config:write"])),
    params(("id" = String, Path, description = "Entry id")),
    responses((status = 200, description = "Deleted", body = MessageResponse))
)]
pub async fn delete_entry(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<MessageResponse>> {
    state
        .bypass()
        .update_async(move |s| {
            let n = s.entries.len();
            s.entries.retain(|e| e.id != id);
            if s.entries.len() == n {
                Err("missing".to_string())
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|m| {
            if m == "missing" {
                ApiError::NotFound("Bypass entry".into())
            } else {
                ApiError::Internal(m)
            }
        })?;
    Ok(Json(MessageResponse {
        message: "Entry deleted".into(),
    }))
}

// ---- subscriptions ----

fn check_url(u: &str) -> ApiResult<()> {
    match url::Url::parse(u) {
        Ok(p) if matches!(p.scheme(), "http" | "https") => Ok(()),
        _ => Err(bad("url: expected an http(s) URL".into())),
    }
}

fn check_name(n: &str) -> ApiResult<()> {
    if n.trim().is_empty() || n.len() > 100 {
        return Err(bad("name: 1 to 100 characters".into()));
    }
    Ok(())
}

/// First-party subscriptions are changed through the categories, not directly.
fn guard_third_party(id: &str) -> ApiResult<()> {
    if core::is_first_party(id) {
        return Err(bad(format!(
            "{id} is a first-party list: change it with /bypass/categories"
        )));
    }
    Ok(())
}

/// Subscribed exclusion lists.
#[utoipa::path(
    get, path = "/bypass/subscriptions", tag = "bypass",
    security(("bearer_auth" = ["config:read"])),
    responses((status = 200, description = "Subscriptions", body = Vec<BypassSubscriptionDto>))
)]
pub async fn list_subscriptions(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<BypassSubscriptionDto>> {
    // The first-party (`argus:*`) subscriptions are managed through the categories.
    Json(state.bypass().read(|s| {
        s.subscriptions
            .iter()
            .filter(|x| !core::is_first_party(&x.id))
            .map(sub_out)
            .collect()
    }))
}

/// Most patterns kept per subscription.
const MAX_SUB_HOSTS: usize = 500_000;

/// Fetch a subscription and store its patterns; the error (kept on the subscription) says why
/// a failed fetch left the old patterns in place.
pub async fn refresh_subscription(state: &AppState, id: &str) -> Result<usize, String> {
    let url = state
        .bypass()
        .read(|s| {
            s.subscriptions
                .iter()
                .find(|x| x.id == id)
                .map(|x| x.url.clone())
        })
        .ok_or_else(|| "missing".to_string())?;
    let fetched = state.list_service.fetch_exclusion_list(&url).await;
    let id = id.to_string();
    match fetched {
        Ok(text) => {
            let (hosts, skipped) = core::parse_exclusion_list_counted(&text, MAX_SUB_HOSTS);
            let n = hosts.len();
            let fetched_url = url.clone();
            state
                .bypass()
                .update_async(move |s| {
                    // The subscription may have been re-pointed (or removed) while the fetch was
                    // in flight: patterns fetched from the old URL must not land on the new one.
                    if let Some(x) = s
                        .subscriptions
                        .iter_mut()
                        .find(|x| x.id == id && x.url == fetched_url)
                    {
                        x.host_count = n;
                        x.last_fetched = Some(core::now());
                        x.last_error = None;
                        x.skipped_lines = skipped.count as u32;
                        x.skipped_sample = skipped.sample;
                        s.set_hosts(&id, hosts);
                    }
                    Ok(())
                })
                .await?;
            Ok(n)
        }
        Err(e) => {
            let failed_url = url.clone();
            let msg = e.clone();
            let _ = state
                .bypass()
                .update_async(move |s| {
                    if let Some(x) = s
                        .subscriptions
                        .iter_mut()
                        .find(|x| x.id == id && x.url == failed_url)
                    {
                        x.last_error = Some(msg);
                    }
                    Ok(())
                })
                .await;
            Err(e)
        }
    }
}

/// Subscribe to an exclusion list (one host or `*.suffix` per line). The first fetch is
/// attempted at once; a failure is recorded on the subscription, which is still created.
#[utoipa::path(
    post, path = "/bypass/subscriptions", tag = "bypass",
    security(("bearer_auth" = ["config:write"])),
    request_body = CreateBypassSubscription,
    responses((status = 201, description = "Created", body = BypassSubscriptionDto))
)]
pub async fn create_subscription(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<CreateBypassSubscription>,
) -> ApiResult<(StatusCode, Json<BypassSubscriptionDto>)> {
    let suggested = match req.suggested_id.as_deref() {
        Some(id) => Some(
            SUGGESTED
                .iter()
                .find(|s| s.id == id)
                .ok_or_else(|| bad(format!("suggested_id: unknown list '{id}'")))?,
        ),
        None => None,
    };
    let (name, url) = match (suggested, req.name, req.url) {
        (Some(s), n, u) => (
            n.unwrap_or_else(|| s.name.to_string()),
            u.unwrap_or_else(|| s.url()),
        ),
        (None, Some(n), Some(u)) => (n, u),
        _ => return Err(bad("give `suggested_id`, or both `name` and `url`".into())),
    };
    check_url(&url)?;
    check_name(&name)?;
    let sub = core::Subscription {
        id: core::new_id(),
        name: name.trim().to_string(),
        url: url.trim().to_string(),
        mode: req
            .mode
            .map(mode_in)
            .or(suggested.map(|s| s.mode))
            .unwrap_or(core::BypassMode::NoDecrypt),
        enabled: req.enabled.unwrap_or(true),
        last_fetched: None,
        last_error: None,
        host_count: 0,
        skipped_lines: 0,
        skipped_sample: Vec::new(),
    };
    let id = sub.id.clone();
    state
        .bypass()
        .update_async(move |s| {
            if s.subscriptions.iter().any(|x| x.url == sub.url) {
                return Err("conflict".to_string());
            }
            s.subscriptions.push(sub);
            Ok(())
        })
        .await
        .map_err(|m| {
            if m == "conflict" {
                ApiError::AlreadyExists("A subscription to that URL".into())
            } else {
                ApiError::Internal(m)
            }
        })?;
    let _ = refresh_subscription(&state, &id).await;
    let out = state
        .bypass()
        .read(|s| s.subscriptions.iter().find(|x| x.id == id).map(sub_out))
        .ok_or_else(|| ApiError::Internal("subscription vanished".into()))?;
    Ok((StatusCode::CREATED, Json(out)))
}

/// Change a subscription (a new URL is fetched again).
#[utoipa::path(
    put, path = "/bypass/subscriptions/{id}", tag = "bypass",
    security(("bearer_auth" = ["config:write"])),
    params(("id" = String, Path, description = "Subscription id")),
    request_body = UpdateBypassSubscription,
    responses((status = 200, description = "Updated", body = BypassSubscriptionDto))
)]
pub async fn update_subscription(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<UpdateBypassSubscription>,
) -> ApiResult<Json<BypassSubscriptionDto>> {
    guard_third_party(&id)?;
    if let Some(u) = &req.url {
        check_url(u)?;
    }
    if let Some(n) = &req.name {
        check_name(n)?;
    }
    let upd_id = id.clone();
    let url_changed = state
        .bypass()
        .update_async(move |s| {
            let id = upd_id;
            let x = s
                .subscriptions
                .iter_mut()
                .find(|x| x.id == id)
                .ok_or_else(|| "missing".to_string())?;
            let mut changed = false;
            if let Some(n) = req.name {
                x.name = n.trim().to_string();
            }
            if let Some(u) = req.url {
                changed = u.trim() != x.url;
                x.url = u.trim().to_string();
            }
            if let Some(m) = req.mode {
                x.mode = mode_in(m);
            }
            if let Some(e) = req.enabled {
                x.enabled = e;
            }
            Ok(changed)
        })
        .await
        .map_err(|m| {
            if m == "missing" {
                ApiError::NotFound("Bypass subscription".into())
            } else {
                ApiError::Internal(m)
            }
        })?;
    if url_changed {
        let _ = refresh_subscription(&state, &id).await;
    }
    let out = state
        .bypass()
        .read(|s| s.subscriptions.iter().find(|x| x.id == id).map(sub_out))
        .ok_or_else(|| ApiError::NotFound("Bypass subscription".into()))?;
    Ok(Json(out))
}

/// Unsubscribe (its patterns stop applying at once).
#[utoipa::path(
    delete, path = "/bypass/subscriptions/{id}", tag = "bypass",
    security(("bearer_auth" = ["config:write"])),
    params(("id" = String, Path, description = "Subscription id")),
    responses((status = 200, description = "Deleted", body = MessageResponse))
)]
pub async fn delete_subscription(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<MessageResponse>> {
    guard_third_party(&id)?;
    state
        .bypass()
        .update_async(move |s| {
            let n = s.subscriptions.len();
            s.subscriptions.retain(|x| x.id != id);
            s.sub_hosts.remove(&id);
            if s.subscriptions.len() == n {
                Err("missing".to_string())
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|m| {
            if m == "missing" {
                ApiError::NotFound("Bypass subscription".into())
            } else {
                ApiError::Internal(m)
            }
        })?;
    Ok(Json(MessageResponse {
        message: "Subscription deleted".into(),
    }))
}

/// Fetch a subscription now.
#[utoipa::path(
    post, path = "/bypass/subscriptions/{id}/refresh", tag = "bypass",
    security(("bearer_auth" = ["config:write"])),
    params(("id" = String, Path, description = "Subscription id")),
    responses(
        (status = 200, description = "Refreshed", body = BypassSubscriptionDto),
        (status = 502, description = "The list could not be fetched"),
    )
)]
pub async fn refresh_subscription_now(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<BypassSubscriptionDto>> {
    if core::is_first_party(&id) {
        // First-party lists are one signed release: refresh them all.
        state.argus().refresh().await.map_err(|e| {
            ApiError::coded(
                StatusCode::BAD_GATEWAY,
                "fetch_failed",
                format!("Could not update the Argus lists: {e}"),
            )
        })?;
        let out = state
            .bypass()
            .read(|s| s.subscriptions.iter().find(|x| x.id == id).map(sub_out))
            .ok_or_else(|| ApiError::NotFound("Bypass subscription".into()))?;
        return Ok(Json(out));
    }
    match refresh_subscription(&state, &id).await {
        Ok(_) => {}
        Err(e) if e == "missing" => {
            return Err(ApiError::NotFound("Bypass subscription".into()));
        }
        Err(e) => {
            return Err(ApiError::coded(
                StatusCode::BAD_GATEWAY,
                "fetch_failed",
                format!("Could not fetch the list: {e}"),
            ))
        }
    }
    let out = state
        .bypass()
        .read(|s| s.subscriptions.iter().find(|x| x.id == id).map(sub_out))
        .ok_or_else(|| ApiError::NotFound("Bypass subscription".into()))?;
    Ok(Json(out))
}

/// Refresh subscriptions that are due (called by the scheduler).
pub async fn refresh_due(state: &Arc<AppState>) {
    let (auto, every) = state.list_service.schedule();
    if !auto {
        return;
    }
    let now = core::now();
    let due: Vec<String> = state.bypass().read(|s| {
        s.subscriptions
            .iter()
            .filter(|x| x.enabled && !core::is_first_party(&x.id))
            .filter(|x| {
                x.last_fetched
                    .is_none_or(|t| now - t >= every.as_secs() as i64)
            })
            .map(|x| x.id.clone())
            .collect()
    });
    for id in due {
        if let Err(e) = refresh_subscription(state, &id).await {
            tracing::warn!("bypass subscription {id}: {e}");
        }
    }
}

/// How often the scheduler looks for due subscriptions.
pub const REFRESH_TICK: Duration = Duration::from_secs(300);

// ---- suggested lists and settings ----

struct Suggested {
    id: &'static str,
    name: &'static str,
    file: &'static str,
    description: &'static str,
    mode: core::BypassMode,
}

impl Suggested {
    fn url(&self) -> String {
        format!(
            "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/{}",
            self.file
        )
    }
}

/// AdGuard's HttpsExclusions lists. Only the addresses are kept here: the lists are fetched at
/// runtime and never shipped.
const SUGGESTED: [Suggested; 7] = [
    Suggested {
        id: "adguard-banks",
        name: "AdGuard: banks and financial services",
        file: "banks.txt",
        description: "Banking and financial sites that break or alarm users when intercepted.",
        mode: core::BypassMode::NoDecrypt,
    },
    Suggested {
        id: "adguard-sensitive",
        name: "AdGuard: sensitive services",
        file: "sensitive.txt",
        description: "Medical, government and other privacy-sensitive sites.",
        mode: core::BypassMode::NoDecrypt,
    },
    Suggested {
        id: "adguard-issues",
        name: "AdGuard: known breakage",
        file: "issues.txt",
        description: "Hosts that stop working under HTTPS filtering (pinned or fragile clients).",
        mode: core::BypassMode::NoDecrypt,
    },
    Suggested {
        id: "adguard-android",
        name: "AdGuard: Android apps",
        file: "android.txt",
        description: "Android system and app endpoints that reject intercepted certificates.",
        mode: core::BypassMode::NoDecrypt,
    },
    Suggested {
        id: "adguard-firefox",
        name: "AdGuard: Firefox",
        file: "firefox.txt",
        description: "Firefox's own service endpoints.",
        mode: core::BypassMode::NoDecrypt,
    },
    Suggested {
        id: "adguard-mac",
        name: "AdGuard: macOS",
        file: "mac.txt",
        description: "macOS and Apple service endpoints.",
        mode: core::BypassMode::NoDecrypt,
    },
    Suggested {
        id: "adguard-windows",
        name: "AdGuard: Windows",
        file: "windows.txt",
        description: "Windows and Microsoft service endpoints.",
        mode: core::BypassMode::NoDecrypt,
    },
];

/// A catalog of one-click exclusion lists (AdGuard's HttpsExclusions), with whether each is
/// already subscribed. Fetched only when subscribed.
#[utoipa::path(
    get, path = "/bypass/subscriptions/suggested", tag = "bypass",
    security(("bearer_auth" = ["config:read"])),
    responses((status = 200, description = "Suggested lists", body = Vec<SuggestedSubscription>))
)]
pub async fn suggested(State(state): State<Arc<AppState>>) -> Json<Vec<SuggestedSubscription>> {
    let urls: Vec<String> = state
        .bypass()
        .read(|s| s.subscriptions.iter().map(|x| x.url.clone()).collect());
    Json(
        SUGGESTED
            .iter()
            .map(|s| SuggestedSubscription {
                id: s.id.to_string(),
                name: s.name.to_string(),
                url: s.url(),
                description: s.description.to_string(),
                default_mode: mode_out(s.mode),
                subscribed: urls.contains(&s.url()),
            })
            .collect(),
    )
}

/// Bypass-wide settings.
#[utoipa::path(
    get, path = "/bypass/settings", tag = "bypass",
    security(("bearer_auth" = ["config:read"])),
    responses((status = 200, description = "Settings", body = BypassSettings))
)]
pub async fn get_bypass_settings(State(state): State<Arc<AppState>>) -> Json<BypassSettings> {
    Json(settings_dto(&state))
}

fn settings_dto(state: &AppState) -> BypassSettings {
    let f = state.bypass().failsafe();
    BypassSettings {
        ev_no_decrypt: state.bypass().ev_no_decrypt(),
        decrypt_without_lists: state.bypass().read(|s| s.decrypt_without_lists),
        failsafe: FailsafeDto {
            active: f.active,
            reason: f.reason,
        },
    }
}

/// Change the bypass-wide settings (applied live).
#[utoipa::path(
    put, path = "/bypass/settings", tag = "bypass",
    security(("bearer_auth" = ["config:write"])),
    request_body = UpdateBypassSettings,
    responses((status = 200, description = "Updated", body = BypassSettings))
)]
pub async fn update_bypass_settings(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<UpdateBypassSettings>,
) -> ApiResult<Json<BypassSettings>> {
    state
        .bypass()
        .update_async(move |s| {
            if let Some(v) = req.ev_no_decrypt {
                s.ev_no_decrypt = v;
            }
            if let Some(v) = req.decrypt_without_lists {
                s.decrypt_without_lists = v;
            }
            Ok(())
        })
        .await
        .map_err(ApiError::Internal)?;
    Ok(Json(settings_dto(&state)))
}

// ---- first-party lists ----

fn argus_status(state: &AppState) -> ArgusListsStatus {
    let ts = |t: Option<i64>| {
        t.and_then(|t| chrono::DateTime::from_timestamp(t, 0))
            .map(|t| t.to_rfc3339())
    };
    state.bypass().read(|s| ArgusListsStatus {
        version: s.argus.version.clone(),
        updated_at: ts(s.argus.updated_at),
        last_checked: ts(s.argus.last_checked),
        last_error: s.argus.last_error.clone(),
        skipped_lines: s.argus.skipped_lines,
        skipped_sample: s.argus.skipped_sample.clone(),
        roots: state.roots.get().map(|c| {
            let r = c.status.read();
            api_types::RootsStatusDto {
                serial: r.serial,
                roots: u32::try_from(r.roots).unwrap_or(u32::MAX),
                signed: r.signed,
                updated_at: r.updated_at.clone(),
                last_checked: r.last_checked.clone(),
                last_error: r.last_error.clone(),
            }
        }),
        categories: core::FIRST_PARTY
            .iter()
            .map(|(cat, title)| {
                let c = category_dto(s, cat, title);
                ArgusCategoryDto {
                    id: c.id,
                    name: c.title,
                    description: c.description,
                    host_count: c.host_count,
                    enabled: c.enabled,
                    mode: c.mode,
                    loaded: c.loaded,
                }
            })
            .collect(),
    })
}

/// The installed release of the first-party (argus-lists) lists and how each category stands.
#[utoipa::path(
    get, path = "/bypass/argus-lists", tag = "bypass",
    security(("bearer_auth" = ["config:read"])),
    responses((status = 200, description = "Status", body = ArgusListsStatus))
)]
pub async fn get_argus_lists(State(state): State<Arc<AppState>>) -> Json<ArgusListsStatus> {
    Json(argus_status(&state))
}

/// Check for a newer release now: fetches `meta.json`, verifies it against the compiled-in
/// public key and installs newer, verified lists. Never installs an older release.
#[utoipa::path(
    post, path = "/bypass/argus-lists/refresh", tag = "bypass",
    security(("bearer_auth" = ["config:write"])),
    responses(
        (status = 200, description = "Checked", body = ArgusListsStatus),
        (status = 502, description = "The release could not be fetched or verified"),
    )
)]
pub async fn refresh_argus_lists(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<ArgusListsStatus>> {
    // The trusted roots follow the same release: check them too (in the background).
    if let Some(c) = state.roots.get() {
        c.wake.notify_one();
    }
    state.argus().refresh().await.map_err(|e| {
        ApiError::coded(
            StatusCode::BAD_GATEWAY,
            "fetch_failed",
            format!("Could not update the Argus lists: {e}"),
        )
    })?;
    Ok(Json(argus_status(&state)))
}

// ---- check ----

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CheckQuery {
    /// Host name to test.
    pub host: String,
}

/// What the proxy would do for a host: the effective mode and which source matched.
#[utoipa::path(
    get, path = "/bypass/check", tag = "bypass",
    security(("bearer_auth" = ["config:read"])),
    params(CheckQuery),
    responses((status = 200, description = "Effective answer", body = BypassCheckResponse))
)]
pub async fn check_host(
    State(state): State<Arc<AppState>>,
    ApiQuery(q): ApiQuery<CheckQuery>,
) -> ApiResult<Json<BypassCheckResponse>> {
    let host = q.host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.contains(['/', ' ', ':']) {
        return Err(bad("host: expected a bare host name".into()));
    }
    let hit = state.bypass().lookup(&host);
    Ok(Json(BypassCheckResponse {
        host,
        bypassed: hit.is_some(),
        mode: hit.as_ref().map(|h| mode_out(h.mode)),
        source: hit.as_ref().map(|h| h.source.clone()),
        pattern: hit.map(|h| h.pattern),
    }))
}

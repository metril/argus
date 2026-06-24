//! Filter compile/reload orchestrator.
//!
//! Ties the persistent [`FilterListStore`] to the running [`SharedEngine`]: download the enabled
//! lists (conditionally, honoring ETags), compile them into a single adblock engine off the async
//! runtime (`spawn_blocking`), and atomically install the result so every proxy worker thread
//! picks it up. Everything here is `Send`, so it runs as ordinary spawned tasks (unlike the old
//! `!Send`/`spawn_local` scheduler).

use std::sync::Arc;

use chrono::Utc;
use filter_engine::{compile_engine, FilterList, SharedEngine};
use reqwest::header::{ETAG, IF_NONE_MATCH};
use reqwest::Client;
use tracing::{info, warn};

use crate::error::{ApiError, ApiResult};
use crate::filter_store::FilterListStore;
use crate::state::AppState;

/// Count the non-empty, non-comment lines of a list as an approximate rule count for display.
fn count_rules(content: &str) -> usize {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('!'))
        .count()
}

/// Fetch one list's content, using a conditional request + the cached copy when unchanged.
///
/// Returns the content to compile with, or `None` if it could neither be fetched nor recovered
/// from cache (in which case the list is skipped this round). Updates `list` metadata (etag,
/// rule_count, last_updated) and the content cache on a successful download.
async fn fetch_list_content(
    client: &Client,
    store: &FilterListStore,
    list: &mut FilterList,
) -> Option<String> {
    let mut req = client.get(&list.url);
    if let Some(etag) = &list.etag {
        req = req.header(IF_NONE_MATCH, etag.clone());
    }

    match req.send().await {
        Ok(resp) if resp.status() == reqwest::StatusCode::NOT_MODIFIED => {
            // Unchanged — reuse cached content.
            match store.get_content(&list.id) {
                Ok(Some(content)) => Some(content),
                _ => {
                    warn!("List {} returned 304 but no cached content; will refetch next cycle", list.name);
                    None
                }
            }
        }
        Ok(resp) if resp.status().is_success() => {
            let new_etag = resp
                .headers()
                .get(ETAG)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            match resp.text().await {
                Ok(content) => {
                    list.etag = new_etag;
                    list.rule_count = count_rules(&content);
                    list.last_updated = Some(Utc::now());
                    if let Err(e) = store.put_content(&list.id, &content) {
                        warn!("Failed to cache content for {}: {}", list.name, e);
                    }
                    if let Err(e) = store.upsert(list) {
                        warn!("Failed to persist metadata for {}: {}", list.name, e);
                    }
                    info!("Downloaded {} ({} rules)", list.name, list.rule_count);
                    Some(content)
                }
                Err(e) => {
                    warn!("Failed to read body for {}: {}; falling back to cache", list.name, e);
                    store.get_content(&list.id).ok().flatten()
                }
            }
        }
        Ok(resp) => {
            warn!("List {} HTTP {}; falling back to cache", list.name, resp.status());
            store.get_content(&list.id).ok().flatten()
        }
        Err(e) => {
            warn!("List {} download error: {}; falling back to cache", list.name, e);
            store.get_content(&list.id).ok().flatten()
        }
    }
}

/// Download all enabled lists, compile them, and install the result into `shared_engine`.
pub async fn reload_now(
    store: Arc<FilterListStore>,
    shared_engine: Arc<SharedEngine>,
    http_client: Client,
) -> ApiResult<()> {
    let lists = store.get_all()?;
    let enabled: Vec<FilterList> = lists.into_iter().filter(|l| l.enabled).collect();
    info!("Reloading filter engine from {} enabled list(s)", enabled.len());

    let mut contents = Vec::new();
    for mut list in enabled {
        if let Some(content) = fetch_list_content(&http_client, &store, &mut list).await {
            contents.push(content);
        }
    }

    // Append the user's custom rules (block/allow/cosmetic) as an extra source so they compile in
    // like any list. `@@` allow rules in here override blocks from the public lists.
    match store.get_custom_rules() {
        Ok(rules) if !rules.trim().is_empty() => contents.push(rules),
        _ => {}
    }

    // Compile off the async runtime — pure CPU, and the !Send engine lives entirely inside.
    let bytes = tokio::task::spawn_blocking(move || compile_engine(&contents))
        .await
        .map_err(|e| ApiError::Internal(format!("compile task panicked: {e}")))?;

    shared_engine.install(bytes);
    Ok(())
}

/// Ensure the scriptlet resource library is loaded into `shared_engine`.
///
/// Uses a cached `<data_dir>/resources.json` (already in adblock-rust format) if present. Otherwise
/// fetches from `url` and caches the converted result. `url` may be:
/// - a GitHub *contents* API URL of uBlock Origin's `src/js/resources/` directory — every `.js`
///   file is downloaded, concatenated, and converted (this is the default, giving the full set);
/// - a single uBO `scriptlets.js` file (`.js`) — fetched and converted;
/// - a pre-built adblock-rust resources array (`.json`) — used directly.
///
/// No-op if `url` is empty. This is what makes `##+js(...)` scriptlet rules actually inject;
/// without it, scriptlets degrade to no-ops (CSS hiding still works).
pub async fn ensure_scriptlet_resources(
    data_dir: std::path::PathBuf,
    shared_engine: Arc<SharedEngine>,
    http_client: Client,
    url: String,
) {
    if url.trim().is_empty() {
        return;
    }
    let cache = data_dir.join("resources.json");

    // Prefer the cached (already-converted) copy.
    if let Ok(json) = tokio::fs::read_to_string(&cache).await {
        match shared_engine.set_resources_from_json(&json) {
            Ok(n) => {
                info!("Loaded {n} scriptlet resources from cache");
                return;
            }
            Err(e) => warn!("Cached resources.json invalid ({e}); re-fetching"),
        }
    }

    // Fetch + (if needed) convert to the adblock-rust resources JSON.
    let json = match fetch_resources_json(&http_client, &url).await {
        Some(j) => j,
        None => return,
    };

    match shared_engine.set_resources_from_json(&json) {
        Ok(n) => {
            info!("Loaded {n} scriptlet resources");
            if let Some(parent) = cache.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            if let Err(e) = tokio::fs::write(&cache, &json).await {
                warn!("Failed to cache resources.json: {e}");
            }
        }
        Err(e) => warn!("Scriptlet resources invalid after conversion: {e}"),
    }
}

/// Fetch resources from `url` and return them as an adblock-rust resources JSON array.
async fn fetch_resources_json(client: &Client, url: &str) -> Option<String> {
    if url.contains("api.github.com") && url.contains("/contents/") {
        // Directory listing: download every `.js` file, concatenate, convert.
        let listing = client.get(url).send().await.ok()?;
        if !listing.status().is_success() {
            warn!("Scriptlet resource listing HTTP {}", listing.status());
            return None;
        }
        let entries: serde_json::Value = listing.json().await.ok()?;
        let mut combined = String::new();
        for entry in entries.as_array()?.iter() {
            let name = entry["name"].as_str().unwrap_or("");
            let dl = entry["download_url"].as_str().unwrap_or("");
            if !name.ends_with(".js") || dl.is_empty() {
                continue;
            }
            match client.get(dl).send().await {
                Ok(r) if r.status().is_success() => {
                    if let Ok(text) = r.text().await {
                        combined.push('\n');
                        combined.push_str(&text);
                    }
                }
                _ => warn!("Failed to fetch scriptlet file {name}"),
            }
        }
        if combined.trim().is_empty() {
            return None;
        }
        filter_engine::ubo_scriptlets_to_json(&combined).ok()
    } else {
        // Single file.
        let resp = client.get(url).send().await.ok()?;
        if !resp.status().is_success() {
            warn!("Scriptlet resources HTTP {}", resp.status());
            return None;
        }
        let body = resp.text().await.ok()?;
        if url.ends_with(".json") {
            Some(body) // already adblock-rust format
        } else {
            filter_engine::ubo_scriptlets_to_json(&body).ok()
        }
    }
}

/// Fire-and-forget reload using the handles in [`AppState`]; logs failures.
///
/// Called after any list mutation so the running engine reflects the change without blocking the
/// HTTP response.
pub fn trigger_reload(state: &Arc<AppState>) {
    let store = state.filter_store.clone();
    let engine = state.shared_engine.clone();
    let client = state.http_client.clone();
    tokio::spawn(async move {
        if let Err(e) = reload_now(store, engine, client).await {
            warn!("Filter reload failed: {}", e);
        }
    });
}

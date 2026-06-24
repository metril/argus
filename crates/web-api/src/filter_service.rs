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

    // Compile off the async runtime — pure CPU, and the !Send engine lives entirely inside.
    let bytes = tokio::task::spawn_blocking(move || compile_engine(&contents))
        .await
        .map_err(|e| ApiError::Internal(format!("compile task panicked: {e}")))?;

    shared_engine.install(bytes);
    Ok(())
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

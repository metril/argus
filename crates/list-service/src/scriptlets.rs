//! Scriptlet resource library loading (uBO-compatible).
//!
//! A pinned snapshot is bundled in the binary and applied on the first build (so scriptlets work
//! offline). The fetched copy (a fixed list of raw uBO files, a single `.js`, or a ready `.json`
//! array) replaces it when available, with background retry and backoff, and is cached on disk.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tracing::{info, warn};

use crate::service::ListService;

/// uBlock Origin `src/js/resources/` files, in name order (the converter parses each separately). Fetched individually from a raw-file base URL instead of listing the directory through
/// the rate-limited contents API; a file that no longer exists upstream is skipped with a warning.
const UBO_RESOURCE_FILES: &[&str] = &[
    "abort-current-script",
    "attribute",
    "base",
    "cookie",
    "create-html",
    "href-sanitizer",
    "json-edit",
    "json-prune",
    "localstorage",
    "noeval",
    "object-prune",
    "parse-replace",
    "prevent-addeventlistener",
    "prevent-bab",
    "prevent-clipboard-write",
    "prevent-dialog",
    "prevent-fetch",
    "prevent-innerHTML",
    "prevent-navigation",
    "prevent-settimeout",
    "prevent-xhr",
    "proxy-apply",
    "replace-argument",
    "run-at",
    "safe-self",
    "scriptlets",
    "set-constant",
    "shared",
    "spoof-css",
    "stack-trace",
    "utils",
    "vod",
];

/// Rewrite a GitHub contents-API directory URL (the previous default) to the equivalent raw-file
/// base; other URLs are returned unchanged.
pub(crate) fn normalize_resources_url(url: &str) -> String {
    let url = url.trim();
    if let Some(rest) = url.strip_prefix("https://api.github.com/repos/") {
        let parts: Vec<&str> = rest.trim_end_matches('/').splitn(4, '/').collect();
        if let [owner, repo, "contents", path] = parts[..] {
            let path = path.split('?').next().unwrap_or(path);
            return format!("https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}");
        }
    }
    url.to_string()
}

impl ListService {
    /// Load scriptlet resources, retrying with exponential backoff until they load (or forever
    /// failing quietly in the background). No-op if the URL is empty. A valid cached
    /// `<data_dir>/resources.json` short-circuits the network.
    pub async fn ensure_scriptlet_resources(self: &Arc<Self>) {
        if self.cfg.scriptlet_resources_url.trim().is_empty() {
            return;
        }
        let mut delay = self.cfg.scriptlet_retry_initial;
        loop {
            match self.load_scriptlets_once().await {
                Ok(()) => {
                    self.scriptlets_tx.send_replace(true);
                    return;
                }
                Err(e) => warn!("Scriptlet resources unavailable: {e}; retrying in {delay:?}"),
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(self.cfg.scriptlet_retry_max);
        }
    }

    /// Apply the bundled snapshot unless disabled (empty URL) or a fetched copy already won.
    /// Runs once, before the first build installs an engine, so the install is a cheap rebuild.
    pub(crate) async fn load_bundled_resources(&self) {
        if !filter_engine::BUNDLED_AVAILABLE
            || self.cfg.scriptlet_resources_url.trim().is_empty()
            || self.bundled_tried.swap(true, Ordering::AcqRel)
        {
            return;
        }
        let engine = self.engine.clone();
        let state = self.fetched_resources_handle();
        let res = tokio::task::spawn_blocking(move || {
            let fetched = state.lock();
            if *fetched {
                return Ok(None);
            }
            engine
                .set_resources_from_json(filter_engine::BUNDLED_RESOURCES_JSON)
                .map(Some)
        })
        .await;
        match res {
            Ok(Ok(Some(n))) => info!(
                "Loaded {n} bundled scriptlet resources (uBlock Origin {})",
                &filter_engine::BUNDLED_RESOURCES_COMMIT[..8]
            ),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => warn!("Bundled scriptlet resources invalid: {e}"),
            Err(e) => warn!("Bundled resources task failed: {e}"),
        }
    }

    /// Parse + rebuild the engine on a blocking thread; marks the fetched copy as authoritative.
    async fn set_resources(&self, json: String) -> Result<usize, String> {
        let engine = self.engine.clone();
        let state = self.fetched_resources_handle();
        tokio::task::spawn_blocking(move || {
            let mut fetched = state.lock();
            let n = engine
                .set_resources_from_json(&json)
                .map_err(|e| e.to_string())?;
            *fetched = true;
            Ok(n)
        })
        .await
        .map_err(|e| e.to_string())?
    }

    async fn load_scriptlets_once(&self) -> Result<(), String> {
        let cache = self.cfg.data_dir.join("resources.json");
        let mut cached = false;
        if let Ok(json) = tokio::fs::read_to_string(&cache).await {
            match self.set_resources(json).await {
                Ok(n) => {
                    info!("Loaded {n} scriptlet resources from cache");
                    if self.engine.resource_report().dropped.is_empty() {
                        return Ok(());
                    }
                    // The cache (e.g. written by an older converter) held resources that fail
                    // validation: they are not served; try to refresh from the source.
                    warn!("Cached resources.json had invalid entries; refreshing");
                    cached = true;
                }
                Err(e) => warn!("Cached resources.json invalid ({e}); re-fetching"),
            }
        }
        let json = match self
            .fetch_resources_json(&self.cfg.scriptlet_resources_url)
            .await
        {
            Ok(j) => j,
            Err(e) if cached => {
                warn!("Refreshing scriptlet resources failed ({e}); keeping the validated cache");
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let n = self
            .set_resources(json.clone())
            .await
            .map_err(|e| format!("resources invalid after conversion: {e}"))?;
        info!("Loaded {n} scriptlet resources");
        let _ = tokio::fs::create_dir_all(&self.cfg.data_dir).await;
        if let Err(e) = tokio::fs::write(&cache, &json).await {
            warn!("Failed to cache resources.json: {e}");
        }
        Ok(())
    }

    /// Fetch `url` and return an adblock-rust resources JSON array. `url` may be a raw-file base
    /// URL of uBO's `src/js/resources/` (the files in [`UBO_RESOURCE_FILES`] are fetched,
    /// concatenated and converted), a single uBO `.js` file (converted), or a ready `.json` array
    /// (used as is).
    async fn fetch_resources_json(&self, url: &str) -> Result<String, String> {
        let url = normalize_resources_url(url);
        if url.ends_with(".json") {
            return self.get_text(&url).await;
        }
        let sources: Vec<String> = if url.ends_with(".js") {
            vec![self.get_text(&url).await?]
        } else {
            let base = url.trim_end_matches('/').to_string();
            // ~30 small files: fetch them all concurrently.
            let fetches: Vec<_> = UBO_RESOURCE_FILES
                .iter()
                .map(|name| self.get_text(format!("{base}/{name}.js")))
                .collect();
            let results: Vec<(&str, Result<String, String>)> = UBO_RESOURCE_FILES
                .iter()
                .copied()
                .zip(futures_util::future::join_all(fetches).await)
                .collect();
            let mut sources = Vec::new();
            for (name, res) in results {
                match res {
                    Ok(text) => sources.push(text),
                    // The scriptlet definitions themselves are required; helpers may have moved.
                    Err(e) if name == "scriptlets" => return Err(e),
                    Err(e) => warn!("Skipping resource file {name}.js: {e}"),
                }
            }
            // `href-sanitizer` imports `urlSkip` from the sibling `src/js/urlskip.js`.
            if let Some(parent) = base.strip_suffix("/resources") {
                match self.get_text(format!("{parent}/urlskip.js")).await {
                    Ok(text) => sources.push(text),
                    Err(e) => warn!("Skipping urlskip.js: {e}"),
                }
            }
            sources
        };
        if sources.iter().all(|s| s.trim().is_empty()) {
            return Err("no scriptlet files found".into());
        }
        // Each module is parsed on its own (a real JS parser, not text scanning); resources that
        // fail validation are dropped here and again, with reasons, when the library is loaded.
        let (json, dropped) =
            filter_engine::ubo_sources_to_json(&sources).map_err(|e| e.to_string())?;
        for d in &dropped {
            warn!("Scriptlet `{}` not converted: {}", d.name, d.reason);
        }
        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contents_api_url_becomes_raw_base() {
        assert_eq!(
            normalize_resources_url(
                "https://api.github.com/repos/gorhill/uBlock/contents/src/js/resources"
            ),
            "https://raw.githubusercontent.com/gorhill/uBlock/HEAD/src/js/resources"
        );
        assert_eq!(
            normalize_resources_url("http://127.0.0.1:1/x.json"),
            "http://127.0.0.1:1/x.json"
        );
    }

    #[test]
    fn file_list_is_sorted_and_unique() {
        let mut s = UBO_RESOURCE_FILES.to_vec();
        s.sort();
        s.dedup();
        assert_eq!(s, UBO_RESOURCE_FILES);
    }
}

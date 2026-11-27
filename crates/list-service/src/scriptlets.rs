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

/// `https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>` -> its four parts.
fn split_raw_github(url: &str) -> Option<(&str, &str, &str, &str)> {
    let rest = url.strip_prefix("https://raw.githubusercontent.com/")?;
    let mut p = rest.splitn(4, '/');
    Some((p.next()?, p.next()?, p.next()?, p.next()?))
}

/// Find `gitref` (`HEAD`, a branch or a tag) in a git ref advertisement (pkt-lines of
/// `<sha> <ref>[\0capabilities]`) and return its commit id (peeled for annotated tags).
fn parse_ref_advertisement(adv: &str, gitref: &str) -> Option<String> {
    let names = if gitref == "HEAD" {
        vec!["HEAD".to_string()]
    } else {
        vec![
            format!("refs/heads/{gitref}"),
            format!("refs/tags/{gitref}"),
        ]
    };
    let sha_of = |name: &str| -> Option<String> {
        let suffix = format!(" {name}");
        adv.split('\n').find_map(|line| {
            let line = line.split('\0').next().unwrap_or(line);
            let head = line.strip_suffix(&suffix)?;
            let sha = head.get(head.len().checked_sub(40)?..)?;
            is_commit_sha(sha).then(|| sha.to_string())
        })
    };
    names
        .iter()
        .find_map(|n| sha_of(&format!("{n}^{{}}")).or_else(|| sha_of(n)))
}

fn is_commit_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

const MAX_RATE_LIMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(3600);

impl ListService {
    /// Pin a raw GitHub base URL (branch or `HEAD`) to the commit it points at now, so the
    /// scriptlets, the redirect map and the redirect files all come from one commit. Other URLs
    /// (and ones already naming a commit) are returned unchanged.
    ///
    /// The commit is read from the git smart-HTTP ref advertisement, which unlike the REST API
    /// is not rate limited per IP (shared CI runners get 403 from the API); the API is only a
    /// fallback.
    #[doc(hidden)]
    pub async fn pin_commit(&self, url: &str) -> Result<String, String> {
        let Some((owner, repo, gitref, path)) = split_raw_github(url) else {
            return Ok(url.to_string());
        };
        if is_commit_sha(gitref) {
            return Ok(url.to_string());
        }
        let git = format!(
            "{}/{owner}/{repo}.git/info/refs?service=git-upload-pack",
            self.cfg.git_host_url.trim_end_matches('/')
        );
        let via_git = match self.get_text_capped(&git, 16 * 1024 * 1024).await {
            Ok(adv) => parse_ref_advertisement(&adv, gitref)
                .ok_or_else(|| format!("`{gitref}` not found in {owner}/{repo} refs")),
            Err(e) => Err(e),
        };
        let sha = match via_git {
            Ok(s) => s,
            Err(git_err) => {
                let api = format!("https://api.github.com/repos/{owner}/{repo}/commits/{gitref}");
                let s = self
                    .get_text_accept(&api, "application/vnd.github.sha")
                    .await
                    .map_err(|e| {
                        format!("cannot resolve `{gitref}` to a commit: {git_err}; {e}")
                    })?;
                s.trim().to_string()
            }
        };
        if !is_commit_sha(&sha) {
            return Err(format!("`{gitref}` resolved to an invalid commit id"));
        }
        info!("Resource source pinned to {owner}/{repo}@{}", &sha[..8]);
        Ok(format!(
            "https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}"
        ))
    }

    /// Load scriptlet resources, retrying with exponential backoff until they load (or forever
    /// failing quietly in the background). No-op if the URL is empty. A valid cached
    /// `<data_dir>/resources.json` short-circuits the network.
    pub async fn ensure_scriptlet_resources(self: &Arc<Self>) {
        if self.cfg.scriptlet_resources_url.trim().is_empty() {
            return;
        }
        // Bundled snapshot (if any) first, so scriptlets work before and without the network;
        // a cached or fetched copy then replaces it.
        self.load_bundled_resources().await;
        let mut delay = self.cfg.scriptlet_retry_initial;
        loop {
            match self.load_scriptlets_once().await {
                Ok(()) => {
                    self.scriptlets_tx.send_replace(true);
                    return;
                }
                Err(e) => {
                    // A rate-limited source says when to come back: honour it (bounded).
                    let hint = self.rate_limit_hint.lock().take();
                    let wait = hint
                        .map_or(delay, |h| h.max(delay))
                        .min(MAX_RATE_LIMIT_WAIT);
                    warn!("Scriptlet resources unavailable: {e}; retrying in {wait:?}");
                    tokio::time::sleep(wait).await;
                }
            }
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
            let json = filter_engine::merge_resources_json(
                filter_engine::BUNDLED_RESOURCES_JSON,
                filter_engine::BUNDLED_REDIRECTS_JSON,
            )?;
            engine.set_resources_from_json(&json).map(Some)
        })
        .await;
        match res {
            Ok(Ok(Some(n))) => info!(
                "Loaded {n} bundled scriptlet and redirect resources (uBlock Origin {})",
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
            // A cache written before redirect resources were fetched has none: fill the gap
            // from the bundled snapshot now and refresh from the source below.
            let has_redirects = json.contains("googlesyndication_adsbygoogle.js");
            let json =
                filter_engine::merge_resources_json(&json, filter_engine::BUNDLED_REDIRECTS_JSON)
                    .unwrap_or(json);
            match self.set_resources(json).await {
                Ok(n) => {
                    info!("Loaded {n} scriptlet resources from cache");
                    if has_redirects && self.engine.resource_report().dropped.is_empty() {
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
        // Gaps (a redirect fetch that failed, a custom `.json`) come from the bundled snapshot.
        let json =
            filter_engine::merge_resources_json(&json, filter_engine::BUNDLED_REDIRECTS_JSON)
                .unwrap_or(json);
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
        let url = self.pin_commit(&url).await?;
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
        // The `$redirect` resources live next to the scriptlets (`src/js/redirect-resources.js`
        // and `src/web_accessible_resources/`); only a raw-file base URL can address them.
        if !url.ends_with(".js") {
            if let Some(js_dir) = url.trim_end_matches('/').strip_suffix("/resources") {
                match self.fetch_redirects_json(js_dir).await {
                    Ok(redirects) => {
                        return filter_engine::merge_resources_json(&json, &redirects)
                            .map_err(|e| e.to_string())
                    }
                    Err(e) => warn!("Redirect resources not fetched ({e}); using the bundled set"),
                }
            }
        }
        Ok(json)
    }

    /// Fetch uBO's redirect map and every file it names, and convert them. `js_dir` is the raw
    /// URL of `src/js`.
    async fn fetch_redirects_json(&self, js_dir: &str) -> Result<String, String> {
        let map = self
            .get_text(format!("{js_dir}/redirect-resources.js"))
            .await?;
        let names = filter_engine::redirect_file_names(&map)?;
        let wa = js_dir
            .strip_suffix("/js")
            .map(|src| format!("{src}/web_accessible_resources"))
            .ok_or("unexpected resources URL layout")?;
        let fetches: Vec<_> = names
            .iter()
            .map(|n| self.get_bytes(format!("{wa}/{n}")))
            .collect();
        let mut files = std::collections::HashMap::new();
        for (name, res) in names
            .iter()
            .zip(futures_util::future::join_all(fetches).await)
        {
            // All or nothing: a half-fetched set must never replace a complete one.
            files.insert(name.clone(), res.map_err(|e| format!("{name}: {e}"))?);
        }
        let (json, dropped) = filter_engine::ubo_redirects_to_json(&map, &files)?;
        if let Some(d) = dropped.first() {
            return Err(format!(
                "redirect resource `{}` is invalid: {} ({} invalid in total)",
                d.name,
                d.reason,
                dropped.len()
            ));
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
    fn github_raw_urls_split_and_shas_are_recognised() {
        let u = "https://raw.githubusercontent.com/gorhill/uBlock/master/src/js/resources";
        assert_eq!(
            split_raw_github(u),
            Some(("gorhill", "uBlock", "master", "src/js/resources"))
        );
        assert_eq!(split_raw_github("http://127.0.0.1:1/res"), None);
        assert!(is_commit_sha("5934db2a0437a50182c4a8f3da2e0941cf806253"));
        assert!(!is_commit_sha("master") && !is_commit_sha("HEAD"));
    }

    #[test]
    fn file_list_is_sorted_and_unique() {
        let mut s = UBO_RESOURCE_FILES.to_vec();
        s.sort();
        s.dedup();
        assert_eq!(s, UBO_RESOURCE_FILES);
    }
}

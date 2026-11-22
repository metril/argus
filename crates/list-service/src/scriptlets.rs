//! Scriptlet resource library loading (uBO-compatible), with background retry and backoff.

use std::sync::Arc;

use tracing::{info, warn};

use crate::service::{read_capped, ListService};

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

    async fn load_scriptlets_once(&self) -> Result<(), String> {
        let cache = self.cfg.data_dir.join("resources.json");
        if let Ok(json) = tokio::fs::read_to_string(&cache).await {
            match self.engine.set_resources_from_json(&json) {
                Ok(n) => {
                    info!("Loaded {n} scriptlet resources from cache");
                    return Ok(());
                }
                Err(e) => warn!("Cached resources.json invalid ({e}); re-fetching"),
            }
        }
        let json = self
            .fetch_resources_json(&self.cfg.scriptlet_resources_url)
            .await?;
        let n = self
            .engine
            .set_resources_from_json(&json)
            .map_err(|e| format!("resources invalid after conversion: {e}"))?;
        info!("Loaded {n} scriptlet resources");
        let _ = tokio::fs::create_dir_all(&self.cfg.data_dir).await;
        if let Err(e) = tokio::fs::write(&cache, &json).await {
            warn!("Failed to cache resources.json: {e}");
        }
        Ok(())
    }

    async fn get_text(&self, url: &str) -> Result<String, String> {
        let resp = self
            .client
            .get(url)
            .timeout(self.cfg.fetch_timeout)
            .send()
            .await
            .map_err(|e| format!("{url}: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("{url}: HTTP {}", resp.status()));
        }
        let body = read_capped(resp, self.cfg.max_list_bytes).await?;
        Ok(String::from_utf8_lossy(&body).into_owned())
    }

    /// Fetch `url` and return an adblock-rust resources JSON array. `url` may be a GitHub contents
    /// API directory of uBO's `src/js/resources/` (every `.js` is concatenated and converted), a
    /// single uBO `.js` file (converted), or a ready `.json` array (used as is).
    async fn fetch_resources_json(&self, url: &str) -> Result<String, String> {
        if url.contains("api.github.com") && url.contains("/contents/") {
            let entries: serde_json::Value = serde_json::from_str(&self.get_text(url).await?)
                .map_err(|e| format!("bad directory listing: {e}"))?;
            let mut combined = String::new();
            for entry in entries.as_array().into_iter().flatten() {
                let name = entry["name"].as_str().unwrap_or("");
                let dl = entry["download_url"].as_str().unwrap_or("");
                if !name.ends_with(".js") || dl.is_empty() {
                    continue;
                }
                combined.push('\n');
                combined.push_str(&self.get_text(dl).await?);
            }
            if combined.trim().is_empty() {
                return Err("no scriptlet files found".into());
            }
            filter_engine::ubo_scriptlets_to_json(&combined).map_err(|e| e.to_string())
        } else {
            let body = self.get_text(url).await?;
            if url.ends_with(".json") {
                Ok(body)
            } else {
                filter_engine::ubo_scriptlets_to_json(&body).map_err(|e| e.to_string())
            }
        }
    }
}

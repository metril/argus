//! Main filter engine implementation

use crate::{
    cosmetic::CosmeticFilterManager,
    list::FilterListManager,
    matcher::{MatchResult, RequestMatcher},
    scriptlets::ScriptletManager,
    stats::FilterStats,
    update::{UpdateConfig, UpdateScheduler, UpdateStats},
    Error, Result,
};
use adblock::lists::FilterSet;
use adblock::Engine as AdblockEngine;
use arc_swap::ArcSwap;
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Main filter engine that coordinates all filtering operations
#[derive(Clone)]
pub struct FilterEngine {
    /// The underlying adblock-rust engine
    engine: Arc<ArcSwap<AdblockEngine>>,
    /// Filter list manager
    list_manager: Arc<FilterListManager>,
    /// Cosmetic filtering manager
    cosmetic_manager: Arc<RwLock<CosmeticFilterManager>>,
    /// Scriptlet injection manager
    scriptlet_manager: Arc<RwLock<ScriptletManager>>,
    /// Statistics tracker
    stats: FilterStats,
    /// Whether the engine is enabled
    enabled: Arc<RwLock<bool>>,
    /// Auto-update scheduler (optional)
    update_scheduler: Arc<RwLock<Option<UpdateScheduler>>>,
}

impl FilterEngine {
    /// Create a new filter engine
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        info!("Initializing filter engine with data dir: {:?}", data_dir);

        // Create data directory if it doesn't exist
        std::fs::create_dir_all(&data_dir)?;

        let list_manager = Arc::new(FilterListManager::new(data_dir));

        // Load default filter lists
        list_manager.load_defaults();

        // Create empty engine initially
        let engine = AdblockEngine::default();

        Ok(Self {
            engine: Arc::new(ArcSwap::new(Arc::new(engine))),
            list_manager,
            cosmetic_manager: Arc::new(RwLock::new(CosmeticFilterManager::new())),
            scriptlet_manager: Arc::new(RwLock::new(ScriptletManager::new())),
            stats: FilterStats::new(),
            enabled: Arc::new(RwLock::new(true)),
            update_scheduler: Arc::new(RwLock::new(None)),
        })
    }

    /// Check if a network request should be blocked
    pub fn check_request(
        &self,
        url: &str,
        source_url: &str,
        resource_type: &str,
    ) -> Result<MatchResult> {
        // Check if engine is enabled
        if !*self.enabled.read() {
            self.stats.record_allowed();
            return Ok(MatchResult::allowed());
        }

        // Get current engine
        let engine = self.engine.load();

        // Check request
        let result = RequestMatcher::check_request(&engine, url, source_url, resource_type)?;

        // Record statistics
        if result.blocked {
            let domain = RequestMatcher::extract_domain(url).unwrap_or_else(|_| "unknown".to_string());
            self.stats.record_blocked(resource_type, &domain);
        } else {
            self.stats.record_allowed();
        }

        Ok(result)
    }

    /// Load filter rules from filter lists
    pub async fn load_filters(&self) -> Result<()> {
        info!("Loading filter lists");

        // Download all enabled filter lists
        let lists = self.list_manager.download_all().await?;

        if lists.is_empty() {
            warn!("No filter lists downloaded");
            return Ok(());
        }

        // Combine all rules into a single FilterSet
        let mut filter_set = FilterSet::new(false); // false = not debug mode

        // Create new cosmetic filter manager
        let mut cosmetic_manager = CosmeticFilterManager::new();

        // Create new scriptlet manager
        let mut scriptlet_manager = ScriptletManager::new();

        for (list_id, content) in lists {
            debug!("Processing filter list: {}", list_id);

            // Parse filter rules line by line
            for line in content.lines() {
                let line = line.trim();

                // Skip empty lines and comments
                if line.is_empty() || line.starts_with('!') {
                    continue;
                }

                // Check if this is a scriptlet injection rule
                if line.contains("#%#") || line.contains("#@%#") {
                    // Try to parse as scriptlet rule
                    if let Err(e) = scriptlet_manager.add_rule_from_string(line) {
                        debug!("Failed to parse scriptlet rule '{}': {}", line, e);
                    }
                }
                // Check if this is a cosmetic filtering rule
                else if line.contains("##") || line.contains("#@#") || line.contains("#?#")
                    || line.contains("#@?#") || line.contains("#$#") || line.contains("#@$#") {
                    // Try to parse as cosmetic rule
                    if let Err(e) = cosmetic_manager.add_rule_from_string(line) {
                        debug!("Failed to parse cosmetic rule '{}': {}", line, e);
                    }
                } else {
                    // Network blocking rule - add to filter set
                    filter_set.add_filter(line).ok(); // Ignore parse errors for individual rules
                }
            }
        }

        // Create new engine from filter set
        let new_engine = AdblockEngine::from_filter_set(filter_set, true); // true = optimize

        // Atomically swap the engine
        self.engine.store(Arc::new(new_engine));

        // Update cosmetic manager
        *self.cosmetic_manager.write() = cosmetic_manager;

        // Update scriptlet manager
        *self.scriptlet_manager.write() = scriptlet_manager;

        info!("Filter engine loaded successfully");
        Ok(())
    }

    /// Reload filters (download and reload)
    pub async fn reload_filters(&self) -> Result<()> {
        info!("Reloading filter lists");
        self.load_filters().await
    }

    /// Enable or disable the filter engine
    pub fn set_enabled(&self, enabled: bool) {
        *self.enabled.write() = enabled;
        info!("Filter engine {}", if enabled { "enabled" } else { "disabled" });
    }

    /// Check if the engine is enabled
    pub fn is_enabled(&self) -> bool {
        *self.enabled.read()
    }

    /// Get statistics snapshot
    pub fn stats(&self) -> crate::stats::BlockingStats {
        self.stats.snapshot()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        self.stats.reset();
    }

    /// Get filter list manager
    pub fn list_manager(&self) -> &FilterListManager {
        &self.list_manager
    }

    /// Get cosmetic hiding CSS for a domain
    pub fn get_cosmetic_hiding_css(&self, domain: &str) -> String {
        if !*self.enabled.read() {
            return String::new();
        }

        let manager = self.cosmetic_manager.read();
        manager.get_hiding_css(domain)
    }

    /// Get cosmetic injection CSS for a domain
    pub fn get_cosmetic_injection_css(&self, domain: &str) -> String {
        if !*self.enabled.read() {
            return String::new();
        }

        let manager = self.cosmetic_manager.read();
        manager.get_injection_css(domain)
    }

    /// Get combined cosmetic CSS (hiding + injection) for a domain
    pub fn get_cosmetic_css(&self, domain: &str) -> String {
        if !*self.enabled.read() {
            return String::new();
        }

        let hiding = self.get_cosmetic_hiding_css(domain);
        let injection = self.get_cosmetic_injection_css(domain);

        if hiding.is_empty() && injection.is_empty() {
            return String::new();
        }

        format!("{}\n{}", hiding, injection).trim().to_string()
    }

    /// Get scriptlet JavaScript code for a domain
    pub fn get_scriptlet_code(&self, domain: &str) -> String {
        if !*self.enabled.read() {
            return String::new();
        }

        let manager = self.scriptlet_manager.read();
        manager.get_scriptlet_code(domain)
    }

    /// Enable auto-update with specified configuration
    pub fn enable_auto_update(&self, config: UpdateConfig) {
        let scheduler = UpdateScheduler::new(self.clone(), config);
        *self.update_scheduler.write() = Some(scheduler);
        info!("Auto-update enabled");
    }

    /// Start auto-update scheduler
    pub async fn start_auto_update(&self) {
        if let Some(scheduler) = self.update_scheduler.read().as_ref() {
            scheduler.start().await;
        } else {
            warn!("Auto-update not enabled, call enable_auto_update() first");
        }
    }

    /// Stop auto-update scheduler
    pub fn stop_auto_update(&self) {
        if let Some(scheduler) = self.update_scheduler.read().as_ref() {
            scheduler.stop();
        }
    }

    /// Trigger an immediate manual update
    pub async fn trigger_update(&self) -> Result<(usize, usize)> {
        if let Some(scheduler) = self.update_scheduler.read().as_ref() {
            scheduler.trigger_update().await
        } else {
            Err(Error::UpdateFailed(
                "Auto-update not enabled".to_string(),
            ))
        }
    }

    /// Get auto-update statistics
    pub fn update_stats(&self) -> Option<&UpdateStats> {
        self.update_scheduler
            .read()
            .as_ref()
            .map(|s| s.stats())
    }

    /// Check if auto-update is running
    pub fn is_auto_update_running(&self) -> bool {
        self.update_scheduler
            .read()
            .as_ref()
            .map(|s| s.is_running())
            .unwrap_or(false)
    }

    /// Update auto-update configuration
    pub fn set_update_config(&self, config: UpdateConfig) {
        if let Some(scheduler) = self.update_scheduler.read().as_ref() {
            scheduler.set_config(config);
        }
    }

    /// Get current auto-update configuration
    pub fn get_update_config(&self) -> Option<UpdateConfig> {
        self.update_scheduler
            .read()
            .as_ref()
            .map(|s| s.get_config())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_engine_creation() {
        let temp_dir = std::env::temp_dir().join("filter-engine-test");
        let engine = FilterEngine::new(temp_dir).unwrap();

        assert!(engine.is_enabled());
    }

    #[tokio::test]
    async fn test_engine_enable_disable() {
        let temp_dir = std::env::temp_dir().join("filter-engine-test-2");
        let engine = FilterEngine::new(temp_dir).unwrap();

        engine.set_enabled(false);
        assert!(!engine.is_enabled());

        engine.set_enabled(true);
        assert!(engine.is_enabled());
    }

    #[tokio::test]
    async fn test_request_checking_when_disabled() {
        let temp_dir = std::env::temp_dir().join("filter-engine-test-3");
        let engine = FilterEngine::new(temp_dir).unwrap();

        engine.set_enabled(false);

        let result = engine.check_request(
            "https://ads.example.com/banner.jpg",
            "https://example.com",
            "image",
        ).unwrap();

        assert!(!result.blocked);
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let temp_dir = std::env::temp_dir().join("filter-engine-test-4");
        let engine = FilterEngine::new(temp_dir).unwrap();

        // Manually record some stats
        engine.stats.record_blocked("script", "ads.example.com");
        engine.stats.record_allowed();

        let stats = engine.stats();
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.blocked_requests, 1);
        assert_eq!(stats.allowed_requests, 1);

        engine.reset_stats();
        let stats_after_reset = engine.stats();
        assert_eq!(stats_after_reset.total_requests, 0);
    }
}

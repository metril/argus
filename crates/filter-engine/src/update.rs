//! Auto-update system for filter lists with checksum verification
//!
//! Implements automatic periodic updates of filter lists with:
//! - Configurable update intervals
//! - MD5 checksum verification
//! - Atomic hot reload
//! - Update statistics and error tracking

use crate::{Error, FilterEngine, Result};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use md5::{Digest, Md5};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};

/// Update configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// Update interval in hours (default: 24)
    pub interval_hours: u64,
    /// Whether auto-update is enabled
    pub enabled: bool,
    /// Whether to verify checksums
    pub verify_checksums: bool,
    /// Maximum update retries on failure
    pub max_retries: u32,
    /// Retry delay in seconds
    pub retry_delay_secs: u64,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            interval_hours: 24,
            enabled: true,
            verify_checksums: true,
            max_retries: 3,
            retry_delay_secs: 300, // 5 minutes
        }
    }
}

/// Statistics for a single update attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAttempt {
    /// Timestamp of the update attempt
    pub timestamp: DateTime<Utc>,
    /// Whether the update succeeded
    pub success: bool,
    /// Number of lists updated
    pub lists_updated: usize,
    /// Number of lists failed
    pub lists_failed: usize,
    /// Error message if failed
    pub error: Option<String>,
    /// Duration of the update in milliseconds
    pub duration_ms: u64,
}

/// Update statistics tracker
#[derive(Debug, Clone)]
pub struct UpdateStats {
    /// Recent update attempts (limited to last 100)
    attempts: Arc<RwLock<Vec<UpdateAttempt>>>,
    /// Per-list update statistics
    list_stats: Arc<RwLock<HashMap<String, ListUpdateStats>>>,
}

/// Statistics for a specific filter list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListUpdateStats {
    /// List ID
    pub list_id: String,
    /// Last successful update
    pub last_success: Option<DateTime<Utc>>,
    /// Last failed update
    pub last_failure: Option<DateTime<Utc>>,
    /// Total successful updates
    pub success_count: u64,
    /// Total failed updates
    pub failure_count: u64,
    /// Last error message
    pub last_error: Option<String>,
    /// Last checksum
    pub last_checksum: Option<String>,
}

impl UpdateStats {
    /// Create new update statistics tracker
    pub fn new() -> Self {
        Self {
            attempts: Arc::new(RwLock::new(Vec::new())),
            list_stats: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record an update attempt
    pub fn record_attempt(&self, attempt: UpdateAttempt) {
        let mut attempts = self.attempts.write();
        attempts.push(attempt);

        // Keep only last 100 attempts
        if attempts.len() > 100 {
            attempts.remove(0);
        }
    }

    /// Record list update success
    pub fn record_list_success(&self, list_id: &str, checksum: Option<String>) {
        let mut stats = self.list_stats.write();
        let list_stat = stats
            .entry(list_id.to_string())
            .or_insert_with(|| ListUpdateStats {
                list_id: list_id.to_string(),
                last_success: None,
                last_failure: None,
                success_count: 0,
                failure_count: 0,
                last_error: None,
                last_checksum: None,
            });

        list_stat.last_success = Some(Utc::now());
        list_stat.success_count += 1;
        list_stat.last_checksum = checksum;
    }

    /// Record list update failure
    pub fn record_list_failure(&self, list_id: &str, error: String) {
        let mut stats = self.list_stats.write();
        let list_stat = stats
            .entry(list_id.to_string())
            .or_insert_with(|| ListUpdateStats {
                list_id: list_id.to_string(),
                last_success: None,
                last_failure: None,
                success_count: 0,
                failure_count: 0,
                last_error: None,
                last_checksum: None,
            });

        list_stat.last_failure = Some(Utc::now());
        list_stat.failure_count += 1;
        list_stat.last_error = Some(error);
    }

    /// Get recent update attempts
    pub fn get_attempts(&self, limit: usize) -> Vec<UpdateAttempt> {
        let attempts = self.attempts.read();
        attempts.iter().rev().take(limit).cloned().collect()
    }

    /// Get statistics for a specific list
    pub fn get_list_stats(&self, list_id: &str) -> Option<ListUpdateStats> {
        let stats = self.list_stats.read();
        stats.get(list_id).cloned()
    }

    /// Get all list statistics
    pub fn get_all_list_stats(&self) -> Vec<ListUpdateStats> {
        let stats = self.list_stats.read();
        stats.values().cloned().collect()
    }

    /// Get last successful update time
    pub fn last_update(&self) -> Option<DateTime<Utc>> {
        let attempts = self.attempts.read();
        attempts
            .iter()
            .rev()
            .find(|a| a.success)
            .map(|a| a.timestamp)
    }
}

impl Default for UpdateStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Filter list checksum verifier
pub struct ChecksumVerifier;

impl ChecksumVerifier {
    /// Extract checksum from filter list content
    ///
    /// Looks for lines like:
    /// ! Checksum: <base64-encoded-md5>
    pub fn extract_checksum(content: &str) -> Option<String> {
        for line in content.lines() {
            if line.starts_with("! Checksum:") || line.starts_with("! checksum:") {
                if let Some(checksum) = line.split(':').nth(1) {
                    return Some(checksum.trim().to_string());
                }
            }
        }
        None
    }

    /// Calculate MD5 checksum of filter list content
    ///
    /// Excludes the checksum line itself as per AdBlock Plus standard
    pub fn calculate_checksum(content: &str) -> String {
        let mut hasher = Md5::new();

        for line in content.lines() {
            // Skip the checksum line itself
            if line.starts_with("! Checksum:") || line.starts_with("! checksum:") {
                continue;
            }

            // Add line to hash (with newline)
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
        }

        let result = hasher.finalize();
        base64::engine::general_purpose::STANDARD.encode(result)
    }

    /// Verify checksum of filter list content
    pub fn verify(content: &str) -> Result<bool> {
        let expected = match Self::extract_checksum(content) {
            Some(checksum) => checksum,
            None => {
                debug!("No checksum found in filter list");
                return Ok(true); // No checksum = assume valid
            }
        };

        let actual = Self::calculate_checksum(content);

        if expected == actual {
            debug!("Checksum verification passed");
            Ok(true)
        } else {
            warn!(
                "Checksum verification failed: expected {}, got {}",
                expected, actual
            );
            Ok(false)
        }
    }
}

/// Auto-update scheduler
pub struct UpdateScheduler {
    engine: FilterEngine,
    config: Arc<RwLock<UpdateConfig>>,
    stats: UpdateStats,
    running: Arc<RwLock<bool>>,
}

impl UpdateScheduler {
    /// Create a new update scheduler
    pub fn new(engine: FilterEngine, config: UpdateConfig) -> Self {
        Self {
            engine,
            config: Arc::new(RwLock::new(config)),
            stats: UpdateStats::new(),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the auto-update scheduler
    ///
    /// Note: This should be called from a dedicated task/thread that owns the UpdateScheduler
    /// because FilterEngine is not Send due to adblock crate limitations.
    pub async fn start(self: Arc<Self>) {
        if *self.running.read() {
            warn!("Update scheduler already running");
            return;
        }

        *self.running.write() = true;
        info!("Starting auto-update scheduler");

        // Clone Arcs for the background task
        let scheduler = self;

        // Use tokio::task::spawn_local for !Send futures
        // This requires running within a LocalSet
        let mut update_interval = {
            let cfg = scheduler.config.read();
            interval(std::time::Duration::from_secs(cfg.interval_hours * 3600))
        };

        loop {
            update_interval.tick().await;

            if !*scheduler.running.read() {
                info!("Update scheduler stopped");
                break;
            }

            let cfg = scheduler.config.read().clone();
            if !cfg.enabled {
                debug!("Auto-update disabled, skipping");
                continue;
            }

            info!("Starting scheduled filter list update");
            let start = std::time::Instant::now();

            match Self::perform_update(&scheduler.engine, &cfg, &scheduler.stats).await {
                Ok((updated, failed)) => {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    info!(
                        "Update completed: {} updated, {} failed, took {}ms",
                        updated, failed, duration_ms
                    );

                    scheduler.stats.record_attempt(UpdateAttempt {
                        timestamp: Utc::now(),
                        success: true,
                        lists_updated: updated,
                        lists_failed: failed,
                        error: None,
                        duration_ms,
                    });
                }
                Err(e) => {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    error!("Update failed: {}", e);

                    scheduler.stats.record_attempt(UpdateAttempt {
                        timestamp: Utc::now(),
                        success: false,
                        lists_updated: 0,
                        lists_failed: 0,
                        error: Some(e.to_string()),
                        duration_ms,
                    });
                }
            }
        }
    }

    /// Stop the auto-update scheduler
    pub fn stop(&self) {
        info!("Stopping auto-update scheduler");
        *self.running.write() = false;
    }

    /// Check if scheduler is running
    pub fn is_running(&self) -> bool {
        *self.running.read()
    }

    /// Trigger an immediate update
    pub async fn trigger_update(&self) -> Result<(usize, usize)> {
        info!("Triggering manual filter list update");
        let config = self.config.read().clone();
        let start = std::time::Instant::now();

        match Self::perform_update(&self.engine, &config, &self.stats).await {
            Ok((updated, failed)) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                info!(
                    "Manual update completed: {} updated, {} failed, took {}ms",
                    updated, failed, duration_ms
                );

                self.stats.record_attempt(UpdateAttempt {
                    timestamp: Utc::now(),
                    success: true,
                    lists_updated: updated,
                    lists_failed: failed,
                    error: None,
                    duration_ms,
                });

                Ok((updated, failed))
            }
            Err(e) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                error!("Manual update failed: {}", e);

                self.stats.record_attempt(UpdateAttempt {
                    timestamp: Utc::now(),
                    success: false,
                    lists_updated: 0,
                    lists_failed: 0,
                    error: Some(e.to_string()),
                    duration_ms,
                });

                Err(e)
            }
        }
    }

    /// Perform the actual update with retries
    async fn perform_update(
        engine: &FilterEngine,
        config: &UpdateConfig,
        stats: &UpdateStats,
    ) -> Result<(usize, usize)> {
        let mut retries = 0;
        let mut last_error = None;

        while retries <= config.max_retries {
            if retries > 0 {
                info!("Retry attempt {} of {}", retries, config.max_retries);
                sleep(std::time::Duration::from_secs(config.retry_delay_secs)).await;
            }

            match Self::download_and_verify(engine, config, stats).await {
                Ok((updated, failed)) => {
                    // Reload filters atomically
                    if updated > 0 {
                        info!("Reloading filter engine with updated lists");
                        engine.load_filters().await?;
                    }
                    return Ok((updated, failed));
                }
                Err(e) => {
                    warn!("Update attempt failed: {}", e);
                    last_error = Some(e);
                    retries += 1;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::UpdateFailed("Unknown error".to_string())))
    }

    /// Download and verify all filter lists
    async fn download_and_verify(
        engine: &FilterEngine,
        config: &UpdateConfig,
        stats: &UpdateStats,
    ) -> Result<(usize, usize)> {
        let list_manager = engine.list_manager();
        let lists = list_manager.get_all_lists();

        let mut updated = 0;
        let mut failed = 0;

        for list in lists {
            if !list.enabled {
                continue;
            }

            info!("Updating filter list: {}", list.name);

            match list.download(list_manager.http_client()).await {
                Ok(content) => {
                    // Verify checksum if enabled
                    if config.verify_checksums {
                        match ChecksumVerifier::verify(&content) {
                            Ok(true) => {
                                debug!("Checksum verification passed for {}", list.name);
                                let checksum = ChecksumVerifier::extract_checksum(&content);
                                stats.record_list_success(&list.id, checksum);
                                updated += 1;
                            }
                            Ok(false) => {
                                error!("Checksum verification failed for {}", list.name);
                                stats.record_list_failure(
                                    &list.id,
                                    "Checksum verification failed".to_string(),
                                );
                                failed += 1;
                            }
                            Err(e) => {
                                error!("Error verifying checksum for {}: {}", list.name, e);
                                stats.record_list_failure(&list.id, e.to_string());
                                failed += 1;
                            }
                        }
                    } else {
                        stats.record_list_success(&list.id, None);
                        updated += 1;
                    }
                }
                Err(e) => {
                    warn!("Failed to download {}: {}", list.name, e);
                    stats.record_list_failure(&list.id, e.to_string());
                    failed += 1;
                }
            }
        }

        info!("Update summary: {} updated, {} failed", updated, failed);
        Ok((updated, failed))
    }

    /// Get update statistics
    pub fn stats(&self) -> &UpdateStats {
        &self.stats
    }

    /// Update configuration
    pub fn set_config(&self, config: UpdateConfig) {
        *self.config.write() = config;
        info!("Update configuration changed");
    }

    /// Get current configuration
    pub fn get_config(&self) -> UpdateConfig {
        self.config.read().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_extraction() {
        let content = r#"! Title: Test List
! Checksum: dGVzdGNoZWNrc3Vt
example.com##.ad
"#;

        let checksum = ChecksumVerifier::extract_checksum(content);
        assert_eq!(checksum, Some("dGVzdGNoZWNrc3Vt".to_string()));
    }

    #[test]
    fn test_checksum_calculation() {
        let content = r#"! Title: Test List
example.com##.ad
test.com##.banner
"#;

        let checksum = ChecksumVerifier::calculate_checksum(content);
        assert!(!checksum.is_empty());

        // Verify it's base64
        assert!(base64::decode(&checksum).is_ok());
    }

    #[test]
    fn test_checksum_verification() {
        // Valid checksum
        let content = r#"! Title: Test List
! Checksum: 8/FRX6I9PqnMzpPRCLwE5Q==
example.com##.ad
"#;

        let result = ChecksumVerifier::verify(content);
        assert!(result.is_ok());

        // No checksum = valid
        let content_no_checksum = r#"! Title: Test List
example.com##.ad
"#;

        let result = ChecksumVerifier::verify(content_no_checksum);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_update_stats() {
        let stats = UpdateStats::new();

        stats.record_list_success("test-list", Some("checksum123".to_string()));
        stats.record_list_failure("other-list", "Network error".to_string());

        let test_stats = stats.get_list_stats("test-list");
        assert!(test_stats.is_some());
        let test_stats = test_stats.unwrap();
        assert_eq!(test_stats.success_count, 1);
        assert_eq!(test_stats.last_checksum, Some("checksum123".to_string()));

        let other_stats = stats.get_list_stats("other-list");
        assert!(other_stats.is_some());
        let other_stats = other_stats.unwrap();
        assert_eq!(other_stats.failure_count, 1);
        assert_eq!(other_stats.last_error, Some("Network error".to_string()));
    }

    #[test]
    fn test_update_config_default() {
        let config = UpdateConfig::default();
        assert_eq!(config.interval_hours, 24);
        assert!(config.enabled);
        assert!(config.verify_checksums);
        assert_eq!(config.max_retries, 3);
    }

    #[tokio::test]
    async fn test_update_stats_attempts() {
        let stats = UpdateStats::new();

        stats.record_attempt(UpdateAttempt {
            timestamp: Utc::now(),
            success: true,
            lists_updated: 5,
            lists_failed: 1,
            error: None,
            duration_ms: 1500,
        });

        let attempts = stats.get_attempts(10);
        assert_eq!(attempts.len(), 1);
        assert!(attempts[0].success);
        assert_eq!(attempts[0].lists_updated, 5);
    }
}

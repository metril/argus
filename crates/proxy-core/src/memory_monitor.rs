//! Memory pressure monitoring and load shedding
//!
//! Monitors process memory usage and triggers load shedding actions
//! when memory pressure exceeds configurable thresholds.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Memory pressure configuration
#[derive(Debug, Clone)]
pub struct MemoryMonitorConfig {
    /// Warning threshold in bytes (default: 2.0 GB)
    pub warning_threshold: u64,
    /// Critical threshold in bytes (default: 2.5 GB)
    pub critical_threshold: u64,
    /// How often to check memory usage
    pub check_interval: Duration,
    /// How long to wait after load shedding before resuming normal operation
    pub recovery_cooldown: Duration,
}

impl Default for MemoryMonitorConfig {
    fn default() -> Self {
        Self {
            warning_threshold: 2 * 1024 * 1024 * 1024, // 2.0 GB
            critical_threshold: 2560 * 1024 * 1024,    // 2.5 GB
            check_interval: Duration::from_secs(5),
            recovery_cooldown: Duration::from_secs(30),
        }
    }
}

/// Memory pressure level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPressure {
    /// Normal operation - under warning threshold
    Normal,
    /// Warning level - approaching limits, disable non-essential features
    Warning,
    /// Critical level - at risk of OOM, reject new connections
    Critical,
}

/// Load shedding action based on memory pressure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadSheddingAction {
    /// No action needed
    None,
    /// Disable userscripts to free memory
    DisableUserscripts,
    /// Reject new connections
    RejectConnections,
}

/// Memory usage snapshot
#[derive(Debug, Clone)]
pub struct MemoryStats {
    /// Resident set size (physical memory)
    pub rss_bytes: u64,
    /// Virtual memory size
    pub virtual_bytes: u64,
    /// Current pressure level
    pub pressure: MemoryPressure,
    /// Timestamp of this measurement
    pub timestamp: Instant,
}

/// Memory pressure monitor
pub struct MemoryMonitor {
    config: MemoryMonitorConfig,
    /// Current pressure level
    pressure: AtomicU64,
    /// Whether load shedding is active
    load_shedding_active: AtomicBool,
    /// When load shedding was last activated
    last_shed_time: parking_lot::Mutex<Option<Instant>>,
    /// Statistics
    stats: MemoryMonitorStats,
}

/// Memory monitor statistics
pub struct MemoryMonitorStats {
    /// Peak RSS observed
    pub peak_rss: AtomicU64,
    /// Number of times warning threshold was crossed
    pub warning_count: AtomicU64,
    /// Number of times critical threshold was crossed
    pub critical_count: AtomicU64,
    /// Number of connections rejected due to load shedding
    pub connections_rejected: AtomicU64,
}

impl Default for MemoryMonitorStats {
    fn default() -> Self {
        Self {
            peak_rss: AtomicU64::new(0),
            warning_count: AtomicU64::new(0),
            critical_count: AtomicU64::new(0),
            connections_rejected: AtomicU64::new(0),
        }
    }
}

impl MemoryMonitor {
    /// Create a new memory monitor with the given configuration
    pub fn new(config: MemoryMonitorConfig) -> Self {
        Self {
            config,
            pressure: AtomicU64::new(MemoryPressure::Normal as u64),
            load_shedding_active: AtomicBool::new(false),
            last_shed_time: parking_lot::Mutex::new(None),
            stats: MemoryMonitorStats::default(),
        }
    }

    /// Create a memory monitor with default configuration
    pub fn with_defaults() -> Self {
        Self::new(MemoryMonitorConfig::default())
    }

    /// Get current memory usage from the OS
    pub fn get_memory_usage(&self) -> MemoryStats {
        let (rss_bytes, virtual_bytes) = get_process_memory();

        // Update peak
        let mut peak = self.stats.peak_rss.load(Ordering::Relaxed);
        while rss_bytes > peak {
            match self.stats.peak_rss.compare_exchange_weak(
                peak,
                rss_bytes,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }

        // Determine pressure level
        let pressure = if rss_bytes >= self.config.critical_threshold {
            MemoryPressure::Critical
        } else if rss_bytes >= self.config.warning_threshold {
            MemoryPressure::Warning
        } else {
            MemoryPressure::Normal
        };

        MemoryStats {
            rss_bytes,
            virtual_bytes,
            pressure,
            timestamp: Instant::now(),
        }
    }

    /// Check memory pressure and determine what action to take
    pub fn should_shed_load(&self) -> LoadSheddingAction {
        let stats = self.get_memory_usage();
        let old_pressure = MemoryPressure::from_u64(self.pressure.load(Ordering::Relaxed));

        // Update pressure level
        self.pressure
            .store(stats.pressure as u64, Ordering::Relaxed);

        // Track pressure level transitions
        if stats.pressure != old_pressure {
            match stats.pressure {
                MemoryPressure::Warning => {
                    warn!(
                        "Memory pressure WARNING: {} MB RSS (threshold: {} MB)",
                        stats.rss_bytes / 1024 / 1024,
                        self.config.warning_threshold / 1024 / 1024
                    );
                    self.stats.warning_count.fetch_add(1, Ordering::Relaxed);
                }
                MemoryPressure::Critical => {
                    warn!(
                        "Memory pressure CRITICAL: {} MB RSS (threshold: {} MB)",
                        stats.rss_bytes / 1024 / 1024,
                        self.config.critical_threshold / 1024 / 1024
                    );
                    self.stats.critical_count.fetch_add(1, Ordering::Relaxed);
                    self.load_shedding_active.store(true, Ordering::Relaxed);
                    *self.last_shed_time.lock() = Some(Instant::now());
                }
                MemoryPressure::Normal => {
                    // Check if we should exit load shedding
                    if let Some(last_shed) = *self.last_shed_time.lock() {
                        if last_shed.elapsed() >= self.config.recovery_cooldown {
                            self.load_shedding_active.store(false, Ordering::Relaxed);
                            info!("Memory pressure returned to normal, exiting load shedding");
                        }
                    }
                }
            }
        }

        match stats.pressure {
            MemoryPressure::Critical => LoadSheddingAction::RejectConnections,
            MemoryPressure::Warning => LoadSheddingAction::DisableUserscripts,
            MemoryPressure::Normal => LoadSheddingAction::None,
        }
    }

    /// Check if a new connection should be accepted
    pub fn should_accept_connection(&self) -> bool {
        let action = self.should_shed_load();
        if action == LoadSheddingAction::RejectConnections {
            self.stats
                .connections_rejected
                .fetch_add(1, Ordering::Relaxed);
            false
        } else {
            true
        }
    }

    /// Check if userscripts should be executed
    pub fn should_execute_userscripts(&self) -> bool {
        let pressure = MemoryPressure::from_u64(self.pressure.load(Ordering::Relaxed));
        pressure == MemoryPressure::Normal
    }

    /// Get current pressure level
    pub fn current_pressure(&self) -> MemoryPressure {
        MemoryPressure::from_u64(self.pressure.load(Ordering::Relaxed))
    }

    /// Check if load shedding is currently active
    pub fn is_load_shedding_active(&self) -> bool {
        self.load_shedding_active.load(Ordering::Relaxed)
    }

    /// Get statistics snapshot
    pub fn stats_snapshot(&self) -> MemoryMonitorStatsSnapshot {
        let stats = self.get_memory_usage();
        MemoryMonitorStatsSnapshot {
            current_rss: stats.rss_bytes,
            current_virtual: stats.virtual_bytes,
            peak_rss: self.stats.peak_rss.load(Ordering::Relaxed),
            current_pressure: stats.pressure,
            warning_count: self.stats.warning_count.load(Ordering::Relaxed),
            critical_count: self.stats.critical_count.load(Ordering::Relaxed),
            connections_rejected: self.stats.connections_rejected.load(Ordering::Relaxed),
            load_shedding_active: self.load_shedding_active.load(Ordering::Relaxed),
        }
    }

    /// Start a background task that periodically checks memory pressure
    pub fn start_monitoring(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = self.config.check_interval;
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;
                let _ = self.should_shed_load();
                debug!(
                    "Memory check: {} MB RSS, pressure: {:?}",
                    self.get_memory_usage().rss_bytes / 1024 / 1024,
                    self.current_pressure()
                );
            }
        })
    }
}

impl MemoryPressure {
    fn from_u64(value: u64) -> Self {
        match value {
            0 => MemoryPressure::Normal,
            1 => MemoryPressure::Warning,
            2 => MemoryPressure::Critical,
            _ => MemoryPressure::Normal,
        }
    }
}

/// Memory monitor statistics snapshot
#[derive(Debug, Clone)]
pub struct MemoryMonitorStatsSnapshot {
    pub current_rss: u64,
    pub current_virtual: u64,
    pub peak_rss: u64,
    pub current_pressure: MemoryPressure,
    pub warning_count: u64,
    pub critical_count: u64,
    pub connections_rejected: u64,
    pub load_shedding_active: bool,
}

/// Get process memory usage (RSS and virtual)
#[cfg(target_os = "linux")]
fn get_process_memory() -> (u64, u64) {
    use std::fs;

    // Read /proc/self/statm for memory info
    // Format: size resident shared text lib data dt
    // All values are in pages (typically 4KB)
    if let Ok(content) = fs::read_to_string("/proc/self/statm") {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 2 {
            let page_size = 4096u64; // Most common page size
            let virtual_pages: u64 = parts[0].parse().unwrap_or(0);
            let resident_pages: u64 = parts[1].parse().unwrap_or(0);
            return (resident_pages * page_size, virtual_pages * page_size);
        }
    }

    // Fallback: try /proc/self/status
    if let Ok(content) = fs::read_to_string("/proc/self/status") {
        let mut rss = 0u64;
        let mut vmsize = 0u64;
        for line in content.lines() {
            if line.starts_with("VmRSS:") {
                rss = parse_proc_kb(line) * 1024;
            } else if line.starts_with("VmSize:") {
                vmsize = parse_proc_kb(line) * 1024;
            }
        }
        return (rss, vmsize);
    }

    (0, 0)
}

#[cfg(target_os = "linux")]
fn parse_proc_kb(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn get_process_memory() -> (u64, u64) {
    // On non-Linux systems, return 0 (memory monitoring not supported)
    // In production, you would use platform-specific APIs
    (0, 0)
}

/// Thread-safe wrapper for global memory monitor
pub type SharedMemoryMonitor = Arc<MemoryMonitor>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pressure_levels() {
        let config = MemoryMonitorConfig {
            warning_threshold: 100,
            critical_threshold: 200,
            ..Default::default()
        };
        let monitor = MemoryMonitor::new(config);

        // Initial state should be normal (we can't control actual memory in tests)
        assert_eq!(monitor.current_pressure(), MemoryPressure::Normal);
    }

    #[test]
    fn test_load_shedding_action() {
        let config = MemoryMonitorConfig::default();
        let monitor = MemoryMonitor::new(config);

        // With normal memory, should return None
        let action = monitor.should_shed_load();
        // On most test systems, memory is normal
        assert!(matches!(
            action,
            LoadSheddingAction::None | LoadSheddingAction::DisableUserscripts
        ));
    }

    #[test]
    fn test_default_config() {
        let config = MemoryMonitorConfig::default();
        assert_eq!(config.warning_threshold, 2 * 1024 * 1024 * 1024);
        assert_eq!(config.critical_threshold, 2560 * 1024 * 1024);
    }

    #[test]
    fn test_stats_snapshot() {
        let monitor = MemoryMonitor::with_defaults();
        let stats = monitor.stats_snapshot();

        // Stats should be initialized
        assert_eq!(stats.warning_count, 0);
        assert_eq!(stats.critical_count, 0);
        assert_eq!(stats.connections_rejected, 0);
        assert!(!stats.load_shedding_active);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_memory_reading() {
        let (rss, vmsize) = get_process_memory();
        // On Linux, we should be able to read some memory value
        assert!(rss > 0, "Should read non-zero RSS");
        assert!(vmsize > 0, "Should read non-zero virtual memory");
    }
}

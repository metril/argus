//! Production load management combining circuit breaker and memory monitoring
//!
//! This module provides unified load management for the proxy server:
//! - Connection admission control based on memory pressure
//! - Per-host circuit breaking for upstream failures
//! - Graceful degradation under load
//! - Statistics aggregation for monitoring

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, warn};

use crate::circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerStatsSnapshot, CircuitCheck,
};
use crate::memory_monitor::{
    LoadSheddingAction, MemoryMonitor, MemoryMonitorConfig, MemoryMonitorStatsSnapshot,
    MemoryPressure,
};

/// Default connection admission rate (new connections per second).
pub const DEFAULT_CONNECTION_RATE_LIMIT: u32 = 10_000;

/// Unified load manager configuration
#[derive(Debug, Clone)]
pub struct LoadManagerConfig {
    /// Circuit breaker configuration
    pub circuit_breaker: CircuitBreakerConfig,
    /// Memory monitor configuration
    pub memory_monitor: MemoryMonitorConfig,
    /// Maximum concurrent connections (0 = unlimited)
    pub max_connections: usize,
    /// Connection rate limit (connections per second, 0 = unlimited)
    pub connection_rate_limit: u32,
    /// Enable adaptive concurrency control
    pub adaptive_concurrency: bool,
}

impl Default for LoadManagerConfig {
    fn default() -> Self {
        Self {
            circuit_breaker: CircuitBreakerConfig::default(),
            memory_monitor: MemoryMonitorConfig::default(),
            max_connections: 10000,
            connection_rate_limit: DEFAULT_CONNECTION_RATE_LIMIT,
            adaptive_concurrency: true,
        }
    }
}

/// Result of connection admission check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionResult {
    /// Connection admitted - proceed normally
    Admitted,
    /// Connection rejected due to memory pressure
    RejectedMemoryPressure,
    /// Connection rejected due to max connections reached
    RejectedMaxConnections,
    /// Connection rejected due to rate limiting
    RejectedRateLimit,
}

/// Load manager statistics
pub struct LoadManagerStats {
    /// Active connections
    pub active_connections: AtomicU64,
    /// Total connections accepted
    pub connections_accepted: AtomicU64,
    /// Connections rejected (all reasons)
    pub connections_rejected: AtomicU64,
    /// Connections rejected due to memory
    pub connections_rejected_memory: AtomicU64,
    /// Connections rejected due to max limit
    pub connections_rejected_max: AtomicU64,
    /// Connections rejected due to rate limit
    pub connections_rejected_rate: AtomicU64,
    /// Rejections since the last summary warning (rate-limited logging).
    rejected_since_log: AtomicU64,
}

impl Default for LoadManagerStats {
    fn default() -> Self {
        Self {
            active_connections: AtomicU64::new(0),
            connections_accepted: AtomicU64::new(0),
            connections_rejected: AtomicU64::new(0),
            connections_rejected_memory: AtomicU64::new(0),
            connections_rejected_max: AtomicU64::new(0),
            connections_rejected_rate: AtomicU64::new(0),
            rejected_since_log: AtomicU64::new(0),
        }
    }
}

/// Unified load manager for production hardening
pub struct LoadManager {
    config: LoadManagerConfig,
    circuit_breaker: CircuitBreaker,
    memory_monitor: Arc<MemoryMonitor>,
    stats: LoadManagerStats,
    limiter: RateLimiter,
    epoch: Instant,
    /// Millis since `epoch` of the last summary warning.
    last_summary_ms: AtomicU64,
}

/// Lock-free token bucket (GCRA): one atomic holds the theoretical arrival time in nanoseconds.
/// Each admission advances it by `1/rate`; a request is refused if that would put it more than
/// the burst allowance (`burst/rate`, 100 ms worth) ahead of now. No locks, no allocation.
pub struct RateLimiter {
    /// Nanoseconds per admitted connection (0 = unlimited).
    interval_ns: u64,
    /// How far ahead of now the schedule may run.
    burst_ns: u64,
    tat: AtomicU64,
    epoch: Instant,
}

impl RateLimiter {
    /// `rate` connections per second; 0 = unlimited.
    pub fn new(rate: u32) -> Self {
        let interval_ns = if rate == 0 {
            0
        } else {
            1_000_000_000 / rate as u64
        };
        // Burst: 100 ms of tokens, at least 1.
        let burst_ns = (interval_ns * (rate as u64 / 10).max(1)).max(interval_ns);
        Self {
            interval_ns,
            burst_ns,
            tat: AtomicU64::new(0),
            epoch: Instant::now(),
        }
    }

    /// Take one token; false if the rate is exceeded.
    #[inline]
    pub fn try_acquire(&self) -> bool {
        if self.interval_ns == 0 {
            return true;
        }
        let now = self.epoch.elapsed().as_nanos() as u64;
        let mut cur = self.tat.load(Ordering::Relaxed);
        loop {
            let base = cur.max(now);
            if base - now > self.burst_ns {
                return false;
            }
            match self.tat.compare_exchange_weak(
                cur,
                base + self.interval_ns,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }
}

pub use common::config::derive_max_connections;

impl LoadManager {
    /// Create a new load manager with the given configuration
    pub fn new(config: LoadManagerConfig) -> Self {
        let circuit_breaker = CircuitBreaker::new(config.circuit_breaker.clone());
        let memory_monitor = Arc::new(MemoryMonitor::new(config.memory_monitor.clone()));
        let config_rate = config.connection_rate_limit;

        Self {
            config,
            circuit_breaker,
            memory_monitor,
            stats: LoadManagerStats::default(),
            limiter: RateLimiter::new(config_rate),
            epoch: Instant::now(),
            last_summary_ms: AtomicU64::new(0),
        }
    }

    /// Create a load manager with default configuration
    pub fn with_defaults() -> Self {
        Self::new(LoadManagerConfig::default())
    }

    /// Start background monitoring tasks
    pub fn start_monitoring(&self) -> tokio::task::JoinHandle<()> {
        self.memory_monitor.clone().start_monitoring()
    }

    /// Check if a new connection should be admitted
    pub fn check_admission(&self) -> AdmissionResult {
        // 1. Check memory pressure first (most critical)
        if !self.memory_monitor.should_accept_connection() {
            self.stats
                .connections_rejected
                .fetch_add(1, Ordering::Relaxed);
            self.stats
                .connections_rejected_memory
                .fetch_add(1, Ordering::Relaxed);
            self.note_rejection();
            return AdmissionResult::RejectedMemoryPressure;
        }

        // 2. Check max connections
        if self.config.max_connections > 0 {
            let active = self.stats.active_connections.load(Ordering::Relaxed) as usize;
            let effective_max = self.effective_max_connections();
            if active >= effective_max {
                self.stats
                    .connections_rejected
                    .fetch_add(1, Ordering::Relaxed);
                self.stats
                    .connections_rejected_max
                    .fetch_add(1, Ordering::Relaxed);
                self.note_rejection();
                return AdmissionResult::RejectedMaxConnections;
            }
        }

        // 3. Check rate limit (lock-free)
        if !self.limiter.try_acquire() {
            self.stats
                .connections_rejected
                .fetch_add(1, Ordering::Relaxed);
            self.stats
                .connections_rejected_rate
                .fetch_add(1, Ordering::Relaxed);
            self.note_rejection();
            return AdmissionResult::RejectedRateLimit;
        }

        // Connection admitted
        self.stats
            .active_connections
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .connections_accepted
            .fetch_add(1, Ordering::Relaxed);

        AdmissionResult::Admitted
    }

    /// Count a rejection and emit at most one summary warning per 10 s; per-event detail is
    /// debug only.
    fn note_rejection(&self) {
        const INTERVAL_MS: u64 = 10_000;
        debug!("Connection rejected");
        self.stats
            .rejected_since_log
            .fetch_add(1, Ordering::Relaxed);
        let now = self.epoch.elapsed().as_millis() as u64;
        let last = self.last_summary_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= INTERVAL_MS
            && self
                .last_summary_ms
                .compare_exchange(last, now.max(1), Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let n = self.stats.rejected_since_log.swap(0, Ordering::Relaxed);
            let s = self.stats();
            warn!(
                "Rejected {} connections since the last report (memory={}, max={}, rate={} in total); active={}",
                n,
                s.connections_rejected_memory,
                s.connections_rejected_max,
                s.connections_rejected_rate,
                s.active_connections
            );
        }
    }

    /// Release a connection (call when connection ends)
    pub fn release_connection(&self) {
        self.stats
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }

    /// Effective max connections based on memory pressure
    fn effective_max_connections(&self) -> usize {
        if !self.config.adaptive_concurrency {
            return self.config.max_connections;
        }

        let pressure = self.memory_monitor.current_pressure();
        match pressure {
            MemoryPressure::Normal => self.config.max_connections,
            MemoryPressure::Warning => self.config.max_connections * 75 / 100, // 75%
            MemoryPressure::Critical => self.config.max_connections * 50 / 100, // 50%
        }
    }

    /// Check if a request to the given upstream host should proceed
    pub fn check_upstream(&self, host: &str) -> CircuitCheck {
        self.circuit_breaker.check(host)
    }

    /// Record a successful upstream request
    pub fn record_upstream_success(&self, host: &str) {
        self.circuit_breaker.record_success(host);
    }

    /// Record a failed upstream request
    pub fn record_upstream_failure(&self, host: &str) {
        self.circuit_breaker.record_failure(host);
    }

    /// Check if userscripts should be executed (based on memory pressure)
    pub fn should_execute_userscripts(&self) -> bool {
        self.memory_monitor.should_execute_userscripts()
    }

    /// Get current memory pressure level
    pub fn memory_pressure(&self) -> MemoryPressure {
        self.memory_monitor.current_pressure()
    }

    /// Check if the system is under load shedding
    pub fn is_load_shedding_active(&self) -> bool {
        self.memory_monitor.is_load_shedding_active()
    }

    /// Get unified statistics snapshot
    pub fn stats(&self) -> LoadManagerStatsSnapshot {
        LoadManagerStatsSnapshot {
            active_connections: self.stats.active_connections.load(Ordering::Relaxed),
            connections_accepted: self.stats.connections_accepted.load(Ordering::Relaxed),
            connections_rejected: self.stats.connections_rejected.load(Ordering::Relaxed),
            connections_rejected_memory: self
                .stats
                .connections_rejected_memory
                .load(Ordering::Relaxed),
            connections_rejected_max: self.stats.connections_rejected_max.load(Ordering::Relaxed),
            connections_rejected_rate: self.stats.connections_rejected_rate.load(Ordering::Relaxed),
            circuit_breaker: self.circuit_breaker.stats(),
            memory: self.memory_monitor.stats_snapshot(),
        }
    }

    /// Reset circuit for a specific host (for manual intervention)
    pub fn reset_circuit(&self, host: &str) {
        self.circuit_breaker.reset_circuit(host);
    }

    /// Get the load shedding action based on current state
    pub fn current_load_shedding_action(&self) -> LoadSheddingAction {
        self.memory_monitor.should_shed_load()
    }
}

/// Snapshot of all load manager statistics
#[derive(Debug, Clone)]
pub struct LoadManagerStatsSnapshot {
    pub active_connections: u64,
    pub connections_accepted: u64,
    pub connections_rejected: u64,
    pub connections_rejected_memory: u64,
    pub connections_rejected_max: u64,
    pub connections_rejected_rate: u64,
    pub circuit_breaker: CircuitBreakerStatsSnapshot,
    pub memory: MemoryMonitorStatsSnapshot,
}

/// Thread-safe wrapper for global load manager
pub type SharedLoadManager = Arc<LoadManager>;

/// RAII guard for connection tracking
pub struct ConnectionGuard {
    load_manager: SharedLoadManager,
}

impl ConnectionGuard {
    /// Create a new connection guard
    pub fn new(load_manager: SharedLoadManager) -> Self {
        Self { load_manager }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.load_manager.release_connection();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_default_config() {
        let config = LoadManagerConfig::default();
        assert_eq!(config.max_connections, 10000);
        assert_eq!(config.connection_rate_limit, 10_000);
        assert!(config.adaptive_concurrency);
    }

    #[test]
    fn test_admission_success() {
        let manager = LoadManager::with_defaults();
        let result = manager.check_admission();
        assert_eq!(result, AdmissionResult::Admitted);

        // Release the connection
        manager.release_connection();
        assert_eq!(manager.stats.active_connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_max_connections() {
        let config = LoadManagerConfig {
            max_connections: 2,
            connection_rate_limit: 0, // Disable rate limiting for this test
            adaptive_concurrency: false,
            ..Default::default()
        };
        let manager = LoadManager::new(config);

        // Fill up connections
        assert_eq!(manager.check_admission(), AdmissionResult::Admitted);
        assert_eq!(manager.check_admission(), AdmissionResult::Admitted);

        // Third should be rejected
        assert_eq!(
            manager.check_admission(),
            AdmissionResult::RejectedMaxConnections
        );

        // Release one and try again
        manager.release_connection();
        assert_eq!(manager.check_admission(), AdmissionResult::Admitted);
    }

    #[test]
    fn rate_limiter_enforces_rate_and_small_burst() {
        let l = RateLimiter::new(1000);
        let ok = (0..1000).filter(|_| l.try_acquire()).count();
        // Burst is 100 ms of tokens (100) plus whatever time elapsed during the loop.
        assert!((100..=150).contains(&ok), "{ok}");
        let off = RateLimiter::new(0);
        assert!((0..100_000).all(|_| off.try_acquire()));
    }

    #[test]
    fn rate_limiter_contended_total_is_bounded() {
        let l = Arc::new(RateLimiter::new(2000));
        let start = Instant::now();
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let l = l.clone();
                std::thread::spawn(move || (0..20_000).filter(|_| l.try_acquire()).count())
            })
            .collect();
        let total: usize = hs.into_iter().map(|h| h.join().unwrap()).sum();
        let max = (2000.0 * start.elapsed().as_secs_f64()) as usize + 200 + 8;
        assert!(total <= max, "{total} > {max}");
        assert!(total >= 100);
    }

    /// Offer `rate` admissions/s for `ms` from 4 threads on a fixed schedule; returns admitted.
    fn offer_paced(m: &Arc<LoadManager>, rate: u64, ms: u64) -> u64 {
        let threads = 4u64;
        let per = rate * ms / 1000 / threads;
        let gap = Duration::from_nanos(1_000_000_000 * threads / rate);
        let start = Instant::now();
        let hs: Vec<_> = (0..threads)
            .map(|t| {
                let m = m.clone();
                std::thread::spawn(move || {
                    let mut ok = 0;
                    for i in 0..per {
                        let at = start + gap * i as u32 + gap * t as u32 / threads as u32;
                        while Instant::now() < at {
                            std::hint::spin_loop();
                        }
                        if m.check_admission() == AdmissionResult::Admitted {
                            ok += 1;
                            m.release_connection();
                        }
                    }
                    ok
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).sum()
    }

    #[test]
    fn default_limit_admits_10k_per_second_and_enforces_above() {
        let m = Arc::new(LoadManager::with_defaults());
        let offered = 10_000 * 1500 / 1000;
        assert_eq!(
            offer_paced(&m, 10_000, 1500),
            offered,
            "rejections at exactly 10k/s"
        );
        assert_eq!(m.stats().connections_rejected, 0);

        let m = Arc::new(LoadManager::with_defaults());
        let ok = offer_paced(&m, 20_000, 1500);
        // 10k/s for 1.5 s plus the 100 ms burst (1000), with a little slack.
        assert!((15_000..=16_500).contains(&ok), "{ok} of 30000 admitted");
    }

    #[test]
    fn derived_max_connections_is_sane() {
        let n = derive_max_connections();
        assert!((256..=100_000).contains(&n));
    }

    #[test]
    fn test_circuit_breaker_integration() {
        let config = LoadManagerConfig {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 2,
                ..Default::default()
            },
            ..Default::default()
        };
        let manager = LoadManager::new(config);

        // Initially allowed
        assert_eq!(manager.check_upstream("test.com"), CircuitCheck::Allowed);

        // Record failures to trip circuit
        manager.record_upstream_failure("test.com");
        manager.record_upstream_failure("test.com");

        // Should be blocked now
        assert_eq!(manager.check_upstream("test.com"), CircuitCheck::Blocked);
    }

    #[test]
    fn test_stats_snapshot() {
        let manager = LoadManager::with_defaults();

        // Make some connections
        manager.check_admission();
        manager.check_admission();

        let stats = manager.stats();
        assert_eq!(stats.active_connections, 2);
        assert_eq!(stats.connections_accepted, 2);
        assert_eq!(stats.connections_rejected, 0);
    }

    #[test]
    fn test_connection_guard() {
        let manager = Arc::new(LoadManager::with_defaults());

        {
            assert_eq!(manager.check_admission(), AdmissionResult::Admitted);
            let _guard = ConnectionGuard::new(manager.clone());
            assert_eq!(manager.stats.active_connections.load(Ordering::Relaxed), 1);
        } // Guard dropped here

        // Connection should be released
        assert_eq!(manager.stats.active_connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_userscript_execution_check() {
        let manager = LoadManager::with_defaults();

        // With normal memory pressure, userscripts should execute
        // Note: This depends on actual system memory state
        let should_execute = manager.should_execute_userscripts();
        // Can't guarantee the result, but it should not panic
        let _ = should_execute;
    }
}

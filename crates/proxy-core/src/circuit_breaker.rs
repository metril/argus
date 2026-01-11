//! Circuit breaker pattern implementation
//!
//! Prevents cascading failures by tracking upstream failures and temporarily
//! blocking requests when the failure rate exceeds a threshold.

use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation - requests pass through
    Closed,
    /// Too many failures - requests are blocked
    Open,
    /// Testing if upstream is healthy again
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening the circuit
    pub failure_threshold: u32,
    /// Number of successes needed to close the circuit from half-open state
    pub success_threshold: u32,
    /// How long to wait before transitioning from open to half-open
    pub timeout: Duration,
    /// Window for tracking failures (failures outside this window are forgotten)
    pub failure_window: Duration,
    /// Maximum requests to allow through in half-open state
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            timeout: Duration::from_secs(30),
            failure_window: Duration::from_secs(60),
            half_open_max_requests: 3,
        }
    }
}

/// Per-host circuit breaker state
struct HostCircuit {
    state: CircuitState,
    failures: Vec<Instant>,
    successes_in_half_open: u32,
    requests_in_half_open: u32,
    opened_at: Option<Instant>,
}

impl Default for HostCircuit {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            failures: Vec::new(),
            successes_in_half_open: 0,
            requests_in_half_open: 0,
            opened_at: None,
        }
    }
}

/// Circuit breaker for managing upstream connection failures
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    /// Per-host circuit state
    circuits: dashmap::DashMap<String, RwLock<HostCircuit>>,
    /// Statistics
    stats: CircuitBreakerStats,
}

/// Circuit breaker statistics
pub struct CircuitBreakerStats {
    /// Total requests blocked by open circuits
    pub requests_blocked: AtomicU64,
    /// Total circuits currently open
    pub circuits_open: AtomicU64,
    /// Total circuit trips (transitions to open state)
    pub circuit_trips: AtomicU64,
}

impl Default for CircuitBreakerStats {
    fn default() -> Self {
        Self {
            requests_blocked: AtomicU64::new(0),
            circuits_open: AtomicU64::new(0),
            circuit_trips: AtomicU64::new(0),
        }
    }
}

/// Result of checking if a request can proceed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitCheck {
    /// Request can proceed
    Allowed,
    /// Request is blocked due to open circuit
    Blocked,
    /// Request can proceed (testing in half-open state)
    AllowedHalfOpen,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given configuration
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            circuits: dashmap::DashMap::new(),
            stats: CircuitBreakerStats::default(),
        }
    }

    /// Create a circuit breaker with default configuration
    pub fn with_defaults() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }

    /// Check if a request to the given host should be allowed
    pub fn check(&self, host: &str) -> CircuitCheck {
        let circuit_entry = self.circuits
            .entry(host.to_string())
            .or_insert_with(|| RwLock::new(HostCircuit::default()));

        let mut circuit = circuit_entry.write();
        let now = Instant::now();

        match circuit.state {
            CircuitState::Closed => CircuitCheck::Allowed,

            CircuitState::Open => {
                // Check if we should transition to half-open
                if let Some(opened_at) = circuit.opened_at {
                    if now.duration_since(opened_at) >= self.config.timeout {
                        debug!("Circuit for {} transitioning to half-open", host);
                        circuit.state = CircuitState::HalfOpen;
                        circuit.successes_in_half_open = 0;
                        circuit.requests_in_half_open = 0;
                        circuit.requests_in_half_open += 1;
                        return CircuitCheck::AllowedHalfOpen;
                    }
                }
                self.stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
                CircuitCheck::Blocked
            }

            CircuitState::HalfOpen => {
                if circuit.requests_in_half_open < self.config.half_open_max_requests {
                    circuit.requests_in_half_open += 1;
                    CircuitCheck::AllowedHalfOpen
                } else {
                    self.stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
                    CircuitCheck::Blocked
                }
            }
        }
    }

    /// Record a successful request to the given host
    pub fn record_success(&self, host: &str) {
        if let Some(circuit_entry) = self.circuits.get(host) {
            let mut circuit = circuit_entry.write();

            match circuit.state {
                CircuitState::Closed => {
                    // Success in closed state - nothing to do
                }
                CircuitState::HalfOpen => {
                    circuit.successes_in_half_open += 1;
                    if circuit.successes_in_half_open >= self.config.success_threshold {
                        info!("Circuit for {} closing after {} successes", host, circuit.successes_in_half_open);
                        circuit.state = CircuitState::Closed;
                        circuit.failures.clear();
                        circuit.opened_at = None;
                        self.stats.circuits_open.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                CircuitState::Open => {
                    // Shouldn't happen - request was blocked
                }
            }
        }
    }

    /// Record a failed request to the given host
    pub fn record_failure(&self, host: &str) {
        let circuit_entry = self.circuits
            .entry(host.to_string())
            .or_insert_with(|| RwLock::new(HostCircuit::default()));

        let mut circuit = circuit_entry.write();
        let now = Instant::now();

        match circuit.state {
            CircuitState::Closed => {
                // Remove old failures outside the window
                let window_start = now - self.config.failure_window;
                circuit.failures.retain(|&f| f > window_start);

                // Add this failure
                circuit.failures.push(now);

                // Check if we should trip the circuit
                if circuit.failures.len() >= self.config.failure_threshold as usize {
                    warn!(
                        "Circuit for {} opening after {} failures in {:?}",
                        host,
                        circuit.failures.len(),
                        self.config.failure_window
                    );
                    circuit.state = CircuitState::Open;
                    circuit.opened_at = Some(now);
                    self.stats.circuits_open.fetch_add(1, Ordering::Relaxed);
                    self.stats.circuit_trips.fetch_add(1, Ordering::Relaxed);
                }
            }
            CircuitState::HalfOpen => {
                // Failure in half-open state - back to open
                warn!("Circuit for {} re-opening due to failure in half-open state", host);
                circuit.state = CircuitState::Open;
                circuit.opened_at = Some(now);
                circuit.successes_in_half_open = 0;
                circuit.requests_in_half_open = 0;
            }
            CircuitState::Open => {
                // Already open - nothing to do
            }
        }
    }

    /// Get circuit breaker statistics
    pub fn stats(&self) -> CircuitBreakerStatsSnapshot {
        CircuitBreakerStatsSnapshot {
            requests_blocked: self.stats.requests_blocked.load(Ordering::Relaxed),
            circuits_open: self.stats.circuits_open.load(Ordering::Relaxed),
            circuit_trips: self.stats.circuit_trips.load(Ordering::Relaxed),
            total_hosts_tracked: self.circuits.len() as u64,
        }
    }

    /// Get the state of a specific host's circuit
    pub fn get_circuit_state(&self, host: &str) -> CircuitState {
        self.circuits
            .get(host)
            .map(|entry| entry.read().state)
            .unwrap_or(CircuitState::Closed)
    }

    /// Reset the circuit for a specific host (for testing or manual intervention)
    pub fn reset_circuit(&self, host: &str) {
        if let Some(circuit_entry) = self.circuits.get(host) {
            let mut circuit = circuit_entry.write();
            if circuit.state == CircuitState::Open {
                self.stats.circuits_open.fetch_sub(1, Ordering::Relaxed);
            }
            *circuit = HostCircuit::default();
            info!("Circuit for {} manually reset", host);
        }
    }

    /// Clear all circuits (for testing)
    pub fn clear_all(&self) {
        self.circuits.clear();
        self.stats.circuits_open.store(0, Ordering::Relaxed);
    }
}

/// Snapshot of circuit breaker statistics
#[derive(Debug, Clone)]
pub struct CircuitBreakerStatsSnapshot {
    pub requests_blocked: u64,
    pub circuits_open: u64,
    pub circuit_trips: u64,
    pub total_hosts_tracked: u64,
}

/// Thread-safe wrapper for global circuit breaker
pub type SharedCircuitBreaker = Arc<CircuitBreaker>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_starts_closed() {
        let cb = CircuitBreaker::with_defaults();
        assert_eq!(cb.check("example.com"), CircuitCheck::Allowed);
        assert_eq!(cb.get_circuit_state("example.com"), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::new(config);

        // Record failures
        cb.record_failure("example.com");
        assert_eq!(cb.check("example.com"), CircuitCheck::Allowed);

        cb.record_failure("example.com");
        assert_eq!(cb.check("example.com"), CircuitCheck::Allowed);

        cb.record_failure("example.com");
        assert_eq!(cb.check("example.com"), CircuitCheck::Blocked);
        assert_eq!(cb.get_circuit_state("example.com"), CircuitState::Open);
    }

    #[test]
    fn test_circuit_transitions_to_half_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_millis(10),
            ..Default::default()
        };
        let cb = CircuitBreaker::new(config);

        // Trip the circuit
        cb.record_failure("example.com");
        cb.record_failure("example.com");
        assert_eq!(cb.get_circuit_state("example.com"), CircuitState::Open);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(20));

        // Should transition to half-open on next check
        assert_eq!(cb.check("example.com"), CircuitCheck::AllowedHalfOpen);
        assert_eq!(cb.get_circuit_state("example.com"), CircuitState::HalfOpen);
    }

    #[test]
    fn test_circuit_closes_after_successes() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(10),
            half_open_max_requests: 5,
            ..Default::default()
        };
        let cb = CircuitBreaker::new(config);

        // Trip the circuit
        cb.record_failure("example.com");
        cb.record_failure("example.com");

        // Wait for timeout and transition to half-open
        std::thread::sleep(Duration::from_millis(20));
        cb.check("example.com");

        // Record successes
        cb.record_success("example.com");
        assert_eq!(cb.get_circuit_state("example.com"), CircuitState::HalfOpen);

        cb.record_success("example.com");
        assert_eq!(cb.get_circuit_state("example.com"), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_reopens_on_half_open_failure() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_millis(10),
            ..Default::default()
        };
        let cb = CircuitBreaker::new(config);

        // Trip and transition to half-open
        cb.record_failure("example.com");
        cb.record_failure("example.com");
        std::thread::sleep(Duration::from_millis(20));
        cb.check("example.com");

        // Failure in half-open should reopen
        cb.record_failure("example.com");
        assert_eq!(cb.get_circuit_state("example.com"), CircuitState::Open);
    }

    #[test]
    fn test_stats_tracking() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            ..Default::default()
        };
        let cb = CircuitBreaker::new(config);

        // Trip circuit
        cb.record_failure("example.com");
        cb.record_failure("example.com");

        let stats = cb.stats();
        assert_eq!(stats.circuits_open, 1);
        assert_eq!(stats.circuit_trips, 1);

        // Blocked request
        cb.check("example.com");
        let stats = cb.stats();
        assert_eq!(stats.requests_blocked, 1);
    }

    #[test]
    fn test_independent_host_circuits() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            ..Default::default()
        };
        let cb = CircuitBreaker::new(config);

        // Trip circuit for host1
        cb.record_failure("host1.com");
        cb.record_failure("host1.com");

        // host1 should be blocked, host2 should be allowed
        assert_eq!(cb.check("host1.com"), CircuitCheck::Blocked);
        assert_eq!(cb.check("host2.com"), CircuitCheck::Allowed);
    }
}

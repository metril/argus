//! Chaos engineering tests for proxy-core
//!
//! Tests the system's resilience under various failure conditions:
//! - Random failures
//! - High load conditions
//! - Circuit breaker behavior
//! - Memory pressure scenarios

use proxy_core::{
    CircuitBreaker, CircuitBreakerConfig, CircuitCheck, CircuitState,
    MemoryMonitor, MemoryMonitorConfig, MemoryPressure, LoadSheddingAction,
};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// =============================================================================
// Circuit Breaker Chaos Tests
// =============================================================================

#[test]
fn test_circuit_breaker_random_failures() {
    let config = CircuitBreakerConfig {
        failure_threshold: 5,
        success_threshold: 2,
        timeout: Duration::from_millis(100),
        failure_window: Duration::from_secs(1),
        half_open_max_requests: 3,
    };
    let cb = CircuitBreaker::new(config);

    let failure_rate = 0.3;
    let num_hosts = 10;
    let requests_per_host = 100;

    let mut total_allowed = 0u32;
    let mut total_blocked = 0u32;

    for i in 0..num_hosts {
        let host = format!("host{}.example.com", i);

        for _ in 0..requests_per_host {
            match cb.check(&host) {
                CircuitCheck::Allowed | CircuitCheck::AllowedHalfOpen => {
                    total_allowed += 1;
                    if rand::random::<f64>() < failure_rate {
                        cb.record_failure(&host);
                    } else {
                        cb.record_success(&host);
                    }
                }
                CircuitCheck::Blocked => {
                    total_blocked += 1;
                }
            }
        }
    }

    let stats = cb.stats();
    assert!(stats.circuit_trips > 0, "Some circuits should have tripped");
    println!(
        "Random failure test: {} allowed, {} blocked, {} circuits tripped",
        total_allowed, total_blocked, stats.circuit_trips
    );
}

#[test]
fn test_circuit_breaker_burst_failures() {
    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        success_threshold: 2,
        timeout: Duration::from_millis(50),
        failure_window: Duration::from_millis(500),
        half_open_max_requests: 2,
    };
    let cb = CircuitBreaker::new(config);

    // Simulate a burst of failures
    for _ in 0..10 {
        cb.check("burst-host.com");
        cb.record_failure("burst-host.com");
    }

    // Circuit should be open
    assert_eq!(cb.get_circuit_state("burst-host.com"), CircuitState::Open);
    assert_eq!(cb.check("burst-host.com"), CircuitCheck::Blocked);

    // Wait for timeout
    thread::sleep(Duration::from_millis(100));

    // Should transition to half-open
    let check = cb.check("burst-host.com");
    assert_eq!(check, CircuitCheck::AllowedHalfOpen);

    // Successful requests should close the circuit
    cb.record_success("burst-host.com");
    cb.check("burst-host.com");
    cb.record_success("burst-host.com");

    assert_eq!(cb.get_circuit_state("burst-host.com"), CircuitState::Closed);
}

#[test]
fn test_circuit_breaker_concurrent_hosts() {
    let cb = Arc::new(CircuitBreaker::with_defaults());
    let num_threads = 8;
    let hosts_per_thread = 50;
    let requests_per_host = 20;

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let cb = Arc::clone(&cb);
            thread::spawn(move || {
                for host_id in 0..hosts_per_thread {
                    let host = format!("thread{}-host{}.com", thread_id, host_id);
                    for _ in 0..requests_per_host {
                        cb.check(&host);
                        if rand::random::<bool>() {
                            cb.record_success(&host);
                        } else {
                            cb.record_failure(&host);
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let stats = cb.stats();
    println!(
        "Concurrent test: {} hosts tracked, {} circuits open, {} trips",
        stats.total_hosts_tracked, stats.circuits_open, stats.circuit_trips
    );

    assert!(stats.total_hosts_tracked > 0);
}

#[test]
fn test_circuit_breaker_memory_under_load() {
    let cb = CircuitBreaker::with_defaults();

    // Create many hosts to stress memory
    let num_hosts = 10_000;

    for i in 0..num_hosts {
        let host = format!("stress-host-{}.example.com", i);
        cb.check(&host);
        if i % 10 == 0 {
            cb.record_failure(&host);
        } else {
            cb.record_success(&host);
        }
    }

    let stats = cb.stats();
    assert_eq!(stats.total_hosts_tracked, num_hosts);

    // Clear and verify memory is released
    cb.clear_all();
    let stats_after = cb.stats();
    assert_eq!(stats_after.total_hosts_tracked, 0);
}

// =============================================================================
// Memory Monitor Chaos Tests
// =============================================================================

#[test]
fn test_memory_monitor_basic_functionality() {
    let config = MemoryMonitorConfig {
        warning_threshold: 2 * 1024 * 1024 * 1024,
        critical_threshold: 2560 * 1024 * 1024,
        check_interval: Duration::from_millis(100),
        recovery_cooldown: Duration::from_secs(1),
    };
    let monitor = MemoryMonitor::new(config);

    let stats = monitor.get_memory_usage();
    println!("Current RSS: {} MB", stats.rss_bytes / 1024 / 1024);

    assert!(
        stats.pressure == MemoryPressure::Normal || stats.pressure == MemoryPressure::Warning,
        "Unexpected pressure level in test environment"
    );
}

#[test]
fn test_memory_monitor_concurrent_access() {
    let monitor = Arc::new(MemoryMonitor::with_defaults());
    let num_threads = 8;
    let iterations = 1000;

    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let monitor = Arc::clone(&monitor);
            thread::spawn(move || {
                for _ in 0..iterations {
                    let _ = monitor.get_memory_usage();
                    let _ = monitor.should_shed_load();
                    let _ = monitor.should_accept_connection();
                    let _ = monitor.current_pressure();
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let stats = monitor.stats_snapshot();
    assert!(stats.peak_rss > 0);
}

#[test]
fn test_memory_monitor_with_custom_thresholds() {
    // Very low thresholds to test threshold crossing
    let config = MemoryMonitorConfig {
        warning_threshold: 1024,
        critical_threshold: 2048,
        check_interval: Duration::from_millis(10),
        recovery_cooldown: Duration::from_millis(50),
    };
    let monitor = MemoryMonitor::new(config);

    let action = monitor.should_shed_load();
    assert_eq!(action, LoadSheddingAction::RejectConnections);
    assert_eq!(monitor.current_pressure(), MemoryPressure::Critical);
}

#[test]
fn test_memory_monitor_with_high_thresholds() {
    let config = MemoryMonitorConfig {
        warning_threshold: 1024 * 1024 * 1024 * 100,
        critical_threshold: 1024 * 1024 * 1024 * 200,
        check_interval: Duration::from_millis(10),
        recovery_cooldown: Duration::from_millis(50),
    };
    let monitor = MemoryMonitor::new(config);

    let action = monitor.should_shed_load();
    assert_eq!(action, LoadSheddingAction::None);
    assert_eq!(monitor.current_pressure(), MemoryPressure::Normal);
}

// =============================================================================
// Concurrent Stress Tests
// =============================================================================

#[test]
fn test_concurrent_stress_circuit_breaker() {
    let cb = Arc::new(CircuitBreaker::with_defaults());
    let duration = Duration::from_secs(1);

    let start = Instant::now();
    let mut total_ops = 0u64;

    let handles: Vec<_> = (0..4)
        .map(|thread_id| {
            let cb = Arc::clone(&cb);
            thread::spawn(move || {
                let mut ops = 0u64;
                let thread_start = Instant::now();

                while thread_start.elapsed() < duration {
                    for i in 0..100 {
                        let host = format!("t{}-h{}.com", thread_id, i % 100);
                        cb.check(&host);
                        if i % 3 == 0 {
                            cb.record_failure(&host);
                        } else {
                            cb.record_success(&host);
                        }
                        ops += 1;
                    }
                }
                ops
            })
        })
        .collect();

    for handle in handles {
        total_ops += handle.join().expect("Thread panicked");
    }

    let elapsed = start.elapsed();
    let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();

    println!(
        "Circuit breaker stress: {} ops in {:?} ({:.0} ops/sec)",
        total_ops, elapsed, ops_per_sec
    );

    assert!(ops_per_sec > 10_000.0, "Throughput too low");
}

#[test]
fn test_spawn_many_short_lived_tasks() {
    let cb = Arc::new(CircuitBreaker::with_defaults());
    let num_tasks = 1000;

    let handles: Vec<_> = (0..num_tasks)
        .map(|i| {
            let cb = Arc::clone(&cb);
            thread::spawn(move || {
                let host = format!("task{}.com", i);
                cb.check(&host);
                cb.record_success(&host);
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let stats = cb.stats();
    assert_eq!(stats.total_hosts_tracked, num_tasks);
}

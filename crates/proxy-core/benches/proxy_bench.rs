//! Proxy core benchmarks
//!
//! Benchmarks for proxy core functionality including:
//! - Certificate generation
//! - Circuit breaker operations
//! - Memory monitoring

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::Duration;

// Import the crates we're benchmarking
use proxy_core::{
    CircuitBreaker, CircuitBreakerConfig,
    MemoryMonitor, MemoryMonitorConfig,
};

/// Benchmark circuit breaker check operations
fn bench_circuit_breaker_check(c: &mut Criterion) {
    let config = CircuitBreakerConfig {
        failure_threshold: 5,
        success_threshold: 2,
        timeout: Duration::from_secs(30),
        failure_window: Duration::from_secs(60),
        half_open_max_requests: 3,
    };
    let cb = CircuitBreaker::new(config);

    c.bench_function("circuit_breaker_check_closed", |b| {
        b.iter(|| {
            black_box(cb.check(black_box("example.com")));
        });
    });
}

/// Benchmark circuit breaker with many hosts
fn bench_circuit_breaker_many_hosts(c: &mut Criterion) {
    let cb = CircuitBreaker::with_defaults();

    // Pre-populate with some hosts
    let hosts: Vec<String> = (0..1000).map(|i| format!("host{}.com", i)).collect();
    for host in &hosts {
        cb.check(host);
    }

    let mut group = c.benchmark_group("circuit_breaker_scaling");

    for num_hosts in [100, 500, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("check", num_hosts),
            num_hosts,
            |b, &n| {
                b.iter(|| {
                    for i in 0..n {
                        black_box(cb.check(&hosts[i as usize]));
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark circuit breaker record operations
fn bench_circuit_breaker_record(c: &mut Criterion) {
    let cb = CircuitBreaker::with_defaults();

    c.bench_function("circuit_breaker_record_success", |b| {
        b.iter(|| {
            cb.check("example.com");
            cb.record_success(black_box("example.com"));
        });
    });

    c.bench_function("circuit_breaker_record_failure", |b| {
        // Use different hosts to avoid opening the circuit
        let mut host_counter = 0u64;
        b.iter(|| {
            let host = format!("host{}.com", host_counter);
            host_counter += 1;
            cb.check(&host);
            cb.record_failure(black_box(&host));
        });
    });
}

/// Benchmark memory monitor checks
fn bench_memory_monitor(c: &mut Criterion) {
    let config = MemoryMonitorConfig {
        warning_threshold: 2 * 1024 * 1024 * 1024,
        critical_threshold: 2560 * 1024 * 1024,
        check_interval: Duration::from_secs(5),
        recovery_cooldown: Duration::from_secs(30),
    };
    let monitor = MemoryMonitor::new(config);

    c.bench_function("memory_monitor_get_usage", |b| {
        b.iter(|| {
            black_box(monitor.get_memory_usage());
        });
    });

    c.bench_function("memory_monitor_should_shed_load", |b| {
        b.iter(|| {
            black_box(monitor.should_shed_load());
        });
    });

    c.bench_function("memory_monitor_should_accept_connection", |b| {
        b.iter(|| {
            black_box(monitor.should_accept_connection());
        });
    });
}

/// Benchmark CA encryption (if enabled)
fn bench_ca_encryption(c: &mut Criterion) {
    use proxy_core::{encrypt_ca_key, decrypt_ca_key};

    let test_key = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgY2N5YmVyIHNlY3Vy\naXR5IHRlc3Qga2V5IGhlcmUhIWhRANCAATy6x+3k7qb7rSWWyRYR7v8zR6+Fxv1B\ngKvLmXgqQqQr7k8wJWLDMwYwO+D7oXDkYLsSTg8O+D7oXDkYLsSTg8\n-----END PRIVATE KEY-----\n";
    let passphrase = "BenchmarkP@ssw0rd!";

    // Encrypt once for decryption benchmark
    let encrypted = encrypt_ca_key(test_key, passphrase).unwrap();

    let mut group = c.benchmark_group("ca_encryption");
    group.sample_size(20); // Fewer samples since encryption is slow

    group.bench_function("encrypt", |b| {
        b.iter(|| {
            black_box(encrypt_ca_key(black_box(test_key), black_box(passphrase)).unwrap());
        });
    });

    group.bench_function("decrypt", |b| {
        b.iter(|| {
            black_box(decrypt_ca_key(black_box(&encrypted), black_box(passphrase)).unwrap());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_circuit_breaker_check,
    bench_circuit_breaker_many_hosts,
    bench_circuit_breaker_record,
    bench_memory_monitor,
    bench_ca_encryption,
);

criterion_main!(benches);

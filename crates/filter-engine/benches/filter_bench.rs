//! Filter engine benchmarks
//!
//! Benchmarks for adblocking filter engine including:
//! - Filter rule matching
//! - Cosmetic rule parsing
//! - ReDoS protection validation

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

use filter_engine::{
    FilterValidator, FilterSafetyConfig,
    validate_filter_rule, validate_filter_rules,
};

/// Sample filter rules for benchmarking
fn sample_rules() -> Vec<String> {
    vec![
        // Simple domain blocks
        "||example.com^".to_string(),
        "||ads.example.com^".to_string(),
        "||tracking.com^$third-party".to_string(),
        // Complex rules with modifiers
        "||ads.com^$domain=a.com|b.com|c.com,third-party".to_string(),
        "@@||cdn.example.com^$document".to_string(),
        // URL pattern rules
        "/banner.*\\.gif$/".to_string(),
        "*&utm_source=*".to_string(),
        // Cosmetic rules
        "example.com##.ad-banner".to_string(),
        "example.com#@#.not-an-ad".to_string(),
        // Extended CSS
        "example.com#?#div:has(> .sponsored)".to_string(),
    ]
}

/// Generate a large set of rules for stress testing
fn generate_large_ruleset(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| format!("||host{}.example.com^$third-party", i))
        .collect()
}

/// Benchmark single rule validation
fn bench_validate_single_rule(c: &mut Criterion) {
    let rules = sample_rules();

    let mut group = c.benchmark_group("filter_validation_single");

    for (i, rule) in rules.iter().enumerate() {
        group.bench_with_input(
            BenchmarkId::new("rule", i),
            rule,
            |b, rule| {
                b.iter(|| {
                    black_box(validate_filter_rule(black_box(rule)));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark batch rule validation
fn bench_validate_batch_rules(c: &mut Criterion) {
    let mut group = c.benchmark_group("filter_validation_batch");

    for count in [100, 500, 1000, 5000].iter() {
        let rules = generate_large_ruleset(*count);

        group.bench_with_input(
            BenchmarkId::new("rules", count),
            &rules,
            |b, rules| {
                b.iter(|| {
                    black_box(validate_filter_rules(black_box(rules)));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark validator with different configurations
fn bench_validator_configs(c: &mut Criterion) {
    let rules = sample_rules();

    let strict_config = FilterSafetyConfig {
        max_rule_length: 1024,
        max_pattern_complexity: 500,
        block_dangerous_patterns: true,
        ..Default::default()
    };

    let lenient_config = FilterSafetyConfig {
        max_rule_length: 8192,
        max_pattern_complexity: 2000,
        block_dangerous_patterns: false,
        ..Default::default()
    };

    let strict_validator = FilterValidator::new(strict_config);
    let lenient_validator = FilterValidator::new(lenient_config);
    let default_validator = FilterValidator::with_defaults();

    let mut group = c.benchmark_group("filter_validator_configs");

    group.bench_function("strict", |b| {
        b.iter(|| {
            for rule in &rules {
                black_box(strict_validator.validate_rule(black_box(rule)));
            }
        });
    });

    group.bench_function("lenient", |b| {
        b.iter(|| {
            for rule in &rules {
                black_box(lenient_validator.validate_rule(black_box(rule)));
            }
        });
    });

    group.bench_function("default", |b| {
        b.iter(|| {
            for rule in &rules {
                black_box(default_validator.validate_rule(black_box(rule)));
            }
        });
    });

    group.finish();
}

/// Benchmark regex complexity detection
fn bench_regex_complexity(c: &mut Criterion) {
    let regex_rules = vec![
        "/simple/".to_string(),
        "/pattern.*match/".to_string(),
        "/^https?:\\/\\/[a-z]+\\.example\\.com/".to_string(),
        "/complex(a|b|c)+pattern/".to_string(),
        "/[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+\\.[a-zA-Z]{2,}/".to_string(),
    ];

    let validator = FilterValidator::with_defaults();

    let mut group = c.benchmark_group("regex_complexity");

    for (i, rule) in regex_rules.iter().enumerate() {
        group.bench_with_input(
            BenchmarkId::new("rule", i),
            rule,
            |b, rule| {
                b.iter(|| {
                    black_box(validator.validate_rule(black_box(rule)));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark rejection of dangerous patterns
fn bench_dangerous_pattern_detection(c: &mut Criterion) {
    let dangerous_rules = vec![
        "/(.*)*/".to_string(),
        "/(a+)+/".to_string(),
        "/([a-z]+)*/".to_string(),
    ];

    let validator = FilterValidator::with_defaults();

    c.bench_function("dangerous_pattern_detection", |b| {
        b.iter(|| {
            for rule in &dangerous_rules {
                black_box(validator.validate_rule(black_box(rule)));
            }
        });
    });
}

/// Benchmark long rule rejection
fn bench_long_rule_rejection(c: &mut Criterion) {
    let validator = FilterValidator::with_defaults();

    let mut group = c.benchmark_group("long_rule_handling");

    for length in [1000, 2000, 4000, 8000].iter() {
        let long_rule = "x".repeat(*length);

        group.bench_with_input(
            BenchmarkId::new("length", length),
            &long_rule,
            |b, rule| {
                b.iter(|| {
                    black_box(validator.validate_rule(black_box(rule)));
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_validate_single_rule,
    bench_validate_batch_rules,
    bench_validator_configs,
    bench_regex_complexity,
    bench_dangerous_pattern_detection,
    bench_long_rule_rejection,
);

criterion_main!(benches);

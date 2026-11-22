//! Counters and rate-limited summaries for proxy-side failures that are otherwise silent
//! (per-event detail stays at debug level): upstream timeouts and errors, DNS failures and
//! destination-policy refusals.
//!
//! At most one `warn!` per interval, naming the total since the last summary and the most
//! frequent failing host of each kind.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// Summary interval of the process-wide tracker.
pub const SUMMARY_INTERVAL: Duration = Duration::from_secs(10);
/// Distinct (kind, host) pairs tracked per interval; further new hosts count but are unnamed.
const MAX_HOSTS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fault {
    UpstreamTimeout,
    UpstreamError,
    DnsFailure,
    PolicyRefusal,
}

impl Fault {
    const ALL: [Fault; 4] = [
        Fault::UpstreamTimeout,
        Fault::UpstreamError,
        Fault::DnsFailure,
        Fault::PolicyRefusal,
    ];
    fn label(self) -> &'static str {
        match self {
            Fault::UpstreamTimeout => "upstream timeouts",
            Fault::UpstreamError => "upstream errors",
            Fault::DnsFailure => "DNS failures",
            Fault::PolicyRefusal => "destination refusals",
        }
    }
}

/// Totals since start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FaultSnapshot {
    pub upstream_timeouts: u64,
    pub upstream_errors: u64,
    pub dns_failures: u64,
    pub policy_refusals: u64,
}

#[derive(Default)]
struct Window {
    last_summary: Option<Instant>,
    per_host: HashMap<(Fault, String), u64>,
    counts: [u64; 4],
}

pub struct FaultTracker {
    interval: Duration,
    totals: [AtomicU64; 4],
    window: Mutex<Window>,
}

impl FaultTracker {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            totals: Default::default(),
            window: Mutex::new(Window::default()),
        }
    }

    /// Count a failure; returns the summary text when one is due (the first failure, then at
    /// most one per interval).
    pub fn record(&self, fault: Fault, host: &str) -> Option<String> {
        self.totals[fault as usize].fetch_add(1, Ordering::Relaxed);
        let mut w = self.window.lock();
        w.counts[fault as usize] += 1;
        let key = (fault, host.to_ascii_lowercase());
        if w.per_host.len() < MAX_HOSTS || w.per_host.contains_key(&key) {
            *w.per_host.entry(key).or_insert(0) += 1;
        }
        let now = Instant::now();
        if w.last_summary
            .is_some_and(|t| now.duration_since(t) < self.interval)
        {
            return None;
        }
        w.last_summary = Some(now);
        let mut parts = Vec::new();
        for f in Fault::ALL {
            let n = w.counts[f as usize];
            if n == 0 {
                continue;
            }
            let top = w
                .per_host
                .iter()
                .filter(|((k, _), _)| *k == f)
                .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0 .1.cmp(&a.0 .1)))
                .map(|((_, h), c)| format!(", most often {h} ({c})"))
                .unwrap_or_default();
            parts.push(format!("{n} {}{top}", f.label()));
        }
        *w = Window {
            last_summary: w.last_summary,
            ..Default::default()
        };
        Some(parts.join("; "))
    }

    pub fn snapshot(&self) -> FaultSnapshot {
        let t = |f: Fault| self.totals[f as usize].load(Ordering::Relaxed);
        FaultSnapshot {
            upstream_timeouts: t(Fault::UpstreamTimeout),
            upstream_errors: t(Fault::UpstreamError),
            dns_failures: t(Fault::DnsFailure),
            policy_refusals: t(Fault::PolicyRefusal),
        }
    }
}

static GLOBAL: LazyLock<FaultTracker> = LazyLock::new(|| FaultTracker::new(SUMMARY_INTERVAL));

/// Record a failure on the process-wide tracker, warning once per interval.
pub fn note(fault: Fault, host: &str) {
    tracing::debug!("{}: {host}", fault.label());
    if let Some(s) = GLOBAL.record(fault, host) {
        tracing::warn!("Since the last report: {s}");
    }
}

/// Process-wide totals since start.
pub fn snapshot() -> FaultSnapshot {
    GLOBAL.snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_summary_per_interval_names_the_top_host() {
        let t = FaultTracker::new(Duration::from_secs(3600));
        let first = t.record(Fault::UpstreamError, "a.test").unwrap();
        assert!(first.contains("1 upstream errors"), "{first}");
        for _ in 0..5 {
            assert!(t.record(Fault::UpstreamError, "b.test").is_none());
        }
        assert!(t.record(Fault::DnsFailure, "c.test").is_none());
        assert_eq!(
            t.snapshot(),
            FaultSnapshot {
                upstream_errors: 6,
                dns_failures: 1,
                ..Default::default()
            }
        );
        let t = FaultTracker::new(Duration::ZERO);
        t.record(Fault::UpstreamTimeout, "x.test");
        t.record(Fault::UpstreamTimeout, "y.test");
        let s = t.record(Fault::UpstreamTimeout, "y.test").unwrap();
        assert!(
            s.contains("1 upstream timeouts, most often y.test (1)"),
            "{s}"
        );
    }
}

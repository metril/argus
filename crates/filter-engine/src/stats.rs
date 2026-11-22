//! Statistics tracking for filter engine

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Resource types tallied in `blocked_by_type`; fixed so the hot path is an array index.
const TYPES: [&str; 14] = [
    "document",
    "subdocument",
    "sub_frame",
    "script",
    "stylesheet",
    "image",
    "font",
    "media",
    "xhr",
    "fetch",
    "websocket",
    "ping",
    "object",
    "other",
];

/// Cap on distinct tracked domains, so hostile traffic cannot grow the map without bound.
const MAX_DOMAINS: usize = 10_000;

fn type_index(t: &str) -> usize {
    TYPES
        .iter()
        .position(|x| *x == t)
        .unwrap_or(TYPES.len() - 1)
}

/// Statistics for blocked and allowed requests
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockingStats {
    /// Total requests processed
    pub total_requests: u64,
    /// Requests blocked
    pub blocked_requests: u64,
    /// Requests allowed
    pub allowed_requests: u64,
    /// Requests blocked by type
    pub blocked_by_type: HashMap<String, u64>,
    /// Top blocked domains
    pub top_blocked_domains: Vec<(String, u64)>,
}

/// Thread-safe filter statistics tracker.
///
/// The hot path (`record_blocked`/`record_allowed`) is lock-free: totals are atomics and the
/// per-type / per-domain tallies use sharded `DashMap`s, so hundreds of concurrent worker threads
/// can record without serializing on a global lock. The (rare) `snapshot` does the sort/top-N.
#[derive(Debug, Clone)]
pub struct FilterStats {
    total_requests: Arc<AtomicU64>,
    blocked_requests: Arc<AtomicU64>,
    allowed_requests: Arc<AtomicU64>,
    blocked_by_type: Arc<[AtomicU64; TYPES.len()]>,
    blocked_domains: Arc<DashMap<String, u64>>,
}

impl Default for FilterStats {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterStats {
    /// Create a new statistics tracker
    pub fn new() -> Self {
        Self {
            total_requests: Arc::new(AtomicU64::new(0)),
            blocked_requests: Arc::new(AtomicU64::new(0)),
            allowed_requests: Arc::new(AtomicU64::new(0)),
            blocked_by_type: Arc::new(std::array::from_fn(|_| AtomicU64::new(0))),
            blocked_domains: Arc::new(DashMap::new()),
        }
    }

    /// Record a blocked request. Allocation-free except the first time a domain is seen.
    pub fn record_blocked(&self, resource_type: &str, domain: &str) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.blocked_requests.fetch_add(1, Ordering::Relaxed);
        self.blocked_by_type[type_index(resource_type)].fetch_add(1, Ordering::Relaxed);

        // Sharded map: look up by &str first (no allocation); only a new domain allocates.
        if let Some(mut v) = self.blocked_domains.get_mut(domain) {
            *v += 1;
        } else if self.blocked_domains.len() < MAX_DOMAINS {
            *self.blocked_domains.entry(domain.to_string()).or_insert(0) += 1;
        }
    }

    /// Record an allowed request
    pub fn record_allowed(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.allowed_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current statistics snapshot
    pub fn snapshot(&self) -> BlockingStats {
        let mut top_blocked: Vec<(String, u64)> = self
            .blocked_domains
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect();
        top_blocked.sort_by(|a, b| b.1.cmp(&a.1));
        top_blocked.truncate(10); // Top 10

        let blocked_by_type: HashMap<String, u64> = TYPES
            .iter()
            .zip(self.blocked_by_type.iter())
            .filter_map(|(t, c)| {
                let n = c.load(Ordering::Relaxed);
                (n > 0).then(|| (t.to_string(), n))
            })
            .collect();

        BlockingStats {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            blocked_requests: self.blocked_requests.load(Ordering::Relaxed),
            allowed_requests: self.allowed_requests.load(Ordering::Relaxed),
            blocked_by_type,
            top_blocked_domains: top_blocked,
        }
    }

    /// Reset all statistics
    pub fn reset(&self) {
        self.total_requests.store(0, Ordering::Relaxed);
        self.blocked_requests.store(0, Ordering::Relaxed);
        self.allowed_requests.store(0, Ordering::Relaxed);
        for c in self.blocked_by_type.iter() {
            c.store(0, Ordering::Relaxed);
        }
        self.blocked_domains.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_stats() {
        let stats = FilterStats::new();

        // Record some blocked requests
        stats.record_blocked("script", "ads.example.com");
        stats.record_blocked("image", "tracker.example.com");
        stats.record_blocked("script", "ads.example.com");

        // Record some allowed requests
        stats.record_allowed();
        stats.record_allowed();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.total_requests, 5);
        assert_eq!(snapshot.blocked_requests, 3);
        assert_eq!(snapshot.allowed_requests, 2);
        assert_eq!(snapshot.blocked_by_type.get("script"), Some(&2));
        assert_eq!(snapshot.blocked_by_type.get("image"), Some(&1));
        assert_eq!(snapshot.top_blocked_domains.len(), 2);
    }

    #[test]
    fn test_stats_reset() {
        let stats = FilterStats::new();
        stats.record_blocked("script", "ads.example.com");
        stats.record_allowed();

        stats.reset();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.total_requests, 0);
        assert_eq!(snapshot.blocked_requests, 0);
        assert_eq!(snapshot.allowed_requests, 0);
    }
}

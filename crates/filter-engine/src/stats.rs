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

/// Block counts by source key.
pub type SourceCounts = Vec<(String, u64)>;

/// Cap on distinct block sources (list ids, rule texts) awaiting attribution to a category.
const MAX_SOURCES: usize = 5_000;

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
    /// Blocks since the last [`FilterStats::take_sources`], by source list id.
    by_list: Arc<DashMap<String, u64>>,
    /// The same for blocks whose list is unknown, by matched rule text.
    by_rule: Arc<DashMap<String, u64>>,
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
            by_list: Arc::new(DashMap::new()),
            by_rule: Arc::new(DashMap::new()),
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

    /// [`Self::record_blocked`] that also remembers what blocked it (the source list, else the
    /// matched rule), so the blocks can later be attributed to list categories.
    pub fn record_blocked_by(
        &self,
        resource_type: &str,
        domain: &str,
        list_id: Option<&str>,
        rule: Option<&str>,
    ) {
        self.record_blocked(resource_type, domain);
        let (map, key) = match (list_id, rule) {
            (Some(l), _) => (&self.by_list, l),
            (None, Some(r)) if !r.is_empty() => (&self.by_rule, r),
            _ => return,
        };
        if let Some(mut v) = map.get_mut(key) {
            *v += 1;
        } else if map.len() < MAX_SOURCES {
            *map.entry(key.to_string()).or_insert(0) += 1;
        }
    }

    /// Hand over (and clear) the block sources tallied since the last call: `(by list id,
    /// by rule text)`.
    pub fn take_sources(&self) -> (SourceCounts, SourceCounts) {
        let drain = |m: &DashMap<String, u64>| -> Vec<(String, u64)> {
            let keys: Vec<String> = m.iter().map(|e| e.key().clone()).collect();
            keys.into_iter().filter_map(|k| m.remove(&k)).collect()
        };
        (drain(&self.by_list), drain(&self.by_rule))
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
        self.by_list.clear();
        self.by_rule.clear();
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
    fn block_sources_are_tallied_and_drained() {
        let stats = FilterStats::new();
        stats.record_blocked_by("script", "a.test", Some("easylist"), Some("||a.test^"));
        stats.record_blocked_by("script", "a.test", Some("easylist"), None);
        stats.record_blocked_by("image", "b.test", None, Some("||b.test^"));
        stats.record_blocked_by("image", "c.test", None, None);
        let (l, r) = stats.take_sources();
        assert_eq!(l, vec![("easylist".to_string(), 2)]);
        assert_eq!(r, vec![("||b.test^".to_string(), 1)]);
        assert_eq!(stats.take_sources(), (vec![], vec![]));
        assert_eq!(stats.snapshot().blocked_requests, 4);
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

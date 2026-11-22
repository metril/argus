//! Bounded, persisted audit log and the in-memory ring of recently blocked requests.
//!
//! The audit log never stores request bodies, cookies or tokens: only who/what/when/where and
//! the outcome. It is pruned by count and age whenever entries are appended.

use api_types::{AuditEntry, BlockedEntry};
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::ApiResult;

/// Filters for reading the audit log (all optional, ANDed).
#[derive(Debug, Default, Clone, Deserialize)]
pub struct AuditFilter {
    /// Actor id or name.
    pub actor: Option<String>,
    pub method: Option<String>,
    pub outcome: Option<String>,
    /// Substring of the route template.
    pub route: Option<String>,
    pub target: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

impl AuditFilter {
    fn matches(&self, e: &AuditEntry) -> bool {
        let at = DateTime::parse_from_rfc3339(&e.at).map(|t| t.with_timezone(&Utc));
        self.actor
            .as_ref()
            .is_none_or(|a| e.actor_id.as_deref() == Some(a) || e.actor_name.as_deref() == Some(a))
            && self
                .method
                .as_ref()
                .is_none_or(|m| e.method.eq_ignore_ascii_case(m))
            && self.outcome.as_ref().is_none_or(|o| &e.outcome == o)
            && self.route.as_ref().is_none_or(|r| e.route.contains(r))
            && self
                .target
                .as_ref()
                .is_none_or(|t| e.target.as_deref() == Some(t))
            && self
                .since
                .is_none_or(|s| at.as_ref().is_ok_and(|a| *a >= s))
            && self
                .until
                .is_none_or(|u| at.as_ref().is_ok_and(|a| *a <= u))
    }
}

/// Sled-backed append-only log keyed by a monotonically increasing id.
pub struct AuditStore {
    db: sled::Db,
    tree: sled::Tree,
    max_entries: usize,
    retention: Duration,
    since_prune: AtomicU64,
}

impl AuditStore {
    pub fn new(db: sled::Db, max_entries: usize, retention_days: u32) -> ApiResult<Self> {
        let tree = db.open_tree("audit")?;
        Ok(Self {
            db,
            tree,
            max_entries: max_entries.max(1),
            retention: Duration::days(retention_days.max(1) as i64),
            since_prune: AtomicU64::new(0),
        })
    }

    /// Append an entry (its `id` is assigned here).
    pub fn append(&self, mut entry: AuditEntry) -> ApiResult<()> {
        let id = self.db.generate_id()?;
        entry.id = format!("{id:016x}");
        self.tree
            .insert(id.to_be_bytes(), serde_json::to_vec(&entry)?)?;
        if self.since_prune.fetch_add(1, Ordering::Relaxed) % 128 == 127 {
            self.prune();
        }
        Ok(())
    }

    /// Drop entries beyond the count bound or older than the retention window.
    pub fn prune(&self) {
        let cutoff = Utc::now() - self.retention;
        while self.tree.len() > self.max_entries {
            if self.tree.pop_min().ok().flatten().is_none() {
                break;
            }
        }
        while let Ok(Some((k, v))) = self.tree.first() {
            let old = serde_json::from_slice::<AuditEntry>(&v)
                .ok()
                .and_then(|e| DateTime::parse_from_rfc3339(&e.at).ok())
                .is_some_and(|t| t.with_timezone(&Utc) < cutoff);
            if !old || self.tree.remove(k).is_err() {
                break;
            }
        }
    }

    /// Newest-first matching entries; returns `(page items, total matches)`.
    pub fn query(&self, f: &AuditFilter, offset: usize, limit: usize) -> (Vec<AuditEntry>, usize) {
        let mut total = 0usize;
        let mut items = Vec::new();
        for (_, v) in self.tree.iter().rev().flatten() {
            let Ok(e) = serde_json::from_slice::<AuditEntry>(&v) else {
                continue;
            };
            if !f.matches(&e) {
                continue;
            }
            if total >= offset && items.len() < limit {
                items.push(e);
            }
            total += 1;
        }
        (items, total)
    }

    pub fn len(&self) -> usize {
        self.tree.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }
}

/// Bounded ring of recently blocked requests.
///
/// The endpoint contract exists now; the filter engine has no observer hook yet, so nothing
/// calls [`RecentBlocked::push`] and the endpoint reports `available: false` until it does.
pub struct RecentBlocked {
    cap: usize,
    inner: Mutex<VecDeque<BlockedEntry>>,
    fed: std::sync::atomic::AtomicBool,
}

impl RecentBlocked {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            inner: Mutex::new(VecDeque::with_capacity(cap.min(1024))),
            fed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn push(&self, entry: BlockedEntry) {
        self.fed.store(true, Ordering::Relaxed);
        let mut q = self.inner.lock();
        if q.len() == self.cap {
            q.pop_front();
        }
        q.push_back(entry);
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    pub fn is_fed(&self) -> bool {
        self.fed.load(Ordering::Relaxed)
    }

    /// Newest first, at most `limit`.
    pub fn recent(&self, limit: usize) -> Vec<BlockedEntry> {
        self.inner
            .lock()
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(who: &str) -> AuditEntry {
        AuditEntry {
            id: String::new(),
            at: Utc::now().to_rfc3339(),
            actor_type: "user".into(),
            actor_id: None,
            actor_name: Some(who.into()),
            method: "POST".into(),
            route: "/api/v1/lists".into(),
            scope: "lists:write".into(),
            target: None,
            status: 200,
            outcome: "success".into(),
            ip: None,
            user_agent: None,
            request_id: None,
        }
    }

    #[test]
    fn bounded_and_filterable() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuditStore::new(sled::open(dir.path()).unwrap(), 3, 90).unwrap();
        for i in 0..5 {
            store.append(entry(&format!("u{i}"))).unwrap();
        }
        store.prune();
        assert_eq!(store.len(), 3);
        let (items, total) = store.query(&AuditFilter::default(), 0, 10);
        assert_eq!(total, 3);
        assert_eq!(items[0].actor_name.as_deref(), Some("u4"));
        let f = AuditFilter {
            actor: Some("u3".into()),
            ..Default::default()
        };
        assert_eq!(store.query(&f, 0, 10).1, 1);
    }

    #[test]
    fn ring_is_bounded() {
        let r = RecentBlocked::new(2);
        for i in 0..3 {
            r.push(BlockedEntry {
                time: String::new(),
                url: i.to_string(),
                source_url: None,
                resource_type: "x".into(),
                rule: None,
            });
        }
        let v = r.recent(10);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].url, "2");
    }
}

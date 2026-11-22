//! Bounded, persisted audit log.
//!
//! The audit log never stores request bodies, cookies or tokens: only who/what/when/where and
//! the outcome. It is pruned by count and age as entries are appended.

use api_types::AuditEntry;
use chrono::{DateTime, Duration, Utc};
use common::db::redb::{Durability, ReadableTable, ReadableTableMetadata, Table};
use common::db::{tables, Db, DbError};
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::error::{ApiError, ApiResult};

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

/// Append-only log keyed by a monotonically increasing id.
///
/// Appends are queued to the database's coalescing writer, so a burst of API calls becomes one
/// `Eventual` (no fsync) transaction and the request path never blocks on disk. Pruning (count
/// via the table's O(1) length, age by peeking the oldest key) runs inside that same transaction
/// and only touches the entries it removes, never the whole table.
pub struct AuditStore {
    db: Arc<Db>,
    next_id: AtomicU64,
    max_entries: usize,
    retention: Duration,
}

/// Trim `tb` to `max` entries and drop entries older than `cutoff`.
fn prune_table(
    tb: &mut Table<u64, &[u8]>,
    max: usize,
    cutoff: DateTime<Utc>,
) -> Result<(), DbError> {
    while tb.len()? as usize > max {
        if tb.pop_first()?.is_none() {
            break;
        }
    }
    loop {
        let old = match tb.first()? {
            Some((_, v)) => serde_json::from_slice::<AuditEntry>(v.value())
                .ok()
                .and_then(|e| DateTime::parse_from_rfc3339(&e.at).ok())
                .is_some_and(|t| t.with_timezone(&Utc) < cutoff),
            None => false,
        };
        if !old || tb.pop_first()?.is_none() {
            break;
        }
    }
    Ok(())
}

impl AuditStore {
    pub fn new(db: Arc<Db>, max_entries: usize, retention_days: u32) -> ApiResult<Self> {
        let last = db.read::<_, ApiError>(|r| {
            let t = r.open_table(tables::AUDIT).map_err(DbError::from)?;
            let last = t
                .last()
                .map_err(DbError::from)?
                .map(|(k, _)| k.value())
                .unwrap_or(0);
            Ok(last)
        })?;
        Ok(Self {
            db,
            next_id: AtomicU64::new(last + 1),
            max_entries: max_entries.max(1),
            retention: Duration::days(retention_days.max(1) as i64),
        })
    }

    /// Append an entry (its `id` is assigned here). Never blocks on disk.
    pub fn append(&self, mut entry: AuditEntry) -> ApiResult<()> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        entry.id = format!("{id:016x}");
        let bytes = serde_json::to_vec(&entry)?;
        let (max, cutoff) = (self.max_entries, Utc::now() - self.retention);
        self.db.defer(move |t| {
            let mut tb = t.open_table(tables::AUDIT)?;
            tb.insert(id, bytes.as_slice())?;
            prune_table(&mut tb, max, cutoff)
        });
        Ok(())
    }

    /// Drop entries beyond the count bound or older than the retention window, now.
    pub fn prune(&self) {
        self.db.flush_deferred();
        let (max, cutoff) = (self.max_entries, Utc::now() - self.retention);
        let res = self.db.write::<_, DbError>(Durability::Eventual, |t| {
            prune_table(&mut t.open_table(tables::AUDIT)?, max, cutoff)
        });
        if let Err(e) = res {
            tracing::error!("audit prune failed: {e}");
        }
    }

    /// Newest-first matching entries; returns `(page items, total matches)`.
    pub fn query(&self, f: &AuditFilter, offset: usize, limit: usize) -> (Vec<AuditEntry>, usize) {
        self.db.flush_deferred();
        let mut total = 0usize;
        let mut items = Vec::new();
        let res = self.db.read::<_, DbError>(|r| {
            let t = r.open_table(tables::AUDIT)?;
            for item in t.iter()?.rev() {
                let (_, v) = item?;
                let Ok(e) = serde_json::from_slice::<AuditEntry>(v.value()) else {
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
            Ok(())
        });
        if let Err(e) = res {
            tracing::error!("audit query failed: {e}");
        }
        (items, total)
    }

    pub fn len(&self) -> usize {
        self.db.flush_deferred();
        self.db
            .read::<_, DbError>(|r| Ok(r.open_table(tables::AUDIT)?.len()? as usize))
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

    fn store(max: usize, days: u32) -> (AuditStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = AuditStore::new(Db::open(dir.path()).unwrap(), max, days).unwrap();
        (s, dir)
    }

    #[test]
    fn bounded_and_filterable() {
        let (store, _d) = store(3, 90);
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
    fn count_bound_holds_without_explicit_prune() {
        let (store, _d) = store(4, 90);
        for i in 0..20 {
            store.append(entry(&format!("u{i}"))).unwrap();
        }
        assert_eq!(store.len(), 4);
        assert_eq!(
            store.query(&AuditFilter::default(), 0, 1).0[0]
                .actor_name
                .as_deref(),
            Some("u19")
        );
    }

    #[test]
    fn age_retention_drops_only_old_entries() {
        let (store, _d) = store(100, 30);
        let mut old = entry("old");
        old.at = (Utc::now() - Duration::days(31)).to_rfc3339();
        store.append(old).unwrap();
        store.append(entry("new")).unwrap();
        let (items, total) = store.query(&AuditFilter::default(), 0, 10);
        assert_eq!(total, 1);
        assert_eq!(items[0].actor_name.as_deref(), Some("new"));
    }

    #[test]
    fn ids_continue_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = AuditStore::new(Db::open(dir.path()).unwrap(), 10, 90).unwrap();
            s.append(entry("a")).unwrap();
            s.append(entry("b")).unwrap();
        }
        let s = AuditStore::new(Db::open(dir.path()).unwrap(), 10, 90).unwrap();
        s.append(entry("c")).unwrap();
        let (items, total) = s.query(&AuditFilter::default(), 0, 10);
        assert_eq!(total, 3);
        assert_eq!(items[0].actor_name.as_deref(), Some("c"));
        assert!(items[0].id > items[1].id);
    }

    #[test]
    fn concurrent_appends_are_all_recorded() {
        let (store, _d) = store(1000, 90);
        let store = Arc::new(store);
        let hs: Vec<_> = (0..4)
            .map(|t| {
                let s = store.clone();
                std::thread::spawn(move || {
                    for i in 0..25 {
                        s.append(entry(&format!("t{t}-{i}"))).unwrap();
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(store.len(), 100);
    }
}

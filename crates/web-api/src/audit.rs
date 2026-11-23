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
    /// Case-insensitive substring of `"METHOD route"`.
    pub action: Option<String>,
    /// Case-insensitive substring of actor, route, target or address.
    pub q: Option<String>,
}

fn has_ci(hay: &str, needle: &str) -> bool {
    hay.to_lowercase().contains(needle)
}

impl AuditFilter {
    fn is_empty(&self) -> bool {
        self.actor.is_none()
            && self.method.is_none()
            && self.outcome.is_none()
            && self.route.is_none()
            && self.target.is_none()
            && self.since.is_none()
            && self.until.is_none()
            && self.action.is_none()
            && self.q.is_none()
    }

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
            && self.action.as_ref().is_none_or(|a| {
                has_ci(
                    &format!("{} {}", e.method, e.route),
                    &a.trim().to_lowercase(),
                )
            })
            && self.q.as_ref().is_none_or(|q| {
                let q = q.trim().to_lowercase();
                [
                    e.actor_name.as_deref(),
                    e.actor_id.as_deref(),
                    Some(e.route.as_str()),
                    Some(e.method.as_str()),
                    e.target.as_deref(),
                    e.ip.as_deref(),
                ]
                .into_iter()
                .flatten()
                .any(|f| has_ci(f, &q))
            })
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
        self.db.defer_keep(move |t| {
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

    /// Newest-first matching entries; returns `(page items, total)`. The scan stops as soon as
    /// the page (plus one entry, to tell whether more follow) is filled or the entries are older
    /// than `since`, so it never reads the whole table. `total` is exact for an unfiltered
    /// query and otherwise the number of matches seen up to the stopping point (a lower bound
    /// that exceeds `offset + items.len()` exactly when more entries follow).
    pub fn query(&self, f: &AuditFilter, offset: usize, limit: usize) -> (Vec<AuditEntry>, usize) {
        let (items, total, _) = self.query_scanned(f, offset, limit);
        (items, total)
    }

    /// [`Self::query`] that also reports how many stored entries were examined.
    pub fn query_scanned(
        &self,
        f: &AuditFilter,
        offset: usize,
        limit: usize,
    ) -> (Vec<AuditEntry>, usize, usize) {
        /// Upper bound on entries examined by one query.
        const MAX_SCAN: usize = 100_000;
        self.db.flush_deferred();
        let unfiltered = f.is_empty();
        let mut seen = 0usize;
        let mut scanned = 0usize;
        let mut items = Vec::new();
        let res = self.db.read::<_, DbError>(|r| {
            let t = r.open_table(tables::AUDIT)?;
            for item in t.iter()?.rev() {
                let (_, v) = item?;
                scanned += 1;
                if scanned > MAX_SCAN {
                    break;
                }
                let Ok(e) = serde_json::from_slice::<AuditEntry>(v.value()) else {
                    continue;
                };
                // Ids grow with time: once entries are older than `since`, nothing newer follows.
                if let (Some(since), Ok(at)) = (f.since, DateTime::parse_from_rfc3339(&e.at)) {
                    if at.with_timezone(&Utc) < since {
                        break;
                    }
                }
                if !f.matches(&e) {
                    continue;
                }
                if seen >= offset && items.len() < limit {
                    items.push(e);
                }
                seen += 1;
                if seen > offset + limit {
                    break;
                }
            }
            Ok(())
        });
        if let Err(e) = res {
            tracing::error!("audit query failed: {e}");
        }
        let total = if unfiltered { self.len() } else { seen };
        (items, total, scanned)
    }

    /// Keyset form of [`Self::query`]: up to `limit` matching entries older than `before` (an
    /// entry id from [`Self::entry_key`]; `None` starts at the newest), plus whether more
    /// follow. Stable while entries are appended or pruned.
    pub fn query_before(
        &self,
        f: &AuditFilter,
        before: Option<u64>,
        limit: usize,
    ) -> (Vec<AuditEntry>, bool) {
        const MAX_SCAN: usize = 100_000;
        self.db.flush_deferred();
        let mut items = Vec::new();
        let mut more = false;
        let mut scanned = 0usize;
        let res = self.db.read::<_, DbError>(|r| {
            let t = r.open_table(tables::AUDIT)?;
            for item in t.range(0..before.unwrap_or(u64::MAX))?.rev() {
                let (_, v) = item?;
                scanned += 1;
                if scanned > MAX_SCAN {
                    break;
                }
                let Ok(e) = serde_json::from_slice::<AuditEntry>(v.value()) else {
                    continue;
                };
                if let (Some(since), Ok(at)) = (f.since, DateTime::parse_from_rfc3339(&e.at)) {
                    if at.with_timezone(&Utc) < since {
                        break;
                    }
                }
                if !f.matches(&e) {
                    continue;
                }
                if items.len() == limit {
                    more = true;
                    break;
                }
                items.push(e);
            }
            Ok(())
        });
        if let Err(e) = res {
            tracing::error!("audit query failed: {e}");
        }
        (items, more)
    }

    /// The numeric key of an entry id (`{:016x}`).
    pub fn entry_key(id: &str) -> Option<u64> {
        u64::from_str_radix(id, 16).ok()
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

    #[test]
    fn query_reads_only_what_the_page_needs() {
        let d = tempfile::tempdir().unwrap();
        let store = AuditStore::new(Db::open(d.path()).unwrap(), 10_000, 30).unwrap();
        for i in 0..2000 {
            let mut e = entry(if i % 2 == 0 { "even" } else { "odd" });
            e.at = (Utc::now() - Duration::minutes(2000 - i)).to_rfc3339();
            store.append(e).unwrap();
        }
        let (items, total, scanned) = store.query_scanned(&AuditFilter::default(), 0, 10);
        assert_eq!(items.len(), 10);
        assert_eq!(total, 2000);
        assert!(scanned <= 11, "scanned {scanned}");
        // A time bound stops the scan at the boundary instead of reading the older history.
        let f = AuditFilter {
            since: Some(Utc::now() - Duration::seconds(6030)),
            ..Default::default()
        };
        let (items, _, scanned) = store.query_scanned(&f, 0, 200);
        assert_eq!(items.len(), 100);
        assert!(scanned <= 102, "scanned {scanned}");
        // Filtered paging reports more-to-come through `total`.
        let f = AuditFilter {
            actor: Some("even".into()),
            ..Default::default()
        };
        let (items, total, _) = store.query_scanned(&f, 0, 5);
        assert_eq!(items.len(), 5);
        assert!(total > items.len());
    }
}

//! The single embedded database (redb) shared by every store in the process.
//!
//! One file, `<data_dir>/adblocker.redb`, is opened once per process (see [`Db::open`]); each
//! domain (lists, users, sessions, tokens, audit, userscripts) keeps a small typed store on top
//! of it. All table definitions live in [`tables`].
//!
//! Durability policy (redb commits are synchronous):
//! * `Immediate` (fsync) for control-plane changes whose loss would surprise a user: users,
//!   username index, sessions, API tokens, list definitions and custom rules, userscripts.
//! * `Eventual` (no fsync; persisted by the next immediate commit or on close) for data that is
//!   cheap to lose or rebuild: list status/reports/build summary, list content pointers, audit
//!   entries, `last_used_at`, GM values, session activity. Hot-path writers use the coalescing
//!   writer thread ([`Db::defer`]) so a burst of calls becomes one transaction.

use parking_lot::Mutex;
pub use redb;
use redb::{
    Database, Durability, ReadTransaction, ReadableTable, TableDefinition, WriteTransaction,
};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Weak};
use std::sync::{Condvar, Mutex as StdMutex};
use std::thread::JoinHandle;
use std::time::Duration;
use tracing::{error, warn};

/// File name of the database inside the data directory.
pub const FILE_NAME: &str = "adblocker.redb";
/// On-disk schema version written by this build.
pub const SCHEMA_VERSION: u32 = 1;

/// Typed table definitions (the only place tables are declared).
pub mod tables {
    use super::TableDefinition;

    /// Misc small values: `schema_version`, `custom_rules`, `build_summary`.
    pub const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
    /// list id -> JSON `FilterList`.
    pub const LISTS: TableDefinition<&str, &[u8]> = TableDefinition::new("lists");
    /// list id -> JSON `ListStatus`.
    pub const LIST_STATUS: TableDefinition<&str, &[u8]> = TableDefinition::new("list_status");
    /// list id (or custom-rules key) -> JSON `ListReport`.
    pub const LIST_REPORTS: TableDefinition<&str, &[u8]> = TableDefinition::new("list_reports");
    /// list id -> sha256 hex of its content blob.
    pub const LIST_CONTENT: TableDefinition<&str, &str> = TableDefinition::new("list_content");
    /// `<list id>\0<include path>` -> sha256 hex of the include blob.
    pub const LIST_INCLUDES: TableDefinition<&str, &str> = TableDefinition::new("list_includes");
    /// user id (uuid string) -> JSON user.
    pub const USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");
    /// username -> user id.
    pub const USERNAMES: TableDefinition<&str, &str> = TableDefinition::new("usernames");
    /// session id (uuid string) -> JSON session.
    pub const SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("sessions");
    /// token id -> JSON stored token.
    pub const API_TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("api_tokens");
    /// monotonically increasing id -> JSON audit entry.
    pub const AUDIT: TableDefinition<u64, &[u8]> = TableDefinition::new("audit");
    /// script id -> JSON userscript.
    pub const USERSCRIPTS: TableDefinition<&str, &[u8]> = TableDefinition::new("userscripts");
    /// `<script id>\0<name>` -> JSON GM value.
    pub const GM_VALUES: TableDefinition<&str, &[u8]> = TableDefinition::new("gm_values");
    /// `<profile>\0<rule id>` -> JSON script-policy site rule.
    pub const POLICY_SITE_RULES: TableDefinition<&str, &[u8]> =
        TableDefinition::new("policy_site_rules");
    /// `<profile>\0<rule id>` -> JSON script-policy source rule.
    pub const POLICY_SOURCE_RULES: TableDefinition<&str, &[u8]> =
        TableDefinition::new("policy_source_rules");
    /// `<profile>\0<grant id>` -> JSON persisted temporary grant.
    pub const POLICY_TEMP: TableDefinition<&str, &[u8]> = TableDefinition::new("policy_temp");
    /// `<profile>\0settings` -> JSON settings; `<profile>\0generation` -> u64 big endian.
    pub const POLICY_META: TableDefinition<&str, &[u8]> = TableDefinition::new("policy_meta");
}

/// Database error.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database error: {0}")]
    Storage(String),
    #[error(
        "database {path} has schema version {found}, newer than the supported {supported}; \
         upgrade the application or use a different data directory"
    )]
    NewerSchema {
        path: String,
        found: u32,
        supported: u32,
    },
}

macro_rules! from_redb {
    ($($t:ty),*) => {$(
        impl From<$t> for DbError {
            fn from(e: $t) -> Self { DbError::Storage(e.to_string()) }
        }
    )*};
}
from_redb!(
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError,
    std::io::Error
);

type Op = Box<dyn FnOnce(&WriteTransaction) -> Result<(), DbError> + Send>;

struct Queued {
    op: Op,
    /// Telemetry-type write that may be dropped (oldest first) when the queue is full.
    droppable: bool,
}

/// The deferred-write queue shared with the writer thread.
#[derive(Default)]
struct QueueState {
    ops: VecDeque<Queued>,
    /// Operations ever accepted (queued or dropped) / finished (committed, failed or dropped).
    accepted: u64,
    done: u64,
    /// `(accepted count to wait for, ack)`.
    waiters: Vec<(u64, Sender<()>)>,
    stop: bool,
}

struct Queue {
    state: StdMutex<QueueState>,
    wake: Condvar,
    dropped: AtomicU64,
    failed: AtomicU64,
}

impl Queue {
    fn lock(&self) -> std::sync::MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// Counters of the deferred-write queue, for the system metrics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeferredStats {
    /// Telemetry writes dropped because the queue was full.
    pub dropped: u64,
    /// Writes that failed (error or panic) or whose batch could not be committed.
    pub failed: u64,
    /// Writes waiting right now.
    pub queued: u64,
}

/// How long the writer thread waits for more work before committing a batch.
const COALESCE: Duration = Duration::from_millis(25);
const MAX_BATCH: usize = 1024;
/// Queue bound; beyond it the oldest droppable write is discarded.
pub const MAX_QUEUE: usize = 16 * 1024;

/// Handle to the process-wide database. Share via `Arc`.
pub struct Db {
    db: Arc<Database>,
    dir: PathBuf,
    queue: Arc<Queue>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

static REGISTRY: Mutex<Option<HashMap<PathBuf, Weak<Db>>>> = Mutex::new(None);

impl Db {
    /// Open (creating if needed) the database in `dir`, or return the handle already open for it
    /// in this process.
    pub fn open(dir: &Path) -> Result<Arc<Db>, DbError> {
        std::fs::create_dir_all(dir)?;
        let key = std::fs::canonicalize(dir)?;
        let mut reg = REGISTRY.lock();
        let map = reg.get_or_insert_with(HashMap::new);
        if let Some(db) = map.get(&key).and_then(Weak::upgrade) {
            return Ok(db);
        }
        map.retain(|_, w| w.strong_count() > 0);
        let db = Arc::new(Self::open_new(&key)?);
        map.insert(key, Arc::downgrade(&db));
        Ok(db)
    }

    fn open_new(dir: &Path) -> Result<Db, DbError> {
        warn_legacy_sled(dir);
        let path = dir.join(FILE_NAME);
        let database = Arc::new(Database::create(&path)?);
        init_schema(&database, &path)?;
        let queue = Arc::new(Queue {
            state: StdMutex::new(QueueState::default()),
            wake: Condvar::new(),
            dropped: AtomicU64::new(0),
            failed: AtomicU64::new(0),
        });
        let worker_db = database.clone();
        let worker_queue = queue.clone();
        let thread = std::thread::Builder::new()
            .name("db-writer".into())
            .spawn(move || writer_loop(worker_db, worker_queue))
            .map_err(|e| DbError::Storage(format!("spawn writer: {e}")))?;
        Ok(Db {
            db: database,
            dir: dir.to_path_buf(),
            queue,
            thread: Mutex::new(Some(thread)),
        })
    }

    /// The data directory holding the database file and the blob directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Size of the database file in bytes.
    pub fn file_size(&self) -> u64 {
        std::fs::metadata(self.dir.join(FILE_NAME))
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Run `f` in a read transaction (a consistent snapshot; never blocked by writers).
    pub fn read<T, E: From<DbError>>(
        &self,
        f: impl FnOnce(&ReadTransaction) -> Result<T, E>,
    ) -> Result<T, E> {
        let txn = self.db.begin_read().map_err(DbError::from)?;
        f(&txn)
    }

    /// Run `f` in a write transaction and commit with `durability`. If `f` fails nothing is
    /// written. Blocks (fsync when `Immediate`): call from `spawn_blocking` on async threads.
    pub fn write<T, E: From<DbError>>(
        &self,
        durability: Durability,
        f: impl FnOnce(&WriteTransaction) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut txn = self.db.begin_write().map_err(DbError::from)?;
        txn.set_durability(durability);
        let out = f(&txn)?;
        txn.commit().map_err(DbError::from)?;
        Ok(out)
    }

    /// Queue a telemetry-type write (last-used stamps, session activity) for the background
    /// writer, which coalesces everything queued within a few milliseconds into one `Eventual`
    /// transaction. Never blocks the caller. When the queue is full the oldest queued
    /// telemetry write is dropped and counted in [`Db::deferred_stats`].
    pub fn defer(&self, f: impl FnOnce(&WriteTransaction) -> Result<(), DbError> + Send + 'static) {
        self.enqueue(Box::new(f), true);
    }

    /// Like [`Db::defer`] for writes that must not be lost to back-pressure (audit entries,
    /// userscript values): never dropped, the queue simply grows.
    pub fn defer_keep(
        &self,
        f: impl FnOnce(&WriteTransaction) -> Result<(), DbError> + Send + 'static,
    ) {
        self.enqueue(Box::new(f), false);
    }

    fn enqueue(&self, op: Op, droppable: bool) {
        let q = &self.queue;
        let mut st = q.lock();
        if st.stop {
            return;
        }
        st.accepted += 1;
        if st.ops.len() >= MAX_QUEUE {
            // Make room by discarding the oldest droppable write (possibly the new one).
            if let Some(i) = st.ops.iter().position(|x| x.droppable) {
                st.ops.remove(i);
                st.done += 1;
                q.dropped.fetch_add(1, Ordering::Relaxed);
            } else if droppable {
                st.done += 1;
                q.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        st.ops.push_back(Queued { op, droppable });
        drop(st);
        q.wake.notify_one();
    }

    /// Drop and failure counters of the deferred-write queue.
    pub fn deferred_stats(&self) -> DeferredStats {
        DeferredStats {
            dropped: self.queue.dropped.load(Ordering::Relaxed),
            failed: self.queue.failed.load(Ordering::Relaxed),
            queued: self.queue.lock().ops.len() as u64,
        }
    }

    /// Wait until everything queued with [`Db::defer`] so far is committed.
    pub fn flush_deferred(&self) {
        let (ack_tx, ack_rx) = mpsc::channel();
        {
            let mut st = self.queue.lock();
            if st.done >= st.accepted || (st.stop && st.ops.is_empty()) {
                return;
            }
            let target = st.accepted;
            st.waiters.push((target, ack_tx));
        }
        self.queue.wake.notify_one();
        let _ = ack_rx.recv();
    }

    /// Flush queued writes and make every `Eventual` commit durable (fsync). Safe to call more
    /// than once; the database stays usable.
    pub fn sync(&self) {
        self.flush_deferred();
        if let Ok(mut txn) = self.db.begin_write() {
            txn.set_durability(Durability::Immediate);
            let _ = txn.commit();
        }
    }

    /// [`Db::sync`] every database open in this process. Call before exiting: relying on `Drop`
    /// order of `Arc`s held by aborted tasks is not enough.
    pub fn sync_all() {
        let dbs: Vec<Arc<Db>> = REGISTRY
            .lock()
            .as_ref()
            .map(|m| m.values().filter_map(Weak::upgrade).collect())
            .unwrap_or_default();
        for db in dbs {
            db.sync();
        }
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        self.queue.lock().stop = true;
        self.queue.wake.notify_all();
        if let Some(t) = self.thread.lock().take() {
            let _ = t.join();
        }
        // Persist anything committed with `Eventual` durability.
        if let Ok(mut txn) = self.db.begin_write() {
            txn.set_durability(Durability::Immediate);
            let _ = txn.commit();
        }
    }
}

fn writer_loop(db: Arc<Database>, q: Arc<Queue>) {
    loop {
        let mut batch: Vec<Queued> = Vec::new();
        {
            let mut st = q.lock();
            loop {
                if !st.ops.is_empty() || !st.waiters.is_empty() || st.stop {
                    break;
                }
                st = q.wake.wait(st).unwrap_or_else(|p| p.into_inner());
            }
            if st.ops.is_empty() && st.stop {
                for (_, a) in st.waiters.drain(..) {
                    let _ = a.send(());
                }
                return;
            }
            // Let a burst coalesce into one transaction.
            if !st.stop && st.waiters.is_empty() && st.ops.len() < MAX_BATCH {
                let (g, _) = q
                    .wake
                    .wait_timeout(st, COALESCE)
                    .unwrap_or_else(|p| p.into_inner());
                st = g;
            }
            while batch.len() < MAX_BATCH {
                match st.ops.pop_front() {
                    Some(o) => batch.push(o),
                    None => break,
                }
            }
        }
        let n = batch.len() as u64;
        if n > 0 {
            // A panic must never end the writer thread: later writes would be lost silently.
            let failures =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| commit_batch(&db, batch)))
                    .unwrap_or_else(|_| {
                        error!("deferred db batch panicked");
                        n
                    });
            q.failed.fetch_add(failures, Ordering::Relaxed);
        }
        let mut st = q.lock();
        st.done += n;
        let done = st.done;
        let (ready, rest): (Vec<_>, Vec<_>) = st.waiters.drain(..).partition(|(t, _)| *t <= done);
        st.waiters = rest;
        drop(st);
        for (_, a) in ready {
            let _ = a.send(());
        }
    }
}

/// Commit `batch` in one transaction; returns how many writes failed.
fn commit_batch(db: &Database, batch: Vec<Queued>) -> u64 {
    let mut failed = 0u64;
    let n = batch.len() as u64;
    let res = (|| -> Result<(), DbError> {
        let mut txn = db.begin_write()?;
        txn.set_durability(Durability::Eventual);
        for q in batch {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (q.op)(&txn)));
            match r {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    failed += 1;
                    error!("deferred db write failed: {e}");
                }
                Err(_) => {
                    failed += 1;
                    error!("deferred db write panicked");
                }
            }
        }
        txn.commit()?;
        Ok(())
    })();
    if let Err(e) = res {
        error!("deferred db commit failed: {e}");
        return n;
    }
    failed
}

fn init_schema(db: &Database, path: &Path) -> Result<(), DbError> {
    use tables::*;
    let mut txn = db.begin_write()?;
    txn.set_durability(Durability::Immediate);
    {
        // Create every table up front so read transactions never see a missing one.
        txn.open_table(LISTS)?;
        txn.open_table(LIST_STATUS)?;
        txn.open_table(LIST_REPORTS)?;
        txn.open_table(LIST_CONTENT)?;
        txn.open_table(LIST_INCLUDES)?;
        txn.open_table(USERS)?;
        txn.open_table(USERNAMES)?;
        txn.open_table(SESSIONS)?;
        txn.open_table(API_TOKENS)?;
        txn.open_table(AUDIT)?;
        txn.open_table(USERSCRIPTS)?;
        txn.open_table(GM_VALUES)?;
        txn.open_table(POLICY_SITE_RULES)?;
        txn.open_table(POLICY_SOURCE_RULES)?;
        txn.open_table(POLICY_TEMP)?;
        txn.open_table(POLICY_META)?;
        let mut meta = txn.open_table(META)?;
        let found = meta
            .get("schema_version")?
            .and_then(|v| <[u8; 4]>::try_from(v.value()).ok())
            .map(u32::from_be_bytes);
        match found {
            Some(v) if v > SCHEMA_VERSION => {
                return Err(DbError::NewerSchema {
                    path: path.display().to_string(),
                    found: v,
                    supported: SCHEMA_VERSION,
                });
            }
            Some(_) => {}
            None => {
                meta.insert("schema_version", SCHEMA_VERSION.to_be_bytes().as_slice())?;
            }
        }
    }
    txn.commit()?;
    Ok(())
}

/// Old builds used sled directories (`conf` + `db` files). Ignore them, naming what to delete.
fn warn_legacy_sled(dir: &Path) {
    let is_sled = |p: &Path| p.join("conf").is_file() && p.join("db").is_file();
    let mut found = Vec::new();
    if is_sled(dir) {
        found.push(dir.to_path_buf());
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() && is_sled(&p) {
                found.push(p);
            }
        }
    }
    for p in found {
        warn!(
            "ignoring legacy sled database at {} (no longer used; safe to delete)",
            p.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::ReadableTableMetadata;

    fn count(db: &Db) -> u64 {
        db.read::<_, DbError>(|r| Ok(r.open_table(tables::AUDIT)?.len()?))
            .unwrap()
    }

    fn put(db: &Db, k: u64) -> Result<(), DbError> {
        db.write::<_, DbError>(Durability::Immediate, |t| {
            t.open_table(tables::AUDIT)?.insert(k, b"x".as_slice())?;
            Ok(())
        })
    }

    fn put_deferred(db: &Db, k: u64) {
        db.defer(move |t| {
            t.open_table(tables::AUDIT)?.insert(k, b"x".as_slice())?;
            Ok(())
        });
    }

    #[test]
    fn panicking_deferred_write_does_not_kill_the_writer() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(d.path()).unwrap();
        db.defer(|_| panic!("boom"));
        put_deferred(&db, 1);
        db.flush_deferred();
        assert_eq!(count(&db), 1);
        // Later writes still land.
        put_deferred(&db, 2);
        db.flush_deferred();
        assert_eq!(count(&db), 2);
        assert!(db.deferred_stats().failed >= 1);
    }

    #[test]
    fn failing_deferred_write_is_counted() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(d.path()).unwrap();
        db.defer(|_| Err(DbError::Storage("nope".into())));
        put_deferred(&db, 1);
        db.flush_deferred();
        assert_eq!(db.deferred_stats().failed, 1);
        assert_eq!(count(&db), 1);
    }

    /// Block the writer thread inside a deferred op until the returned sender is used.
    fn stall_writer(db: &Db) -> Sender<()> {
        let (started_tx, started_rx) = mpsc::channel();
        let (gate_tx, gate_rx) = mpsc::channel::<()>();
        db.defer_keep(move |_| {
            let _ = started_tx.send(());
            let _ = gate_rx.recv();
            Ok(())
        });
        started_rx.recv().unwrap();
        gate_tx
    }

    #[test]
    fn full_queue_drops_oldest_telemetry_and_counts_it() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(d.path()).unwrap();
        let gate = stall_writer(&db);
        let extra = 10u64;
        for k in 0..MAX_QUEUE as u64 + extra {
            put_deferred(&db, k);
        }
        assert_eq!(db.deferred_stats().dropped, extra);
        assert_eq!(db.deferred_stats().queued, MAX_QUEUE as u64);
        gate.send(()).unwrap();
        db.flush_deferred();
        assert_eq!(count(&db), MAX_QUEUE as u64);
        // The oldest were the ones discarded.
        let first = db
            .read::<_, DbError>(|r| {
                Ok(r.open_table(tables::AUDIT)?
                    .first()?
                    .map(|(k, _)| k.value()))
            })
            .unwrap();
        assert_eq!(first, Some(extra));
    }

    #[test]
    fn keep_writes_are_never_dropped() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(d.path()).unwrap();
        let gate = stall_writer(&db);
        let n = MAX_QUEUE as u64 + 50;
        for k in 0..n {
            db.defer_keep(move |t| {
                t.open_table(tables::AUDIT)?.insert(k, b"x".as_slice())?;
                Ok(())
            });
        }
        // A droppable write on a full queue of keepers is the one discarded.
        put_deferred(&db, n + 1);
        assert_eq!(db.deferred_stats().dropped, 1);
        gate.send(()).unwrap();
        db.flush_deferred();
        assert_eq!(count(&db), n);
    }

    #[test]
    fn sync_all_commits_queued_writes_before_exit() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(d.path()).unwrap();
        let gate = stall_writer(&db);
        for k in 0..100 {
            put_deferred(&db, k);
        }
        // Not yet committed: the writer is stalled.
        assert_eq!(count(&db), 0);
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            gate.send(()).unwrap();
        });
        Db::sync_all();
        release.join().unwrap();
        assert_eq!(count(&db), 100, "sync_all must drain the deferred queue");
    }

    #[test]
    fn open_is_shared_and_reopens() {
        let d = tempfile::tempdir().unwrap();
        let a = Db::open(d.path()).unwrap();
        let b = Db::open(d.path()).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        put(&a, 1).unwrap();
        drop((a, b));
        let c = Db::open(d.path()).unwrap();
        assert_eq!(count(&c), 1);
    }

    #[test]
    fn failed_write_is_not_visible() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(d.path()).unwrap();
        let r = db.write::<(), DbError>(Durability::Immediate, |t| {
            t.open_table(tables::AUDIT)?.insert(1u64, b"x".as_slice())?;
            Err(DbError::Storage("boom".into()))
        });
        assert!(r.is_err());
        assert_eq!(count(&db), 0);
    }

    #[test]
    fn deferred_writes_coalesce_and_flush() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(d.path()).unwrap();
        for i in 0..50u64 {
            db.defer(move |t| {
                t.open_table(tables::AUDIT)?.insert(i, b"x".as_slice())?;
                Ok(())
            });
        }
        db.flush_deferred();
        assert_eq!(count(&db), 50);
        drop(db);
        assert_eq!(count(&Db::open(d.path()).unwrap()), 50);
    }

    #[test]
    fn readers_see_snapshot_during_write() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(d.path()).unwrap();
        let rtxn = db.db.begin_read().unwrap();
        put(&db, 1).unwrap();
        // The earlier snapshot is unaffected; a fresh reader sees the commit.
        assert_eq!(
            rtxn.open_table(tables::AUDIT)
                .unwrap()
                .iter()
                .unwrap()
                .count(),
            0
        );
        assert_eq!(count(&db), 1);
    }

    #[test]
    fn rejects_newer_schema() {
        let d = tempfile::tempdir().unwrap();
        {
            let db = Db::open(d.path()).unwrap();
            db.write::<_, DbError>(Durability::Immediate, |t| {
                t.open_table(tables::META)?
                    .insert("schema_version", 99u32.to_be_bytes().as_slice())?;
                Ok(())
            })
            .unwrap();
        }
        let err = Db::open(d.path()).err().unwrap();
        assert!(
            matches!(err, DbError::NewerSchema { found: 99, .. }),
            "{err}"
        );
    }

    #[test]
    fn legacy_sled_dir_is_ignored() {
        let d = tempfile::tempdir().unwrap();
        let old = d.path().join("lists");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("conf"), b"x").unwrap();
        std::fs::write(old.join("db"), b"x").unwrap();
        assert!(Db::open(d.path()).is_ok());
    }
}

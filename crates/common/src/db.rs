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

pub use redb;
use parking_lot::Mutex;
use redb::{
    Database, Durability, ReadTransaction, ReadableTable, TableDefinition, WriteTransaction,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Weak};
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

enum Msg {
    Op(Op),
    Flush(Sender<()>),
    Stop,
}

/// How long the writer thread waits for more work before committing a batch.
const COALESCE: Duration = Duration::from_millis(25);
const MAX_BATCH: usize = 1024;

/// Handle to the process-wide database. Share via `Arc`.
pub struct Db {
    db: Arc<Database>,
    dir: PathBuf,
    tx: Mutex<Option<Sender<Msg>>>,
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
        let (tx, rx) = mpsc::channel();
        let worker_db = database.clone();
        let thread = std::thread::Builder::new()
            .name("db-writer".into())
            .spawn(move || writer_loop(worker_db, rx))
            .map_err(|e| DbError::Storage(format!("spawn writer: {e}")))?;
        Ok(Db {
            db: database,
            dir: dir.to_path_buf(),
            tx: Mutex::new(Some(tx)),
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

    /// Queue a write for the background writer, which coalesces everything queued within a few
    /// milliseconds into one `Eventual` transaction. Never blocks the caller.
    pub fn defer(&self, f: impl FnOnce(&WriteTransaction) -> Result<(), DbError> + Send + 'static) {
        if let Some(tx) = self.tx.lock().as_ref() {
            let _ = tx.send(Msg::Op(Box::new(f)));
        }
    }

    /// Wait until everything queued with [`Db::defer`] so far is committed.
    pub fn flush_deferred(&self) {
        let (ack_tx, ack_rx) = mpsc::channel();
        let sent = self
            .tx
            .lock()
            .as_ref()
            .is_some_and(|tx| tx.send(Msg::Flush(ack_tx)).is_ok());
        if sent {
            let _ = ack_rx.recv();
        }
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.lock().take() {
            let _ = tx.send(Msg::Stop);
        }
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

fn writer_loop(db: Arc<Database>, rx: Receiver<Msg>) {
    let mut stop = false;
    while !stop {
        let Ok(first) = rx.recv() else { return };
        let mut ops: Vec<Op> = Vec::new();
        let mut acks: Vec<Sender<()>> = Vec::new();
        let mut next = Some(first);
        while let Some(m) = next.take() {
            match m {
                Msg::Op(op) => ops.push(op),
                Msg::Flush(a) => {
                    acks.push(a);
                    break;
                }
                Msg::Stop => {
                    stop = true;
                    break;
                }
            }
            if ops.len() >= MAX_BATCH {
                break;
            }
            next = rx.recv_timeout(COALESCE).ok();
        }
        if !ops.is_empty() {
            commit_batch(&db, ops);
        }
        for a in acks {
            let _ = a.send(());
        }
    }
}

fn commit_batch(db: &Database, ops: Vec<Op>) {
    let res = (|| -> Result<(), DbError> {
        let mut txn = db.begin_write()?;
        txn.set_durability(Durability::Eventual);
        for op in ops {
            if let Err(e) = op(&txn) {
                error!("deferred db write failed: {e}");
            }
        }
        txn.commit()?;
        Ok(())
    })();
    if let Err(e) = res {
        error!("deferred db commit failed: {e}");
    }
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
        assert_eq!(rtxn.open_table(tables::AUDIT).unwrap().iter().unwrap().count(), 0);
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
        assert!(matches!(err, DbError::NewerSchema { found: 99, .. }), "{err}");
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

//! Persisted request / block history: lifetime totals and per-day buckets by category, kept for
//! [`RETENTION_DAYS`] days in `stats-history.json` next to the filter data. Fed by the same
//! sampler as the in-memory [`crate::timeseries::Timeseries`]; written on a timer and at
//! shutdown, so a restart keeps the history (the engine's own counters start at zero again).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{Datelike, TimeZone, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// Days of daily buckets kept.
pub const RETENTION_DAYS: i64 = 400;
/// Category names, in the order of the count arrays.
pub const CATEGORIES: [&str; 6] = [
    "ads",
    "trackers",
    "social",
    "annoyances",
    "security",
    "other",
];
pub const OTHER: usize = 5;
const DAY: i64 = 86_400;

pub type Counts = [u64; 6];

/// Index of the category a catalogue `category` string belongs to.
pub fn category_index(catalogue_category: &str) -> usize {
    match catalogue_category.trim().to_ascii_lowercase().as_str() {
        "ads" | "ad" | "advertising" | "adverts" => 0,
        "privacy" | "tracking" | "trackers" | "tracker" | "analytics" => 1,
        "social" | "social-media" => 2,
        "annoyances" | "annoyance" | "cookies" | "cookie" | "popups" => 3,
        "malware" | "phishing" | "security" | "scam" | "threats" => 4,
        _ => OTHER,
    }
}

fn add(into: &mut Counts, from: &Counts) {
    for (a, b) in into.iter_mut().zip(from) {
        *a += b;
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Day {
    pub total: u64,
    pub blocked: u64,
    pub cats: Counts,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Data {
    lifetime_total: u64,
    lifetime_blocked: u64,
    lifetime_cats: Counts,
    /// Days since the Unix epoch (UTC).
    days: BTreeMap<i64, Day>,
}

#[derive(Default)]
struct Inner {
    data: Data,
    /// Counter values at the previous sample.
    last: Option<(u64, u64)>,
    reset: bool,
    dirty: bool,
}

/// One bucket of [`DailyStats::days`] / [`DailyStats::months`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    /// Start of the day or month, Unix seconds (UTC).
    pub ts: i64,
    pub requests: u64,
    pub blocked: u64,
    pub cats: Counts,
}

pub struct DailyStats {
    path: Option<PathBuf>,
    inner: Mutex<Inner>,
}

impl DailyStats {
    /// Load the history at `path` (none or unreadable: empty). Without a path nothing is saved.
    pub fn open(path: Option<PathBuf>) -> Self {
        let data = path.as_deref().map(load).unwrap_or_default();
        Self {
            path,
            inner: Mutex::new(Inner {
                data,
                // The engine's counters start at zero with the process: nothing is lost before
                // the first sample.
                last: Some((0, 0)),
                ..Default::default()
            }),
        }
    }

    /// Add the growth of the running counters since the previous sample to today's bucket and
    /// the lifetime totals. `read` returns `(total, blocked)` and runs under the lock (see
    /// [`crate::timeseries::Timeseries::sample`]); `cats` are the blocks of the same period by
    /// category (blocks they do not explain count as `other`).
    pub fn sample(&self, now: i64, read: impl FnOnce() -> (u64, u64), cats: Counts) {
        let mut g = self.inner.lock();
        let (total, blocked) = read();
        let reset = std::mem::take(&mut g.reset);
        let Some((lt, lb)) = g.last else {
            g.last = Some((total, blocked));
            return;
        };
        if (total < lt || blocked < lb) && !reset {
            return;
        }
        g.last = Some((total, blocked));
        let dt = if total >= lt { total - lt } else { total };
        let db = if blocked >= lb { blocked - lb } else { blocked };
        let mut c = cats;
        let known: u64 = c.iter().sum();
        if db > known {
            c[OTHER] += db - known;
        }
        if dt == 0 && db == 0 {
            return;
        }
        let day = now.div_euclid(DAY);
        let d = g.data.days.entry(day).or_default();
        d.total += dt;
        d.blocked += db;
        add(&mut d.cats, &c);
        g.data.lifetime_total += dt;
        g.data.lifetime_blocked += db;
        add(&mut g.data.lifetime_cats, &c);
        let oldest = day - RETENTION_DAYS;
        g.data.days.retain(|k, _| *k > oldest);
        g.dirty = true;
    }

    /// The counters are about to be (or were just) reset: the next lower reading is genuine.
    pub fn note_reset(&self) {
        self.inner.lock().reset = true;
    }

    /// `(total, blocked, blocked by category)` since the first start.
    pub fn lifetime(&self) -> (u64, u64, Counts) {
        let g = self.inner.lock();
        (
            g.data.lifetime_total,
            g.data.lifetime_blocked,
            g.data.lifetime_cats,
        )
    }

    /// The last `n` UTC days, oldest first, ending with the one containing `now` (empty days
    /// included).
    pub fn days(&self, now: i64, n: i64) -> Vec<Point> {
        let g = self.inner.lock();
        let today = now.div_euclid(DAY);
        (0..n)
            .map(|i| {
                let day = today - (n - 1 - i);
                let d = g.data.days.get(&day).copied().unwrap_or_default();
                Point {
                    ts: day * DAY,
                    requests: d.total,
                    blocked: d.blocked,
                    cats: d.cats,
                }
            })
            .collect()
    }

    /// The last `n` calendar months (UTC), oldest first, ending with the current one.
    pub fn months(&self, now: i64, n: i64) -> Vec<Point> {
        let g = self.inner.lock();
        let cur = Utc.timestamp_opt(now, 0).single().unwrap_or_default();
        let mut idx = cur.year() as i64 * 12 + cur.month0() as i64;
        let mut out = Vec::new();
        for _ in 0..n {
            let (y, m) = ((idx.div_euclid(12)) as i32, idx.rem_euclid(12) as u32 + 1);
            let start = Utc.with_ymd_and_hms(y, m, 1, 0, 0, 0).single();
            let end = Utc
                .with_ymd_and_hms(y + (m == 12) as i32, m % 12 + 1, 1, 0, 0, 0)
                .single();
            let mut p = Point {
                ts: start.map_or(0, |s| s.timestamp()),
                requests: 0,
                blocked: 0,
                cats: [0; 6],
            };
            if let (Some(s), Some(e)) = (start, end) {
                for (_, d) in g
                    .data
                    .days
                    .range(s.timestamp().div_euclid(DAY)..e.timestamp().div_euclid(DAY))
                {
                    p.requests += d.total;
                    p.blocked += d.blocked;
                    add(&mut p.cats, &d.cats);
                }
            }
            out.push(p);
            idx -= 1;
        }
        out.reverse();
        out
    }

    /// Write the history if it changed (atomically: temp file, then rename).
    pub fn flush(&self) {
        let Some(path) = &self.path else { return };
        let bytes = {
            let mut g = self.inner.lock();
            if !g.dirty {
                return;
            }
            g.dirty = false;
            match serde_json::to_vec(&g.data) {
                Ok(b) => b,
                Err(_) => return,
            }
        };
        if let Err(e) = write_durably(path, &bytes) {
            tracing::warn!("could not save {}: {e}", path.display());
            self.inner.lock().dirty = true;
        }
    }
}

fn side_path(path: &Path, suffix: &str) -> PathBuf {
    let mut n = path.as_os_str().to_owned();
    n.push(suffix);
    PathBuf::from(n)
}

fn parse(bytes: &[u8]) -> Option<Data> {
    serde_json::from_slice::<Data>(bytes).ok()
}

/// Read the history. A file that does not parse is renamed to `.corrupt-<unix time>` (never
/// overwritten by the next save) and the last good copy (`.bak`) is tried instead.
fn load(path: &Path) -> Data {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // A save interrupted between its two renames leaves only the backup.
            return std::fs::read(side_path(path, ".bak"))
                .ok()
                .and_then(|b| parse(&b))
                .unwrap_or_default();
        }
        Err(e) => {
            tracing::warn!("could not read {}: {e}", path.display());
            return Data::default();
        }
    };
    if let Some(d) = parse(&bytes) {
        return d;
    }
    let moved = side_path(
        path,
        &format!(".corrupt-{}", chrono::Utc::now().timestamp()),
    );
    match std::fs::rename(path, &moved) {
        Ok(()) => tracing::warn!(
            "{} is not valid; kept as {} and starting from the last good copy",
            path.display(),
            moved.display()
        ),
        Err(e) => tracing::warn!(
            "{} is not valid and could not be moved: {e}",
            path.display()
        ),
    }
    std::fs::read(side_path(path, ".bak"))
        .ok()
        .and_then(|b| parse(&b))
        .unwrap_or_default()
}

/// Write `bytes` to `path`: temp file, fsync, the previous file kept as `.bak`, rename, fsync of
/// the directory.
fn write_durably(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    if let Some(d) = dir {
        std::fs::create_dir_all(d)?;
    }
    let tmp = side_path(path, ".tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if path.exists() {
        // The file being replaced parsed when it was loaded or written: it is the last good one.
        let bak = side_path(path, ".bak");
        let _ = std::fs::remove_file(&bak);
        if std::fs::hard_link(path, &bak).is_err() {
            let _ = std::fs::copy(path, &bak);
        }
    }
    std::fs::rename(&tmp, path)?;
    if let Ok(d) = std::fs::File::open(dir.unwrap_or(Path::new("."))) {
        let _ = d.sync_all();
    }
    Ok(())
}

impl Drop for DailyStats {
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_map_from_the_catalogue() {
        assert_eq!(category_index("ads"), 0);
        assert_eq!(category_index("Privacy"), 1);
        assert_eq!(category_index("social"), 2);
        assert_eq!(category_index("annoyances"), 3);
        assert_eq!(category_index("malware"), 4);
        assert_eq!(category_index("regional"), OTHER);
    }

    #[test]
    fn daily_buckets_by_category_with_remainder_as_other() {
        let s = DailyStats::open(None);
        let t = 1_700_000_000;
        s.sample(t + 5, || (50, 8), [5, 2, 0, 0, 0, 0]);
        s.sample(t + DAY + 5, || (60, 10), [0, 0, 2, 0, 0, 0]);
        let d = s.days(t + DAY + 5, 3);
        assert_eq!(d[0].requests, 0);
        assert_eq!((d[1].requests, d[1].blocked), (50, 8));
        assert_eq!(d[1].cats, [5, 2, 0, 0, 0, 1]);
        assert_eq!((d[2].requests, d[2].blocked), (10, 2));
        assert_eq!(s.lifetime(), (60, 10, [5, 2, 2, 0, 0, 1]));
        let m = s.months(t + DAY, 2);
        assert_eq!(m.iter().map(|p| p.requests).sum::<u64>(), 60);
        // A lower reading without a reset is stale; after a reset it counts from zero.
        s.sample(t + DAY + 6, || (3, 0), [0; 6]);
        assert_eq!(s.lifetime().0, 60);
        s.note_reset();
        s.sample(t + DAY + 7, || (7, 1), [0; 6]);
        assert_eq!(s.lifetime(), (67, 11, [5, 2, 2, 0, 0, 2]));
    }

    #[test]
    fn history_survives_a_reopen_and_old_days_are_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats-history.json");
        let t = 1_700_000_000;
        {
            let s = DailyStats::open(Some(path.clone()));
            s.sample(t + 1, || (40, 4), [4, 0, 0, 0, 0, 0]);
            s.flush();
        }
        let s = DailyStats::open(Some(path.clone()));
        assert_eq!(s.lifetime(), (40, 4, [4, 0, 0, 0, 0, 0]));
        assert_eq!(s.days(t, 1)[0].blocked, 4);
        // Dropping flushes too.
        s.sample(t + 3, || (10, 1), [0; 6]); // a new process counts from zero again
        drop(s);
        assert_eq!(DailyStats::open(Some(path.clone())).lifetime().0, 50);
        // Days beyond the retention fall away.
        let s = DailyStats::open(Some(path));
        let later = t + (RETENTION_DAYS + 5) * DAY;
        s.sample(later + 1, || (1, 0), [0; 6]);
        assert_eq!(s.days(t, 1)[0].requests, 0);
        assert_eq!(s.lifetime().0, 51);
    }

    #[test]
    fn a_corrupt_file_is_set_aside_and_the_last_good_copy_is_used() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats-history.json");
        let t = 1_700_000_000;
        {
            let s = DailyStats::open(Some(path.clone()));
            s.sample(t, || (10, 2), [2, 0, 0, 0, 0, 0]);
            s.flush();
            s.sample(t + 1, || (30, 5), [5, 0, 0, 0, 0, 0]);
            s.flush(); // the first save is now the backup
        }
        assert!(side_path(&path, ".bak").exists());
        std::fs::write(&path, b"{ not json").unwrap();
        let s = DailyStats::open(Some(path.clone()));
        // The backup holds the previous save (10 requests), not nothing.
        assert_eq!(s.lifetime().0, 10);
        let corrupt: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
            .collect();
        assert_eq!(corrupt.len(), 1);
        assert_eq!(std::fs::read(corrupt[0].path()).unwrap(), b"{ not json");
        // Saving again does not touch the set-aside file.
        s.sample(t + 2, || (5, 0), [0; 6]);
        s.flush();
        assert_eq!(std::fs::read(corrupt[0].path()).unwrap(), b"{ not json");
        assert!(DailyStats::open(Some(path)).lifetime().0 >= 10);
    }
}

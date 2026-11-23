//! Request / block counts over time, kept in a bounded in-memory ring of 30-minute buckets
//! (7 days). Not persisted: a restart starts the history again.

use std::collections::VecDeque;

use parking_lot::Mutex;

pub const BUCKET_SECS: i64 = 1800;
/// 7 days of 30-minute buckets, plus one for the current period.
const CAPACITY: usize = 7 * 48 + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bucket {
    /// Start of the bucket, Unix seconds.
    pub ts: i64,
    pub requests: u64,
    pub blocked: u64,
}

#[derive(Default)]
struct Inner {
    buckets: VecDeque<Bucket>,
    /// Counter values at the previous sample.
    last: Option<(u64, u64)>,
    /// The counters were reset since the last sample (a lower total is then genuine).
    reset: bool,
}

#[derive(Default)]
pub struct Timeseries {
    inner: Mutex<Inner>,
}

impl Timeseries {
    /// Record the running totals at `now` (Unix seconds). The first call only sets the baseline;
    /// later calls add the growth since the previous one to the bucket `now` falls in. A counter
    /// that went backwards (stats were reset) counts from zero.
    ///
    /// `read` returns `(total, blocked)` and runs while the series is locked, so concurrent
    /// samples are ordered like the counters they read. A total that went down without
    /// [`Self::note_reset`] having been called is ignored (it is a stale read, not a reset).
    pub fn sample(&self, now: i64, read: impl FnOnce() -> (u64, u64)) {
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
        let ts = now - now.rem_euclid(BUCKET_SECS);
        // Fill quiet periods with empty buckets so the series is continuous.
        let mut next = g.buckets.back().map_or(ts, |b| b.ts + BUCKET_SECS);
        while next <= ts {
            g.buckets.push_back(Bucket {
                ts: next,
                requests: 0,
                blocked: 0,
            });
            next += BUCKET_SECS;
        }
        while g.buckets.len() > CAPACITY {
            g.buckets.pop_front();
        }
        if let Some(b) = g.buckets.iter_mut().rev().find(|b| b.ts == ts) {
            b.requests += dt;
            b.blocked += db;
        }
    }

    /// The counters are about to be (or were just) reset: the next lower reading is genuine.
    pub fn note_reset(&self) {
        self.inner.lock().reset = true;
    }

    /// `n` buckets of `step` seconds ending with the one containing `now` (empty ones included).
    pub fn series(&self, now: i64, step: i64, n: i64) -> Vec<Bucket> {
        let g = self.inner.lock();
        let end = now - now.rem_euclid(step);
        (0..n)
            .map(|i| {
                let ts = end - (n - 1 - i) * step;
                let (requests, blocked) = g
                    .buckets
                    .iter()
                    .filter(|b| b.ts >= ts && b.ts < ts + step)
                    .fold((0, 0), |(r, k), b| (r + b.requests, k + b.blocked));
                Bucket {
                    ts,
                    requests,
                    blocked,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deltas_land_in_their_bucket_and_gaps_are_filled() {
        let t = Timeseries::default();
        let base = 1_000_000 - 1_000_000 % BUCKET_SECS;
        t.sample(base + 10, || (100, 10)); // baseline only
        t.sample(base + 20, || (150, 12));
        t.sample(base + BUCKET_SECS * 3 + 5, || (160, 12));
        let s = t.series(base + BUCKET_SECS * 3 + 5, BUCKET_SECS, 4);
        let got: Vec<_> = s.iter().map(|b| (b.requests, b.blocked)).collect();
        assert_eq!(got, [(50, 2), (0, 0), (0, 0), (10, 0)]);
        // A lower reading without a reset is a stale read and changes nothing.
        t.sample(base + BUCKET_SECS * 3 + 7, || (3, 0));
        assert_eq!(
            t.series(base + BUCKET_SECS * 3, BUCKET_SECS, 1)[0].requests,
            10
        );
        // After a reset the counter counts from zero.
        t.note_reset();
        t.sample(base + BUCKET_SECS * 3 + 9, || (7, 1));
        assert_eq!(
            t.series(base + BUCKET_SECS * 3, BUCKET_SECS, 1)[0].requests,
            17
        );
        // Coarser steps aggregate.
        let six = t.series(base + BUCKET_SECS * 3, BUCKET_SECS * 12, 1);
        assert_eq!(six[0].requests, 67);
    }
}

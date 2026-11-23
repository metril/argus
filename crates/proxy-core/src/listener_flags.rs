//! Per-listener switches (MITM, HTTP/2, WebSockets, ad blocking), swappable while the proxy runs.
//!
//! Each listener (explicit and transparent) owns one [`ListenerFlags`]; every connection it
//! accepts carries a handle, so a change applies to the next request without a restart.

use common::config::ListenerFlagValues;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a client counts as "connected" after its last connection.
const CLIENT_WINDOW: Duration = Duration::from_secs(300);
/// Most distinct clients tracked (a flood of sources cannot grow it without bound).
const MAX_CLIENTS: usize = 10_000;
/// Rate window: the request rate is measured over at least this span.
const RATE_WINDOW: Duration = Duration::from_secs(5);

/// Live traffic counters of one listener.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ListenerCounters {
    pub active_connections: u64,
    pub requests_per_sec: f64,
    /// Distinct client addresses seen in the last 5 minutes.
    pub clients: u64,
}

/// A request count at a point in time.
type Sample = (Instant, u64);

#[derive(Debug, Default)]
struct Traffic {
    active: AtomicU64,
    requests: AtomicU64,
    clients: parking_lot::Mutex<HashMap<IpAddr, Instant>>,
    /// `(prev, cur)` samples of `(time, request count)` for the rate.
    rate: parking_lot::Mutex<(Option<Sample>, Option<Sample>)>,
}

/// Decrements the listener's active-connection count when dropped.
pub struct ActiveGuard(Arc<ListenerFlags>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.traffic.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub struct ListenerFlags {
    traffic: Traffic,
    mitm: AtomicBool,
    http2: AtomicBool,
    websockets: AtomicBool,
    adblock: AtomicBool,
}

impl ListenerFlags {
    pub fn new(v: ListenerFlagValues) -> Self {
        Self {
            traffic: Traffic::default(),
            mitm: AtomicBool::new(v.mitm),
            http2: AtomicBool::new(v.http2),
            websockets: AtomicBool::new(v.websockets),
            adblock: AtomicBool::new(v.adblock),
        }
    }

    /// Replace every switch.
    pub fn set(&self, v: ListenerFlagValues) {
        self.mitm.store(v.mitm, Ordering::Relaxed);
        self.http2.store(v.http2, Ordering::Relaxed);
        self.websockets.store(v.websockets, Ordering::Relaxed);
        self.adblock.store(v.adblock, Ordering::Relaxed);
    }

    /// Count an accepted connection until the guard drops.
    pub fn open(self: &Arc<Self>, client: IpAddr) -> ActiveGuard {
        self.traffic.active.fetch_add(1, Ordering::Relaxed);
        let mut c = self.traffic.clients.lock();
        if c.len() >= MAX_CLIENTS {
            let now = Instant::now();
            c.retain(|_, t| now.duration_since(*t) < CLIENT_WINDOW);
        }
        if c.len() < MAX_CLIENTS || c.contains_key(&client) {
            c.insert(client, Instant::now());
        }
        ActiveGuard(self.clone())
    }

    /// Count one request served.
    #[inline]
    pub fn note_request(&self) {
        self.traffic.requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Current counters. The rate is measured over the last few seconds of traffic.
    pub fn counters(&self) -> ListenerCounters {
        let now = Instant::now();
        let count = self.traffic.requests.load(Ordering::Relaxed);
        let rate = {
            let mut r = self.traffic.rate.lock();
            if r.1
                .is_none_or(|(t, _)| now.duration_since(t) >= RATE_WINDOW)
            {
                r.0 = r.1;
                r.1 = Some((now, count));
            }
            let base = r.0.or(r.1);
            base.map_or(0.0, |(t, c)| {
                let dt = now.duration_since(t).as_secs_f64();
                if dt < 0.5 {
                    0.0
                } else {
                    count.saturating_sub(c) as f64 / dt
                }
            })
        };
        let clients = {
            let mut c = self.traffic.clients.lock();
            c.retain(|_, t| now.duration_since(*t) < CLIENT_WINDOW);
            c.len() as u64
        };
        ListenerCounters {
            active_connections: self.traffic.active.load(Ordering::Relaxed),
            requests_per_sec: rate,
            clients,
        }
    }

    pub fn mitm(&self) -> bool {
        self.mitm.load(Ordering::Relaxed)
    }
    pub fn http2(&self) -> bool {
        self.http2.load(Ordering::Relaxed)
    }
    pub fn websockets(&self) -> bool {
        self.websockets.load(Ordering::Relaxed)
    }
    pub fn adblock(&self) -> bool {
        self.adblock.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags() -> Arc<ListenerFlags> {
        Arc::new(ListenerFlags::new(ListenerFlagValues {
            mitm: true,
            http2: true,
            websockets: true,
            adblock: true,
        }))
    }

    #[test]
    fn counts_active_connections_requests_and_distinct_clients() {
        let f = flags();
        let a = f.open("10.0.0.1".parse().unwrap());
        let _b = f.open("10.0.0.2".parse().unwrap());
        let c = f.open("10.0.0.1".parse().unwrap());
        for _ in 0..10 {
            f.note_request();
        }
        let n = f.counters();
        assert_eq!((n.active_connections, n.clients), (3, 2));
        drop((a, c));
        assert_eq!(f.counters().active_connections, 1);
        assert_eq!(
            f.counters().clients,
            2,
            "clients stay counted for the window"
        );
    }

    #[test]
    fn listeners_count_separately() {
        let (e, t) = (flags(), flags());
        let _g = e.open("10.0.0.1".parse().unwrap());
        e.note_request();
        assert_eq!(t.counters().active_connections, 0);
        assert_eq!(t.counters().clients, 0);
    }
}

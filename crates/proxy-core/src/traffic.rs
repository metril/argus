//! Traffic accounting: bytes crossing the client-facing socket, per device and host.
//!
//! * [`Counted`] wraps the accepted socket (below TLS and HTTP framing, so every path is covered:
//!   plain, MITM h1/h2, tunnels, SOCKS5, transparent, WebSocket) and bumps two per-connection
//!   atomics. Nothing else happens on the I/O path: no lock, map lookup or allocation.
//! * Each connection is a [`ConnTraffic`]: those counters plus who it belongs to (device,
//!   profile), the host in flight and how it is handled. When the host or the device changes, the
//!   bytes counted so far are first credited to the old one (one table lock per change, never per
//!   byte).
//! * [`Traffic::fold`] runs about once a second: it moves each connection's new bytes into a
//!   bounded table keyed by device and host (totals stay exact when hosts are evicted into an
//!   "other" bucket) and advances the smoothed rates. Connections without new bytes cost nothing
//!   there: their "active" mark is a counter they hold, not a lookup. A closing connection folds
//!   its last bytes itself. Nothing is persisted.

use arc_swap::ArcSwap;
use common::traffic::{DeviceTraffic, HandlingBytes, HostTraffic, TrafficRow, TrafficSnapshot};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering::Relaxed};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// How often live connections are folded into the table.
pub const FOLD_INTERVAL: Duration = Duration::from_secs(1);
/// Time constant of the smoothed rates, seconds.
const RATE_TAU_SECS: f64 = 3.0;
/// Most host entries kept per device and overall; older ones fold into the device's "other".
pub const MAX_HOSTS_PER_DEVICE: usize = 256;
pub const MAX_HOSTS_TOTAL: usize = 4096;
/// Most devices kept; the least recently active idle one is dropped beyond this.
pub const MAX_DEVICES: usize = 1024;
/// An idle host entry is retired (into "other") after this long without traffic.
const HOST_RETENTION_MS: u64 = 10 * 60 * 1000;
/// An idle device (no connection, no traffic) is dropped after this long.
const DEVICE_RETENTION_MS: u64 = 24 * 3600 * 1000;
/// Shown for bytes of a connection that closed without ever naming a host.
pub const UNKNOWN_HOST: &str = "(unknown)";
/// Shown for a host name that is not valid hostname or IP-literal syntax (or too long).
pub const INVALID_HOST: &str = "(invalid)";

/// A host as the table keys it: lowercase, no port, no trailing dot, at most 253 bytes, and only
/// valid hostname labels or an IP literal; anything else is [`INVALID_HOST`]. An empty name stays
/// empty ("not known yet").
pub fn sanitize_host(raw: &str) -> String {
    let h = raw.trim();
    if h.is_empty() {
        return String::new();
    }
    if h.len() > 300 {
        return INVALID_HOST.into();
    }
    let h = if let Some(rest) = h.strip_prefix('[') {
        match rest.find(']') {
            Some(i) => &rest[..i],
            None => return INVALID_HOST.into(),
        }
    } else if h.bytes().filter(|&b| b == b':').count() == 1 {
        h.split(':').next().unwrap_or("")
    } else {
        h
    };
    let h = h.trim_end_matches('.');
    if h.is_empty() || h.len() > 253 {
        return INVALID_HOST.into();
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        return crate::profiles::normalize_ip(ip).to_string();
    }
    let ok = h.split('.').all(|l| {
        (1..=63).contains(&l.len())
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    if ok {
        h.to_ascii_lowercase()
    } else {
        INVALID_HOST.into()
    }
}

/// How the proxy handles a connection's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Handling {
    /// Plain HTTP, forwarded.
    Plain = 0,
    /// TLS terminated and filtered (MITM).
    Decrypted = 1,
    /// Opaque tunnel: no decryption (bypass, EV, fail-safe).
    Tunnelled = 2,
}

impl Handling {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Decrypted,
            2 => Self::Tunnelled,
            _ => Self::Plain,
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

// ---------------------------------------------------------------------------------------------
// Per-connection counters
// ---------------------------------------------------------------------------------------------

struct Ident {
    device: Arc<str>,
    profile_id: u64,
    /// Extension session this identity was derived from (0: none).
    ext_session: u64,
}

/// What changed on a connection since it was last folded.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delta {
    pub up: u64,
    pub down: u64,
    pub local_requests: u64,
    pub local_bytes: u64,
    pub new_conn: bool,
}

/// The "active connections" counters of the device and host entries a connection is counted in.
struct Bound {
    device: Arc<AtomicU32>,
    host: Arc<AtomicU32>,
}

/// Live accounting of one client connection.
pub struct ConnTraffic {
    hub: Arc<Traffic>,
    client: SocketAddr,
    up: AtomicU64,
    down: AtomicU64,
    local_requests: AtomicU64,
    local_bytes: AtomicU64,
    handling: AtomicU8,
    ident: ArcSwap<Ident>,
    host: ArcSwap<String>,
    /// What was already folded. Written only while the hub's table lock is held, so the fold,
    /// a host or device change and the final fold never race.
    done_up: AtomicU64,
    done_down: AtomicU64,
    done_lreq: AtomicU64,
    done_lbytes: AtomicU64,
    counted: AtomicBool,
    /// Entries this connection is currently counted active in (table lock held to touch it).
    bound: Mutex<Option<Bound>>,
}

impl ConnTraffic {
    /// Bytes read from the client.
    #[inline]
    pub fn add_up(&self, n: u64) {
        self.up.fetch_add(n, Relaxed);
    }

    /// Bytes written to the client.
    #[inline]
    pub fn add_down(&self, n: u64) {
        self.down.fetch_add(n, Relaxed);
    }

    pub fn up(&self) -> u64 {
        self.up.load(Relaxed)
    }

    pub fn down(&self) -> u64 {
        self.down.load(Relaxed)
    }

    pub fn client(&self) -> SocketAddr {
        self.client
    }

    pub fn set_handling(&self, h: Handling) {
        self.handling.store(h as u8, Relaxed);
    }

    pub fn handling(&self) -> Handling {
        Handling::from_u8(self.handling.load(Relaxed))
    }

    /// The host the next bytes belong to (see [`sanitize_host`]). Cheap when unchanged (one load
    /// and a compare); when it changes, what was counted so far is credited to the old host first.
    pub fn set_host(&self, raw: &str) {
        if self.host.load().eq_ignore_ascii_case(raw) {
            return;
        }
        let new = sanitize_host(raw);
        if self.host.load().as_str() == new {
            return;
        }
        self.hub.flush(self);
        self.host.store(Arc::new(new));
    }

    pub fn host(&self) -> Arc<String> {
        self.host.load_full()
    }

    /// Who the connection belongs to; call once per request with the resolved context. The
    /// device `Arc` is replaced on every re-resolution, so a pointer compare finds changes. A
    /// change credits what was counted so far to the previous device.
    #[inline]
    pub fn note_ident(&self, device: &Arc<str>, profile_id: u64) {
        let cur = self.ident.load();
        if cur.ext_session == 0 && Arc::ptr_eq(&cur.device, device) && cur.profile_id == profile_id
        {
            return;
        }
        drop(cur);
        self.hub.flush(self);
        self.ident.store(Arc::new(Ident {
            device: device.clone(),
            profile_id,
            ext_session: 0,
        }));
    }

    /// Like [`Self::note_ident`] for a connection bound to extension session `session`:
    /// `key` (called only on a change) names the stable, non-secret identity to count it under.
    #[inline]
    pub fn note_ext(&self, session: u64, profile_id: u64, key: impl FnOnce() -> Option<Arc<str>>) {
        let cur = self.ident.load();
        if cur.ext_session == session && cur.profile_id == profile_id {
            return;
        }
        drop(cur);
        let Some(device) = key() else { return };
        self.hub.flush(self);
        self.ident.store(Arc::new(Ident {
            device,
            profile_id,
            ext_session: session,
        }));
    }

    pub fn device(&self) -> Arc<str> {
        self.ident.load().device.clone()
    }

    /// A request the proxy answered itself, with the response body size when known.
    pub fn note_local(&self, body_bytes: u64) {
        self.local_requests.fetch_add(1, Relaxed);
        self.local_bytes.fetch_add(body_bytes, Relaxed);
    }

    /// Everything new since the last call; advances the cursors. Call with the table lock held.
    fn take_delta(&self) -> Delta {
        let step = |cur: &AtomicU64, done: &AtomicU64| {
            let c = cur.load(Relaxed);
            let d = c.saturating_sub(done.load(Relaxed));
            done.store(c, Relaxed);
            d
        };
        Delta {
            up: step(&self.up, &self.done_up),
            down: step(&self.down, &self.done_down),
            local_requests: step(&self.local_requests, &self.done_lreq),
            local_bytes: step(&self.local_bytes, &self.done_lbytes),
            new_conn: !self.counted.swap(true, Relaxed),
        }
    }

    fn is_bound(&self) -> bool {
        self.bound.lock().is_some()
    }

    /// Count this connection active in the entries behind `b` (and no longer in its old ones).
    fn bind(&self, b: Bound) {
        let mut g = self.bound.lock();
        if let Some(old) = g.as_ref() {
            if Arc::ptr_eq(&old.device, &b.device) && Arc::ptr_eq(&old.host, &b.host) {
                return;
            }
        }
        b.device.fetch_add(1, Relaxed);
        b.host.fetch_add(1, Relaxed);
        if let Some(old) = g.replace(b) {
            old.device.fetch_sub(1, Relaxed);
            old.host.fetch_sub(1, Relaxed);
        }
    }

    fn unbind(&self) {
        if let Some(old) = self.bound.lock().take() {
            old.device.fetch_sub(1, Relaxed);
            old.host.fetch_sub(1, Relaxed);
        }
    }
}

impl Drop for ConnTraffic {
    fn drop(&mut self) {
        let hub = self.hub.clone();
        hub.absorb(self);
    }
}

// ---------------------------------------------------------------------------------------------
// The counting socket wrapper
// ---------------------------------------------------------------------------------------------

/// A stream that counts what crosses it into a [`ConnTraffic`].
pub struct Counted<S> {
    inner: S,
    ct: Arc<ConnTraffic>,
}

impl<S> Counted<S> {
    pub fn new(inner: S, ct: Arc<ConnTraffic>) -> Self {
        Self { inner, ct }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let n = buf.filled().len() - before;
            if n > 0 {
                self.ct.add_up(n as u64);
            }
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            self.ct.add_down(*n as u64);
        }
        r
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &r {
            self.ct.add_down(*n as u64);
        }
        r
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------------------------

#[derive(Default, Clone, Debug)]
struct Agg {
    up: u64,
    down: u64,
    conns: u64,
    local_requests: u64,
    local_bytes: u64,
    /// Bytes (up plus down) by [`Handling`].
    hand: [u64; 3],
    /// Live connections counted in this entry (held by the connections through [`Bound`]).
    active: Arc<AtomicU32>,
    /// Bytes since the last tick.
    acc_up: u64,
    acc_down: u64,
    rate_up: f64,
    rate_down: f64,
    /// Unix ms of the last byte, or of creation.
    last_ms: u64,
}

impl Agg {
    fn new(now_ms: u64) -> Self {
        Self {
            last_ms: now_ms,
            ..Self::default()
        }
    }

    fn active(&self) -> u32 {
        self.active.load(Relaxed)
    }

    fn add(&mut self, d: &Delta, mode: Handling, now_ms: u64) {
        self.up += d.up;
        self.down += d.down;
        self.acc_up += d.up;
        self.acc_down += d.down;
        self.local_requests += d.local_requests;
        self.local_bytes += d.local_bytes;
        self.hand[mode as usize] += d.up + d.down;
        self.conns += d.new_conn as u64;
        if d.up + d.down > 0 {
            self.last_ms = now_ms;
        }
    }

    /// Fold `o`'s cumulative figures in (rates are not carried).
    fn absorb(&mut self, o: &Agg) {
        self.up += o.up;
        self.down += o.down;
        self.conns += o.conns;
        self.local_requests += o.local_requests;
        self.local_bytes += o.local_bytes;
        for i in 0..3 {
            self.hand[i] += o.hand[i];
        }
        self.last_ms = self.last_ms.max(o.last_ms);
    }

    /// Advance the smoothed rates by `dt` seconds.
    fn tick(&mut self, dt: f64) {
        let alpha = ewma_alpha(dt);
        self.rate_up = ewma(self.rate_up, self.acc_up as f64 / dt, alpha);
        self.rate_down = ewma(self.rate_down, self.acc_down as f64 / dt, alpha);
        self.acc_up = 0;
        self.acc_down = 0;
    }

    fn row(&self) -> TrafficRow {
        TrafficRow {
            up: self.up,
            down: self.down,
            up_rate: self.rate_up,
            down_rate: self.rate_down,
            connections_total: self.conns,
            connections_active: self.active(),
            local_requests: self.local_requests,
            local_bytes: self.local_bytes,
            handling: HandlingBytes {
                plain: self.hand[Handling::Plain as usize],
                decrypted: self.hand[Handling::Decrypted as usize],
                tunnelled: self.hand[Handling::Tunnelled as usize],
            },
            last_active_ms: (self.up + self.down > 0).then_some(self.last_ms),
        }
    }

    fn idle(&self) -> bool {
        self.active() == 0 && self.rate_up == 0.0 && self.rate_down == 0.0
    }
}

/// Weight of the newest sample after `dt` seconds.
pub fn ewma_alpha(dt: f64) -> f64 {
    1.0 - (-dt / RATE_TAU_SECS).exp()
}

/// One smoothing step; tiny residues snap to zero so idle entries can be retired.
pub fn ewma(prev: f64, sample: f64, alpha: f64) -> f64 {
    let v = prev + alpha * (sample - prev);
    if v < 0.5 && sample == 0.0 {
        0.0
    } else {
        v
    }
}

struct DeviceAgg {
    profile_id: u64,
    agg: Agg,
    hosts: HashMap<Arc<str>, Agg>,
    other: Agg,
}

#[derive(Default)]
struct Table {
    devices: HashMap<Arc<str>, DeviceAgg>,
    host_count: usize,
}

impl Table {
    fn device_mut(&mut self, key: &Arc<str>, profile_id: u64, now: u64) -> &mut DeviceAgg {
        if !self.devices.contains_key(key) {
            if self.devices.len() >= MAX_DEVICES {
                self.evict_device();
            }
            self.devices.insert(
                key.clone(),
                DeviceAgg {
                    profile_id,
                    agg: Agg::new(now),
                    hosts: HashMap::new(),
                    other: Agg::default(),
                },
            );
        }
        let d = self.devices.get_mut(key).expect("just inserted");
        d.profile_id = profile_id;
        d
    }

    /// Drop the least recently active device, preferring ones with no live connection.
    fn evict_device(&mut self) {
        let victim = self
            .devices
            .iter()
            .min_by_key(|(_, d)| (d.agg.active() > 0, d.agg.last_ms))
            .map(|(k, _)| k.clone());
        if let Some(k) = victim {
            if let Some(d) = self.devices.remove(&k) {
                self.host_count -= d.hosts.len();
            }
        }
    }

    /// Credit `d` to `(device, host)`, creating the entries; returns their active counters.
    #[allow(clippy::too_many_arguments)]
    fn apply(
        &mut self,
        device: &Arc<str>,
        profile_id: u64,
        host: &str,
        d: &Delta,
        mode: Handling,
        now: u64,
    ) -> Bound {
        let host = if host.is_empty() { UNKNOWN_HOST } else { host };
        let need_room = {
            let dev = self.device_mut(device, profile_id, now);
            dev.agg.add(d, mode, now);
            !dev.hosts.contains_key(host)
        };
        if need_room {
            if self.host_count >= MAX_HOSTS_TOTAL {
                self.evict_oldest_hosts(MAX_HOSTS_TOTAL / 10);
            }
            let dev = self.devices.get_mut(device).expect("device exists");
            if dev.hosts.len() >= MAX_HOSTS_PER_DEVICE {
                let victim = dev
                    .hosts
                    .iter()
                    .min_by_key(|(_, h)| (h.active() > 0, h.last_ms))
                    .map(|(k, _)| k.clone());
                if let Some(k) = victim {
                    if let Some(h) = dev.hosts.remove(&k) {
                        dev.other.absorb(&h);
                        self.host_count -= 1;
                    }
                }
            }
            dev.hosts.insert(Arc::from(host), Agg::new(now));
            self.host_count += 1;
        }
        let dev = self.devices.get_mut(device).expect("device exists");
        let h = dev.hosts.get_mut(host).expect("host exists");
        h.add(d, mode, now);
        Bound {
            device: dev.agg.active.clone(),
            host: h.active.clone(),
        }
    }

    /// Fold the `n` least recently active host entries (across devices) into their device's
    /// "other" bucket.
    fn evict_oldest_hosts(&mut self, n: usize) {
        let mut all: Vec<(bool, u64, Arc<str>, Arc<str>)> = self
            .devices
            .iter()
            .flat_map(|(dk, d)| {
                d.hosts
                    .iter()
                    .map(move |(hk, h)| (h.active() > 0, h.last_ms, dk.clone(), hk.clone()))
            })
            .collect();
        all.sort_by_key(|e| (e.0, e.1));
        for (_, _, dk, hk) in all.into_iter().take(n) {
            if let Some(d) = self.devices.get_mut(&dk) {
                if let Some(h) = d.hosts.remove(&hk) {
                    d.other.absorb(&h);
                    self.host_count -= 1;
                }
            }
        }
    }

    fn tick(&mut self, dt: f64, now: u64) {
        for d in self.devices.values_mut() {
            d.agg.tick(dt);
            d.other.tick(dt);
            let mut retire = Vec::new();
            for (k, h) in d.hosts.iter_mut() {
                h.tick(dt);
                if h.idle() && now.saturating_sub(h.last_ms) > HOST_RETENTION_MS {
                    retire.push(k.clone());
                }
            }
            for k in retire {
                if let Some(h) = d.hosts.remove(&k) {
                    d.other.absorb(&h);
                    self.host_count -= 1;
                }
            }
        }
        let gone: Vec<Arc<str>> = self
            .devices
            .iter()
            .filter(|(_, d)| {
                d.agg.idle() && now.saturating_sub(d.agg.last_ms) > DEVICE_RETENTION_MS
            })
            .map(|(k, _)| k.clone())
            .collect();
        for k in gone {
            if let Some(d) = self.devices.remove(&k) {
                self.host_count -= d.hosts.len();
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The hub
// ---------------------------------------------------------------------------------------------

/// Registry of live connections and the aggregate table.
pub struct Traffic {
    reg: Mutex<Vec<Weak<ConnTraffic>>>,
    table: Mutex<Table>,
    up_total: AtomicU64,
    down_total: AtomicU64,
    last_tick: Mutex<Instant>,
    folder_started: AtomicBool,
}

impl Default for Traffic {
    fn default() -> Self {
        Self {
            reg: Mutex::new(Vec::new()),
            table: Mutex::new(Table::default()),
            up_total: AtomicU64::new(0),
            down_total: AtomicU64::new(0),
            last_tick: Mutex::new(Instant::now()),
            folder_started: AtomicBool::new(false),
        }
    }
}

impl Traffic {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Start accounting a connection from `client` (default device: its address, an IPv4-mapped
    /// IPv6 address counting as the IPv4 one).
    pub fn register(self: &Arc<Self>, client: SocketAddr) -> Arc<ConnTraffic> {
        let ip = crate::profiles::normalize_ip(client.ip());
        let ct = Arc::new(ConnTraffic {
            hub: self.clone(),
            client,
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            local_requests: AtomicU64::new(0),
            local_bytes: AtomicU64::new(0),
            handling: AtomicU8::new(Handling::Plain as u8),
            ident: ArcSwap::from_pointee(Ident {
                device: Arc::from(format!("i:{ip}")),
                profile_id: 0,
                ext_session: 0,
            }),
            host: ArcSwap::from_pointee(String::new()),
            done_up: AtomicU64::new(0),
            done_down: AtomicU64::new(0),
            done_lreq: AtomicU64::new(0),
            done_lbytes: AtomicU64::new(0),
            counted: AtomicBool::new(false),
            bound: Mutex::new(None),
        });
        self.reg.lock().push(Arc::downgrade(&ct));
        ct
    }

    /// Exact bytes `(received from clients, sent to clients)` folded so far. Two atomic loads.
    pub fn totals(&self) -> (u64, u64) {
        (self.up_total.load(Relaxed), self.down_total.load(Relaxed))
    }

    /// Credit what `c` counted so far to its current device and host and stop counting it active
    /// there. Used before either changes (and by the final fold). A connection whose host is
    /// still unknown keeps its bytes pending for the host it will name.
    fn flush(&self, c: &ConnTraffic) {
        if c.host.load().is_empty() {
            return;
        }
        let mut t = self.table.lock();
        if c.has_bytes() {
            self.credit(&mut t, c, now_ms());
        }
        c.unbind();
    }

    /// Take `c`'s pending bytes into `t` under its current device and host. Table lock held.
    fn credit(&self, t: &mut Table, c: &ConnTraffic, now: u64) -> Bound {
        let ident = c.ident.load();
        let host = c.host.load();
        let d = c.take_delta();
        self.up_total.fetch_add(d.up, Relaxed);
        self.down_total.fetch_add(d.down, Relaxed);
        t.apply(
            &ident.device,
            ident.profile_id,
            &host,
            &d,
            c.handling(),
            now,
        )
    }

    /// A closing connection's last bytes (a connection that never named a host is credited
    /// under "(unknown)").
    fn absorb(&self, c: &ConnTraffic) {
        let mut t = self.table.lock();
        self.credit(&mut t, c, now_ms());
        c.unbind();
    }

    /// Fold live connections into the table and advance the rates.
    pub fn fold(&self) {
        let now = Instant::now();
        let dt = {
            let mut l = self.last_tick.lock();
            let dt = now.duration_since(*l).as_secs_f64();
            *l = now;
            dt
        };
        self.fold_with(dt.max(0.001), now_ms());
    }

    /// [`Self::fold`] with the elapsed time and wall clock given (deterministic in tests).
    pub fn fold_with(&self, dt: f64, now: u64) {
        let live: Vec<Arc<ConnTraffic>> = {
            let mut r = self.reg.lock();
            r.retain(|w| w.strong_count() > 0);
            r.iter().filter_map(Weak::upgrade).collect()
        };
        {
            let mut t = self.table.lock();
            for c in &live {
                // Bytes before the host is known wait for it.
                if c.host.load().is_empty() {
                    continue;
                }
                // Nothing new and already counted active: no map work at all.
                if c.is_bound() && !c.has_pending() {
                    continue;
                }
                let b = self.credit(&mut t, c, now);
                c.bind(b);
            }
            t.tick(dt, now);
        }
        // Dropping the last strong reference of a connection folds it: with no lock held.
        drop(live);
    }

    /// Forget everything counted so far (bytes still pending on live connections included).
    pub fn reset(&self) {
        let live: Vec<Arc<ConnTraffic>> =
            self.reg.lock().iter().filter_map(Weak::upgrade).collect();
        let mut t = self.table.lock();
        for c in &live {
            c.take_delta();
            // Counted again (as active) by the next fold, in the fresh table.
            c.unbind();
        }
        *t = Table::default();
        self.up_total.store(0, Relaxed);
        self.down_total.store(0, Relaxed);
        drop(t);
        drop(live);
    }

    /// Point-in-time copy of the table.
    pub fn snapshot(&self) -> TrafficSnapshot {
        let t = self.table.lock();
        let devices = t
            .devices
            .iter()
            .map(|(k, d)| DeviceTraffic {
                key: k.to_string(),
                profile_id: d.profile_id,
                row: d.agg.row(),
                hosts: d
                    .hosts
                    .iter()
                    .map(|(h, a)| HostTraffic {
                        host: h.to_string(),
                        row: a.row(),
                    })
                    .collect(),
                other: d.other.row(),
            })
            .collect();
        TrafficSnapshot {
            at_ms: now_ms(),
            interval_ms: FOLD_INTERVAL.as_millis() as u64,
            up_total: self.up_total.load(Relaxed),
            down_total: self.down_total.load(Relaxed),
            devices,
        }
    }

    /// Run [`Self::fold`] every [`FOLD_INTERVAL`] until the hub is dropped. Once per hub.
    pub fn spawn_folder(self: &Arc<Self>) {
        if self.folder_started.swap(true, Relaxed) {
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(FOLD_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                match weak.upgrade() {
                    Some(t) => t.fold(),
                    None => break,
                }
            }
        });
    }
}

impl ConnTraffic {
    /// Whether anything was counted (or noted local) since the last fold, or the connection was
    /// never counted at all.
    fn has_pending(&self) -> bool {
        !self.counted.load(Relaxed) || self.has_bytes()
    }

    /// Whether bytes or local answers were counted since the last fold of this connection.
    fn has_bytes(&self) -> bool {
        self.up.load(Relaxed) != self.done_up.load(Relaxed)
            || self.down.load(Relaxed) != self.done_down.load(Relaxed)
            || self.local_requests.load(Relaxed) != self.done_lreq.load(Relaxed)
            || self.local_bytes.load(Relaxed) != self.done_lbytes.load(Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn dev(table: &TrafficSnapshot, key: &str) -> DeviceTraffic {
        table
            .devices
            .iter()
            .find(|d| d.key == key)
            .unwrap_or_else(|| panic!("no device {key}"))
            .clone()
    }

    fn host_row(d: &DeviceTraffic, h: &str) -> TrafficRow {
        d.hosts
            .iter()
            .find(|x| x.host == h)
            .unwrap_or_else(|| panic!("no host {h}"))
            .row
            .clone()
    }

    /// A stream that returns `Pending` every other poll and moves at most `chunk` bytes per call.
    struct Flaky {
        chunk: usize,
        flip: bool,
        to_read: Vec<u8>,
        written: Vec<u8>,
    }

    impl Flaky {
        fn new(chunk: usize, to_read: Vec<u8>) -> Self {
            Self {
                chunk,
                flip: false,
                to_read,
                written: Vec::new(),
            }
        }
        fn pending(&mut self, cx: &mut Context<'_>) -> bool {
            self.flip = !self.flip;
            if self.flip {
                cx.waker().wake_by_ref();
            }
            self.flip
        }
    }

    impl AsyncRead for Flaky {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.pending(cx) {
                return Poll::Pending;
            }
            let n = self.chunk.min(buf.remaining()).min(self.to_read.len());
            let chunk: Vec<u8> = self.to_read.drain(..n).collect();
            buf.put_slice(&chunk);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Flaky {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.pending(cx) {
                return Poll::Pending;
            }
            let n = self.chunk.min(buf.len());
            self.written.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn counted_counts_both_directions_exactly() {
        let hub = Traffic::new();
        let ct = hub.register(addr("10.0.0.1:1"));
        let (a, mut b) = tokio::io::duplex(64 * 1024);
        let mut a = Counted::new(a, ct.clone());
        b.write_all(&[7u8; 1000]).await.unwrap();
        let mut buf = [0u8; 1000];
        a.read_exact(&mut buf).await.unwrap();
        a.write_all(&[1u8; 300]).await.unwrap();
        let n = a
            .write_vectored(&[io::IoSlice::new(&[2; 10]), io::IoSlice::new(&[3; 5])])
            .await
            .unwrap();
        assert_eq!(ct.up(), 1000);
        assert_eq!(ct.down(), 300 + n as u64);
        // EOF counts nothing.
        drop(b);
        let mut rest = Vec::new();
        a.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        assert_eq!(ct.up(), 1000);
    }

    #[tokio::test]
    async fn counted_survives_pending_partial_and_vectored_io() {
        let hub = Traffic::new();
        let ct = hub.register(addr("10.0.0.1:2"));
        let mut s = Counted::new(Flaky::new(3, (0..100u8).collect()), ct.clone());
        // Reads: Pending half the time, 3 bytes at a time; only delivered bytes count.
        let mut got = Vec::new();
        let mut buf = [0u8; 16];
        while got.len() < 100 {
            let n = s.read(&mut buf).await.unwrap();
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(ct.up(), 100);
        assert_eq!(got, (0..100u8).collect::<Vec<_>>());
        // Writes: partial (3 of 10) and Pending retried by write_all; counted once each.
        s.write_all(&[9u8; 10]).await.unwrap();
        assert_eq!(ct.down(), 10);
        // Vectored: the default implementation writes the first non-empty slice, partially.
        let n = s
            .write_vectored(&[io::IoSlice::new(&[1; 8]), io::IoSlice::new(&[2; 8])])
            .await
            .unwrap();
        assert_eq!(n, 3);
        assert_eq!(ct.down(), 13);
        assert_eq!(s.get_ref().written.len(), 13);
    }

    #[test]
    fn ewma_converges_and_decays() {
        let a = ewma_alpha(1.0);
        let mut r = 0.0;
        for _ in 0..30 {
            r = ewma(r, 1000.0, a);
        }
        assert!((r - 1000.0).abs() < 1.0, "{r}");
        assert!((ewma(0.0, 1000.0, a) - 1000.0 * a).abs() < 1e-9);
        for _ in 0..40 {
            r = ewma(r, 0.0, a);
        }
        assert_eq!(r, 0.0, "decays to exactly zero so idle entries can retire");
        assert!(ewma_alpha(2.0) > ewma_alpha(1.0));
    }

    #[test]
    fn fold_attributes_bytes_to_device_host_and_mode() {
        let hub = Traffic::new();
        let ct = hub.register(addr("10.0.0.1:1"));
        let d: Arc<str> = Arc::from("t:abc");
        ct.note_ident(&d, 7);
        ct.set_host("a.example");
        ct.set_handling(Handling::Decrypted);
        ct.add_up(100);
        ct.add_down(900);
        hub.fold_with(1.0, 1_000);
        ct.set_host("b.example");
        ct.set_handling(Handling::Tunnelled);
        ct.add_down(500);
        ct.note_local(40);
        hub.fold_with(1.0, 2_000);
        let s = hub.snapshot();
        let dv = dev(&s, "t:abc");
        assert_eq!(dv.profile_id, 7);
        assert_eq!((dv.row.up, dv.row.down), (100, 1400));
        assert_eq!(dv.row.connections_total, 1);
        assert_eq!(dv.row.connections_active, 1);
        assert_eq!(dv.row.handling.decrypted, 1000);
        assert_eq!(dv.row.handling.tunnelled, 500);
        assert_eq!(dv.row.local_requests, 1);
        let host = |n: &str| host_row(&dv, n);
        assert_eq!((host("a.example").up, host("a.example").down), (100, 900));
        assert_eq!(host("a.example").connections_active, 0);
        assert_eq!(host("b.example").down, 500);
        assert_eq!(host("b.example").connections_active, 1);
        assert!(host("b.example").down_rate > 0.0);
        assert_eq!(s.up_total + s.down_total, 1500);
    }

    #[test]
    fn a_host_change_credits_pending_bytes_to_the_old_host() {
        let hub = Traffic::new();
        let ct = hub.register(addr("10.0.0.20:1"));
        ct.set_host("a.com");
        ct.add_down(50_000_000);
        // The next request on the same keep-alive connection names another host before any fold.
        ct.set_host("b.com");
        ct.add_down(100);
        hub.fold_with(1.0, 1_000);
        let dv = dev(&hub.snapshot(), "i:10.0.0.20");
        assert_eq!(host_row(&dv, "a.com").down, 50_000_000);
        assert_eq!(host_row(&dv, "b.com").down, 100);
        assert_eq!(host_row(&dv, "a.com").connections_active, 0);
        assert_eq!(host_row(&dv, "b.com").connections_active, 1);
        // A closing connection credits what is pending to its last host only.
        ct.add_down(7);
        ct.set_host("c.com");
        ct.add_down(3);
        drop(ct);
        let dv = dev(&hub.snapshot(), "i:10.0.0.20");
        assert_eq!(host_row(&dv, "b.com").down, 107);
        assert_eq!(host_row(&dv, "c.com").down, 3);
        assert_eq!(dv.row.down, 50_000_110);
    }

    #[test]
    fn a_device_change_credits_pending_bytes_to_the_old_device() {
        let hub = Traffic::new();
        let ct = hub.register(addr("10.0.0.21:1"));
        ct.set_host("h.example");
        ct.add_down(50);
        let d: Arc<str> = Arc::from("t:newdev");
        ct.note_ident(&d, 4);
        ct.add_down(5);
        hub.fold_with(1.0, 1_000);
        let s = hub.snapshot();
        assert_eq!(dev(&s, "i:10.0.0.21").row.down, 50);
        assert_eq!(dev(&s, "i:10.0.0.21").row.connections_active, 0);
        assert_eq!(dev(&s, "t:newdev").row.down, 5);
        assert_eq!(dev(&s, "t:newdev").profile_id, 4);
        assert_eq!(dev(&s, "t:newdev").row.connections_active, 1);
    }

    #[test]
    fn idle_connections_stay_active_without_map_work_and_stop_on_close() {
        let hub = Traffic::new();
        let busy = hub.register(addr("10.0.0.22:1"));
        let idle = hub.register(addr("10.0.0.22:2"));
        busy.set_host("h.example");
        idle.set_host("h.example");
        busy.add_down(1);
        idle.add_down(1);
        hub.fold_with(1.0, 1_000);
        for i in 0..5 {
            hub.fold_with(1.0, 2_000 + i);
        }
        let dv = dev(&hub.snapshot(), "i:10.0.0.22");
        assert_eq!(dv.row.connections_active, 2);
        assert_eq!(host_row(&dv, "h.example").connections_active, 2);
        assert_eq!(dv.row.connections_total, 2);
        drop(idle);
        let dv = dev(&hub.snapshot(), "i:10.0.0.22");
        assert_eq!(dv.row.connections_active, 1);
        drop(busy);
        assert_eq!(
            dev(&hub.snapshot(), "i:10.0.0.22").row.connections_active,
            0
        );
    }

    #[test]
    fn closing_connection_folds_its_last_bytes_and_stops_being_active() {
        let hub = Traffic::new();
        let ct = hub.register(addr("10.0.0.2:1"));
        ct.set_host("x.example");
        ct.add_down(10);
        hub.fold_with(1.0, 1_000);
        ct.add_down(25);
        drop(ct);
        let s = hub.snapshot();
        assert_eq!(dev(&s, "i:10.0.0.2").row.down, 35);
        hub.fold_with(1.0, 2_000);
        let dv = dev(&hub.snapshot(), "i:10.0.0.2");
        assert_eq!(dv.row.connections_active, 0);
        assert_eq!(dv.row.connections_total, 1);
        assert_eq!(hub.totals(), (0, 35));
    }

    #[test]
    fn bytes_wait_for_the_host_instead_of_landing_under_unknown() {
        let hub = Traffic::new();
        let ct = hub.register(addr("10.0.0.8:1"));
        ct.add_up(40);
        hub.fold_with(1.0, 1_000);
        assert!(hub.snapshot().devices.is_empty(), "nothing folded yet");
        ct.set_host("late.example");
        ct.add_down(60);
        hub.fold_with(1.0, 2_000);
        let dv = dev(&hub.snapshot(), "i:10.0.0.8");
        assert_eq!(dv.hosts.len(), 1);
        assert_eq!(dv.hosts[0].host, "late.example");
        assert_eq!((dv.hosts[0].row.up, dv.hosts[0].row.down), (40, 60));
        assert_eq!(dv.hosts[0].row.connections_total, 1);
    }

    #[test]
    fn a_connection_that_never_named_a_host_is_counted_once_under_unknown() {
        let hub = Traffic::new();
        let ct = hub.register(addr("10.0.0.3:1"));
        ct.add_up(3);
        drop(ct);
        let dv = dev(&hub.snapshot(), "i:10.0.0.3");
        assert_eq!((dv.row.up, dv.row.connections_total), (3, 1));
        assert_eq!(dv.hosts[0].host, UNKNOWN_HOST);
    }

    #[test]
    fn eviction_keeps_device_totals_exact() {
        let hub = Traffic::new();
        let ct = hub.register(addr("10.0.0.5:1"));
        let n = MAX_HOSTS_PER_DEVICE + 40;
        let mut total = 0u64;
        for i in 0..n {
            ct.set_host(&format!("h{i}.example"));
            ct.add_down(10 + i as u64);
            total += 10 + i as u64;
            hub.fold_with(1.0, 1_000 + i as u64);
        }
        let dv = dev(&hub.snapshot(), "i:10.0.0.5");
        assert_eq!(dv.hosts.len(), MAX_HOSTS_PER_DEVICE);
        assert_eq!(dv.row.down, total);
        let kept: u64 = dv.hosts.iter().map(|h| h.row.down).sum();
        assert_eq!(
            kept + dv.other.down,
            total,
            "evicted bytes live on in other"
        );
        assert!(dv.other.down > 0);
        assert!(dv
            .hosts
            .iter()
            .any(|h| h.host == format!("h{}.example", n - 1)));
    }

    #[test]
    fn global_host_cap_evicts_oldest_across_devices() {
        let mut t = Table::default();
        let d = Delta {
            down: 1,
            ..Delta::default()
        };
        let mut sum = 0;
        for dvc in 0..20u64 {
            let key: Arc<str> = Arc::from(format!("i:10.1.0.{dvc}"));
            for h in 0..(MAX_HOSTS_TOTAL as u64 / 10) {
                t.apply(
                    &key,
                    0,
                    &format!("h{h}.{dvc}"),
                    &d,
                    Handling::Plain,
                    dvc * 1000 + h,
                );
                sum += 1;
            }
        }
        assert!(t.host_count <= MAX_HOSTS_TOTAL);
        let counted: u64 = t.devices.values().map(|x| x.agg.down).sum();
        assert_eq!(counted, sum);
        let kept: usize = t.devices.values().map(|x| x.hosts.len()).sum();
        assert_eq!(kept, t.host_count);
        let acc: u64 = t
            .devices
            .values()
            .map(|x| x.hosts.values().map(|h| h.down).sum::<u64>() + x.other.down)
            .sum();
        assert_eq!(acc, sum, "no byte lost to eviction");
    }

    #[test]
    fn idle_hosts_retire_into_other_after_retention() {
        let hub = Traffic::new();
        let ct = hub.register(addr("10.0.0.6:1"));
        ct.set_host("old.example");
        ct.add_down(100);
        hub.fold_with(1.0, 1_000);
        for i in 0..40 {
            hub.fold_with(1.0, 2_000 + i * 1_000);
        }
        let dv = dev(&hub.snapshot(), "i:10.0.0.6");
        assert_eq!(dv.hosts.len(), 1, "still within retention");
        // The connection is still open, so its host entry is live and stays.
        hub.fold_with(1.0, 1_000 + HOST_RETENTION_MS + 60_000);
        let dv = dev(&hub.snapshot(), "i:10.0.0.6");
        assert!(dv.hosts.iter().all(|h| h.row.connections_active == 1));
        drop(ct);
        hub.fold_with(1.0, 1_000 + HOST_RETENTION_MS + 70_000);
        let dv = dev(&hub.snapshot(), "i:10.0.0.6");
        assert!(dv.hosts.is_empty());
        assert_eq!(dv.other.down, 100);
        assert_eq!(dv.row.down, 100);
    }

    #[test]
    fn reset_clears_everything_including_pending_bytes() {
        let hub = Traffic::new();
        let ct = hub.register(addr("10.0.0.7:1"));
        ct.set_host("h");
        ct.add_down(50);
        hub.fold_with(1.0, 1_000);
        ct.add_down(70);
        hub.reset();
        assert!(hub.snapshot().devices.is_empty());
        hub.fold_with(1.0, 2_000);
        let dv = dev(&hub.snapshot(), "i:10.0.0.7");
        assert_eq!(dv.row.down, 0);
        // The live connection is counted again, in the fresh table.
        assert_eq!(dv.row.connections_active, 1);
        ct.add_down(5);
        hub.fold_with(1.0, 3_000);
        assert_eq!(dev(&hub.snapshot(), "i:10.0.0.7").row.down, 5);
        assert_eq!(hub.totals(), (0, 5));
    }

    #[test]
    fn reset_during_live_traffic_loses_nothing_after_it() {
        let hub = Traffic::new();
        let cts: Vec<_> = (0..4)
            .map(|i| {
                let c = hub.register(addr(&format!("10.0.1.{i}:1")));
                c.set_host("h.example");
                c
            })
            .collect();
        let threads: Vec<_> = cts
            .iter()
            .map(|c| {
                let c = c.clone();
                std::thread::spawn(move || {
                    for _ in 0..2000 {
                        c.add_down(1);
                    }
                })
            })
            .collect();
        for _ in 0..20 {
            hub.fold_with(1.0, 1_000);
        }
        hub.reset();
        for t in threads {
            t.join().unwrap();
        }
        let sent: u64 = cts.iter().map(|c| c.down()).sum();
        assert_eq!(sent, 8000);
        hub.fold_with(1.0, 1_500);
        let before = hub.totals().1;
        for c in &cts {
            c.add_down(10);
        }
        hub.fold_with(1.0, 2_000);
        assert_eq!(hub.totals().1 - before, 40, "bytes after the reset count");
        let s = hub.snapshot();
        assert_eq!(s.devices.len(), 4);
        assert!(s.devices.iter().all(|d| d.row.connections_active == 1));
    }

    #[test]
    fn hostnames_are_validated_and_normalised() {
        assert_eq!(sanitize_host("Example.COM"), "example.com");
        assert_eq!(sanitize_host("example.com."), "example.com");
        assert_eq!(sanitize_host("example.com:8443"), "example.com");
        assert_eq!(sanitize_host("[::1]:443"), "::1");
        assert_eq!(sanitize_host("[2001:DB8::1]"), "2001:db8::1");
        assert_eq!(sanitize_host("::ffff:10.0.0.9"), "10.0.0.9");
        assert_eq!(sanitize_host("10.0.0.9:80"), "10.0.0.9");
        assert_eq!(sanitize_host("a_b-c.example"), "a_b-c.example");
        assert_eq!(sanitize_host(""), "");
        let long = format!("{}.com", "a".repeat(250));
        assert_eq!(sanitize_host(&long), INVALID_HOST);
        let label = format!("{}.com", "a".repeat(64));
        assert_eq!(sanitize_host(&label), INVALID_HOST);
        for bad in [
            "a b.com",
            "a..com",
            "<script>",
            "exa\u{0}mple.com",
            "[::1",
            "é.com",
            ".",
        ] {
            assert_eq!(sanitize_host(bad), INVALID_HOST, "{bad:?}");
        }
        // Many distinct junk names share one bucket.
        let hub = Traffic::new();
        let ct = hub.register(addr("10.0.0.30:1"));
        for i in 0..50 {
            ct.set_host(&format!("bad host {i}"));
            ct.add_down(1);
        }
        hub.fold_with(1.0, 1_000);
        let dv = dev(&hub.snapshot(), "i:10.0.0.30");
        assert_eq!(dv.hosts.len(), 1);
        assert_eq!(dv.hosts[0].host, INVALID_HOST);
        assert_eq!(dv.hosts[0].row.down, 50);
    }

    #[test]
    fn ipv4_mapped_addresses_are_one_device() {
        let hub = Traffic::new();
        let a = hub.register(addr("10.0.0.9:1"));
        let b = hub.register(addr("[::ffff:10.0.0.9]:2"));
        for c in [&a, &b] {
            c.set_host("h");
            c.add_down(1);
        }
        hub.fold_with(1.0, 1_000);
        let s = hub.snapshot();
        assert_eq!(s.devices.len(), 1);
        assert_eq!(s.devices[0].key, "i:10.0.0.9");
        assert_eq!(s.devices[0].row.down, 2);
    }

    #[test]
    fn extension_reconnects_stay_one_device() {
        let hub = Traffic::new();
        let key = || Some(Arc::<str>::from("x:token-1"));
        // Two connections of session 5, then the browser reconnects as session 9.
        let a = hub.register(addr("10.0.0.40:1"));
        let b = hub.register(addr("10.0.0.40:2"));
        let c = hub.register(addr("10.0.0.40:3"));
        for (ct, session) in [(&a, 5), (&b, 5), (&c, 9)] {
            ct.set_host("h");
            ct.note_ext(session, 0, key);
            ct.add_down(10);
        }
        // A call with the same session does not look the key up again.
        a.note_ext(5, 0, || panic!("unchanged session must not resolve"));
        hub.fold_with(1.0, 1_000);
        let s = hub.snapshot();
        assert_eq!(s.devices.len(), 1, "{:?}", s.devices);
        assert_eq!(s.devices[0].key, "x:token-1");
        assert_eq!(s.devices[0].row.down, 30);
        assert_eq!(s.devices[0].row.connections_active, 3);
        // A session that cannot be resolved keeps the previous identity.
        let d = hub.register(addr("10.0.0.41:1"));
        d.note_ext(77, 0, || None);
        assert_eq!(&*d.device(), "i:10.0.0.41");
    }
}

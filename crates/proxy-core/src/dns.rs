//! Caching DNS resolution for upstream connections.
//!
//! The cache stores only resolved addresses (clamped to the configured TTL bounds). Only
//! definite negative answers (NXDOMAIN, or a name with no address records) are cached, briefly;
//! transport failures (timeouts, SERVFAIL, I/O errors) never are, and a timed-out lookup is
//! retried once. It never decides policy: callers apply the destination policy to the addresses
//! returned on every lookup, hit or miss, and connect to exactly those addresses.
//!
//! Names hickory cannot resolve but the operating system can (mDNS `.local`, NSS sources) are
//! looked up through the OS resolver whenever hickory answers "does not exist". This happens in
//! the shared backend, so every path (MITM HTTP, CONNECT, WebSocket, transparent, control-plane
//! fetches) behaves the same, and the policy still judges whatever either resolver returned.

use common::config::DnsSettings;
use moka::Expiry;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Why a lookup failed; decides whether the failure may be cached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailKind {
    /// The name does not exist or has no addresses: cacheable.
    NotFound,
    /// The query timed out: retried once, never cached.
    Timeout,
    /// SERVFAIL, I/O or other transport failure: never cached.
    Transient,
}

#[derive(Debug, Clone)]
pub struct DnsFailure {
    pub kind: FailKind,
    pub message: String,
}

impl DnsFailure {
    pub fn new(kind: FailKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// A resolved name: addresses with their (unclamped) TTL, or the failure.
pub type BackendResult = Result<(Vec<IpAddr>, Duration), DnsFailure>;

/// Source of truth behind the cache.
pub trait DnsBackend: Send + Sync + 'static {
    fn lookup(&self, name: &str) -> BoxFut<BackendResult>;
}

/// Cache bounds.
#[derive(Debug, Clone)]
pub struct DnsCacheConfig {
    pub capacity: u64,
    pub min_ttl: Duration,
    pub max_ttl: Duration,
    pub negative_ttl: Duration,
}

impl From<&DnsSettings> for DnsCacheConfig {
    fn from(s: &DnsSettings) -> Self {
        let min = Duration::from_secs(s.min_ttl_secs);
        Self {
            capacity: s.cache_size.max(1),
            min_ttl: min,
            max_ttl: Duration::from_secs(s.max_ttl_secs).max(min),
            negative_ttl: Duration::from_secs(s.negative_ttl_secs),
        }
    }
}

#[derive(Clone)]
struct Entry {
    result: Result<Arc<[IpAddr]>, Arc<str>>,
    ttl: Duration,
}

struct PerEntry;
impl Expiry<Arc<str>, Entry> for PerEntry {
    fn expire_after_create(&self, _k: &Arc<str>, v: &Entry, _now: Instant) -> Option<Duration> {
        Some(v.ttl)
    }
}

/// TTL-respecting, bounded, single-flight DNS cache.
pub struct CachedResolver {
    /// Backend, cache and limits; replaced as a unit by [`Self::reconfigure`], so everyone
    /// holding this resolver switches over at once.
    inner: arc_swap::ArcSwap<Inner>,
    lookups: AtomicU64,
    /// Lookups that went to the backend.
    misses: AtomicU64,
}

struct Inner {
    backend: Arc<dyn DnsBackend>,
    cache: moka::future::Cache<Arc<str>, Entry>,
    cfg: DnsCacheConfig,
}

impl Inner {
    fn new(backend: Arc<dyn DnsBackend>, cfg: DnsCacheConfig) -> Self {
        let cache = moka::future::Cache::builder()
            .max_capacity(cfg.capacity)
            .expire_after(PerEntry)
            .build();
        Self {
            backend,
            cache,
            cfg,
        }
    }
}

impl CachedResolver {
    pub fn new(backend: Arc<dyn DnsBackend>, cfg: DnsCacheConfig) -> Self {
        Self {
            inner: arc_swap::ArcSwap::from_pointee(Inner::new(backend, cfg)),
            lookups: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Resolver for `settings`: hickory (system config or the configured servers) behind the cache.
    pub fn from_settings(settings: &DnsSettings) -> Self {
        Self::new(
            Arc::new(FallbackBackend {
                primary: Arc::new(HickoryBackend::new(settings)),
                secondary: Arc::new(OsBackend),
            }),
            DnsCacheConfig::from(settings),
        )
    }

    /// Switch to new settings. The servers are re-read and the cache starts empty (cached
    /// answers from the old servers must not outlive them); lookups already in flight finish
    /// on the old state.
    pub fn reconfigure(&self, settings: &DnsSettings) {
        self.reconfigure_with(
            Arc::new(FallbackBackend {
                primary: Arc::new(HickoryBackend::new(settings)),
                secondary: Arc::new(OsBackend),
            }),
            DnsCacheConfig::from(settings),
        );
    }

    /// [`Self::reconfigure`] with a ready backend.
    pub fn reconfigure_with(&self, backend: Arc<dyn DnsBackend>, cfg: DnsCacheConfig) {
        self.inner.store(Arc::new(Inner::new(backend, cfg)));
    }

    /// Names currently cached (after pending maintenance).
    pub async fn cached_names(&self) -> u64 {
        let inner = self.inner.load_full();
        inner.cache.run_pending_tasks().await;
        inner.cache.entry_count()
    }

    /// Cache hits and backend lookups so far.
    pub fn stats(&self) -> (u64, u64) {
        let (l, m) = (
            self.lookups.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        );
        (l.saturating_sub(m), m)
    }

    /// Addresses for `name` (cached). Policy is the caller's job.
    pub async fn resolve(&self, name: &str) -> Result<Arc<[IpAddr]>, String> {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        let key: Arc<str> = name.trim_end_matches('.').to_ascii_lowercase().into();
        let inner = self.inner.load_full();
        let backend = inner.backend.clone();
        let cfg = inner.cfg.clone();
        let misses = &self.misses;
        let k2 = key.clone();
        // `try_get_with` stores only `Ok`: transport failures are returned, not cached, and
        // concurrent callers of one lookup share its outcome.
        let entry = inner
            .cache
            .try_get_with(key, async move {
                misses.fetch_add(1, Ordering::Relaxed);
                let mut r = backend.lookup(&k2).await;
                if matches!(&r, Err(f) if f.kind == FailKind::Timeout) {
                    r = backend.lookup(&k2).await;
                }
                match r {
                    Ok((addrs, ttl)) if !addrs.is_empty() => Ok(Entry {
                        result: Ok(addrs.into()),
                        ttl: ttl.clamp(cfg.min_ttl, cfg.max_ttl),
                    }),
                    Ok(_) => Ok(Entry {
                        result: Err("no addresses".into()),
                        ttl: cfg.negative_ttl,
                    }),
                    Err(f) if f.kind == FailKind::NotFound => Ok(Entry {
                        result: Err(f.message.into()),
                        ttl: cfg.negative_ttl,
                    }),
                    Err(f) => Err(f),
                }
            })
            .await;
        let out = match entry {
            Ok(e) => e.result.map_err(|e| e.to_string()),
            Err(f) => Err(f.message.clone()),
        };
        if out.is_err() {
            common::faults::note(common::faults::Fault::DnsFailure, name);
        }
        out
    }
}

/// A [`CachedResolver`] as the address source of destination policies (`NetPolicy`).
#[derive(Clone)]
pub struct DnsHandle(pub Arc<CachedResolver>);

impl common::net_policy::NameResolver for DnsHandle {
    fn lookup(&self, name: &str) -> common::net_policy::AddrFuture {
        let name = name.to_string();
        let this = self.0.clone();
        Box::pin(async move {
            this.resolve(&name)
                .await
                .map(|a| a.to_vec())
                .map_err(std::io::Error::other)
        })
    }
}

impl std::fmt::Debug for CachedResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedResolver").finish_non_exhaustive()
    }
}

/// Operating-system resolver (`getaddrinfo`).
pub struct OsBackend;

impl DnsBackend for OsBackend {
    fn lookup(&self, name: &str) -> BoxFut<BackendResult> {
        let name = name.to_string();
        Box::pin(async move {
            match tokio::net::lookup_host((name.as_str(), 0)).await {
                Ok(addrs) => {
                    let v: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                    if v.is_empty() {
                        Err(DnsFailure::new(FailKind::NotFound, "no addresses"))
                    } else {
                        Ok((v, Duration::from_secs(30)))
                    }
                }
                Err(e) => Err(DnsFailure::new(classify_io(&e), e.to_string())),
            }
        })
    }
}

/// `getaddrinfo` reports "not found" as a plain error; its text is the only portable signal.
fn classify_io(e: &std::io::Error) -> FailKind {
    let m = e.to_string().to_ascii_lowercase();
    if m.contains("not known")
        || m.contains("no such host")
        || m.contains("no address associated")
        || m.contains("name or service not found")
        || m.contains("nodata")
    {
        FailKind::NotFound
    } else {
        FailKind::Transient
    }
}

/// Asks `secondary` only when `primary` says the name does not exist.
pub struct FallbackBackend {
    pub primary: Arc<dyn DnsBackend>,
    pub secondary: Arc<dyn DnsBackend>,
}

impl DnsBackend for FallbackBackend {
    fn lookup(&self, name: &str) -> BoxFut<BackendResult> {
        let first = self.primary.lookup(name);
        let secondary = self.secondary.clone();
        let name = name.to_string();
        Box::pin(async move {
            match first.await {
                Err(f) if f.kind == FailKind::NotFound => match secondary.lookup(&name).await {
                    Ok(r) => Ok(r),
                    // Both say the name does not exist; a transport failure of the second
                    // resolver is not an answer, so it stays uncached.
                    Err(g) if g.kind == FailKind::NotFound => Err(f),
                    Err(g) => Err(g),
                },
                other => other,
            }
        })
    }
}

/// Hickory-backed lookups; falls back to the OS resolver if the system configuration cannot be
/// read.
pub struct HickoryBackend {
    resolver: Option<hickory_resolver::TokioResolver>,
}

impl HickoryBackend {
    /// False when setup failed and lookups use the OS resolver instead.
    pub fn uses_hickory(&self) -> bool {
        self.resolver.is_some()
    }

    pub fn new(settings: &DnsSettings) -> Self {
        use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig};
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        use hickory_resolver::Resolver;

        let servers: Vec<SocketAddr> = settings
            .servers
            .iter()
            .filter_map(|s| {
                s.parse::<SocketAddr>()
                    .ok()
                    .or_else(|| s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53)))
                    .or_else(|| {
                        tracing::warn!("ignoring invalid DNS server {s:?}");
                        None
                    })
            })
            .collect();
        let builder = if servers.is_empty() {
            Resolver::builder_tokio().ok()
        } else {
            let ns = servers
                .iter()
                .map(|a| {
                    let mut n = NameServerConfig::udp_and_tcp(a.ip());
                    for c in &mut n.connections {
                        c.port = a.port();
                    }
                    n
                })
                .collect();
            Some(Resolver::builder_with_config(
                ResolverConfig::from_name_servers(ns),
                TokioRuntimeProvider::default(),
            ))
        };
        let resolver = builder.and_then(|mut b| {
            let o = b.options_mut();
            // Caching happens in `CachedResolver`, which owns the TTL clamps.
            o.cache_size = 0;
            o.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
            b.build().ok()
        });
        if resolver.is_none() {
            tracing::warn!("DNS: resolver setup failed, using the OS resolver");
        }
        Self { resolver }
    }
}

/// Only an authoritative "no such name" / "no records" answer is a negative result; a timeout is
/// retried, everything else (SERVFAIL, refused, I/O) is transient. Checked against hickory-net
/// 0.26: `NetError::is_no_records_found` covers NXDOMAIN and NODATA (`DnsError::NoRecordsFound`).
fn classify_hickory(e: &hickory_resolver::net::NetError) -> FailKind {
    if e.is_no_records_found() {
        FailKind::NotFound
    } else if matches!(e, hickory_resolver::net::NetError::Timeout) {
        FailKind::Timeout
    } else {
        FailKind::Transient
    }
}

impl DnsBackend for HickoryBackend {
    fn lookup(&self, name: &str) -> BoxFut<BackendResult> {
        let name = name.to_string();
        let resolver = self.resolver.clone();
        Box::pin(async move {
            match resolver {
                Some(r) => {
                    let l = r
                        .lookup_ip(name.as_str())
                        .await
                        .map_err(|e| DnsFailure::new(classify_hickory(&e), e.to_string()))?;
                    let ttl = l.valid_until().saturating_duration_since(Instant::now());
                    Ok((l.iter().collect(), ttl))
                }
                None => OsBackend.lookup(&name).await,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fake {
        calls: AtomicU64,
        answer: Mutex<BackendResult>,
        /// Answers handed out first, in order, before `answer`.
        script: Mutex<Vec<BackendResult>>,
    }
    impl DnsBackend for Fake {
        fn lookup(&self, _name: &str) -> BoxFut<BackendResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut sc = self.script.lock().unwrap();
            let a = if sc.is_empty() {
                self.answer.lock().unwrap().clone()
            } else {
                sc.remove(0)
            };
            Box::pin(async move { a })
        }
    }
    fn failing(kind: FailKind) -> Arc<Fake> {
        Arc::new(Fake {
            calls: AtomicU64::new(0),
            answer: Mutex::new(Err(DnsFailure::new(kind, "boom"))),
            script: Mutex::new(vec![]),
        })
    }
    fn fake(ip: &str, ttl: Duration) -> Arc<Fake> {
        Arc::new(Fake {
            calls: AtomicU64::new(0),
            answer: Mutex::new(Ok((vec![ip.parse().unwrap()], ttl))),
            script: Mutex::new(vec![]),
        })
    }
    fn cfg(min: u64, max: u64) -> DnsCacheConfig {
        DnsCacheConfig {
            capacity: 100,
            min_ttl: Duration::from_millis(min),
            max_ttl: Duration::from_millis(max),
            negative_ttl: Duration::from_millis(min),
        }
    }

    #[tokio::test]
    async fn second_lookup_is_a_cache_hit() {
        let f = fake("203.0.113.5", Duration::from_secs(60));
        let r = CachedResolver::new(f.clone(), cfg(10_000, 60_000));
        let a = r.resolve("Example.test.").await.unwrap();
        let b = r.resolve("example.test").await.unwrap();
        assert_eq!(a, b);
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
        assert_eq!(r.stats().1, 1);
    }

    #[tokio::test]
    async fn expired_entry_is_re_resolved_and_ttl_is_clamped() {
        // Backend TTL 1 h is clamped to the 200 ms maximum.
        let f = fake("203.0.113.5", Duration::from_secs(3600));
        let r = CachedResolver::new(f.clone(), cfg(50, 200));
        r.resolve("a.test").await.unwrap();
        tokio::time::sleep(Duration::from_millis(350)).await;
        *f.answer.lock().unwrap() = Ok((vec!["203.0.113.6".parse().unwrap()], Duration::ZERO));
        let again = r.resolve("a.test").await.unwrap();
        assert_eq!(f.calls.load(Ordering::SeqCst), 2);
        assert_eq!(again[0], "203.0.113.6".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn nxdomain_is_cached_negatively() {
        let f = failing(FailKind::NotFound);
        let r = CachedResolver::new(f.clone(), cfg(5_000, 60_000));
        assert!(r.resolve("nx.test").await.is_err());
        assert!(r.resolve("nx.test").await.is_err());
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn transport_errors_are_never_cached() {
        let f = failing(FailKind::Transient);
        let r = CachedResolver::new(f.clone(), cfg(5_000, 60_000));
        assert!(r.resolve("flaky.test").await.is_err());
        assert!(r.resolve("flaky.test").await.is_err());
        assert_eq!(
            f.calls.load(Ordering::SeqCst),
            2,
            "a lost answer must not stick"
        );
        // The next client gets a fresh attempt and succeeds.
        *f.answer.lock().unwrap() = Ok((
            vec!["203.0.113.9".parse().unwrap()],
            Duration::from_secs(60),
        ));
        assert!(r.resolve("flaky.test").await.is_ok());
    }

    #[tokio::test]
    async fn a_timeout_is_retried_once_and_not_cached() {
        let f = failing(FailKind::Timeout);
        let r = CachedResolver::new(f.clone(), cfg(5_000, 60_000));
        assert!(r.resolve("slow.test").await.is_err());
        assert_eq!(f.calls.load(Ordering::SeqCst), 2, "one retry, no more");
        assert!(r.resolve("slow.test").await.is_err());
        assert_eq!(f.calls.load(Ordering::SeqCst), 4);
        // First attempt times out, the retry answers.
        let g = failing(FailKind::Timeout);
        g.script
            .lock()
            .unwrap()
            .push(Err(DnsFailure::new(FailKind::Timeout, "t")));
        *g.answer.lock().unwrap() = Ok((
            vec!["203.0.113.9".parse().unwrap()],
            Duration::from_secs(60),
        ));
        let r = CachedResolver::new(g.clone(), cfg(5_000, 60_000));
        assert!(r.resolve("slow2.test").await.is_ok());
        assert_eq!(g.calls.load(Ordering::SeqCst), 2);
    }

    /// CONNECT, WebSocket and transparent dials go through `DestPolicy::resolve`; it must use the
    /// cache, apply the policy to the cached answer, and see OS-only names.
    #[tokio::test]
    async fn policy_dials_use_the_cache_and_the_os_fallback() {
        use crate::policy::DestPolicy;
        let ok = fake("203.0.113.7", Duration::from_secs(60));
        let backend = Arc::new(FallbackBackend {
            primary: failing(FailKind::NotFound),
            secondary: ok.clone(),
        });
        let dns = Arc::new(CachedResolver::new(backend, cfg(5_000, 60_000)));
        let policy = DestPolicy::new(false, &[])
            .unwrap()
            .with_resolver(Arc::new(DnsHandle(dns.clone())));
        for _ in 0..3 {
            let a = policy.resolve("printer.local", 9100, None).await.unwrap();
            assert_eq!(a, "203.0.113.7:9100".parse::<SocketAddr>().unwrap());
        }
        assert_eq!(ok.calls.load(Ordering::SeqCst), 1, "resolved once, cached");
        // The policy still judges cached answers.
        let loopback = Arc::new(CachedResolver::new(
            fake("127.0.0.1", Duration::from_secs(60)),
            cfg(5_000, 60_000),
        ));
        let p = DestPolicy::new(false, &[])
            .unwrap()
            .with_resolver(Arc::new(DnsHandle(loopback)));
        for _ in 0..2 {
            assert!(p.resolve("rebind.test", 80, None).await.is_err());
        }
    }

    #[tokio::test]
    async fn os_fallback_only_on_nonexistence() {
        let ok = fake("203.0.113.7", Duration::from_secs(60));
        let nx = failing(FailKind::NotFound);
        let r = CachedResolver::new(
            Arc::new(FallbackBackend {
                primary: nx,
                secondary: ok.clone(),
            }),
            cfg(5_000, 60_000),
        );
        assert_eq!(
            r.resolve("printer.local").await.unwrap()[0],
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
        let ok2 = fake("203.0.113.7", Duration::from_secs(60));
        let r = CachedResolver::new(
            Arc::new(FallbackBackend {
                primary: failing(FailKind::Transient),
                secondary: ok2.clone(),
            }),
            cfg(5_000, 60_000),
        );
        assert!(r.resolve("x.test").await.is_err());
        assert_eq!(
            ok2.calls.load(Ordering::SeqCst),
            0,
            "a transient failure is not 'does not exist'"
        );
    }

    fn settings(servers: Vec<String>) -> DnsSettings {
        DnsSettings {
            servers,
            cache_size: 100,
            min_ttl_secs: 1,
            max_ttl_secs: 60,
            negative_ttl_secs: 1,
        }
    }

    /// Minimal UDP DNS server: answers every A query with 192.0.2.77 (TTL 300). Counts queries.
    fn fake_dns_server() -> (SocketAddr, Arc<AtomicU64>) {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let n = Arc::new(AtomicU64::new(0));
        let n2 = n.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((len, peer)) = sock.recv_from(&mut buf) {
                n2.fetch_add(1, Ordering::SeqCst);
                let q = &buf[..len];
                // Question section ends after the name (labels, 0) plus type and class.
                let mut i = 12;
                while q[i] != 0 {
                    i += q[i] as usize + 1;
                }
                let qend = i + 1 + 4;
                let qtype = u16::from_be_bytes([q[qend - 4], q[qend - 3]]);
                let mut r = Vec::new();
                r.extend_from_slice(&q[..2]); // id
                                              // `nx.*` answers NXDOMAIN, `fail.*` SERVFAIL, anything else succeeds.
                let rcode = match &q[13..15] {
                    b"nx" => 3,
                    b"fa" => 2,
                    _ => 0,
                };
                r.extend_from_slice(&[0x81, 0x80 | rcode, 0, 1]); // response, RD+RA, qdcount
                let an: u16 = if qtype == 1 && rcode == 0 { 1 } else { 0 };
                r.extend_from_slice(&an.to_be_bytes());
                r.extend_from_slice(&[0, 0, 0, 0]);
                r.extend_from_slice(&q[12..qend]);
                if an == 1 {
                    r.extend_from_slice(&[
                        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 192, 0, 2, 77,
                    ]);
                }
                let _ = sock.send_to(&r, peer);
            }
        });
        (addr, n)
    }

    #[tokio::test]
    async fn explicit_server_with_port_override_resolves_and_caches() {
        let (addr, queries) = fake_dns_server();
        assert_ne!(addr.port(), 53);
        let st = settings(vec![addr.to_string()]);
        let b = HickoryBackend::new(&st);
        assert!(b.uses_hickory());
        let r = CachedResolver::new(Arc::new(b), DnsCacheConfig::from(&st));
        let a = r.resolve("host.example.test").await.unwrap();
        assert_eq!(a[0], "192.0.2.77".parse::<IpAddr>().unwrap());
        let before = queries.load(Ordering::SeqCst);
        assert!(before >= 1);
        r.resolve("host.example.test").await.unwrap();
        assert_eq!(
            queries.load(Ordering::SeqCst),
            before,
            "second lookup must hit the cache"
        );
    }

    #[tokio::test]
    async fn hickory_caches_nxdomain_but_not_servfail() {
        let (addr, queries) = fake_dns_server();
        let st = settings(vec![addr.to_string()]);
        let r = CachedResolver::new(
            Arc::new(HickoryBackend::new(&st)),
            DnsCacheConfig {
                negative_ttl: Duration::from_secs(30),
                ..DnsCacheConfig::from(&st)
            },
        );
        assert!(r.resolve("nx.example.test").await.is_err());
        let n = queries.load(Ordering::SeqCst);
        assert!(r.resolve("nx.example.test").await.is_err());
        assert_eq!(queries.load(Ordering::SeqCst), n, "NXDOMAIN is cached");

        assert!(r.resolve("fail.example.test").await.is_err());
        let n = queries.load(Ordering::SeqCst);
        assert!(r.resolve("fail.example.test").await.is_err());
        assert!(
            queries.load(Ordering::SeqCst) > n,
            "SERVFAIL must be asked again"
        );
    }

    #[tokio::test]
    async fn system_config_resolves_localhost() {
        let b = HickoryBackend::new(&settings(vec![]));
        assert!(
            b.uses_hickory(),
            "system resolver configuration was not usable"
        );
        let r = CachedResolver::new(Arc::new(b), DnsCacheConfig::from(&settings(vec![])));
        let a = r.resolve("localhost").await.unwrap();
        assert!(a.iter().any(|ip| ip.is_loopback()), "{a:?}");
    }

    #[tokio::test]
    async fn reconfigure_swaps_backend_and_flushes_the_cache() {
        let cfg = DnsCacheConfig::from(&DnsSettings::default());
        let old = fake("192.0.2.1", Duration::from_secs(300));
        let r = CachedResolver::new(old.clone(), cfg.clone());
        assert_eq!(
            &*r.resolve("a.test").await.unwrap(),
            &["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(r.cached_names().await, 1);
        let new = fake("192.0.2.2", Duration::from_secs(300));
        r.reconfigure_with(new.clone(), cfg);
        assert_eq!(r.cached_names().await, 0, "cache flushed");
        assert_eq!(
            &*r.resolve("a.test").await.unwrap(),
            &["192.0.2.2".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(old.calls.load(Ordering::SeqCst), 1);
    }
}

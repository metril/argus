//! Name resolution for Argus's own upstream connections.
//!
//! Every hostname Argus connects to (the wreq client, CONNECT and transparent tunnels,
//! WebSockets, the upstream proxy, control-plane fetches) goes through one [`Resolver`]
//! (a [`CachedResolver`] over the upstream-DNS [`engine`]). Argus is not a DNS server.
//!
//! The cache stores only resolved addresses (clamped to the configured TTL bounds). Only
//! definite negative answers (NXDOMAIN, or a name with no address records) are cached, briefly;
//! transport failures (timeouts, SERVFAIL, I/O errors) never are, and a timed-out lookup is
//! retried once. With optimistic caching an expired answer is served at once while a refresh runs
//! in the background. The cache never decides policy: callers apply the destination policy to the
//! addresses returned on every lookup, hit or miss, and connect to exactly those addresses.
//!
//! With no upstream configured the engine uses the system resolver (hickory, then the OS for
//! names hickory cannot resolve, such as mDNS `.local` or NSS sources); the policy still judges
//! whatever either returned.

use common::config::DnsSettings;
use moka::Expiry;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub mod dnscrypt;
pub mod engine;
pub mod upstream;

#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod stub;

pub use engine::{Engine, EngineResolver, EngineSpec, ProbeResult, RaceOpts};
pub use upstream::UpstreamStats;

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// How long an expired answer may still be served by the optimistic cache.
const OPTIMISTIC_STALE_MAX: Duration = Duration::from_secs(24 * 3600);
/// After a failed background refresh, how long the stale answer is treated as fresh again.
const REFRESH_BACKOFF: Duration = Duration::from_secs(5);

/// Why a lookup failed; decides whether the failure may be cached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailKind {
    /// The name does not exist or has no addresses: cacheable.
    NotFound,
    /// The query timed out: retried once, never cached.
    Timeout,
    /// SERVFAIL, I/O or other transport failure: never cached.
    Transient,
    /// DNSSEC validation failed: never cached, never retried elsewhere.
    Dnssec,
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

/// The one resolution interface: the engine, the system resolver and test doubles implement it,
/// and the cache wraps it.
pub trait Resolver: Send + Sync + 'static {
    /// Addresses of `name` (A and AAAA).
    fn lookup(&self, name: &str) -> BoxFut<BackendResult>;

    /// Host names of `ip` (PTR).
    fn lookup_ptr(&self, _ip: IpAddr) -> BoxFut<Result<Vec<String>, DnsFailure>> {
        Box::pin(async {
            Err(DnsFailure::new(
                FailKind::Transient,
                "reverse lookups are not supported by this resolver",
            ))
        })
    }

    /// Per-upstream health and RTT figures (empty when there are no upstreams to report).
    fn stats(&self) -> Vec<UpstreamStats> {
        Vec::new()
    }
}

/// Old name of [`Resolver`].
pub use Resolver as DnsBackend;

// ---- DNS message helpers shared by the engine and the upstreams ----

/// A recursive query for `name`/`rtype` with EDNS (and ECS when given).
pub(crate) fn query_message(
    name: &str,
    rtype: hickory_resolver::proto::rr::RecordType,
    ecs: Option<hickory_resolver::proto::rr::rdata::opt::ClientSubnet>,
) -> hickory_resolver::proto::op::Message {
    use hickory_resolver::proto::op::{Edns, Message, Query};
    use hickory_resolver::proto::rr::rdata::opt::EdnsOption;
    use hickory_resolver::proto::rr::Name;
    let mut m = Message::query();
    m.metadata.id = rand::random();
    m.metadata.recursion_desired = true;
    let n = Name::from_ascii(format!("{}.", name.trim_end_matches('.'))).unwrap_or_default();
    m.add_query(Query::query(n, rtype));
    let mut e = Edns::new();
    e.set_max_payload(1232);
    if let Some(c) = ecs {
        e.options_mut().insert(EdnsOption::Subnet(c));
    }
    m.set_edns(e);
    m
}

/// Addresses in the answer section and the smallest TTL among them (seconds).
pub(crate) fn addresses(m: &hickory_resolver::proto::op::Message) -> (Vec<IpAddr>, u32) {
    use hickory_resolver::proto::rr::RData;
    let mut ips = Vec::new();
    let mut ttl = u32::MAX;
    for r in &m.answers {
        match &r.data {
            RData::A(a) => ips.push(IpAddr::V4(a.0)),
            RData::AAAA(a) => ips.push(IpAddr::V6(a.0)),
            _ => continue,
        }
        ttl = ttl.min(r.ttl);
    }
    (ips, ttl)
}

/// Whether DNSSEC validation marked any answer record bogus.
pub(crate) fn has_bogus(m: &hickory_resolver::proto::op::Message) -> bool {
    use hickory_resolver::proto::dnssec::Proof;
    m.answers.iter().any(|r| r.proof == Proof::Bogus)
}

/// Cache bounds.
#[derive(Debug, Clone)]
pub struct DnsCacheConfig {
    pub capacity: u64,
    pub min_ttl: Duration,
    pub max_ttl: Duration,
    pub negative_ttl: Duration,
    /// Serve expired answers while refreshing in the background.
    pub optimistic: bool,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            capacity: 4096,
            min_ttl: Duration::from_secs(10),
            max_ttl: Duration::from_secs(300),
            negative_ttl: Duration::from_secs(10),
            optimistic: false,
        }
    }
}

impl From<&DnsSettings> for DnsCacheConfig {
    fn from(s: &DnsSettings) -> Self {
        let min = Duration::from_secs(s.min_ttl_secs);
        Self {
            capacity: s.cache_size.max(1),
            min_ttl: min,
            max_ttl: Duration::from_secs(s.max_ttl_secs).max(min),
            negative_ttl: Duration::from_secs(s.negative_ttl_secs),
            optimistic: s.optimistic_cache,
        }
    }
}

#[derive(Clone)]
struct Entry {
    result: Result<Arc<[IpAddr]>, Arc<str>>,
    /// Until when the answer is fresh.
    fresh_until: Instant,
    /// How long the cache keeps the entry (longer than `fresh_until` for optimistic hits).
    keep: Duration,
}

struct PerEntry;
impl Expiry<Arc<str>, Entry> for PerEntry {
    fn expire_after_create(&self, _k: &Arc<str>, v: &Entry, _now: Instant) -> Option<Duration> {
        Some(v.keep)
    }
    fn expire_after_update(
        &self,
        _k: &Arc<str>,
        v: &Entry,
        _now: Instant,
        _d: Option<Duration>,
    ) -> Option<Duration> {
        Some(v.keep)
    }
}

/// TTL-respecting, bounded, single-flight DNS cache.
pub struct CachedResolver {
    /// Backend, cache and limits; replaced as a unit by [`Self::reconfigure`], so everyone
    /// holding this resolver switches over at once.
    inner: arc_swap::ArcSwap<Inner>,
    lookups: AtomicU64,
    /// Lookups that went to the backend.
    misses: Arc<AtomicU64>,
    /// Whether fastest-address mode may dial the answers directly (off behind an upstream proxy).
    direct_probes: Arc<std::sync::atomic::AtomicBool>,
}

struct Inner {
    backend: Arc<dyn Resolver>,
    cache: moka::future::Cache<Arc<str>, Entry>,
    cfg: DnsCacheConfig,
    /// Names being refreshed in the background.
    refreshing: parking_lot::Mutex<std::collections::HashSet<Arc<str>>>,
}

impl Inner {
    fn new(backend: Arc<dyn Resolver>, cfg: DnsCacheConfig) -> Self {
        let cache = moka::future::Cache::builder()
            .max_capacity(cfg.capacity)
            .expire_after(PerEntry)
            .build();
        Self {
            backend,
            cache,
            cfg,
            refreshing: Default::default(),
        }
    }

    /// Ask the backend (one retry on timeout) and turn the answer into a cache entry. Transport
    /// failures are errors, not entries.
    async fn fetch(&self, name: &str) -> Result<Entry, DnsFailure> {
        let cfg = &self.cfg;
        let mut r = self.backend.lookup(name).await;
        if matches!(&r, Err(f) if f.kind == FailKind::Timeout) {
            r = self.backend.lookup(name).await;
        }
        let now = Instant::now();
        let neg = |msg: Arc<str>| Entry {
            result: Err(msg),
            fresh_until: now + cfg.negative_ttl,
            keep: cfg.negative_ttl,
        };
        match r {
            Ok((addrs, ttl)) if !addrs.is_empty() => {
                let ttl = ttl.clamp(cfg.min_ttl, cfg.max_ttl);
                Ok(Entry {
                    result: Ok(addrs.into()),
                    fresh_until: now + ttl,
                    keep: if cfg.optimistic {
                        ttl + OPTIMISTIC_STALE_MAX
                    } else {
                        ttl
                    },
                })
            }
            Ok(_) => Ok(neg("no addresses".into())),
            Err(f) if f.kind == FailKind::NotFound => Ok(neg(f.message.into())),
            Err(f) => Err(f),
        }
    }
}

/// The resolver for the system's own configuration: hickory, then the OS for names hickory
/// cannot resolve.
pub fn system_resolver() -> Arc<dyn Resolver> {
    Arc::new(FallbackBackend {
        primary: Arc::new(HickoryBackend::system()),
        secondary: Arc::new(OsBackend),
    })
}

impl CachedResolver {
    pub fn new(backend: Arc<dyn Resolver>, cfg: DnsCacheConfig) -> Self {
        Self {
            inner: arc_swap::ArcSwap::from_pointee(Inner::new(backend, cfg)),
            lookups: AtomicU64::new(0),
            misses: Arc::new(AtomicU64::new(0)),
            direct_probes: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }

    /// The upstream-DNS engine for `settings` behind the cache.
    pub fn from_settings(settings: &DnsSettings) -> Self {
        Self::from_settings_with(settings, &[])
    }

    /// [`Self::from_settings`] with the lines of `upstreams_source` already loaded.
    pub fn from_settings_with(settings: &DnsSettings, extra_lines: &[String]) -> Self {
        let me = Self::new(
            system_resolver(),
            DnsCacheConfig::from(settings),
        );
        me.reconfigure_lines(settings, extra_lines);
        me
    }

    /// Allow or forbid dialing returned addresses to find the fastest (forbidden when an
    /// upstream proxy is configured: a direct dial would reveal this host's address).
    pub fn set_direct_probes(&self, on: bool) {
        self.direct_probes
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// Switch to new settings. The upstreams are rebuilt and the cache starts empty (cached
    /// answers from the old servers must not outlive them); lookups already in flight finish on
    /// the old state.
    pub fn reconfigure(&self, settings: &DnsSettings) {
        self.reconfigure_lines(settings, &[]);
    }

    /// [`Self::reconfigure`] with the lines of `upstreams_source` already loaded.
    pub fn reconfigure_lines(&self, settings: &DnsSettings, extra_lines: &[String]) {
        self.reconfigure_with(
            backend_for(settings, extra_lines, self.direct_probes.clone()),
            DnsCacheConfig::from(settings),
        );
    }

    /// [`Self::reconfigure`] with a ready backend.
    pub fn reconfigure_with(&self, backend: Arc<dyn Resolver>, cfg: DnsCacheConfig) {
        self.inner.store(Arc::new(Inner::new(backend, cfg)));
    }

    /// Names currently cached (after pending maintenance).
    pub async fn cached_names(&self) -> u64 {
        let inner = self.inner.load_full();
        inner.cache.run_pending_tasks().await;
        inner.cache.entry_count()
    }

    /// Names in the cache right now (not waiting for pending maintenance).
    pub fn cached_names_approx(&self) -> u64 {
        self.inner.load().cache.entry_count()
    }

    /// Cache hits and backend lookups so far.
    pub fn stats(&self) -> (u64, u64) {
        let (l, m) = (
            self.lookups.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        );
        (l.saturating_sub(m), m)
    }

    /// Health and RTT of every configured upstream.
    pub fn upstream_stats(&self) -> Vec<UpstreamStats> {
        self.inner.load().backend.stats()
    }

    /// Drop the cached answer for `name`, so the next lookup asks again.
    pub async fn forget(&self, name: &str) {
        let key: Arc<str> = name.trim_end_matches('.').to_ascii_lowercase().into();
        self.inner.load_full().cache.invalidate(&key).await;
    }

    /// Host names of `ip` (uncached).
    pub async fn resolve_ptr(&self, ip: IpAddr) -> Result<Vec<String>, String> {
        let b = self.inner.load().backend.clone();
        b.lookup_ptr(ip).await.map_err(|f| f.message)
    }

    /// Addresses for `name` (cached). Policy is the caller's job.
    pub async fn resolve(&self, name: &str) -> Result<Arc<[IpAddr]>, String> {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        let key: Arc<str> = name.trim_end_matches('.').to_ascii_lowercase().into();
        let inner = self.inner.load_full();
        if let Some(e) = inner.cache.get(&key).await {
            if Instant::now() < e.fresh_until {
                return e.result.map_err(|e| e.to_string());
            }
            // Expired but still held: only optimistic answers (successes) are.
            if let Ok(a) = &e.result {
                Self::refresh_later(inner.clone(), key.clone(), e.clone());
                return Ok(a.clone());
            }
            inner.cache.invalidate(&key).await;
        }
        let misses = self.misses.clone();
        let (i2, k2) = (inner.clone(), key.clone());
        // `try_get_with` stores only `Ok`: transport failures are returned, not cached, and
        // concurrent callers of one lookup share its outcome.
        let entry = inner
            .cache
            .try_get_with(key, async move {
                misses.fetch_add(1, Ordering::Relaxed);
                i2.fetch(&k2).await
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

    /// Refresh `key` in the background (once at a time), keeping the stale answer if it fails.
    fn refresh_later(inner: Arc<Inner>, key: Arc<str>, stale: Entry) {
        if !inner.refreshing.lock().insert(key.clone()) {
            return;
        }
        tokio::spawn(async move {
            match inner.fetch(&key).await {
                Ok(e) => inner.cache.insert(key.clone(), e).await,
                Err(_) => {
                    // Keep serving the stale answer, and look again shortly.
                    let mut e = stale;
                    e.fresh_until = Instant::now() + REFRESH_BACKOFF;
                    inner.cache.insert(key.clone(), e).await;
                }
            }
            inner.refreshing.lock().remove(&key);
        });
    }
}

/// The backend for `settings`: the upstream-DNS engine, or the system resolver if the settings
/// cannot be built (they are validated before they get here).
fn backend_for(
    settings: &DnsSettings,
    extra_lines: &[String],
    direct_probes: Arc<std::sync::atomic::AtomicBool>,
) -> Arc<dyn Resolver> {
    match Engine::new(EngineSpec {
        settings,
        extra_lines,
        tls: None,
        system: system_resolver(),
        race: RaceOpts {
            enabled: direct_probes,
            ..Default::default()
        },
    }) {
        Ok(e) => Arc::new(EngineResolver(Arc::new(e))),
        Err(e) => {
            tracing::warn!("DNS: {e}; using the system resolver");
            system_resolver()
        }
    }
}

/// Read at most `max` bytes from a stream of chunks; more is an error (the rest is not read).
async fn read_capped<S, E>(mut s: S, max: usize) -> Result<Vec<u8>, String>
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    use futures_util::StreamExt;
    let mut out = Vec::new();
    while let Some(c) = s.next().await {
        let c = c.map_err(|e| format!("dns.upstreams_source: {e}"))?;
        if out.len() + c.len() > max {
            return Err("dns.upstreams_source is larger than 1 MiB".into());
        }
        out.extend_from_slice(&c);
    }
    Ok(out)
}

const SOURCE_MAX: usize = 1 << 20;

/// Lines from `settings.upstreams_source`; empty when unset. A file must lie inside
/// `<data_dir>/dns/` (after resolving symlinks and `..`); a URL must be https and resolve only
/// to public addresses, with no redirects. Errors never repeat the content of the source.
pub async fn load_upstream_lines(
    settings: &DnsSettings,
    data_dir: &std::path::Path,
) -> Result<Vec<String>, String> {
    let src = settings.upstreams_source.trim();
    if src.is_empty() {
        return Ok(Vec::new());
    }
    let text = if src.contains("://") {
        fetch_source_url(src).await?
    } else {
        read_source_file(src, data_dir).await?
    };
    let lines: Vec<String> = text.lines().map(|l| l.trim().to_string()).collect();
    dns_syntax::parse_upstreams(&lines).map_err(|e| {
        format!(
            "dns.upstreams_source, line {}: not a valid upstream line",
            e[0].0
        )
    })?;
    Ok(lines)
}

async fn read_source_file(src: &str, data_dir: &std::path::Path) -> Result<String, String> {
    use tokio::io::AsyncReadExt;
    let base = data_dir.join("dns");
    let _ = tokio::fs::create_dir_all(&base).await;
    let base = tokio::fs::canonicalize(&base)
        .await
        .map_err(|_| "dns.upstreams_source: the data directory has no dns folder".to_string())?;
    let p = std::path::Path::new(src);
    let cand = if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    };
    let real = tokio::fs::canonicalize(&cand)
        .await
        .map_err(|_| "dns.upstreams_source: file not found".to_string())?;
    if !real.starts_with(&base) {
        return Err("dns.upstreams_source must be a file inside the data directory's dns folder".into());
    }
    let f = tokio::fs::File::open(&real)
        .await
        .map_err(|_| "dns.upstreams_source: cannot read the file".to_string())?;
    let mut buf = Vec::new();
    f.take(SOURCE_MAX as u64 + 1)
        .read_to_end(&mut buf)
        .await
        .map_err(|_| "dns.upstreams_source: cannot read the file".to_string())?;
    if buf.len() > SOURCE_MAX {
        return Err("dns.upstreams_source is larger than 1 MiB".into());
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

async fn fetch_source_url(src: &str) -> Result<String, String> {
    let url = url::Url::parse(src).map_err(|_| "dns.upstreams_source is not a valid URL".to_string())?;
    if url.scheme() != "https" {
        return Err("dns.upstreams_source URLs must be https".into());
    }
    let host = url
        .host_str()
        .ok_or("dns.upstreams_source has no host")?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|_| "dns.upstreams_source: the host does not resolve".to_string())?
        .collect();
    // Every address must be public: the fetch must not reach internal services.
    if addrs.is_empty()
        || addrs
            .iter()
            .any(|a| common::net_policy::classify(a.ip()) != common::net_policy::Class::Public)
    {
        return Err("dns.upstreams_source resolves to a non-public address".into());
    }
    let client = wreq::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(wreq::redirect::Policy::none())
        .resolve(host.clone(), addrs[0])
        .build()
        .map_err(|_| "dns.upstreams_source: cannot build the client".to_string())?;
    let resp = client
        .get(url.as_str())
        .send()
        .await
        .map_err(|_| "dns.upstreams_source: the request failed".to_string())?;
    if !resp.status().is_success() {
        return Err(format!("dns.upstreams_source: HTTP {}", resp.status()));
    }
    if resp.content_length().is_some_and(|l| l > SOURCE_MAX as u64) {
        return Err("dns.upstreams_source is larger than 1 MiB".into());
    }
    let body = read_capped(Box::pin(resp.bytes_stream()), SOURCE_MAX).await?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Probe every upstream in `settings` (plus `extra_lines`) once with a fresh engine; nothing in
/// force changes.
pub async fn test_upstreams(
    settings: &DnsSettings,
    extra_lines: &[String],
) -> Result<Vec<ProbeResult>, String> {
    let e = Engine::new(EngineSpec {
        settings,
        extra_lines,
        tls: None,
        system: system_resolver(),
        race: Default::default(),
    })?;
    Ok(e.probe("example.com").await)
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

impl Resolver for OsBackend {
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
    pub primary: Arc<dyn Resolver>,
    pub secondary: Arc<dyn Resolver>,
}

impl Resolver for FallbackBackend {
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

    fn lookup_ptr(&self, ip: IpAddr) -> BoxFut<Result<Vec<String>, DnsFailure>> {
        self.primary.lookup_ptr(ip)
    }
}

/// Hickory lookups with the system resolver configuration (`/etc/resolv.conf`); uses the OS
/// resolver if that configuration cannot be read.
pub struct HickoryBackend {
    resolver: Option<hickory_resolver::TokioResolver>,
}

impl HickoryBackend {
    /// False when setup failed and lookups use the OS resolver instead.
    pub fn uses_hickory(&self) -> bool {
        self.resolver.is_some()
    }

    /// The system resolver configuration.
    pub fn system() -> Self {
        use hickory_resolver::config::LookupIpStrategy;
        use hickory_resolver::Resolver;
        let resolver = Resolver::builder_tokio().ok().and_then(|mut b| {
            let o = b.options_mut();
            // Caching happens in `CachedResolver`, which owns the TTL clamps.
            o.cache_size = 0;
            o.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
            b.build().ok()
        });
        if resolver.is_none() {
            tracing::warn!("DNS: system resolver setup failed, using the OS resolver");
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

impl Resolver for HickoryBackend {
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

    fn lookup_ptr(&self, ip: IpAddr) -> BoxFut<Result<Vec<String>, DnsFailure>> {
        let resolver = self.resolver.clone();
        Box::pin(async move {
            let r = resolver.ok_or_else(|| {
                DnsFailure::new(FailKind::Transient, "no system resolver configuration")
            })?;
            let l = r
                .reverse_lookup(ip)
                .await
                .map_err(|e| DnsFailure::new(classify_hickory(&e), e.to_string()))?;
            Ok(l.answers()
                .iter()
                .filter_map(|r| match &r.data {
                    hickory_resolver::proto::rr::RData::PTR(p) => {
                        Some(p.0.to_utf8().trim_end_matches('.').to_string())
                    }
                    _ => None,
                })
                .collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Mutex;

    struct Fake {
        calls: AtomicU64,
        answer: Mutex<BackendResult>,
        /// Answers handed out first, in order, before `answer`.
        script: Mutex<Vec<BackendResult>>,
    }
    impl Resolver for Fake {
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
            optimistic: false,
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
            ..Default::default()
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
        let r = CachedResolver::from_settings(&st);
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
        let r = CachedResolver::from_settings(&DnsSettings {
            negative_ttl_secs: 30,
            ..st
        });
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
        let b = HickoryBackend::system();
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

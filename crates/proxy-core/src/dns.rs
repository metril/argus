//! Caching DNS resolution for upstream connections.
//!
//! The cache stores only resolved addresses (clamped to the configured TTL bounds, failures
//! cached briefly). It never decides policy: callers apply the destination policy to the
//! addresses returned on every lookup, hit or miss, and connect to exactly those addresses.

use common::config::DnsSettings;
use moka::Expiry;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// A resolved name: addresses with their (unclamped) TTL, or an error message.
pub type BackendResult = Result<(Vec<IpAddr>, Duration), String>;

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
    backend: Arc<dyn DnsBackend>,
    cache: moka::future::Cache<Arc<str>, Entry>,
    cfg: DnsCacheConfig,
    lookups: AtomicU64,
    /// Lookups that went to the backend.
    misses: AtomicU64,
}

impl CachedResolver {
    pub fn new(backend: Arc<dyn DnsBackend>, cfg: DnsCacheConfig) -> Self {
        let cache = moka::future::Cache::builder()
            .max_capacity(cfg.capacity)
            .expire_after(PerEntry)
            .build();
        Self {
            backend,
            cache,
            cfg,
            lookups: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Resolver for `settings`: hickory (system config or the configured servers) behind the cache.
    pub fn from_settings(settings: &DnsSettings) -> Self {
        Self::new(
            Arc::new(HickoryBackend::new(settings)),
            DnsCacheConfig::from(settings),
        )
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
        let backend = self.backend.clone();
        let cfg = self.cfg.clone();
        let misses = &self.misses;
        let k2 = key.clone();
        let entry = self
            .cache
            .get_with(key, async move {
                misses.fetch_add(1, Ordering::Relaxed);
                match backend.lookup(&k2).await {
                    Ok((addrs, ttl)) if !addrs.is_empty() => Entry {
                        result: Ok(addrs.into()),
                        ttl: ttl.clamp(cfg.min_ttl, cfg.max_ttl),
                    },
                    Ok(_) => Entry {
                        result: Err("no addresses".into()),
                        ttl: cfg.negative_ttl,
                    },
                    Err(e) => Entry {
                        result: Err(e.into()),
                        ttl: cfg.negative_ttl,
                    },
                }
            })
            .await;
        entry.result.map_err(|e| e.to_string())
    }
}

impl std::fmt::Debug for CachedResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedResolver").finish_non_exhaustive()
    }
}

/// Hickory-backed lookups; falls back to the OS resolver if the system configuration cannot be
/// read.
pub struct HickoryBackend {
    resolver: Option<hickory_resolver::TokioResolver>,
}

impl HickoryBackend {
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

impl DnsBackend for HickoryBackend {
    fn lookup(&self, name: &str) -> BoxFut<BackendResult> {
        let name = name.to_string();
        let resolver = self.resolver.clone();
        Box::pin(async move {
            match resolver {
                Some(r) => {
                    let l = r.lookup_ip(name.as_str()).await.map_err(|e| e.to_string())?;
                    let ttl = l.valid_until().saturating_duration_since(Instant::now());
                    Ok((l.iter().collect(), ttl))
                }
                None => {
                    let addrs = tokio::net::lookup_host((name.as_str(), 0))
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok((addrs.map(|a| a.ip()).collect(), Duration::from_secs(30)))
                }
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
    }
    impl DnsBackend for Fake {
        fn lookup(&self, _name: &str) -> BoxFut<BackendResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let a = self.answer.lock().unwrap().clone();
            Box::pin(async move { a })
        }
    }
    fn fake(ip: &str, ttl: Duration) -> Arc<Fake> {
        Arc::new(Fake {
            calls: AtomicU64::new(0),
            answer: Mutex::new(Ok((vec![ip.parse().unwrap()], ttl))),
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
    async fn failures_are_cached_negatively() {
        let f = Arc::new(Fake {
            calls: AtomicU64::new(0),
            answer: Mutex::new(Err("nxdomain".into())),
        });
        let r = CachedResolver::new(f.clone(), cfg(5_000, 60_000));
        assert!(r.resolve("nx.test").await.is_err());
        assert!(r.resolve("nx.test").await.is_err());
        assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    }
}

//! Construction of the pooled upstream HTTP client.

use crate::dns::CachedResolver;
use crate::policy::{DestPolicy, PolicyRefused};
use crate::{Error, Result};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Options for [`build_upstream_client`].
#[derive(Debug, Clone, Default)]
pub struct UpstreamOptions {
    /// PEM root CA files trusted in addition to the built-in web roots.
    pub extra_ca_paths: Vec<PathBuf>,
    /// Resolve every upstream hostname to this IP (ports come from the URL). Meant for tests
    /// and controlled environments; leave `None` in normal operation.
    ///
    /// Code-only on purpose: never derived from config or serde.
    pub resolve_all_to: Option<IpAddr>,
    /// TCP connect timeout for upstream connections.
    pub connect_timeout: Option<Duration>,
    /// Idle read timeout between upstream body chunks.
    pub read_timeout: Option<Duration>,
    /// Destination policy applied to every address the client resolves.
    pub policy: Arc<DestPolicy>,
    /// Shared caching resolver; a default one is created per client when `None`.
    pub dns: Option<Arc<CachedResolver>>,
    /// Idle pooled connections kept per origin; `None` keeps the default of 32.
    pub pool_max_idle_per_host: Option<usize>,
}

impl UpstreamOptions {
    /// Options derived from the proxy configuration.
    pub fn from_config(config: &crate::ProxyConfig) -> Self {
        Self {
            extra_ca_paths: config.proxy.extra_upstream_ca_paths.clone(),
            resolve_all_to: None,
            connect_timeout: Some(Duration::from_secs(
                config.performance.connection_timeout_secs.max(1),
            )),
            read_timeout: Some(Duration::from_secs(
                config.performance.request_timeout_secs.max(1),
            )),
            dns: Some(Arc::new(CachedResolver::from_settings(&config.dns))),
            pool_max_idle_per_host: Some(common::config::pool_idle_per_host(
                match config.performance.max_connections {
                    0 => common::config::derive_max_connections(),
                    n => n,
                },
            )),
            policy: Arc::new(DestPolicy::from_config(config).unwrap_or_else(|e| {
                // `ProxyServer::new` rejects invalid CIDRs; this fallback keeps defaults only.
                tracing::warn!("destination policy config invalid: {e}");
                DestPolicy::default()
            })),
        }
    }
}

/// Root store used for every upstream TLS dial: built-in web roots plus `extra_ca_paths` (PEM
/// files). Shared by the WebSocket path so HTTP and WebSocket trust the same CAs.
pub fn build_root_store(extra_ca_paths: &[PathBuf]) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for path in extra_ca_paths {
        let pem = std::fs::read(path).map_err(|e| {
            Error::Config(format!(
                "Failed to read upstream CA {}: {e}",
                path.display()
            ))
        })?;
        let mut n = 0;
        for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
            let cert = cert.map_err(|e| {
                Error::Config(format!("Invalid upstream CA {}: {e}", path.display()))
            })?;
            roots.add(cert).map_err(|e| {
                Error::Config(format!("Invalid upstream CA {}: {e}", path.display()))
            })?;
            n += 1;
        }
        if n == 0 {
            return Err(Error::Config(format!(
                "Upstream CA {} contains no PEM certificates",
                path.display()
            )));
        }
    }
    Ok(roots)
}

/// DNS resolver that applies the destination policy to what the name resolves to (reqwest never
/// calls it for IP-literal hosts; callers check those explicitly). With a code-only override the
/// override address is returned unfiltered.
struct PolicyResolver {
    policy: Arc<DestPolicy>,
    override_ip: Option<IpAddr>,
    /// Also refuse every address of this host (client used for the proxy's own ports).
    strict: bool,
    dns: Arc<CachedResolver>,
}

impl PolicyResolver {
    /// Resolve (cached) and apply the destination policy to every address, on every call. The
    /// returned addresses are exactly what the connector dials; nothing is resolved again.
    async fn resolve_checked(
        &self,
        name: &str,
    ) -> std::result::Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ip) = self.override_ip {
            return Ok(vec![SocketAddr::new(ip, 0)]);
        }
        let addrs = self.dns.resolve(name).await.map_err(|e| {
            Box::new(std::io::Error::other(format!("dns lookup failed: {e}")))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        let mut allowed = Vec::with_capacity(addrs.len());
        let mut denied = None;
        for ip in addrs.iter() {
            let verdict = if self.strict {
                self.policy.check_ip_strict(*ip)
            } else {
                self.policy.check_ip(*ip)
            };
            match verdict {
                Ok(()) => allowed.push(SocketAddr::new(*ip, 0)),
                Err(r) => {
                    denied.get_or_insert(r);
                }
            }
        }
        if allowed.is_empty() {
            if let Some(r) = denied {
                return Err(Box::new(PolicyRefused(r)));
            }
        }
        Ok(allowed)
    }
}

impl reqwest::dns::Resolve for PolicyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let this = PolicyResolver {
            policy: self.policy.clone(),
            override_ip: self.override_ip,
            strict: self.strict,
            dns: self.dns.clone(),
        };
        Box::pin(async move {
            let v = this.resolve_checked(name.as_str()).await?;
            Ok(Box::new(v.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Build the shared upstream client. Redirects are passed through to the downstream client
/// (the proxy must not follow them itself).
pub fn build_upstream_client(opts: &UpstreamOptions) -> Result<reqwest::Client> {
    build_client(opts, false)
}

/// Like [`build_upstream_client`], for requests aimed at the proxy's own ports: its resolver
/// refuses every address of this host, since the resolver cannot see the port.
pub fn build_strict_upstream_client(opts: &UpstreamOptions) -> Result<reqwest::Client> {
    build_client(opts, true)
}

fn build_client(opts: &UpstreamOptions, strict: bool) -> Result<reqwest::Client> {
    // `no_proxy`: never route through an environment-configured proxy, which would bypass the
    // destination policy.
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        // Latency over batching: the proxy relays whole messages, never small interactive writes
        // it could usefully coalesce (also reqwest's default; stated so it cannot regress).
        .tcp_nodelay(true)
        // Detect dead pooled connections (NAT timeouts, vanished peers) before a request is
        // sent down one.
        .tcp_keepalive(Some(Duration::from_secs(60)))
        // Bound idle descriptors per origin (scaled to the descriptor budget); connections
        // beyond this are closed when idle. reqwest has no total cap, so the budget also
        // reserves one descriptor per connection slot for the pool.
        .pool_max_idle_per_host(opts.pool_max_idle_per_host.unwrap_or(32))
        .pool_idle_timeout(Duration::from_secs(60))
        // Grow HTTP/2 flow-control windows to the measured bandwidth-delay product instead of
        // the 64 KiB default, which throttles large downloads from distant origins.
        .http2_adaptive_window(true);
    for path in &opts.extra_ca_paths {
        let pem = std::fs::read(path).map_err(|e| {
            Error::Config(format!(
                "Failed to read upstream CA {}: {e}",
                path.display()
            ))
        })?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|e| Error::Config(format!("Invalid upstream CA {}: {e}", path.display())))?;
        if certs.is_empty() {
            return Err(Error::Config(format!(
                "Upstream CA {} contains no PEM certificates",
                path.display()
            )));
        }
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    if let Some(t) = opts.connect_timeout {
        builder = builder.connect_timeout(t);
    }
    if let Some(t) = opts.read_timeout {
        builder = builder.read_timeout(t);
    }
    builder = builder.dns_resolver(Arc::new(PolicyResolver {
        policy: opts.policy.clone(),
        override_ip: opts.resolve_all_to,
        strict,
        dns: opts
            .dns
            .clone()
            .unwrap_or_else(|| Arc::new(CachedResolver::from_settings(&Default::default()))),
    }));
    builder
        .build()
        .map_err(|e| Error::Config(format!("Failed to build upstream HTTP client: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts_with(path: PathBuf) -> UpstreamOptions {
        UpstreamOptions {
            extra_ca_paths: vec![path],
            ..Default::default()
        }
    }

    #[test]
    fn resolve_override_and_timeouts_come_from_code_not_config() {
        let mut cfg = crate::ProxyConfig::default();
        cfg.performance.connection_timeout_secs = 3;
        cfg.performance.request_timeout_secs = 9;
        let o = UpstreamOptions::from_config(&cfg);
        assert_eq!(o.resolve_all_to, None);
        assert_eq!(o.connect_timeout, Some(Duration::from_secs(3)));
        assert_eq!(o.read_timeout, Some(Duration::from_secs(9)));
        // A config file cannot carry the override: unknown keys are not part of the schema.
        let toml = toml::to_string(&cfg).unwrap();
        assert!(!toml.contains("resolve_all_to"));
    }

    #[test]
    fn pool_idle_cap_follows_the_connection_budget() {
        let mut cfg = crate::ProxyConfig::default();
        cfg.performance.max_connections = 170;
        assert_eq!(
            UpstreamOptions::from_config(&cfg).pool_max_idle_per_host,
            Some(10)
        );
    }

    struct Fixed(std::sync::atomic::AtomicU64, IpAddr);
    impl crate::dns::DnsBackend for Fixed {
        fn lookup(
            &self,
            _n: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::dns::BackendResult> + Send>>
        {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let ip = self.1;
            Box::pin(async move { Ok((vec![ip], Duration::from_secs(60))) })
        }
    }

    #[tokio::test]
    async fn policy_is_applied_to_cache_hits() {
        let backend = Arc::new(Fixed(Default::default(), "127.0.0.1".parse().unwrap()));
        let dns = Arc::new(CachedResolver::new(
            backend.clone(),
            crate::dns::DnsCacheConfig {
                capacity: 10,
                min_ttl: Duration::from_secs(60),
                max_ttl: Duration::from_secs(60),
                negative_ttl: Duration::from_secs(60),
            },
        ));
        let r = PolicyResolver {
            policy: Arc::new(DestPolicy::default()),
            override_ip: None,
            strict: false,
            dns: dns.clone(),
        };
        for _ in 0..3 {
            assert!(r.resolve_checked("rebind.test").await.is_err());
        }
        // One backend lookup, two cache hits, refused every time.
        assert_eq!(backend.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(dns.stats(), (2, 1));
    }

    #[test]
    fn root_store_includes_web_roots_and_rejects_empty_ca_file() {
        assert!(!build_root_store(&[]).unwrap().is_empty());
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.pem");
        std::fs::write(&p, "nope").unwrap();
        assert!(build_root_store(&[p]).is_err());
    }

    #[test]
    fn ca_file_without_certificates_is_a_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-ca.pem");
        std::fs::write(&path, "this is not a certificate\n").unwrap();
        let err = build_upstream_client(&opts_with(path)).unwrap_err();
        assert!(err.to_string().contains("no PEM certificates"), "{err}");
    }

    #[test]
    fn missing_ca_file_is_a_config_error() {
        let err =
            build_upstream_client(&opts_with(PathBuf::from("/nonexistent/ca.pem"))).unwrap_err();
        assert!(
            err.to_string().contains("Failed to read upstream CA"),
            "{err}"
        );
    }
}

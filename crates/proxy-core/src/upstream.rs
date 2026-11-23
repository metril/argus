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
    /// Where the certificates upstream servers present are recorded (shared with the web API).
    pub certs: Arc<common::certstore::CertStore>,
}

impl UpstreamOptions {
    /// Options derived from the proxy configuration.
    pub fn from_config(config: &crate::ProxyConfig) -> Self {
        // One caching resolver for every dial: the HTTP client, CONNECT and transparent
        // tunnels and WebSocket (through the policy) share it.
        let dns = Arc::new(CachedResolver::from_settings(&config.dns));
        Self {
            extra_ca_paths: config.proxy.extra_upstream_ca_paths.clone(),
            resolve_all_to: None,
            connect_timeout: Some(Duration::from_secs(
                config.performance.connection_timeout_secs.max(1),
            )),
            read_timeout: Some(Duration::from_secs(
                config.performance.request_timeout_secs.max(1),
            )),
            certs: Default::default(),
            dns: Some(dns.clone()),
            pool_max_idle_per_host: Some(common::config::pool_idle_per_host(
                match config.performance.max_connections {
                    0 => common::config::derive_max_connections(),
                    n => n,
                },
            )),
            policy: Arc::new(
                DestPolicy::from_config(config)
                    .unwrap_or_else(|e| {
                        // `ProxyServer::new` rejects invalid CIDRs; this fallback keeps defaults only.
                        tracing::warn!("destination policy config invalid: {e}");
                        DestPolicy::default()
                    })
                    .with_resolver(Arc::new(crate::dns::DnsHandle(dns))),
            ),
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

/// Verifier of the probe handshake: standard web-PKI verification, remembering the chain it saw
/// and the verdict (the handshake is rejected on a failure, so the verdict is kept here).
#[derive(Debug)]
struct ProbeVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    seen: parking_lot::Mutex<Option<ProbeSeen>>,
}

type ProbeSeen = (
    Vec<Vec<u8>>,
    std::result::Result<(), (common::certstore::FailReason, String)>,
);

fn fail_reason(e: &rustls::Error) -> common::certstore::FailReason {
    use common::certstore::FailReason as R;
    use rustls::CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            C::Expired | C::ExpiredContext { .. } => R::Expired,
            C::NotValidYet | C::NotValidYetContext { .. } => R::NotYetValid,
            C::NotValidForName | C::NotValidForNameContext { .. } => R::NameMismatch,
            C::UnknownIssuer => R::UnknownIssuer,
            _ => R::Other,
        },
        _ => R::Other,
    }
}

impl rustls::client::danger::ServerCertVerifier for ProbeVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let res = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        let chain = std::iter::once(end_entity.as_ref())
            .chain(intermediates.iter().map(|c| c.as_ref()))
            .map(<[u8]>::to_vec)
            .collect();
        let verdict = match &res {
            Ok(_) => Ok(()),
            Err(e) => Err((fail_reason(e), e.to_string())),
        };
        *self.seen.lock() = Some((chain, verdict));
        res
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

impl common::certstore::ChainProbe for CertProber {
    fn probe<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(CertProber::probe(self, host, port))
    }
}

/// Standard web-PKI verification that also keeps the chain of every chain it accepts, so the
/// full path of a certificate is known without any extra connection. It only delegates and
/// returns the inner result; it writes no verdict, host, port or profile.
#[derive(Debug)]
pub struct ChainCapture {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    store: Arc<common::certstore::CertStore>,
}

impl rustls::client::danger::ServerCertVerifier for ChainCapture {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let ok = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let chain: Vec<&[u8]> = std::iter::once(end_entity.as_ref())
            .chain(intermediates.iter().map(|c| c.as_ref()))
            .collect();
        self.store
            .record_chain(&chain, &|| crate::ev::is_ev_der(end_entity.as_ref()));
        Ok(ok)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Web-PKI client config over `roots` (chains captured into `store`), ALPN h2 then http/1.1.
pub fn client_tls_config(
    roots: rustls::RootCertStore,
    store: Arc<common::certstore::CertStore>,
) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .map_err(|e| Error::Config(format!("Failed to build upstream verifier: {e}")))?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Config(format!("Failed to build upstream TLS config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ChainCapture { inner, store }))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

/// How long a probe result (ok or invalid) is reused.
const PROBE_TTL: Duration = Duration::from_secs(300);
/// Probe handshakes running at once.
const PROBE_CONCURRENCY: usize = 8;
/// How long a request waits for a free probe slot before it gives up and probes in the
/// background instead.
const PROBE_WAIT: Duration = Duration::from_millis(250);

/// No probe slot was free in time (the result is not cached).
#[derive(Debug)]
struct Busy;

struct ProbeInner {
    store: Arc<common::certstore::CertStore>,
    roots: Arc<rustls::RootCertStore>,
    resolver: PolicyResolver,
    connect_timeout_ms: std::sync::atomic::AtomicU64,
    limit: tokio::sync::Semaphore,
    wait: Duration,
    cache: moka::future::Cache<String, Option<String>>,
    handshakes: std::sync::atomic::AtomicUsize,
}

/// Dedicated handshake to a `host:port` after an upstream TLS failure, to learn the certificate
/// and why it was rejected. Results are cached per `host:port` (single-flight, bounded
/// concurrency) so repeated failures cannot multiply outbound connections. A caller never waits
/// long for a slot: when none is free it gets `None` at once and the probe runs in the
/// background to fill the store.
#[derive(Clone)]
pub struct CertProber(Arc<ProbeInner>);

impl CertProber {
    pub fn new(opts: &UpstreamOptions) -> Result<Self> {
        Self::with_limits(opts, PROBE_CONCURRENCY, PROBE_WAIT)
    }

    fn with_limits(opts: &UpstreamOptions, permits: usize, wait: Duration) -> Result<Self> {
        Ok(Self(Arc::new(ProbeInner {
            store: opts.certs.clone(),
            roots: Arc::new(build_root_store(&opts.extra_ca_paths)?),
            resolver: PolicyResolver {
                policy: opts.policy.clone(),
                override_ip: opts.resolve_all_to,
                strict: false,
                dns: opts.dns.clone().unwrap_or_else(|| {
                    Arc::new(CachedResolver::from_settings(&Default::default()))
                }),
            },
            connect_timeout_ms: opts
                .connect_timeout
                .map_or(10_000, |t| t.as_millis() as u64)
                .into(),
            handshakes: Default::default(),
            limit: tokio::sync::Semaphore::new(permits),
            wait,
            cache: moka::future::Cache::builder()
                .max_capacity(4096)
                .time_to_live(PROBE_TTL)
                .build(),
        })))
    }

    /// Follow a changed connect timeout.
    pub fn set_connect_timeout(&self, t: Option<Duration>) {
        self.0.connect_timeout_ms.store(
            t.map_or(10_000, |t| t.as_millis() as u64),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Probe handshakes started so far.
    pub fn handshakes(&self) -> usize {
        self.0.handshakes.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Fingerprint of the certificate `host:port` presented, recorded in the store with its
    /// verdict. `None` when the probe learnt nothing (no certificate arrived, the handshake
    /// failed for another reason) or no slot was free in time (then it continues in the
    /// background).
    pub async fn probe(&self, host: &str, port: u16) -> Option<String> {
        match self.0.probe(host, port).await {
            Ok(fp) => fp,
            Err(Busy) => {
                let (inner, host) = (self.0.clone(), host.to_string());
                tokio::spawn(async move {
                    let _ = inner.probe_waiting(&host, port).await;
                });
                None
            }
        }
    }
}

impl ProbeInner {
    async fn probe(&self, host: &str, port: u16) -> std::result::Result<Option<String>, Busy> {
        self.cached(host, port, Some(self.wait)).await
    }

    async fn probe_waiting(
        &self,
        host: &str,
        port: u16,
    ) -> std::result::Result<Option<String>, Busy> {
        self.cached(host, port, None).await
    }

    async fn cached(
        &self,
        host: &str,
        port: u16,
        wait: Option<Duration>,
    ) -> std::result::Result<Option<String>, Busy> {
        let key = common::certstore::hostport(host, port);
        self.cache
            .try_get_with(key.clone(), async {
                let _permit = match wait {
                    Some(w) => tokio::time::timeout(w, self.limit.acquire())
                        .await
                        .map_err(|_| Busy)?
                        .map_err(|_| Busy)?,
                    None => self.limit.acquire().await.map_err(|_| Busy)?,
                };
                let limit = Duration::from_millis(
                    self.connect_timeout_ms
                        .load(std::sync::atomic::Ordering::Relaxed),
                );
                Ok(tokio::time::timeout(limit, self.run(&key, host, port))
                    .await
                    .ok()
                    .flatten())
            })
            .await
            .map_err(|_: Arc<Busy>| Busy)
    }

    async fn run(&self, key: &str, host: &str, port: u16) -> Option<String> {
        self.handshakes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let candidates: Vec<IpAddr> = match bare.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => self
                .resolver
                .resolve_checked(bare)
                .await
                .ok()?
                .into_iter()
                .map(|a| a.ip())
                .collect(),
        };
        // The same port-aware destination policy as the request path (own listeners, private
        // ranges), for literals and resolved addresses alike. A code-only override is unfiltered.
        let addrs: Vec<SocketAddr> = match self.resolver.override_ip {
            Some(o) => vec![SocketAddr::new(o, port)],
            None => candidates
                .into_iter()
                .filter(|ip| self.resolver.policy.check(*ip, port).is_ok())
                .map(|ip| SocketAddr::new(ip, port))
                .collect(),
        };
        let name = rustls::pki_types::ServerName::try_from(bare.to_string()).ok()?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(ProbeVerifier {
            inner: rustls::client::WebPkiServerVerifier::builder_with_provider(
                self.roots.clone(),
                provider.clone(),
            )
            .build()
            .ok()?,
            seen: Default::default(),
        });
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .ok()?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
        let mut completed = None;
        for addr in addrs {
            let Ok(tcp) = tokio::net::TcpStream::connect(addr).await else {
                continue;
            };
            completed = Some(connector.connect(name.clone(), tcp).await.is_ok());
            break;
        }
        let (chain, verdict) = verifier.seen.lock().take()?;
        // An `ok` needs a completed handshake (the server proved it holds the key); a
        // certificate rejection is recorded as such. Anything else learnt nothing.
        if verdict.is_ok() && completed != Some(true) {
            return None;
        }
        let refs: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
        self.store.record_probe(key, &refs, verdict, &|| {
            chain.first().is_some_and(|d| crate::ev::is_ev_der(d))
        })
    }
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
        // Each response carries the certificate of the connection that served it.
        .tls_info(true)
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
    builder = builder.use_preconfigured_tls(client_tls_config(
        build_root_store(&opts.extra_ca_paths)?,
        opts.certs.clone(),
    )?);
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

/// Error kind of a failed I/O operation towards the upstream server.
pub fn classify_io(e: &std::io::Error) -> filter_engine::ErrorKind {
    use filter_engine::ErrorKind as K;
    use std::io::ErrorKind as I;
    if e.get_ref().is_some_and(|i| i.is::<rustls::Error>()) {
        return K::UpstreamTls;
    }
    match e.kind() {
        I::TimedOut => K::UpstreamTimeout,
        I::ConnectionReset
        | I::ConnectionAborted
        | I::ConnectionRefused
        | I::BrokenPipe
        | I::UnexpectedEof => K::UpstreamReset,
        _ => K::Other,
    }
}

/// Error kind of a failed upstream HTTP request: walks the error chain for a timeout, a TLS
/// (certificate or handshake) failure or a connection reset.
pub fn classify_reqwest(e: &reqwest::Error) -> filter_engine::ErrorKind {
    use filter_engine::ErrorKind as K;
    if e.is_timeout() {
        return K::UpstreamTimeout;
    }
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    let mut io_kind = None;
    while let Some(err) = cur {
        if err.is::<rustls::Error>() {
            return K::UpstreamTls;
        }
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            match classify_io(io) {
                K::Other => {}
                k @ (K::UpstreamTls | K::UpstreamTimeout) => return k,
                k => io_kind = io_kind.or(Some(k)),
            }
        }
        cur = err.source();
    }
    if let Some(k) = io_kind {
        return k;
    }
    let text = format!("{e:?}").to_ascii_lowercase();
    if text.contains("certificate")
        || text.contains("tls handshake")
        || text.contains("invalidcert")
    {
        K::UpstreamTls
    } else if text.contains("incompletemessage")
        || text.contains("connection closed")
        || text.contains("connection reset")
    {
        K::UpstreamReset
    } else {
        K::Other
    }
}

#[cfg(test)]
mod classify_tests {
    use super::*;
    use filter_engine::ErrorKind as K;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[test]
    fn io_errors_map_to_kinds() {
        let e = |k| std::io::Error::new(k, "x");
        assert_eq!(
            classify_io(&e(std::io::ErrorKind::TimedOut)),
            K::UpstreamTimeout
        );
        for k in [
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            assert_eq!(classify_io(&e(k)), K::UpstreamReset, "{k:?}");
        }
        assert_eq!(
            classify_io(&e(std::io::ErrorKind::PermissionDenied)),
            K::Other
        );
        let tls = std::io::Error::other(rustls::Error::General("x".into()));
        assert_eq!(classify_io(&tls), K::UpstreamTls);
    }

    #[tokio::test]
    async fn a_silent_server_is_a_timeout() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 64];
            let _ = s.read(&mut b).await;
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        let err = reqwest::Client::new()
            .get(format!("http://{addr}/"))
            .timeout(std::time::Duration::from_millis(150))
            .send()
            .await
            .unwrap_err();
        assert_eq!(classify_reqwest(&err), K::UpstreamTimeout);
    }

    #[tokio::test]
    async fn a_server_that_hangs_up_is_a_reset() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                let mut b = [0u8; 512];
                let _ = s.read(&mut b).await;
                drop(s); // close without answering
            }
        });
        let err = reqwest::Client::new()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap_err();
        assert_eq!(classify_reqwest(&err), K::UpstreamReset, "{err:?}");
        // Nothing listening at all: connection refused is a reset-class failure too.
        let err = reqwest::Client::new()
            .get("http://127.0.0.1:1/")
            .send()
            .await
            .unwrap_err();
        assert_eq!(classify_reqwest(&err), K::UpstreamReset, "{err:?}");
    }

    #[tokio::test]
    async fn an_untrusted_upstream_certificate_is_a_tls_error() {
        // A TLS server whose certificate the client does not trust.
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                let a = acceptor.clone();
                tokio::spawn(async move {
                    let _ = a.accept(s).await;
                });
            }
        });
        let err = reqwest::Client::new()
            .get(format!("https://localhost:{port}/"))
            .send()
            .await
            .unwrap_err();
        assert_eq!(classify_reqwest(&err), K::UpstreamTls, "{err:?}");
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    use common::certstore::{FailReason, Verdict};
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Pki {
        ca_pem: String,
        issuer: Issuer<'static, KeyPair>,
    }

    fn pki() -> Pki {
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "probe test CA");
        p.distinguished_name = dn;
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let key = KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        Pki {
            ca_pem: cert.pem(),
            issuer: Issuer::new(p, key),
        }
    }

    /// A TLS server presenting a certificate for `name` (expired when asked); returns its port
    /// and a counter of accepted connections.
    async fn server(pki: &Pki, name: &str, expired: bool) -> (u16, Arc<AtomicUsize>) {
        let mut p = CertificateParams::new(vec![name.to_string()]).unwrap();
        if expired {
            p.not_before = rcgen::date_time_ymd(2000, 1, 1);
            p.not_after = rcgen::date_time_ymd(2001, 1, 1);
        }
        let key = KeyPair::generate().unwrap();
        let cert = p.signed_by(&key, &pki.issuer).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                c.fetch_add(1, Ordering::SeqCst);
                let a = acceptor.clone();
                tokio::spawn(async move {
                    let _ = a.accept(s).await;
                });
            }
        });
        (port, count)
    }

    fn prober(pki: &Pki) -> (CertProber, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, &pki.ca_pem).unwrap();
        let opts = UpstreamOptions {
            extra_ca_paths: vec![ca],
            resolve_all_to: Some("127.0.0.1".parse().unwrap()),
            connect_timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        };
        (CertProber::new(&opts).unwrap(), dir)
    }

    #[tokio::test]
    async fn probe_records_reason_per_port_and_is_cached() {
        let pki = pki();
        let (bad, bad_hits) = server(&pki, "h.test", true).await;
        let (good, _) = server(&pki, "h.test", false).await;
        let (p, _d) = prober(&pki);
        let fp = p.probe("h.test", bad).await.expect("fingerprint");
        let info = p.0.store.by_host(&format!("h.test:{bad}")).unwrap();
        assert_eq!(info.fp, fp);
        assert_eq!(
            (info.verdict, info.reason),
            (Verdict::Invalid, Some(FailReason::Expired))
        );
        // The same host on another port is independent.
        let fp2 = p.probe("h.test", good).await.unwrap();
        assert_ne!(fp, fp2);
        let ok = p.0.store.by_host(&format!("h.test:{good}")).unwrap();
        assert_eq!(ok.verdict, Verdict::Ok);
        // Cached: no new connection, same answer.
        let before = bad_hits.load(Ordering::SeqCst);
        assert_eq!(p.probe("h.test", bad).await, Some(fp));
        assert_eq!(bad_hits.load(Ordering::SeqCst), before);
    }

    #[tokio::test]
    async fn concurrent_probes_of_one_host_share_one_handshake() {
        let pki = pki();
        let (port, hits) = server(&pki, "h.test", true).await;
        let (p, _d) = prober(&pki);
        let p = Arc::new(p);
        let rs = futures_util::future::join_all((0..8).map(|_| {
            let p = p.clone();
            async move { p.probe("h.test", port).await }
        }))
        .await;
        assert!(rs.iter().all(|r| r == &rs[0] && r.is_some()));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_ok_verdict_needs_a_completed_handshake() {
        // The certificate verifies, but the server cannot sign with its key: the handshake
        // fails after verification, so nothing may be recorded as ok.
        use rustls::sign::CertifiedKey;
        #[derive(Debug)]
        struct Wrong(Arc<CertifiedKey>);
        impl rustls::server::ResolvesServerCert for Wrong {
            fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
                Some(self.0.clone())
            }
        }
        let pki = pki();
        let mut p = CertificateParams::new(vec!["h.test".to_string()]).unwrap();
        p.distinguished_name.push(DnType::CommonName, "h.test");
        let real = KeyPair::generate().unwrap();
        let cert = p.signed_by(&real, &pki.issuer).unwrap();
        let other = KeyPair::generate().unwrap();
        let signer = rustls::crypto::ring::sign::any_supported_type(
            &rustls::pki_types::PrivateKeyDer::try_from(other.serialize_der()).unwrap(),
        )
        .unwrap();
        let ck = Arc::new(CertifiedKey::new(vec![cert.der().clone()], signer));
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Wrong(ck)));
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                let a = acceptor.clone();
                tokio::spawn(async move {
                    let _ = a.accept(s).await;
                });
            }
        });
        let (pr, _d) = prober(&pki);
        assert_eq!(pr.probe("h.test", port).await, None);
        assert!(pr.0.store.by_host(&format!("h.test:{port}")).is_none());
    }

    #[tokio::test]
    async fn probe_respects_the_port_aware_destination_policy() {
        let pki = pki();
        let (port, hits) = server(&pki, "127.0.0.1", true).await;
        // No override: the default policy refuses loopback literals.
        let opts = UpstreamOptions {
            connect_timeout: Some(Duration::from_secs(2)),
            ..Default::default()
        };
        let p = CertProber::new(&opts).unwrap();
        assert_eq!(p.probe("127.0.0.1", port).await, None);
        assert_eq!(hits.load(Ordering::SeqCst), 0, "no connection was made");
    }

    #[tokio::test]
    async fn a_busy_prober_answers_at_once_and_finishes_in_the_background() {
        let pki = pki();
        // A server that accepts and then says nothing keeps the only slot busy.
        let hole = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hole_port = hole.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                held.push(hole.accept().await.unwrap());
            }
        });
        let (bad, _) = server(&pki, "b.test", true).await;
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, &pki.ca_pem).unwrap();
        let opts = UpstreamOptions {
            extra_ca_paths: vec![ca],
            resolve_all_to: Some("127.0.0.1".parse().unwrap()),
            connect_timeout: Some(Duration::from_secs(2)),
            ..Default::default()
        };
        let p = CertProber::with_limits(&opts, 1, Duration::from_millis(50)).unwrap();
        let slow = {
            let p = p.clone();
            tokio::spawn(async move { p.probe("a.test", hole_port).await })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        let t = std::time::Instant::now();
        assert_eq!(p.probe("b.test", bad).await, None);
        assert!(
            t.elapsed() < Duration::from_secs(1),
            "did not wait for a slot"
        );
        assert_eq!(slow.await.unwrap(), None);
        // The background probe fills the store once the slot frees up.
        let key = format!("b.test:{bad}");
        for _ in 0..50 {
            if p.0.store.by_host(&key).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(p.0.store.by_host(&key).unwrap().verdict, Verdict::Invalid);
    }

    #[tokio::test]
    async fn probe_failure_yields_nothing() {
        let pki = pki();
        let (p, _d) = prober(&pki);
        // Nothing listens on port 1.
        assert_eq!(p.probe("h.test", 1).await, None);
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;
    use common::certstore::{fingerprint, CertStore};
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    fn ca(cn: &str) -> (CertificateDer<'static>, Issuer<'static, KeyPair>) {
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name.push(DnType::CommonName, cn);
        let key = KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        (cert.der().clone(), Issuer::new(p, key))
    }

    fn leaf(name: &str, issuer: &Issuer<'static, KeyPair>, expired: bool) -> Vec<u8> {
        let mut p = CertificateParams::new(vec![name.to_string()]).unwrap();
        if expired {
            p.not_before = rcgen::date_time_ymd(2000, 1, 1);
            p.not_after = rcgen::date_time_ymd(2001, 1, 1);
        }
        let key = KeyPair::generate().unwrap();
        p.signed_by(&key, issuer).unwrap().der().to_vec()
    }

    fn capture(root: &CertificateDer<'static>, store: &Arc<CertStore>) -> ChainCapture {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root.clone()).unwrap();
        ChainCapture {
            inner: rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                Arc::new(rustls::crypto::ring::default_provider()),
            )
            .build()
            .unwrap(),
            store: store.clone(),
        }
    }

    fn check(
        v: &ChainCapture,
        leaf: &[u8],
        extra: &[Vec<u8>],
        host: &str,
    ) -> std::result::Result<(), rustls::Error> {
        let inter: Vec<_> = extra
            .iter()
            .map(|d| CertificateDer::from(d.clone()))
            .collect();
        v.verify_server_cert(
            &CertificateDer::from(leaf.to_vec()),
            &inter,
            &ServerName::try_from(host.to_string()).unwrap(),
            &[],
            UnixTime::now(),
        )
        .map(|_| ())
    }

    #[test]
    fn accepted_chain_is_captured_trimmed_and_nothing_else_is_written() {
        let (root, root_i) = ca("root");
        let (stranger, _) = ca("stranger");
        let store = Arc::new(CertStore::default());
        let v = capture(&root, &store);
        let l = leaf("good.test", &root_i, false);
        check(&v, &l, &[stranger.to_vec(), root.to_vec()], "good.test").unwrap();
        let info = store.info(&fingerprint(&l), None).unwrap();
        assert_eq!(info.chain.len(), 2, "stranger dropped, root kept");
        assert_eq!(info.chain[1].fp, fingerprint(&root));
        assert!(store.by_host("good.test").is_none());
        assert!(store.seen_by("good.test").is_empty());
    }

    #[test]
    fn failing_verification_stores_nothing_and_a_replay_for_another_name_too() {
        let (root, root_i) = ca("root");
        let store = Arc::new(CertStore::default());
        let v = capture(&root, &store);
        let expired = leaf("old.test", &root_i, true);
        assert!(check(&v, &expired, &[root.to_vec()], "old.test").is_err());
        // A genuine chain replayed for a name it is not valid for is rejected: nothing stored.
        let genuine = leaf("bank.test", &root_i, false);
        assert!(check(&v, &genuine, &[root.to_vec()], "evil.test").is_err());
        assert!(store.is_empty());
        // Presented for its own name, only that chain is stored, under its own fingerprint.
        check(&v, &genuine, &[root.to_vec()], "bank.test").unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(
            store
                .info(&fingerprint(&genuine), None)
                .unwrap()
                .chain
                .len(),
            2
        );
    }
}

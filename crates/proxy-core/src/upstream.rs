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

/// Wraps the standard web-PKI verifier: delegates, then records the presented chain and the
/// verdict (also for rejected chains) so the real server certificate can be inspected. Runs once
/// per handshake, not per request.
#[derive(Debug)]
pub struct RecordingVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    store: Arc<common::certstore::CertStore>,
}

impl RecordingVerifier {
    pub fn new(
        roots: rustls::RootCertStore,
        provider: Arc<rustls::crypto::CryptoProvider>,
        store: Arc<common::certstore::CertStore>,
    ) -> Result<Self> {
        let inner =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|e| Error::Config(format!("Failed to build upstream verifier: {e}")))?;
        Ok(Self { inner, store })
    }
}

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

impl rustls::client::danger::ServerCertVerifier for RecordingVerifier {
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
        let host = server_name.to_str();
        let chain: Vec<&[u8]> = std::iter::once(end_entity.as_ref())
            .chain(intermediates.iter().map(|c| c.as_ref()))
            .collect();
        let verdict = match &res {
            Ok(_) => Ok(()),
            Err(e) => Err((fail_reason(e), e.to_string())),
        };
        self.store.record(&host, &chain, verdict, &|| {
            crate::ev::is_ev_der(end_entity.as_ref())
        });
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

/// Client TLS config: `roots` verified through a [`RecordingVerifier`], ALPN h2 then http/1.1.
pub fn recording_tls_config(
    roots: rustls::RootCertStore,
    store: Arc<common::certstore::CertStore>,
) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = RecordingVerifier::new(roots, provider.clone(), store)?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Config(format!("Failed to build upstream TLS config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
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
    builder = builder.use_preconfigured_tls(recording_tls_config(
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
mod recording_tests {
    use super::*;
    use common::certstore::{CertStore, FailReason, Verdict};
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    struct Pki {
        ca_der: CertificateDer<'static>,
        issuer: Issuer<'static, KeyPair>,
    }

    fn pki() -> Pki {
        pki_named("test CA")
    }

    fn pki_named(cn: &str) -> Pki {
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        p.distinguished_name = dn;
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let key = KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        Pki {
            ca_der: cert.der().clone(),
            issuer: Issuer::new(p, key),
        }
    }

    fn leaf(pki: &Pki, name: &str, expired: bool) -> Vec<u8> {
        let mut p = CertificateParams::new(vec![name.to_string()]).unwrap();
        if expired {
            p.not_before = rcgen::date_time_ymd(2000, 1, 1);
            p.not_after = rcgen::date_time_ymd(2001, 1, 1);
        }
        let key = KeyPair::generate().unwrap();
        p.signed_by(&key, &pki.issuer).unwrap().der().to_vec()
    }

    fn verifier(trusted: Option<&Pki>, store: &Arc<CertStore>) -> RecordingVerifier {
        let mut roots = rustls::RootCertStore::empty();
        if let Some(p) = trusted {
            roots.add(p.ca_der.clone()).unwrap();
        }
        RecordingVerifier::new(
            roots,
            Arc::new(rustls::crypto::ring::default_provider()),
            store.clone(),
        )
        .unwrap()
    }

    fn check(
        v: &RecordingVerifier,
        der: &[u8],
        host: &str,
    ) -> std::result::Result<(), rustls::Error> {
        v.verify_server_cert(
            &CertificateDer::from(der.to_vec()),
            &[],
            &ServerName::try_from(host.to_string()).unwrap(),
            &[],
            UnixTime::now(),
        )
        .map(|_| ())
    }

    #[test]
    fn good_chain_is_accepted_and_recorded() {
        let (store, pki) = (Arc::new(CertStore::default()), pki());
        let der = leaf(&pki, "good.test", false);
        check(&verifier(Some(&pki), &store), &der, "good.test").unwrap();
        let info = store.by_host("good.test").unwrap();
        assert_eq!(info.verdict, Verdict::Ok);
        assert_eq!(info.reason, None);
        assert!(info.subject.contains("good.test") || info.sans == ["good.test"]);
    }

    #[test]
    fn bad_chains_are_still_rejected_but_recorded_with_a_reason() {
        let (store, pki) = (Arc::new(CertStore::default()), pki());
        let v = verifier(Some(&pki), &store);

        let expired = leaf(&pki, "old.test", true);
        assert!(check(&v, &expired, "old.test").is_err());
        let i = store.by_host("old.test").unwrap();
        assert_eq!(
            (i.verdict, i.reason),
            (Verdict::Invalid, Some(FailReason::Expired))
        );

        let other = leaf(&pki, "other.test", false);
        assert!(check(&v, &other, "wrong.test").is_err());
        let i = store.by_host("wrong.test").unwrap();
        assert_eq!(i.reason, Some(FailReason::NameMismatch));

        let stranger = leaf(&pki, "x.test", false);
        assert!(check(
            &verifier(Some(&pki_named("unrelated CA")), &store),
            &stranger,
            "x.test"
        )
        .is_err());
        let i = store.by_host("x.test").unwrap();
        assert_eq!(i.reason, Some(FailReason::UnknownIssuer));
        assert!(i.detail.is_some());
    }
}

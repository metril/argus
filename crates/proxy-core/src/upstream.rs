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
    /// The live trusted root set; built from `extra_ca_paths` over the compiled-in floor when
    /// `None` (a context installs one so every client shares it).
    pub roots: Option<Arc<crate::roots::RootsHandle>>,
    /// Connect with the requesting browser's TLS/HTTP2 fingerprint (the wreq client); off uses
    /// the rustls client.
    pub browser_like: bool,
}

impl UpstreamOptions {
    /// The root set handle: the shared one, or a fresh floor of the extra CAs.
    pub fn roots_handle(&self) -> Result<Arc<crate::roots::RootsHandle>> {
        match &self.roots {
            Some(r) => Ok(r.clone()),
            None => crate::roots::RootsHandle::floor(&self.extra_ca_paths),
        }
    }
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
            roots: None,
            browser_like: config.proxy.upstream.browser_like,
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

/// Trust anchors of the compiled-in set plus `extra_ca_paths` (PEM files), for callers that
/// need a plain store. Upstream dials use the live [`RootsHandle`] instead.
pub fn build_root_store(extra_ca_paths: &[PathBuf]) -> Result<rustls::RootCertStore> {
    Ok(crate::roots::ActiveRoots::floor(extra_ca_paths)?
        .store()
        .clone())
}

/// Verifier of the probe handshake: the same verification as every dial, on the set in force
/// when the probe started, remembering the chain it saw and the verdict (the handshake is
/// rejected on a failure, so the verdict is kept here).
impl std::fmt::Debug for ProbeVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeVerifier").finish_non_exhaustive()
    }
}

struct ProbeVerifier {
    active: Arc<crate::roots::ActiveRoots>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
    seen: parking_lot::Mutex<Option<ProbeSeen>>,
}

type ProbeSeen = (
    Vec<Vec<u8>>,
    std::result::Result<(), (common::certstore::FailReason, String)>,
);

pub(crate) fn fail_reason(e: &rustls::Error) -> common::certstore::FailReason {
    use common::certstore::FailReason as R;
    use rustls::CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            C::Expired | C::ExpiredContext { .. } => R::Expired,
            C::NotValidYet | C::NotValidYetContext { .. } => R::NotYetValid,
            C::NotValidForName | C::NotValidForNameContext { .. } => R::NameMismatch,
            C::UnknownIssuer => R::UnknownIssuer,
            C::Other(o) if o.0.downcast_ref::<crate::roots::Distrusted>().is_some() => {
                R::Distrusted
            }
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
        _ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let res = self
            .active
            .verify(end_entity, intermediates, server_name, now);
        // An accepted chain is stored as the verified path; a rejected one only for its leaf.
        let (chain, verdict) = match &res {
            Ok(path) => (path.iter().map(|d| d.to_vec()).collect(), Ok(())),
            Err(e) => (
                vec![end_entity.as_ref().to_vec()],
                Err((fail_reason(e), e.to_string())),
            ),
        };
        *self.seen.lock() = Some((chain, verdict));
        res.map(|_| rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
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

/// Client TLS config: every handshake is verified against the live root set (chains captured
/// into `store`), ALPN h2 then http/1.1.
pub fn client_tls_config(
    roots: Arc<crate::roots::RootsHandle>,
    store: Arc<common::certstore::CertStore>,
) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Config(format!("Failed to build upstream TLS config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::roots::LiveVerifier::new(
            roots,
            Some(store),
        )))
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

/// Background probes queued or running at once; further ones are dropped.
const PROBE_BACKGROUND: usize = 16;

/// No probe slot was free in time (the result is not cached).
#[derive(Debug)]
struct Busy;

struct ProbeInner {
    store: Arc<common::certstore::CertStore>,
    roots: Arc<crate::roots::RootsHandle>,
    resolver: PolicyResolver,
    connect_timeout_ms: std::sync::atomic::AtomicU64,
    limit: tokio::sync::Semaphore,
    wait: Duration,
    cache: moka::future::Cache<String, Option<String>>,
    handshakes: std::sync::atomic::AtomicUsize,
    /// Keys with a probe running right now (never started twice).
    inflight: parking_lot::Mutex<std::collections::HashSet<String>>,
    /// Keys with a background probe queued or running.
    queued: parking_lot::Mutex<std::collections::HashSet<String>>,
    /// Room for background probes.
    background: Arc<tokio::sync::Semaphore>,
    spawned: std::sync::atomic::AtomicUsize,
}

/// Removes a key from the queued set when its background probe ends.
struct Queued(Arc<ProbeInner>, String);

impl Drop for Queued {
    fn drop(&mut self) {
        self.0.queued.lock().remove(&self.1);
    }
}

/// Removes a key from the in-flight set when the probe ends (or is dropped).
struct Inflight<'a>(&'a ProbeInner, String);

impl<'a> Inflight<'a> {
    fn new(p: &'a ProbeInner, key: &str) -> Self {
        p.inflight.lock().insert(key.to_string());
        Self(p, key.to_string())
    }
}

impl Drop for Inflight<'_> {
    fn drop(&mut self) {
        self.0.inflight.lock().remove(&self.1);
    }
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
        Self::with_limits(opts, PROBE_CONCURRENCY, PROBE_WAIT, PROBE_BACKGROUND)
    }

    fn with_limits(
        opts: &UpstreamOptions,
        permits: usize,
        wait: Duration,
        background: usize,
    ) -> Result<Self> {
        Ok(Self(Arc::new(ProbeInner {
            store: opts.certs.clone(),
            roots: opts.roots_handle()?,
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
            inflight: Default::default(),
            queued: Default::default(),
            background: Arc::new(tokio::sync::Semaphore::new(background)),
            spawned: Default::default(),
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
        // Bounded as a whole: also a caller joining a probe that is already running.
        match tokio::time::timeout(self.0.wait, self.0.cached(host, port, Some(self.0.wait))).await
        {
            Ok(Ok(fp)) => fp,
            Ok(Err(Busy)) | Err(_) => {
                self.spawn_background(host, port);
                None
            }
        }
    }

    /// Probe in the background to fill the store: not when one is already running for the key,
    /// and dropped when too many are queued.
    fn spawn_background(&self, host: &str, port: u16) {
        let key = common::certstore::hostport(host, port);
        if self.0.inflight.lock().contains(&key) {
            return;
        }
        // Claim the key before queueing: a duplicate must not take another slot.
        if !self.0.queued.lock().insert(key.clone()) {
            return;
        }
        let queued = Queued(self.0.clone(), key);
        let Ok(permit) = self.0.background.clone().try_acquire_owned() else {
            return;
        };
        self.0
            .spawned
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (inner, host) = (self.0.clone(), host.to_string());
        tokio::spawn(async move {
            let _permit = permit;
            let _queued = queued;
            let _ = inner.cached(&host, port, None).await;
        });
    }

    /// Background probes started so far.
    pub fn background_started(&self) -> usize {
        self.0.spawned.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl ProbeInner {
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
                let _running = Inflight::new(self, &key);
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
            // The set in force when the probe starts.
            active: self.roots.load_full(),
            algs: provider.signature_verification_algorithms,
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

impl wreq::dns::Resolve for PolicyResolver {
    fn resolve(&self, name: wreq::dns::Name) -> wreq::dns::Resolving {
        let this = PolicyResolver {
            policy: self.policy.clone(),
            override_ip: self.override_ip,
            strict: self.strict,
            dns: self.dns.clone(),
        };
        Box::pin(async move {
            let v = this.resolve_checked(name.as_str()).await?;
            Ok(Box::new(v.into_iter()) as wreq::dns::Addrs)
        })
    }
}

/// The pooled upstream client: the browser-like wreq client or the previous reqwest one.
#[derive(Clone)]
pub enum UpstreamClient {
    Wreq(wreq::Client),
    Reqwest(reqwest::Client),
}

impl std::fmt::Debug for UpstreamClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Wreq(_) => "UpstreamClient::Wreq",
            Self::Reqwest(_) => "UpstreamClient::Reqwest",
        })
    }
}

impl From<reqwest::Client> for UpstreamClient {
    fn from(c: reqwest::Client) -> Self {
        Self::Reqwest(c)
    }
}

/// A failed upstream request, from either client.
#[derive(Debug)]
pub enum UpstreamError {
    Wreq(wreq::Error),
    Reqwest(reqwest::Error),
    /// The request could not be formed (a header that is not valid).
    Invalid(String),
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wreq(e) => e.fmt(f),
            Self::Reqwest(e) => e.fmt(f),
            Self::Invalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for UpstreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wreq(e) => Some(e),
            Self::Reqwest(e) => Some(e),
            Self::Invalid(_) => None,
        }
    }
}

impl UpstreamError {
    /// Error kind for the request log.
    pub fn kind(&self) -> filter_engine::ErrorKind {
        match self {
            Self::Wreq(e) => classify_wreq(e),
            Self::Reqwest(e) => classify_reqwest(e),
            Self::Invalid(_) => filter_engine::ErrorKind::Other,
        }
    }
}

type BodyStream = futures_util::stream::BoxStream<'static, std::io::Result<bytes::Bytes>>;

/// An upstream request being assembled; nothing is sent (and no client-specific state chosen)
/// until [`Self::send`], since the browser profile depends on the headers.
pub struct UpstreamRequest {
    client: UpstreamClient,
    method: hyper::Method,
    url: String,
    headers: hyper::HeaderMap,
    bad_header: Option<String>,
    body: Option<UpstreamBody>,
}

enum UpstreamBody {
    Bytes(bytes::Bytes),
    Stream(BodyStream),
}

impl UpstreamClient {
    pub fn request(&self, method: hyper::Method, url: impl AsRef<str>) -> UpstreamRequest {
        UpstreamRequest {
            client: self.clone(),
            method,
            url: url.as_ref().to_string(),
            headers: Default::default(),
            bad_header: None,
            body: None,
        }
    }

    pub fn get(&self, url: impl AsRef<str>) -> UpstreamRequest {
        self.request(hyper::Method::GET, url)
    }

    /// Whether this is the browser-like client.
    pub fn is_browser_like(&self) -> bool {
        matches!(self, Self::Wreq(_))
    }
}

impl UpstreamRequest {
    /// Add a header (several of one name are kept in order).
    pub fn header<K, V>(mut self, name: K, value: V) -> Self
    where
        K: TryInto<hyper::header::HeaderName>,
        V: TryInto<hyper::header::HeaderValue>,
    {
        match (name.try_into(), value.try_into()) {
            (Ok(n), Ok(v)) => {
                self.headers.append(n, v);
            }
            _ => self.bad_header = Some("invalid header name or value".into()),
        }
        self
    }

    pub fn body(mut self, body: impl Into<bytes::Bytes>) -> Self {
        self.body = Some(UpstreamBody::Bytes(body.into()));
        self
    }

    /// Stream the request body; nothing is buffered.
    pub fn body_stream<S>(mut self, stream: S) -> Self
    where
        S: futures_util::Stream<Item = std::io::Result<bytes::Bytes>> + Send + 'static,
    {
        use futures_util::StreamExt;
        self.body = Some(UpstreamBody::Stream(stream.boxed()));
        self
    }

    pub async fn send(self) -> std::result::Result<UpstreamResponse, UpstreamError> {
        use futures_util::StreamExt;
        if let Some(m) = self.bad_header {
            return Err(UpstreamError::Invalid(m));
        }
        match self.client {
            UpstreamClient::Reqwest(c) => {
                let mut rb = c.request(self.method, &self.url).headers(self.headers);
                rb = match self.body {
                    Some(UpstreamBody::Bytes(b)) => rb.body(b),
                    Some(UpstreamBody::Stream(s)) => rb.body(reqwest::Body::wrap_stream(s)),
                    None => rb,
                };
                let r = rb.send().await.map_err(UpstreamError::Reqwest)?;
                let peer_cert = r
                    .extensions()
                    .get::<reqwest::tls::TlsInfo>()
                    .and_then(|t| t.peer_certificate())
                    .map(<[u8]>::to_vec);
                let (status, headers) = (r.status(), r.headers().clone());
                Ok(UpstreamResponse {
                    status,
                    headers,
                    peer_cert,
                    body: r
                        .bytes_stream()
                        .map(|c| c.map_err(std::io::Error::other))
                        .boxed(),
                })
            }
            UpstreamClient::Wreq(c) => {
                // The profile is the browser's own (client hints, then User-Agent); its
                // transport fingerprint is used, but none of its headers: the browser's go
                // through as they came, in their order.
                let profile = crate::browser_profile::BrowserProfile::classify(&self.headers);
                let orig = crate::browser_profile::orig_headers(&profile, self.headers.keys());
                let mut rb = c
                    .request(self.method, &self.url)
                    .emulation(profile.emulation())
                    .default_headers(false)
                    .headers(self.headers)
                    .orig_headers(orig);
                rb = match self.body {
                    Some(UpstreamBody::Bytes(b)) => rb.body(b),
                    Some(UpstreamBody::Stream(s)) => rb.body(wreq::Body::wrap_stream(s)),
                    None => rb,
                };
                let mut r = rb.send().await.map_err(UpstreamError::Wreq)?;
                let peer_cert = r
                    .extensions()
                    .get::<wreq::tls::TlsInfo>()
                    .and_then(|t| t.peer_certificate())
                    .map(<[u8]>::to_vec);
                let (status, headers) = (r.status(), std::mem::take(r.headers_mut()));
                Ok(UpstreamResponse {
                    status,
                    headers,
                    peer_cert,
                    body: r
                        .bytes_stream()
                        .map(|c| c.map_err(std::io::Error::other))
                        .boxed(),
                })
            }
        }
    }
}

/// The head of an upstream response and its body stream.
pub struct UpstreamResponse {
    status: hyper::StatusCode,
    headers: hyper::HeaderMap,
    peer_cert: Option<Vec<u8>>,
    body: BodyStream,
}

impl std::fmt::Debug for UpstreamResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamResponse")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl UpstreamResponse {
    pub fn status(&self) -> hyper::StatusCode {
        self.status
    }

    pub fn headers(&self) -> &hyper::HeaderMap {
        &self.headers
    }

    pub fn headers_mut(&mut self) -> &mut hyper::HeaderMap {
        &mut self.headers
    }

    /// DER of the certificate of the connection that served this response (https only).
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_cert.as_deref()
    }

    pub fn bytes_stream(self) -> BodyStream {
        self.body
    }
}

/// Build the shared upstream client (browser-like when `opts.browser_like`). Redirects are
/// passed through to the downstream client (the proxy must not follow them itself).
pub fn build_upstream_client(opts: &UpstreamOptions) -> Result<UpstreamClient> {
    build_client(opts, false)
}

/// Like [`build_upstream_client`], for requests aimed at the proxy's own ports: its resolver
/// refuses every address of this host, since the resolver cannot see the port.
pub fn build_strict_upstream_client(opts: &UpstreamOptions) -> Result<UpstreamClient> {
    build_client(opts, true)
}

fn build_client(opts: &UpstreamOptions, strict: bool) -> Result<UpstreamClient> {
    if opts.browser_like {
        build_wreq(opts, strict).map(UpstreamClient::Wreq)
    } else {
        build_reqwest(opts, strict).map(UpstreamClient::Reqwest)
    }
}

fn resolver_of(opts: &UpstreamOptions, strict: bool) -> PolicyResolver {
    PolicyResolver {
        policy: opts.policy.clone(),
        override_ip: opts.resolve_all_to,
        strict,
        dns: opts
            .dns
            .clone()
            .unwrap_or_else(|| Arc::new(CachedResolver::from_settings(&Default::default()))),
    }
}

/// The browser-like client: BoringSSL with the shared root set verified in the handshake. The
/// browser profile (TLS and HTTP/2 fingerprint) is chosen per request.
fn build_wreq(opts: &UpstreamOptions, strict: bool) -> Result<wreq::Client> {
    let roots = opts.roots_handle()?;
    let certs = opts.certs.clone();
    let verify: wreq::tls::CustomVerify =
        Arc::new(move |ssl, host| crate::roots::verify_btls(&roots, Some(&certs), ssl, host));
    let mut b = wreq::Client::builder()
        .no_proxy()
        .tls_info(true)
        .redirect(wreq::redirect::Policy::none())
        .tcp_nodelay(true)
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .pool_max_idle_per_host(opts.pool_max_idle_per_host.unwrap_or(32))
        .pool_idle_timeout(Duration::from_secs(60))
        .tls_custom_verify(verify)
        // Sessions kept per host for resumption (the default keeps 8).
        .tls_session_cache(Arc::new(wreq::tls::session::LruTlsSessionCache::new(256)))
        .dns_resolver(Arc::new(resolver_of(opts, strict)));
    if let Some(t) = opts.connect_timeout {
        b = b.connect_timeout(t);
    }
    if let Some(t) = opts.read_timeout {
        b = b.read_timeout(t);
    }
    b.build()
        .map_err(|e| Error::Config(format!("Failed to build upstream HTTP client: {e}")))
}

fn build_reqwest(opts: &UpstreamOptions, strict: bool) -> Result<reqwest::Client> {
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
    builder =
        builder.use_preconfigured_tls(client_tls_config(opts.roots_handle()?, opts.certs.clone())?);
    if let Some(t) = opts.connect_timeout {
        builder = builder.connect_timeout(t);
    }
    if let Some(t) = opts.read_timeout {
        builder = builder.read_timeout(t);
    }
    builder = builder.dns_resolver(Arc::new(resolver_of(opts, strict)));
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

/// Error kind of a failed browser-like upstream request (see [`classify_reqwest`]). Decided from
/// the typed source chain only, never from the top error's text: that carries the request URI,
/// which can contain any word.
pub fn classify_wreq(e: &wreq::Error) -> filter_engine::ErrorKind {
    use filter_engine::ErrorKind as K;
    use std::error::Error as _;
    if e.is_timeout() {
        return K::UpstreamTimeout;
    }
    let mut cur: Option<&(dyn std::error::Error + 'static)> = e.source();
    let mut io_kind = None;
    while let Some(err) = cur {
        if err.is::<rustls::Error>() || err.is::<btls::error::ErrorStack>() {
            return K::UpstreamTls;
        }
        if let Some(ssl) = err.downcast_ref::<btls::ssl::Error>() {
            // A BoringSSL protocol failure with no I/O cause is the handshake being refused
            // (our verify hook, or the server's alert); SYSCALL is the transport going away.
            if let Some(io) = ssl.io_error() {
                io_kind = io_kind.or(Some(classify_io(io)));
            } else if ssl.code() == btls::ssl::ErrorCode::SSL {
                return K::UpstreamTls;
            } else if ssl.code() == btls::ssl::ErrorCode::SYSCALL
                || ssl.code() == btls::ssl::ErrorCode::ZERO_RETURN
            {
                io_kind = io_kind.or(Some(K::UpstreamReset));
            }
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
    if e.is_connection_reset() {
        return K::UpstreamReset;
    }
    // Message text of the sources only (not the URI-bearing top error).
    let mut cur = e.source();
    while let Some(err) = cur {
        let t = err.to_string().to_ascii_lowercase();
        if t.contains("incomplete message")
            || t.contains("connection closed")
            || t.contains("connection reset")
        {
            return K::UpstreamReset;
        }
        cur = err.source();
    }
    K::Other
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
        let p = CertProber::with_limits(&opts, 1, Duration::from_millis(50), 4).unwrap();
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

    /// A listener that accepts and never answers, so a probe to it holds its slot.
    async fn black_hole() -> u16 {
        let hole = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = hole.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                held.push(hole.accept().await.unwrap());
            }
        });
        port
    }

    fn slow_opts() -> (UpstreamOptions, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let opts = UpstreamOptions {
            resolve_all_to: Some("127.0.0.1".parse().unwrap()),
            connect_timeout: Some(Duration::from_secs(3)),
            ..Default::default()
        };
        (opts, dir)
    }

    #[tokio::test]
    async fn background_probes_are_capped_and_never_duplicated() {
        let port = black_hole().await;
        let (opts, _d) = slow_opts();
        let p = CertProber::with_limits(&opts, 1, Duration::from_millis(20), 3).unwrap();
        let holder = {
            let p = p.clone();
            tokio::spawn(async move { p.probe("held.test", port).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Many distinct hosts while the only slot is busy: at most 3 queue, the rest drop.
        for i in 0..40 {
            assert_eq!(p.probe(&format!("h{i}.test"), port).await, None);
        }
        assert_eq!(p.background_started(), 3);
        // The same key again: its probe is already queued or running, so none is added.
        let before = p.background_started();
        p.probe("h0.test", port).await;
        assert_eq!(p.background_started(), before);
        holder.abort();
    }

    #[tokio::test]
    async fn repeated_keys_do_not_consume_background_slots() {
        let port = black_hole().await;
        let (opts, _d) = slow_opts();
        // More slots than keys: only duplicates could exhaust them.
        let p = CertProber::with_limits(&opts, 1, Duration::from_millis(20), 100).unwrap();
        let holder = {
            let p = p.clone();
            tokio::spawn(async move { p.probe("held.test", port).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        for _ in 0..4 {
            for i in 0..5 {
                assert_eq!(p.probe(&format!("k{i}.test"), port).await, None);
            }
        }
        // The holder's own call handed its probe over once, then one per distinct key.
        holder.await.unwrap();
        assert_eq!(p.background_started(), 6);
    }

    #[tokio::test]
    async fn a_caller_joining_a_running_probe_returns_within_the_wait() {
        let port = black_hole().await;
        let (opts, _d) = slow_opts();
        let p = CertProber::with_limits(&opts, 4, Duration::from_millis(100), 4).unwrap();
        let first = {
            let p = p.clone();
            tokio::spawn(async move { p.probe("j.test", port).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let t = std::time::Instant::now();
        assert_eq!(p.probe("j.test", port).await, None);
        assert!(t.elapsed() < Duration::from_secs(1));
        // The first caller handed the slow probe to the background; the joiner adds none.
        first.await.unwrap();
        assert_eq!(p.background_started(), 1);
    }

    #[tokio::test]
    async fn probe_failure_yields_nothing() {
        let pki = pki();
        let (p, _d) = prober(&pki);
        // Nothing listens on port 1.
        assert_eq!(p.probe("h.test", 1).await, None);
    }
}

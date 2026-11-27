//! One upstream resolver: its transport (UDP, TCP, DoT, DoH, DoH3, DoQ, DNSCrypt), connection
//! reuse, host-name bootstrap, and the health and RTT figures that drive load balancing and the
//! web UI.

use super::{BoxFut, DnsFailure, FailKind};
use dns_syntax::{Transport, UpstreamSpec};
use futures_util::stream::Stream;
use hickory_resolver::config::{ConnectionConfig, ProtocolConfig, ResolverOpts};
use hickory_resolver::net::dnssec::DnssecDnsHandle;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::xfer::{DnsExchange, DnsHandle, FirstAnswer};
use hickory_resolver::net::NetError;
use hickory_resolver::proto::op::{DnsRequest, DnsRequestOptions, DnsResponse, Message};
use hickory_resolver::{ConnectionProvider, PoolContext, TlsConfig};
use parking_lot::Mutex;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Which list an upstream belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Primary,
    Fallback,
    Bootstrap,
    Private,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Primary => "upstream",
            Role::Fallback => "fallback",
            Role::Bootstrap => "bootstrap",
            Role::Private => "private",
        }
    }
}

/// A connection to one upstream, as a plain `DnsHandle` regardless of transport, so DNSSEC
/// validation wraps all of them the same way.
#[derive(Clone)]
pub(crate) struct AnyHandle(
    Arc<dyn Fn(DnsRequest) -> BoxFut<Result<DnsResponse, NetError>> + Send + Sync>,
);

impl AnyHandle {
    pub(crate) fn new<F>(f: F) -> Self
    where
        F: Fn(DnsRequest) -> BoxFut<Result<DnsResponse, NetError>> + Send + Sync + 'static,
    {
        Self(Arc::new(f))
    }
}

impl DnsHandle for AnyHandle {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        Box::pin(futures_util::stream::once((self.0)(request)))
    }
}

/// What every upstream shares.
pub struct Env {
    pub timeout: Duration,
    pub dnssec: bool,
    pub tls: rustls::ClientConfig,
    pub bootstrap: Arc<Bootstrap>,
    pub ipv6: bool,
    pool: Arc<PoolContext>,
    /// Owns the background tasks of every connection: dropping it would abort them.
    provider: TokioRuntimeProvider,
}

impl Env {
    pub fn new(
        timeout: Duration,
        dnssec: bool,
        ipv6: bool,
        tls: rustls::ClientConfig,
        bootstrap: Arc<Bootstrap>,
    ) -> Self {
        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 1;
        let pool = Arc::new(PoolContext::new(
            opts,
            TlsConfig {
                config: tls.clone(),
            },
        ));
        Self {
            timeout,
            dnssec,
            tls,
            bootstrap,
            ipv6,
            pool,
            provider: TokioRuntimeProvider::default(),
        }
    }
}

/// Resolves the host names of encrypted upstreams through plain-IP resolvers (or the operating
/// system when none are configured). Used for nothing else.
pub struct Bootstrap {
    servers: Vec<Arc<Upstream>>,
}

impl Bootstrap {
    pub fn system() -> Arc<Self> {
        Arc::new(Self { servers: vec![] })
    }

    pub fn new(servers: Vec<Arc<Upstream>>) -> Arc<Self> {
        Arc::new(Self { servers })
    }

    pub fn servers(&self) -> &[Arc<Upstream>] {
        &self.servers
    }

    pub(crate) async fn resolve(&self, host: &str, ipv6: bool) -> Result<Vec<IpAddr>, String> {
        if self.servers.is_empty() {
            let r = tokio::net::lookup_host((host, 0))
                .await
                .map_err(|e| format!("system resolver: {e}"))?;
            let v: Vec<IpAddr> = r.map(|a| a.ip()).filter(|i| ipv6 || i.is_ipv4()).collect();
            return if v.is_empty() {
                Err(format!("{host}: no addresses"))
            } else {
                Ok(v)
            };
        }
        let mut last = format!("{host}: no bootstrap resolver answered");
        for s in &self.servers {
            let mut ips = Vec::new();
            let rt = hickory_resolver::proto::rr::RecordType::A;
            let six = hickory_resolver::proto::rr::RecordType::AAAA;
            let (a, b) = futures_util::future::join(
                s.exchange(super::query_message(host, rt, None)),
                async {
                    if ipv6 {
                        Some(s.exchange(super::query_message(host, six, None)).await)
                    } else {
                        None
                    }
                },
            )
            .await;
            for r in [Some(a), b].into_iter().flatten() {
                match r {
                    Ok(m) => ips.extend(super::addresses(&m).0),
                    Err(e) => last = format!("{}: {}", s.label(), e.message),
                }
            }
            if !ips.is_empty() {
                return Ok(ips);
            }
        }
        Err(last)
    }
}

/// Health and speed counters of one upstream.
#[derive(Default)]
struct Counters {
    queries: AtomicU64,
    failures: AtomicU64,
    consecutive: AtomicU32,
    /// Smoothed RTT, microseconds; 0 = not measured yet.
    rtt_us: AtomicU64,
    last_rtt_us: AtomicU64,
    last_error: Mutex<Option<String>>,
    last_ok: Mutex<Option<Instant>>,
}

/// Snapshot for the API.
#[derive(Debug, Clone)]
pub struct UpstreamStats {
    pub upstream: String,
    pub role: &'static str,
    pub transport: &'static str,
    pub queries: u64,
    pub failures: u64,
    pub consecutive_failures: u32,
    /// Smoothed round-trip time.
    pub rtt_ms: Option<f64>,
    pub last_rtt_ms: Option<f64>,
    pub healthy: bool,
    pub last_error: Option<String>,
    pub last_ok_secs_ago: Option<u64>,
}

struct Resolved {
    ips: Vec<IpAddr>,
    at: Instant,
}

/// How long a bootstrapped address list is trusted.
const RESOLVED_TTL: Duration = Duration::from_secs(300);
/// Failures in a row after which an upstream counts as down (it is still probed).
pub const UNHEALTHY_AFTER: u32 = 3;

pub struct Upstream {
    pub spec: UpstreamSpec,
    pub role: Role,
    env: Arc<Env>,
    counters: Counters,
    conn: tokio::sync::Mutex<Option<AnyHandle>>,
    resolved: Mutex<Option<Resolved>>,
}

impl Upstream {
    pub fn new(spec: UpstreamSpec, role: Role, env: Arc<Env>) -> Arc<Self> {
        Arc::new(Self {
            spec,
            role,
            env,
            counters: Counters::default(),
            conn: tokio::sync::Mutex::new(None),
            resolved: Mutex::new(None),
        })
    }

    pub fn label(&self) -> String {
        self.spec.label()
    }

    pub fn stats(&self) -> UpstreamStats {
        let c = &self.counters;
        let us = |v: u64| (v > 0).then(|| v as f64 / 1000.0);
        let consecutive = c.consecutive.load(Ordering::Relaxed);
        UpstreamStats {
            upstream: self.label(),
            role: self.role.name(),
            transport: self.spec.transport.scheme(),
            queries: c.queries.load(Ordering::Relaxed),
            failures: c.failures.load(Ordering::Relaxed),
            consecutive_failures: consecutive,
            rtt_ms: us(c.rtt_us.load(Ordering::Relaxed)),
            last_rtt_ms: us(c.last_rtt_us.load(Ordering::Relaxed)),
            healthy: consecutive < UNHEALTHY_AFTER,
            last_error: c.last_error.lock().clone(),
            last_ok_secs_ago: c.last_ok.lock().map(|t| t.elapsed().as_secs()),
        }
    }

    /// Selection weight for load balancing: faster is heavier, an upstream that keeps failing
    /// is nearly never picked first (but still gets probed now and then).
    pub fn weight(&self) -> f64 {
        let rtt = self.counters.rtt_us.load(Ordering::Relaxed);
        // Unmeasured upstreams look average, so they get tried.
        let ms = if rtt == 0 { 50.0 } else { rtt as f64 / 1000.0 };
        let w = 1.0 / ms.max(1.0);
        if self.counters.consecutive.load(Ordering::Relaxed) >= UNHEALTHY_AFTER {
            w * 0.01
        } else {
            w
        }
    }

    fn record_ok(&self, rtt: Duration) {
        let c = &self.counters;
        let us = (rtt.as_micros() as u64).max(1);
        let old = c.rtt_us.load(Ordering::Relaxed);
        let new = if old == 0 {
            us
        } else {
            (old * 7 + us * 3) / 10
        };
        c.rtt_us.store(new, Ordering::Relaxed);
        c.last_rtt_us.store(us, Ordering::Relaxed);
        c.consecutive.store(0, Ordering::Relaxed);
        *c.last_ok.lock() = Some(Instant::now());
        *c.last_error.lock() = None;
    }

    fn record_fail(&self, why: &str) {
        let c = &self.counters;
        c.failures.fetch_add(1, Ordering::Relaxed);
        c.consecutive.fetch_add(1, Ordering::Relaxed);
        *c.last_error.lock() = Some(why.to_string());
    }

    /// Send `msg` and return the response (any response code: NXDOMAIN is an answer). Errors are
    /// transport failures, timeouts, SERVFAIL-class codes and DNSSEC failures.
    ///
    /// Boxed: an upstream's exchange can bootstrap its host name, which exchanges again.
    pub fn exchange<'a>(
        &'a self,
        msg: Message,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Message, DnsFailure>> + Send + 'a>> {
        Box::pin(async move {
            self.counters.queries.fetch_add(1, Ordering::Relaxed);
            let t0 = Instant::now();
            let r = match tokio::time::timeout(self.env.timeout * 3, self.exchange_inner(msg)).await
            {
                Ok(r) => r,
                Err(_) => Err(DnsFailure::new(
                    FailKind::Timeout,
                    format!("{}: timed out", self.label()),
                )),
            };
            match &r {
                Ok(_) => self.record_ok(t0.elapsed()),
                Err(f) => self.record_fail(&f.message),
            }
            r
        })
    }

    async fn exchange_inner(&self, msg: Message) -> Result<Message, DnsFailure> {
        let mut opts = DnsRequestOptions::default();
        opts.use_edns = true;
        opts.edns_set_dnssec_ok = self.env.dnssec;
        let mut reused_err = None;
        for attempt in 0..2 {
            let (h, fresh) = self.handle(attempt > 0).await?;
            let req = DnsRequest::new(msg.clone(), opts);
            match h.send(req).first_answer().await {
                Ok(resp) => return classify(self, resp.into_message()),
                Err(e) => {
                    let f = net_failure(&self.label(), &e);
                    // A reused connection may have been closed by the server meanwhile;
                    // anything else is a real failure.
                    if fresh || f.kind == FailKind::Dnssec {
                        return Err(f);
                    }
                    reused_err = Some(f);
                }
            }
        }
        Err(reused_err.unwrap_or_else(|| DnsFailure::new(FailKind::Transient, "no connection")))
    }

    /// The live connection (opened on first use). `fresh` is true when it was opened now.
    async fn handle(&self, force_new: bool) -> Result<(AnyHandle, bool), DnsFailure> {
        let mut g = self.conn.lock().await;
        if !force_new {
            if let Some(h) = g.as_ref() {
                return Ok((h.clone(), false));
            }
        }
        let h = self.connect().await?;
        let h = if self.env.dnssec { Self::secured(h) } else { h };
        *g = Some(h.clone());
        Ok((h, true))
    }

    /// Addresses of the upstream's host: pinned, literal, or bootstrapped.
    async fn addresses(&self, refresh: bool) -> Result<Vec<IpAddr>, DnsFailure> {
        if let Some(ip) = self.spec.host_ip() {
            return Ok(vec![ip]);
        }
        if !self.spec.ips.is_empty() {
            return Ok(self.spec.ips.clone());
        }
        if !refresh {
            if let Some(r) = &*self.resolved.lock() {
                if r.at.elapsed() < RESOLVED_TTL {
                    return Ok(r.ips.clone());
                }
            }
        }
        let ips = self
            .env
            .bootstrap
            .resolve(&self.spec.host, self.env.ipv6)
            .await
            .map_err(|e| {
                DnsFailure::new(
                    FailKind::Transient,
                    format!("{}: cannot resolve its address: {e}", self.label()),
                )
            })?;
        *self.resolved.lock() = Some(Resolved {
            ips: ips.clone(),
            at: Instant::now(),
        });
        Ok(ips)
    }

    async fn connect(&self) -> Result<AnyHandle, DnsFailure> {
        let mut last = None;
        for refresh in [false, true] {
            let ips = self.addresses(refresh).await?;
            for ip in ips {
                if !self.env.ipv6 && ip.is_ipv6() {
                    continue;
                }
                match self.connect_to(ip).await {
                    Ok(h) => return Ok(h),
                    Err(e) => last = Some(e),
                }
            }
            // Pinned or literal addresses never change; bootstrapped ones are looked up again
            // once (the host may have moved).
            if self.spec.host_ip().is_some() || !self.spec.ips.is_empty() {
                break;
            }
        }
        Err(last.unwrap_or_else(|| {
            DnsFailure::new(
                FailKind::Transient,
                format!("{}: no usable address", self.label()),
            )
        }))
    }

    async fn connect_to(&self, ip: IpAddr) -> Result<AnyHandle, DnsFailure> {
        let label = self.label();
        let fail = |e: &dyn std::fmt::Display| {
            DnsFailure::new(FailKind::Transient, format!("{label}: {e}"))
        };
        let spec = &self.spec;
        if spec.transport == Transport::DnsCrypt {
            let info = spec
                .dnscrypt
                .clone()
                .ok_or_else(|| fail(&"no stamp data"))?;
            let client = Arc::new(super::dnscrypt::DnsCrypt::new(
                std::net::SocketAddr::new(ip, spec.port),
                info,
                self.env.timeout,
            ));
            return Ok(AnyHandle::new(move |req| {
                let c = client.clone();
                Box::pin(async move {
                    let (m, _) = req.into_parts();
                    c.exchange(m).await.map_err(NetError::from)
                })
            }));
        }
        let name: Arc<str> = Arc::from(spec.host.as_str());
        let path: Arc<str> = Arc::from(spec.path.as_str());
        let make = |proto: ProtocolConfig| -> Result<_, DnsFailure> {
            let mut cc = ConnectionConfig::new(proto);
            cc.port = spec.port;
            self.env
                .provider
                .new_connection(ip, &cc, &self.env.pool)
                .map_err(|e| fail(&e))
        };
        let timeout = self.env.timeout;
        let connect_label = label.clone();
        let connect = |proto: ProtocolConfig| {
            let fut = make(proto);
            let label = connect_label.clone();
            async move {
                let fut = fut?;
                match tokio::time::timeout(timeout, fut).await {
                    Ok(Ok(ex)) => Ok::<DnsExchange<TokioRuntimeProvider>, DnsFailure>(ex),
                    Ok(Err(e)) => Err(fail(&e)),
                    Err(_) => Err(DnsFailure::new(
                        FailKind::Timeout,
                        format!("{label}: connect timed out"),
                    )),
                }
            }
        };
        let proto = match spec.transport {
            Transport::Udp => {
                // UDP, with TCP for answers that do not fit (opened on first need).
                let udp = connect(ProtocolConfig::Udp).await?;
                let tcp: Arc<tokio::sync::OnceCell<DnsExchange<TokioRuntimeProvider>>> =
                    Arc::default();
                let (pool, port, provider) =
                    (self.env.pool.clone(), spec.port, self.env.provider.clone());
                return Ok(AnyHandle::new(move |req| {
                    let (udp, tcp, pool, provider) =
                        (udp.clone(), tcp.clone(), pool.clone(), provider.clone());
                    Box::pin(async move {
                        let r = udp.send(req.clone()).first_answer().await?;
                        if !r.metadata.truncation {
                            return Ok(r);
                        }
                        let ex = tcp
                            .get_or_try_init(|| async {
                                let mut cc = ConnectionConfig::new(ProtocolConfig::Tcp);
                                cc.port = port;
                                provider.new_connection(ip, &cc, &pool)?.await
                            })
                            .await?;
                        ex.send(req).first_answer().await
                    })
                }));
            }
            Transport::Tcp => ProtocolConfig::Tcp,
            Transport::Tls => ProtocolConfig::Tls { server_name: name },
            Transport::Https => ProtocolConfig::Https {
                server_name: name,
                path,
            },
            Transport::Quic => ProtocolConfig::Quic { server_name: name },
            Transport::H3 => ProtocolConfig::H3 {
                server_name: name,
                path,
                disable_grease: false,
            },
            Transport::DnsCrypt => unreachable!("handled above"),
        };
        let ex = connect(proto).await?;
        Ok(AnyHandle::new(move |req| {
            let ex = ex.clone();
            Box::pin(async move { ex.send(req).first_answer().await })
        }))
    }
}

/// The handle queries go through: DNSSEC validation wraps the transport when it is on.
impl Upstream {
    fn secured(h: AnyHandle) -> AnyHandle {
        let v = DnssecDnsHandle::new(h);
        AnyHandle::new(move |req| {
            let v = v.clone();
            Box::pin(async move { v.send(req).first_answer().await })
        })
    }
}

/// Map a response to success or failure: SERVFAIL-class codes and DNSSEC-bogus answers fail,
/// NOERROR (with or without data) and NXDOMAIN are answers.
fn classify(u: &Upstream, m: Message) -> Result<Message, DnsFailure> {
    use hickory_resolver::proto::op::ResponseCode as R;
    match m.metadata.response_code {
        R::NoError | R::NXDomain => {
            if u.env.dnssec && super::has_bogus(&m) {
                return Err(DnsFailure::new(
                    FailKind::Dnssec,
                    format!("{}: DNSSEC validation failed", u.label()),
                ));
            }
            Ok(m)
        }
        c => Err(DnsFailure::new(
            FailKind::Transient,
            format!("{}: server answered {c}", u.label()),
        )),
    }
}

fn net_failure(label: &str, e: &NetError) -> DnsFailure {
    let s = e.to_string();
    let l = s.to_ascii_lowercase();
    let kind = if matches!(e, NetError::Timeout) {
        FailKind::Timeout
    } else if l.contains("dnssec")
        || l.contains("nsec")
        || l.contains("proof")
        || l.contains("bogus")
    {
        FailKind::Dnssec
    } else {
        FailKind::Transient
    };
    DnsFailure::new(kind, format!("{label}: {s}"))
}

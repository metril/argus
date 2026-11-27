//! The upstream-DNS engine: routes a name to a set of upstreams (per-domain rules, private
//! zones, defaults), spreads queries over them (load balance, parallel, fastest address), and
//! falls back when they all fail. It is a [`Resolver`]; the cache sits in front of it.

use super::upstream::{Bootstrap, Env, Role, Upstream, UpstreamStats};
use super::{addresses, query_message, BackendResult, BoxFut, DnsFailure, FailKind, Resolver};
use common::config::{DnsEcs, DnsMode, DnsSettings};
use dns_syntax::{is_private_name, private_reverse_zone};
use futures_util::stream::{FuturesUnordered, StreamExt};
use hickory_resolver::proto::op::Message;
use hickory_resolver::proto::rr::{RData, RecordType};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// After the first answer, how long fastest-address mode waits for the other upstreams.
const FASTEST_GRACE: Duration = Duration::from_millis(250);
/// How long an empty answer waits for another upstream's positive one.
const EMPTY_GRACE: Duration = Duration::from_millis(50);
/// How long a connect probe to a returned address may take.
const RACE_TIMEOUT: Duration = Duration::from_millis(1500);

/// How fastest-address mode probes the returned addresses.
#[derive(Debug, Clone)]
pub struct RaceOpts {
    /// TCP ports tried on each address, in order.
    pub ports: Vec<u16>,
    /// Probe private and loopback addresses too (tests only: a resolver answer must not make
    /// Argus connect to internal addresses).
    pub allow_private: bool,
    /// Probing at all (shared with the resolver, which switches it off behind an upstream
    /// proxy).
    pub enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl Default for RaceOpts {
    fn default() -> Self {
        Self {
            ports: vec![443, 80],
            allow_private: false,
            enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }
}

/// Everything an engine is built from; `tls` is overridable for tests.
pub struct EngineSpec<'a> {
    pub settings: &'a DnsSettings,
    /// Upstream lines from `upstreams_source`, appended to `settings.servers`.
    pub extra_lines: &'a [String],
    pub tls: Option<rustls::ClientConfig>,
    /// Where the system resolver comes from (a name that no group serves, or private names
    /// without private resolvers).
    pub system: Arc<dyn Resolver>,
    pub race: RaceOpts,
}

enum Ecs {
    Off,
    Fixed(hickory_resolver::proto::rr::rdata::opt::ClientSubnet),
    Auto(OnceLock<Option<hickory_resolver::proto::rr::rdata::opt::ClientSubnet>>),
}

pub struct Engine {
    mode: DnsMode,
    ipv6: bool,
    private_rdns: bool,
    ecs: Ecs,
    rules: dns_syntax::Upstreams,
    /// `rules.rules[i]` is served by `rule_groups[i]` (empty = the default group).
    rule_groups: Vec<Vec<Arc<Upstream>>>,
    default: Vec<Arc<Upstream>>,
    fallback: Vec<Arc<Upstream>>,
    private: Vec<Arc<Upstream>>,
    bootstrap: Arc<Bootstrap>,
    system: Arc<dyn Resolver>,
    race: RaceOpts,
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v) => {
            let m = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix.min(32))
            };
            IpAddr::V4((u32::from(v) & m).into())
        }
        IpAddr::V6(v) => {
            let m = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix.min(128))
            };
            IpAddr::V6((u128::from(v) & m).into())
        }
    }
}

/// Whether `ip` may be probed with a connection: public unicast only. Addresses that embed an
/// IPv4 one (mapped, NAT64, 6to4) are judged by it, and NAT64 and 6to4 are never probed;
/// 0/8, 198.18/15, 240/4 and everything the destination policy treats as private or reserved
/// are refused too.
pub(crate) fn probeable(ip: IpAddr) -> bool {
    use common::net_policy::{canonical, classify, Class};
    if let IpAddr::V6(v6) = ip {
        let s = v6.segments();
        if (s[0] == 0x64 && s[1] == 0xff9b) || s[0] == 0x2002 {
            return false;
        }
    }
    let c = canonical(ip);
    if classify(c) != Class::Public {
        return false;
    }
    match c {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(o[0] == 0
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240
                || v.is_documentation())
        }
        IpAddr::V6(_) => true,
    }
}

fn auto_subnet() -> Option<hickory_resolver::proto::rr::rdata::opt::ClientSubnet> {
    use hickory_resolver::proto::rr::rdata::opt::ClientSubnet;
    // Connecting a UDP socket sends nothing; it only reveals the source address the OS would use.
    let local = |target: &str, bind: &str| {
        let s = std::net::UdpSocket::bind(bind).ok()?;
        s.connect(target).ok()?;
        s.local_addr().ok().map(|a| a.ip())
    };
    let ip = local("1.1.1.1:53", "0.0.0.0:0").or_else(|| local("[2606:4700:4700::1111]:53", "[::]:0"))?;
    if !probeable(ip) {
        return None;
    }
    let p = if ip.is_ipv4() { 24 } else { 56 };
    Some(ClientSubnet::new(mask(ip, p), p, 0))
}

impl Engine {
    pub fn new(spec: EngineSpec<'_>) -> Result<Self, String> {
        let s = spec.settings;
        let mut lines = s.servers.clone();
        lines.extend(spec.extra_lines.iter().cloned());
        let rules = dns_syntax::parse_upstreams(&lines)
            .map_err(|e| format!("upstreams, line {}: not a valid upstream line", e[0].0))?;
        let fallback = dns_syntax::parse_flat(&s.fallback)
            .map_err(|e| format!("fallback, line {}: not a valid upstream line", e[0].0))?;
        let bootstrap = dns_syntax::parse_plain(&s.bootstrap)
            .map_err(|e| format!("bootstrap, line {}: not a plain IP address", e[0].0))?;
        let private = dns_syntax::parse_plain(&s.private_resolvers)
            .map_err(|e| format!("private resolvers, line {}: not a plain IP address", e[0].0))?;
        let tls = match spec.tls {
            Some(t) => t,
            None => hickory_resolver::net::tls::client_config().map_err(|e| e.to_string())?,
        };
        let timeout = Duration::from_millis(s.timeout_ms);
        // Bootstrap servers are plain IPs: they need no bootstrap of their own.
        let plain_env = Arc::new(Env::new(
            timeout,
            false,
            s.ipv6,
            tls.clone(),
            Bootstrap::system(),
        ));
        let bootstrap = Bootstrap::new(
            bootstrap
                .into_iter()
                .map(|b| Upstream::new(b, Role::Bootstrap, plain_env.clone()))
                .collect(),
        );
        let env = Arc::new(Env::new(timeout, s.dnssec, s.ipv6, tls.clone(), bootstrap.clone()));
        // Private resolvers are local plain servers; they are not DNSSEC-validated.
        let private_env = plain_env.clone();

        let mut shared: HashMap<(String, u8), Arc<Upstream>> = HashMap::new();
        let mut get = |sp: &dns_syntax::UpstreamSpec, role: Role, env: &Arc<Env>| -> Arc<Upstream> {
            let key = (format!("{}|{:?}", sp.label(), sp.ips), role as u8);
            shared
                .entry(key)
                .or_insert_with(|| Upstream::new(sp.clone(), role, env.clone()))
                .clone()
        };
        let default: Vec<_> = rules
            .default
            .iter()
            .map(|u| get(u, Role::Primary, &env))
            .collect();
        let rule_groups = rules
            .rules
            .iter()
            .map(|r| r.upstreams.iter().map(|u| get(u, Role::Primary, &env)).collect())
            .collect();
        let fallback = fallback.iter().map(|u| get(u, Role::Fallback, &env)).collect();
        let private = private
            .iter()
            .map(|u| get(u, Role::Private, &private_env))
            .collect();

        let ecs = match s.ecs {
            DnsEcs::Off => Ecs::Off,
            DnsEcs::Auto => Ecs::Auto(OnceLock::new()),
            DnsEcs::Custom => {
                let (ip, p) = common::config::parse_ecs_subnet(&s.ecs_subnet)?;
                Ecs::Fixed(hickory_resolver::proto::rr::rdata::opt::ClientSubnet::new(
                    mask(ip, p),
                    p,
                    0,
                ))
            }
        };
        Ok(Self {
            mode: s.mode,
            ipv6: s.ipv6,
            private_rdns: s.private_rdns,
            ecs,
            rules,
            rule_groups,
            default,
            fallback,
            private,
            bootstrap,
            system: spec.system,
            race: spec.race,
        })
    }

    /// Whether any upstream (not just the system resolver) is configured.
    pub fn is_empty(&self) -> bool {
        self.default.is_empty()
            && self.rule_groups.iter().all(|g| g.is_empty())
            && self.fallback.is_empty()
            && self.private.is_empty()
    }

    fn ecs(&self) -> Option<hickory_resolver::proto::rr::rdata::opt::ClientSubnet> {
        match &self.ecs {
            Ecs::Off => None,
            Ecs::Fixed(c) => Some(*c),
            Ecs::Auto(cell) => *cell.get_or_init(auto_subnet),
        }
    }

    /// Every upstream, once.
    pub fn all_upstreams(&self) -> Vec<Arc<Upstream>> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        let groups = std::iter::once(&self.default)
            .chain(self.rule_groups.iter())
            .chain([&self.fallback, &self.private])
            .flat_map(|g| g.iter())
            .chain(self.bootstrap.servers());
        for u in groups {
            if seen.insert(Arc::as_ptr(u) as usize) {
                out.push(u.clone());
            }
        }
        out
    }

    /// Where `name` goes.
    fn route(&self, name: &str) -> Route<'_> {
        if let Some(i) = self.rules.rule_index(name) {
            let g = &self.rule_groups[i];
            // `#`: the default upstreams (or the system resolver when there are none).
            return if g.is_empty() {
                self.default_route()
            } else {
                Route::Group(g)
            };
        }
        if self.private_rdns && is_private_name(name) {
            return if self.private.is_empty() {
                Route::System
            } else {
                Route::Group(&self.private)
            };
        }
        self.default_route()
    }

    fn default_route(&self) -> Route<'_> {
        if self.default.is_empty() {
            Route::System
        } else {
            Route::Group(&self.default)
        }
    }

    /// Group order for one query: weighted random by speed (Efraimidis-Spirakis).
    fn weighted_order(group: &[Arc<Upstream>]) -> Vec<Arc<Upstream>> {
        let mut keyed: Vec<(f64, Arc<Upstream>)> = group
            .iter()
            .map(|u| {
                let r: f64 = rand::random::<f64>().max(f64::MIN_POSITIVE);
                (r.powf(1.0 / u.weight()), u.clone())
            })
            .collect();
        keyed.sort_by(|a, b| b.0.total_cmp(&a.0));
        keyed.into_iter().map(|(_, u)| u).collect()
    }

    /// Send `msg` to `group` under the configured mode. Returns every collected answer.
    async fn exchange_group(
        &self,
        group: &[Arc<Upstream>],
        msg: &Message,
    ) -> Result<Vec<Message>, DnsFailure> {
        let mut last = DnsFailure::new(FailKind::Transient, "no upstream configured");
        match self.mode {
            DnsMode::LoadBalance => {
                for u in Self::weighted_order(group) {
                    match u.exchange(msg.clone()).await {
                        Ok(m) => return Ok(vec![m]),
                        Err(f) if f.kind == FailKind::Dnssec => return Err(f),
                        Err(f) => last = f,
                    }
                }
                Err(last)
            }
            DnsMode::Parallel | DnsMode::FastestIp => {
                let fastest = self.mode == DnsMode::FastestIp;
                let mut set: FuturesUnordered<_> = group
                    .iter()
                    .map(|u| {
                        let (u, m) = (u.clone(), msg.clone());
                        async move { u.exchange(m).await }
                    })
                    .collect();
                let mut collected: Vec<Message> = Vec::new();
                let mut empty: Option<Message> = None;
                let mut deadline: Option<tokio::time::Instant> = None;
                loop {
                    let next = match deadline {
                        Some(d) => match tokio::time::timeout_at(d, set.next()).await {
                            Ok(n) => n,
                            Err(_) => break,
                        },
                        None => set.next().await,
                    };
                    match next {
                        None => break,
                        Some(Ok(m)) => {
                            if addresses(&m).0.is_empty() && ptr_names(&m).is_empty() {
                                empty.get_or_insert(m);
                                // A holder of no addresses may be beaten by a slower upstream
                                // that has some, but not for long.
                                deadline.get_or_insert(tokio::time::Instant::now() + EMPTY_GRACE);
                            } else if fastest {
                                collected.push(m);
                                deadline.get_or_insert(tokio::time::Instant::now() + FASTEST_GRACE);
                            } else {
                                return Ok(vec![m]);
                            }
                        }
                        Some(Err(f)) => last = f,
                    }
                }
                if !collected.is_empty() {
                    Ok(collected)
                } else if let Some(m) = empty {
                    Ok(vec![m])
                } else {
                    Err(last)
                }
            }
        }
    }

    /// A and AAAA of `name` from `group`.
    async fn addrs_from(&self, group: &[Arc<Upstream>], name: &str) -> BackendResult {
        let ecs = self.ecs();
        let qa = query_message(name, RecordType::A, ecs);
        let q6 = query_message(name, RecordType::AAAA, ecs);
        let a = self.exchange_group(group, &qa);
        let aaaa = async {
            if self.ipv6 {
                Some(self.exchange_group(group, &q6).await)
            } else {
                None
            }
        };
        let (a, aaaa) = tokio::join!(a, aaaa);
        let mut ips: Vec<IpAddr> = Vec::new();
        let mut ttl = u32::MAX;
        let mut nx = false;
        let mut err: Option<DnsFailure> = None;
        for r in [Some(a), aaaa].into_iter().flatten() {
            match r {
                Ok(msgs) => {
                    for m in &msgs {
                        if m.metadata.response_code
                            == hickory_resolver::proto::op::ResponseCode::NXDomain
                        {
                            nx = true;
                        }
                        let (v, t) = addresses(m);
                        for ip in v {
                            if !ips.contains(&ip) {
                                ips.push(ip);
                            }
                        }
                        ttl = ttl.min(t);
                    }
                }
                Err(f) => {
                    if err.is_none() || f.kind == FailKind::Dnssec {
                        err = Some(f);
                    }
                }
            }
        }
        if let Some(f) = err.as_ref().filter(|f| f.kind == FailKind::Dnssec) {
            return Err(f.clone());
        }
        if ips.is_empty() {
            return Err(match err {
                Some(f) if !nx => f,
                _ => DnsFailure::new(
                    FailKind::NotFound,
                    if nx { "no such name" } else { "no addresses" },
                ),
            });
        }
        if self.mode == DnsMode::FastestIp && self.race.enabled.load(std::sync::atomic::Ordering::Relaxed) {
            ips = fastest_first(ips, &self.race).await;
        }
        let ttl = if ttl == u32::MAX { 30 } else { ttl };
        Ok((ips, Duration::from_secs(ttl as u64)))
    }

    /// Forward lookup with routing and fallback.
    pub async fn lookup_name(&self, name: &str) -> BackendResult {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let r = match self.route(&name) {
            Route::System => self.system.lookup(&name).await,
            Route::Group(g) => {
                let r = self.addrs_from(g, &name).await;
                match r {
                    Err(f)
                        if matches!(f.kind, FailKind::Timeout | FailKind::Transient)
                            && !self.fallback.is_empty() =>
                    {
                        self.addrs_from(&self.fallback, &name).await
                    }
                    other => other,
                }
            }
        };
        r.map(|(mut ips, ttl)| {
            if !self.ipv6 {
                ips.retain(|i| i.is_ipv4());
            }
            (ips, ttl)
        })
        .and_then(|(ips, ttl)| {
            if ips.is_empty() {
                Err(DnsFailure::new(FailKind::NotFound, "no IPv4 addresses"))
            } else {
                Ok((ips, ttl))
            }
        })
    }

    /// Reverse lookup (PTR). Private addresses go to the private resolvers.
    pub async fn lookup_ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsFailure> {
        let name = private_reverse_zone(ip);
        let route = match self.rules.rule_index(&name) {
            Some(_) => self.route(&name),
            None if self.private_rdns && dns_syntax::routing::is_private_ip(ip) => {
                if self.private.is_empty() {
                    Route::System
                } else {
                    Route::Group(&self.private)
                }
            }
            None => self.default_route(),
        };
        let group: &[Arc<Upstream>] = match route {
            Route::System => return self.system.lookup_ptr(ip).await,
            Route::Group(g) => g,
        };
        let run = |g: &[Arc<Upstream>]| {
            let msg = query_message(&name, RecordType::PTR, None);
            let g = g.to_vec();
            async move {
                let msgs = self.exchange_group(&g, &msg).await?;
                let mut out = Vec::new();
                for m in &msgs {
                    out.extend(ptr_names(m));
                }
                if out.is_empty() {
                    Err(DnsFailure::new(FailKind::NotFound, "no PTR record"))
                } else {
                    Ok(out)
                }
            }
        };
        match run(group).await {
            Err(f)
                if matches!(f.kind, FailKind::Timeout | FailKind::Transient)
                    && !self.fallback.is_empty() =>
            {
                run(&self.fallback).await
            }
            other => other,
        }
    }

    /// One probe query to every upstream, concurrently.
    pub async fn probe(&self, name: &str) -> Vec<ProbeResult> {
        let ups = self.all_upstreams();
        if ups.is_empty() {
            let t = Instant::now();
            let r = self.system.lookup(name).await;
            return vec![ProbeResult {
                upstream: "system resolver".into(),
                role: "system",
                ok: r.is_ok(),
                latency_ms: Some(t.elapsed().as_secs_f64() * 1000.0),
                error: r.as_ref().err().map(|f| f.message.clone()),
                answers: r.map(|(v, _)| v).unwrap_or_default(),
            }];
        }
        let ecs = self.ecs();
        futures_util::future::join_all(ups.into_iter().map(|u| async move {
            let t = Instant::now();
            let r = u.exchange(query_message(name, RecordType::A, ecs)).await;
            ProbeResult {
                upstream: u.label(),
                role: u.role.name(),
                ok: r.is_ok(),
                latency_ms: Some(t.elapsed().as_secs_f64() * 1000.0),
                error: r.as_ref().err().map(|f| f.message.clone()),
                answers: r.map(|m| addresses(&m).0).unwrap_or_default(),
            }
        }))
        .await
    }
}

/// Outcome of probing one upstream.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub upstream: String,
    pub role: &'static str,
    pub ok: bool,
    pub latency_ms: Option<f64>,
    pub error: Option<String>,
    pub answers: Vec<IpAddr>,
}

enum Route<'a> {
    System,
    Group(&'a [Arc<Upstream>]),
}

fn ptr_names(m: &Message) -> Vec<String> {
    m.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::PTR(p) => Some(p.0.to_utf8().trim_end_matches('.').to_string()),
            _ => None,
        })
        .collect()
}

/// Race TCP connects to the public addresses; the first to answer goes first, the rest keep
/// their order. Addresses that are private, loopback or otherwise not for the public internet are
/// never connected to (a resolver must not make Argus touch internal ports).
async fn fastest_first(ips: Vec<IpAddr>, race: &RaceOpts) -> Vec<IpAddr> {
    let cand: Vec<IpAddr> = ips
        .iter()
        .copied()
        .filter(|i| race.allow_private || probeable(*i))
        .collect();
    if cand.len() < 2 {
        return ips;
    }
    let mut set: FuturesUnordered<_> = cand
        .iter()
        .map(|&ip| async move {
            for &port in &race.ports {
                let c = tokio::net::TcpStream::connect((ip, port));
                if matches!(tokio::time::timeout(RACE_TIMEOUT, c).await, Ok(Ok(_))) {
                    return Some(ip);
                }
            }
            None
        })
        .collect();
    let winner = tokio::time::timeout(RACE_TIMEOUT * 2, async {
        while let Some(r) = set.next().await {
            if r.is_some() {
                return r;
            }
        }
        None
    })
    .await
    .ok()
    .flatten();
    match winner {
        Some(w) => std::iter::once(w)
            .chain(ips.into_iter().filter(|i| *i != w))
            .collect(),
        None => ips,
    }
}

/// `Arc<Engine>` as a [`Resolver`] (lookups borrow the engine for their whole duration).
pub struct EngineResolver(pub Arc<Engine>);

impl Resolver for EngineResolver {
    fn lookup(&self, name: &str) -> BoxFut<BackendResult> {
        let (e, n) = (self.0.clone(), name.to_string());
        Box::pin(async move { e.lookup_name(&n).await })
    }

    fn lookup_ptr(&self, ip: IpAddr) -> BoxFut<Result<Vec<String>, DnsFailure>> {
        let e = self.0.clone();
        Box::pin(async move { e.lookup_ptr(ip).await })
    }

    fn stats(&self) -> Vec<UpstreamStats> {
        self.0.all_upstreams().iter().map(|u| u.stats()).collect()
    }
}

//! Destination policy shared by the proxy (what it may connect to) and the control plane (what
//! list/resource fetches may reach).
//!
//! Decisions are made on the *resolved* socket address that is actually connected to, never on
//! the hostname string, so DNS rebinding cannot slip past. Always refused: loopback,
//! unspecified, "this network", multicast, broadcast, link-local (cloud metadata lives at
//! 169.254.169.254) - including IPv4-mapped, NAT64, 6to4 and IPv4-compatible IPv6 forms - and the
//! proxy's own listeners. Private ranges (RFC 1918, ULA, CGNAT) are allowed unless
//! `block_private`. Allowed CIDRs override every refusal except loops onto own listeners.

use crate::{Error, Result};
use ipnet::IpNet;
use parking_lot::RwLock;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

/// Why a destination was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Loopback, unspecified, link-local, multicast, broadcast, ...
    Reserved,
    /// Private range while `block_private_destinations` is set.
    Private,
    /// The proxy's own listener.
    OwnListener,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Refusal::Reserved => "reserved address",
            Refusal::Private => "private address",
            Refusal::OwnListener => "the proxy's own listener",
        })
    }
}

/// Error carried through resolver / connector chains so callers can recognise a refusal.
#[derive(Debug)]
pub struct PolicyRefused(pub Refusal);

impl fmt::Display for PolicyRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "destination refused: {}", self.0)
    }
}

impl std::error::Error for PolicyRefused {}

/// Whether `err` (or anything in its source chain) is a [`PolicyRefused`].
pub fn is_refusal(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if e.is::<PolicyRefused>() {
            return true;
        }
        cur = e.source();
    }
    false
}

#[derive(Debug, PartialEq, Eq)]
pub enum Class {
    Reserved,
    Private,
    Public,
}

/// Fold IPv4-mapped, NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`) and IPv4-compatible IPv6
/// addresses onto the IPv4 address they embed.
pub fn canonical(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = ip else { return ip };
    let s = v6.segments();
    let v4 = |hi: u16, lo: u16| {
        IpAddr::V4(Ipv4Addr::new(
            (hi >> 8) as u8,
            hi as u8,
            (lo >> 8) as u8,
            lo as u8,
        ))
    };
    if let Some(m) = v6.to_ipv4_mapped() {
        IpAddr::V4(m)
    } else if s[0] == 0x64 && s[1] == 0xff9b && s[2..6].iter().all(|x| *x == 0) {
        v4(s[6], s[7])
    } else if s[0] == 0x2002 {
        v4(s[1], s[2])
    } else if s[..6].iter().all(|x| *x == 0) && (s[6] != 0 || s[7] > 1) {
        // ::a.b.c.d (deprecated IPv4-compatible); `::` and `::1` stay as they are.
        v4(s[6], s[7])
    } else {
        ip
    }
}

pub fn classify(ip: IpAddr) -> Class {
    match canonical(ip) {
        IpAddr::V4(a) => {
            let o = a.octets();
            if a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_link_local()
                || o[0] == 0
            {
                Class::Reserved
            } else if a.is_private() || (o[0] == 100 && (o[1] & 0xc0) == 64) {
                Class::Private
            } else {
                Class::Public
            }
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            if a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xffc0) == 0xfe80
            {
                Class::Reserved
            } else if (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfec0 {
                Class::Private
            } else {
                Class::Public
            }
        }
    }
}

/// Addresses assigned to this host's network interfaces.
#[cfg(unix)]
fn interface_addrs() -> Vec<IpAddr> {
    let mut out = Vec::new();
    // SAFETY: `getifaddrs` fills a list that is only read here, then released with
    // `freeifaddrs`; every pointer is checked for null before it is dereferenced.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() {
                match (*ifa.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                            sin.sin_addr.s_addr,
                        ))));
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    out
}

#[cfg(not(unix))]
fn interface_addrs() -> Vec<IpAddr> {
    Vec::new()
}

#[derive(Default)]
struct Own {
    ports: Vec<u16>,
    /// Specific (non-wildcard) addresses the proxy's listeners are bound to.
    addrs: Vec<IpAddr>,
}

/// Future of a name lookup.
pub type AddrFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = std::io::Result<Vec<IpAddr>>> + Send + 'static>,
>;

/// Source of addresses for a host name (the proxy installs a caching resolver). It only returns
/// addresses: every policy still judges them on every use, so one instance can serve the proxy
/// path and the stricter control-plane fetches alike.
pub trait NameResolver: Send + Sync {
    fn lookup(&self, name: &str) -> AddrFuture;
}

static SHARED_RESOLVER: std::sync::OnceLock<Arc<dyn NameResolver>> = std::sync::OnceLock::new();

/// Make `resolver` the default for every [`NetPolicy`] without its own (first call wins).
/// Returns false when one was already installed.
pub fn install_shared_resolver(resolver: Arc<dyn NameResolver>) -> bool {
    SHARED_RESOLVER.set(resolver).is_ok()
}

/// How long a name is resolved to decide whether it is the web UI endpoint.
const WEB_UI_LOOKUP: std::time::Duration = std::time::Duration::from_secs(2);

/// Which upstream addresses the proxy may connect to.
#[derive(Default)]
pub struct NetPolicy {
    resolver: Option<Arc<dyn NameResolver>>,
    /// `(block_private, allowed CIDRs)`; replaceable at runtime ([`Self::set_rules`]).
    rules: RwLock<(bool, Vec<IpNet>)>,
    /// Host names whose private (but never reserved) resolved addresses are accepted.
    allowed_hosts: Vec<String>,
    own: RwLock<Own>,
    /// The web UI endpoint `(port, bound address)`. Not an own listener: the proxy routes
    /// requests to it straight to that listener (see [`Self::web_ui_addr`]).
    web_ui: RwLock<Option<(u16, Option<IpAddr>)>>,
}

impl fmt::Debug for NetPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetPolicy")
            .field("rules", &*self.rules.read())
            .finish_non_exhaustive()
    }
}

impl NetPolicy {
    /// Use `resolver` for this policy's lookups instead of the shared one or the OS.
    pub fn with_resolver(mut self, resolver: Arc<dyn NameResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Addresses of `name` from this policy's resolver, else the shared one, else the OS.
    async fn lookup(&self, name: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        match self.resolver.as_ref().or_else(|| SHARED_RESOLVER.get()) {
            Some(r) => Ok(r
                .lookup(name)
                .await?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect()),
            None => Ok(tokio::net::lookup_host((name, port)).await?.collect()),
        }
    }
}

pub fn parse_nets(entries: &[String]) -> Result<Vec<IpNet>> {
    entries
        .iter()
        .map(|e| {
            let e = e.trim();
            e.parse::<IpNet>()
                .or_else(|_| e.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| Error::Config(format!("invalid CIDR {e:?}")))
        })
        .collect()
}

impl NetPolicy {
    /// Build from config values; invalid CIDR entries are an error.
    pub fn new(block_private: bool, allowed_destinations: &[String]) -> Result<Self> {
        Ok(Self {
            rules: RwLock::new((block_private, parse_nets(allowed_destinations)?)),
            allowed_hosts: Vec::new(),
            own: RwLock::default(),
            web_ui: RwLock::default(),
            resolver: None,
        })
    }

    /// Replace the private-range switch and the allowed CIDRs live. An invalid entry is an
    /// error and leaves the current rules untouched.
    pub fn set_rules(&self, block_private: bool, allowed_destinations: &[String]) -> Result<()> {
        let nets = parse_nets(allowed_destinations)?;
        *self.rules.write() = (block_private, nets);
        Ok(())
    }

    /// Build from the proxy settings.
    pub fn from_config(config: &crate::ProxyConfig) -> Result<Self> {
        Self::new(
            config.proxy.block_private_destinations,
            &config.proxy.allowed_destinations,
        )
    }

    /// Record the proxy's own listeners (explicit, transparent, web UI).
    pub fn set_own_listeners(&self, ports: &[u16], addrs: &[IpAddr]) {
        let mut own = self.own.write();
        own.ports = ports.to_vec();
        own.addrs = addrs
            .iter()
            .map(|a| canonical(*a))
            .filter(|a| !a.is_unspecified())
            .collect();
    }

    /// Record where the web UI listens (`None` bound address: any, reached on loopback).
    pub fn set_web_ui(&self, endpoint: Option<(u16, Option<IpAddr>)>) {
        *self.web_ui.write() = endpoint.map(|(p, ip)| (p, ip.map(canonical)));
    }

    /// Whether `host:port` names the web UI endpoint AND `client` could reach it directly, so
    /// that routing it there widens nothing: an unparseable or loopback bind is reachable only
    /// by loopback clients, a specific bind only at that address, a wildcard bind at any
    /// address the client's proxy connection arrived on (`client_local`; loopback names only
    /// for loopback clients). Names must
    /// resolve (within a short timeout) to at least one address that satisfies this.
    pub async fn is_web_ui(
        &self,
        host: &str,
        port: u16,
        override_ip: Option<IpAddr>,
        client: IpAddr,
        client_local: Option<IpAddr>,
    ) -> bool {
        let Some((wp, bound)) = *self.web_ui.read() else {
            return false;
        };
        if wp != port {
            return false;
        }
        // Fail closed: an unknown bind address counts as loopback.
        let bound = bound.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let client_loopback = canonical(client).is_loopback();
        let client_local = client_local.map(canonical);
        let reach = |ip: IpAddr| {
            let ip = canonical(ip);
            if bound.is_unspecified() {
                // A v4 wildcard listener cannot serve a v6 address.
                if bound.is_ipv4() && ip.is_ipv6() {
                    return false;
                }
                if ip.is_loopback() || ip.is_unspecified() {
                    client_loopback
                } else {
                    // Only the address this client's proxy connection arrived on: the client
                    // reached the proxy there, so it could reach the web UI there too.
                    client_local == Some(ip)
                }
            } else {
                ip == bound && (!bound.is_loopback() || client_loopback)
            }
        };
        let bare = unbracket(host);
        match bare.parse::<IpAddr>() {
            Ok(ip) => reach(ip),
            Err(_) if override_ip.is_some() => false,
            Err(_) => {
                let looked = tokio::time::timeout(WEB_UI_LOOKUP, self.lookup(bare, port)).await;
                match looked {
                    Ok(Ok(addrs)) => addrs.iter().any(|a| reach(a.ip())),
                    _ => false,
                }
            }
        }
    }

    /// Whether `port` is one of the proxy's own listening ports.
    pub fn is_own_port(&self, port: u16) -> bool {
        self.own.read().ports.contains(&port)
    }

    fn is_own_ip(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        ip.is_loopback()
            || ip.is_unspecified()
            || self.own.read().addrs.contains(&ip)
            || interface_addrs().iter().any(|a| canonical(*a) == ip)
    }

    fn decide(&self, ip: IpAddr, own: bool) -> std::result::Result<(), Refusal> {
        if own {
            return Err(Refusal::OwnListener);
        }
        let c = canonical(ip);
        let (block_private, allowed) = &*self.rules.read();
        if allowed.iter().any(|n| n.contains(&ip) || n.contains(&c)) {
            return Ok(());
        }
        match classify(ip) {
            Class::Reserved => Err(Refusal::Reserved),
            Class::Private if *block_private => Err(Refusal::Private),
            _ => Ok(()),
        }
    }

    /// Decide on the exact socket address about to be connected to.
    pub fn check(&self, ip: IpAddr, port: u16) -> std::result::Result<(), Refusal> {
        let own = self.is_own_port(port) && self.is_own_ip(ip);
        self.decide(ip, own)
    }

    /// Check for the address of the configured upstream proxy. The administrator chose it, so
    /// private and reserved ranges are fine, but Argus never chains to its own listener.
    pub fn check_proxy_endpoint(&self, ip: IpAddr, port: u16) -> std::result::Result<(), Refusal> {
        if self.is_own_port(port) && self.is_own_ip(ip) {
            Err(Refusal::OwnListener)
        } else {
            Ok(())
        }
    }

    /// Address-only check for DNS answers of a general destination (port not known to the
    /// resolver).
    pub fn check_ip(&self, ip: IpAddr) -> std::result::Result<(), Refusal> {
        self.decide(ip, false)
    }

    /// Address-only check that also treats every address of this host as an own listener. Used
    /// by the resolver of the client that serves requests to the proxy's own ports.
    pub fn check_ip_strict(&self, ip: IpAddr) -> std::result::Result<(), Refusal> {
        self.decide(ip, self.is_own_ip(ip))
    }

    /// Check `host` when it is an IP literal (names are checked when resolved). With an override
    /// the literal is still what is judged.
    pub fn check_literal(&self, host: &str, port: u16) -> std::result::Result<(), Refusal> {
        match unbracket(host).parse::<IpAddr>() {
            Ok(ip) => self.check(ip, port),
            Err(_) => Ok(()),
        }
    }

    /// Resolve `host:port` once and return the exact address to connect to, already checked.
    ///
    /// `override_ip` (code-only test hook) replaces the connect address; the policy then judges
    /// the requested literal (or `localhost` names) rather than the override.
    pub async fn resolve(
        &self,
        host: &str,
        port: u16,
        override_ip: Option<IpAddr>,
    ) -> std::result::Result<SocketAddr, ResolveError> {
        let bare = unbracket(host);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            self.check(ip, port).map_err(ResolveError::Refused)?;
            return Ok(SocketAddr::new(override_ip.unwrap_or(ip), port));
        }
        if let Some(over) = override_ip {
            let lower = bare.trim_end_matches('.').to_ascii_lowercase();
            if lower == "localhost" || lower.ends_with(".localhost") {
                self.check(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
                    .map_err(ResolveError::Refused)?;
            }
            return Ok(SocketAddr::new(over, port));
        }
        let mut denied = None;
        for addr in self.lookup(bare, port).await.map_err(ResolveError::Io)? {
            match self.check(addr.ip(), port) {
                Ok(()) => return Ok(addr),
                Err(r) => {
                    denied.get_or_insert(r);
                }
            }
        }
        Err(match denied {
            Some(r) => ResolveError::Refused(r),
            None => ResolveError::NoAddresses(bare.to_string()),
        })
    }
}

impl NetPolicy {
    /// Resolve `host:port` for a control-plane fetch and return the one address to connect to,
    /// judged as the control-plane resolver judges it (a host on the allowlist may be private).
    pub async fn resolve_control(
        &self,
        host: &str,
        port: u16,
    ) -> std::result::Result<SocketAddr, ResolveError> {
        let bare = unbracket(host);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            self.check_ip(ip).map_err(ResolveError::Refused)?;
            return Ok(SocketAddr::new(ip, port));
        }
        let mut denied = None;
        for addr in self.lookup(bare, port).await.map_err(ResolveError::Io)? {
            match self.check_resolved(bare, addr.ip()) {
                Ok(()) => return Ok(addr),
                Err(r) => {
                    denied.get_or_insert(r);
                }
            }
        }
        Err(match denied {
            Some(r) => ResolveError::Refused(r),
            None => ResolveError::NoAddresses(bare.to_string()),
        })
    }
}

/// Strip the brackets of an IPv6 literal.
pub fn unbracket(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Why [`NetPolicy::resolve`] failed.
#[derive(Debug)]
pub enum ResolveError {
    Refused(Refusal),
    NoAddresses(String),
    Io(std::io::Error),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::Refused(r) => write!(f, "destination refused: {r}"),
            ResolveError::NoAddresses(h) => write!(f, "no addresses for {h}"),
            ResolveError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Why a control-plane URL was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlRefusal {
    /// Not a parseable absolute URL.
    Invalid,
    /// Scheme other than `http` / `https`.
    Scheme,
    /// No host.
    NoHost,
    /// The host (literal or resolved) is a refused destination.
    Destination(Refusal),
}

impl fmt::Display for UrlRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UrlRefusal::Invalid => f.write_str("invalid URL"),
            UrlRefusal::Scheme => f.write_str("only http and https URLs are allowed"),
            UrlRefusal::NoHost => f.write_str("URL has no host"),
            UrlRefusal::Destination(r) => write!(
                f,
                "destination not allowed ({r}); add it to adblock.allowed_fetch_destinations to permit it"
            ),
        }
    }
}

impl NetPolicy {
    /// Strict policy for control-plane fetches: private ranges are refused too. `allowed` holds
    /// CIDRs / IPs and host names that may be fetched from regardless.
    pub fn control_plane(allowed: &[String]) -> Result<Self> {
        let (mut nets, mut hosts) = (Vec::new(), Vec::new());
        for e in allowed {
            let e = e.trim();
            if e.parse::<IpNet>().is_ok() || e.parse::<IpAddr>().is_ok() {
                nets.push(e.to_string());
            } else if !e.is_empty() && !e.contains(['/', ':', ' ']) {
                hosts.push(e.trim_end_matches('.').to_ascii_lowercase());
            } else {
                return Err(Error::Config(format!(
                    "invalid allowed_fetch_destinations entry {e:?}"
                )));
            }
        }
        let mut p = Self::new(true, &nets)?;
        p.allowed_hosts = hosts;
        Ok(p)
    }

    fn host_allowed(&self, name: &str) -> bool {
        let n = name.trim_end_matches('.').to_ascii_lowercase();
        self.allowed_hosts.contains(&n)
    }

    /// Address check for a DNS answer of `name`: an allowlisted host name may resolve to private
    /// addresses (never reserved ones).
    pub fn check_resolved(&self, name: &str, ip: IpAddr) -> std::result::Result<(), Refusal> {
        match self.check_ip(ip) {
            Err(Refusal::Private) if self.host_allowed(name) => Ok(()),
            v => v,
        }
    }

    /// Judge a control-plane URL without DNS: scheme, host and IP literals.
    pub fn check_url_literal(&self, url: &url::Url) -> std::result::Result<(), UrlRefusal> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(UrlRefusal::Scheme);
        }
        match url.host() {
            None => Err(UrlRefusal::NoHost),
            Some(url::Host::Ipv4(ip)) => self
                .check_ip(IpAddr::V4(ip))
                .map_err(UrlRefusal::Destination),
            Some(url::Host::Ipv6(ip)) => self
                .check_ip(IpAddr::V6(ip))
                .map_err(UrlRefusal::Destination),
            Some(url::Host::Domain(_)) => Ok(()),
        }
    }

    /// [`Self::check_url_literal`] plus a DNS lookup of a name host: refused when every answer is
    /// refused. A name that does not resolve is not refused here (the fetch will fail on its own).
    pub async fn check_url(&self, raw: &str) -> std::result::Result<url::Url, UrlRefusal> {
        let url = url::Url::parse(raw).map_err(|_| UrlRefusal::Invalid)?;
        self.check_url_literal(&url)?;
        if let Some(url::Host::Domain(name)) = url.host() {
            let port = url.port_or_known_default().unwrap_or(443);
            let Ok(addrs) = self.lookup(name, port).await else {
                return Ok(url);
            };
            let mut denied = None;
            let mut any = false;
            for a in addrs {
                match self.check_resolved(name, a.ip()) {
                    Ok(()) => any = true,
                    Err(r) => {
                        denied.get_or_insert(r);
                    }
                }
            }
            if let (false, Some(r)) = (any, denied) {
                return Err(UrlRefusal::Destination(r));
            }
        }
        Ok(url)
    }
}

/// reqwest DNS resolver that applies a [`NetPolicy`] to what a name resolves to (reqwest never
/// calls it for IP-literal hosts; callers check those explicitly). With a code-only override the
/// override address is returned unfiltered.
pub struct GuardedResolver {
    policy: Arc<NetPolicy>,
    override_ip: Option<IpAddr>,
    /// Also refuse every address of this host (client used for the proxy's own ports).
    strict: bool,
    /// Judge with [`NetPolicy::check_resolved`] (host allowlist) instead of the plain check.
    by_host: bool,
}

impl GuardedResolver {
    pub fn new(policy: Arc<NetPolicy>, override_ip: Option<IpAddr>, strict: bool) -> Self {
        Self {
            policy,
            override_ip,
            strict,
            by_host: false,
        }
    }

    /// Resolver for control-plane clients (honours the host allowlist).
    pub fn control_plane(policy: Arc<NetPolicy>) -> Self {
        Self {
            policy,
            override_ip: None,
            strict: false,
            by_host: true,
        }
    }
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = self.policy.clone();
        let (override_ip, strict, by_host) = (self.override_ip, self.strict, self.by_host);
        Box::pin(async move {
            if let Some(ip) = override_ip {
                return Ok(Box::new(std::iter::once(SocketAddr::new(ip, 0))) as reqwest::dns::Addrs);
            }
            let mut allowed = Vec::new();
            let mut denied = None;
            for addr in policy.lookup(name.as_str(), 0).await? {
                let verdict = if strict {
                    policy.check_ip_strict(addr.ip())
                } else if by_host {
                    policy.check_resolved(name.as_str(), addr.ip())
                } else {
                    policy.check_ip(addr.ip())
                };
                match verdict {
                    Ok(()) => allowed.push(addr),
                    Err(r) => {
                        denied.get_or_insert(r);
                    }
                }
            }
            if allowed.is_empty() {
                if let Some(r) = denied {
                    return Err(
                        Box::new(PolicyRefused(r)) as Box<dyn std::error::Error + Send + Sync>
                    );
                }
            }
            Ok(Box::new(allowed.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Maximum redirect hops a control-plane fetch follows.
pub const MAX_FETCH_REDIRECTS: usize = 3;

/// Whether a control-plane fetch may follow a redirect to `next` after `previous` hops: a few
/// hops, http/https only, no https to http downgrade (unless the fetch began on http), and
/// IP-literal targets judged by `policy` (names are vetted by the resolver when connecting).
pub fn redirect_verdict(
    policy: &NetPolicy,
    previous: &[url::Url],
    next: &url::Url,
) -> std::result::Result<(), String> {
    if previous.len() >= MAX_FETCH_REDIRECTS {
        return Err("too many redirects".into());
    }
    let began_https = previous.first().is_none_or(|u| u.scheme() == "https");
    if next.scheme() == "http" && began_https {
        return Err("redirect would downgrade https to http".into());
    }
    policy.check_url_literal(next).map_err(|e| e.to_string())
}

/// Redirect policy for control-plane fetches, see [`redirect_verdict`].
pub fn control_plane_redirects(policy: Arc<NetPolicy>) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        match redirect_verdict(&policy, attempt.previous(), attempt.url()) {
            Ok(()) => attempt.follow(),
            Err(e) => attempt.error(e),
        }
    })
}

/// A client builder wired to the control-plane policy: guarded DNS, bounded checked redirects,
/// no environment proxy. While the upstream proxy is on its requests go through it (see
/// [`crate::control_bridge`]); the destination checks are the same either way.
pub fn control_plane_client(policy: Arc<NetPolicy>) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .proxy(crate::control_bridge::proxy_rule(policy.clone()))
        .dns_resolver(Arc::new(GuardedResolver::control_plane(policy.clone())))
        .redirect(control_plane_redirects(policy))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Always answers one private address and counts lookups.
    struct Fixed(std::sync::atomic::AtomicUsize);
    impl NameResolver for Fixed {
        fn lookup(&self, _name: &str) -> AddrFuture {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(vec![ip("10.1.2.3")]) })
        }
    }

    #[tokio::test]
    async fn one_resolver_serves_both_policies_and_each_judges_the_answer() {
        let r = Arc::new(Fixed(Default::default()));
        // Proxy policy allows private ranges; the control plane refuses them (unless allowlisted).
        let proxy = NetPolicy::new(false, &[]).unwrap().with_resolver(r.clone());
        let ctl = NetPolicy::control_plane(&[])
            .unwrap()
            .with_resolver(r.clone());
        let a = proxy.resolve("nas.test", 80, None).await.unwrap();
        assert_eq!(a, SocketAddr::new(ip("10.1.2.3"), 80));
        assert!(matches!(
            ctl.resolve("nas.test", 80, None).await,
            Err(ResolveError::Refused(Refusal::Private))
        ));
        assert!(matches!(
            ctl.check_url("http://nas.test/x").await,
            Err(UrlRefusal::Destination(Refusal::Private))
        ));
        // Same answer, different verdicts: the resolver never decides policy.
        assert_eq!(r.0.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn classifier_table() {
        use Class::*;
        let table = [
            ("127.0.0.1", Reserved),
            ("127.9.9.9", Reserved),
            ("0.0.0.0", Reserved),
            ("0.1.2.3", Reserved),
            ("169.254.169.254", Reserved),
            ("224.0.0.1", Reserved),
            ("255.255.255.255", Reserved),
            ("::1", Reserved),
            ("::", Reserved),
            ("fe80::1", Reserved),
            ("febf::1", Reserved),
            ("ff02::1", Reserved),
            ("::ffff:127.0.0.1", Reserved),
            ("::ffff:169.254.169.254", Reserved),
            ("64:ff9b::7f00:1", Reserved),
            ("64:ff9b::a9fe:a9fe", Reserved),
            ("2002:7f00:1::1", Reserved),
            ("::7f00:1", Reserved),
            ("10.0.0.1", Private),
            ("172.16.5.5", Private),
            ("172.31.255.255", Private),
            ("192.168.1.1", Private),
            ("100.64.0.1", Private),
            ("100.127.255.254", Private),
            ("fd00::1", Private),
            ("fc00::1", Private),
            ("::ffff:192.168.1.1", Private),
            ("64:ff9b::c0a8:101", Private),
            ("8.8.8.8", Public),
            ("172.32.0.1", Public),
            ("100.128.0.1", Public),
            ("169.253.1.1", Public),
            ("2606:4700::1111", Public),
            ("::ffff:8.8.8.8", Public),
            ("64:ff9b::808:808", Public),
        ];
        for (addr, want) in table {
            assert_eq!(classify(ip(addr)), want, "{addr}");
        }
    }

    #[test]
    fn default_policy_refuses_reserved_allows_private_and_public() {
        let p = NetPolicy::default();
        for a in [
            "127.0.0.1",
            "::1",
            "169.254.169.254",
            "::ffff:127.0.0.1",
            "fe80::1",
        ] {
            assert_eq!(p.check(ip(a), 80), Err(Refusal::Reserved), "{a}");
        }
        for a in [
            "10.1.1.1",
            "192.168.0.1",
            "fd00::5",
            "100.64.1.1",
            "8.8.8.8",
        ] {
            assert_eq!(p.check(ip(a), 80), Ok(()), "{a}");
        }
    }

    #[test]
    fn block_private_and_allowlist() {
        let p = NetPolicy::new(true, &strs(&["192.168.1.10/32", "169.254.169.254"])).unwrap();
        assert_eq!(p.check(ip("10.0.0.1"), 80), Err(Refusal::Private));
        assert_eq!(p.check(ip("fd00::1"), 80), Err(Refusal::Private));
        assert_eq!(p.check(ip("192.168.1.11"), 80), Err(Refusal::Private));
        assert_eq!(p.check(ip("192.168.1.10"), 80), Ok(()));
        // An allowlist entry overrides a reserved refusal, mapped forms included.
        assert_eq!(p.check(ip("169.254.169.254"), 80), Ok(()));
        assert_eq!(p.check(ip("::ffff:169.254.169.254"), 80), Ok(()));
        assert_eq!(p.check(ip("127.0.0.1"), 80), Err(Refusal::Reserved));
        assert!(NetPolicy::new(false, &strs(&["not-a-cidr"])).is_err());
    }

    #[test]
    fn own_listeners_are_never_allowed() {
        let p = NetPolicy::new(false, &strs(&["127.0.0.0/8", "10.0.0.0/8"])).unwrap();
        p.set_own_listeners(&[8080, 3000], &[ip("10.0.0.7")]);
        // Allowlisted loopback works on other ports but never on an own port.
        assert_eq!(p.check(ip("127.0.0.1"), 9000), Ok(()));
        assert_eq!(p.check(ip("127.0.0.1"), 8080), Err(Refusal::OwnListener));
        assert_eq!(
            p.check(ip("::ffff:127.0.0.1"), 3000),
            Err(Refusal::OwnListener)
        );
        assert_eq!(p.check(ip("0.0.0.0"), 8080), Err(Refusal::OwnListener));
        // An own interface address, own port only.
        assert_eq!(p.check(ip("10.0.0.7"), 3000), Err(Refusal::OwnListener));
        assert_eq!(p.check(ip("10.0.0.7"), 9000), Ok(()));
        // Another host on the same port is fine.
        assert_eq!(p.check(ip("10.0.0.8"), 8080), Ok(()));
        assert_eq!(p.check_ip_strict(ip("10.0.0.7")), Err(Refusal::OwnListener));
        assert_eq!(p.check_ip(ip("10.0.0.7")), Ok(()));
    }

    #[tokio::test]
    async fn web_ui_port_is_self_but_proxy_ports_stay_refused() {
        let p = NetPolicy::new(false, &[]).unwrap();
        p.set_own_listeners(&[8080], &[]);
        let (lo, remote) = (ip("127.0.0.1"), ip("203.0.113.9"));
        // Wildcard bind: loopback names only for loopback clients.
        p.set_web_ui(Some((3000, Some(ip("0.0.0.0")))));
        assert!(p.is_web_ui("127.0.0.1", 3000, None, lo, Some(lo)).await);
        assert!(p.is_web_ui("localhost", 3000, None, lo, Some(lo)).await);
        assert!(!p.is_web_ui("[::1]", 3000, None, lo, Some(lo)).await);
        assert!(
            !p.is_web_ui("127.0.0.1", 3000, None, remote, Some(ip("10.8.0.1")))
                .await
        );
        assert!(
            !p.is_web_ui("localhost", 3000, None, remote, Some(ip("10.8.0.1")))
                .await
        );
        // Only the address the client's proxy connection arrived on: a VPN-side client asking
        // for the LAN address is not self.
        let (vpn, lan) = (ip("10.8.0.1"), ip("192.168.1.5"));
        assert!(p.is_web_ui("10.8.0.1", 3000, None, remote, Some(vpn)).await);
        assert!(
            !p.is_web_ui("192.168.1.5", 3000, None, remote, Some(vpn))
                .await
        );
        assert!(
            p.is_web_ui("192.168.1.5", 3000, None, remote, Some(lan))
                .await
        );
        assert!(!p.is_web_ui("192.168.1.5", 3000, None, remote, None).await);
        // `::` serves both families.
        p.set_web_ui(Some((3000, Some(ip("::")))));
        assert!(p.is_web_ui("[::1]", 3000, None, lo, Some(lo)).await);
        assert!(p.is_web_ui("10.8.0.1", 3000, None, remote, Some(vpn)).await);
        p.set_web_ui(Some((3000, Some(ip("0.0.0.0")))));
        // Other ports and other hosts are not the web UI.
        assert!(!p.is_web_ui("127.0.0.1", 8080, None, lo, Some(lo)).await);
        assert!(!p.is_web_ui("93.184.216.34", 3000, None, lo, Some(lo)).await);
        // Whatever misses the handoff is refused: the web UI port stays an own listener.
        p.set_own_listeners(&[8080, 3000], &[]);
        assert_eq!(p.check(ip("127.0.0.1"), 8080), Err(Refusal::OwnListener));
        assert_eq!(p.check(ip("127.0.0.1"), 3000), Err(Refusal::OwnListener));
        // Loopback bind (or unknown): loopback clients only.
        p.set_web_ui(Some((3000, Some(ip("127.0.0.1")))));
        assert!(p.is_web_ui("127.0.0.1", 3000, None, lo, Some(lo)).await);
        assert!(
            !p.is_web_ui("127.0.0.1", 3000, None, remote, Some(vpn))
                .await
        );
        p.set_web_ui(Some((3000, None)));
        assert!(
            !p.is_web_ui("127.0.0.1", 3000, None, remote, Some(vpn))
                .await
        );
        // Bound to one address: only that address.
        p.set_web_ui(Some((3000, Some(ip("10.0.0.7")))));
        assert!(p.is_web_ui("10.0.0.7", 3000, None, remote, None).await);
        assert!(!p.is_web_ui("127.0.0.1", 3000, None, lo, Some(lo)).await);
        p.set_web_ui(None);
        assert!(!p.is_web_ui("127.0.0.1", 3000, None, lo, Some(lo)).await);
    }

    #[tokio::test]
    async fn resolve_checks_the_resolved_address_not_the_name() {
        let p = NetPolicy::default();
        // localhost resolves to loopback: refused even though the name looks harmless.
        let e = p.resolve("localhost", 80, None).await.unwrap_err();
        assert!(matches!(e, ResolveError::Refused(_)), "{e}");
        assert!(p.resolve("[::1]", 80, None).await.is_err());
        assert!(p.resolve("169.254.169.254", 80, None).await.is_err());
        let ok = p.resolve("93.184.216.34", 443, None).await.unwrap();
        assert_eq!(ok, "93.184.216.34:443".parse().unwrap());
    }

    #[tokio::test]
    async fn override_keeps_the_policy_on_the_requested_destination() {
        let p = NetPolicy::default();
        let over = Some(ip("127.0.0.1"));
        // Name: connects to the override.
        assert_eq!(
            p.resolve("example.test", 8443, over).await.unwrap(),
            "127.0.0.1:8443".parse().unwrap()
        );
        // Literals and localhost names are judged on what was requested.
        assert!(p.resolve("127.0.0.1", 80, over).await.is_err());
        assert!(p.resolve("169.254.169.254", 80, over).await.is_err());
        assert!(p.resolve("localhost", 80, over).await.is_err());
        assert!(p.resolve("a.localhost", 80, over).await.is_err());
        assert!(p.resolve("203.0.113.9", 80, over).await.is_ok());
    }

    #[test]
    fn control_plane_refuses_private_and_bracketed_ipv6_literals() {
        let p = NetPolicy::control_plane(&[]).unwrap();
        let u = |s: &str| url::Url::parse(s).unwrap();
        for bad in [
            "http://[::1]/x",
            "https://[::ffff:127.0.0.1]/x",
            "https://[fd00::1]/x",
            "https://[fe80::1]/x",
            "http://127.0.0.1/x",
            "http://10.1.2.3/x",
            "http://192.168.0.1/x",
            "http://100.64.0.1/x",
            "http://169.254.169.254/x",
            "http://[64:ff9b::a9fe:a9fe]/x",
        ] {
            assert!(
                matches!(
                    p.check_url_literal(&u(bad)),
                    Err(UrlRefusal::Destination(_))
                ),
                "{bad}"
            );
        }
        assert_eq!(
            p.check_url_literal(&u("ftp://8.8.8.8/x")),
            Err(UrlRefusal::Scheme)
        );
        assert_eq!(
            p.check_url_literal(&u("file:///etc/passwd")),
            Err(UrlRefusal::Scheme)
        );
        assert!(p.check_url_literal(&u("https://8.8.8.8/x")).is_ok());
        assert!(p
            .check_url_literal(&u("https://[2606:4700::1111]/x"))
            .is_ok());
        assert!(p.check_url_literal(&u("https://example.com/x")).is_ok());
    }

    #[test]
    fn control_plane_allowlist_takes_cidrs_and_hosts() {
        let p = NetPolicy::control_plane(&strs(&["192.168.1.0/24", "nas.lan"])).unwrap();
        assert_eq!(p.check_ip(ip("192.168.1.5")), Ok(()));
        assert_eq!(p.check_ip(ip("192.168.2.5")), Err(Refusal::Private));
        // A listed host may resolve to private, but never to reserved, addresses.
        assert_eq!(p.check_resolved("NAS.lan.", ip("10.0.0.9")), Ok(()));
        assert_eq!(
            p.check_resolved("other.lan", ip("10.0.0.9")),
            Err(Refusal::Private)
        );
        assert_eq!(
            p.check_resolved("nas.lan", ip("127.0.0.1")),
            Err(Refusal::Reserved)
        );
        assert!(NetPolicy::control_plane(&strs(&["bad entry/x"])).is_err());
    }

    #[test]
    fn redirects_are_bounded_checked_and_never_downgrade() {
        let p = NetPolicy::control_plane(&[]).unwrap();
        let u = |s: &str| url::Url::parse(s).unwrap();
        let hop = u("https://a.example/");
        assert!(redirect_verdict(&p, std::slice::from_ref(&hop), &u("https://b.example/")).is_ok());
        assert!(redirect_verdict(&p, std::slice::from_ref(&hop), &u("http://b.example/")).is_err());
        // A fetch that began on http may stay on http.
        let h = u("http://a.example/");
        assert!(redirect_verdict(&p, std::slice::from_ref(&h), &u("http://b.example/")).is_ok());
        assert!(redirect_verdict(&p, std::slice::from_ref(&hop), &u("https://[::1]/")).is_err());
        assert!(redirect_verdict(
            &p,
            std::slice::from_ref(&hop),
            &u("https://169.254.169.254/")
        )
        .is_err());
        assert!(redirect_verdict(&p, std::slice::from_ref(&hop), &u("ftp://b.example/")).is_err());
        let many = vec![hop; MAX_FETCH_REDIRECTS];
        assert!(redirect_verdict(&p, &many, &u("https://b.example/")).is_err());
    }
}

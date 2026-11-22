//! Destination policy (what the proxy may connect to) and client access control (who may use it).
//!
//! Every upstream dial goes through [`DestPolicy`], and the decision is made on the *resolved*
//! socket address that is actually connected to, never on the hostname string, so DNS rebinding
//! cannot slip past it.
//!
//! Always refused: loopback, unspecified, "this network", multicast, broadcast, link-local (cloud
//! metadata lives at 169.254.169.254) — including IPv4-mapped, NAT64, 6to4 and IPv4-compatible
//! IPv6 forms — and the proxy's own listeners (loopback or an own interface address on an own
//! port). Private ranges (RFC 1918, ULA, CGNAT) are allowed unless `block_private_destinations`.
//! `allowed_destinations` CIDRs override every refusal except loops onto the proxy's own
//! listeners.

use crate::{Error, Result};
use ipnet::IpNet;
use parking_lot::RwLock;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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
enum Class {
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

fn classify(ip: IpAddr) -> Class {
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

/// Which upstream addresses the proxy may connect to.
#[derive(Default)]
pub struct DestPolicy {
    block_private: bool,
    allowed: Vec<IpNet>,
    own: RwLock<Own>,
}

impl fmt::Debug for DestPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DestPolicy")
            .field("block_private", &self.block_private)
            .field("allowed", &self.allowed)
            .finish_non_exhaustive()
    }
}

fn parse_nets(entries: &[String]) -> Result<Vec<IpNet>> {
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

impl DestPolicy {
    /// Build from config values; invalid CIDR entries are an error.
    pub fn new(block_private: bool, allowed_destinations: &[String]) -> Result<Self> {
        Ok(Self {
            block_private,
            allowed: parse_nets(allowed_destinations)?,
            own: RwLock::default(),
        })
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
        if self
            .allowed
            .iter()
            .any(|n| n.contains(&ip) || n.contains(&c))
        {
            return Ok(());
        }
        match classify(ip) {
            Class::Reserved => Err(Refusal::Reserved),
            Class::Private if self.block_private => Err(Refusal::Private),
            _ => Ok(()),
        }
    }

    /// Decide on the exact socket address about to be connected to.
    pub fn check(&self, ip: IpAddr, port: u16) -> std::result::Result<(), Refusal> {
        let own = self.is_own_port(port) && self.is_own_ip(ip);
        self.decide(ip, own)
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
        match crate::authority::unbracket(host).parse::<IpAddr>() {
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
    ) -> Result<SocketAddr> {
        let bare = crate::authority::unbracket(host);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            self.check(ip, port).map_err(refused)?;
            return Ok(SocketAddr::new(override_ip.unwrap_or(ip), port));
        }
        if let Some(over) = override_ip {
            let lower = bare.trim_end_matches('.').to_ascii_lowercase();
            if lower == "localhost" || lower.ends_with(".localhost") {
                self.check(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
                    .map_err(refused)?;
            }
            return Ok(SocketAddr::new(over, port));
        }
        let mut denied = None;
        for addr in tokio::net::lookup_host((bare, port)).await? {
            match self.check(addr.ip(), port) {
                Ok(()) => return Ok(addr),
                Err(r) => {
                    denied.get_or_insert(r);
                }
            }
        }
        Err(match denied {
            Some(r) => refused(r),
            None => Error::Connection(format!("no addresses for {bare}")),
        })
    }
}

fn refused(r: Refusal) -> Error {
    Error::DestinationRefused(r.to_string())
}

/// Precomputed client ACL: one linear scan over integer prefixes, no locks, no allocation.
#[derive(Debug, Clone, Default)]
pub struct ClientAcl {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl ClientAcl {
    pub fn new(entries: &[String]) -> Result<Self> {
        let mut acl = Self::default();
        for net in parse_nets(entries)? {
            match net {
                IpNet::V4(n) => acl
                    .v4
                    .push((u32::from(n.network()), u32::from(n.netmask()))),
                IpNet::V6(n) => acl
                    .v6
                    .push((u128::from(n.network()), u128::from(n.netmask()))),
            }
        }
        Ok(acl)
    }

    /// Whether a client at `ip` may use the proxy.
    pub fn allows(&self, ip: IpAddr) -> bool {
        match canonical_client(ip) {
            IpAddr::V4(a) => {
                let a = u32::from(a);
                self.v4.iter().any(|(net, mask)| a & mask == *net)
            }
            IpAddr::V6(a) => {
                let a = u128::from(a);
                self.v6.iter().any(|(net, mask)| a & mask == *net)
            }
        }
    }
}

/// Client addresses only fold the IPv4-mapped form (dual-stack sockets).
fn canonical_client(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Whether a dial error is a policy refusal.
pub fn is_refused_error(e: &Error) -> bool {
    matches!(e, Error::DestinationRefused(_))
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
        let p = DestPolicy::default();
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
        let p = DestPolicy::new(true, &strs(&["192.168.1.10/32", "169.254.169.254"])).unwrap();
        assert_eq!(p.check(ip("10.0.0.1"), 80), Err(Refusal::Private));
        assert_eq!(p.check(ip("fd00::1"), 80), Err(Refusal::Private));
        assert_eq!(p.check(ip("192.168.1.11"), 80), Err(Refusal::Private));
        assert_eq!(p.check(ip("192.168.1.10"), 80), Ok(()));
        // An allowlist entry overrides a reserved refusal, mapped forms included.
        assert_eq!(p.check(ip("169.254.169.254"), 80), Ok(()));
        assert_eq!(p.check(ip("::ffff:169.254.169.254"), 80), Ok(()));
        assert_eq!(p.check(ip("127.0.0.1"), 80), Err(Refusal::Reserved));
        assert!(DestPolicy::new(false, &strs(&["not-a-cidr"])).is_err());
    }

    #[test]
    fn own_listeners_are_never_allowed() {
        let p = DestPolicy::new(false, &strs(&["127.0.0.0/8", "10.0.0.0/8"])).unwrap();
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
    async fn resolve_checks_the_resolved_address_not_the_name() {
        let p = DestPolicy::default();
        // localhost resolves to loopback: refused even though the name looks harmless.
        let e = p.resolve("localhost", 80, None).await.unwrap_err();
        assert!(is_refused_error(&e), "{e}");
        assert!(p.resolve("[::1]", 80, None).await.is_err());
        assert!(p.resolve("169.254.169.254", 80, None).await.is_err());
        let ok = p.resolve("93.184.216.34", 443, None).await.unwrap();
        assert_eq!(ok, "93.184.216.34:443".parse().unwrap());
    }

    #[tokio::test]
    async fn override_keeps_the_policy_on_the_requested_destination() {
        let p = DestPolicy::default();
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
    fn client_acl_matching() {
        let acl = ClientAcl::new(&crate::config::default_allowed_clients()).unwrap();
        for a in [
            "127.0.0.1",
            "::1",
            "10.2.3.4",
            "172.20.0.9",
            "192.168.50.2",
            "100.100.1.1",
            "169.254.3.3",
            "fd12::1",
            "fe80::abcd",
            "::ffff:192.168.1.5",
        ] {
            assert!(acl.allows(ip(a)), "{a}");
        }
        for a in ["8.8.8.8", "172.32.0.1", "2606:4700::1", "::ffff:8.8.8.8"] {
            assert!(!acl.allows(ip(a)), "{a}");
        }
        assert!(!ClientAcl::new(&[]).unwrap().allows(ip("127.0.0.1")));
        let only = ClientAcl::new(&strs(&["203.0.113.0/24", "198.51.100.7"])).unwrap();
        assert!(only.allows(ip("203.0.113.200")));
        assert!(only.allows(ip("198.51.100.7")));
        assert!(!only.allows(ip("198.51.100.8")));
        assert!(ClientAcl::new(&strs(&["bogus"])).is_err());
    }
}

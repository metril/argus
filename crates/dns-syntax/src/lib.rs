//! AdGuard Home upstream DNS syntax, shared by the proxy and the web UI (so both validate a line
//! identically). Pure and dependency-light: no I/O, wasm-safe.
//!
//! Accepted upstream forms: `1.1.1.1`, `1.1.1.1:5353`, `[2606:4700::1111]:53`, `udp://`, `tcp://`,
//! `tls://host[:853]`, `https://host[:443]/path`, `h3://host[:443]/path`, `quic://host[:853]`
//! and `sdns://` stamps (plain, DNSCrypt, DoH, DoT, DoQ). A `#ip[,ip]` suffix on a hostname
//! upstream pins its bootstrap addresses. Domain routing: `[/a.com/b.org/]upstream...`,
//! `[/*.a.com/]` (subdomains only), `[//]` (single-label names), `[/lan/]#` (use the default
//! upstreams).

use base64::Engine;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub mod routing;
pub use routing::{is_private_name, private_reverse_zone};

/// How an upstream is spoken to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
    Https,
    H3,
    Quic,
    DnsCrypt,
}

impl Transport {
    pub fn scheme(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
            Transport::Tls => "tls",
            Transport::Https => "https",
            Transport::H3 => "h3",
            Transport::Quic => "quic",
            Transport::DnsCrypt => "dnscrypt",
        }
    }
    pub fn default_port(self) -> u16 {
        match self {
            Transport::Udp | Transport::Tcp => 53,
            Transport::Tls | Transport::Quic => 853,
            Transport::Https | Transport::H3 | Transport::DnsCrypt => 443,
        }
    }
    /// Plain transports need no TLS name.
    pub fn is_plain(self) -> bool {
        matches!(self, Transport::Udp | Transport::Tcp)
    }
}

/// DNSCrypt provider data from a stamp.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsCryptInfo {
    /// Provider name, e.g. `2.dnscrypt-cert.example.com`.
    pub provider_name: String,
    /// Provider's long-term Ed25519 public key.
    pub provider_pk: [u8; 32],
}

/// One parsed upstream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamSpec {
    pub transport: Transport,
    /// Host name or IP literal (the TLS server name for encrypted transports).
    pub host: String,
    pub port: u16,
    /// DoH / H3 request path (`/dns-query` by default).
    pub path: String,
    /// Addresses to use instead of resolving `host` (from `#ip` or a stamp).
    pub ips: Vec<IpAddr>,
    pub dnscrypt: Option<DnsCryptInfo>,
    /// The text it was parsed from.
    pub text: String,
}

impl UpstreamSpec {
    /// The host as an IP address, if it is a literal.
    pub fn host_ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }

    /// Short human label, e.g. `tls://dns.google:853`.
    pub fn label(&self) -> String {
        let h = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.transport {
            Transport::Udp | Transport::Tcp => {
                let t = if self.transport == Transport::Tcp {
                    "tcp://"
                } else {
                    ""
                };
                if self.port == 53 {
                    format!("{t}{}", self.host)
                } else {
                    format!("{t}{h}:{}", self.port)
                }
            }
            Transport::Https | Transport::H3 => {
                format!(
                    "{}://{h}:{}{}",
                    self.transport.scheme(),
                    self.port,
                    self.path
                )
            }
            Transport::DnsCrypt => format!(
                "dnscrypt://{}",
                self.dnscrypt
                    .as_ref()
                    .map(|d| d.provider_name.as_str())
                    .unwrap_or(&self.host)
            ),
            t => format!("{}://{h}:{}", t.scheme(), self.port),
        }
    }

    /// Whether reaching it requires resolving a name first.
    pub fn needs_bootstrap(&self) -> bool {
        self.host_ip().is_none() && self.ips.is_empty()
    }
}

/// Domain match of a routing rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainPattern {
    /// `example.com`: the name and everything under it.
    Suffix(String),
    /// `*.example.com`: subdomains only.
    Subdomains(String),
    /// `[//]`: names without a dot.
    Unqualified,
}

impl DomainPattern {
    /// Specificity of a match (label count), `None` if `name` is not covered.
    pub fn matches(&self, name: &str) -> Option<usize> {
        match self {
            DomainPattern::Suffix(d) => (name == d || name.ends_with(&format!(".{d}")))
                .then(|| d.matches('.').count() + 1),
            DomainPattern::Subdomains(d) => name
                .ends_with(&format!(".{d}"))
                .then(|| d.matches('.').count() + 1),
            DomainPattern::Unqualified => (!name.contains('.')).then_some(0),
        }
    }
}

/// A `[/domains/]upstreams` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRule {
    pub domains: Vec<DomainPattern>,
    /// Empty (`#`) = use the default upstreams.
    pub upstreams: Vec<UpstreamSpec>,
}

/// One meaningful line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    Default(Vec<UpstreamSpec>),
    Rule(DomainRule),
}

/// All upstream lines, parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Upstreams {
    pub default: Vec<UpstreamSpec>,
    pub rules: Vec<DomainRule>,
}

impl Upstreams {
    /// Index (in `rules`) of the most specific rule covering `name`; the later line wins a tie.
    pub fn rule_index(&self, name: &str) -> Option<usize> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let mut best: Option<(usize, usize)> = None;
        for (i, r) in self.rules.iter().enumerate() {
            if let Some(s) = r.domains.iter().filter_map(|d| d.matches(&name)).max() {
                if best.is_none_or(|(b, _)| s >= b) {
                    best = Some((s, i));
                }
            }
        }
        best.map(|(_, i)| i)
    }

    /// The most specific rule covering `name`, if any.
    pub fn rule_for(&self, name: &str) -> Option<&DomainRule> {
        self.rule_index(name).map(|i| &self.rules[i])
    }
}

/// Parse a whole list. Blank lines and `# comments` are skipped; every bad line is reported
/// with its 1-based number.
pub fn parse_upstreams<S: AsRef<str>>(lines: &[S]) -> Result<Upstreams, Vec<(usize, String)>> {
    let mut out = Upstreams::default();
    let mut errs = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        match parse_line(l.as_ref()) {
            Ok(None) => {}
            Ok(Some(Line::Default(mut v))) => out.default.append(&mut v),
            Ok(Some(Line::Rule(r))) => out.rules.push(r),
            Err(e) => errs.push((i + 1, e)),
        }
    }
    if errs.is_empty() {
        Ok(out)
    } else {
        Err(errs)
    }
}

/// A list of upstreams without routing rules (fallback).
pub fn parse_flat<S: AsRef<str>>(lines: &[S]) -> Result<Vec<UpstreamSpec>, Vec<(usize, String)>> {
    let u = parse_upstreams(lines)?;
    if !u.rules.is_empty() {
        return Err(vec![(1, "domain rules are not allowed here".into())]);
    }
    Ok(u.default)
}

/// A list of resolvers reached by IP over plain DNS (bootstrap, private resolvers).
pub fn parse_plain<S: AsRef<str>>(lines: &[S]) -> Result<Vec<UpstreamSpec>, Vec<(usize, String)>> {
    let mut errs = Vec::new();
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        match parse_line(l.as_ref()) {
            Ok(None) => {}
            Ok(Some(Line::Default(v))) => {
                for s in v {
                    if s.transport.is_plain() && s.host_ip().is_some() {
                        out.push(s);
                    } else {
                        errs.push((i + 1, "must be a plain IP address (ip or ip:port)".into()));
                    }
                }
            }
            Ok(Some(Line::Rule(_))) => {
                errs.push((i + 1, "domain rules are not allowed here".into()))
            }
            Err(e) => errs.push((i + 1, e)),
        }
    }
    if errs.is_empty() {
        Ok(out)
    } else {
        Err(errs)
    }
}

/// Parse one line: `Ok(None)` for blank and comment lines.
pub fn parse_line(raw: &str) -> Result<Option<Line>, String> {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    if let Some(rest) = line.strip_prefix("[/") {
        let end = rest.find("/]").ok_or("missing `/]` after the domain list")?;
        let domains = parse_domains(&rest[..end])?;
        let tail = rest[end + 2..].trim();
        let upstreams = if tail.is_empty() || tail == "#" {
            Vec::new()
        } else {
            parse_upstream_list(tail)?
        };
        return Ok(Some(Line::Rule(DomainRule { domains, upstreams })));
    }
    Ok(Some(Line::Default(parse_upstream_list(line)?)))
}

fn parse_upstream_list(s: &str) -> Result<Vec<UpstreamSpec>, String> {
    s.split_whitespace().map(parse_upstream).collect()
}

fn parse_domains(s: &str) -> Result<Vec<DomainPattern>, String> {
    if s.is_empty() {
        return Ok(vec![DomainPattern::Unqualified]);
    }
    let mut out = Vec::new();
    for d in s.split('/') {
        if d.is_empty() {
            return Err("empty domain in the list".into());
        }
        let (wild, name) = match d.strip_prefix("*.") {
            Some(n) => (true, n),
            None => (false, d),
        };
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        valid_domain(&name).map_err(|e| format!("{d:?}: {e}"))?;
        out.push(if wild {
            DomainPattern::Subdomains(name)
        } else {
            DomainPattern::Suffix(name)
        });
    }
    Ok(out)
}

fn valid_domain(n: &str) -> Result<(), &'static str> {
    if n.is_empty() || n.len() > 253 {
        return Err("not a valid domain");
    }
    for l in n.split('.') {
        if l.is_empty() || l.len() > 63 {
            return Err("not a valid domain");
        }
        if !l
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("not a valid domain");
        }
    }
    Ok(())
}

/// Parse one upstream token.
pub fn parse_upstream(tok: &str) -> Result<UpstreamSpec, String> {
    let tok = tok.trim();
    if let Some(stamp) = tok.strip_prefix("sdns://") {
        return parse_stamp(stamp, tok);
    }
    let (scheme, rest) = match tok.split_once("://") {
        Some((s, r)) => (Some(s.to_ascii_lowercase()), r),
        None => (None, tok),
    };
    let transport = match scheme.as_deref() {
        None | Some("udp") => Transport::Udp,
        Some("tcp") => Transport::Tcp,
        Some("tls") => Transport::Tls,
        Some("https") => Transport::Https,
        Some("h3") => Transport::H3,
        Some("quic") => Transport::Quic,
        Some(s) => return Err(format!("unsupported scheme `{s}://`")),
    };
    // `#ip[,ip]` pins bootstrap addresses.
    let (rest, pin) = match rest.split_once('#') {
        Some((r, p)) => (r, Some(p)),
        None => (rest, None),
    };
    let mut ips = Vec::new();
    if let Some(p) = pin {
        for ip in p.split(',') {
            ips.push(
                ip.trim()
                    .parse::<IpAddr>()
                    .map_err(|_| format!("`#{p}`: not an IP address"))?,
            );
        }
    }
    let (authority, path) = match rest.find('/') {
        Some(i) if matches!(transport, Transport::Https | Transport::H3) => {
            (&rest[..i], rest[i..].to_string())
        }
        Some(_) => return Err("unexpected path".into()),
        None => (rest, String::new()),
    };
    let (host, port) = split_host_port(authority, transport.default_port())?;
    let path = match transport {
        Transport::Https | Transport::H3 if path.is_empty() => "/dns-query".to_string(),
        _ => path,
    };
    if transport.is_plain() && host.parse::<IpAddr>().is_err() {
        return Err(format!(
            "`{tok}` is not an IP address; use tls://, https://, h3://, quic:// or sdns:// for hostnames"
        ));
    }
    if transport.is_plain() && !ips.is_empty() {
        return Err("`#ip` only applies to hostname upstreams".into());
    }
    Ok(UpstreamSpec {
        transport,
        host,
        port,
        path,
        ips,
        dnscrypt: None,
        text: tok.to_string(),
    })
}

/// Split `host`, `host:port`, `[v6]`, `[v6]:port` or a bare IPv6 literal.
fn split_host_port(s: &str, default: u16) -> Result<(String, u16), String> {
    if s.is_empty() {
        return Err("missing host".into());
    }
    if let Some(r) = s.strip_prefix('[') {
        let (h, tail) = r.split_once(']').ok_or("missing `]`")?;
        h.parse::<Ipv6Addr>().map_err(|_| "invalid IPv6 address")?;
        let port = match tail.strip_prefix(':') {
            Some(p) => parse_port(p)?,
            None if tail.is_empty() => default,
            None => return Err("junk after `]`".into()),
        };
        return Ok((h.to_string(), port));
    }
    if s.parse::<Ipv6Addr>().is_ok() {
        return Ok((s.to_string(), default));
    }
    match s.rsplit_once(':') {
        Some((h, p)) => {
            check_host(h)?;
            Ok((h.to_ascii_lowercase(), parse_port(p)?))
        }
        None => {
            check_host(s)?;
            Ok((s.to_ascii_lowercase(), default))
        }
    }
}

fn check_host(h: &str) -> Result<(), String> {
    if h.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }
    // Looks numeric but is not an address (e.g. 300.1.1.1).
    if h.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(format!("`{h}` is not a valid IP address"));
    }
    valid_domain(h).map_err(|e| format!("`{h}`: {e}"))
}

fn parse_port(p: &str) -> Result<u16, String> {
    match p.parse::<u16>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(format!("`{p}` is not a valid port")),
    }
}

// ---- sdns:// stamps (https://dnscrypt.info/stamps-specifications) ----

struct Cur<'a>(&'a [u8]);

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("truncated stamp".into());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn lp(&mut self) -> Result<&'a [u8], String> {
        let n = self.take(1)?[0] as usize;
        self.take(n)
    }
    fn lp_str(&mut self) -> Result<String, String> {
        String::from_utf8(self.lp()?.to_vec()).map_err(|_| "stamp text is not UTF-8".to_string())
    }
    /// Variable-length set: every item but the last has its high bit set.
    fn vlp(&mut self) -> Result<Vec<&'a [u8]>, String> {
        let mut v = Vec::new();
        loop {
            let b = self.take(1)?[0];
            let n = (b & 0x7f) as usize;
            let item = self.take(n)?;
            if n > 0 || b & 0x80 != 0 {
                v.push(item);
            }
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
    }
    fn done(&self) -> bool {
        self.0.is_empty()
    }
}

fn stamp_addr(a: &str) -> Result<(Option<IpAddr>, Option<u16>), String> {
    if a.is_empty() {
        return Ok((None, None));
    }
    if let Ok(sa) = a.parse::<SocketAddr>() {
        return Ok((Some(sa.ip()), Some(sa.port())));
    }
    let a = a.trim_start_matches('[').trim_end_matches(']');
    a.parse::<IpAddr>()
        .map(|ip| (Some(ip), None))
        .map_err(|_| format!("stamp address `{a}` is not an IP"))
}

fn parse_stamp(b64: &str, text: &str) -> Result<UpstreamSpec, String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64.trim_end_matches('='))
        .map_err(|_| "invalid sdns:// stamp (not base64)".to_string())?;
    let mut c = Cur(&bytes);
    let proto = c.take(1)?[0];
    let _props = c.take(8)?;
    let mk = |transport, host: String, port, path: String, ips, dnscrypt| UpstreamSpec {
        transport,
        host,
        port,
        path,
        ips,
        dnscrypt,
        text: text.to_string(),
    };
    match proto {
        0x00 => {
            let (ip, port) = stamp_addr(&c.lp_str()?)?;
            let ip = ip.ok_or("plain stamp has no address")?;
            Ok(mk(
                Transport::Udp,
                ip.to_string(),
                port.unwrap_or(53),
                String::new(),
                vec![],
                None,
            ))
        }
        0x01 => {
            let addr = c.lp_str()?;
            let pk: [u8; 32] = c
                .lp()?
                .try_into()
                .map_err(|_| "DNSCrypt public key must be 32 bytes".to_string())?;
            let provider_name = c.lp_str()?;
            let (ip, port) = stamp_addr(&addr)?;
            let ip = ip.ok_or("DNSCrypt stamp has no server address")?;
            Ok(mk(
                Transport::DnsCrypt,
                ip.to_string(),
                port.unwrap_or(443),
                String::new(),
                vec![ip],
                Some(DnsCryptInfo {
                    provider_name,
                    provider_pk: pk,
                }),
            ))
        }
        0x02..=0x04 => {
            let addr = c.lp_str()?;
            let _hashes = c.vlp()?;
            let hostname = c.lp_str()?;
            let path = if proto == 0x02 {
                c.lp_str()?
            } else {
                String::new()
            };
            let mut ips = Vec::new();
            let (aip, aport) = stamp_addr(&addr)?;
            ips.extend(aip);
            if !c.done() {
                for b in c.vlp()? {
                    let s = std::str::from_utf8(b).map_err(|_| "bad bootstrap address")?;
                    ips.extend(stamp_addr(s)?.0);
                }
            }
            let transport = match proto {
                0x02 => Transport::Https,
                0x03 => Transport::Tls,
                _ => Transport::Quic,
            };
            let (host, hport) =
                split_host_port(&hostname, aport.unwrap_or(transport.default_port()))?;
            let path = if transport == Transport::Https && path.is_empty() {
                "/dns-query".to_string()
            } else {
                path
            };
            Ok(mk(transport, host, hport, path, ips, None))
        }
        0x05 => Err("Oblivious DoH stamps are not supported".into()),
        0x81 => Err("anonymized DNSCrypt relay stamps are not upstreams".into()),
        p => Err(format!("unknown stamp protocol {p:#04x}")),
    }
}

#[cfg(test)]
mod tests;

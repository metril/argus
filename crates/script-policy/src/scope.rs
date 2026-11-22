//! Rule scopes: global, registrable domain ("site"), exact host, host + scheme.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// URL scheme of a page or source. Only the two web schemes carry policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn parse(s: &str) -> Option<Scheme> {
        if s.eq_ignore_ascii_case("https") || s.eq_ignore_ascii_case("wss") {
            Some(Scheme::Https)
        } else if s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("ws") {
            Some(Scheme::Http)
        } else {
            None
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

/// Scope error (bad host, bad syntax, not a registrable domain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeError(pub String);

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ScopeError {}

fn err<T>(m: impl Into<String>) -> Result<T, ScopeError> {
    Err(ScopeError(m.into()))
}

/// True for IPv4 literals and bracketed IPv6 literals.
pub fn is_ip(host: &str) -> bool {
    let b = host.as_bytes();
    match b.last() {
        None => false,
        Some(b']') => b[0] == b'[',
        // Punycode TLDs can end in a digit, so confirm with a real parse.
        Some(c) if c.is_ascii_digit() => host.parse::<std::net::Ipv4Addr>().is_ok(),
        _ => false,
    }
}

/// Registrable domain of `host` (public suffix list incl. private suffixes such as
/// `github.io`), or `host` itself when it has none (IPs, `localhost`, single labels, a bare
/// public suffix). `host` must be normalised (lowercase, punycode, no trailing dot). No allocation.
pub fn site_of(host: &str) -> &str {
    if is_ip(host) {
        return host;
    }
    psl::domain_str(host).unwrap_or(host)
}

/// Normalise a host name: lowercase, IDNA to punycode, trailing dot removed, IPv6 bracketed.
pub fn normalize_host(raw: &str) -> Result<String, ScopeError> {
    let raw = raw.trim().trim_end_matches('.');
    if raw.is_empty() {
        return err("empty host");
    }
    if raw.contains(['/', '@', '?', '#', ' ']) {
        return err(format!("not a bare host: {raw}"));
    }
    let raw: String = if raw.contains(':') && !raw.starts_with('[') {
        format!("[{raw}]")
    } else {
        raw.to_string()
    };
    match url::Host::parse(&raw) {
        Ok(h) => Ok(h.to_string()),
        Err(e) => err(format!("invalid host {raw}: {e}")),
    }
}

/// Where a rule applies (page side) or what it matches (source side).
///
/// Text form: `*`, `site:example.com`, `host:www.example.com`, `https://www.example.com`.
/// A bare `example.com` parses as `site:example.com`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    Global,
    /// The registrable domain and every subdomain.
    Site(String),
    /// Exactly this host (any scheme).
    Host(String),
    /// Exactly this host on this scheme.
    HostScheme(Scheme, String),
}

impl Scope {
    /// 0 global, 1 site, 2 host, 3 host+scheme.
    pub fn specificity(&self) -> u8 {
        match self {
            Scope::Global => 0,
            Scope::Site(_) => 1,
            Scope::Host(_) => 2,
            Scope::HostScheme(..) => 3,
        }
    }

    pub fn site(host: &str) -> Result<Scope, ScopeError> {
        let h = normalize_host(host)?;
        if site_of(&h) != h {
            return err(format!(
                "{h} is not a registrable domain (use site:{} or host:{h})",
                site_of(&h)
            ));
        }
        Ok(Scope::Site(h))
    }
    pub fn host(host: &str) -> Result<Scope, ScopeError> {
        Ok(Scope::Host(normalize_host(host)?))
    }

    pub fn parse(s: &str) -> Result<Scope, ScopeError> {
        let s = s.trim();
        if s == "*" {
            return Ok(Scope::Global);
        }
        if let Some(r) = s.strip_prefix("site:") {
            return Scope::site(r);
        }
        if let Some(r) = s.strip_prefix("host:") {
            return Scope::host(r);
        }
        if let Some((scheme, rest)) = s.split_once("://") {
            let Some(scheme) = Scheme::parse(scheme) else {
                return err(format!("unsupported scheme {scheme}"));
            };
            return Ok(Scope::HostScheme(
                scheme,
                normalize_host(rest.trim_end_matches('/'))?,
            ));
        }
        Scope::site(s)
    }

    /// Does the scope match a page / source with this scheme and host? `site` is
    /// `site_of(host)`, passed in so hot paths compute it once. An unknown scheme never matches
    /// a host+scheme scope.
    pub fn matches(&self, scheme: Option<Scheme>, host: &str, site: &str) -> bool {
        match self {
            Scope::Global => true,
            Scope::Site(s) => s == site,
            Scope::Host(h) => h == host,
            Scope::HostScheme(sc, h) => Some(*sc) == scheme && h == host,
        }
    }

    /// Does every page/source matched by `other` also match `self`?
    pub fn covers(&self, other: &Scope) -> bool {
        match (self, other) {
            (Scope::Global, _) => true,
            (_, Scope::Global) => false,
            (Scope::Site(a), Scope::Site(b)) => a == b,
            (Scope::Site(a), Scope::Host(h) | Scope::HostScheme(_, h)) => site_of(h) == a,
            (Scope::Host(a), Scope::Host(b)) => a == b,
            (Scope::Host(a), Scope::HostScheme(_, b)) => a == b,
            (Scope::HostScheme(s1, a), Scope::HostScheme(s2, b)) => s1 == s2 && a == b,
            _ => false,
        }
    }

    /// A search key for filtering: the host or site part (empty for global).
    pub fn host_part(&self) -> &str {
        match self {
            Scope::Global => "",
            Scope::Site(h) | Scope::Host(h) | Scope::HostScheme(_, h) => h,
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::Global => f.write_str("*"),
            Scope::Site(h) => write!(f, "site:{h}"),
            Scope::Host(h) => write!(f, "host:{h}"),
            Scope::HostScheme(s, h) => write!(f, "{}://{h}", s.as_str()),
        }
    }
}

impl Serialize for Scope {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Scope::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Scheme, host (normalised) and port of an absolute `http(s)`/`ws(s)` URL.
pub fn parse_origin(url: &str) -> Option<(Scheme, String, Option<u16>)> {
    let u = url::Url::parse(url).ok()?;
    let scheme = Scheme::parse(u.scheme())?;
    let host = u.host_str()?.to_ascii_lowercase();
    Some((scheme, host.trim_end_matches('.').to_string(), u.port()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_of_cases() {
        assert_eq!(site_of("www.example.com"), "example.com");
        assert_eq!(site_of("a.b.example.co.uk"), "example.co.uk");
        assert_eq!(site_of("co.uk"), "co.uk");
        assert_eq!(site_of("localhost"), "localhost");
        assert_eq!(site_of("intranet"), "intranet");
        assert_eq!(site_of("192.168.1.10"), "192.168.1.10");
        assert_eq!(site_of("[::1]"), "[::1]");
        assert_eq!(site_of("alice.github.io"), "alice.github.io");
        assert_eq!(site_of("xn--bcher-kva.example"), "xn--bcher-kva.example");
        assert_eq!(site_of("shop.xn--bcher-kva.de"), "xn--bcher-kva.de");
    }

    #[test]
    fn parse_forms() {
        assert_eq!(Scope::parse("*").unwrap(), Scope::Global);
        assert_eq!(
            Scope::parse("Example.COM").unwrap(),
            Scope::Site("example.com".into())
        );
        assert_eq!(
            Scope::parse("host:WWW.Example.com.").unwrap(),
            Scope::Host("www.example.com".into())
        );
        assert_eq!(
            Scope::parse("https://a.example.com/").unwrap(),
            Scope::HostScheme(Scheme::Https, "a.example.com".into())
        );
        assert_eq!(
            Scope::parse("site:bücher.de").unwrap(),
            Scope::Site("xn--bcher-kva.de".into())
        );
        assert!(Scope::parse("site:www.example.com").is_err());
        assert!(Scope::parse("ftp://x.com").is_err());
        assert!(Scope::parse("").is_err());
        assert_eq!(
            Scope::parse("host:[::1]").unwrap(),
            Scope::Host("[::1]".into())
        );
        let s = Scope::parse("https://a.example.com").unwrap();
        assert_eq!(Scope::parse(&s.to_string()).unwrap(), s);
    }

    #[test]
    fn covers_relation() {
        let site = Scope::parse("example.com").unwrap();
        let host = Scope::parse("host:a.example.com").unwrap();
        let hs = Scope::parse("https://a.example.com").unwrap();
        assert!(Scope::Global.covers(&site));
        assert!(site.covers(&host) && site.covers(&hs) && host.covers(&hs));
        assert!(!hs.covers(&host) && !host.covers(&site));
        assert!(!site.covers(&Scope::parse("host:a.other.com").unwrap()));
    }
}

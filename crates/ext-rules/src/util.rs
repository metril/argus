//! Small allocation-free helpers: hashing, URL splitting, host-suffix walking, domain sets.

use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

/// Fx-style hasher: fast for short strings and integer keys. Keys are rule-derived; request data
/// is only ever probed, never inserted, so hash flooding is not a concern.
#[derive(Default, Clone, Copy)]
pub(crate) struct Fx(u64);

impl Hasher for Fx {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0.rotate_left(5) ^ b as u64).wrapping_mul(0x517c_c1b7_2722_0a95);
        }
    }
    fn write_u64(&mut self, i: u64) {
        self.0 = (self.0.rotate_left(5) ^ i).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
}

pub(crate) type FxMap<K, V> = HashMap<K, V, BuildHasherDefault<Fx>>;

/// Byte range of the host in `url` (`scheme://[user@]host[:port]/...`), or `None`.
pub(crate) fn host_range(url: &str) -> Option<(usize, usize)> {
    let b = url.as_bytes();
    let s = url.find("://")? + 3;
    let end = s + b[s..]
        .iter()
        .position(|&c| matches!(c, b'/' | b'?' | b'#'))
        .unwrap_or(b.len() - s);
    let mut start = s;
    if let Some(at) = b[s..end].iter().rposition(|&c| c == b'@') {
        start = s + at + 1;
    }
    let mut stop = end;
    if b.get(start) == Some(&b'[') {
        if let Some(close) = b[start..end].iter().position(|&c| c == b']') {
            return Some((start, start + close + 1));
        }
    } else if let Some(colon) = b[start..end].iter().rposition(|&c| c == b':') {
        stop = start + colon;
    }
    (stop > start).then_some((start, stop))
}

#[cfg(test)]
pub(crate) fn host_of(url: &str) -> Option<&str> {
    host_range(url).map(|(a, b)| &url[a..b])
}

/// Lowercase only when needed (hosts are normally lowercase already).
pub(crate) fn lower(s: &str) -> Cow<'_, str> {
    if s.bytes().any(|c| c.is_ascii_uppercase()) {
        Cow::Owned(s.to_ascii_lowercase())
    } else {
        Cow::Borrowed(s)
    }
}

/// `host`, then each parent domain: `a.b.c` -> `a.b.c`, `b.c`, `c`.
pub(crate) fn suffixes(host: &str) -> impl Iterator<Item = &str> {
    let mut next = Some(host);
    std::iter::from_fn(move || {
        let cur = next?;
        next = cur
            .find('.')
            .map(|i| &cur[i + 1..])
            .filter(|s| !s.is_empty());
        Some(cur)
    })
}

/// `host == d` or `host` is a subdomain of `d`.
pub(crate) fn host_is_or_under(host: &str, d: &str) -> bool {
    host == d
        || (host.len() > d.len()
            && host.ends_with(d)
            && host.as_bytes()[host.len() - d.len() - 1] == b'.')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Dom {
    /// `example.com` (and its subdomains).
    Suffix(Box<str>),
    /// `example.*`: `example` followed by any 1-3 label suffix (`.com`, `.co.uk`).
    Entity(Box<str>),
}

impl Dom {
    fn parse(s: &str) -> Option<Dom> {
        let s = s.trim().to_ascii_lowercase();
        if s.is_empty() || s.contains(['/', ' ']) {
            return None;
        }
        Some(match s.strip_suffix(".*") {
            Some(base) if !base.is_empty() => Dom::Entity(base.into()),
            _ => Dom::Suffix(s.into()),
        })
    }
    fn matches(&self, host: &str) -> bool {
        match self {
            Dom::Suffix(d) => host_is_or_under(host, d),
            Dom::Entity(base) => suffixes(host).any(|s| {
                s.strip_prefix(&**base)
                    .and_then(|r| r.strip_prefix('.'))
                    .is_some_and(|rest| (1..=3).contains(&rest.split('.').count()))
            }),
        }
    }
    fn weight(&self) -> usize {
        match self {
            Dom::Suffix(d) => d.len(),
            Dom::Entity(d) => d.len() + 2,
        }
    }
}

/// `a.com|~b.a.com` style list. The most specific entry matching the host wins (uBO "Static
/// filter syntax", `domain=` option); with no matching entry the set matches only when it has no
/// positive entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DomainSet {
    pub include: Vec<Dom>,
    pub exclude: Vec<Dom>,
}

impl DomainSet {
    /// Parse entries separated by `sep`; `Err` on a malformed entry.
    pub fn parse(list: &str, sep: char) -> Result<Self, String> {
        let mut out = DomainSet::default();
        for part in list.split(sep) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (neg, name) = match part.strip_prefix('~') {
                Some(n) => (true, n),
                None => (false, part),
            };
            if name.starts_with('/') {
                return Err("regular-expression domains are not supported".into());
            }
            let d = Dom::parse(name).ok_or_else(|| format!("bad domain `{part}`"))?;
            if neg {
                out.exclude.push(d)
            } else {
                out.include.push(d)
            }
        }
        Ok(out)
    }
    pub fn is_unrestricted(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }
    pub fn matches(&self, host: &str) -> bool {
        let mut best: Option<(usize, bool)> = None;
        for (set, inc) in [(&self.include, true), (&self.exclude, false)] {
            for d in set {
                if d.matches(host) && best.is_none_or(|(w, _)| d.weight() > w) {
                    best = Some((d.weight(), inc));
                }
            }
        }
        match best {
            Some((_, inc)) => inc,
            None => self.include.is_empty(),
        }
    }
    /// Plain-suffix keys usable for host bucketing, or `None` if any positive entry is an entity
    /// or the set has no positive entries.
    pub fn bucket_keys(&self) -> Option<Vec<&str>> {
        if self.include.is_empty() {
            return None;
        }
        self.include
            .iter()
            .map(|d| match d {
                Dom::Suffix(s) => Some(&**s),
                Dom::Entity(_) => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(host_of("https://u:p@a.b.com:8080/x?y"), Some("a.b.com"));
        assert_eq!(host_of("http://[::1]:80/"), Some("[::1]"));
        assert_eq!(host_of("nope"), None);
        assert_eq!(suffixes("a.b.c").collect::<Vec<_>>(), ["a.b.c", "b.c", "c"]);
    }

    #[test]
    fn domain_specificity() {
        let d = DomainSet::parse("~a.com|b.a.com", '|').unwrap();
        assert!(d.matches("b.a.com") && !d.matches("a.com") && !d.matches("x.a.com"));
        assert!(!d.matches("other.org"));
        let d = DomainSet::parse("~a.com", '|').unwrap();
        assert!(d.matches("other.org") && !d.matches("w.a.com"));
        let d = DomainSet::parse("google.*", '|').unwrap();
        assert!(d.matches("www.google.co.uk") && d.matches("google.com") && !d.matches("google"));
    }
}

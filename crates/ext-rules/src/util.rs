//! Small allocation-free helpers: hashing, URL splitting, host-suffix walking, domain sets.

use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

use regex::{Regex, RegexBuilder};

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

/// Size limit of every regex compiled from a rule (matches the other rule regexes).
pub(crate) const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Index of the unescaped `/` closing the regex literal opening at `b[start]`, honouring `\`
/// escapes and `[...]` classes.
fn regex_end(b: &[u8], start: usize) -> Option<usize> {
    let (mut i, mut class) = (start + 1, false);
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b'[' => class = true,
            b']' => class = false,
            b'/' if !class => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Compile a `/regex/flags` literal (flags: `i`, `s`). `force_ci` makes it case-insensitive
/// (hostnames). Every failure message contains "unsupported" so callers report the rule as
/// unsupported: the `regex` crate has no look-around or back-references.
pub(crate) fn compile_slash_regex(lit: &str, force_ci: bool) -> Result<Regex, String> {
    let lit = lit.trim();
    let end = lit
        .starts_with('/')
        .then(|| lit.rfind('/'))
        .flatten()
        .filter(|&e| e > 0)
        .ok_or_else(|| "unsupported regex: unterminated /regex/".to_string())?;
    let (src, flags) = (&lit[1..end], &lit[end + 1..]);
    if src.is_empty() {
        return Err("unsupported regex: empty regular expression".into());
    }
    if !flags.bytes().all(|c| matches!(c, b'i' | b's')) {
        return Err(format!("unsupported regex flags `{flags}`"));
    }
    RegexBuilder::new(src)
        .case_insensitive(force_ci || flags.contains('i'))
        .dot_matches_new_line(flags.contains('s'))
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| {
            let msg = e.to_string();
            let first = msg.lines().last().unwrap_or("").trim().to_string();
            let what = if msg.contains("look-around") || msg.contains("backreferences") {
                "look-around and back-references are not supported"
            } else if msg.contains("size limit") {
                "pattern too large"
            } else {
                "pattern does not compile"
            };
            format!("unsupported regex ({what}): {first}")
        })
}

/// Split `list` on `sep`, keeping `/regex/flags` items (optionally `~`-prefixed) whole, so a
/// separator inside a regex (`{0,1}`, `a|b`) does not split it.
pub(crate) fn split_items(list: &str, sep: char) -> Vec<&str> {
    let b = list.as_bytes();
    let sep = sep as u8;
    let (mut out, mut start, mut i) = (Vec::new(), 0usize, 0usize);
    while i <= b.len() {
        if i == start {
            let s = if b.get(i) == Some(&b'~') { i + 1 } else { i };
            if b.get(s) == Some(&b'/') {
                if let Some(e) = regex_end(b, s) {
                    i = e + 1;
                    while i < b.len() && b[i].is_ascii_alphabetic() {
                        i += 1;
                    }
                }
            }
        }
        if i >= b.len() || b[i] == sep {
            out.push(&list[start..i.min(b.len())]);
            start = i + 1;
        }
        i += 1;
    }
    out
}

/// Path and query of an absolute URL (`/` when empty; the fragment is dropped).
pub(crate) fn path_and_query(url: &str) -> Cow<'_, str> {
    let Some((_, e)) = host_range(url) else {
        return Cow::Borrowed("/");
    };
    let rest = &url[e..];
    let rest = &rest[rest.find(['/', '?']).unwrap_or(rest.len())..];
    let rest = rest.split('#').next().unwrap_or("");
    match rest {
        "" => Cow::Borrowed("/"),
        r if r.starts_with('?') => Cow::Owned(format!("/{r}")),
        r => Cow::Borrowed(r),
    }
}

/// `host == d` or `host` is a subdomain of `d`.
pub(crate) fn host_is_or_under(host: &str, d: &str) -> bool {
    host == d
        || (host.len() > d.len()
            && host.ends_with(d)
            && host.as_bytes()[host.len() - d.len() - 1] == b'.')
}

/// A `/regex/` hostname entry; compared by its source text.
#[derive(Debug, Clone)]
pub(crate) struct HostRe {
    src: Box<str>,
    re: Regex,
}

impl PartialEq for HostRe {
    fn eq(&self, o: &Self) -> bool {
        self.src == o.src
    }
}
impl Eq for HostRe {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Dom {
    /// `/regex/` matched against the whole hostname (case-insensitive).
    Regex(HostRe),
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
            Dom::Regex(r) => r.re.is_match(host),
            Dom::Suffix(d) => host_is_or_under(host, d),
            Dom::Entity(base) => suffixes(host).any(|s| {
                s.strip_prefix(&**base)
                    .and_then(|r| r.strip_prefix('.'))
                    .is_some_and(|rest| (1..=3).contains(&rest.split('.').count()))
            }),
        }
    }
    /// Specificity. A regex is the least specific positive entry but beats any plain entry when
    /// it excludes, so `b.com,~/^m\.b\.com$/` leaves `m.b.com` out.
    fn weight(&self, exclude: bool) -> usize {
        match self {
            Dom::Regex(_) => {
                if exclude {
                    usize::MAX / 2
                } else {
                    1
                }
            }
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
        for part in split_items(list, sep) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (neg, name) = match part.strip_prefix('~') {
                Some(n) => (true, n),
                None => (false, part),
            };
            let d = if name.starts_with('/') {
                Dom::Regex(HostRe {
                    src: name.into(),
                    re: compile_slash_regex(name, true)?,
                })
            } else {
                Dom::parse(name).ok_or_else(|| format!("bad domain `{part}`"))?
            };
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
                let w = d.weight(!inc);
                if d.matches(host) && best.is_none_or(|(b, _)| w > b) {
                    best = Some((w, inc));
                }
            }
        }
        match best {
            Some((_, inc)) => inc,
            None => self.include.is_empty(),
        }
    }
    /// Host-bucket plan for page-scoped rules: the plain-suffix keys, and whether the rule must
    /// also sit in the generic list (it has entity or regex entries, or no positive entry).
    /// Candidates are a superset of the matches; exclusions are applied by [`Self::matches`].
    pub fn bucket_plan(&self) -> (Vec<&str>, bool) {
        let keys: Vec<&str> = self
            .include
            .iter()
            .filter_map(|d| match d {
                Dom::Suffix(s) => Some(&**s),
                _ => None,
            })
            .collect();
        let generic = self.include.is_empty() || keys.len() != self.include.len();
        (keys, generic)
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
                Dom::Entity(_) | Dom::Regex(_) => None,
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
    fn regex_domains() {
        let d = DomainSet::parse(r"b.com,~/^m\.b\.com$/", ',').unwrap();
        assert!(d.matches("b.com") && d.matches("www.b.com") && !d.matches("m.b.com"));
        let d = DomainSet::parse(r"/(\d{0,1})?tamilprint(\d{1,2})?\.[a-z]{3,7}/", ',').unwrap();
        assert!(
            d.matches("tamilprint12.com") && d.matches("TAMILPRINT.net") && !d.matches("x.org")
        );
        assert!(d.bucket_keys().is_none());
        let d = DomainSet::parse(r"/^a\.(b|c)\.com$/|x.org", '|').unwrap();
        assert!(d.matches("a.c.com") && d.matches("x.org") && !d.matches("a.d.com"));
        for bad in [r"/(?=x)/", r"/(a)\1/", "/(/", "/x"] {
            let e = DomainSet::parse(bad, ',').unwrap_err();
            assert!(e.contains("unsupported"), "{bad}: {e}");
        }
        assert_eq!(
            split_items(r"a,/x{1,2}/,~/y,z/i,b", ','),
            ["a", "/x{1,2}/", "~/y,z/i", "b"]
        );
    }

    #[test]
    fn path_query() {
        assert_eq!(path_and_query("https://a.com"), "/");
        assert_eq!(path_and_query("https://a.com/x/y?z=1#f"), "/x/y?z=1");
        assert_eq!(path_and_query("https://a.com:81?z=1"), "/?z=1");
        assert_eq!(path_and_query("https://a.com/#f"), "/");
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

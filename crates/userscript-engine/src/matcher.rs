//! URL matching for `@match`, `@include`, `@exclude` and `@exclude-match`.
//!
//! * `@match` / `@exclude-match`: Chrome extension match-pattern grammar
//!   (`<scheme>://<host><path>`, `<all_urls>`), plus the `.tld` host suffix Violentmonkey and
//!   Tampermonkey accept. Scheme `*` means http or https. A port, when written, must match;
//!   when omitted any port matches (as in Chrome). The path is matched against path + query.
//! * `@include` / `@exclude`: Greasemonkey globs (`*` = any run of characters, everything else
//!   literal, ASCII case-insensitive) or `/regex/flags` (flags `i`, `m`, `s` honoured).
//!   A host ending in `.tld` matches any public suffix.
//! * Precedence: an exclude always wins. A script with no `@match` and no `@include` matches
//!   everything: Violentmonkey documents "if neither `@match` nor `@include` rule is defined,
//!   the script is assumed to match" (violentmonkey.github.io/api/matching). Tampermonkey's docs
//!   are silent on this, so it is a policy knob ([`Options::match_all_without_rules`]).
//!
//! Everything compiles once; matching allocates nothing.

use crate::metadata::UserscriptMetadata;
use regex::{Regex, RegexBuilder};

/// Compile options.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Treat a script with no `@match`/`@include` as matching every URL.
    pub match_all_without_rules: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            match_all_without_rules: true,
        }
    }
}

/// Borrowed pieces of a normalised URL (`Url::as_str()` form). Allocation-free.
#[derive(Debug, Clone, Copy)]
pub struct UrlParts<'a> {
    pub scheme: &'a str,
    /// Without brackets for IPv6; may be empty (`file:///`).
    pub host: &'a str,
    pub port: Option<u16>,
    /// Path plus query, `/` when empty.
    pub path_query: &'a str,
    /// The URL without its `#fragment`.
    pub full: &'a str,
}

impl<'a> UrlParts<'a> {
    pub fn parse(url: &'a str) -> Option<Self> {
        let full = url.split('#').next().unwrap_or(url);
        let (scheme, rest) = full.split_once("://")?;
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (auth, tail) = rest.split_at(end);
        let auth = auth.rsplit('@').next().unwrap_or(auth);
        let (host, port) = if let Some(b) = auth.strip_prefix('[') {
            let close = b.find(']')?;
            let after = &b[close + 1..];
            (&b[..close], after.strip_prefix(':').and_then(|p| p.parse().ok()))
        } else {
            match auth.rsplit_once(':') {
                Some((h, p)) if p.bytes().all(|c| c.is_ascii_digit()) => (h, p.parse().ok()),
                _ => (auth, None),
            }
        };
        let path_query = if tail.is_empty() || tail.starts_with('?') {
            // `http://h?x` has no path; Chrome treats the path as `/`+query.
            if tail.is_empty() { "/" } else { tail }
        } else {
            tail
        };
        Some(UrlParts {
            scheme,
            host,
            port,
            path_query,
            full,
        })
    }

    fn default_port(&self) -> Option<u16> {
        match self.scheme {
            "http" | "ws" => Some(80),
            "https" | "wss" => Some(443),
            "ftp" => Some(21),
            _ => None,
        }
    }
}

/// Which hosts a matcher can possibly match; used to bucket scripts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HostKey {
    Any,
    Exact(String),
    /// The host itself or any subdomain.
    Suffix(String),
}

#[derive(Debug, Clone)]
struct Glob {
    parts: Vec<Vec<u8>>, // split on '*', lowercase when `ci`
    ci: bool,
}

impl Glob {
    fn new(pat: &str, ci: bool) -> Self {
        let f = |s: &str| if ci { s.to_ascii_lowercase().into_bytes() } else { s.as_bytes().to_vec() };
        Glob {
            parts: pat.split('*').map(f).collect(),
            ci,
        }
    }

    fn eq(&self, a: &[u8], b: &[u8]) -> bool {
        if self.ci { a.eq_ignore_ascii_case(b) } else { a == b }
    }

    fn find(&self, hay: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        if hay.len() < needle.len() {
            return None;
        }
        (0..=hay.len() - needle.len()).find(|&i| self.eq(&hay[i..i + needle.len()], needle))
    }

    fn is_match(&self, text: &str) -> bool {
        let t = text.as_bytes();
        let n = self.parts.len();
        if n == 1 {
            return self.eq(&self.parts[0], t);
        }
        let (first, last) = (&self.parts[0], &self.parts[n - 1]);
        if t.len() < first.len() + last.len() || !self.eq(&t[..first.len()], first) {
            return false;
        }
        let end = t.len() - last.len();
        if !self.eq(&t[end..], last) {
            return false;
        }
        let mut pos = first.len();
        for mid in &self.parts[1..n - 1] {
            match self.find(&t[pos..end], mid) {
                Some(i) => pos += i + mid.len(),
                None => return false,
            }
        }
        true
    }
}

#[derive(Debug, Clone)]
enum SchemeSpec {
    /// http or https
    Web,
    Exact(String),
}

#[derive(Debug, Clone)]
enum HostSpec {
    Any,
    Exact(String),
    Suffix(String),
    /// `name.tld`: `name` + any public suffix.
    Tld(Glob),
}

#[derive(Debug, Clone)]
enum PortSpec {
    Any,
    Exact(u16),
}

/// A compiled Chrome match pattern.
#[derive(Debug, Clone)]
pub struct MatchPattern {
    all_urls: bool,
    scheme: SchemeSpec,
    host: HostSpec,
    port: PortSpec,
    path: Glob,
}

impl MatchPattern {
    pub fn parse(p: &str) -> Result<Self, String> {
        let p = p.trim();
        if p == "<all_urls>" {
            return Ok(MatchPattern {
                all_urls: true,
                scheme: SchemeSpec::Web,
                host: HostSpec::Any,
                port: PortSpec::Any,
                path: Glob::new("*", false),
            });
        }
        let (scheme, rest) = p.split_once("://").ok_or("missing '://'")?;
        let scheme_l = scheme.to_ascii_lowercase();
        let scheme = match scheme_l.as_str() {
            "*" | "http*" => SchemeSpec::Web,
            s if !s.is_empty()
                && s.as_bytes()[0].is_ascii_alphabetic()
                && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"+-.".contains(&c)) =>
            {
                SchemeSpec::Exact(s.to_string())
            }
            _ => return Err(format!("invalid scheme '{scheme}'")),
        };
        let slash = rest.find('/').ok_or("missing path (a pattern must contain '/' after the host)")?;
        let (hostport, path) = rest.split_at(slash);
        let (host_s, port) = match hostport.rsplit_once(':') {
            Some((h, "*")) => (h, PortSpec::Any),
            Some((h, pt)) if !pt.is_empty() && pt.bytes().all(|c| c.is_ascii_digit()) => {
                (h, PortSpec::Exact(pt.parse().map_err(|_| "bad port")?))
            }
            Some((_, pt)) if !hostport.starts_with('[') => return Err(format!("bad port '{pt}'")),
            _ => (hostport, PortSpec::Any),
        };
        let host_l = host_s.to_ascii_lowercase();
        let host = if matches!(&scheme, SchemeSpec::Exact(s) if s == "file") {
            if !host_l.is_empty() {
                return Err("file patterns must have an empty host".into());
            }
            HostSpec::Any
        } else if host_l.is_empty() {
            return Err("empty host".into());
        } else if host_l == "*" {
            HostSpec::Any
        } else if let Some(sfx) = host_l.strip_prefix("*.") {
            if sfx.contains('*') || sfx.is_empty() {
                return Err("'*' is only allowed as the whole host or a leading '*.'".into());
            }
            if let Some(stem) = sfx.strip_suffix(".tld") {
                // `*.google.tld`
                HostSpec::Tld(Glob::new(&format!("*.{stem}"), true))
            } else {
                HostSpec::Suffix(sfx.to_string())
            }
        } else if host_l.contains('*') {
            return Err("'*' is only allowed as the whole host or a leading '*.'".into());
        } else if let Some(stem) = host_l.strip_suffix(".tld") {
            HostSpec::Tld(Glob::new(stem, true))
        } else {
            HostSpec::Exact(host_l)
        };
        Ok(MatchPattern {
            all_urls: false,
            scheme,
            host,
            port,
            path: Glob::new(path, false),
        })
    }

    pub fn is_match(&self, u: &UrlParts<'_>) -> bool {
        let scheme_ok = match &self.scheme {
            SchemeSpec::Web => u.scheme == "http" || u.scheme == "https",
            SchemeSpec::Exact(s) => {
                if self.all_urls {
                    false
                } else {
                    u.scheme.eq_ignore_ascii_case(s)
                }
            }
        } || (self.all_urls && matches!(u.scheme, "file" | "ftp"));
        if !scheme_ok {
            return false;
        }
        if let PortSpec::Exact(p) = self.port {
            if u.port.or_else(|| u.default_port()) != Some(p) {
                return false;
            }
        }
        let host_ok = match &self.host {
            HostSpec::Any => true,
            HostSpec::Exact(h) => u.host.eq_ignore_ascii_case(h),
            HostSpec::Suffix(s) => host_in_domain(u.host, s),
            HostSpec::Tld(g) => tld_match(g, u.host),
        };
        host_ok && self.path.is_match(u.path_query)
    }

    fn host_key(&self) -> HostKey {
        match &self.host {
            HostSpec::Exact(h) => HostKey::Exact(h.clone()),
            HostSpec::Suffix(s) => HostKey::Suffix(s.clone()),
            _ => HostKey::Any,
        }
    }
}

fn host_in_domain(host: &str, domain: &str) -> bool {
    let (h, d) = (host.as_bytes(), domain.as_bytes());
    h.eq_ignore_ascii_case(d) || (h.len() > d.len() && h[h.len() - d.len() - 1] == b'.' && h[h.len() - d.len()..].eq_ignore_ascii_case(d))
}

/// `stem_glob` + `.` + a public suffix == host.
fn tld_match(stem_glob: &Glob, host: &str) -> bool {
    let Some(sfx) = psl::suffix(host.as_bytes()) else {
        return false;
    };
    let n = sfx.as_bytes().len();
    if host.len() <= n + 1 || host.as_bytes()[host.len() - n - 1] != b'.' {
        return false;
    }
    stem_glob.is_match(&host[..host.len() - n - 1])
}

/// A compiled `@include`/`@exclude` rule.
#[derive(Debug, Clone)]
enum IncKind {
    All,
    Glob(Glob),
    /// scheme glob, host stem glob, path glob (`path` includes query)
    TldGlob { scheme: Glob, stem: Glob, path: Glob },
    Regex(Regex),
}

#[derive(Debug, Clone)]
pub struct IncludeRule {
    kind: IncKind,
    key: HostKey,
}

impl IncludeRule {
    pub fn parse(p: &str) -> Result<Self, String> {
        let p = p.trim();
        if p == "*" {
            return Ok(Self { kind: IncKind::All, key: HostKey::Any });
        }
        if p.len() >= 2 && p.starts_with('/') {
            if let Some(close) = p.rfind('/').filter(|&i| i > 0) {
                let (body, flags) = (&p[1..close], &p[close + 1..]);
                if flags.bytes().all(|c| c.is_ascii_alphabetic()) {
                    let mut b = RegexBuilder::new(body);
                    b.size_limit(1 << 20);
                    for f in flags.chars() {
                        match f {
                            'i' => {
                                b.case_insensitive(true);
                            }
                            'm' => {
                                b.multi_line(true);
                            }
                            's' => {
                                b.dot_matches_new_line(true);
                            }
                            _ => {}
                        }
                    }
                    let re = b.build().map_err(|e| format!("bad regex: {e}"))?;
                    return Ok(Self { kind: IncKind::Regex(re), key: HostKey::Any });
                }
            }
        }
        // Glob. Split `scheme://host/path` to bucket by host and to support `.tld`.
        if let Some((scheme, rest)) = p.split_once("://") {
            let hend = rest.find('/').unwrap_or(rest.len());
            let (hostport, path) = rest.split_at(hend);
            let host = match hostport.rsplit_once(':') {
                Some((h, port)) if port == "*" || port.bytes().all(|c| c.is_ascii_digit()) => h,
                _ => hostport,
            };
            let host_l = host.to_ascii_lowercase();
            if let Some(stem) = host_l.strip_suffix(".tld") {
                // Port-less comparison: `.tld` rules ignore the port.
                let path = if path.is_empty() { "/" } else { path };
                return Ok(Self {
                    kind: IncKind::TldGlob {
                        scheme: Glob::new(scheme, true),
                        stem: Glob::new(stem, true),
                        path: Glob::new(path, true),
                    },
                    key: HostKey::Any,
                });
            }
            let key = if host_l.is_empty() || host_l.contains('*') {
                match host_l.strip_prefix("*.") {
                    Some(r) if !r.is_empty() && !r.contains('*') => HostKey::Suffix(r.to_string()),
                    _ => HostKey::Any,
                }
            } else {
                HostKey::Exact(host_l)
            };
            return Ok(Self { kind: IncKind::Glob(Glob::new(p, true)), key });
        }
        Ok(Self { kind: IncKind::Glob(Glob::new(p, true)), key: HostKey::Any })
    }

    pub fn is_match(&self, u: &UrlParts<'_>) -> bool {
        match &self.kind {
            IncKind::All => true,
            IncKind::Glob(g) => g.is_match(u.full),
            IncKind::Regex(r) => r.is_match(u.full),
            IncKind::TldGlob { scheme, stem, path } => {
                scheme.is_match(u.scheme) && tld_match(stem, u.host) && path.is_match(u.path_query)
            }
        }
    }
}

/// One compiled rule of either kind.
#[derive(Debug, Clone)]
pub enum Matcher {
    Match(MatchPattern),
    Include(IncludeRule),
}

impl Matcher {
    pub fn is_match(&self, u: &UrlParts<'_>) -> bool {
        match self {
            Matcher::Match(m) => m.is_match(u),
            Matcher::Include(i) => i.is_match(u),
        }
    }
    pub fn host_key(&self) -> HostKey {
        match self {
            Matcher::Match(m) => m.host_key(),
            Matcher::Include(i) => i.key.clone(),
        }
    }
}

/// All URL rules of one script, compiled once.
#[derive(Debug, Clone)]
pub struct Rules {
    includes: Vec<Matcher>,
    excludes: Vec<Matcher>,
    /// No `@match`/`@include` were declared at all.
    declared_none: bool,
    match_all_without_rules: bool,
}

impl Rules {
    /// Compile; unparsable patterns are skipped and returned as messages.
    pub fn compile(meta: &UserscriptMetadata, opts: Options) -> (Self, Vec<String>) {
        let mut errs = Vec::new();
        let mut includes = Vec::new();
        let mut excludes = Vec::new();
        for m in &meta.matches {
            match MatchPattern::parse(m) {
                Ok(p) => includes.push(Matcher::Match(p)),
                Err(e) => errs.push(format!("@match {m}: {e}")),
            }
        }
        for m in &meta.includes {
            match IncludeRule::parse(m) {
                Ok(p) => includes.push(Matcher::Include(p)),
                Err(e) => errs.push(format!("@include {m}: {e}")),
            }
        }
        for m in &meta.excludes {
            match IncludeRule::parse(m) {
                Ok(p) => excludes.push(Matcher::Include(p)),
                Err(e) => errs.push(format!("@exclude {m}: {e}")),
            }
        }
        for m in &meta.exclude_matches {
            match MatchPattern::parse(m) {
                Ok(p) => excludes.push(Matcher::Match(p)),
                Err(e) => errs.push(format!("@exclude-match {m}: {e}")),
            }
        }
        let declared_none = meta.matches.is_empty() && meta.includes.is_empty();
        (
            Rules {
                includes,
                excludes,
                declared_none,
                match_all_without_rules: opts.match_all_without_rules,
            },
            errs,
        )
    }

    /// Host buckets of the include side; a single `Any` when rule-less and match-all.
    pub fn host_keys(&self) -> Vec<HostKey> {
        if self.declared_none {
            return if self.match_all_without_rules { vec![HostKey::Any] } else { vec![] };
        }
        let mut v: Vec<HostKey> = self.includes.iter().map(Matcher::host_key).collect();
        v.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
        v.dedup();
        v
    }

    pub fn is_match(&self, u: &UrlParts<'_>) -> bool {
        if self.excludes.iter().any(|e| e.is_match(u)) {
            return false;
        }
        if self.declared_none {
            return self.match_all_without_rules;
        }
        self.includes.iter().any(|i| i.is_match(u))
    }

    pub fn is_match_url(&self, url: &str) -> bool {
        UrlParts::parse(url).is_some_and(|u| self.is_match(&u))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mp(p: &str, url: &str) -> bool {
        MatchPattern::parse(p).unwrap().is_match(&UrlParts::parse(url).unwrap())
    }
    fn inc(p: &str, url: &str) -> bool {
        IncludeRule::parse(p).unwrap().is_match(&UrlParts::parse(url).unwrap())
    }

    #[test]
    fn chrome_match_pattern_table() {
        // (pattern, url, expected): from the Chrome match-pattern documentation.
        let t = [
            ("https://*/*", "https://www.google.com/", true),
            ("https://*/*", "http://www.google.com/", false),
            ("https://*/foo*", "https://example.org/foo/bar.html", true),
            ("https://*/foo*", "https://example.org/bar", false),
            ("https://*.google.com/foo*bar", "https://www.google.com/foo/baz/bar", true),
            ("https://*.google.com/foo*bar", "https://docs.google.com/foobar", true),
            ("https://*.google.com/foo*bar", "https://google.com/foobar", true),
            ("https://*.google.com/foo*bar", "https://evilgoogle.com/foobar", false),
            ("https://example.org/foo/bar.html", "https://example.org/foo/bar.html", true),
            ("https://example.org/foo/bar.html", "https://example.org/foo/bar.htm", false),
            ("http://127.0.0.1/*", "http://127.0.0.1/", true),
            ("http://127.0.0.1/*", "http://127.0.0.1/foo/bar.html", true),
            ("*://mail.google.com/*", "http://mail.google.com/foo/baz/bar", true),
            ("*://mail.google.com/*", "https://mail.google.com/foobar", true),
            ("*://mail.google.com/*", "ftp://mail.google.com/foobar", false),
            ("<all_urls>", "http://example.org/foo/bar.html", true),
            ("<all_urls>", "file:///bar/baz.html", true),
            ("<all_urls>", "ftp://example.org/x", true),
            ("<all_urls>", "chrome://settings/", false),
            ("file:///foo*", "file:///foo/bar.html", true),
            ("file:///foo*", "file:///bar", false),
            ("http://*/*", "https://a.com/", false),
            ("*://*/*", "https://a.com:8443/x?y=1", true),
            ("*://example.com/a?b=*", "https://example.com/a?b=3", true),
            ("*://example.com/a", "https://example.com/a?b=3", false),
            ("http://localhost:3000/*", "http://localhost:3000/x", true),
            ("http://localhost:3000/*", "http://localhost:4000/x", false),
            ("http://example.com/*", "http://example.com:8080/x", true),
            ("https://example.com:443/*", "https://example.com/x", true),
            ("*://*.example.com/*", "https://EXAMPLE.com/", true),
            ("*://*/*", "https://x.com/path#frag", true),
            ("*://x.com/path", "https://x.com/path#frag", true),
        ];
        for (p, u, want) in t {
            assert_eq!(mp(p, u), want, "{p} vs {u}");
        }
    }

    #[test]
    fn invalid_match_patterns() {
        for p in ["https://*foo/bar", "https://foo.*.org/bar", "https://example.com", "example.com/*", "https:///x", "file://host/x", "*://*.*/x", "://a/*"] {
            assert!(MatchPattern::parse(p).is_err(), "{p}");
        }
    }

    #[test]
    fn tld_in_match() {
        assert!(mp("*://google.tld/*", "https://google.com/x"));
        assert!(mp("*://google.tld/*", "https://google.co.uk/x"));
        assert!(!mp("*://google.tld/*", "https://www.google.com/x"));
        assert!(mp("*://*.google.tld/*", "https://www.google.co.uk/x"));
        assert!(!mp("*://google.tld/*", "https://google.evil.test.invalidtld.x/"));
    }

    #[test]
    fn greasemonkey_include_semantics() {
        assert!(inc("*", "https://anything.example/x"));
        assert!(inc("http://example.com/*", "http://example.com/a/b"));
        assert!(inc("HTTP://EXAMPLE.com/*", "http://example.com/a"));
        assert!(inc("http://example.com/Foo*", "http://example.com/foo1"));
        assert!(inc("*://*.example.com/*", "https://a.b.example.com/x"));
        assert!(!inc("*://*.example.com/*", "https://example.com/x"));
        assert!(inc("http*://example.com/*", "https://example.com/"));
        assert!(inc("*example.com*", "https://www.example.com/x"));
        assert!(inc("https://example.com/*/edit", "https://example.com/a/b/edit"));
        assert!(!inc("https://example.com/*/edit", "https://example.com/a/b/edit2"));
        assert!(inc("https://example.com/a.b", "https://example.com/a.b"));
        assert!(!inc("https://example.com/a.b", "https://example.com/aXb")); // '.' is literal
        assert!(inc("https://example.com/?q", "https://example.com/?q"));
        assert!(!inc("https://example.com/?q", "https://example.com/Xq")); // '?' is literal
    }

    #[test]
    fn regex_include() {
        assert!(inc(r"/^https?:\/\/(www\.)?foo\.com\/.*$/", "https://www.foo.com/x"));
        assert!(!inc(r"/^https?:\/\/(www\.)?foo\.com\/.*$/", "https://bar.com/x"));
        assert!(inc(r"/FOO\.com/i", "https://foo.com/"));
        assert!(!inc(r"/FOO\.com/", "https://foo.com/"));
        assert!(IncludeRule::parse("/(?<=a)b/").is_err()); // look-behind unsupported
    }

    #[test]
    fn tld_in_include() {
        assert!(inc("http://google.tld/*", "http://google.co.uk/search"));
        assert!(inc("*://*.google.tld/*", "https://www.google.com/"));
        assert!(!inc("http://google.tld/*", "https://google.com/"));
    }

    fn rules(src: &str) -> Rules {
        let m = UserscriptMetadata::parse(src).unwrap();
        let (r, e) = Rules::compile(&m, Options::default());
        assert!(e.is_empty(), "{e:?}");
        r
    }

    #[test]
    fn precedence_and_defaults() {
        let r = rules("// ==UserScript==\n// @name x\n// @match https://a.com/*\n// @include https://b.com/*\n// @exclude https://a.com/no*\n// @exclude-match https://b.com/x/*\n// ==/UserScript==");
        assert!(r.is_match_url("https://a.com/yes"));
        assert!(!r.is_match_url("https://a.com/nope"));
        assert!(r.is_match_url("https://b.com/y"));
        assert!(!r.is_match_url("https://b.com/x/z"));
        assert!(!r.is_match_url("https://c.com/"));
        let r = rules("// ==UserScript==\n// @name x\n// ==/UserScript==");
        assert!(r.is_match_url("https://anything/"));
        let m = UserscriptMetadata::parse("// ==UserScript==\n// @name x\n// ==/UserScript==").unwrap();
        let (r, _) = Rules::compile(&m, Options { match_all_without_rules: false });
        assert!(!r.is_match_url("https://anything/"));
        // Only invalid @match given: matches nothing, not everything.
        let m = UserscriptMetadata::parse("// ==UserScript==\n// @name x\n// @match bogus\n// ==/UserScript==").unwrap();
        let (r, e) = Rules::compile(&m, Options::default());
        assert_eq!(e.len(), 1);
        assert!(!r.is_match_url("https://a.com/"));
    }

    #[test]
    fn url_parts() {
        let u = UrlParts::parse("https://user:pw@[::1]:8080/a?b#c").unwrap();
        assert_eq!((u.host, u.port, u.path_query), ("::1", Some(8080), "/a?b"));
        let u = UrlParts::parse("http://h").unwrap();
        assert_eq!(u.path_query, "/");
        assert!(UrlParts::parse("nonsense").is_none());
    }
}

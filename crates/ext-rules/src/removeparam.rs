//! `$removeparam`: query-parameter removal (uBO / AdGuard semantics) for the forms the network
//! engine cannot express: regex, negated and bare. Untouched parameters keep their exact bytes
//! and order; the fragment is preserved.

use regex::{Regex, RegexBuilder};

/// Compiled-regex size cap (bytes) so a list cannot allocate unbounded automata.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

#[derive(Debug, Clone)]
enum Matcher {
    /// `$removeparam` with no value: drop the whole query.
    All,
    /// Plain parameter name (compared decoded, case-sensitive like uBO).
    Name(String),
    /// `/regex/[i]`, tested against `name=value`.
    Regex(Regex),
}

/// One parsed `$removeparam` modifier.
#[derive(Debug, Clone)]
pub struct RemoveParam {
    matcher: Matcher,
    /// `~`: keep only the matching parameters, remove the rest.
    negate: bool,
}

impl RemoveParam {
    /// Parse the modifier value (text after `removeparam=`; empty for the bare form).
    pub fn parse(v: &str) -> Result<Self, String> {
        if v.is_empty() {
            return Ok(Self {
                matcher: Matcher::All,
                negate: false,
            });
        }
        let (negate, body) = match v.strip_prefix('~') {
            Some(b) => (true, b),
            None => (false, v),
        };
        if body.is_empty() {
            return Err("`~` without a parameter".into());
        }
        // uBO: a regex is `/.../` or `/.../i`; anything else starting with `/` is a plain name.
        let (inner, icase) = match body.strip_suffix("/i") {
            Some(x) => (x, true),
            None => (body.strip_suffix('/').unwrap_or(body), false),
        };
        let is_re = body.len() > 2 && body.starts_with('/') && inner.len() < body.len();
        if is_re {
            let re = &inner[1..];
            if re.is_empty() {
                return Err("empty regex".into());
            }
            let re = RegexBuilder::new(re)
                .size_limit(REGEX_SIZE_LIMIT)
                .case_insensitive(icase)
                .build()
                .map_err(|e| format!("regex: {e}"))?;
            return Ok(Self {
                matcher: Matcher::Regex(re),
                negate,
            });
        }
        Ok(Self {
            matcher: Matcher::Name(body.to_string()),
            negate,
        })
    }

    fn hits(&self, seg: &str) -> bool {
        match &self.matcher {
            Matcher::All => true,
            Matcher::Name(n) => {
                let raw = seg.split_once('=').map_or(seg, |(k, _)| k);
                raw == n || decode(raw) == *n
            }
            Matcher::Regex(re) => re.is_match(seg) || re.is_match(&decode(seg)),
        }
    }

    /// Should `seg` (one `name=value` piece) be removed?
    fn removes(&self, seg: &str) -> bool {
        match self.matcher {
            Matcher::All => true,
            _ => self.hits(seg) != self.negate,
        }
    }
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// Split `url` into (before-query, query-without-`?`, fragment-with-`#`). `None` without a query.
fn split(url: &str) -> Option<(&str, &str, &str)> {
    let (head, frag) = match url.find('#') {
        Some(p) => url.split_at(p),
        None => (url, ""),
    };
    let q = head.find('?')?;
    Some((&head[..q], &head[q + 1..], frag))
}

/// Apply `specs` in order to the query of `url`. `None` when nothing was removed.
pub fn apply(url: &str, specs: &[&RemoveParam]) -> Option<String> {
    let (base, query, frag) = split(url)?;
    let mut segs: Vec<&str> = query.split('&').collect();
    let before = segs.len();
    for s in specs {
        segs.retain(|seg| !s.removes(seg));
    }
    if segs.len() == before {
        return None;
    }
    let mut out = String::with_capacity(url.len());
    out.push_str(base);
    if !segs.is_empty() {
        out.push('?');
        out.push_str(&segs.join("&"));
    }
    out.push_str(frag);
    (out != url).then_some(out)
}

/// Undo part of a plain-name removal: starting from `original`, remove only the parameters that
/// `rewritten` lacks, except those named in `keep` (all of them when `keep_all`).
pub fn restore_exempt(original: &str, rewritten: &str, keep: &[String], keep_all: bool) -> String {
    if keep_all {
        return original.to_string();
    }
    let (Some((base, q0, frag)), r) = (split(original), split(rewritten)) else {
        return rewritten.to_string();
    };
    let mut have: Vec<&str> = r
        .map(|(_, q, _)| q.split('&').collect())
        .unwrap_or_default();
    let name = |s: &str| decode(s.split_once('=').map_or(s, |(k, _)| k));
    let mut out: Vec<&str> = Vec::new();
    for seg in q0.split('&') {
        if let Some(p) = have.iter().position(|h| *h == seg) {
            have.remove(p);
            out.push(seg);
        } else if keep.iter().any(|k| *k == name(seg)) {
            out.push(seg);
        }
    }
    if out.is_empty() {
        format!("{base}{frag}")
    } else {
        format!("{base}?{}{frag}", out.join("&"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(rule: &[&str], url: &str) -> Option<String> {
        let specs: Vec<RemoveParam> = rule
            .iter()
            .map(|r| RemoveParam::parse(r).unwrap())
            .collect();
        apply(url, &specs.iter().collect::<Vec<_>>())
    }

    #[test]
    fn name_regex_negated_bare() {
        let u = "https://a.test/p?utm_a=1&keep=%20x&utm_b=2&z#frag";
        assert_eq!(
            run(&["utm_a"], u).unwrap(),
            "https://a.test/p?keep=%20x&utm_b=2&z#frag"
        );
        assert_eq!(
            run(&["/^utm_/"], u).unwrap(),
            "https://a.test/p?keep=%20x&z#frag"
        );
        assert_eq!(
            run(&["/^UTM_A=1$/i"], u).unwrap(),
            "https://a.test/p?keep=%20x&utm_b=2&z#frag"
        );
        assert_eq!(
            run(&["~keep"], u).unwrap(),
            "https://a.test/p?keep=%20x#frag"
        );
        assert_eq!(
            run(&["~/^utm_/"], u).unwrap(),
            "https://a.test/p?utm_a=1&utm_b=2#frag"
        );
        assert_eq!(run(&[""], u).unwrap(), "https://a.test/p#frag");
        assert_eq!(run(&["nope"], u), None);
        assert_eq!(run(&[""], "https://a.test/p"), None);
        // regex sees name=value, decoded too
        assert_eq!(
            run(&["/keep= x/"], u).unwrap(),
            "https://a.test/p?utm_a=1&utm_b=2&z#frag"
        );
    }

    #[test]
    fn parse_errors() {
        assert!(RemoveParam::parse("~").is_err());
        assert!(RemoveParam::parse("/(?=a)/").is_err());
        // Not `/.../[i]`: a plain name.
        assert!(matches!(
            RemoveParam::parse("/a/g").unwrap().matcher,
            Matcher::Name(_)
        ));
    }

    #[test]
    fn restore() {
        let o = "https://a.test/p?a=1&utm=2&b=3";
        assert_eq!(
            restore_exempt(o, "https://a.test/p?a=1&b=3", &["utm".into()], false),
            o
        );
        assert_eq!(restore_exempt(o, "https://a.test/p?a=1&b=3", &[], true), o);
        assert_eq!(
            restore_exempt(o, "https://a.test/p?b=3", &["a".into()], false),
            "https://a.test/p?a=1&b=3"
        );
    }
}

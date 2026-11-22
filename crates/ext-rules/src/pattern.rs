//! ABP URL pattern matching (`||`, `|`, `^`, `*`, `/regex/`) without allocation, plus the token
//! used to pre-filter candidates.
//!
//! Semantics follow the Adblock Plus filter docs ("Filter options" / "Wildcards and separators"):
//! `^` matches one separator character (anything but a letter, digit, `_`, `-`, `.`, `%`) or the
//! end of the address; `||` anchors at a hostname label start; `|` anchors at either end; matching
//! is case-insensitive unless `$match-case`.

use regex::{Regex, RegexBuilder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Anchor {
    None,
    Url,
    Host,
}

#[derive(Debug, Clone)]
enum Tok {
    Lit(Vec<u8>),
    Sep,
}

#[derive(Debug, Clone)]
pub(crate) enum Pattern {
    Any,
    Glob(Glob),
    Regex(Regex),
}

#[derive(Debug, Clone)]
pub(crate) struct Glob {
    anchor: Anchor,
    end: bool,
    lead_star: bool,
    trail_star: bool,
    segs: Vec<Vec<Tok>>,
    match_case: bool,
}

fn is_sep(c: u8) -> bool {
    !(c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'%'))
}

impl Pattern {
    pub fn parse(p: &str, match_case: bool) -> Result<Pattern, String> {
        if p.len() > 2 && p.starts_with('/') && p.ends_with('/') {
            let re = RegexBuilder::new(&p[1..p.len() - 1])
                .case_insensitive(!match_case)
                .size_limit(1 << 20)
                .build()
                .map_err(|e| format!("unsupported regex pattern: {e}"))?;
            return Ok(Pattern::Regex(re));
        }
        let (anchor, mut rest) = if let Some(r) = p.strip_prefix("||") {
            (Anchor::Host, r)
        } else if let Some(r) = p.strip_prefix('|') {
            (Anchor::Url, r)
        } else {
            (Anchor::None, p)
        };
        let end = !rest.is_empty() && rest.ends_with('|');
        if end {
            rest = &rest[..rest.len() - 1];
        }
        let raw_segs: Vec<&str> = rest.split('*').collect();
        let lead_star = raw_segs.first().is_some_and(|s| s.is_empty()) && raw_segs.len() > 1;
        let trail_star = raw_segs.last().is_some_and(|s| s.is_empty()) && raw_segs.len() > 1;
        let segs: Vec<Vec<Tok>> = raw_segs
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| {
                let mut toks = Vec::new();
                let mut lit = Vec::new();
                for c in s.bytes() {
                    if c == b'^' {
                        if !lit.is_empty() {
                            toks.push(Tok::Lit(std::mem::take(&mut lit)));
                        }
                        toks.push(Tok::Sep);
                    } else {
                        lit.push(if match_case {
                            c
                        } else {
                            c.to_ascii_lowercase()
                        });
                    }
                }
                if !lit.is_empty() {
                    toks.push(Tok::Lit(lit));
                }
                toks
            })
            .collect();
        if segs.is_empty() {
            return Ok(Pattern::Any);
        }
        if segs.len() > 16 {
            return Err("pattern has too many wildcards".into());
        }
        Ok(Pattern::Glob(Glob {
            anchor,
            end,
            lead_star,
            trail_star,
            segs,
            match_case,
        }))
    }

    /// Does the pattern match `url`? `host` is the host's byte range within `url`.
    pub fn matches(&self, url: &str, host: (usize, usize)) -> bool {
        match self {
            Pattern::Any => true,
            Pattern::Regex(r) => r.is_match(url),
            Pattern::Glob(g) => g.matches(url.as_bytes(), host),
        }
    }

    /// Literal host for `||host^...` / `||host/...` / `||host` patterns: the request must be on
    /// that host or a subdomain.
    pub fn host_key(&self) -> Option<String> {
        let Pattern::Glob(g) = self else { return None };
        if g.anchor != Anchor::Host || g.lead_star {
            return None;
        }
        let first = &g.segs[0];
        let Tok::Lit(l) = &first[0] else { return None };
        let end = l
            .iter()
            .position(|&c| matches!(c, b'/' | b':' | b'?'))
            .unwrap_or(l.len());
        let host = &l[..end];
        // The literal must be a complete host: followed by a terminator inside the pattern.
        let terminated = end < l.len()
            || matches!(first.get(1), Some(Tok::Sep))
            || (first.len() == 1 && g.segs.len() == 1 && !g.trail_star && g.end);
        if host.is_empty()
            || !terminated
            || !host
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
            || !host.contains(&b'.')
        {
            return None;
        }
        Some(String::from_utf8_lossy(host).into_owned())
    }

    /// Longest alphanumeric run (>= 3 bytes, lowercase) that must appear as a *whole* URL token.
    pub fn token(&self) -> Option<Vec<u8>> {
        let Pattern::Glob(g) = self else { return None };
        let mut best: Option<Vec<u8>> = None;
        let nseg = g.segs.len();
        for (si, seg) in g.segs.iter().enumerate() {
            for (ti, tok) in seg.iter().enumerate() {
                let Tok::Lit(l) = tok else { continue };
                let mut i = 0;
                while i < l.len() {
                    if !l[i].is_ascii_alphanumeric() {
                        i += 1;
                        continue;
                    }
                    let s = i;
                    while i < l.len() && l[i].is_ascii_alphanumeric() {
                        i += 1;
                    }
                    // bounded on the left: inside the literal, after a separator token, or at an anchor
                    let left = if s > 0 || ti > 0 {
                        true
                    } else if si == 0 {
                        g.anchor != Anchor::None && !g.lead_star
                    } else {
                        false
                    };
                    let right = if i < l.len() || ti + 1 < seg.len() {
                        true
                    } else if si + 1 == nseg {
                        g.end && !g.trail_star
                    } else {
                        false
                    };
                    if left && right && i - s >= 3 && best.as_ref().is_none_or(|b| i - s > b.len())
                    {
                        best = Some(l[s..i].to_ascii_lowercase());
                    }
                }
            }
        }
        best
    }
}

impl Glob {
    fn seg_at(&self, seg: &[Tok], u: &[u8], mut p: usize) -> Option<usize> {
        for t in seg {
            match t {
                Tok::Lit(l) => {
                    let e = p.checked_add(l.len())?;
                    if e > u.len() {
                        return None;
                    }
                    let ok = if self.match_case {
                        &u[p..e] == l.as_slice()
                    } else {
                        u[p..e]
                            .iter()
                            .zip(l)
                            .all(|(a, b)| a.to_ascii_lowercase() == *b)
                    };
                    if !ok {
                        return None;
                    }
                    p = e;
                }
                Tok::Sep => {
                    if p == u.len() {
                        // matches the end of the address (zero width)
                    } else if is_sep(u[p]) {
                        p += 1;
                    } else {
                        return None;
                    }
                }
            }
        }
        Some(p)
    }

    fn match_from(&self, u: &[u8], start: usize, free_first: bool) -> bool {
        let n = self.segs.len();
        let mut cur = start;
        for (i, seg) in self.segs.iter().enumerate() {
            let last = i + 1 == n;
            let need_end = last && self.end && !self.trail_star;
            if i == 0 && !free_first {
                match self.seg_at(seg, u, start) {
                    Some(e) if !need_end || e == u.len() => cur = e,
                    _ => return false,
                }
                continue;
            }
            let mut pos = cur;
            loop {
                if pos > u.len() {
                    return false;
                }
                if let Some(e) = self.seg_at(seg, u, pos) {
                    if !need_end || e == u.len() {
                        cur = e;
                        break;
                    }
                }
                pos += 1;
            }
        }
        true
    }

    fn matches(&self, u: &[u8], host: (usize, usize)) -> bool {
        let (hs, he) = host;
        match self.anchor {
            Anchor::None => self.match_from(u, 0, true),
            Anchor::Url => self.match_from(u, 0, self.lead_star),
            // `||*...`: free scan, but only from the start of the host.
            Anchor::Host if self.lead_star => self.match_from(u, hs, true),
            Anchor::Host => (hs..he.max(hs))
                .filter(|&i| i == hs || u[i - 1] == b'.')
                .any(|s| self.match_from(u, s, false)),
        }
    }
}

/// Visit every maximal alphanumeric run of `url` as a hash (ASCII-lowercased FNV-1a); runs shorter
/// than 3 bytes are skipped. Stops early when `f` returns `true`.
pub(crate) fn for_each_token(url: &str, mut f: impl FnMut(u64) -> bool) {
    let b = url.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        let s = i;
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        while i < b.len() && b[i].is_ascii_alphanumeric() {
            h = (h ^ b[i].to_ascii_lowercase() as u64).wrapping_mul(0x0100_0000_01b3);
            i += 1;
        }
        if i - s >= 3 && f(h) {
            return;
        }
    }
}

pub(crate) fn token_hash(t: &[u8]) -> u64 {
    t.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &c| {
        (h ^ c as u64).wrapping_mul(0x0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::host_range;

    fn m(p: &str, url: &str) -> bool {
        Pattern::parse(p, false)
            .unwrap()
            .matches(url, host_range(url).unwrap())
    }

    #[test]
    fn abp_semantics() {
        assert!(m("||example.com^", "https://example.com/"));
        assert!(m("||example.com^", "https://a.example.com:81/x"));
        assert!(!m("||example.com^", "https://badexample.com/"));
        assert!(!m("||example.com^", "https://evil.com/?u=example.com"));
        assert!(m("||example.com^", "https://example.com"));
        assert!(m("/ads/*.js|", "https://x.org/ads/a/b.js"));
        assert!(!m("/ads/*.js|", "https://x.org/ads/a/b.json"));
        assert!(m("|https://x.org/", "https://x.org/a"));
        assert!(!m("|http://x.org/", "https://x.org/a"));
        assert!(m("ads^banner", "https://x.org/ads/banner"));
        assert!(!m("ads^banner", "https://x.org/adsbanner"));
        assert!(m("BANNER", "https://x.org/banner"));
        assert!(m("*", "https://x.org/"));
        assert!(m("/banner\\d+\\.gif/", "https://x.org/banner12.gif"));
        assert!(!Pattern::parse("pop", true)
            .unwrap()
            .matches("https://x.org/POP", (8, 13)));
    }

    #[test]
    fn keys_and_tokens() {
        let p = Pattern::parse("||ads.example.com^", false).unwrap();
        assert_eq!(p.host_key().as_deref(), Some("ads.example.com"));
        let p = Pattern::parse("||ads.example.com/path", false).unwrap();
        assert_eq!(p.host_key().as_deref(), Some("ads.example.com"));
        assert!(Pattern::parse("||ads.example.", false)
            .unwrap()
            .host_key()
            .is_none());
        let p = Pattern::parse("/adserver/banner.", false).unwrap();
        assert_eq!(p.token().as_deref(), Some(&b"adserver"[..]));
        let p = Pattern::parse("adserv", false).unwrap();
        assert!(p.token().is_none());
    }
}

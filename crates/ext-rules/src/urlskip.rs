//! `$urlskip=`: extract the destination of a redirector / link-shim URL (uBO "Static filter
//! syntax", `urlskip=`). A value is a space-separated list of steps run over a current string
//! that starts as the request URL; the final string must be an absolute `http(s)` URL.
//!
//! Steps: `?name` (query parameter value), `&i` (name of the i-th query parameter, 1-based), `#`
//! (the hash), `/re/` (first capture group), `+https` (prepend `https://` unless a scheme is
//! there), `-base64`, `-safebase64`, `-uricomponent`, `-blocked` (flag: also apply to requests
//! that are blocked). An unsupported or failing step aborts: no redirection.

use regex::Regex;

use crate::util::{compile_slash_regex, host_range, split_items};

#[derive(Debug, Clone)]
enum Step {
    Query(String),
    ParamName(usize),
    Hash,
    Regex(Regex),
    PrependHttps,
    Base64,
    SafeBase64,
    UriComponent,
}

/// A parsed `$urlskip=` step list.
#[derive(Debug, Clone)]
pub struct UrlSkip {
    steps: Vec<Step>,
    /// `-blocked`: the rule also applies to requests that other rules block.
    pub allow_blocked: bool,
}

fn pct_decode(s: &str, plus: bool) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = s.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 3;
                continue;
            }
            b'+' if plus => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

fn base64_decode(s: &str, url_safe: bool) -> Option<String> {
    let mut acc = 0u32;
    let mut bits = 0;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' if (c == b'+') != url_safe => 62,
            b'/' | b'_' if (c == b'/') != url_safe => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `(name, value)` pairs of the query of `s` (everything after the first `?`, before `#`).
fn query_pairs(s: &str) -> Vec<(&str, &str)> {
    let q = s.split_once('?').map_or("", |(_, q)| q);
    let q = q.split('#').next().unwrap_or("");
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .collect()
}

impl UrlSkip {
    pub fn parse(v: &str) -> Result<Self, String> {
        let mut steps = Vec::new();
        let mut allow_blocked = false;
        for tok in split_items(v.trim(), ' ')
            .into_iter()
            .filter(|t| !t.is_empty())
        {
            if tok.starts_with('/') {
                steps.push(Step::Regex(compile_slash_regex(tok, false)?));
                continue;
            }
            let (head, rest) = tok.split_at(1);
            steps.push(match (head, rest) {
                ("?", n) if !n.is_empty() => Step::Query(n.to_string()),
                ("&", n) => Step::ParamName(
                    n.parse::<usize>()
                        .ok()
                        .filter(|&i| i > 0)
                        .ok_or_else(|| format!("bad urlskip step `{tok}`"))?,
                ),
                ("#", "") => Step::Hash,
                ("+", "https") => Step::PrependHttps,
                ("-", "base64") => Step::Base64,
                ("-", "safebase64") => Step::SafeBase64,
                ("-", "uricomponent") => Step::UriComponent,
                ("-", "blocked") => {
                    allow_blocked = true;
                    continue;
                }
                _ => return Err(format!("unsupported urlskip step `{tok}`")),
            });
        }
        if steps.is_empty() {
            return Err("urlskip needs at least one step".into());
        }
        Ok(Self {
            steps,
            allow_blocked,
        })
    }

    /// The destination URL extracted from `url`, or `None` when a step fails or the result is not
    /// an absolute `http(s)` URL different from `url`.
    pub fn apply(&self, url: &str) -> Option<String> {
        let mut cur = url.to_string();
        for st in &self.steps {
            cur = match st {
                Step::Query(n) => query_pairs(&cur)
                    .into_iter()
                    .find(|(k, _)| pct_decode(k, true).as_deref() == Some(n.as_str()))
                    .and_then(|(_, v)| pct_decode(v, true))?,
                Step::ParamName(i) => pct_decode(query_pairs(&cur).get(i - 1)?.0, true)?,
                Step::Hash => cur.split_once('#')?.1.to_string(),
                Step::Regex(r) => r.captures(&cur)?.get(1)?.as_str().to_string(),
                Step::PrependHttps => {
                    if cur.starts_with("http://") || cur.starts_with("https://") {
                        cur
                    } else {
                        format!("https://{cur}")
                    }
                }
                Step::Base64 => base64_decode(&cur, false)?,
                Step::SafeBase64 => base64_decode(&cur, true)?,
                Step::UriComponent => pct_decode(&cur, false)?,
            };
            if cur.is_empty() {
                return None;
            }
        }
        let ok = (cur.starts_with("https://") || cur.starts_with("http://"))
            && host_range(&cur).is_some()
            && !cur.bytes().any(|c| c <= b' ' || c == 0x7f)
            && cur != url;
        ok.then_some(cur)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skip(steps: &str, url: &str) -> Option<String> {
        UrlSkip::parse(steps).unwrap().apply(url)
    }

    #[test]
    fn real_rules() {
        assert_eq!(
            skip(
                "?url",
                "https://shortnest.com/st?url=https%3A%2F%2Fdest.example%2Fa%3Fb%3D1"
            ),
            Some("https://dest.example/a?b=1".into())
        );
        assert_eq!(
            skip(
                "?url -base64",
                "https://anylinks.in/full?url=aHR0cHM6Ly9kZXN0LmV4YW1wbGUv"
            ),
            Some("https://dest.example/".into())
        );
        assert_eq!(
            skip("?url +https", "https://pelistop.xyz/x?url=dest.example/p"),
            Some("https://dest.example/p".into())
        );
        assert_eq!(
            skip(
                r"/\/go\/\?(aHR0c.+)/ -base64",
                "https://meong.club/go/?aHR0cHM6Ly9kZXN0LmV4YW1wbGUv"
            ),
            Some("https://dest.example/".into())
        );
        assert_eq!(
            skip(
                "&1 -base64",
                "https://sonixgvn.net/dark/?aHR0cHM6Ly9kZXN0LmV4YW1wbGUv&x=1"
            ),
            Some("https://dest.example/".into())
        );
        assert_eq!(
            skip(
                r"/(traffic\.megaphone\.fm\/\w+\.mp3)/ +https",
                "https://traffic.megaphone.fm/ABC123.mp3?x=1"
            ),
            Some("https://traffic.megaphone.fm/ABC123.mp3".into())
        );
        assert_eq!(
            skip("#", "https://a.example/x#https://b.example/"),
            Some("https://b.example/".into())
        );
        assert_eq!(
            skip(
                "?u -safebase64",
                "https://a.example/?u=aHR0cHM6Ly9iLmV4YW1wbGUvPz4"
            ),
            Some("https://b.example/?>".into())
        );
        assert_eq!(
            skip(
                "?u -uricomponent",
                "https://a.example/?u=https%253A%252F%252Fb.example%252F"
            ),
            Some("https://b.example/".into())
        );
    }

    #[test]
    fn failures_abort() {
        assert_eq!(skip("?url", "https://a.example/x"), None);
        assert_eq!(skip("?url", "https://a.example/x?url=not-a-url"), None);
        assert_eq!(
            skip("?url", "https://a.example/x?url=javascript:alert(1)"),
            None
        );
        assert_eq!(skip("?url -base64", "https://a.example/x?url=%%%"), None);
        assert_eq!(skip("&3", "https://a.example/x?a&b"), None);
        assert!(UrlSkip::parse("?url -nope")
            .unwrap_err()
            .contains("unsupported"));
        assert!(UrlSkip::parse("/(?=x)/")
            .unwrap_err()
            .contains("unsupported"));
        assert!(UrlSkip::parse("").is_err());
        assert!(UrlSkip::parse("?u -blocked").unwrap().allow_blocked);
    }
}

//! `$replace=/regex/replacement/flags` and the shared `/re/repl/flags` value syntax
//! (`$urltransform` uses it too).
//!
//! Regexes run on the `regex` crate: matching is linear in the input (no catastrophic
//! backtracking), so no wall-clock budget is needed; compile size is capped. Look-around and
//! back-references are *not supported* (the engine rejects them) and are reported as an
//! unsupported-regex error at parse time: `fancy-regex` would reintroduce backtracking and every
//! `$replace` in the common lists is expressible without them.
//!
//! Semantics (AdGuard KB "$replace", uBO wiki "Static filter syntax: replace="): the rule matches
//! the request, the response body (text content types only, bounded size) has *every* match of the
//! regex substituted; flags `i`, `s`, `m` are honoured, `g` is implied. `$1`, `$&` references work
//! as in JavaScript. An empty `$replace` in an exception (`@@...$replace`) disables all replace
//! rules for the request; with a value it disables the rule with the identical value.

use std::borrow::Cow;

use regex::bytes::{Regex, RegexBuilder};

/// AdGuard documents a 3 MB limit for `$replace`; the same cap bounds every regex body rewrite.
pub const MAX_REPLACE_BYTES: usize = 3 * 1024 * 1024;

/// A parsed `/regex/replacement/flags` value.
#[derive(Debug, Clone)]
pub struct ReplaceSpec {
    /// The option value as written (used to pair exceptions with rules).
    pub value: String,
    re: Regex,
    replacement: Vec<u8>,
}

/// Split `/re/repl/flags` (escapes: `\/` is a slash, handled here; `\,` was handled earlier).
pub(crate) fn split_slash_value(v: &str) -> Result<(String, String, String), String> {
    let rest = v.strip_prefix('/').ok_or("value must start with `/`")?;
    let mut parts: Vec<String> = vec![String::new()];
    let mut it = rest.chars();
    while let Some(c) = it.next() {
        match c {
            '\\' => match it.next() {
                Some('/') => parts.last_mut().unwrap().push('/'),
                Some(n) => {
                    let p = parts.last_mut().unwrap();
                    p.push('\\');
                    p.push(n);
                }
                None => return Err("dangling escape".into()),
            },
            '/' if parts.len() < 3 => parts.push(String::new()),
            _ => parts.last_mut().unwrap().push(c),
        }
    }
    match parts.len() {
        // `/re/`: regex only, empty replacement
        2 if parts[1].is_empty() => Ok((parts.remove(0), String::new(), String::new())),
        3 => Ok((parts.remove(0), parts.remove(0), parts.remove(0))),
        _ => Err("expected /regex/replacement/flags".into()),
    }
}

/// Convert a JS-style replacement (`$1`, `$&`, `$$`, `\$`) into the `regex` crate's syntax.
fn convert_replacement(r: &str, groups: usize) -> String {
    let b: Vec<char> = r.chars().collect();
    let mut out = String::with_capacity(r.len() + 4);
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            '\\' if i + 1 < b.len() => {
                match b[i + 1] {
                    '$' => out.push_str("$$"),
                    c => out.push(c),
                }
                i += 2;
            }
            '$' if i + 1 < b.len() => {
                let n = b[i + 1];
                if n == '$' {
                    out.push_str("$$");
                    i += 2;
                } else if n == '&' {
                    out.push_str("${0}");
                    i += 2;
                } else if n.is_ascii_digit() {
                    let mut j = i + 1;
                    while j < b.len() && b[j].is_ascii_digit() && j < i + 3 {
                        j += 1;
                    }
                    let mut num: String = b[i + 1..j].iter().collect();
                    if num.len() == 2 && num.parse::<usize>().unwrap_or(99) >= groups {
                        num.pop();
                        j -= 1;
                    }
                    out.push_str(&format!("${{{num}}}"));
                    i = j;
                } else {
                    out.push_str("$$");
                    i += 1;
                }
            }
            '$' => {
                out.push_str("$$");
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

impl ReplaceSpec {
    pub fn parse(value: &str) -> Result<Self, String> {
        let (re_src, repl, flags) = split_slash_value(value)?;
        if re_src.is_empty() {
            return Err("empty regular expression".into());
        }
        let mut b = RegexBuilder::new(&re_src);
        b.size_limit(1 << 20).dfa_size_limit(4 << 20);
        for f in flags.chars() {
            match f {
                'i' => b.case_insensitive(true),
                's' => b.dot_matches_new_line(true),
                'm' => b.multi_line(true),
                'g' | 'u' => &mut b,
                other => return Err(format!("unknown regex flag `{other}`")),
            };
        }
        let re = b.build().map_err(|e| {
            format!("unsupported regex (look-around and back-references are not supported): {e}")
        })?;
        let replacement = convert_replacement(&repl, re.captures_len()).into_bytes();
        Ok(Self {
            value: value.to_string(),
            re,
            replacement,
        })
    }

    pub(crate) fn apply_str<'a>(&self, s: &'a str) -> Cow<'a, str> {
        match self
            .re
            .replace_all(s.as_bytes(), self.replacement.as_slice())
        {
            Cow::Borrowed(_) => Cow::Borrowed(s),
            Cow::Owned(v) => String::from_utf8(v)
                .map(Cow::Owned)
                .unwrap_or(Cow::Borrowed(s)),
        }
    }
}

/// Apply `spec` to a response body. Bodies over [`MAX_REPLACE_BYTES`] are returned untouched.
pub fn apply_replace<'a>(body: &'a [u8], spec: &ReplaceSpec) -> Cow<'a, [u8]> {
    if body.len() > MAX_REPLACE_BYTES {
        return Cow::Borrowed(body);
    }
    spec.re.replace_all(body, spec.replacement.as_slice())
}

/// Whether `$replace` may touch a response with this `Content-Type` (AdGuard KB: text content
/// only; binary bodies are never rewritten).
pub fn is_textual_content_type(ct: &str) -> bool {
    let mime = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    mime.starts_with("text/")
        || mime.ends_with("+json")
        || mime.ends_with("+xml")
        || matches!(
            mime.as_str(),
            "application/javascript"
                | "application/x-javascript"
                | "application/ecmascript"
                | "application/json"
                | "application/xml"
                | "application/xhtml+xml"
                | "application/x-mpegurl"
                | "application/vnd.apple.mpegurl"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(v: &str, body: &str) -> String {
        String::from_utf8(apply_replace(body.as_bytes(), &ReplaceSpec::parse(v).unwrap()).into())
            .unwrap()
    }

    #[test]
    fn substitutes() {
        assert_eq!(run("/ad(s?)/X$1/", "ad ads"), "X Xs");
        assert_eq!(run("/foo/BAR/i", "Foo foo"), "BAR BAR");
        assert_eq!(run(r"/a\/b/c\/d/", "a/b"), "c/d");
        assert_eq!(run(r"/x/\$1/", "x"), "$1");
        assert_eq!(
            run(
                "/(<VAST[\\s\\S]*?>)[\\s\\S]*<\\/VAST>/$1<\\/VAST>/i",
                "<VAST a>junk</VAST>"
            ),
            "<VAST a></VAST>"
        );
        assert_eq!(run("/zzz/", "azzzb"), "ab");
        assert_eq!(run("/b/[$&]/", "abc"), "a[b]c");
    }

    #[test]
    fn rejects() {
        assert!(ReplaceSpec::parse("/(?=a)/x/")
            .unwrap_err()
            .contains("look-around"));
        assert!(ReplaceSpec::parse("/a/b/q").is_err());
        assert!(ReplaceSpec::parse("nope").is_err());
        assert!(ReplaceSpec::parse("//x/").is_err());
    }

    #[test]
    fn caps_and_binary() {
        let big = vec![b'a'; MAX_REPLACE_BYTES + 1];
        let s = ReplaceSpec::parse("/a/b/").unwrap();
        assert!(matches!(apply_replace(&big, &s), Cow::Borrowed(_)));
        let bin = [0xff, b'a', 0xfe];
        assert_eq!(&*apply_replace(&bin, &s), &[0xff, b'b', 0xfe]);
        assert!(is_textual_content_type("text/html; charset=utf-8"));
        assert!(!is_textual_content_type("image/png"));
    }
}

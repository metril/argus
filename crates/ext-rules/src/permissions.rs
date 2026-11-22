//! `Permissions-Policy` dictionaries: parsing, and merging list-supplied members into the
//! site's own header without ever widening it.
//!
//! The header is a structured-field dictionary, and a later key overrides an earlier one, so
//! appending `camera=*` after the site's `camera=()` would loosen it. Instead the plan carries
//! ONE merged header: per feature the most restrictive of what the site sent and what the rules
//! ask for. Members from untrusted lists must be `feature=()` (the only always-restrictive
//! form); trusted lists may set any allowlist, which replaces the site's value.

/// An allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Allow {
    /// `()`: nobody.
    None,
    /// `*`: every origin.
    Any,
    /// `self` and/or quoted origins.
    List(Vec<String>),
}

impl Allow {
    fn parse(v: &str) -> Option<Self> {
        let v = v.split(';').next()?.trim();
        let inner = match v.strip_prefix('(') {
            Some(rest) => rest.strip_suffix(')')?,
            None if v.is_empty() => return None,
            None => v,
        };
        if inner.contains(['(', ')', ',']) {
            return None;
        }
        let mut items: Vec<String> = Vec::new();
        let mut rest = inner.trim();
        while !rest.is_empty() {
            let (tok, tail) = if let Some(q) = rest.strip_prefix('"') {
                let end = q.find('"')?;
                (format!("\"{}\"", &q[..end]), &q[end + 1..])
            } else {
                let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
                (rest[..end].to_string(), &rest[end..])
            };
            if !(tok.starts_with('"') || matches!(tok.as_str(), "*" | "self" | "src")) {
                return None;
            }
            items.push(tok);
            rest = tail.trim_start();
        }
        Some(match items.as_slice() {
            [] => Allow::None,
            [s] if s == "*" => Allow::Any,
            _ if items.iter().any(|i| i == "*") => Allow::Any,
            _ => Allow::List(items),
        })
    }

    fn render(&self) -> String {
        match self {
            Allow::None => "()".into(),
            Allow::Any => "*".into(),
            Allow::List(v) => format!("({})", v.join(" ")),
        }
    }

    fn intersect(&self, o: &Allow) -> Allow {
        match (self, o) {
            (Allow::None, _) | (_, Allow::None) => Allow::None,
            (Allow::Any, x) | (x, Allow::Any) => x.clone(),
            (Allow::List(a), Allow::List(b)) => {
                let c: Vec<String> = a.iter().filter(|x| b.contains(x)).cloned().collect();
                if c.is_empty() {
                    Allow::None
                } else {
                    Allow::List(c)
                }
            }
        }
    }
}

/// One `feature=allowlist` member; `raw` is its text as sent.
#[derive(Debug, Clone)]
struct Member {
    name: String,
    allow: Option<Allow>,
    raw: String,
}

fn valid_feature(n: &str) -> bool {
    !n.is_empty()
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'*')
}

/// Split on commas outside parentheses and quotes.
fn split_members(s: &str) -> Option<Vec<&str>> {
    let (mut depth, mut quoted, mut start) = (0i32, false, 0usize);
    let mut out = Vec::new();
    for (i, c) in s.char_indices() {
        match c {
            '"' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            ',' if !quoted && depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 || quoted {
        return None;
    }
    out.push(&s[start..]);
    Some(out)
}

fn parse_members(s: &str, strict: bool) -> Option<Vec<Member>> {
    let mut out = Vec::new();
    for m in split_members(s)? {
        let m = m.trim();
        if m.is_empty() {
            if strict {
                return None;
            }
            continue;
        }
        let parsed = m.split_once('=').and_then(|(n, v)| {
            let n = n.trim();
            valid_feature(n).then(|| (n.to_string(), Allow::parse(v)))
        });
        match parsed {
            Some((name, allow)) if allow.is_some() || !strict => out.push(Member {
                name,
                allow,
                raw: m.to_string(),
            }),
            _ if strict => return None,
            // A site member we do not understand is kept as sent, under its own name if any.
            _ => out.push(Member {
                name: m.split('=').next().unwrap_or(m).trim().to_string(),
                allow: None,
                raw: m.to_string(),
            }),
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Is `value` a well-formed `Permissions-Policy` dictionary?
pub fn is_valid(value: &str) -> bool {
    parse_members(value, true).is_some()
}

/// Whether every member of `value` is `feature=()` (honoured from any list).
pub fn is_restrictive(value: &str) -> bool {
    parse_members(value, true)
        .is_some_and(|m| m.iter().all(|m| m.allow.as_ref() == Some(&Allow::None)))
}

/// The single header to send: the site's header lines combined (a later key wins, as in the
/// browser), then each restriction intersected in, then each trusted member set outright.
pub fn merge(site_lines: &[&str], restrictions: &[&str], trusted: &[&str]) -> String {
    let mut members: Vec<Member> = Vec::new();
    let put = |m: Member, members: &mut Vec<Member>| match members
        .iter_mut()
        .find(|x| x.name == m.name)
    {
        Some(x) => *x = m,
        None => members.push(m),
    };
    for line in site_lines {
        for m in parse_members(line, false).unwrap_or_default() {
            put(m, &mut members);
        }
    }
    for v in restrictions {
        for r in parse_members(v, true).unwrap_or_default() {
            let Some(ra) = r.allow.clone() else { continue };
            match members.iter_mut().find(|x| x.name == r.name) {
                Some(x) => match &x.allow {
                    Some(sa) => {
                        let m = sa.intersect(&ra);
                        if &m != sa {
                            x.raw = format!("{}={}", x.name, m.render());
                            x.allow = Some(m);
                        }
                    }
                    // Site value we cannot read: the restriction wins.
                    None => {
                        x.raw = format!("{}={}", x.name, ra.render());
                        x.allow = Some(ra);
                    }
                },
                None => members.push(r),
            }
        }
    }
    for v in trusted {
        for t in parse_members(v, true).unwrap_or_default() {
            put(t, &mut members);
        }
    }
    members
        .iter()
        .map(|m| m.raw.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity() {
        assert!(is_valid("camera=(), geolocation=(self \"https://a.test\")"));
        assert!(is_valid("fullscreen=*"));
        assert!(!is_valid("camera"));
        assert!(!is_valid("camera=("));
        assert!(!is_valid("Camera=()"));
        assert!(!is_valid(""));
        assert!(!is_valid("camera=(),"));
        assert!(is_restrictive("camera=(), microphone=()"));
        assert!(!is_restrictive("camera=(), microphone=self"));
        assert!(!is_restrictive("camera=*"));
        assert!(!is_restrictive("camera=( )x"));
    }

    #[test]
    fn merge_is_most_restrictive() {
        assert_eq!(merge(&["camera=*"], &["camera=()"], &[]), "camera=()");
        assert_eq!(merge(&["camera=()"], &["camera=()"], &[]), "camera=()");
        assert_eq!(
            merge(&["a=self, b=(self \"https://x.test\")"], &["b=()"], &[]),
            "a=self, b=()"
        );
        assert_eq!(merge(&[], &["camera=()"], &[]), "camera=()");
        // later duplicate key in the site's own header wins, as in the browser
        assert_eq!(merge(&["camera=(), camera=self"], &[], &[]), "camera=self");
        assert_eq!(merge(&["camera=()"], &[], &["camera=*"]), "camera=*");
    }
}

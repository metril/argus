//! `$cookie` (AdGuard KB "$cookie"): remove cookies, or rewrite `Set-Cookie` attributes.
//!
//! * `$cookie` (empty value) matches every cookie; `$cookie=name` an exact name; `$cookie=/re/i`
//!   a regular expression on the name.
//! * Without `maxAge` / `sameSite` the matched cookies are *removed*: dropped from the request
//!   `Cookie` header and from response `Set-Cookie` headers.
//! * With `;maxAge=<seconds>` and/or `;sameSite=<none|lax|strict>` matched response cookies are
//!   *modified* instead (`Max-Age` set and `Expires` dropped; `SameSite` replaced). Modifying
//!   rules do not touch the request.
//! * `@@...$cookie[=value]` exceptions disable all cookie rules / the rule with the same value.

use regex::{Regex, RegexBuilder};

#[derive(Debug, Clone)]
pub enum CookieName {
    Any,
    Exact(String),
    Regex(Regex),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    None,
    Lax,
    Strict,
}

impl SameSite {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Lax => "Lax",
            Self::Strict => "Strict",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CookieSpec {
    /// The option value as written.
    pub value: String,
    pub name: CookieName,
    pub max_age: Option<u64>,
    pub same_site: Option<SameSite>,
}

impl CookieSpec {
    pub fn parse(value: &str) -> Result<Self, String> {
        let mut parts = value.split(';');
        let head = parts.next().unwrap_or("").trim();
        let name = if head.is_empty() {
            CookieName::Any
        } else if let Some(r) = head
            .strip_prefix('/')
            .and_then(|r| r.rfind('/').map(|i| (&r[..i], &r[i + 1..])))
        {
            let mut b = RegexBuilder::new(r.0);
            b.size_limit(1 << 20).case_insensitive(r.1.contains('i'));
            CookieName::Regex(b.build().map_err(|e| format!("unsupported regex: {e}"))?)
        } else {
            CookieName::Exact(head.to_string())
        };
        let (mut max_age, mut same_site) = (None, None);
        for p in parts {
            let (k, v) = p.split_once('=').ok_or("expected key=value after `;`")?;
            match k.trim().to_ascii_lowercase().as_str() {
                "maxage" => max_age = Some(v.trim().parse::<u64>().map_err(|_| "bad maxAge")?),
                "samesite" => {
                    same_site = Some(match v.trim().to_ascii_lowercase().as_str() {
                        "none" => SameSite::None,
                        "lax" => SameSite::Lax,
                        "strict" => SameSite::Strict,
                        _ => return Err("bad sameSite".into()),
                    })
                }
                other => return Err(format!("unsupported cookie option `{other}`")),
            }
        }
        Ok(Self {
            value: value.to_string(),
            name,
            max_age,
            same_site,
        })
    }

    pub fn modifies(&self) -> bool {
        self.max_age.is_some() || self.same_site.is_some()
    }

    pub fn matches_name(&self, n: &str) -> bool {
        match &self.name {
            CookieName::Any => true,
            CookieName::Exact(e) => e == n,
            CookieName::Regex(r) => r.is_match(n),
        }
    }
}

/// Drop cookies matched by removing specs from a `Cookie` request header. `None` = unchanged;
/// `Some("")` = every cookie removed (drop the header).
pub fn filter_request_cookie(header: &str, specs: &[&CookieSpec]) -> Option<String> {
    let mut changed = false;
    let kept: Vec<&str> = header
        .split(';')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .filter(|c| {
            let name = c.split_once('=').map_or(*c, |x| x.0).trim();
            let drop = specs.iter().any(|s| !s.modifies() && s.matches_name(name));
            changed |= drop;
            !drop
        })
        .collect();
    changed.then(|| kept.join("; "))
}

#[derive(Debug, PartialEq, Eq)]
pub enum SetCookie {
    Keep,
    Remove,
    Replace(String),
}

/// Apply specs to one `Set-Cookie` header value.
pub fn apply_set_cookie(line: &str, specs: &[&CookieSpec]) -> SetCookie {
    let mut parts = line.split(';');
    let first = parts.next().unwrap_or("");
    let name = first.split_once('=').map_or(first, |x| x.0).trim();
    let mut max_age = None;
    let mut same_site = None;
    for s in specs.iter().filter(|s| s.matches_name(name)) {
        if !s.modifies() {
            return SetCookie::Remove;
        }
        max_age = s.max_age.or(max_age);
        same_site = s.same_site.or(same_site);
    }
    if max_age.is_none() && same_site.is_none() {
        return SetCookie::Keep;
    }
    let mut out = String::from(first.trim_end());
    for attr in parts {
        let key = attr
            .split_once('=')
            .map_or(attr, |x| x.0)
            .trim()
            .to_ascii_lowercase();
        let skip = (max_age.is_some() && (key == "max-age" || key == "expires"))
            || (same_site.is_some() && key == "samesite");
        if !skip && !attr.trim().is_empty() {
            out.push_str("; ");
            out.push_str(attr.trim());
        }
    }
    if let Some(m) = max_age {
        out.push_str(&format!("; Max-Age={m}"));
    }
    if let Some(s) = same_site {
        out.push_str(&format!("; SameSite={}", s.as_str()));
    }
    SetCookie::Replace(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_response() {
        let any = CookieSpec::parse("").unwrap();
        assert_eq!(
            filter_request_cookie("a=1; b=2", &[&any]).as_deref(),
            Some("")
        );
        let b = CookieSpec::parse("b").unwrap();
        assert_eq!(
            filter_request_cookie("a=1; b=2", &[&b]).as_deref(),
            Some("a=1")
        );
        assert_eq!(filter_request_cookie("a=1", &[&b]), None);
        let re = CookieSpec::parse("/^_ga/i").unwrap();
        assert_eq!(
            filter_request_cookie("_GA=1; x=2", &[&re]).as_deref(),
            Some("x=2")
        );
        assert_eq!(apply_set_cookie("b=2; Path=/", &[&b]), SetCookie::Remove);
        assert_eq!(apply_set_cookie("c=2; Path=/", &[&b]), SetCookie::Keep);
        let m = CookieSpec::parse("c;maxAge=3600;sameSite=lax").unwrap();
        assert_eq!(
            apply_set_cookie(
                "c=2; Path=/; Expires=Wed, 21 Oct 2099 07:28:00 GMT; SameSite=None; Secure",
                &[&m]
            ),
            SetCookie::Replace("c=2; Path=/; Secure; Max-Age=3600; SameSite=Lax".into())
        );
        assert_eq!(filter_request_cookie("c=1", &[&m]), None);
        assert!(CookieSpec::parse("a;sameSite=x").is_err());
        assert!(CookieSpec::parse("a;foo=1").is_err());
    }
}

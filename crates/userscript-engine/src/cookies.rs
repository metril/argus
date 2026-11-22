//! Per-(profile, script) cookie jar behind `GM_cookie` and `GM_xmlhttpRequest` (non-anonymous requests).
//!
//! A proxy cannot see the browser's cookie store, so this is a separate jar that scripts fill
//! (`GM_cookie.set`, `Set-Cookie` on their own requests) and read back. It is in memory, bounded
//! in size and lost on restart.

use crate::backend::{Cookie, CookieJar};
use cookie_store::{CookieStore, RawCookie};
use parking_lot::Mutex;
use std::collections::HashMap;
use url::Url;

/// Most cookies kept per profile; further `set`s are refused.
pub const MAX_COOKIES: usize = 4000;

/// A `Domain=` attribute that is a public suffix (including an unlisted single-label TLD such as
/// `lan`, which browsers treat as one) is refused unless it is exactly the request host.
/// `cookie_store` ships without a suffix list, so this is checked here with `psl`.
fn domain_attr_ok(url: &Url, domain: &str) -> bool {
    let d = domain.trim_start_matches('.').to_ascii_lowercase();
    if url.host_str().is_some_and(|h| h.eq_ignore_ascii_case(&d)) {
        return true;
    }
    d.contains('.')
        && psl::domain(d.as_bytes()).is_some_and(|reg| reg.as_bytes().len() <= d.len())
        && psl::suffix(d.as_bytes()).is_some_and(|sfx| sfx.as_bytes() != d.as_bytes())
}

/// One jar per (profile, script): a script never sees cookies another script obtained.
fn key(profile: &str, script: &str) -> String {
    format!("{profile}\u{0}{script}")
}

#[derive(Default)]
pub struct GmCookieJar {
    stores: Mutex<HashMap<String, CookieStore>>,
}

impl GmCookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    /// `Cookie` request-header value for `url` (None when nothing matches).
    pub fn header_for(&self, profile: &str, script: &str, url: &Url) -> Option<String> {
        let stores = self.stores.lock();
        let s = stores.get(&key(profile, script))?;
        let v: Vec<String> = s
            .get_request_values(url)
            .map(|(n, v)| format!("{n}={v}"))
            .collect();
        (!v.is_empty()).then(|| v.join("; "))
    }

    /// Store the `Set-Cookie` values of a response from `url`.
    pub fn store_response<'a>(
        &self,
        profile: &str,
        script: &str,
        url: &Url,
        set_cookies: impl Iterator<Item = &'a str>,
    ) {
        let mut stores = self.stores.lock();
        let s = stores.entry(key(profile, script)).or_default();
        for c in set_cookies {
            if s.iter_any().count() >= MAX_COOKIES {
                break;
            }
            if let Ok(r) = RawCookie::parse(c) {
                let bad_domain = r.domain().is_some_and(|d| !domain_attr_ok(url, d));
                let insecure = r.secure() == Some(true) && url.scheme() != "https";
                if bad_domain || insecure {
                    continue;
                }
            }
            let _ = s.parse(c, url);
        }
    }
}

impl CookieJar for GmCookieJar {
    fn list(&self, profile: &str, script: &str, url: &Url, name: Option<&str>) -> Vec<Cookie> {
        let stores = self.stores.lock();
        let Some(s) = stores.get(&key(profile, script)) else {
            return Vec::new();
        };
        s.matches(url)
            .into_iter()
            .filter(|c| name.is_none_or(|n| c.name() == n))
            .map(|c| Cookie {
                name: c.name().to_string(),
                value: c.value().to_string(),
                domain: c.domain().map(str::to_string),
                path: c.path().map(str::to_string),
                secure: c.secure().unwrap_or(false),
                http_only: c.http_only().unwrap_or(false),
                same_site: c.same_site().map(|s| s.to_string()),
                expiration_date: c.expires_datetime().map(|t| t.unix_timestamp()),
            })
            .collect()
    }

    fn set(&self, profile: &str, script: &str, url: &Url, cookie: Cookie) -> Result<(), String> {
        if cookie.secure && url.scheme() != "https" {
            return Err("a Secure cookie can only be set from an https URL".into());
        }
        let mut raw = RawCookie::new(cookie.name, cookie.value);
        if let Some(d) = cookie.domain {
            if !domain_attr_ok(url, &d) {
                return Err("cookie domain is not allowed".into());
            }
            raw.set_domain(d);
        }
        raw.set_path(cookie.path.unwrap_or_else(|| "/".into()));
        raw.set_secure(cookie.secure);
        raw.set_http_only(cookie.http_only);
        if let Some(ss) = cookie.same_site.as_deref() {
            raw.set_same_site(match ss.to_ascii_lowercase().as_str() {
                "strict" => Some(cookie::SameSite::Strict),
                "lax" => Some(cookie::SameSite::Lax),
                "none" | "no_restriction" => Some(cookie::SameSite::None),
                _ => None,
            });
        }
        if let Some(t) = cookie.expiration_date {
            if let Ok(dt) = time::OffsetDateTime::from_unix_timestamp(t) {
                raw.set_expires(dt);
            }
        }
        let mut stores = self.stores.lock();
        let s = stores.entry(key(profile, script)).or_default();
        if s.iter_any().count() >= MAX_COOKIES {
            return Err("cookie jar is full".into());
        }
        s.insert_raw(&raw, url)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn delete(&self, profile: &str, script: &str, url: &Url, name: &str) -> Result<(), String> {
        let mut stores = self.stores.lock();
        if let Some(s) = stores.get_mut(&key(profile, script)) {
            let doomed: Vec<(String, String)> = s
                .matches(url)
                .into_iter()
                .filter(|c| c.name() == name)
                .map(|c| {
                    (
                        c.domain()
                            .or(url.host_str())
                            .unwrap_or_default()
                            .to_string(),
                        c.path().unwrap_or("/").to_string(),
                    )
                })
                .collect();
            for (d, p) in doomed {
                s.remove(&d, &p, name);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_cookie_roundtrip_is_scoped_by_profile_and_host() {
        let j = GmCookieJar::new();
        let u = Url::parse("https://a.test/x").unwrap();
        j.store_response(
            "p",
            "s",
            &u,
            ["sid=1; Path=/".to_string()].iter().map(|s| s.as_str()),
        );
        assert_eq!(j.header_for("p", "s", &u).as_deref(), Some("sid=1"));
        assert!(j.header_for("q", "s", &u).is_none());
        assert!(j
            .header_for("p", "s", &Url::parse("https://b.test/").unwrap())
            .is_none());
        assert_eq!(j.list("p", "s", &u, Some("sid")).len(), 1);
        j.delete("p", "s", &u, "sid").unwrap();
        assert!(j.header_for("p", "s", &u).is_none());
    }

    #[test]
    fn explicit_set_and_list() {
        let j = GmCookieJar::new();
        let u = Url::parse("https://a.test/").unwrap();
        j.set(
            "p",
            "s",
            &u,
            Cookie {
                name: "k".into(),
                value: "v".into(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(j.list("p", "s", &u, None)[0].value, "v");
    }

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }
    fn store(j: &GmCookieJar, url: &str, sc: &str) {
        j.store_response("p", "s", &u(url), [sc].into_iter());
    }
    fn sees(j: &GmCookieJar, url: &str) -> bool {
        j.header_for("p", "s", &u(url)).is_some()
    }

    #[test]
    fn rfc6265_domain_path_secure_and_host_only() {
        let j = GmCookieJar::new();
        // host-only: not sent to subdomains
        store(&j, "https://a.test/", "h=1; Path=/");
        assert!(sees(&j, "https://a.test/"));
        assert!(!sees(&j, "https://sub.a.test/"));
        // Domain= applies to subdomains, and is refused for a foreign domain
        let j = GmCookieJar::new();
        store(&j, "https://a.test/", "d=1; Domain=a.test; Path=/");
        assert!(sees(&j, "https://sub.a.test/"));
        assert!(!sees(&j, "https://nota.test/"));
        let j = GmCookieJar::new();
        store(&j, "https://a.test/", "x=1; Domain=b.test");
        assert!(!sees(&j, "https://b.test/") && !sees(&j, "https://a.test/"));
        // a subdomain cannot set for a sibling
        store(&j, "https://one.a.test/", "y=1; Domain=two.a.test");
        assert!(!sees(&j, "https://two.a.test/"));
        // public suffixes are refused for Domain=
        for sfx in ["test", "com", "co.uk"] {
            let j = GmCookieJar::new();
            let host = format!("https://a.{sfx}/");
            store(&j, &host, &format!("s=1; Domain={sfx}"));
            assert!(!sees(&j, &format!("https://b.{sfx}/")), "{sfx}");
        }
        // path-match: /foo matches /foo and /foo/bar, not /foobar
        let j = GmCookieJar::new();
        store(&j, "https://a.test/foo/x", "p=1; Path=/foo");
        assert!(sees(&j, "https://a.test/foo"));
        assert!(sees(&j, "https://a.test/foo/bar"));
        assert!(!sees(&j, "https://a.test/foobar"));
        assert!(!sees(&j, "https://a.test/"));
        // Secure only over https, and not set from plain http
        let j = GmCookieJar::new();
        store(&j, "https://a.test/", "t=1; Secure; Path=/");
        assert!(sees(&j, "https://a.test/"));
        assert!(!sees(&j, "http://a.test/"), "Secure cookie sent over http");
        let j = GmCookieJar::new();
        store(&j, "http://a.test/", "t=1; Secure; Path=/");
        assert!(
            !sees(&j, "https://a.test/"),
            "Secure cookie accepted from http"
        );
        // expired cookies are not sent
        let j = GmCookieJar::new();
        store(&j, "https://a.test/", "e=1; Max-Age=0");
        assert!(!sees(&j, "https://a.test/"));
    }

    #[test]
    fn explicit_set_cannot_widen_scope() {
        let j = GmCookieJar::new();
        let c = |d: &str| Cookie {
            name: "k".into(),
            value: "v".into(),
            domain: Some(d.into()),
            ..Default::default()
        };
        assert!(j.set("p", "s", &u("https://a.test/"), c("b.test")).is_err());
        assert!(j.set("p", "s", &u("https://a.test/"), c("test")).is_err());
        assert!(j.set("p", "s", &u("https://a.test/"), c("a.test")).is_ok());
    }
}

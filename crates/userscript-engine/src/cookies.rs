//! Per-profile cookie jar behind `GM_cookie` and `GM_xmlhttpRequest` (non-anonymous requests).
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

#[derive(Default)]
pub struct GmCookieJar {
    stores: Mutex<HashMap<String, CookieStore>>,
}

impl GmCookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    /// `Cookie` request-header value for `url` (None when nothing matches).
    pub fn header_for(&self, profile: &str, url: &Url) -> Option<String> {
        let stores = self.stores.lock();
        let s = stores.get(profile)?;
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
        url: &Url,
        set_cookies: impl Iterator<Item = &'a str>,
    ) {
        let mut stores = self.stores.lock();
        let s = stores.entry(profile.to_string()).or_default();
        for c in set_cookies {
            if s.iter_any().count() >= MAX_COOKIES {
                break;
            }
            let _ = s.parse(c, url);
        }
    }
}

impl CookieJar for GmCookieJar {
    fn list(&self, profile: &str, url: &Url, name: Option<&str>) -> Vec<Cookie> {
        let stores = self.stores.lock();
        let Some(s) = stores.get(profile) else {
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

    fn set(&self, profile: &str, url: &Url, cookie: Cookie) -> Result<(), String> {
        let mut raw = RawCookie::new(cookie.name, cookie.value);
        if let Some(d) = cookie.domain {
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
        let s = stores.entry(profile.to_string()).or_default();
        if s.iter_any().count() >= MAX_COOKIES {
            return Err("cookie jar is full".into());
        }
        s.insert_raw(&raw, url)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn delete(&self, profile: &str, url: &Url, name: &str) -> Result<(), String> {
        let mut stores = self.stores.lock();
        if let Some(s) = stores.get_mut(profile) {
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
            &u,
            ["sid=1; Path=/".to_string()].iter().map(|s| s.as_str()),
        );
        assert_eq!(j.header_for("p", &u).as_deref(), Some("sid=1"));
        assert!(j.header_for("q", &u).is_none());
        assert!(j
            .header_for("p", &Url::parse("https://b.test/").unwrap())
            .is_none());
        assert_eq!(j.list("p", &u, Some("sid")).len(), 1);
        j.delete("p", &u, "sid").unwrap();
        assert!(j.header_for("p", &u).is_none());
    }

    #[test]
    fn explicit_set_and_list() {
        let j = GmCookieJar::new();
        let u = Url::parse("https://a.test/").unwrap();
        j.set(
            "p",
            &u,
            Cookie {
                name: "k".into(),
                value: "v".into(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(j.list("p", &u, None)[0].value, "v");
    }
}

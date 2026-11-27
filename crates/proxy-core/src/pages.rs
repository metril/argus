//! Which page a request belongs to when its own headers do not say.
//!
//! Browsers spread one page over many connections, so the state is per *device* (the key
//! `RequestCtx::device` already carries). One bounded, expiring map: stylesheet URL -> the
//! document that loaded it (transitively through `@import`), so a font or image fetched by CSS
//! (`Referer` = the stylesheet) resolves to the page. The first mapping of a sheet wins, and
//! only mappings learned from a document `Referer` or an already-known sheet are recorded.
//! URLs are truncated to [`MAX_URL`] bytes, which bounds memory.

use crate::request_type::RequestType;
use hyper::header::{HeaderMap, REFERER};
use std::time::Duration;

const TTL: Duration = Duration::from_secs(30 * 60);
/// Longest URL kept (keys and values are cut to it).
const MAX_URL: usize = 2048;

pub struct PageTracker {
    sheets: moka::sync::Cache<String, String>,
}

impl Default for PageTracker {
    fn default() -> Self {
        Self {
            sheets: moka::sync::Cache::builder()
                .max_capacity(16_384)
                .time_to_idle(TTL)
                .build(),
        }
    }
}

fn cut(s: &str) -> &str {
    let mut n = s.len().min(MAX_URL);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
}

fn key(dev: &str, url: &str) -> String {
    let url = url.split('#').next().unwrap_or(url);
    format!("{dev}\0{}", cut(url))
}

impl PageTracker {
    /// Record a stylesheet request and return the page a request resolves to when its
    /// `Referer` names a known stylesheet (`None`: the headers alone decide).
    pub fn hint(
        &self,
        dev: &str,
        headers: &HeaderMap,
        url: &str,
        ty: RequestType,
    ) -> Option<String> {
        if ty == RequestType::Document {
            return None;
        }
        let referer = headers
            .get(REFERER)
            .and_then(|v| v.to_str().ok())
            .filter(|r| !r.is_empty());
        let hint = referer.and_then(|r| self.sheets.get(&key(dev, r)));
        if ty == RequestType::Stylesheet {
            if let Some(doc) = hint.as_deref().or(referer) {
                let k = key(dev, url);
                if self.sheets.get(&k).is_none() {
                    self.sheets.insert(k, cut(doc).to_string());
                }
            }
        }
        hint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn hm(p: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in p {
            h.insert(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn css_initiated_requests_resolve_to_the_page() {
        let t = PageTracker::default();
        let page = "https://page.test/index.html";
        assert_eq!(t.hint("d", &hm(&[]), page, RequestType::Document), None);
        // The stylesheet is referred by the page: no hint needed, but it is remembered.
        let sheet = "https://cdn.test/a.css";
        let h = hm(&[("referer", page)]);
        assert_eq!(t.hint("d", &h, sheet, RequestType::Stylesheet), None);
        // @import chain: referer is the first sheet.
        let sheet2 = "https://cdn2.test/b.css";
        let h = hm(&[("referer", sheet)]);
        assert_eq!(
            t.hint("d", &h, sheet2, RequestType::Stylesheet).as_deref(),
            Some(page)
        );
        // A font fetched by the nested sheet.
        let h = hm(&[("referer", sheet2)]);
        assert_eq!(
            t.hint("d", &h, "https://f.test/x.woff2", RequestType::Font)
                .as_deref(),
            Some(page)
        );
        // Another device does not see it.
        assert_eq!(
            t.hint("other", &h, "https://f.test/x.woff2", RequestType::Font),
            None
        );
        // A page Referer is not a sheet: no hint.
        let h = hm(&[("referer", page)]);
        assert_eq!(
            t.hint("d", &h, "https://f.test/y.png", RequestType::Image),
            None
        );
    }

    #[test]
    fn no_guessing_without_a_known_sheet() {
        let t = PageTracker::default();
        let u = "https://ads.test/p.gif";
        let cross = hm(&[("sec-fetch-site", "cross-site")]);
        assert_eq!(t.hint("d", &cross, u, RequestType::Image), None);
        assert_eq!(t.hint("d", &hm(&[]), u, RequestType::Document), None);
        assert_eq!(t.hint("d", &cross, u, RequestType::Image), None);
    }

    #[test]
    fn first_sheet_mapping_wins_and_urls_are_bounded() {
        let t = PageTracker::default();
        let sheet = "https://cdn.test/a.css";
        t.hint(
            "d",
            &hm(&[("referer", "https://one.test/")]),
            sheet,
            RequestType::Stylesheet,
        );
        t.hint(
            "d",
            &hm(&[("referer", "https://two.test/")]),
            sheet,
            RequestType::Stylesheet,
        );
        let h = hm(&[("referer", sheet)]);
        assert_eq!(
            t.hint("d", &h, "https://f.test/x.woff2", RequestType::Font)
                .as_deref(),
            Some("https://one.test/")
        );
        let long = format!("https://page.test/{}", "a".repeat(10_000));
        t.hint(
            "d",
            &hm(&[("referer", &long)]),
            "https://c.test/b.css",
            RequestType::Stylesheet,
        );
        let h = hm(&[("referer", "https://c.test/b.css")]);
        let got = t
            .hint("d", &h, "https://f.test/y", RequestType::Font)
            .unwrap();
        assert!(got.len() <= MAX_URL);
    }
}

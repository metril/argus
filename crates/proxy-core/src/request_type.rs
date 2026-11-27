//! Request typing and source (page) URL inference from browser request headers.
//!
//! Resource type: `Sec-Fetch-Dest` first, then `Accept` / `X-Requested-With` / URL extension.
//! Source URL: used for third-party and `$domain=` matching. Allocation-free: results borrow
//! from the headers or the request URL.

use hyper::header::{HeaderMap, ACCEPT, CONTENT_TYPE, ORIGIN, REFERER, UPGRADE};
use hyper::Method;

/// Coarse resource type used for filter matching and block-response selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    Document,
    Subdocument,
    Script,
    Stylesheet,
    Image,
    Font,
    Media,
    /// `fetch()` / `XMLHttpRequest`.
    Xhr,
    Websocket,
    /// `navigator.sendBeacon`, `<a ping>`, CSP/Reporting API reports.
    Ping,
    Object,
    Other,
}

impl RequestType {
    /// The type name understood by the adblock engine.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Subdocument => "sub_frame",
            Self::Script => "script",
            Self::Stylesheet => "stylesheet",
            Self::Image => "image",
            Self::Font => "font",
            Self::Media => "media",
            Self::Xhr => "xhr",
            Self::Websocket => "websocket",
            Self::Ping => "ping",
            Self::Object => "object",
            Self::Other => "other",
        }
    }

    /// Whether the response is an HTML page (`$csp` applies, block page makes sense).
    pub fn is_frame(self) -> bool {
        matches!(self, Self::Document | Self::Subdocument)
    }
}

fn hstr(headers: &HeaderMap, name: impl hyper::header::AsHeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Classify a request. `path` is the path (and optional query) used for the extension fallback.
pub fn classify(method: &Method, headers: &HeaderMap, path: &str) -> RequestType {
    if hstr(headers, UPGRADE).is_some_and(|u| u.eq_ignore_ascii_case("websocket")) {
        return RequestType::Websocket;
    }
    let content_type = hstr(headers, CONTENT_TYPE);
    let is_ping_body = content_type.is_some_and(|c| c.starts_with("text/ping"));

    if let Some(dest) = hstr(headers, "sec-fetch-dest") {
        match dest {
            "document" => return RequestType::Document,
            "iframe" | "frame" | "fencedframe" => return RequestType::Subdocument,
            "script" | "worker" | "sharedworker" | "serviceworker" | "audioworklet"
            | "paintworklet" => return RequestType::Script,
            "style" | "xslt" => return RequestType::Stylesheet,
            "image" => return RequestType::Image,
            "font" => return RequestType::Font,
            "audio" | "video" | "track" => return RequestType::Media,
            "embed" | "object" => return RequestType::Object,
            "report" => return RequestType::Ping,
            "manifest" => return RequestType::Other,
            "websocket" => return RequestType::Websocket,
            "empty" => {
                // sendBeacon: POST, no-cors, no CORS-safelisted preflight.
                let beacon = *method == Method::POST
                    && hstr(headers, "sec-fetch-mode").is_some_and(|m| m == "no-cors");
                return if is_ping_body || beacon {
                    RequestType::Ping
                } else {
                    RequestType::Xhr
                };
            }
            _ => {}
        }
    }

    if is_ping_body {
        return RequestType::Ping;
    }
    // Clients without Fetch Metadata (older browsers, non-browser clients): navigations still
    // announce themselves with `Upgrade-Insecure-Requests: 1` (sent by browsers for top-level and
    // frame loads only) and an `Accept` that lists `text/html` (handled below).
    if hstr(headers, "sec-fetch-mode").is_some_and(|m| m == "navigate")
        || (*method == Method::GET
            && hstr(headers, "upgrade-insecure-requests").is_some_and(|v| v.trim() == "1"))
    {
        return RequestType::Document;
    }
    if hstr(headers, "x-requested-with").is_some_and(|v| v.eq_ignore_ascii_case("xmlhttprequest")) {
        return RequestType::Xhr;
    }
    if let Some(accept) = hstr(headers, ACCEPT) {
        if accept.contains("text/html") {
            return RequestType::Document;
        }
        if accept.contains("text/css") {
            return RequestType::Stylesheet;
        }
        if accept.starts_with("image/") {
            return RequestType::Image;
        }
        if accept.contains("text/event-stream") || accept.starts_with("application/json") {
            return RequestType::Xhr;
        }
    }
    classify_extension(path)
}

fn classify_extension(path: &str) -> RequestType {
    let p = path.split(['?', '#']).next().unwrap_or(path);
    let Some((_, ext)) = p.rsplit_once('.') else {
        return RequestType::Other;
    };
    let is = |list: &[&str]| list.iter().any(|e| ext.eq_ignore_ascii_case(e));
    if is(&["js", "mjs"]) {
        RequestType::Script
    } else if is(&["css"]) {
        RequestType::Stylesheet
    } else if is(&[
        "png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "bmp",
    ]) {
        RequestType::Image
    } else if is(&["woff", "woff2", "ttf", "otf", "eot"]) {
        RequestType::Font
    } else if is(&["mp4", "webm", "mp3", "ogg", "m4a", "m3u8", "ts", "wav"]) {
        RequestType::Media
    } else if is(&["swf"]) {
        RequestType::Object
    } else {
        RequestType::Other
    }
}

/// The URL of the page that issued the request, for third-party / `$domain` matching.
///
/// * Documents are first-party to themselves.
/// * Otherwise `Referer` (full URL or just an origin: only the host matters), then `Origin`.
/// * With neither: `Sec-Fetch-Site: cross-site` yields `""` (the engine then treats the request
///   as third-party); any other value, or no fetch metadata, counts as same-party.
pub fn source_url<'a>(headers: &'a HeaderMap, url: &'a str, ty: RequestType) -> &'a str {
    source_url_hinted(headers, url, ty, None)
}

/// [`source_url`] with the page the proxy resolved itself (see `crate::pages`), which wins over
/// the header inference: it covers a `Referer` that names a stylesheet and a missing one.
///
/// `Sec-Fetch-Site: same-origin|same-site|none` with no `Referer`/`Origin` yields the request
/// URL itself: first-party for `$third-party`, which is right at eTLD+1 granularity (`same-site`
/// is by definition the same registrable domain).
pub fn source_url_hinted<'a>(
    headers: &'a HeaderMap,
    url: &'a str,
    ty: RequestType,
    hint: Option<&'a str>,
) -> &'a str {
    if ty == RequestType::Document {
        return url;
    }
    if let Some(h) = hint.filter(|h| !h.is_empty()) {
        return h;
    }
    if let Some(r) = hstr(headers, REFERER).filter(|r| !r.is_empty()) {
        return r;
    }
    if let Some(o) = hstr(headers, ORIGIN).filter(|o| !o.is_empty() && *o != "null") {
        return o;
    }
    match hstr(headers, "sec-fetch-site") {
        Some("cross-site") => "",
        _ => url,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn request_typing_table() {
        use RequestType::*;
        let get = Method::GET;
        type Case<'a> = (&'a [(&'a str, &'a str)], &'a str, RequestType);
        let cases: &[Case] = &[
            (&[("sec-fetch-dest", "document")], "/", Document),
            (&[("sec-fetch-dest", "iframe")], "/", Subdocument),
            (&[("sec-fetch-dest", "frame")], "/", Subdocument),
            (&[("sec-fetch-dest", "script")], "/x", Script),
            (&[("sec-fetch-dest", "worker")], "/w", Script),
            (&[("sec-fetch-dest", "style")], "/x", Stylesheet),
            (&[("sec-fetch-dest", "image")], "/x", Image),
            (&[("sec-fetch-dest", "font")], "/x", Font),
            (&[("sec-fetch-dest", "audio")], "/x", Media),
            (&[("sec-fetch-dest", "video")], "/x", Media),
            (&[("sec-fetch-dest", "track")], "/x", Media),
            (&[("sec-fetch-dest", "object")], "/x", Object),
            (&[("sec-fetch-dest", "embed")], "/x", Object),
            (&[("sec-fetch-dest", "report")], "/x", Ping),
            (&[("sec-fetch-dest", "manifest")], "/x", Other),
            (&[("sec-fetch-dest", "empty")], "/api", Xhr),
            (&[("upgrade", "websocket")], "/ws", Websocket),
            (&[("sec-fetch-dest", "websocket")], "/ws", Websocket),
            // Fallbacks without Sec-Fetch-Dest.
            (
                &[("accept", "text/html,application/xhtml+xml")],
                "/",
                Document,
            ),
            (&[("accept", "text/css,*/*;q=0.1")], "/a", Stylesheet),
            (&[("accept", "image/avif,image/webp,*/*")], "/a", Image),
            (&[("accept", "application/json")], "/a", Xhr),
            (&[("x-requested-with", "XMLHttpRequest")], "/a", Xhr),
            (&[("content-type", "text/ping")], "/p", Ping),
            (&[("accept", "*/*")], "/a.js?v=1", Script),
            (&[], "/a.JS", Script),
            (&[], "/a.css", Stylesheet),
            (&[], "/a.png", Image),
            (&[], "/a.woff2", Font),
            (&[], "/a.mp4", Media),
            (&[], "/a.swf", Object),
            (&[], "/a", Other),
            // Sec-Fetch-Dest wins over Accept/extension.
            (
                &[("sec-fetch-dest", "image"), ("accept", "text/html")],
                "/a.js",
                Image,
            ),
        ];
        for (h, path, want) in cases {
            assert_eq!(classify(&get, &hm(h), path), *want, "{h:?} {path}");
        }
    }

    #[test]
    fn beacon_is_ping_but_plain_post_fetch_is_xhr() {
        let h = hm(&[("sec-fetch-dest", "empty"), ("sec-fetch-mode", "no-cors")]);
        assert_eq!(classify(&Method::POST, &h, "/b"), RequestType::Ping);
        let h = hm(&[("sec-fetch-dest", "empty"), ("sec-fetch-mode", "cors")]);
        assert_eq!(classify(&Method::POST, &h, "/b"), RequestType::Xhr);
    }

    #[test]
    fn source_url_rules() {
        let url = "https://cdn.test/a.js";
        // Document is first-party to itself even with a foreign Referer.
        let h = hm(&[("referer", "https://other.test/")]);
        assert_eq!(source_url(&h, url, RequestType::Document), url);
        // Referer stripped to an origin still works.
        let h = hm(&[("referer", "https://page.test/")]);
        assert_eq!(
            source_url(&h, url, RequestType::Script),
            "https://page.test/"
        );
        // Origin when no Referer; "null" ignored.
        let h = hm(&[("origin", "https://page.test")]);
        assert_eq!(source_url(&h, url, RequestType::Xhr), "https://page.test");
        let h = hm(&[("origin", "null"), ("sec-fetch-site", "cross-site")]);
        assert_eq!(source_url(&h, url, RequestType::Xhr), "");
        // cross-site without Referer/Origin: unknown page, third-party.
        let h = hm(&[("sec-fetch-site", "cross-site")]);
        assert_eq!(source_url(&h, url, RequestType::Image), "");
        // same-origin / no metadata: same party.
        let h = hm(&[("sec-fetch-site", "same-origin")]);
        assert_eq!(source_url(&h, url, RequestType::Image), url);
        assert_eq!(source_url(&HeaderMap::new(), url, RequestType::Image), url);
    }

    #[test]
    fn hint_overrides_headers_but_not_documents() {
        let url = "https://f.test/x.woff2";
        let h = hm(&[("referer", "https://cdn.test/a.css")]);
        assert_eq!(
            source_url_hinted(&h, url, RequestType::Font, Some("https://page.test/")),
            "https://page.test/"
        );
        assert_eq!(
            source_url_hinted(&h, url, RequestType::Font, None),
            "https://cdn.test/a.css"
        );
        assert_eq!(
            source_url_hinted(&h, url, RequestType::Document, Some("https://x/")),
            url
        );
    }

    #[test]
    fn same_site_without_referer_is_first_party() {
        // Source = the request URL: same registrable domain, so `$third-party` is false.
        let u = "https://cdn.page.test/a.js";
        for s in ["same-site", "same-origin", "none"] {
            let h = hm(&[("sec-fetch-site", s)]);
            assert_eq!(source_url(&h, u, RequestType::Script), u, "{s}");
        }
    }

    #[test]
    fn navigations_without_fetch_metadata() {
        let nav = hm(&[("upgrade-insecure-requests", "1"), ("accept", "*/*")]);
        assert_eq!(classify(&Method::GET, &nav, "/x"), RequestType::Document);
        assert_eq!(classify(&Method::POST, &nav, "/x"), RequestType::Other);
        let html = hm(&[("accept", "text/html,application/xhtml+xml")]);
        assert_eq!(classify(&Method::GET, &html, "/x"), RequestType::Document);
        // Fetch Metadata wins over the heuristics.
        let xhr = hm(&[
            ("upgrade-insecure-requests", "1"),
            ("sec-fetch-dest", "empty"),
        ]);
        assert_eq!(classify(&Method::GET, &xhr, "/x"), RequestType::Xhr);
    }
}

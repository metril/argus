//! Allocation-free request pre-parsing for the domain-set fast path.
//!
//! A pure domain rule behaves like the engine's default network rule: it applies to some request
//! types (not `document`) for some schemes. Instead of hard-coding that, [`applies`] is measured
//! once from the real engine (a probe engine holding `||probe.test^`), so the fast path cannot
//! drift from adblock-rust. [`raw_type`] mirrors adblock-rust's string-to-type mapping, and a test
//! pins it against `Request::new`.

use std::sync::OnceLock;

use adblock::lists::{parse_filter, FilterSet, ParseOptions, ParsedFilter};
use adblock::request::{Request, RequestType};
use adblock::Engine;

use crate::domainset::Scheme;

/// Mirror of adblock-rust's `cpt_match_type` (unknown strings map to `other`).
pub(crate) fn raw_type(t: &str) -> RequestType {
    match t {
        "beacon" | "ping" => RequestType::Ping,
        "csp_report" => RequestType::Csp,
        "document" | "main_frame" => RequestType::Document,
        "font" => RequestType::Font,
        "image" | "imageset" => RequestType::Image,
        "media" => RequestType::Media,
        "object" | "object_subrequest" => RequestType::Object,
        "script" => RequestType::Script,
        "stylesheet" => RequestType::Stylesheet,
        "sub_frame" | "subdocument" => RequestType::Subdocument,
        "websocket" => RequestType::Websocket,
        "xhr" | "xmlhttprequest" => RequestType::Xmlhttprequest,
        _ => RequestType::Other,
    }
}

/// Representative raw type string per producible [`RequestType`].
const PROBE_TYPES: &[&str] = &[
    "ping",
    "csp_report",
    "document",
    "font",
    "image",
    "media",
    "object",
    "script",
    "stylesheet",
    "subdocument",
    "websocket",
    "xhr",
    "other",
];

fn scheme_index(s: Scheme) -> usize {
    match s {
        Scheme::Http => 0,
        Scheme::Https => 1,
        Scheme::Ws | Scheme::Wss => 2,
    }
}

/// `[exact][scheme][type]`: does a `||probe.test^` (exact = 0) or `|scheme://probe.test^`
/// (exact = 1) rule match?
type Table = [[[bool; 32]; 3]; 2];

fn probe_engine(rule: &str) -> Engine {
    let set = match parse_filter(rule, false, ParseOptions::default()) {
        Ok(ParsedFilter::Network(f)) => FilterSet::new_with_rules(vec![f], vec![], false),
        _ => FilterSet::new(false),
    };
    Engine::from_filter_set(set, false)
}

fn table() -> &'static Table {
    static T: OnceLock<Table> = OnceLock::new();
    T.get_or_init(|| {
        let mut t = [[[false; 32]; 3]; 2];
        let suffix = probe_engine("||probe.test^");
        for (si, scheme) in ["http", "https", "wss"].into_iter().enumerate() {
            let exact = probe_engine(&format!("|{scheme}://probe.test^"));
            let url = format!("{scheme}://probe.test/");
            for raw in PROBE_TYPES {
                if let Ok(req) = Request::new(&url, "", raw) {
                    let i = idx(&req.request_type);
                    t[0][si][i] = suffix.check_network_request(&req).matched;
                    t[1][si][i] = exact.check_network_request(&req).matched;
                }
            }
        }
        t
    })
}

/// Does the engine apply an option-less `||host^` rule (`exact = false`) or `|scheme://host^`
/// rule (`exact = true`) to a request of this scheme and type? Measured from the engine itself
/// (for example `||host^` also matches document requests; `|https://host^` does not).
#[inline]
pub(crate) fn applies(exact: bool, scheme: Scheme, rt: usize) -> bool {
    table()[exact as usize][scheme_index(scheme)][rt]
}

/// Table index of a request type.
pub(crate) fn idx(rt: &RequestType) -> usize {
    rt.clone() as usize
}

/// The parts of a request URL the fast path needs.
pub(crate) struct Fast<'a> {
    pub scheme: Scheme,
    /// `RequestType` discriminant (see [`idx`]).
    pub rt: usize,
    pub host: &'a str,
    /// The host has no uppercase letters. adblock-rust does not lowercase request hostnames, so
    /// `||host^` rules never match a mixed-case host; the set must not either.
    pub lower: bool,
    /// The authority carries `user@` (exact-host rules would not match such a URL).
    pub userinfo: bool,
}

fn eq_ci(a: &[u8], lit: &[u8]) -> bool {
    a.len() >= lit.len() && a[..lit.len()].eq_ignore_ascii_case(lit)
}

/// Parse `url` without allocating. `None` means "not simple": the caller takes the exact slow
/// path (unsupported scheme, IPv6, non-ASCII or odd characters, empty or dotted-edge hosts).
pub(crate) fn fast<'a>(url: &'a str, raw: &str) -> Option<Fast<'a>> {
    let b = url.as_bytes();
    let (scheme, skip) = if eq_ci(b, b"https://") {
        (Scheme::Https, 8)
    } else if eq_ci(b, b"http://") {
        (Scheme::Http, 7)
    } else if eq_ci(b, b"wss://") {
        (Scheme::Wss, 6)
    } else if eq_ci(b, b"ws://") {
        (Scheme::Ws, 5)
    } else {
        return None;
    };
    let rest = &url[skip..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let auth = &rest[..end];
    if auth.bytes().any(|c| c <= b' ' || c >= 0x7f || c == b'\\') {
        return None;
    }
    let (userinfo, hostport) = match auth.rsplit_once('@') {
        Some((_, h)) => (true, h),
        None => (false, auth),
    };
    let host = hostport.split(':').next().unwrap_or("");
    let hb = host.as_bytes();
    if hb.is_empty()
        || hb[0] == b'.'
        || hb[hb.len() - 1] == b'.'
        || host.contains("..")
        || !hb
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
    {
        return None;
    }
    let rt = idx(&if matches!(scheme, Scheme::Ws | Scheme::Wss) {
        RequestType::Websocket
    } else {
        raw_type(raw)
    });
    Some(Fast {
        scheme,
        rt,
        host,
        lower: !host.bytes().any(|c| c.is_ascii_uppercase()),
        userinfo,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_type_matches_adblock_for_all_strings() {
        for raw in PROBE_TYPES.iter().chain(&[
            "beacon",
            "main_frame",
            "imageset",
            "object_subrequest",
            "sub_frame",
            "xmlhttprequest",
            "speculative",
            "web_manifest",
            "xbl",
            "xml_dtd",
            "xslt",
            "fetch",
            "",
            "weird",
        ]) {
            let r = Request::new("https://a.test/", "", raw).unwrap();
            assert_eq!(idx(&r.request_type), idx(&raw_type(raw)), "{raw}");
        }
    }

    #[test]
    fn measured_applicability() {
        let (script, image, doc) = (
            idx(&RequestType::Script),
            idx(&RequestType::Image),
            idx(&RequestType::Document),
        );
        assert!(applies(false, Scheme::Https, script) && applies(true, Scheme::Http, image));
        // `||host^` implicitly matches main documents; `|https://host^` does not.
        assert!(applies(false, Scheme::Https, doc));
        assert!(!applies(true, Scheme::Https, doc));
    }

    #[test]
    fn fast_parse() {
        let f = fast("HTTPS://Sub.Ads.test:8443/x?y=1", "script").unwrap();
        assert_eq!(
            (f.host, f.scheme, f.userinfo),
            ("Sub.Ads.test", Scheme::Https, false)
        );
        let f = fast("http://u:p@h.test/", "image").unwrap();
        assert_eq!((f.host, f.userinfo), ("h.test", true));

        for odd in [
            "ftp://h.test/",
            "http://[::1]/",
            "http://h.test./",
            "http://héllo.test/",
            "http:///x",
            "http://a b.test/",
            "http://a..test/",
            "http://h%41.test/",
            "http://a.test\\@b.test/",
        ] {
            assert!(fast(odd, "script").is_none(), "{odd}");
        }
    }
}

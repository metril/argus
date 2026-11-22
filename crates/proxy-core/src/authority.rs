//! Host/port extraction from request authorities and the SAN coverage rule for intercepted
//! connections.

use hyper::header::HOST;
use hyper::http::uri::Authority;
use hyper::{HeaderMap, Uri};
use std::net::IpAddr;

/// Strip the brackets of an IPv6 literal.
pub fn unbracket(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Host (IPv6 brackets removed) and optional port of an authority string such as the `Host`
/// header value. Userinfo is rejected.
pub fn parse(authority: &str) -> Option<(String, Option<u16>)> {
    let a: Authority = authority.parse().ok()?;
    if a.as_str().contains('@') {
        return None;
    }
    Some((unbracket(a.host()).to_string(), a.port_u16()))
}

/// Host and port a request names: the URI's authority (absolute-form, h2 `:authority`) if any,
/// else the `Host` header.
pub fn of_request(uri: &Uri, headers: &HeaderMap) -> Option<(String, Option<u16>)> {
    if let Some(a) = uri.authority() {
        return parse(a.as_str());
    }
    parse(headers.get(HOST)?.to_str().ok()?)
}

/// Every host the request names (URI authority and `Host` header), for consistency checks.
pub fn named_hosts(uri: &Uri, headers: &HeaderMap) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(a) = uri.authority() {
        out.extend(parse(a.as_str()).map(|(h, _)| h));
    }
    if let Some(v) = headers.get(HOST) {
        match v.to_str().ok().and_then(parse) {
            Some((h, _)) => out.push(h),
            // An unparsable Host can never be covered by a certificate.
            None => out.push(String::new()),
        }
    }
    out
}

/// A host as it appears in a URL (IPv6 literals bracketed).
pub fn url_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Whether the leaf certificate issued for `cert_host` (see `ca::subject_alt_names`: the name and
/// `*.name` for names with a dot, an IP SAN alone for literals) covers `req_host`. Wildcards
/// match exactly one label.
pub fn covered_by_cert(cert_host: &str, req_host: &str) -> bool {
    let c = unbracket(cert_host)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let r = unbracket(req_host)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if c.is_empty() || r.is_empty() {
        return false;
    }
    if c == r {
        return true;
    }
    if c.parse::<IpAddr>().is_ok() || r.parse::<IpAddr>().is_ok() {
        return false;
    }
    c.contains('.')
        && r.strip_suffix(c.as_str())
            .and_then(|p| p.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_authorities() {
        assert_eq!(parse("example.com"), Some(("example.com".into(), None)));
        assert_eq!(
            parse("example.com:8443"),
            Some(("example.com".into(), Some(8443)))
        );
        assert_eq!(parse("[::1]:443"), Some(("::1".into(), Some(443))));
        assert_eq!(parse("[2001:db8::1]"), Some(("2001:db8::1".into(), None)));
        assert_eq!(parse("1.2.3.4:80"), Some(("1.2.3.4".into(), Some(80))));
        assert_eq!(parse("user@evil.test"), None);
        assert_eq!(parse(""), None);
        assert_eq!(url_host("::1"), "[::1]");
        assert_eq!(url_host("a.test"), "a.test");
    }

    #[test]
    fn host_header_wins_when_uri_is_origin_form() {
        let uri: Uri = "/x".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert(HOST, "[::1]:8443".parse().unwrap());
        assert_eq!(of_request(&uri, &h), Some(("::1".into(), Some(8443))));
    }

    #[test]
    fn san_coverage_mirrors_issued_certificate() {
        assert!(covered_by_cert("example.com", "example.com"));
        assert!(covered_by_cert("Example.com", "EXAMPLE.com."));
        assert!(covered_by_cert("example.com", "www.example.com"));
        assert!(!covered_by_cert("example.com", "a.b.example.com"));
        assert!(!covered_by_cert("example.com", "evilexample.com"));
        assert!(!covered_by_cert("www.example.com", "example.com"));
        assert!(!covered_by_cert("example.com", "other.test"));
        // Single-label names get no wildcard.
        assert!(!covered_by_cert("localhost", "a.localhost"));
        // IP literals only cover themselves.
        assert!(covered_by_cert("127.0.0.1", "127.0.0.1"));
        assert!(!covered_by_cert("127.0.0.1", "a.127.0.0.1"));
        assert!(covered_by_cert("[::1]", "::1"));
        assert!(!covered_by_cert("example.com", ""));
    }
}

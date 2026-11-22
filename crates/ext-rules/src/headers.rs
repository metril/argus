//! `$removeheader` policy and the header-edit vocabulary shared by request and response plans.
//!
//! The forbidden list is AdGuard KB "$removeheader" ("cannot remove headers from the list
//! below", checked against the published page): the `access-control-*` CORS family, `origin`,
//! `timing-allow-origin`, `allow`, the `cross-origin-*-policy` family, CSP (+ report-only),
//! `expect-ct`, `feature-policy`, `origin-isolation`, `strict-transport-security`,
//! `upgrade-insecure-requests`, `x-content-type-options`, `x-download-options`, `x-frame-options`,
//! `x-permitted-cross-domain-policies`, `x-powered-by`, `x-xss-protection`, `public-key-pins(-report-only)`,
//! `sec-websocket-*`, `p3p`, `sec-fetch-*`, `referrer-policy`, `content-type`, `content-length`,
//! `accept`, `accept-encoding`, `host`, `connection`, `transfer-encoding`, `upgrade`.
//! uBO restricts response removal to an even smaller allowlist (`location`, `refresh`,
//! `report-to`, `set-cookie`). Beyond AdGuard's list we also protect headers that frame the
//! message: `content-encoding`, `content-range`, `te`, `trailer`, `proxy-*`.

/// One header modification, in terms plain enough for any HTTP library to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderEdit {
    /// Remove every value of the header.
    Remove(String),
    /// Replace every value of the header with exactly these (empty = remove).
    SetAll(String, Vec<String>),
    /// Add one more value.
    Append(String, String),
}

impl HeaderEdit {
    pub fn name(&self) -> &str {
        match self {
            Self::Remove(n) | Self::SetAll(n, _) | Self::Append(n, _) => n,
        }
    }
}

/// May a `$removeheader` rule remove this (ASCII-lowercase) header?
pub fn is_removable_header(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "origin",
        "timing-allow-origin",
        "allow",
        "content-security-policy",
        "content-security-policy-report-only",
        "expect-ct",
        "feature-policy",
        "origin-isolation",
        "strict-transport-security",
        "upgrade-insecure-requests",
        "x-content-type-options",
        "x-download-options",
        "x-frame-options",
        "x-permitted-cross-domain-policies",
        "x-powered-by",
        "x-xss-protection",
        "public-key-pins",
        "public-key-pins-report-only",
        "p3p",
        "referrer-policy",
        "accept",
        "accept-encoding",
        "content-length",
        "content-type",
        "content-encoding",
        "content-range",
        "transfer-encoding",
        "connection",
        "host",
        "upgrade",
        "te",
        "trailer",
    ];
    !(name.is_empty()
        || EXACT.contains(&name)
        || name.starts_with("access-control-")
        || name.starts_with("cross-origin-")
        || name.starts_with("sec-websocket-")
        || name.starts_with("sec-fetch-")
        || name.starts_with("proxy-")
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'))
}

/// Case-insensitive header lookup over a slice of pairs.
pub(crate) fn find<'a>(headers: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| *v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy() {
        for ok in [
            "refresh",
            "location",
            "set-cookie",
            "x-cache",
            "report-to",
        ] {
            assert!(is_removable_header(ok), "{ok}");
        }
        for bad in [
            "access-control-allow-origin",
            "content-length",
            "origin",
            "x-powered-by",
            "referrer-policy",
            "sec-fetch-mode",
            "cross-origin-opener-policy",
            "content-security-policy",
            "",
            "a b",
        ] {
            assert!(!is_removable_header(bad), "{bad}");
        }
    }
}

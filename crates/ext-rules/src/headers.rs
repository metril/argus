//! `$removeheader` policy and the header-edit vocabulary shared by request and response plans.
//!
//! AdGuard KB "$removeheader" forbids removing the CORS family (`Access-Control-*`), `Origin`,
//! `Timing-Allow-Origin`, `Allow`, the `Cross-Origin-*-Policy` family and `Content-Security-Policy`
//! because stripping them silently weakens or breaks site security; uBO restricts response removal
//! to an even smaller allowlist (`location`, `refresh`, `report-to`, `set-cookie`). This
//! implementation enforces AdGuard's list plus the headers that frame the message (so a rule can
//! never corrupt the proxied connection): `content-length`, `content-type`, `content-encoding`,
//! `content-range`, `transfer-encoding`, `connection`, `host`, `upgrade`, `te`, `trailer`,
//! `proxy-*`, `strict-transport-security`.

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
        "strict-transport-security",
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
            "x-powered-by",
            "report-to",
        ] {
            assert!(is_removable_header(ok), "{ok}");
        }
        for bad in [
            "access-control-allow-origin",
            "content-length",
            "origin",
            "cross-origin-opener-policy",
            "content-security-policy",
            "",
            "a b",
        ] {
            assert!(!is_removable_header(bad), "{bad}");
        }
    }
}

//! CSRF protection for cookie-authenticated, state-changing requests.
//!
//! Scheme: signed double-submit. At login the server sets a readable (non-HttpOnly) cookie
//! `csrf_token` holding `BLAKE3-keyed(secret, session id)`. The client echoes it in the
//! `X-CSRF-Token` header; the server recomputes the expected value for the request's session
//! and compares in constant time, so a token planted via cookie tossing or issued for another
//! session never validates. As defence in depth, a present `Origin` must match the `Host` (or
//! the CORS allowlist) and `Sec-Fetch-Site: cross-site` is refused.
//!
//! Bearer-token requests carry no ambient credentials and are exempt.

use axum::http::{header, HeaderMap};
use uuid::Uuid;

pub const CSRF_COOKIE: &str = "csrf_token";
pub const CSRF_HEADER: &str = "x-csrf-token";

fn key(secret: &str) -> [u8; 32] {
    blake3::derive_key("argus api csrf v1", secret.as_bytes())
}

/// The CSRF token for a session.
pub fn token_for(secret: &str, session: &Uuid) -> String {
    blake3::keyed_hash(&key(secret), session.as_bytes())
        .to_hex()
        .to_string()
}

fn origin_ok(headers: &HeaderMap, allowed: &[String]) -> bool {
    let allowlisted = |origin: &str| allowed.iter().any(|a| a == origin);
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
        let same = origin
            .split_once("://")
            .is_some_and(|(_, h)| Some(h) == host);
        if !same && !allowlisted(origin) {
            return false;
        }
    } else if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if site == "cross-site" {
            return false;
        }
    }
    true
}

/// Validate the CSRF header for `session`.
pub fn verify(
    headers: &HeaderMap,
    secret: &str,
    session: &Uuid,
    allowed_origins: &[String],
) -> bool {
    if !origin_ok(headers, allowed_origins) {
        return false;
    }
    let Some(given) = headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    // Hash both sides so the comparison is constant-time regardless of input length.
    blake3::hash(given.as_bytes()) == blake3::hash(token_for(secret, session).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_bound_to_session_and_secret() {
        let s = Uuid::new_v4();
        let mut h = HeaderMap::new();
        assert!(!verify(&h, "k", &s, &[]));
        h.insert(CSRF_HEADER, token_for("k", &s).parse().unwrap());
        assert!(verify(&h, "k", &s, &[]));
        assert!(!verify(&h, "other", &s, &[]));
        assert!(!verify(&h, "k", &Uuid::new_v4(), &[]));
        h.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        h.insert(header::HOST, "adblock.lan:3000".parse().unwrap());
        assert!(!verify(&h, "k", &s, &[]));
        h.insert(header::ORIGIN, "http://adblock.lan:3000".parse().unwrap());
        assert!(verify(&h, "k", &s, &[]));
    }
}

//! Per-document, per-script capability tokens for the GM endpoints.
//!
//! `token = "v1." + b64url(script_id) + "." + exp_unix_secs + "." + b64url(HMAC-SHA256(key, msg))`
//! with `msg = "adblock-gm-v1" 0 profile 0 script_id 0 script_version 0 origin 0 caps_hash 0 exp`.
//!
//! The token only *identifies the claimed script* (its id is in the clear). The server never
//! trusts anything in it: it recomputes the MAC from its own records (the profile resolved from
//! the connection, the script's stored version and capability hash, the request's `Origin`) and
//! compares in constant time. Any change to the script's version, grants or `@connect`, a
//! different profile or origin, or expiry invalidates it.

use crate::metadata::UserscriptMetadata;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Secret HMAC key supplied by the caller (>= 32 random bytes recommended).
#[derive(Clone)]
pub struct TokenKey(Vec<u8>);

impl TokenKey {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
}

impl std::fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenKey(..)")
    }
}

/// What a token is bound to.
#[derive(Debug, Clone)]
pub struct TokenClaims<'a> {
    pub profile: &'a str,
    pub script_id: &'a str,
    pub script_version: &'a str,
    /// Page origin, e.g. `https://example.com` (`Origin` header form, no trailing slash).
    pub origin: &'a str,
    pub caps_hash: &'a str,
    /// Expiry, unix seconds.
    pub exp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("malformed token")]
    Malformed,
    #[error("token expired")]
    Expired,
    #[error("unknown script")]
    UnknownScript,
    #[error("token does not match")]
    BadSignature,
}

/// Hash of the capability set that matters for authority: canonical grants, `@connect` list and
/// the install-time `@connect *` approval.
pub fn caps_hash(meta: &UserscriptMetadata, allow_connect_all: bool) -> String {
    let mut h = Sha256::new();
    for g in meta.effective_grants() {
        h.update(g.as_bytes());
        h.update([0]);
    }
    h.update([1]);
    let mut c = meta.connect.clone();
    c.sort();
    c.dedup();
    for x in c {
        h.update(x.as_bytes());
        h.update([0]);
    }
    h.update([if allow_connect_all { 2 } else { 3 }]);
    B64.encode(&h.finalize()[..16])
}

fn mac(key: &TokenKey, c: &TokenClaims<'_>) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(&key.0).expect("hmac accepts any key length");
    for part in ["adblock-gm-v1", c.profile, c.script_id, c.script_version, c.origin, c.caps_hash] {
        m.update(part.as_bytes());
        m.update(&[0]);
    }
    m.update(c.exp.to_string().as_bytes());
    m.finalize().into_bytes().to_vec()
}

/// Mint a token for one script in one document.
pub fn mint(key: &TokenKey, c: &TokenClaims<'_>) -> String {
    format!("v1.{}.{}.{}", B64.encode(c.script_id), c.exp, B64.encode(mac(key, c)))
}

/// The claimed script id (unverified). Use to look the script up before [`verify`].
pub fn claimed_script_id(token: &str) -> Option<String> {
    let mut it = token.split('.');
    if it.next()? != "v1" {
        return None;
    }
    String::from_utf8(B64.decode(it.next()?).ok()?).ok()
}

/// What the server knows about a script (from its own records).
pub struct ScriptRecord<'a> {
    pub version: &'a str,
    pub caps_hash: &'a str,
}

/// Verify `token` for a request. `lookup` maps the claimed id to the server's record; returns
/// the verified script id.
pub fn verify<'a>(
    key: &TokenKey,
    token: &str,
    now: u64,
    profile: &str,
    origin: &str,
    lookup: impl FnOnce(&str) -> Option<ScriptRecord<'a>>,
) -> Result<String, TokenError> {
    let mut it = token.split('.');
    if it.next() != Some("v1") {
        return Err(TokenError::Malformed);
    }
    let id = String::from_utf8(B64.decode(it.next().ok_or(TokenError::Malformed)?).map_err(|_| TokenError::Malformed)?)
        .map_err(|_| TokenError::Malformed)?;
    let exp: u64 = it.next().and_then(|e| e.parse().ok()).ok_or(TokenError::Malformed)?;
    let sig = B64.decode(it.next().ok_or(TokenError::Malformed)?).map_err(|_| TokenError::Malformed)?;
    if it.next().is_some() {
        return Err(TokenError::Malformed);
    }
    let rec = lookup(&id).ok_or(TokenError::UnknownScript)?;
    let claims = TokenClaims {
        profile,
        script_id: &id,
        script_version: rec.version,
        origin,
        caps_hash: rec.caps_hash,
        exp,
    };
    // Compare the MAC first so expiry is not an oracle for forged tokens.
    let ok: bool = mac(key, &claims).ct_eq(&sig).into();
    if !ok {
        return Err(TokenError::BadSignature);
    }
    if now >= exp {
        return Err(TokenError::Expired);
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> ScriptRecord<'static> {
        ScriptRecord { version: "1.0", caps_hash: "h" }
    }
    fn tok(key: &TokenKey) -> String {
        mint(key, &TokenClaims { profile: "p", script_id: "ns:na me/é", script_version: "1.0", origin: "https://a.com", caps_hash: "h", exp: 100 })
    }

    #[test]
    fn roundtrip() {
        let k = TokenKey::new(vec![7; 32]);
        let t = tok(&k);
        assert_eq!(claimed_script_id(&t).as_deref(), Some("ns:na me/é"));
        assert_eq!(verify(&k, &t, 50, "p", "https://a.com", |_| Some(rec())).unwrap(), "ns:na me/é");
    }

    #[test]
    fn rejects() {
        let k = TokenKey::new(vec![7; 32]);
        let t = tok(&k);
        let v = |t: &str, now, p, o, r: Option<ScriptRecord<'static>>| verify(&k, t, now, p, o, move |_| r);
        assert_eq!(v(&t, 100, "p", "https://a.com", Some(rec())), Err(TokenError::Expired));
        assert_eq!(v(&t, 1, "q", "https://a.com", Some(rec())), Err(TokenError::BadSignature));
        assert_eq!(v(&t, 1, "p", "https://b.com", Some(rec())), Err(TokenError::BadSignature));
        assert_eq!(v(&t, 1, "p", "https://a.com", Some(ScriptRecord { version: "1.1", caps_hash: "h" })), Err(TokenError::BadSignature));
        assert_eq!(v(&t, 1, "p", "https://a.com", Some(ScriptRecord { version: "1.0", caps_hash: "x" })), Err(TokenError::BadSignature));
        assert_eq!(v(&t, 1, "p", "https://a.com", None), Err(TokenError::UnknownScript));
        assert_eq!(v("garbage", 1, "p", "o", Some(rec())), Err(TokenError::Malformed));
        // Tampering with the expiry or the claimed id.
        let parts: Vec<_> = t.split('.').collect();
        let t2 = format!("{}.{}.{}.{}", parts[0], parts[1], "9999", parts[3]);
        assert_eq!(v(&t2, 1, "p", "https://a.com", Some(rec())), Err(TokenError::BadSignature));
        let t3 = format!("{}.{}.{}.{}", parts[0], B64.encode("other"), parts[2], parts[3]);
        assert_eq!(v(&t3, 1, "p", "https://a.com", Some(rec())), Err(TokenError::BadSignature));
        let k2 = TokenKey::new(vec![8; 32]);
        assert_eq!(verify(&k2, &t, 1, "p", "https://a.com", |_| Some(rec())), Err(TokenError::BadSignature));
    }

    #[test]
    fn caps_hash_tracks_grants_and_connect() {
        let m = |h: &str| UserscriptMetadata::parse(&format!("// ==UserScript==\n// @name x\n{h}\n// ==/UserScript==")).unwrap();
        let a = caps_hash(&m("// @grant GM_getValue"), false);
        assert_eq!(a, caps_hash(&m("// @grant GM.getValue"), false));
        assert_ne!(a, caps_hash(&m("// @grant GM_getValue\n// @grant GM_log"), false));
        assert_ne!(a, caps_hash(&m("// @grant GM_getValue\n// @connect a.com"), false));
        assert_ne!(a, caps_hash(&m("// @grant GM_getValue"), true));
    }
}

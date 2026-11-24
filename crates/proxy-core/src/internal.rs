//! The proxy's own `/__adblock__/` endpoints.
//!
//! Every host's `/__adblock__/…` is answered here and never forwarded or filtered. Any web page
//! in the user's browser can send requests to these URLs, so each route is an explicit
//! allowlist entry with a method, caching and size policy, and nothing reflects request input:
//!
//! | route                        | method    | notes                                               |
//! |------------------------------|-----------|-----------------------------------------------------|
//! | `/__adblock__/boot.<hash>.js`| GET, HEAD | static script, immutable cache, hash in the URL     |
//! | `/__adblock__/s/<hash>.js`   | GET, HEAD | scriptlet bundle generated for a page, by hash      |
//! | `/__adblock__/us/<doc>.<n>.js`| GET      | per-document userscript bundle, single use, `no-store`, see [`crate::gm`] |
//! | `/__adblock__/gm/v1/*`       | POST, GET | userscript backend (`resource` is GET); capability token + same-origin checks, see [`crate::gm`] |
//! | `/__adblock__/cc`            | POST      | class/id selectors; JSON only (forces a CORS preflight for foreign pages), per-page HMAC token bound to the host, page URL must be on that host, same-origin fetch metadata, 64 KiB cap |
//!
//! Static responses use `Cross-Origin-Resource-Policy: cross-origin` so they load under
//! `Cross-Origin-Embedder-Policy: require-corp` (also from sandboxed, opaque-origin frames); the
//! beacon answers `same-origin` only and sends no CORS headers.

use crate::inject::{full_body, ProxyBody};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use filter_engine::SharedEngine;
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Largest `/__adblock__/cc` request body accepted.
pub const MAX_INTERNAL_BODY: usize = 64 * 1024;
/// Validity of a page token.
const TOKEN_TTL: Duration = Duration::from_secs(24 * 3600);
/// Number of generated scriptlet bundles kept for the pages that reference them.
const SCRIPTLET_CACHE: u64 = 2048;

const BOOT_JS: &str = include_str!("../assets/boot.js");

static BOOT: LazyLock<(String, String)> = LazyLock::new(|| {
    let hash = short_hash(BOOT_JS.as_bytes());
    let path = format!("{}boot.{hash}.js", crate::csp::INTERNAL_PREFIX);
    (hash, path)
});

/// Path of the content-hashed `boot.js` for this build.
pub fn boot_path() -> &'static str {
    &BOOT.1
}

const PANEL_JS: &str = include_str!("../assets/panel.js");

static PANEL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{}panel.{}.js",
        crate::csp::INTERNAL_PREFIX,
        short_hash(PANEL_JS.as_bytes())
    )
});

/// Path of the content-hashed panel script (fetched only when the hotkey is first used).
pub fn panel_path() -> &'static str {
    &PANEL
}

static GM_RUNTIME: LazyLock<(String, String)> = LazyLock::new(|| {
    let js = userscript_engine::bundle::runtime_script();
    let path = format!(
        "{}gm.{}.js",
        crate::csp::INTERNAL_PREFIX,
        short_hash(js.as_bytes())
    );
    (js, path)
});

/// Path of the content-hashed shared GM runtime script (loaded once per document that has
/// userscripts).
pub fn gm_runtime_path() -> &'static str {
    &GM_RUNTIME.1
}

fn short_hash(data: &[u8]) -> String {
    let d = Sha256::digest(data);
    d[..12].iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    k[..key.len().min(64)].copy_from_slice(&key[..key.len().min(64)]);
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new()
        .chain_update(ipad)
        .chain_update(msg)
        .finalize();
    Sha256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize()
        .into()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// State behind the internal endpoints: the token key and the scriptlet bundles by hash.
pub struct Internal {
    key: [u8; 32],
    scriptlets: moka::sync::Cache<String, Arc<str>>,
    unsupported: parking_lot::Mutex<std::collections::BTreeMap<String, u64>>,
    /// Userscript delivery and backend state.
    pub gm: Arc<crate::gm::GmHost>,
    /// The in-page panel's state endpoint and the reserved confirmation host.
    pub panel: Arc<crate::panel::PanelHost>,
    /// Policy-violation reports accepted so far per document (rate limit).
    pv_counts: moka::sync::Cache<String, Arc<std::sync::atomic::AtomicU32>>,
}

/// Violation reports accepted per document.
const PV_PER_DOC: u32 = 64;
/// Largest violation report accepted.
const PV_MAX_BODY: usize = 8 * 1024;

impl Default for Internal {
    fn default() -> Self {
        Self::new()
    }
}

impl Internal {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self {
            key,
            scriptlets: moka::sync::Cache::builder()
                .max_capacity(SCRIPTLET_CACHE)
                .time_to_idle(Duration::from_secs(3600))
                .build(),
            unsupported: Default::default(),
            gm: Arc::new(crate::gm::GmHost::new()),
            panel: Arc::default(),
            pv_counts: moka::sync::Cache::builder()
                .max_capacity(16_384)
                .time_to_idle(Duration::from_secs(600))
                .build(),
        }
    }

    /// Per-document token for the violation report endpoint: `exp.doc.mac`, bound to `host`.
    pub fn doc_token(&self, host: &str) -> String {
        let mut r = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut r);
        let doc: String = r.iter().map(|b| format!("{b:02x}")).collect();
        let exp = now_secs() + TOKEN_TTL.as_secs();
        format!("{exp:x}.{doc}.{}", self.mac(&format!("{host}\n{doc}"), exp))
    }

    /// Validate a [`Self::doc_token`]; returns the document id.
    fn doc_token_valid<'a>(&self, token: &'a str, host: &str) -> Option<&'a str> {
        let mut it = token.splitn(3, '.');
        let (exp_hex, doc, mac) = (it.next()?, it.next()?, it.next()?);
        let exp = u64::from_str_radix(exp_hex, 16).ok()?;
        if exp < now_secs() || doc.len() != 16 || !doc.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let want = self.mac(&format!("{host}\n{doc}"), exp);
        (want.len() == mac.len()
            && want
                .bytes()
                .zip(mac.bytes())
                .fold(0u8, |a, (x, y)| a | (x ^ y))
                == 0)
            .then_some(doc)
    }

    /// `POST /__adblock__/pv?d=<doc token>`: a browser `report-uri` report for the policy the
    /// proxy added. Accepted only when the token is ours for this host, the report names that
    /// host, and its `original-policy` is the very header we generated for the page (the site's
    /// own policy is never forwarded). Bounded: 8 KiB, 64 reports per document.
    async fn pv(
        &self,
        req: Request<Incoming>,
        host: &str,
        rctx: &crate::request_ctx::RequestCtx,
    ) -> Response<ProxyBody> {
        let deny = |s| plain(s, "no-store", "same-origin");
        if req.method() != Method::POST {
            return deny(StatusCode::METHOD_NOT_ALLOWED);
        }
        let Some(sc) = rctx
            .profile
            .load()
            .script_control
            .clone()
            .filter(|sc| sc.enabled())
        else {
            return deny(StatusCode::NOT_FOUND);
        };
        let h: &HeaderMap = req.headers();
        if h.get("sec-fetch-site").and_then(|v| v.to_str().ok()) == Some("cross-site") {
            return deny(StatusCode::FORBIDDEN);
        }
        let ctype_ok = h
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(|m| m.trim().to_ascii_lowercase())
            .is_some_and(|m| {
                matches!(
                    m.as_str(),
                    "application/csp-report" | "application/json" | "application/reports+json"
                )
            });
        if !ctype_ok {
            return deny(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        if h.get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|n| n > PV_MAX_BODY)
        {
            return deny(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let token = req
            .uri()
            .query()
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("d=")))
            .unwrap_or("")
            .to_string();
        let Some(doc) = self.doc_token_valid(&token, host).map(str::to_string) else {
            return deny(StatusCode::FORBIDDEN);
        };
        let n = self
            .pv_counts
            .get_with(doc, || Arc::new(std::sync::atomic::AtomicU32::new(0)))
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n >= PV_PER_DOC {
            return deny(StatusCode::TOO_MANY_REQUESTS);
        }
        let bytes = match Limited::new(req.into_body(), PV_MAX_BODY).collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => return deny(StatusCode::PAYLOAD_TOO_LARGE),
        };
        #[derive(serde::Deserialize)]
        struct Wrap {
            #[serde(rename = "csp-report")]
            r: Report,
        }
        #[derive(serde::Deserialize)]
        struct Report {
            #[serde(rename = "document-uri", default)]
            document_uri: String,
            #[serde(rename = "blocked-uri", default)]
            blocked_uri: String,
            #[serde(rename = "effective-directive", default)]
            effective_directive: String,
            #[serde(rename = "violated-directive", default)]
            violated_directive: String,
            #[serde(rename = "original-policy", default)]
            original_policy: String,
            #[serde(default)]
            disposition: String,
        }
        let Ok(Wrap { r }) = serde_json::from_slice::<Wrap>(&bytes) else {
            return deny(StatusCode::BAD_REQUEST);
        };
        let Some(u) = url::Url::parse(&r.document_uri)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https"))
        else {
            return deny(StatusCode::FORBIDDEN);
        };
        let same_host = u
            .host_str()
            .and_then(crate::authority::normalize_host)
            .is_some_and(|h| h == host);
        if !same_host {
            return deny(StatusCode::FORBIDDEN);
        }
        let port = u.port_or_known_default().unwrap_or(443);
        let ours = sc
            .document(u.scheme(), &crate::authority::url_host(host), port)
            .and_then(|e| e.csp.clone())
            .is_some_and(|t| normalize_policy(&r.original_policy) == t);
        if !ours {
            // The site's own policy (or a stale copy of ours): not ours to report.
            return deny(StatusCode::NO_CONTENT);
        }
        let effective = if r.effective_directive.is_empty() {
            r.violated_directive
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string()
        } else {
            r.effective_directive
        };
        sc.store().record_violation(
            sc.profile_name(),
            &script_policy::CspViolation {
                document_uri: r.document_uri,
                effective_directive: effective,
                blocked_uri: r.blocked_uri,
                disposition: if r.disposition.is_empty() {
                    "enforce".into()
                } else {
                    r.disposition
                },
            },
        );
        deny(StatusCode::NO_CONTENT)
    }

    /// Per-page token for the beacon, bound to `host` (name without port) and an expiry.
    pub fn token_for(&self, host: &str) -> String {
        let exp = now_secs() + TOKEN_TTL.as_secs();
        format!("{exp:x}.{}", self.mac(host, exp))
    }

    fn mac(&self, host: &str, exp: u64) -> String {
        let msg = format!("{}\n{exp}", host.to_ascii_lowercase());
        URL_SAFE_NO_PAD.encode(&hmac_sha256(&self.key, msg.as_bytes())[..16])
    }

    fn token_valid(&self, token: &str, host: &str) -> bool {
        let Some((exp_hex, mac)) = token.split_once('.') else {
            return false;
        };
        let Ok(exp) = u64::from_str_radix(exp_hex, 16) else {
            return false;
        };
        if exp < now_secs() {
            return false;
        }
        let want = self.mac(host, exp);
        // Constant-time comparison.
        want.len() == mac.len()
            && want
                .bytes()
                .zip(mac.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }

    /// Store a scriptlet bundle and return its URL path (`/__adblock__/s/<hash>.js`).
    pub fn put_scriptlet(&self, code: &str) -> String {
        let hash: String = hmac_sha256(&self.key, code.as_bytes())[..12]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if !self.scriptlets.contains_key(&hash) {
            self.scriptlets.insert(hash.clone(), Arc::from(code));
        }
        format!("{}s/{hash}.js", crate::csp::INTERNAL_PREFIX)
    }

    /// Count one "unsupported scriptlet <name>" report (names bounded in number and length).
    fn note_unsupported(&self, note: &str) {
        const MAX_NAMES: usize = 256;
        let Some(name) = note.strip_prefix("unsupported scriptlet ") else {
            return;
        };
        let name: String = name.chars().filter(|c| !c.is_control()).take(64).collect();
        let mut m = self.unsupported.lock();
        if m.len() < MAX_NAMES || m.contains_key(&name) {
            *m.entry(name).or_insert(0) += 1;
        }
    }

    /// Scriptlet names pages reported as unsupported, with report counts (one per page load).
    pub fn unsupported_scriptlets(&self) -> Vec<(String, u64)> {
        self.unsupported
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    /// Answer an internal request. `host` is the request's normalised host name (no port);
    /// `origin` is the connection authority in `Origin`-header form.
    pub async fn handle(
        &self,
        req: Request<Incoming>,
        host: &str,
        origin: &str,
        rctx: &crate::request_ctx::RequestCtx,
        up: &crate::gm::Upstream<'_>,
    ) -> Response<ProxyBody> {
        let profile = rctx.profile.load_full();
        let engine: &SharedEngine = &profile.engine;
        if req.uri().path() == format!("{}pv", crate::csp::INTERNAL_PREFIX) {
            return self.pv(req, host, rctx).await;
        }
        // Refused outright while ad blocking is off for the profile.
        if !engine.is_enabled() {
            return plain(StatusCode::NOT_FOUND, "no-store", "same-origin");
        }
        let path = req.uri().path().to_string();
        let rest = path
            .strip_prefix(crate::csp::INTERNAL_PREFIX)
            .unwrap_or_default();
        let method = req.method().clone();

        if rest == "panel/state" {
            return self.panel_state(req, host, rctx).await;
        }
        if rest == "cc" {
            return self.cc(req, host, &profile).await;
        }
        if let Some(r) = rest.strip_prefix("us/") {
            return match profile.userscript_manager() {
                Some(m) => self.gm.serve_chunk(
                    m,
                    &crate::gm::Caller {
                        manager: m,
                        host,
                        origin,
                        profile: &profile.name,
                    },
                    &method,
                    req.headers(),
                    r,
                ),
                None => plain(StatusCode::NOT_FOUND, "no-store", "same-origin"),
            };
        }
        if let Some(r) = rest.strip_prefix("gm/v1/") {
            return match profile.userscript_manager() {
                Some(m) => {
                    let caller = crate::gm::Caller {
                        manager: m,
                        host,
                        origin,
                        profile: &profile.name,
                    };
                    self.gm.handle_gm(req, &caller, up, r).await
                }
                None => plain(StatusCode::NOT_FOUND, "no-store", "same-origin"),
            };
        }
        let asset: Option<(Bytes, &'static str)> = if path == boot_path() {
            Some((Bytes::from_static(BOOT_JS.as_bytes()), "immutable"))
        } else if path == panel_path() {
            Some((Bytes::from_static(PANEL_JS.as_bytes()), "immutable"))
        } else if path == gm_runtime_path() {
            Some((Bytes::from(GM_RUNTIME.0.clone()), "immutable"))
        } else if let Some(h) = rest.strip_prefix("s/").and_then(|r| r.strip_suffix(".js")) {
            self.scriptlets
                .get(h)
                .map(|code| (Bytes::copy_from_slice(code.as_bytes()), "immutable"))
        } else {
            None
        };
        let Some((body, _)) = asset else {
            return plain(StatusCode::NOT_FOUND, "no-store", "same-origin");
        };
        if method != Method::GET && method != Method::HEAD {
            let mut r = plain(StatusCode::METHOD_NOT_ALLOWED, "no-store", "same-origin");
            r.headers_mut().insert(
                "allow",
                hyper::header::HeaderValue::from_static("GET, HEAD"),
            );
            return r;
        }
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/javascript; charset=utf-8")
            .header("cache-control", "public, max-age=31536000, immutable")
            .header("x-content-type-options", "nosniff")
            .header("cross-origin-resource-policy", "cross-origin")
            .body(full_body(body))
            .expect("static internal response")
    }

    /// `POST /__adblock__/panel/state`: the read-only data the in-page panel shows. Guarded like
    /// `cc` (JSON, page token bound to the host, same-origin, size cap, page URL on that host).
    async fn panel_state(
        &self,
        req: Request<Incoming>,
        host: &str,
        rctx: &crate::request_ctx::RequestCtx,
    ) -> Response<ProxyBody> {
        let deny = |s| plain(s, "no-store", "same-origin");
        if req.method() != Method::POST {
            return deny(StatusCode::METHOD_NOT_ALLOWED);
        }
        let h: &HeaderMap = req.headers();
        let is_json = h
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
            });
        if !is_json {
            return deny(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        if h.get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v != "same-origin")
        {
            return deny(StatusCode::FORBIDDEN);
        }
        if !h
            .get("x-adblock-token")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| self.token_valid(t, host))
        {
            return deny(StatusCode::FORBIDDEN);
        }
        let bytes = match Limited::new(req.into_body(), 4096).collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => return deny(StatusCode::PAYLOAD_TOO_LARGE),
        };
        #[derive(serde::Deserialize)]
        struct Req {
            url: String,
        }
        let Ok(Req { url }) = serde_json::from_slice::<Req>(&bytes) else {
            return deny(StatusCode::BAD_REQUEST);
        };
        let same_host = url::Url::parse(&url)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https"))
            .and_then(|u| crate::authority::normalize_host(u.host_str()?))
            .is_some_and(|h| h == host);
        if !same_host {
            return deny(StatusCode::FORBIDDEN);
        }
        let Some(state) = self.panel.state(rctx, &url) else {
            return deny(StatusCode::NOT_FOUND);
        };
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .header("cache-control", "no-store")
            .header("x-content-type-options", "nosniff")
            .header("cross-origin-resource-policy", "same-origin")
            .body(full_body(Bytes::from(state.to_string())))
            .expect("panel state response")
    }

    /// HMAC over `msg` with the process key (no case folding), URL-safe base64.
    pub(crate) fn sign(&self, msg: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(&hmac_sha256(&self.key, msg)[..16])
    }

    async fn cc(
        &self,
        req: Request<Incoming>,
        host: &str,
        profile: &crate::request_ctx::Profile,
    ) -> Response<ProxyBody> {
        let deny = |s| plain(s, "no-store", "same-origin");
        if req.method() != Method::POST {
            let mut r = deny(StatusCode::METHOD_NOT_ALLOWED);
            r.headers_mut()
                .insert("allow", hyper::header::HeaderValue::from_static("POST"));
            return r;
        }
        let h: &HeaderMap = req.headers();
        if h.get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|n| n > MAX_INTERNAL_BODY)
        {
            return deny(StatusCode::PAYLOAD_TOO_LARGE);
        }
        // `application/json` is not a CORS-safelisted type, so a foreign page cannot forge this
        // request without a preflight (which is never answered).
        let is_json = h
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
            });
        if !is_json {
            return deny(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        if h.get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v != "same-origin")
        {
            return deny(StatusCode::FORBIDDEN);
        }
        let token_ok = h
            .get("x-adblock-token")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| self.token_valid(t, host));
        if !token_ok {
            return deny(StatusCode::FORBIDDEN);
        }
        let bytes = match Limited::new(req.into_body(), MAX_INTERNAL_BODY)
            .collect()
            .await
        {
            Ok(c) => c.to_bytes(),
            Err(e)
                if e.downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some() =>
            {
                return deny(StatusCode::PAYLOAD_TOO_LARGE)
            }
            Err(_) => return deny(StatusCode::BAD_REQUEST),
        };
        #[derive(serde::Deserialize)]
        struct CcReq {
            url: String,
            #[serde(default)]
            classes: Vec<String>,
            #[serde(default)]
            ids: Vec<String>,
            /// "unsupported scriptlet <name>" notes from the in-page runtime.
            #[serde(default)]
            unsupported: Vec<String>,
        }
        let Ok(parsed) = serde_json::from_slice::<CcReq>(&bytes) else {
            return deny(StatusCode::BAD_REQUEST);
        };
        // The token is bound to the page's host: the URL a page asks about must be that host too,
        // or any page could probe which cosmetic rules the user has for other sites.
        let same_host = url::Url::parse(&parsed.url)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https"))
            .and_then(|u| crate::authority::normalize_host(u.host_str()?))
            .is_some_and(|h| h == host);
        if !same_host {
            return deny(StatusCode::FORBIDDEN);
        }
        for note in parsed.unsupported.iter().take(32) {
            self.note_unsupported(note);
        }
        let selectors =
            crate::filtering::dynamic_selectors(profile, &parsed.url, &parsed.classes, &parsed.ids);
        let json = serde_json::json!({ "selectors": selectors }).to_string();
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .header("cache-control", "no-store")
            .header("x-content-type-options", "nosniff")
            .header("cross-origin-resource-policy", "same-origin")
            .body(full_body(Bytes::from(json)))
            .expect("internal json response")
    }
}

/// A reported policy with the per-document nonce and token replaced by the cache markers, so it
/// can be compared with the cached header text.
fn normalize_policy(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    let mut rest = p;
    while let Some(i) = rest.find("'nonce-") {
        out.push_str(&rest[..i + 7]);
        let after = &rest[i + 7..];
        let end = after.find('\'').unwrap_or(after.len());
        out.push_str(crate::scriptctl::NONCE_MARK);
        rest = &after[end..];
    }
    out.push_str(rest);
    match out.find("/pv?d=") {
        Some(i) => {
            let tail = &out[i + 6..];
            let end = tail.find([';', ' ']).unwrap_or(tail.len());
            format!(
                "{}{}{}",
                &out[..i + 6],
                crate::scriptctl::DOC_MARK,
                &tail[end..]
            )
        }
        None => out,
    }
}

/// An empty-bodied answer with the standard hardening headers.
fn plain(status: StatusCode, cache: &str, corp: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header("cache-control", cache)
        .header("x-content-type-options", "nosniff")
        .header("cross-origin-resource-policy", corp)
        .body(full_body(Bytes::new()))
        .expect("internal plain response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_roundtrip_and_binding() {
        let i = Internal::new();
        let t = i.token_for("Example.test");
        assert!(i.token_valid(&t, "example.test"));
        assert!(!i.token_valid(&t, "other.test"));
        assert!(!i.token_valid("", "example.test"));
        assert!(!i.token_valid("ffffffffff.AAAA", "example.test"));
        // tampered expiry
        let (_, mac) = t.split_once('.').unwrap();
        assert!(!i.token_valid(&format!("fffffffffff.{mac}"), "example.test"));
        // another process key
        assert!(!Internal::new().token_valid(&t, "example.test"));
    }

    #[test]
    fn hmac_known_vector() {
        // RFC 4231 test case 2.
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn unsupported_notes_are_counted_and_bounded() {
        let i = Internal::new();
        i.note_unsupported("unsupported scriptlet foo");
        i.note_unsupported("unsupported scriptlet foo");
        i.note_unsupported("bogus");
        assert_eq!(i.unsupported_scriptlets(), vec![("foo".to_string(), 2)]);
    }

    #[test]
    fn boot_defines_runtime_hook() {
        assert!(BOOT_JS.contains("__argusRuntime"));
        assert!(BOOT_JS.contains("unsupported scriptlet "));
    }

    #[test]
    fn boot_path_is_content_hashed() {
        assert!(boot_path().starts_with("/__adblock__/boot."));
        assert!(boot_path().ends_with(".js"));
    }

    #[test]
    fn scriptlet_urls_cannot_be_guessed_from_their_content() {
        // A keyed hash: a page cannot compute another site's bundle URL from a known rule set
        // and probe whether the user visited that site.
        let (a, b) = (Internal::new(), Internal::new());
        assert_ne!(a.put_scriptlet("a()"), b.put_scriptlet("a()"));
        let unkeyed = format!("{}s/{}.js", crate::csp::INTERNAL_PREFIX, short_hash(b"a()"));
        assert_ne!(a.put_scriptlet("a()"), unkeyed);
    }

    #[test]
    fn scriptlets_stored_by_hash() {
        let i = Internal::new();
        let p = i.put_scriptlet("a()");
        assert_eq!(p, i.put_scriptlet("a()"));
        assert_ne!(p, i.put_scriptlet("b()"));
    }
}

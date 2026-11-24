//! Userscript delivery and the `/__adblock__/gm/` backend (protocol: `docs/USERSCRIPT-PROTOCOL.md`).
//!
//! * Delivery: for an HTML document the proxy asks the profile's [`ScriptIndex`] which scripts
//!   match, registers a short-lived per-document record ([`DocStore`]) and puts one same-origin
//!   `<script src="/__adblock__/us/<doc>.<n>.js">` per script at the top of `<head>`. The bundle
//!   (runtime + one script + its capability token and stored values) is generated when that URL
//!   is fetched, served `no-store`, once. Tokens therefore never appear in a URL or in the
//!   document's markup, only in the response body that the page's own `<script>` consumes.
//!   One file per script means a syntax error in one cannot break another.
//! * Backend: every `/__adblock__/gm/v1/*` call is authenticated (capability token + `Origin` +
//!   fetch metadata), then authorised from the *stored* script, never from the token or body.
//! * Outbound `GM_xmlhttpRequest` / `GM_download` traffic uses the proxy's own upstream client
//!   under the destination policy, re-checks `@connect` on every redirect hop, streams the
//!   response, and is not run through the filter engine (script managers do not filter either).

use crate::ext_bridge::{ExtHub, JobEvent, Route, Wait};
use crate::inject::{full_body, ProxyBody};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{HeaderMap, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use userscript_engine::backend::{
    next_hop, CookieOp, ErrorCode, GmError, GmResult, Redirect, ScriptCtx, XhrRequest,
};
use userscript_engine::bundle::{self, BundleOptions};
use userscript_engine::metadata::RunAt;
use userscript_engine::token::{self, ScriptRecord, TokenClaims};
use userscript_engine::{ScriptIndex, UserscriptManager};

/// Per-document records kept (oldest evicted first).
pub const DOC_CAP: usize = 4096;
/// A document's bundle URLs must be fetched within this long.
pub const DOC_TTL: Duration = Duration::from_secs(60);
/// Token lifetime.
const TOKEN_TTL: u64 = 3600;
/// Cap on JSON request bodies.
const JSON_CAP: usize = 2 * 1024 * 1024;
/// Cap on the `xhr` meta block.
const META_CAP: usize = 64 * 1024;
/// Cap on a streamed `xhr` response body.
pub const MAX_RESPONSE: u64 = 256 * 1024 * 1024;
/// Concurrent outbound requests per script and per profile.
pub const MAX_XHR_PER_SCRIPT: usize = 8;
pub const MAX_XHR_PER_PROFILE: usize = 32;
/// Concurrent JSON calls per script and per profile (they hold a slot only while the body is read).
pub const MAX_JSON_PER_SCRIPT: usize = 32;
pub const MAX_JSON_PER_PROFILE: usize = 128;
/// Global budget for request bytes buffered under `/__adblock__/gm/` (the worst case, in bytes).
pub const BODY_BUDGET: usize = 64 * 1024 * 1024;
/// Reserved per in-flight `xhr`: the frame head, the first data frame and the bounded upload
/// channel (two frames). The upload itself is streamed and never buffered whole.
pub const XHR_RESERVE: usize = 2 * 1024 * 1024;
/// A body frame must arrive within this long once a request holds its slot.
const BODY_IDLE: Duration = Duration::from_secs(30);
/// Every `POST` route other than `xhr`.
const JSON_ROUTES: &[&str] = &[
    "values/get",
    "values/set",
    "values/delete",
    "values/list",
    "values/changes",
    "token/refresh",
    "cookie",
    "menu/sync",
    "menu/wait",
];

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- per-document state ---------------------------------------------------------------------

struct Doc {
    index: Arc<ScriptIndex>,
    /// Script ids in injection order (run-at group, then install order).
    ids: Vec<String>,
    fetched: Vec<bool>,
    /// Storage namespace the document was planned for.
    profile: String,
    host: String,
    origin: String,
    top: bool,
    created: Instant,
    /// Public document id, when the document is bound to a live extension session.
    mdoc: Option<String>,
}

/// What one bundle fetch needs.
pub struct Chunk {
    pub index: Arc<ScriptIndex>,
    pub script_id: String,
    pub origin: String,
    pub top: bool,
    pub mdoc: Option<String>,
}

/// Bounded, expiring map of documents that were handed script URLs.
pub struct DocStore {
    inner: Mutex<(HashMap<String, Doc>, VecDeque<String>)>,
    cap: usize,
    ttl: Duration,
}

impl DocStore {
    pub fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            inner: Mutex::new((HashMap::new(), VecDeque::new())),
            cap,
            ttl,
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn insert(&self, doc: Doc) -> String {
        use base64::Engine as _;
        use rand::RngCore;
        let mut raw = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let mut g = self.inner.lock();
        let (map, order) = &mut *g;
        // Oldest first: expired ones, then whatever exceeds the cap.
        while let Some(front) = order.front() {
            let expired = map
                .get(front)
                .is_none_or(|d| d.created.elapsed() > self.ttl);
            if expired || order.len() >= self.cap {
                let f = order.pop_front().expect("front");
                map.remove(&f);
            } else {
                break;
            }
        }
        order.push_back(id.clone());
        map.insert(id.clone(), doc);
        id
    }

    /// Take chunk `n` of document `id` for a request to `host`. Each chunk is served once; a
    /// wrong host or profile, or an expired record, yields `None` (which does not consume the chunk).
    fn take(&self, id: &str, n: usize, host: &str, profile: &str) -> Option<Chunk> {
        let mut g = self.inner.lock();
        let (map, _) = &mut *g;
        let d = map.get_mut(id)?;
        if d.created.elapsed() > self.ttl
            || d.host != host
            || d.profile != profile
            || n >= d.ids.len()
            || d.fetched[n]
        {
            return None;
        }
        d.fetched[n] = true;
        let chunk = Chunk {
            index: d.index.clone(),
            script_id: d.ids[n].clone(),
            origin: d.origin.clone(),
            top: d.top,
            mdoc: d.mdoc.clone(),
        };
        if d.fetched.iter().all(|f| *f) {
            map.remove(id);
        }
        Some(chunk)
    }
}

/// Result of matching a document against the profile's scripts.
pub struct DocPlan {
    /// `<script src>` paths, in order.
    pub srcs: Vec<String>,
    /// Some script talks to the backend (the policy must allow `fetch` to `/__adblock__/`).
    pub connect: bool,
    /// Some script adds styles (`GM_addStyle`, `@unwrap`): needs the style nonce.
    pub style: bool,
    /// Public document id (`Server-Timing: argus;desc="<mdoc>"`).
    pub mdoc: Option<String>,
    /// The document is bound to a live extension session: no in-page menu button.
    pub ext_bound: bool,
}

fn group(r: RunAt) -> u8 {
    match r {
        RunAt::DocumentStart => 0,
        RunAt::DocumentBody => 1,
        RunAt::DocumentEnd => 2,
        _ => 3,
    }
}

// ---- host ------------------------------------------------------------------------------------

/// Outbound pieces the xhr executor borrows from the proxy context.
pub struct Upstream<'a> {
    pub client: &'a reqwest::Client,
    pub strict_client: &'a reqwest::Client,
    pub policy: &'a crate::policy::DestPolicy,
    /// Code-only dial override (tests); IP-literal hosts are aimed at it explicitly.
    pub resolve_all_to: Option<std::net::IpAddr>,
}

/// Where a request to `/__adblock__/gm|us/…` came from.
pub struct Caller<'a> {
    pub manager: &'a Arc<UserscriptManager>,
    /// Request host (lowercase, no port).
    pub host: &'a str,
    /// Origin of the connection's authority in `Origin`-header form.
    pub origin: &'a str,
    /// The requesting profile's name: the namespace of tokens, GM values and cookies.
    pub profile: &'a str,
}

#[derive(Default)]
struct Counts {
    per_script: HashMap<String, usize>,
    /// In-flight requests per profile name, so one profile cannot use up everyone's slots.
    per_profile: HashMap<String, usize>,
}

#[derive(Default)]
struct Limits {
    xhr: Counts,
    json: Counts,
}

#[derive(Clone, Copy)]
enum Kind {
    Xhr,
    Json,
}

/// Releases a request slot on drop.
struct Permit {
    host: Arc<GmHost>,
    profile: String,
    script: String,
    kind: Kind,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut l = self.host.limits.lock();
        let c = match self.kind {
            Kind::Xhr => &mut l.xhr,
            Kind::Json => &mut l.json,
        };
        if let Some(n) = c.per_profile.get_mut(&self.profile) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                c.per_profile.remove(&self.profile);
            }
        }
        if let Some(n) = c.per_script.get_mut(&self.script) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                c.per_script.remove(&self.script);
            }
        }
    }
}

type Held = (Permit, OwnedSemaphorePermit);

/// Grants that give a script network, download or cookie reach beyond the page.
pub fn is_privileged(s: &userscript_engine::Userscript) -> bool {
    s.metadata.effective_grants().iter().any(|g| {
        matches!(
            g.as_str(),
            "gm_xmlhttprequest" | "gm_download" | "gm_cookie"
        )
    })
}

pub struct GmHost {
    sw_policy: std::sync::atomic::AtomicU8,
    ext: Arc<ExtHub>,
    pub docs: DocStore,
    limits: Mutex<Limits>,
    budget: Arc<Semaphore>,
}

impl Default for GmHost {
    fn default() -> Self {
        Self::new()
    }
}

struct Authed {
    profile: String,
    idx: Arc<ScriptIndex>,
    id: String,
    origin: String,
    page_host: String,
}

impl Authed {
    fn script(&self) -> &userscript_engine::Userscript {
        &self.idx.get(&self.id).expect("authenticated").script
    }
    fn ctx(&self) -> ScriptCtx<'_> {
        ScriptCtx {
            profile: &self.profile,
            script: self.script(),
            page_host: &self.page_host,
        }
    }
}

fn gm_json(status: u16, body: Value) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(CONTENT_TYPE, "application/json")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .header("cross-origin-resource-policy", "same-origin")
        .body(full_body(Bytes::from(body.to_string())))
        .expect("gm json response")
}

fn gm_err(e: &GmError) -> Response<ProxyBody> {
    gm_json(e.code.http_status(), e.to_json())
}

fn forbidden() -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .header("cross-origin-resource-policy", "same-origin")
        .body(full_body(Bytes::new()))
        .expect("forbidden")
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

fn media_is(h: &HeaderMap, want: &str) -> bool {
    header(h, "content-type").is_some_and(|v| {
        v.split(';')
            .next()
            .is_some_and(|m| m.trim().eq_ignore_ascii_case(want))
    })
}

/// Fetch-metadata and `Origin` checks shared by every endpoint. `Origin` is mandatory for
/// POSTs (browsers always send it there); the `resource` GET relies on `Sec-Fetch-Site`.
fn same_origin_ok(h: &HeaderMap, origin: &str, post: bool) -> bool {
    if header(h, "sec-fetch-site").is_some_and(|v| v != "same-origin") {
        return false;
    }
    match header(h, "origin") {
        Some(o) => o == origin,
        None => !post && header(h, "sec-fetch-site") == Some("same-origin"),
    }
}

fn frame(t: u8, payload: &[u8]) -> Bytes {
    let mut v = Vec::with_capacity(5 + payload.len());
    v.push(t);
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload);
    Bytes::from(v)
}

fn err_frame(kind: &str, code: &str, msg: &str) -> Bytes {
    frame(
        4,
        json!({"kind": kind, "code": code, "message": msg})
            .to_string()
            .as_bytes(),
    )
}

fn frames_response(body: ProxyBody) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-gm-frames")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .header("cross-origin-resource-policy", "same-origin")
        .body(body)
        .expect("frames response")
}

fn single_error_frame(kind: &str, code: &str, msg: &str) -> Response<ProxyBody> {
    frames_response(full_body(err_frame(kind, code, msg)))
}

impl GmHost {
    pub fn new() -> Self {
        Self {
            sw_policy: std::sync::atomic::AtomicU8::new(
                common::config::ServiceWorkerPolicy::default() as u8,
            ),
            ext: ExtHub::shared(),
            docs: DocStore::new(DOC_CAP, DOC_TTL),
            limits: Mutex::new(Limits::default()),
            budget: Arc::new(Semaphore::new(BODY_BUDGET)),
        }
    }

    /// The extension bridge hub.
    pub fn ext(&self) -> &Arc<ExtHub> {
        &self.ext
    }

    /// Where a request or cookie call of `script` goes once its own checks (grant, `@connect`,
    /// method and header rules, destination policy) have passed: only a non-anonymous call of a
    /// script approved for browser logins, from a document bound to a live extension session
    /// that holds a permission for `host`, goes to the browser; everything else uses the
    /// script's own jar. A fall back of an approved script is remembered for its page.
    #[allow(clippy::too_many_arguments)]
    pub fn credentialed_route(
        &self,
        script: &userscript_engine::Userscript,
        profile: &str,
        origin: &str,
        anonymous: bool,
        download: bool,
        manual_redirect: bool,
        mdoc: Option<&str>,
        host: &str,
    ) -> Route {
        if anonymous || download {
            return Route::Jar(crate::ext_bridge::Fallback::Anonymous);
        }
        if !script.browser_cookies {
            return Route::Jar(crate::ext_bridge::Fallback::NotApproved);
        }
        if manual_redirect {
            return Route::Jar(crate::ext_bridge::Fallback::ManualRedirect);
        }
        let r = self.ext.route(mdoc, profile, origin, &script.id, host);
        self.ext
            .note_route(profile, &script.id, matches!(r, Route::Jar(_)));
        r
    }

    pub fn set_sw_policy(&self, p: common::config::ServiceWorkerPolicy) {
        self.sw_policy
            .store(p as u8, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn sw_policy(&self) -> common::config::ServiceWorkerPolicy {
        use common::config::ServiceWorkerPolicy::*;
        match self.sw_policy.load(std::sync::atomic::Ordering::Relaxed) {
            x if x == Allow as u8 => Allow,
            x if x == Block as u8 => Block,
            _ => BlockWhenPrivileged,
        }
    }

    /// Must service workers be kept off `host`? (`block`: always; `block_when_privileged`: when a
    /// script with network, download or cookie grants may run there.)
    pub fn blocks_service_workers(
        &self,
        manager: &UserscriptManager,
        profile: &str,
        host: &str,
    ) -> bool {
        self.blocks_service_workers_in(&manager.index_for(profile), host)
    }

    /// [`Self::blocks_service_workers`] over an index the caller already holds (a profile keeps
    /// its own handle, so the request path takes no lock).
    pub fn blocks_service_workers_in(&self, index: &ScriptIndex, host: &str) -> bool {
        use common::config::ServiceWorkerPolicy::*;
        match self.sw_policy() {
            Allow => false,
            Block => !index.is_empty(),
            BlockWhenPrivileged => index.for_host(host).any(|c| is_privileged(&c.script)),
        }
    }

    // ---- delivery ---------------------------------------------------------------------------

    /// Match `url` against the scripts of storage namespace `profile` and register the document.
    /// `None` (no allocation beyond the index probe) when nothing applies.
    pub fn plan_document(
        &self,
        manager: &UserscriptManager,
        profile: &str,
        host: &str,
        url: &str,
        origin: &str,
        is_top_frame: bool,
    ) -> Option<DocPlan> {
        self.plan_document_in(
            &manager.index_for(profile),
            profile,
            host,
            url,
            origin,
            is_top_frame,
        )
    }

    /// [`Self::plan_document`] over the index of `profile` (the storage namespace) the caller
    /// already holds. The registered document remembers the namespace: its chunks are served
    /// only to requests of the same profile.
    pub fn plan_document_in(
        &self,
        index: &Arc<ScriptIndex>,
        profile: &str,
        host: &str,
        url: &str,
        origin: &str,
        is_top_frame: bool,
    ) -> Option<DocPlan> {
        self.plan_document_bound(index, profile, host, url, origin, is_top_frame, None, "")
    }

    /// [`Self::plan_document_in`] for a document the request header bound to extension session
    /// `ext_session` (see [`ExtHub::bind`]).
    #[allow(clippy::too_many_arguments)]
    pub fn plan_document_bound(
        &self,
        index: &Arc<ScriptIndex>,
        profile: &str,
        host: &str,
        url: &str,
        origin: &str,
        is_top_frame: bool,
        ext_session: Option<u64>,
        store: &str,
    ) -> Option<DocPlan> {
        let guard = index;
        if guard.is_empty() {
            return None;
        }
        let mut cands = guard.candidates(host, url, is_top_frame);
        if cands.is_empty() {
            return None;
        }
        cands.sort_by_key(|c| group(c.run_at));
        let mut connect = false;
        let mut style = false;
        let ids: Vec<String> = cands
            .iter()
            .map(|c| {
                let grants = bundle::runtime_grants(&c.script.metadata);
                connect |= !grants.is_empty();
                style |= c.script.metadata.unwrap || grants.iter().any(|g| g == "gm_addstyle");
                c.script.id.clone()
            })
            .collect();
        let names: Vec<(String, String)> = cands
            .iter()
            .map(|c| (c.script.id.clone(), c.script.metadata.name.clone()))
            .collect();
        // Only a document bound to a live extension session gets a record and a public id;
        // every other page behaves exactly as without the bridge.
        let mdoc = ext_session.map(|s| self.ext.register_doc(profile, origin, names, s, store));
        let ext_bound = mdoc.is_some();
        let doc = Doc {
            index: Arc::clone(guard),
            fetched: vec![false; ids.len()],
            ids,
            profile: profile.to_string(),
            host: host.to_string(),
            origin: origin.to_string(),
            top: is_top_frame,
            created: Instant::now(),
            mdoc: mdoc.clone(),
        };
        let n = doc.ids.len();
        let id = self.docs.insert(doc);
        let srcs = (0..n)
            .map(|i| format!("{}us/{id}.{i}.js", crate::csp::INTERNAL_PREFIX))
            .collect();
        Some(DocPlan {
            srcs,
            connect,
            style,
            mdoc,
            ext_bound,
        })
    }

    /// `GET /__adblock__/us/<doc>.<n>.js`
    pub fn serve_chunk(
        &self,
        manager: &UserscriptManager,
        c: &Caller<'_>,
        method: &Method,
        headers: &HeaderMap,
        rest: &str,
    ) -> Response<ProxyBody> {
        if method != Method::GET {
            return forbidden();
        }
        // A script element sends `Sec-Fetch-Site: same-origin`; anything else is a foreign page
        // that somehow learned the URL.
        if header(headers, "sec-fetch-site").is_some_and(|v| v != "same-origin") {
            return forbidden();
        }
        // Only a `<script>` element loads a bundle; a `fetch()` (a service worker reading a URL
        // it learned from the markup, say) carries another destination, which the browser sets
        // and page code cannot change.
        if header(headers, "sec-fetch-dest").is_some_and(|v| v != "script") {
            return forbidden();
        }
        let parsed = rest
            .strip_suffix(".js")
            .and_then(|r| r.rsplit_once('.'))
            .and_then(|(id, n)| Some((id, n.parse::<usize>().ok()?)));
        let Some((id, n)) = parsed else {
            return not_found();
        };
        let Some(chunk) = self.docs.take(id, n, c.host, c.profile) else {
            return not_found();
        };
        let Some(cs) = chunk.index.get(&chunk.script_id) else {
            return not_found();
        };
        let mut values = HashMap::new();
        let ctx = ScriptCtx {
            profile: c.profile,
            script: &cs.script,
            page_host: c.host,
        };
        if let Ok(v) = manager.gm().values_get(&ctx, None) {
            values.insert(cs.script.id.clone(), v);
        }
        let mut opts = BundleOptions::new(
            c.profile,
            &chunk.origin,
            chunk.top,
            manager.token_key(),
            now_secs(),
            &values,
        );
        opts.shared_runtime = true;
        opts.mdoc = chunk.mdoc.as_deref();
        let b = bundle::generate(&[cs], &opts);
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/javascript; charset=utf-8")
            .header("cache-control", "no-store")
            .header("x-content-type-options", "nosniff")
            .header("cross-origin-resource-policy", "same-origin")
            .body(full_body(Bytes::from(b.js)))
            .expect("bundle response")
    }

    // ---- authentication ---------------------------------------------------------------------

    fn authenticate(
        &self,
        manager: &UserscriptManager,
        c: &Caller<'_>,
        tok: &str,
    ) -> GmResult<Authed> {
        let unauth = |m: &str| GmError::new(ErrorCode::Unauthorized, m);
        let id = token::claimed_script_id(tok).ok_or_else(|| unauth("bad token"))?;
        let idx: Arc<ScriptIndex> = Arc::clone(&manager.index_for(c.profile));
        let cs = idx.get(&id).ok_or_else(|| unauth("unknown script"))?;
        let caps = token::caps_hash(&cs.script.metadata, cs.script.allow_connect_all);
        let version = cs.script.metadata.version.clone().unwrap_or_default();
        token::verify(
            manager.token_key(),
            tok,
            now_secs(),
            c.profile,
            c.origin,
            |_| {
                Some(ScriptRecord {
                    version: &version,
                    caps_hash: &caps,
                })
            },
        )
        .map_err(|e| unauth(&format!("token rejected: {e:?}")))?;
        Ok(Authed {
            profile: c.profile.to_string(),
            idx,
            id,
            origin: c.origin.to_string(),
            page_host: c.host.to_ascii_lowercase(),
        })
    }

    // ---- JSON endpoints ---------------------------------------------------------------------

    /// Pure core of the JSON endpoints (everything but `xhr`/`resource`): authenticate, run, and
    /// return `(status, body)`. Separate from the hyper plumbing so it can be benchmarked.
    pub fn json_call(
        &self,
        manager: &UserscriptManager,
        c: &Caller<'_>,
        route: &str,
        token_hdr: Option<&str>,
        body: &[u8],
    ) -> (u16, Value) {
        match self.json_inner(manager, c, route, token_hdr, body) {
            Ok(v) => (200, json!({"ok": true, "result": v})),
            Err(e) => (e.code.http_status(), e.to_json()),
        }
    }

    fn json_inner(
        &self,
        manager: &UserscriptManager,
        c: &Caller<'_>,
        route: &str,
        token_hdr: Option<&str>,
        body: &[u8],
    ) -> GmResult<Value> {
        let tok =
            token_hdr.ok_or_else(|| GmError::new(ErrorCode::Unauthorized, "missing token"))?;
        let a = self.authenticate(manager, c, tok)?;
        self.json_run(manager, &a, route, body)
    }

    /// The JSON endpoints once the caller is authenticated.
    fn json_run(
        &self,
        manager: &UserscriptManager,
        a: &Authed,
        route: &str,
        body: &[u8],
    ) -> GmResult<Value> {
        let bad = |m: &str| GmError::new(ErrorCode::BadRequest, m.to_string());
        let req: Value = if body.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(body).map_err(|e| bad(&format!("bad JSON: {e}")))?
        };
        let names = |v: &Value| -> GmResult<Option<Vec<String>>> {
            match v {
                Value::Null => Ok(None),
                Value::Array(a) => a
                    .iter()
                    .map(|x| {
                        x.as_str()
                            .map(str::to_string)
                            .ok_or_else(|| bad("names must be strings"))
                    })
                    .collect::<GmResult<Vec<_>>>()
                    .map(Some),
                _ => Err(bad("names must be an array or null")),
            }
        };
        let gm = manager.gm();
        let ctx = a.ctx();
        match route {
            "values/get" => {
                let n = names(req.get("names").unwrap_or(&Value::Null))?;
                Ok(Value::Object(gm.values_get(&ctx, n.as_deref())?))
            }
            "values/set" => {
                let vals = req
                    .get("values")
                    .and_then(Value::as_object)
                    .ok_or_else(|| bad("values must be an object"))?;
                let v: Vec<(String, Value)> =
                    vals.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                gm.values_set(&ctx, v, req.get("src").and_then(Value::as_str))?;
                Ok(Value::Null)
            }
            "values/delete" => {
                let n = names(req.get("names").unwrap_or(&Value::Null))?
                    .ok_or_else(|| bad("names required"))?;
                gm.values_delete(&ctx, &n, req.get("src").and_then(Value::as_str))?;
                Ok(Value::Null)
            }
            "values/list" => Ok(json!(gm.values_list(&ctx)?)),
            "values/changes" => {
                let since = req.get("since").and_then(Value::as_u64);
                gm.values_changes(&ctx, since)
                    .map(|c| serde_json::to_value(c).unwrap_or(Value::Null))
            }
            "token/refresh" => {
                if !a.script().enabled {
                    return Err(GmError::new(ErrorCode::Disabled, "script is disabled"));
                }
                let s = a.script();
                let caps = token::caps_hash(&s.metadata, s.allow_connect_all);
                let exp = now_secs() + TOKEN_TTL;
                let t = token::mint(
                    manager.token_key(),
                    &TokenClaims {
                        profile: &a.profile,
                        script_id: &s.id,
                        script_version: s.metadata.version.as_deref().unwrap_or(""),
                        origin: &a.origin,
                        caps_hash: &caps,
                        exp,
                    },
                );
                Ok(json!({"token": t, "exp": exp}))
            }
            "cookie" => {
                let op: CookieOp =
                    serde_json::from_value(req).map_err(|e| bad(&format!("bad cookie op: {e}")))?;
                gm.cookie_op(&ctx, op, manager.cookies())
            }
            "menu/sync" => {
                ctx.require(&["GM_registerMenuCommand"])?;
                let mdoc = req
                    .get("mdoc")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("mdoc required"))?;
                let list = req
                    .get("cmds")
                    .and_then(Value::as_array)
                    .ok_or_else(|| bad("cmds must be an array"))?;
                let s = |c: &Value, k: &str| {
                    c.get(k)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string()
                };
                let cmds = list
                    .iter()
                    .map(|c| {
                        let id = s(c, "id");
                        if id.is_empty() {
                            return Err(bad("command id required"));
                        }
                        Ok((
                            id,
                            s(c, "name"),
                            s(c, "accessKey"),
                            s(c, "title"),
                            c.get("autoClose").and_then(Value::as_bool).unwrap_or(true),
                        ))
                    })
                    .collect::<GmResult<Vec<_>>>()?;
                let live = self
                    .ext
                    .menu_sync(&a.profile, &a.origin, &a.id, mdoc, cmds)?;
                Ok(json!({"ext": live}))
            }
            _ => Err(GmError::new(ErrorCode::NotFound, "no such endpoint")),
        }
    }

    // ---- hyper entry point ------------------------------------------------------------------

    /// `/__adblock__/gm/v1/<route>`
    pub async fn handle_gm(
        self: &Arc<Self>,
        req: Request<Incoming>,
        c: &Caller<'_>,
        up: &Upstream<'_>,
        route: &str,
    ) -> Response<ProxyBody> {
        let manager = c.manager;
        let is_get = req.method() == Method::GET;
        if route == "resource" {
            if !is_get && req.method() != Method::HEAD {
                return forbidden();
            }
            return self.resource(manager, c, &req);
        }
        if req.method() != Method::POST {
            return forbidden();
        }
        // Order matters: nothing is read from the body until the caller is a verified script
        // with a free slot and the global byte budget has room.
        if route != "xhr" && !JSON_ROUTES.contains(&route) {
            return not_found();
        }
        let h = req.headers().clone();
        if !same_origin_ok(&h, c.origin, true) {
            return forbidden();
        }
        let is_xhr = route == "xhr";
        let want = if is_xhr {
            "application/x-gm-frame"
        } else {
            "application/json"
        };
        if !media_is(&h, want) {
            return gm_json(
                415,
                GmError::new(
                    ErrorCode::BadRequest,
                    format!("content type must be {want}"),
                )
                .to_json(),
            );
        }
        let cap = if is_xhr { META_CAP + 4 } else { JSON_CAP };
        let declared = header(&h, "content-length").and_then(|v| v.parse::<usize>().ok());
        if !is_xhr && declared.is_some_and(|n| n > cap) {
            return gm_err(&GmError::new(
                ErrorCode::QuotaExceeded,
                "request body too large",
            ));
        }
        let Some(tok) = header(&h, "x-gm-token") else {
            return gm_err(&GmError::new(ErrorCode::Unauthorized, "missing token"));
        };
        let a = match self.authenticate(manager, c, tok) {
            Ok(a) => a,
            Err(e) => return gm_err(&e),
        };
        let quota = || {
            gm_json(
                429,
                GmError::new(ErrorCode::QuotaExceeded, "too many concurrent requests").to_json(),
            )
        };
        if is_xhr {
            // The xhr slot is taken here and held until the response has been streamed.
            let Some(permit) = self.permit(&a.profile, &a.id, Kind::Xhr) else {
                return quota();
            };
            let Some(bytes) = self.reserve(XHR_RESERVE) else {
                return quota();
            };
            return self
                .xhr(manager, c, up, &h, a, req.into_body(), (permit, bytes))
                .await;
        }
        let Some(permit) = self.permit(&a.profile, &a.id, Kind::Json) else {
            return quota();
        };
        let Some(bytes_held) = self.reserve(declared.unwrap_or(JSON_CAP).min(JSON_CAP)) else {
            return quota();
        };
        let limit = declared.unwrap_or(JSON_CAP).min(JSON_CAP);
        let body = match Limited::new(req.into_body(), limit).collect().await {
            Ok(b) => b.to_bytes(),
            Err(e)
                if e.downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some() =>
            {
                return gm_err(&GmError::new(
                    ErrorCode::QuotaExceeded,
                    "request body too large",
                ))
            }
            Err(_) => return gm_err(&GmError::new(ErrorCode::BadRequest, "body read failed")),
        };
        // The slot covers reading the body only; a long poll or a relayed call must not hold it.
        drop(permit);
        drop(bytes_held);
        let res = match route {
            "menu/wait" => self.menu_wait(&a, &body).await,
            "cookie" => self.cookie_call(manager, &a, &body).await,
            _ => self.json_run(manager, &a, route, &body),
        };
        match res {
            Ok(v) => gm_json(200, json!({"ok": true, "result": v})),
            Err(e) => gm_err(&e),
        }
    }

    /// `menu/wait`: long poll for triggers of this script's commands.
    async fn menu_wait(self: &Arc<Self>, a: &Authed, body: &[u8]) -> GmResult<Value> {
        let req: Value = serde_json::from_slice(body)
            .map_err(|e| GmError::new(ErrorCode::BadRequest, format!("bad JSON: {e}")))?;
        let mdoc = req
            .get("mdoc")
            .and_then(Value::as_str)
            .ok_or_else(|| GmError::new(ErrorCode::BadRequest, "mdoc required"))?;
        let w = self
            .ext
            .menu_wait(&a.profile, &a.origin, &a.id, mdoc, crate::ext_bridge::WAIT)
            .await?;
        Ok(match w {
            Wait::NoExt => json!({"ext": false}),
            Wait::Fire(cmds) => json!({
                "ext": true,
                "fire": cmds.into_iter().map(|c| json!({"script": a.id, "cmd": c})).collect::<Vec<_>>(),
            }),
        })
    }

    /// `GM_cookie`: the stored script's checks first; then the browser's cookies when the script
    /// is approved for them and the document is served by a live extension session that holds a
    /// permission for the host, else the script's own jar. HttpOnly cookies are never exposed
    /// or written through the browser.
    async fn cookie_call(
        self: &Arc<Self>,
        manager: &Arc<UserscriptManager>,
        a: &Authed,
        body: &[u8],
    ) -> GmResult<Value> {
        let bad = |m: String| GmError::new(ErrorCode::BadRequest, m);
        let mut req: Value = if body.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(body).map_err(|e| bad(format!("bad JSON: {e}")))?
        };
        let mdoc = req
            .as_object_mut()
            .and_then(|o| o.remove("mdoc"))
            .and_then(|v| v.as_str().map(str::to_string));
        let op: CookieOp =
            serde_json::from_value(req.clone()).map_err(|e| bad(format!("bad cookie op: {e}")))?;
        let gm = manager.gm();
        let ctx = a.ctx();
        let url = gm.cookie_authorize(&ctx, &op)?;
        let s = a.script();
        {
            let host = url.host_str().unwrap_or_default().to_string();
            let route = self.credentialed_route(
                s,
                &a.profile,
                &a.origin,
                false,
                false,
                false,
                mdoc.as_deref(),
                &host,
            );
            // A host the Extended Validation setting tunnels is not decrypted: jar.
            let route = match route {
                Route::Ext(_)
                    if !self
                        .ext
                        .ev_allows(&host, url.port_or_known_default().unwrap_or(443))
                        .await =>
                {
                    Route::Jar(crate::ext_bridge::Fallback::Bypassed)
                }
                r => r,
            };
            match route {
                Route::Ext(session) => {
                    if matches!(&op, CookieOp::Set { cookie, .. } if cookie.http_only) {
                        return Err(bad("httpOnly cookies are not accessible".into()));
                    }
                    let connect = connect_spec(s, &a.page_host);
                    let meta = json!({
                        "op": "cookie", "script": a.id, "connect": connect, "cookie": req,
                        "store": self.ext.doc_store(mdoc.as_deref()),
                    });
                    self.ext.audit_relay(session, &a.id, &host, "", "cookie");
                    let mut h = self
                        .ext
                        .dispatch(session, meta, &a.profile, &a.id, &a.page_host, None)
                        .await?;
                    return relay_result(&mut h).await;
                }
                Route::Jar(why) => {
                    tracing::debug!("GM_cookie of {} used the jar: {why:?}", a.id);
                }
            }
        }
        gm.cookie_op(&ctx, op, manager.cookies())
    }

    /// Reserve `n` bytes of the global request-body budget (released on drop).
    fn reserve(&self, n: usize) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.budget)
            .try_acquire_many_owned(n as u32)
            .ok()
    }

    fn resource(
        &self,
        manager: &UserscriptManager,
        c: &Caller<'_>,
        req: &Request<Incoming>,
    ) -> Response<ProxyBody> {
        if !same_origin_ok(req.headers(), c.origin, false) {
            return forbidden();
        }
        // The token is accepted from the header only: a URL would show up in the page's
        // `performance` entries.
        let q = req.uri().query().unwrap_or("");
        let mut name = None;
        for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
            if &*k == "name" {
                name = Some(v.into_owned());
            }
        }
        let tok = header(req.headers(), "x-gm-token").map(str::to_string);
        let res: GmResult<(String, Vec<u8>)> = (|| {
            let tok = tok.ok_or_else(|| GmError::new(ErrorCode::Unauthorized, "missing token"))?;
            let name = name.ok_or_else(|| GmError::new(ErrorCode::BadRequest, "missing name"))?;
            let a = self.authenticate(manager, c, &tok)?;
            manager.gm().resource(&a.ctx(), &name)
        })();
        match res {
            Ok((mime, bytes)) => {
                // Same-origin with the page: never let a stored body run as a document.
                let mime = if mime.to_ascii_lowercase().contains("html")
                    || mime.to_ascii_lowercase().contains("xml")
                    || mime.contains('\n')
                    || mime.contains('\r')
                {
                    "text/plain; charset=utf-8".to_string()
                } else {
                    mime
                };
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, mime)
                    .header("cache-control", "no-store")
                    .header("x-content-type-options", "nosniff")
                    .header("content-security-policy", "sandbox; default-src 'none'")
                    .header("cross-origin-resource-policy", "same-origin")
                    .body(full_body(Bytes::from(bytes)))
                    .expect("resource response")
            }
            Err(e) => gm_err(&e),
        }
    }

    fn permit(self: &Arc<Self>, profile: &str, script: &str, kind: Kind) -> Option<Permit> {
        let mut l = self.limits.lock();
        let (c, per, all) = match kind {
            Kind::Xhr => (&mut l.xhr, MAX_XHR_PER_SCRIPT, MAX_XHR_PER_PROFILE),
            Kind::Json => (&mut l.json, MAX_JSON_PER_SCRIPT, MAX_JSON_PER_PROFILE),
        };
        let n = c.per_script.get(script).copied().unwrap_or(0);
        let p = c.per_profile.get(profile).copied().unwrap_or(0);
        if n >= per || p >= all {
            return None;
        }
        *c.per_profile.entry(profile.to_string()).or_insert(0) += 1;
        *c.per_script.entry(script.to_string()).or_insert(0) += 1;
        Some(Permit {
            host: Arc::clone(self),
            profile: profile.to_string(),
            script: script.to_string(),
            kind,
        })
    }

    // ---- xmlhttpRequest / download ----------------------------------------------------------

    /// Run a credentialed request through the extension's browser. The extension fetches with
    /// the browser's cookies and `X-Argus-Relay`; the proxy re-checks every hop of that fetch
    /// when it arrives (see [`ExtHub::check_relay`]). The answer is piped back as frames.
    async fn run_relayed(
        self: &Arc<Self>,
        a: Authed,
        out: userscript_engine::backend::OutboundRequest,
        session: u64,
        held: Held,
        upload: Option<Upload>,
        store: String,
    ) -> Response<ProxyBody> {
        let s = a.script();
        // Headers a page cannot set in a browser fetch (Cookie, Origin, Host) are dropped: the
        // browser supplies its own.
        let headers: Vec<[&str; 2]> = out
            .headers
            .iter()
            .filter(|(n, _)| {
                !matches!(
                    n.to_ascii_lowercase().as_str(),
                    "cookie" | "origin" | "host" | "x-argus-relay" | "proxy-authorization"
                )
            })
            .map(|(n, v)| [n.as_str(), v.as_str()])
            .collect();
        let redirect = match out.redirect {
            Redirect::Follow => "follow",
            Redirect::Error => "error",
            Redirect::Manual => "manual",
        };
        let host = out.url.host_str().unwrap_or_default().to_string();
        let meta = json!({
            "op": "xhr",
            "script": a.id,
            "connect": connect_spec(s, &a.page_host),
            "method": out.method,
            "url": out.url.as_str(),
            "headers": headers,
            "redirect": redirect,
            "timeout": out.timeout.as_millis() as u64,
            "store": store,
        });
        self.ext
            .audit_relay(session, &a.id, &host, &out.method, "xhr");
        let rx = upload.map(|u| u.rx);
        let handle = match self
            .ext
            .dispatch(session, meta, &a.profile, &a.id, &a.page_host, rx)
            .await
        {
            Ok(h) => h,
            Err(e) => return single_error_frame("network", "network", &e.message),
        };
        let deadline = tokio::time::Instant::now() + out.timeout;
        let stream = async_stream::stream! {
            let _permit = held;
            // The whole handle moves in (not just its receiver): its guard cancels the job when
            // the page goes away, and must not drop before that.
            let mut handle = handle;
            let mut total: u64 = 0;
            loop {
                match tokio::time::timeout_at(deadline, handle.rx.recv()).await {
                    Err(_) => {
                        yield Ok::<_, std::io::Error>(Frame::data(err_frame("timeout", "timeout", "request timed out")));
                        return;
                    }
                    Ok(None) => {
                        let why = if handle.overflowed() { "response not read fast enough" } else { "extension disconnected" };
                        yield Ok(Frame::data(err_frame("network", "network", why)));
                        return;
                    }
                    Ok(Some(JobEvent::Head(b))) => {
                        let Some(head) = sanitize_head(&b) else {
                            yield Ok(Frame::data(err_frame("network", "network", "bad response head")));
                            return;
                        };
                        yield Ok(Frame::data(frame(1, head.to_string().as_bytes())));
                    }
                    Ok(Some(JobEvent::Data(chunk))) => {
                        total += chunk.len() as u64;
                        if total > MAX_RESPONSE {
                            yield Ok(Frame::data(err_frame("too_large", "too_large", "response too large")));
                            return;
                        }
                        if !chunk.is_empty() {
                            yield Ok(Frame::data(frame(2, &chunk)));
                        }
                    }
                    Ok(Some(JobEvent::End)) => {
                        yield Ok(Frame::data(frame(3, b"{}")));
                        return;
                    }
                    Ok(Some(JobEvent::Error(b))) => {
                        let v: Value = serde_json::from_slice(&b).unwrap_or(Value::Null);
                        let t = |k: &str, d: &str| v.get(k).and_then(Value::as_str).unwrap_or(d).chars().take(200).collect::<String>();
                        yield Ok(Frame::data(err_frame(&t("kind", "network"), &t("code", "network"), &t("message", "request failed"))));
                        return;
                    }
                }
            }
        };
        frames_response(BodyExt::boxed_unsync(StreamBody::new(stream)))
    }

    #[allow(clippy::too_many_arguments)]
    async fn xhr(
        self: &Arc<Self>,
        manager: &Arc<UserscriptManager>,
        c: &Caller<'_>,
        up: &Upstream<'_>,
        req_headers: &HeaderMap,
        a: Authed,
        mut body: Incoming,
        held: Held,
    ) -> Response<ProxyBody> {
        let _ = c;
        let max = manager.gm().quotas().max_request_body;
        if header(req_headers, "content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|n| n > max + META_CAP + 4)
        {
            return gm_err(&GmError::new(
                ErrorCode::QuotaExceeded,
                "request body too large",
            ));
        }
        // Head: 4-byte meta length, the meta block; whatever follows in the same frames is the
        // start of the upload.
        let mut buf: Vec<u8> = Vec::new();
        let head = loop {
            if buf.len() >= 4 {
                let n = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                if n > META_CAP {
                    return gm_err(&GmError::new(ErrorCode::BadRequest, "bad frame length"));
                }
                if buf.len() >= 4 + n {
                    break 4 + n;
                }
            }
            match tokio::time::timeout(BODY_IDLE, body.frame()).await {
                Ok(Some(Ok(f))) => {
                    if let Ok(d) = f.into_data() {
                        buf.extend_from_slice(&d);
                    }
                }
                Ok(None) => {
                    return gm_err(&GmError::new(ErrorCode::BadRequest, "short frame"));
                }
                _ => return gm_err(&GmError::new(ErrorCode::BadRequest, "body read failed")),
            }
        };
        let meta: XhrRequest = match serde_json::from_slice(&buf[4..head]) {
            Ok(m) => m,
            Err(e) => {
                return gm_err(&GmError::new(
                    ErrorCode::BadRequest,
                    format!("bad meta: {e}"),
                ))
            }
        };
        let prefix = buf.split_off(head);
        drop(buf);
        let mut out = match manager.gm().build_outbound(&a.ctx(), &meta, prefix.clone()) {
            Ok(o) => o,
            Err(e) => return gm_err(&e),
        };
        // A literal address the destination policy refuses never gets dialled.
        if let Err(e) = check_dest(up, &out.url) {
            return gm_err(&e);
        }
        let mut upload = None;
        if matches!(out.method.as_str(), "GET" | "HEAD") {
            // No body allowed: anything after the head is an error.
            loop {
                match tokio::time::timeout(BODY_IDLE, body.frame()).await {
                    Ok(None) => break,
                    Ok(Some(Ok(f))) => {
                        if f.into_data().is_ok_and(|d| !d.is_empty()) {
                            return gm_err(&GmError::new(
                                ErrorCode::BadRequest,
                                "GET/HEAD requests cannot have a body",
                            ));
                        }
                    }
                    _ => return gm_err(&GmError::new(ErrorCode::BadRequest, "body read failed")),
                }
            }
        } else {
            out.body.clear();
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(2);
            let exceeded = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = Arc::clone(&exceeded);
            tokio::spawn(pump_upload(body, prefix, max, tx, flag));
            let len = header(req_headers, "content-length")
                .and_then(|v| v.parse::<usize>().ok())
                .map(|n| n.saturating_sub(head));
            upload = Some(Upload { rx, len, exceeded });
        }
        // Browser logins: a script approved for them, not anonymous, with a live extension
        // session bound to this very document and a host permission for the target. The checks
        // above (grant, `@connect`, method and header rules, destination policy) have passed.
        {
            let host = out.url.host_str().unwrap_or_default().to_string();
            let route = self.credentialed_route(
                a.script(),
                &a.profile,
                &a.origin,
                meta.anonymous,
                meta.op == "download",
                out.redirect == Redirect::Manual,
                meta.mdoc.as_deref(),
                &host,
            );
            // A host the Extended Validation setting tunnels is not decrypted: jar.
            let route = match route {
                Route::Ext(_)
                    if !self
                        .ext
                        .ev_allows(&host, out.url.port_or_known_default().unwrap_or(443))
                        .await =>
                {
                    Route::Jar(crate::ext_bridge::Fallback::Bypassed)
                }
                r => r,
            };
            match route {
                Route::Ext(session) => {
                    return self
                        .run_relayed(
                            a,
                            out,
                            session,
                            held,
                            upload,
                            self.ext.doc_store(meta.mdoc.as_deref()),
                        )
                        .await;
                }
                Route::Jar(why) => {
                    tracing::debug!("xhr of {} used the jar: {why:?}", a.id);
                }
            }
        }
        let default_ua = header(req_headers, "user-agent").map(str::to_string);
        run_outbound(manager.clone(), a, out, up, default_ua, held, upload).await
    }
}

/// Validate and normalise the head the extension sent: status, text, header pairs (no
/// `Set-Cookie`, no hop-by-hop headers), final URL.
fn sanitize_head(b: &[u8]) -> Option<Value> {
    let v: Value = serde_json::from_slice(b).ok()?;
    let status = v
        .get("status")
        .and_then(Value::as_u64)
        .filter(|s| (100..=599).contains(s))?;
    let headers: Vec<(String, String)> = v
        .get("headers")
        .and_then(Value::as_array)
        .map(|l| {
            l.iter()
                .filter_map(|p| {
                    let p = p.as_array()?;
                    Some((
                        p.first()?.as_str()?.to_string(),
                        p.get(1)?.as_str()?.to_string(),
                    ))
                })
                .filter(|(n, _)| {
                    let n = n.to_ascii_lowercase();
                    !matches!(
                        n.as_str(),
                        "set-cookie"
                            | "set-cookie2"
                            | "connection"
                            | "keep-alive"
                            | "transfer-encoding"
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let s = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    Some(json!({
        "status": status,
        "statusText": s("statusText"),
        "headers": headers,
        "finalUrl": s("finalUrl"),
        "redirected": v.get("redirected").and_then(Value::as_bool).unwrap_or(false),
    }))
}

/// The `@connect` description the extension re-checks (it may only narrow it).
fn connect_spec(s: &userscript_engine::Userscript, page_host: &str) -> Value {
    json!({
        "page": page_host,
        "list": s.metadata.connect.iter().filter(|c| c.as_str() != "*").collect::<Vec<_>>(),
        "all": s.allow_connect_all && s.metadata.connect.iter().any(|c| c == "*"),
    })
}

/// Wait for the answer of a cookie job: `{"result": ...}`; HttpOnly cookies are dropped from it
/// whatever the extension sent.
async fn relay_result(h: &mut crate::ext_bridge::JobHandle) -> GmResult<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut result = None;
    loop {
        match tokio::time::timeout_at(deadline, h.rx.recv()).await {
            Err(_) => {
                return Err(GmError::new(
                    ErrorCode::Internal,
                    "extension did not answer",
                ))
            }
            Ok(None) => return Err(GmError::new(ErrorCode::Internal, "extension disconnected")),
            Ok(Some(JobEvent::Head(b))) => {
                let v: Value = serde_json::from_slice(&b)
                    .map_err(|_| GmError::new(ErrorCode::Internal, "bad answer"))?;
                result = Some(v.get("result").cloned().unwrap_or(Value::Null));
            }
            Ok(Some(JobEvent::Data(_))) => {}
            Ok(Some(JobEvent::End)) => {
                let mut r = result.unwrap_or(Value::Null);
                if let Value::Array(list) = &mut r {
                    list.retain(|c| !c.get("http_only").and_then(Value::as_bool).unwrap_or(false));
                }
                return Ok(r);
            }
            Ok(Some(JobEvent::Error(b))) => {
                let v: Value = serde_json::from_slice(&b).unwrap_or(Value::Null);
                let msg = v
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("extension error")
                    .chars()
                    .take(200)
                    .collect::<String>();
                let code = match v.get("code").and_then(Value::as_str) {
                    Some("connect_denied") | Some("permission") => ErrorCode::ConnectDenied,
                    Some("bad_request") => ErrorCode::BadRequest,
                    _ => ErrorCode::Internal,
                };
                return Err(GmError::new(code, msg));
            }
        }
    }
}

/// An in-flight, bounded upload for the first hop.
struct Upload {
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
    len: Option<usize>,
    exceeded: Arc<std::sync::atomic::AtomicBool>,
}

/// Move the request body to upstream through a two-slot channel, enforcing the size quota and
/// an idle timeout. Dropping `tx` ends the upload; an `Err` aborts it.
async fn pump_upload(
    mut body: Incoming,
    prefix: Vec<u8>,
    max: usize,
    tx: tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
    exceeded: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut total = 0usize;
    let mut send = |chunk: Bytes| {
        total += chunk.len();
        (total > max, chunk)
    };
    if !prefix.is_empty() {
        let (over, chunk) = send(Bytes::from(prefix));
        if over || tx.send(Ok(chunk)).await.is_err() {
            exceeded.store(over, std::sync::atomic::Ordering::SeqCst);
            return;
        }
    }
    loop {
        match tokio::time::timeout(BODY_IDLE, body.frame()).await {
            Ok(None) => return,
            Ok(Some(Ok(f))) => {
                let Ok(d) = f.into_data() else { continue };
                if d.is_empty() {
                    continue;
                }
                let (over, chunk) = send(d);
                if over {
                    exceeded.store(true, std::sync::atomic::Ordering::SeqCst);
                    let _ = tx
                        .send(Err(std::io::Error::other("request body too large")))
                        .await;
                    return;
                }
                if tx.send(Ok(chunk)).await.is_err() {
                    return;
                }
            }
            _ => {
                let _ = tx
                    .send(Err(std::io::Error::other("request body read failed")))
                    .await;
                return;
            }
        }
    }
}

fn tokio_stream_from(
    mut rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
    futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
}

fn not_found() -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .header("cross-origin-resource-policy", "same-origin")
        .body(full_body(Bytes::new()))
        .expect("404")
}

fn check_dest(up: &Upstream<'_>, url: &url::Url) -> GmResult<()> {
    let host = url.host_str().unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or(80);
    up.policy.check_literal(host, port).map_err(|r| {
        GmError::new(
            ErrorCode::ConnectDenied,
            format!("destination refused by the proxy's policy: {r}"),
        )
    })
}

/// Execute the request (following redirects with `@connect` re-checked per hop) and stream the
/// answer back as frames.
async fn run_outbound(
    manager: Arc<UserscriptManager>,
    a: Authed,
    first: userscript_engine::backend::OutboundRequest,
    up: &Upstream<'_>,
    default_ua: Option<String>,
    permit: Held,
    mut upload: Option<Upload>,
) -> Response<ProxyBody> {
    let deadline = tokio::time::Instant::now() + first.timeout;
    let mut cur = first;
    let mut redirected = false;
    let mut exceeded: Option<Arc<std::sync::atomic::AtomicBool>> = None;
    let resp = loop {
        if let Err(e) = check_dest(up, &cur.url) {
            return single_error_frame("denied", "connect_denied", &e.message);
        }
        let port = cur.url.port_or_known_default().unwrap_or(80);
        let client = if up.policy.is_own_port(port) {
            up.strict_client
        } else {
            up.client
        };
        let method =
            reqwest::Method::from_bytes(cur.method.as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut dial = cur.url.clone();
        let mut host_hdr = None;
        if let (Some(over), Some(h)) = (up.resolve_all_to, cur.url.host_str()) {
            if h.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok()
            {
                host_hdr = Some(match cur.url.port() {
                    Some(p) => format!("{h}:{p}"),
                    None => h.to_string(),
                });
                let _ = dial.set_ip_host(over);
            }
        }
        let mut rb = client.request(method, dial);
        if let Some(h) = host_hdr {
            rb = rb.header("host", h);
        }
        let mut have_ae = false;
        let mut have_ua = false;
        let mut explicit_cookie: Option<String> = None;
        for (n, v) in &cur.headers {
            if n.eq_ignore_ascii_case("cookie") {
                explicit_cookie = Some(v.clone());
                continue;
            }
            have_ae |= n.eq_ignore_ascii_case("accept-encoding");
            have_ua |= n.eq_ignore_ascii_case("user-agent");
            rb = rb.header(n.as_str(), v.as_str());
        }
        if !have_ae {
            rb = rb.header("accept-encoding", "identity");
        }
        if !have_ua {
            if let Some(ua) = &default_ua {
                rb = rb.header("user-agent", ua.as_str());
            }
        }
        let jar_cookie = cur
            .use_cookie_jar
            .then(|| manager.cookies().header_for(&a.profile, &a.id, &cur.url))
            .flatten();
        let cookie = match (jar_cookie, explicit_cookie) {
            (Some(j), Some(e)) => Some(format!("{j}; {e}")),
            (j, e) => j.or(e),
        };
        if let Some(c) = cookie {
            rb = rb.header("cookie", c);
        }
        let mut streamed = false;
        if let Some(u) = upload.take() {
            if let Some(n) = u.len {
                rb = rb.header("content-length", n);
            }
            let stream = tokio_stream_from(u.rx);
            rb = rb.body(reqwest::Body::wrap_stream(stream));
            exceeded = Some(u.exceeded);
            streamed = true;
        } else if !cur.body.is_empty() {
            rb = rb.body(cur.body.clone());
        }
        let sent = tokio::time::timeout_at(deadline, rb.send()).await;
        let resp = match sent {
            Err(_) => return single_error_frame("timeout", "timeout", "request timed out"),
            Ok(Err(e)) if crate::policy::is_refusal(&e) => {
                return single_error_frame(
                    "denied",
                    "connect_denied",
                    "destination refused by the proxy's policy",
                )
            }
            Ok(Err(_))
                if exceeded
                    .as_ref()
                    .is_some_and(|f| f.load(std::sync::atomic::Ordering::SeqCst)) =>
            {
                return single_error_frame("denied", "quota_exceeded", "request body too large")
            }
            Ok(Err(e)) => {
                return single_error_frame("network", "network", &format!("upstream error: {e}"))
            }
            Ok(Ok(r)) => r,
        };
        if streamed
            && matches!(resp.status().as_u16(), 307 | 308)
            && cur.redirect == Redirect::Follow
        {
            return single_error_frame(
                "network",
                "redirect",
                "a redirect that must resend a streamed request body is refused",
            );
        }
        if cur.use_cookie_jar {
            let sc: Vec<&str> = resp
                .headers()
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            if !sc.is_empty() {
                manager
                    .cookies()
                    .store_response(&a.profile, &a.id, &cur.url, sc.into_iter());
            }
        }
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            if let Some(loc) = location {
                match cur.redirect {
                    Redirect::Manual => break resp,
                    Redirect::Error => {
                        return single_error_frame(
                            "network",
                            "redirect",
                            "redirect refused (redirect: error)",
                        )
                    }
                    Redirect::Follow => match next_hop(&a.ctx(), &cur, status, &loc) {
                        Ok(n) => {
                            cur = n;
                            redirected = true;
                            continue;
                        }
                        Err(e) => {
                            return single_error_frame(
                                "denied",
                                match e.code {
                                    ErrorCode::ConnectDenied => "connect_denied",
                                    _ => "bad_request",
                                },
                                &e.message,
                            )
                        }
                    },
                }
            }
        }
        break resp;
    };

    let status = resp.status();
    let head_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter(|(n, _)| {
            let n = n.as_str();
            n != "set-cookie"
                && n != "set-cookie2"
                && n != "connection"
                && n != "keep-alive"
                && n != "transfer-encoding"
        })
        .filter_map(|(n, v)| Some((n.as_str().to_string(), v.to_str().ok()?.to_string())))
        .collect();
    let head = json!({
        "status": status.as_u16(),
        "statusText": status.canonical_reason().unwrap_or(""),
        "headers": head_headers,
        "finalUrl": cur.url.as_str(),
        "redirected": redirected,
    });
    let mut stream = resp.bytes_stream();
    let out = async_stream::stream! {
        let _permit = permit;
        yield Ok::<_, std::io::Error>(Frame::data(frame(1, head.to_string().as_bytes())));
        let mut total: u64 = 0;
        loop {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Err(_) => {
                    yield Ok(Frame::data(err_frame("timeout", "timeout", "request timed out")));
                    return;
                }
                Ok(None) => break,
                Ok(Some(Err(e))) => {
                    yield Ok(Frame::data(err_frame("network", "network", &format!("body error: {e}"))));
                    return;
                }
                Ok(Some(Ok(chunk))) => {
                    total += chunk.len() as u64;
                    if total > MAX_RESPONSE {
                        yield Ok(Frame::data(err_frame("too_large", "too_large", "response too large")));
                        return;
                    }
                    if !chunk.is_empty() {
                        yield Ok(Frame::data(frame(2, &chunk)));
                    }
                }
            }
        }
        yield Ok(Frame::data(frame(3, b"{}")));
    };
    frames_response(BodyExt::boxed_unsync(StreamBody::new(out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_slots_are_capped_per_profile() {
        let host = Arc::new(GmHost::new());
        let mut held = Vec::new();
        // Profile "a" fills its cap across several scripts.
        for i in 0..MAX_XHR_PER_PROFILE {
            let p = host.permit("a", &format!("a{}", i / MAX_XHR_PER_SCRIPT), Kind::Xhr);
            held.push(p.expect("within the cap"));
        }
        assert!(
            host.permit("a", "a-extra", Kind::Xhr).is_none(),
            "a is full"
        );
        // Another profile is not starved by it.
        assert!(host.permit("b", "b0", Kind::Xhr).is_some());
        // Releasing a slot frees room for "a" again.
        held.pop();
        assert!(host.permit("a", "a-extra", Kind::Xhr).is_some());
        // The JSON pool is separate.
        assert!(host.permit("a", "a0", Kind::Json).is_some());
    }

    fn doc(host: &str, n: usize) -> Doc {
        Doc {
            index: Arc::new(ScriptIndex::default()),
            ids: (0..n).map(|i| format!("s{i}")).collect(),
            fetched: vec![false; n],
            profile: "p".into(),
            host: host.into(),
            origin: format!("https://{host}"),
            top: true,
            created: Instant::now(),
            mdoc: None,
        }
    }

    #[test]
    fn chunks_are_single_use_and_bound_to_the_host() {
        let s = DocStore::new(8, Duration::from_secs(60));
        let id = s.insert(doc("a.test", 2));
        assert!(s.take(&id, 0, "b.test", "p").is_none(), "wrong host");
        assert!(s.take(&id, 0, "a.test", "q").is_none(), "wrong profile");
        assert!(s.take(&id, 0, "a.test", "p").is_some());
        assert!(s.take(&id, 0, "a.test", "p").is_none(), "replay");
        assert!(s.take(&id, 5, "a.test", "p").is_none());
        assert!(s.take(&id, 1, "a.test", "p").is_some());
        assert!(s.is_empty(), "fully fetched documents are dropped");
    }

    #[test]
    fn the_store_is_bounded_and_evicts_oldest_first() {
        let s = DocStore::new(3, Duration::from_secs(60));
        let ids: Vec<String> = (0..10).map(|_| s.insert(doc("a.test", 1))).collect();
        assert!(s.len() <= 3);
        assert!(
            s.take(&ids[0], 0, "a.test", "p").is_none(),
            "oldest evicted"
        );
        assert!(s.take(&ids[9], 0, "a.test", "p").is_some());
    }

    #[test]
    fn expired_documents_are_refused_and_purged() {
        let s = DocStore::new(8, Duration::from_millis(10));
        let id = s.insert(doc("a.test", 1));
        std::thread::sleep(Duration::from_millis(30));
        assert!(s.take(&id, 0, "a.test", "p").is_none());
        s.insert(doc("a.test", 1));
        assert_eq!(s.len(), 1, "insert purges expired entries");
    }

    #[test]
    fn same_origin_rules() {
        let mut h = HeaderMap::new();
        assert!(
            !same_origin_ok(&h, "https://a.test", true),
            "POST needs Origin"
        );
        h.insert("origin", "https://a.test".parse().unwrap());
        assert!(same_origin_ok(&h, "https://a.test", true));
        assert!(!same_origin_ok(&h, "https://b.test", true));
        h.insert("sec-fetch-site", "cross-site".parse().unwrap());
        assert!(!same_origin_ok(&h, "https://a.test", true));
        let mut g = HeaderMap::new();
        assert!(
            !same_origin_ok(&g, "https://a.test", false),
            "GET needs fetch metadata"
        );
        g.insert("sec-fetch-site", "same-origin".parse().unwrap());
        assert!(same_origin_ok(&g, "https://a.test", false));
        g.insert("origin", "null".parse().unwrap());
        assert!(!same_origin_ok(&g, "https://a.test", false));
    }
}

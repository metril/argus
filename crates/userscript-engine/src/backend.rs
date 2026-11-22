//! Server side of the GM API as pure Rust (no HTTP types). The proxy authenticates the request
//! (see `token`), builds a [`ScriptCtx`] from its own records, and calls these operations; see
//! `docs/USERSCRIPT-PROTOCOL.md` for the wire format.

use crate::{
    script::Userscript,
    storage::{ns, UserscriptStorage},
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};
use url::Url;

/// Stable error codes surfaced on the wire (`error.code`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Token missing/invalid/expired, or script unknown.
    Unauthorized,
    /// The script did not `@grant` this API.
    NotGranted,
    /// Target is outside the script's `@connect` policy.
    ConnectDenied,
    QuotaExceeded,
    BadRequest,
    NotFound,
    Unsupported,
    Disabled,
    Internal,
}

impl ErrorCode {
    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::Unauthorized => 401,
            ErrorCode::NotGranted | ErrorCode::ConnectDenied | ErrorCode::Disabled => 403,
            ErrorCode::QuotaExceeded => 413,
            ErrorCode::BadRequest => 400,
            ErrorCode::NotFound => 404,
            ErrorCode::Unsupported => 501,
            ErrorCode::Internal => 500,
        }
    }
}

#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
#[error("{code:?}: {message}")]
pub struct GmError {
    pub code: ErrorCode,
    pub message: String,
}

impl GmError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    /// `{"ok":false,"error":{"code","message"}}`
    pub fn to_json(&self) -> Value {
        serde_json::json!({"ok": false, "error": {"code": self.code, "message": self.message}})
    }
}

impl From<crate::Error> for GmError {
    fn from(e: crate::Error) -> Self {
        GmError::new(ErrorCode::Internal, e.to_string())
    }
}

pub type GmResult<T> = std::result::Result<T, GmError>;

/// The authenticated request context, built by the proxy from its own records.
#[derive(Debug, Clone, Copy)]
pub struct ScriptCtx<'a> {
    pub profile: &'a str,
    /// The server's stored script (never data from the client).
    pub script: &'a Userscript,
    /// Host of the page's origin (`Origin` header), lowercase. Backs `@connect self`.
    pub page_host: &'a str,
}

impl ScriptCtx<'_> {
    fn require(&self, any_of: &[&str]) -> GmResult<()> {
        if !self.script.enabled {
            return Err(GmError::new(ErrorCode::Disabled, "script is disabled"));
        }
        if any_of.iter().any(|g| self.script.metadata.has_grant(g)) {
            Ok(())
        } else {
            Err(GmError::new(
                ErrorCode::NotGranted,
                format!("script did not @grant {}", any_of[0]),
            ))
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Quotas {
    pub per_script: usize,
    pub per_profile: usize,
    pub per_value: usize,
    pub max_names_per_call: usize,
    /// Cap on the xhr request body.
    pub max_request_body: usize,
}

impl Default for Quotas {
    fn default() -> Self {
        Self {
            per_script: 5 << 20,
            per_profile: 50 << 20,
            per_value: 1 << 20,
            max_names_per_call: 1000,
            max_request_body: 64 << 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub seq: u64,
    pub name: String,
    pub old: Option<Value>,
    pub new: Option<Value>,
    /// Opaque id of the writer (the runtime's per-page id) so listeners can tell `remote`.
    pub src: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Changes {
    /// Latest sequence number for the script.
    pub seq: u64,
    /// The caller's `since` was older than the retained log: re-read values.
    pub reset: bool,
    pub changes: Vec<Change>,
}

const LOG_CAP: usize = 256;

#[derive(Default)]
struct ChangeLog {
    seq: u64,
    log: VecDeque<Change>,
}

#[derive(Default)]
struct State {
    /// profile -> namespace -> bytes used. Loaded lazily from storage.
    usage: HashMap<String, HashMap<String, usize>>,
    changes: HashMap<String, ChangeLog>,
}

pub struct GmBackend {
    storage: Arc<UserscriptStorage>,
    quotas: Quotas,
    state: Mutex<State>,
}

fn entry_size(name: &str, v: &Value) -> usize {
    name.len() + serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0)
}

impl GmBackend {
    pub fn new(storage: Arc<UserscriptStorage>, quotas: Quotas) -> Self {
        Self {
            storage,
            quotas,
            state: Mutex::new(State::default()),
        }
    }

    pub fn quotas(&self) -> &Quotas {
        &self.quotas
    }

    fn usage<'a>(
        &self,
        st: &'a mut State,
        profile: &str,
    ) -> GmResult<&'a mut HashMap<String, usize>> {
        if !st.usage.contains_key(profile) {
            let loaded = self.storage.profile_usage(profile)?;
            st.usage.insert(profile.to_string(), loaded);
        }
        Ok(st.usage.get_mut(profile).expect("just inserted"))
    }

    fn check_names(&self, n: usize) -> GmResult<()> {
        if n > self.quotas.max_names_per_call {
            return Err(GmError::new(
                ErrorCode::BadRequest,
                "too many names in one call",
            ));
        }
        Ok(())
    }

    /// `names = None` reads every value.
    pub fn values_get(
        &self,
        ctx: &ScriptCtx<'_>,
        names: Option<&[String]>,
    ) -> GmResult<Map<String, Value>> {
        ctx.require(&[
            "GM_getValue",
            "GM_getValues",
            "GM_listValues",
            // A change listener is handed old and new values, so it may read them.
            "GM_addValueChangeListener",
        ])?;
        let space = ns(ctx.profile, &ctx.script.id);
        let all;
        let names: &[String] = match names {
            Some(n) => {
                self.check_names(n.len())?;
                n
            }
            None => {
                all = self
                    .storage
                    .list_sizes(&space)?
                    .into_iter()
                    .map(|(n, _)| n)
                    .collect::<Vec<_>>();
                &all
            }
        };
        let mut out = Map::new();
        for n in names {
            if let Some(v) = self.storage.get_raw(&space, n)? {
                out.insert(n.clone(), v);
            }
        }
        Ok(out)
    }

    pub fn values_list(&self, ctx: &ScriptCtx<'_>) -> GmResult<Vec<String>> {
        ctx.require(&["GM_listValues"])?;
        let mut v: Vec<String> = self
            .storage
            .list_sizes(&ns(ctx.profile, &ctx.script.id))?
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        v.sort();
        Ok(v)
    }

    /// All-or-nothing: if any entry would exceed a quota nothing is written.
    pub fn values_set(
        &self,
        ctx: &ScriptCtx<'_>,
        values: Vec<(String, Value)>,
        src: Option<&str>,
    ) -> GmResult<()> {
        ctx.require(&["GM_setValue", "GM_setValues"])?;
        self.check_names(values.len())?;
        let space = ns(ctx.profile, &ctx.script.id);
        let mut st = self.state.lock();
        let mut deltas: Vec<(isize, Option<Value>, usize)> = Vec::new();
        let (mut script_delta, mut profile_delta) = (0isize, 0isize);
        for (name, v) in &values {
            if name.is_empty() || name.contains('\0') {
                return Err(GmError::new(ErrorCode::BadRequest, "invalid value name"));
            }
            let new_size = entry_size(name, v);
            if new_size > self.quotas.per_value {
                return Err(GmError::new(
                    ErrorCode::QuotaExceeded,
                    format!("value {name:?} exceeds the per-value limit"),
                ));
            }
            let old = self.storage.get_raw(&space, name)?;
            let old_size = old.as_ref().map(|o| entry_size(name, o)).unwrap_or(0);
            let d = new_size as isize - old_size as isize;
            script_delta += d;
            profile_delta += d;
            deltas.push((d, old, new_size));
        }
        let profile_usage = self.usage(&mut st, ctx.profile)?;
        let script_used = *profile_usage.get(&space).unwrap_or(&0) as isize;
        let total: isize = profile_usage.values().map(|&x| x as isize).sum();
        if script_used + script_delta > self.quotas.per_script as isize {
            return Err(GmError::new(
                ErrorCode::QuotaExceeded,
                "script storage quota exceeded",
            ));
        }
        if profile_delta > 0 && total + profile_delta > self.quotas.per_profile as isize {
            return Err(GmError::new(
                ErrorCode::QuotaExceeded,
                "profile storage quota exceeded",
            ));
        }
        let mut log = Vec::new();
        for ((name, v), (_, old, _)) in values.into_iter().zip(deltas) {
            if old.as_ref() != Some(&v) {
                log.push((name.clone(), old, Some(v.clone())));
            }
            self.storage.set_raw(&space, &name, v)?;
        }
        *self
            .usage(&mut st, ctx.profile)?
            .entry(space.clone())
            .or_default() = (script_used + script_delta).max(0) as usize;
        Self::record(&mut st, &space, log, src);
        Ok(())
    }

    pub fn values_delete(
        &self,
        ctx: &ScriptCtx<'_>,
        names: &[String],
        src: Option<&str>,
    ) -> GmResult<()> {
        ctx.require(&["GM_deleteValue", "GM_deleteValues"])?;
        self.check_names(names.len())?;
        let space = ns(ctx.profile, &ctx.script.id);
        let mut st = self.state.lock();
        let mut freed = 0usize;
        let mut log = Vec::new();
        for n in names {
            if let Some(old) = self.storage.get_raw(&space, n)? {
                freed += entry_size(n, &old);
                self.storage.delete_raw(&space, n)?;
                log.push((n.clone(), Some(old), None));
            }
        }
        let u = self
            .usage(&mut st, ctx.profile)?
            .entry(space.clone())
            .or_default();
        *u = u.saturating_sub(freed);
        Self::record(&mut st, &space, log, src);
        Ok(())
    }

    fn record(
        st: &mut State,
        space: &str,
        entries: Vec<(String, Option<Value>, Option<Value>)>,
        src: Option<&str>,
    ) {
        if entries.is_empty() {
            return;
        }
        let l = st.changes.entry(space.to_string()).or_default();
        for (name, old, new) in entries {
            l.seq += 1;
            let seq = l.seq;
            l.log.push_back(Change {
                seq,
                name,
                old,
                new,
                src: src.map(str::to_string),
            });
            if l.log.len() > LOG_CAP {
                l.log.pop_front();
            }
        }
    }

    /// Changes after `since` (`None`: just report the current sequence number).
    pub fn values_changes(&self, ctx: &ScriptCtx<'_>, since: Option<u64>) -> GmResult<Changes> {
        ctx.require(&["GM_addValueChangeListener", "GM_getValue"])?;
        let st = self.state.lock();
        let Some(l) = st.changes.get(&ns(ctx.profile, &ctx.script.id)) else {
            return Ok(Changes {
                seq: 0,
                reset: false,
                changes: vec![],
            });
        };
        let Some(since) = since else {
            return Ok(Changes {
                seq: l.seq,
                reset: false,
                changes: vec![],
            });
        };
        let oldest = l.log.front().map(|c| c.seq).unwrap_or(l.seq + 1);
        Ok(Changes {
            seq: l.seq,
            reset: since + 1 < oldest,
            changes: l.log.iter().filter(|c| c.seq > since).cloned().collect(),
        })
    }

    /// Drop in-memory accounting for a script (after uninstall).
    pub fn forget_script(&self, profile: &str, script_id: &str) {
        let space = ns(profile, script_id);
        let mut st = self.state.lock();
        if let Some(u) = st.usage.get_mut(profile) {
            u.remove(&space);
        }
        st.changes.remove(&space);
    }

    /// `@resource` body and MIME type.
    pub fn resource(&self, ctx: &ScriptCtx<'_>, name: &str) -> GmResult<(String, Vec<u8>)> {
        ctx.require(&["GM_getResourceText", "GM_getResourceURL"])?;
        ctx.script
            .assets
            .resources
            .iter()
            .find(|r| r.name == name)
            .map(|r| (r.mime.clone(), r.bytes()))
            .ok_or_else(|| {
                GmError::new(ErrorCode::NotFound, format!("no @resource named {name:?}"))
            })
    }
}

// ---- @connect ------------------------------------------------------------------------------

/// Whether `target` may be contacted by the script on behalf of a page on `page_host`.
///
/// Matches Tampermonkey's documented `@connect`: a domain allows itself and its subdomains,
/// `self` the page's own host, `localhost` and IP literals match exactly, `*` allows everything
/// but only when the user approved it at install time (`Userscript::allow_connect_all`). The
/// page's own host is always allowed. Only http(s) targets are ever allowed. Call it again for
/// every redirect hop ([`next_hop`]).
pub fn check_connect(script: &Userscript, page_host: &str, target: &Url) -> GmResult<()> {
    if !matches!(target.scheme(), "http" | "https") {
        return Err(GmError::new(
            ErrorCode::ConnectDenied,
            format!("scheme {} is not allowed", target.scheme()),
        ));
    }
    let Some(host) = target
        .host_str()
        .map(|h| h.trim_matches(['[', ']']).to_ascii_lowercase())
    else {
        return Err(GmError::new(ErrorCode::ConnectDenied, "target has no host"));
    };
    let page_host = page_host.to_ascii_lowercase();
    if host == page_host {
        return Ok(());
    }
    for c in &script.metadata.connect {
        let ok = match c.as_str() {
            "*" => script.allow_connect_all,
            "self" => host == page_host,
            "localhost" => host == "localhost",
            c => {
                let d = c.strip_prefix("*.").unwrap_or(c);
                !d.is_empty()
                    && (host == d
                        || (host.len() > d.len()
                            && host.ends_with(d)
                            && host.as_bytes()[host.len() - d.len() - 1] == b'.'))
            }
        };
        if ok {
            return Ok(());
        }
    }
    Err(GmError::new(
        ErrorCode::ConnectDenied,
        format!("{host} is not listed in @connect"),
    ))
}

// ---- xmlhttpRequest -------------------------------------------------------------------------

/// Metadata half of an `xhr` request (the body bytes travel separately).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct XhrRequest {
    /// `xhr` (needs `GM_xmlhttpRequest`) or `download` (needs `GM_download`).
    pub op: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub anonymous: bool,
    /// Extra `Cookie` header content.
    pub cookie: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    /// Milliseconds; 0 = default.
    pub timeout: u64,
    /// `follow` (default), `error`, `manual`.
    pub redirect: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redirect {
    Follow,
    Error,
    Manual,
}

/// What the proxy executes with its own client (under its destination policy).
#[derive(Debug, Clone)]
pub struct OutboundRequest {
    pub method: String,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Send/accept cookies from the profile's GM cookie jar (false when `anonymous`).
    pub use_cookie_jar: bool,
    pub redirect: Redirect,
    pub hops_left: u8,
    pub timeout: Duration,
    /// Headers the script set that were refused.
    pub dropped_headers: Vec<String>,
}

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_TIMEOUT: Duration = Duration::from_secs(600);
pub const MAX_REDIRECTS: u8 = 20;

/// Headers a script may never set: connection management and framing (set by the proxy's
/// HTTP stack), `Host`, proxy-* and forwarding headers (spoofing the proxy's own view),
/// and `Sec-*` (browsers reserve them).
fn forbidden_header(lc: &str) -> bool {
    matches!(
        lc,
        "host"
            | "content-length"
            | "connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "expect"
            | "via"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-real-ip"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "proxy-connection"
            | "http2-settings"
    ) || lc.starts_with("proxy-")
        || lc.starts_with("sec-")
        || lc.starts_with("x-gm-")
}

fn valid_header(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        && !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

impl GmBackend {
    /// Validate an `xhr`/`download` request and describe what to send. Headers page JS cannot
    /// set but userscript managers allow (`Referer`, `Origin`, `User-Agent`, `Cookie`,
    /// `Accept-Encoding`, ...) are passed through.
    pub fn build_outbound(
        &self,
        ctx: &ScriptCtx<'_>,
        req: &XhrRequest,
        body: Vec<u8>,
    ) -> GmResult<OutboundRequest> {
        match req.op.as_str() {
            "download" => ctx.require(&["GM_download"])?,
            "xhr" | "" => ctx.require(&["GM_xmlhttpRequest"])?,
            o => {
                return Err(GmError::new(
                    ErrorCode::BadRequest,
                    format!("unknown op {o:?}"),
                ))
            }
        }
        let url = Url::parse(&req.url)
            .map_err(|e| GmError::new(ErrorCode::BadRequest, format!("bad url: {e}")))?;
        check_connect(ctx.script, ctx.page_host, &url)?;
        let method = if req.method.is_empty() {
            "GET".to_string()
        } else {
            req.method.to_ascii_uppercase()
        };
        if !matches!(
            method.as_str(),
            "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS"
        ) {
            return Err(GmError::new(
                ErrorCode::BadRequest,
                format!("method {method} is not allowed"),
            ));
        }
        if matches!(method.as_str(), "GET" | "HEAD") && !body.is_empty() {
            return Err(GmError::new(
                ErrorCode::BadRequest,
                "GET/HEAD requests cannot have a body",
            ));
        }
        if body.len() > self.quotas.max_request_body {
            return Err(GmError::new(
                ErrorCode::QuotaExceeded,
                "request body too large",
            ));
        }
        let redirect = match req.redirect.as_str() {
            "" | "follow" => Redirect::Follow,
            "error" => Redirect::Error,
            "manual" => Redirect::Manual,
            r => {
                return Err(GmError::new(
                    ErrorCode::BadRequest,
                    format!("bad redirect mode {r:?}"),
                ))
            }
        };
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut dropped = Vec::new();
        for (n, v) in &req.headers {
            let lc = n.to_ascii_lowercase();
            if !valid_header(n, v) {
                return Err(GmError::new(
                    ErrorCode::BadRequest,
                    format!("invalid header {n:?}"),
                ));
            }
            if forbidden_header(&lc) {
                dropped.push(n.clone());
                continue;
            }
            headers.push((n.clone(), v.clone()));
        }
        if let Some(c) = req.cookie.as_deref().filter(|c| !c.is_empty()) {
            if !valid_header("Cookie", c) {
                return Err(GmError::new(ErrorCode::BadRequest, "invalid cookie value"));
            }
            match headers
                .iter_mut()
                .find(|(n, _)| n.eq_ignore_ascii_case("cookie"))
            {
                Some((_, v)) => {
                    v.push_str("; ");
                    v.push_str(c);
                }
                None => headers.push(("Cookie".into(), c.to_string())),
            }
        }
        if let (Some(u), Some(p)) = (&req.user, &req.password) {
            if !headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("authorization"))
            {
                use base64::Engine;
                let tok = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
                headers.push(("Authorization".into(), format!("Basic {tok}")));
            }
        }
        let timeout = if req.timeout == 0 {
            DEFAULT_TIMEOUT
        } else {
            Duration::from_millis(req.timeout).min(MAX_TIMEOUT)
        };
        Ok(OutboundRequest {
            method,
            url,
            headers,
            body,
            use_cookie_jar: !req.anonymous,
            redirect,
            hops_left: MAX_REDIRECTS,
            timeout,
            dropped_headers: dropped,
        })
    }
}

/// Decide the follow-up request for a redirect response, re-checking `@connect` for the new
/// target. Cross-origin hops drop `Authorization` and `Cookie`; 301/302 (POST) and 303 become
/// GET without a body; 307/308 keep method and body.
pub fn next_hop(
    ctx: &ScriptCtx<'_>,
    prev: &OutboundRequest,
    status: u16,
    location: &str,
) -> GmResult<OutboundRequest> {
    if prev.hops_left == 0 {
        return Err(GmError::new(ErrorCode::BadRequest, "too many redirects"));
    }
    let url = prev
        .url
        .join(location)
        .map_err(|e| GmError::new(ErrorCode::BadRequest, format!("bad redirect location: {e}")))?;
    check_connect(ctx.script, ctx.page_host, &url)?;
    let mut next = prev.clone();
    next.hops_left -= 1;
    if matches!(status, 301..=303)
        && (prev.method != "GET" && prev.method != "HEAD" || status == 303)
    {
        next.method = if prev.method == "HEAD" {
            "HEAD".into()
        } else {
            "GET".into()
        };
        next.body.clear();
        next.headers
            .retain(|(n, _)| !n.to_ascii_lowercase().starts_with("content-"));
    }
    if url.origin() != prev.url.origin() {
        next.headers.retain(|(n, _)| {
            !n.eq_ignore_ascii_case("authorization") && !n.eq_ignore_ascii_case("cookie")
        });
    }
    next.url = url;
    Ok(next)
}

// ---- cookies --------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    /// Unix seconds.
    pub expiration_date: Option<i64>,
}

/// Cookie storage the proxy provides (per profile and script; the GM jar that `xhr` uses too).
pub trait CookieJar {
    fn list(&self, profile: &str, script: &str, url: &Url, name: Option<&str>) -> Vec<Cookie>;
    fn set(&self, profile: &str, script: &str, url: &Url, cookie: Cookie) -> Result<(), String>;
    fn delete(&self, profile: &str, script: &str, url: &Url, name: &str) -> Result<(), String>;
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CookieOp {
    List { url: String, name: Option<String> },
    Set { url: String, cookie: Cookie },
    Delete { url: String, name: String },
}

impl GmBackend {
    /// `GM_cookie.*`: needs `@grant GM_cookie`, and the cookie's URL must pass `@connect`.
    pub fn cookie_op(
        &self,
        ctx: &ScriptCtx<'_>,
        op: CookieOp,
        jar: &dyn CookieJar,
    ) -> GmResult<Value> {
        ctx.require(&["GM_cookie"])?;
        let parse = |u: &str| -> GmResult<Url> {
            let url = Url::parse(u)
                .map_err(|e| GmError::new(ErrorCode::BadRequest, format!("bad url: {e}")))?;
            check_connect(ctx.script, ctx.page_host, &url)?;
            Ok(url)
        };
        let internal = |e: String| GmError::new(ErrorCode::BadRequest, e);
        match op {
            CookieOp::List { url, name } => {
                let url = parse(&url)?;
                Ok(serde_json::to_value(jar.list(
                    ctx.profile,
                    &ctx.script.id,
                    &url,
                    name.as_deref(),
                ))
                .unwrap_or(Value::Null))
            }
            CookieOp::Set { url, cookie } => {
                let url = parse(&url)?;
                jar.set(ctx.profile, &ctx.script.id, &url, cookie)
                    .map_err(internal)?;
                Ok(Value::Null)
            }
            CookieOp::Delete { url, name } => {
                let url = parse(&url)?;
                jar.delete(ctx.profile, &ctx.script.id, &url, &name)
                    .map_err(internal)?;
                Ok(Value::Null)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        install::{finish_install, plan_install, Approvals, Fetched},
        script::Userscript,
    };
    use serde_json::json;

    fn script(hdr: &str, connect_all: bool) -> Userscript {
        let src =
            format!("// ==UserScript==\n// @name t\n// @namespace n\n{hdr}\n// ==/UserScript==\n");
        finish_install(
            plan_install(&src, None).unwrap(),
            Fetched::default(),
            Approvals {
                allow_connect_all: connect_all,
            },
        )
        .unwrap()
    }

    fn backend() -> (GmBackend, tempfile::TempDir) {
        let d = tempfile::tempdir().unwrap();
        let st = Arc::new(UserscriptStorage::new(d.path().to_path_buf()).unwrap());
        (
            GmBackend::new(
                st,
                Quotas {
                    per_script: 200,
                    per_profile: 300,
                    per_value: 120,
                    ..Default::default()
                },
            ),
            d,
        )
    }

    fn ctx<'a>(s: &'a Userscript, p: &'a str) -> ScriptCtx<'a> {
        ScriptCtx {
            profile: p,
            script: s,
            page_host: "page.test",
        }
    }

    #[test]
    fn connect_matrix() {
        let u = |s: &str| Url::parse(s).unwrap();
        let s = script("// @connect api.example.com\n// @connect self\n// @connect localhost\n// @connect 10.1.2.3\n// @connect *.cdn.test", false);
        let ok = |url: &str| check_connect(&s, "page.test", &u(url)).is_ok();
        assert!(ok("https://api.example.com/x"));
        assert!(ok("https://v2.api.example.com/x"));
        assert!(!ok("https://example.com/x"));
        assert!(!ok("https://evilapi.example.com/x"));
        assert!(!ok("https://api.example.com.evil.test/"));
        assert!(ok("https://page.test/x"));
        assert!(ok("http://localhost:8080/"));
        assert!(!ok("http://localhost.evil.test/"));
        assert!(ok("http://10.1.2.3/"));
        assert!(!ok("http://10.1.2.4/"));
        assert!(ok("https://a.cdn.test/") && ok("https://cdn.test/"));
        assert!(
            !ok("ftp://api.example.com/") && !ok("file:///etc/passwd") && !ok("data:text/plain,hi")
        );
        // `*` only with the install-time approval
        let star = script("// @connect *", false);
        assert!(check_connect(&star, "page.test", &u("https://anything.test/")).is_err());
        let star = script("// @connect *", true);
        assert!(check_connect(&star, "page.test", &u("https://anything.test/")).is_ok());
        assert!(check_connect(&star, "page.test", &u("ftp://anything.test/")).is_err());
        // no @connect: only the page's own host
        let none = script("", false);
        assert!(check_connect(&none, "page.test", &u("https://page.test/")).is_ok());
        assert!(check_connect(&none, "page.test", &u("https://other.test/")).is_err());
    }

    #[test]
    fn values_grants_quota_and_isolation() {
        let (b, _d) = backend();
        let s = script("// @grant GM_getValue\n// @grant GM_setValue\n// @grant GM_deleteValue\n// @grant GM_listValues", false);
        let c = ctx(&s, "p1");
        b.values_set(
            &c,
            vec![("a".into(), json!({"x": 1})), ("b".into(), json!("s"))],
            Some("tab1"),
        )
        .unwrap();
        assert_eq!(
            b.values_get(&c, Some(&["a".into()])).unwrap()["a"],
            json!({"x": 1})
        );
        assert_eq!(b.values_list(&c).unwrap(), ["a", "b"]);
        // another profile sees nothing
        let c2 = ctx(&s, "p2");
        assert!(b.values_get(&c2, None).unwrap().is_empty());
        // per-value limit
        let big = json!("x".repeat(200));
        assert_eq!(
            b.values_set(&c, vec![("big".into(), big)], None)
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        // per-script quota (200 bytes): all-or-nothing
        let r = b.values_set(
            &c,
            vec![
                ("k1".into(), json!("y".repeat(95))),
                ("k2".into(), json!("y".repeat(95))),
            ],
            None,
        );
        assert_eq!(r.unwrap_err().code, ErrorCode::QuotaExceeded);
        assert!(b.values_get(&c, Some(&["k1".into()])).unwrap().is_empty());
        // overwrite shrinks usage; delete frees it
        b.values_set(&c, vec![("a".into(), json!(1))], None)
            .unwrap();
        b.values_delete(&c, &["b".into()], None).unwrap();
        b.values_set(&c, vec![("k1".into(), json!("y".repeat(100)))], None)
            .unwrap();
        // per-profile quota (300) across scripts
        let s2 = script("// @name other\n// @grant GM_setValue", false);
        let mut s2 = s2;
        s2.id = "other".into();
        let c3 = ScriptCtx {
            profile: "p1",
            script: &s2,
            page_host: "page.test",
        };
        b.values_set(&c3, vec![("z".into(), json!("q".repeat(100)))], None)
            .unwrap();
        let mut s3 = s2.clone();
        s3.id = "third".into();
        let c4 = ScriptCtx {
            profile: "p1",
            script: &s3,
            page_host: "page.test",
        };
        assert_eq!(
            b.values_set(&c4, vec![("z".into(), json!("q".repeat(100)))], None)
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        // not granted
        let g = script("// @grant GM_getValue", false);
        assert_eq!(
            b.values_set(&ctx(&g, "p1"), vec![("a".into(), json!(1))], None)
                .unwrap_err()
                .code,
            ErrorCode::NotGranted
        );
        let none = script("// @grant none", false);
        assert_eq!(
            b.values_get(&ctx(&none, "p1"), None).unwrap_err().code,
            ErrorCode::NotGranted
        );
    }

    #[test]
    fn usage_survives_restart() {
        let d = tempfile::tempdir().unwrap();
        let st = Arc::new(UserscriptStorage::new(d.path().to_path_buf()).unwrap());
        let s = script("// @grant GM_setValue", false);
        let q = Quotas {
            per_script: 100,
            ..Default::default()
        };
        let b = GmBackend::new(st.clone(), q);
        b.values_set(
            &ctx(&s, "p"),
            vec![("k".into(), json!("a".repeat(80)))],
            None,
        )
        .unwrap();
        let b2 = GmBackend::new(st, q);
        assert!(b2
            .values_set(
                &ctx(&s, "p"),
                vec![("k2".into(), json!("a".repeat(80)))],
                None
            )
            .is_err());
    }

    #[test]
    fn change_log() {
        let (b, _d) = backend();
        let s = script("// @grant GM_getValue\n// @grant GM_setValue\n// @grant GM_deleteValue\n// @grant GM_addValueChangeListener", false);
        let c = ctx(&s, "p");
        assert_eq!(b.values_changes(&c, None).unwrap().seq, 0);
        b.values_set(&c, vec![("a".into(), json!(1))], Some("t1"))
            .unwrap();
        b.values_set(&c, vec![("a".into(), json!(1))], Some("t1"))
            .unwrap(); // unchanged: no event
        b.values_set(&c, vec![("a".into(), json!(2))], Some("t2"))
            .unwrap();
        b.values_delete(&c, &["a".into()], None).unwrap();
        let ch = b.values_changes(&c, Some(0)).unwrap();
        assert_eq!(ch.seq, 3);
        assert_eq!(ch.changes.len(), 3);
        assert_eq!(
            (ch.changes[1].old.clone(), ch.changes[1].new.clone()),
            (Some(json!(1)), Some(json!(2)))
        );
        assert_eq!(ch.changes[1].src.as_deref(), Some("t2"));
        assert_eq!(b.values_changes(&c, Some(2)).unwrap().changes.len(), 1);
    }

    fn xhr(url: &str, headers: &[(&str, &str)]) -> XhrRequest {
        XhrRequest {
            op: "xhr".into(),
            url: url.into(),
            headers: headers
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn outbound_headers_and_policy() {
        let (b, _d) = backend();
        let s = script("// @grant GM_xmlhttpRequest\n// @connect api.test", false);
        let c = ctx(&s, "p");
        let r = b
            .build_outbound(
                &c,
                &XhrRequest {
                    cookie: Some("a=b".into()),
                    user: Some("u".into()),
                    password: Some("p".into()),
                    ..xhr(
                        "https://api.test/x",
                        &[
                            ("Referer", "https://x.test/"),
                            ("Origin", "https://o.test"),
                            ("User-Agent", "UA"),
                            ("Cookie", "c=d"),
                            ("Host", "evil"),
                            ("Connection", "close"),
                            ("Content-Length", "5"),
                            ("Transfer-Encoding", "chunked"),
                            ("Sec-Fetch-Site", "none"),
                            ("X-Forwarded-For", "1.1.1.1"),
                            ("Proxy-Authorization", "x"),
                            ("X-Custom", "ok"),
                        ],
                    )
                },
                vec![],
            )
            .unwrap();
        let get = |n: &str| {
            r.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(n))
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("referer"), Some("https://x.test/"));
        assert_eq!(get("origin"), Some("https://o.test"));
        assert_eq!(get("user-agent"), Some("UA"));
        assert_eq!(get("cookie"), Some("c=d; a=b"));
        assert_eq!(get("authorization"), Some("Basic dTpw"));
        assert_eq!(get("x-custom"), Some("ok"));
        for n in [
            "host",
            "connection",
            "content-length",
            "transfer-encoding",
            "sec-fetch-site",
            "x-forwarded-for",
            "proxy-authorization",
        ] {
            assert!(get(n).is_none(), "{n}");
        }
        assert_eq!(r.dropped_headers.len(), 7);
        assert!(r.use_cookie_jar);
        // denied target / not granted / bad input
        assert_eq!(
            b.build_outbound(&c, &xhr("https://other.test/", &[]), vec![])
                .unwrap_err()
                .code,
            ErrorCode::ConnectDenied
        );
        assert_eq!(
            b.build_outbound(
                &c,
                &XhrRequest {
                    op: "download".into(),
                    ..xhr("https://api.test/", &[])
                },
                vec![]
            )
            .unwrap_err()
            .code,
            ErrorCode::NotGranted
        );
        assert_eq!(
            b.build_outbound(
                &c,
                &XhrRequest {
                    method: "TRACE".into(),
                    ..xhr("https://api.test/", &[])
                },
                vec![]
            )
            .unwrap_err()
            .code,
            ErrorCode::BadRequest
        );
        assert_eq!(
            b.build_outbound(
                &c,
                &xhr("https://api.test/", &[("X", "a\r\nInjected: 1")]),
                vec![]
            )
            .unwrap_err()
            .code,
            ErrorCode::BadRequest
        );
        assert_eq!(
            b.build_outbound(&c, &xhr("https://api.test/", &[]), vec![1])
                .unwrap_err()
                .code,
            ErrorCode::BadRequest
        );
        let anon = b
            .build_outbound(
                &c,
                &XhrRequest {
                    anonymous: true,
                    timeout: 10_000_000,
                    ..xhr("https://api.test/", &[])
                },
                vec![],
            )
            .unwrap();
        assert!(!anon.use_cookie_jar);
        assert_eq!(anon.timeout, MAX_TIMEOUT);
    }

    #[test]
    fn redirects_rechecked_per_hop() {
        let (b, _d) = backend();
        let s = script(
            "// @grant GM_xmlhttpRequest\n// @connect a.test\n// @connect b.test",
            false,
        );
        let c = ctx(&s, "p");
        let first = b
            .build_outbound(
                &c,
                &XhrRequest {
                    method: "POST".into(),
                    ..xhr(
                        "https://a.test/x",
                        &[("Authorization", "t"), ("Content-Type", "text/plain")],
                    )
                },
                b"body".to_vec(),
            )
            .unwrap();
        let h = next_hop(&c, &first, 302, "https://b.test/y").unwrap();
        assert_eq!(h.method, "GET");
        assert!(h.body.is_empty());
        assert!(h
            .headers
            .iter()
            .all(|(n, _)| !n.eq_ignore_ascii_case("authorization")
                && !n.eq_ignore_ascii_case("content-type")));
        let h = next_hop(&c, &first, 307, "/z").unwrap();
        assert_eq!(
            (h.method.as_str(), h.body.len(), h.url.as_str()),
            ("POST", 4, "https://a.test/z")
        );
        assert!(h.headers.iter().any(|(n, _)| n == "Authorization"));
        assert_eq!(
            next_hop(&c, &first, 302, "https://evil.test/")
                .unwrap_err()
                .code,
            ErrorCode::ConnectDenied
        );
        assert_eq!(
            next_hop(&c, &first, 302, "http://127.0.0.1/")
                .unwrap_err()
                .code,
            ErrorCode::ConnectDenied
        );
        let mut spent = first.clone();
        spent.hops_left = 0;
        assert!(next_hop(&c, &spent, 302, "/").is_err());
    }

    #[test]
    fn resources_and_cookies_gated() {
        let (b, _d) = backend();
        let mut s = script(
            "// @grant GM_getResourceText\n// @grant GM_cookie\n// @connect a.test",
            false,
        );
        s.assets.resources.push(crate::script::ResourceBlob {
            name: "r".into(),
            url: "https://a.test/r".into(),
            mime: "text/css".into(),
            data_b64: "aGk=".into(),
        });
        let c = ctx(&s, "p");
        assert_eq!(
            b.resource(&c, "r").unwrap(),
            ("text/css".to_string(), b"hi".to_vec())
        );
        assert_eq!(
            b.resource(&c, "nope").unwrap_err().code,
            ErrorCode::NotFound
        );

        struct Jar;
        impl CookieJar for Jar {
            fn list(&self, _: &str, _: &str, _: &Url, _: Option<&str>) -> Vec<Cookie> {
                vec![Cookie {
                    name: "a".into(),
                    value: "1".into(),
                    ..Default::default()
                }]
            }
            fn set(&self, _: &str, _: &str, _: &Url, _: Cookie) -> Result<(), String> {
                Ok(())
            }
            fn delete(&self, _: &str, _: &str, _: &Url, _: &str) -> Result<(), String> {
                Ok(())
            }
        }
        let l = b
            .cookie_op(
                &c,
                CookieOp::List {
                    url: "https://a.test/".into(),
                    name: None,
                },
                &Jar,
            )
            .unwrap();
        assert_eq!(l[0]["name"], "a");
        assert_eq!(
            b.cookie_op(
                &c,
                CookieOp::List {
                    url: "https://z.test/".into(),
                    name: None
                },
                &Jar
            )
            .unwrap_err()
            .code,
            ErrorCode::ConnectDenied
        );
        let nog = script("// @grant GM_getValue", false);
        assert_eq!(
            b.cookie_op(
                &ctx(&nog, "p"),
                CookieOp::Delete {
                    url: "https://a.test/".into(),
                    name: "a".into()
                },
                &Jar
            )
            .unwrap_err()
            .code,
            ErrorCode::NotGranted
        );
        assert_eq!(
            b.resource(&ctx(&nog, "p"), "r").unwrap_err().code,
            ErrorCode::NotGranted
        );
    }

    #[test]
    fn cookie_jars_are_isolated_per_script() {
        let (b, _d) = backend();
        let mk = |name: &str| {
            let src = format!(
                "// ==UserScript==\n// @name {name}\n// @namespace n\n// @grant GM_cookie\n// @connect a.test\n// ==/UserScript==\n"
            );
            finish_install(
                plan_install(&src, None).unwrap(),
                Fetched::default(),
                Approvals::default(),
            )
            .unwrap()
        };
        let (a, c) = (mk("alpha"), mk("beta"));
        assert_ne!(a.id, c.id);
        let jar = crate::cookies::GmCookieJar::new();
        let u = "https://a.test/".to_string();
        b.cookie_op(
            &ctx(&a, "p"),
            CookieOp::Set {
                url: u.clone(),
                cookie: Cookie {
                    name: "sid".into(),
                    value: "secret".into(),
                    http_only: true,
                    ..Default::default()
                },
            },
            &jar,
        )
        .unwrap();
        let list = |s: &Userscript| {
            b.cookie_op(
                &ctx(s, "p"),
                CookieOp::List {
                    url: u.clone(),
                    name: None,
                },
                &jar,
            )
            .unwrap()
        };
        assert_eq!(
            list(&a).as_array().unwrap().len(),
            1,
            "owner sees its cookie"
        );
        assert!(
            list(&c).as_array().unwrap().is_empty(),
            "another script must not"
        );
        let url = Url::parse(&u).unwrap();
        assert!(
            jar.header_for("p", &c.id, &url).is_none(),
            "nor replay it on its own requests"
        );
    }
}

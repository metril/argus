//! The browser-extension bridge endpoints.
//!
//! * `GET /ext/channel` is a WebSocket. It is public at the HTTP layer because browsers cannot
//!   set headers on a WebSocket and the token must not travel in the URL: the first frame is
//!   `{"t":"hello","token":...,"v":1}` and the socket is closed when it does not arrive within
//!   five seconds, or the token is unknown, expired, or lacks `userscripts:bridge`.
//! * `GET /ext/menu` and `POST /ext/menu/trigger` need the bridge scope and the `X-Argus-Session`
//!   header naming the live session of the calling token; the document must be bound to that
//!   very session (a document opened by another browser, or by a browser without the
//!   extension, is refused).

use std::sync::Arc;
use std::time::Duration;

use api_types::{
    AuditEntry, ExtAuditEvent, ExtCookieAttrs, ExtCookieChange, ExtCookieProvenance,
    ExtCookieRecord, ExtError, ExtIdent, ExtLogEntry, ExtLogResponse, ExtMenuResponse, ExtOut,
    ExtRuleRequest, ExtRuleResult, ExtSiteRule, ExtSiteRules, ExtTriggerRequest,
    ExtTriggerResponse, Scope, UserRole,
};
use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::Response,
    Extension, Json,
};
use chrono::Utc;
use serde::Deserialize;
use tracing::debug;
use utoipa::IntoParams;

use crate::auth::authz::{Actor, Principal};
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::state::{blocking, AppState, ExtBridge};

/// The first frame must arrive within this long.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// A silent channel (no frame, no ping) is closed after this long.
const IDLE_TIMEOUT: Duration = Duration::from_secs(75);
/// Largest hello frame.
const HELLO_MAX: usize = 4096;
/// Header naming the caller's channel session.
pub const SESSION_HEADER: &str = "x-argus-session";

pub const CLOSE_BAD_TOKEN: u16 = 4401;
pub const CLOSE_NO_SCOPE: u16 = 4403;
pub const CLOSE_HELLO_TIMEOUT: u16 = 4408;
pub const CLOSE_BAD_HELLO: u16 = 4400;

impl AppState {
    /// Close the live extension channels of these tokens (revoked, or their owner is gone).
    pub fn close_ext_tokens(&self, ids: &[String]) {
        if let Some(b) = self.ext.get() {
            for id in ids {
                b.close_token(id);
            }
        }
    }

    /// Close the live extension channels of every token `user` owns.
    pub fn close_ext_for_user(&self, user: &uuid::Uuid) {
        let ids: Vec<String> = self
            .tokens
            .list(Some(user), true)
            .into_iter()
            .map(|t| t.id.clone())
            .collect();
        self.close_ext_tokens(&ids);
    }

    /// Append a bridge audit record to the persisted audit log.
    pub fn record_ext_audit(&self, ev: ExtAuditEvent) {
        let entry = AuditEntry {
            id: String::new(),
            at: Utc::now().to_rfc3339(),
            actor_type: "token".into(),
            actor_id: None,
            actor_name: Some(ev.actor),
            method: "EXT".into(),
            route: format!("ext/{}", ev.action),
            scope: Scope::UserscriptsBridge.as_str().into(),
            target: ev.target,
            status: 200,
            outcome: "success".into(),
            ip: None,
            user_agent: None,
            request_id: None,
        };
        if let Err(e) = self.audit.append(entry) {
            tracing::error!("Failed to write audit entry: {e}");
        }
    }
}

fn bridge(state: &AppState) -> ApiResult<&Arc<dyn ExtBridge>> {
    state.ext.get().ok_or_else(|| {
        ApiError::coded(
            StatusCode::SERVICE_UNAVAILABLE,
            "ext_unavailable",
            "The extension bridge is not available in this build",
        )
    })
}

/// Origins an extension background script connects from (or none at all, e.g. a CLI).
fn origin_ok(h: &HeaderMap) -> bool {
    match h.get("origin").and_then(|v| v.to_str().ok()) {
        None => true,
        Some(o) => [
            "chrome-extension://",
            "moz-extension://",
            "safari-web-extension://",
        ]
        .iter()
        .any(|p| o.starts_with(p)),
    }
}

/// WebSocket channel of the browser extension.
#[utoipa::path(
    get, path = "/ext/channel", tag = "ext",
    security(()),
    responses(
        (status = 101, description = "Switching protocols; first frame `{\"t\":\"hello\",\"token\":...,\"v\":1}`"),
        (status = 403, description = "Origin is not an extension"),
        (status = 503, description = "No extension bridge in this build")
    )
)]
pub async fn channel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    if !origin_ok(&headers) {
        return Err(ApiError::AuthorizationFailed(
            "The channel is for the Argus extension".into(),
        ));
    }
    let b = bridge(&state)?.clone();
    Ok(ws
        .max_message_size(1 << 20)
        .max_frame_size(1 << 20)
        .on_upgrade(move |sock| run_channel(state, b, sock)))
}

async fn close_with(mut sock: WebSocket, code: u16, why: &'static str) {
    let _ = sock
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: why.into(),
        })))
        .await;
}

#[derive(Deserialize)]
struct Hello {
    t: String,
    token: String,
    #[serde(default)]
    v: u32,
    /// The `sid` of a session this channel takes over (worker restart, dropped socket).
    #[serde(default)]
    resume: Option<String>,
}

/// Validate a hello: the token is live, its owner is enabled, and it holds the bridge scope
/// (limited to what the owner can still do).
fn identify(state: &AppState, token: &str) -> Result<ExtIdent, u16> {
    let cached = state.tokens.verify(token).map_err(|_| CLOSE_BAD_TOKEN)?;
    let user = state
        .session_store
        .get_user(&cached.stored.created_by)
        .ok()
        .flatten()
        .filter(|u| u.enabled)
        .ok_or(CLOSE_BAD_TOKEN)?;
    let role: UserRole = user.role;
    let ok = cached.stored.scopes.contains(&Scope::UserscriptsBridge)
        && role.scopes().contains(&Scope::UserscriptsBridge);
    if !ok {
        return Err(CLOSE_NO_SCOPE);
    }
    state.tokens.mark_used(&cached, None);
    Ok(ExtIdent {
        token_id: cached.stored.id.clone(),
        user: user.username,
        profiles: cached.stored.profiles.clone(),
    })
}

/// How many pings pass between token re-verifications of a live channel.
const REVERIFY_PINGS: u32 = 3;

impl AppState {
    /// The same checks a `hello` makes, for a stored token id (restoring persisted sessions).
    pub fn ext_token_ok(&self, token_id: &str) -> bool {
        let Some(t) = self.tokens.get(token_id) else {
            return false;
        };
        self.tokens.is_live(token_id)
            && t.stored.scopes.contains(&Scope::UserscriptsBridge)
            && self
                .session_store
                .get_user(&t.stored.created_by)
                .ok()
                .flatten()
                .is_some_and(|u| u.enabled && u.role.scopes().contains(&Scope::UserscriptsBridge))
    }
}

/// [`identify`] without marking the token used.
fn identify_quiet(state: &AppState, token: &str) -> Result<(), u16> {
    let cached = state.tokens.verify(token).map_err(|_| CLOSE_BAD_TOKEN)?;
    let user = state
        .session_store
        .get_user(&cached.stored.created_by)
        .ok()
        .flatten()
        .filter(|u| u.enabled)
        .ok_or(CLOSE_BAD_TOKEN)?;
    if cached.stored.scopes.contains(&Scope::UserscriptsBridge)
        && user.role.scopes().contains(&Scope::UserscriptsBridge)
    {
        Ok(())
    } else {
        Err(CLOSE_NO_SCOPE)
    }
}

async fn run_channel(state: Arc<AppState>, b: Arc<dyn ExtBridge>, mut sock: WebSocket) {
    let first = tokio::time::timeout(HELLO_TIMEOUT, sock.recv()).await;
    let text = match first {
        Err(_) => return close_with(sock, CLOSE_HELLO_TIMEOUT, "hello timeout").await,
        Ok(Some(Ok(Message::Text(t)))) if t.len() <= HELLO_MAX => t.to_string(),
        Ok(_) => return close_with(sock, CLOSE_BAD_HELLO, "bad hello").await,
    };
    let hello: Hello = match serde_json::from_str::<Hello>(&text) {
        Ok(h) if h.t == "hello" && h.v == 1 => h,
        _ => return close_with(sock, CLOSE_BAD_HELLO, "bad hello").await,
    };
    let ident = match identify(&state, &hello.token) {
        Ok(i) => i,
        Err(code) => return close_with(sock, code, "refused").await,
    };
    let user = ident.user.clone();
    let resumed = hello
        .resume
        .as_deref()
        .filter(|r| r.len() <= 128)
        .and_then(|r| b.resume(&ident, r));
    let was_resumed = resumed.is_some();
    let (id, sid, mut out) = resumed.unwrap_or_else(|| b.open(ident));
    let welcome =
        serde_json::json!({"t": "welcome", "sid": sid, "v": 1, "resumed": was_resumed}).to_string();
    if sock.send(Message::Text(welcome.into())).await.is_err() {
        b.close(id);
        return;
    }
    if sock
        .send(Message::Text(b.proxy_msg().into()))
        .await
        .is_err()
    {
        b.close(id);
        return;
    }
    state.record_ext_audit(ExtAuditEvent {
        actor: user.clone(),
        action: if was_resumed {
            "session_resume"
        } else {
            "session_open"
        }
        .into(),
        target: Some(id.to_string()),
    });
    let mut pings = 0u32;
    // Ends the session for good (revoked, evicted, or the extension said `bye`); otherwise a
    // dropped channel leaves it in its grace period.
    let mut hard = false;
    loop {
        tokio::select! {
            o = out.recv() => match o {
                Some(ExtOut::Text(t)) => if sock.send(Message::Text(t.into())).await.is_err() { break },
                Some(ExtOut::Binary(v)) => if sock.send(Message::Binary(v.into())).await.is_err() { break },
                Some(ExtOut::Close(code)) => {
                    let _ = sock.send(Message::Close(Some(CloseFrame { code, reason: "closed".into() }))).await;
                    hard = true;
                    break;
                }
                None => break,
            },
            m = tokio::time::timeout(IDLE_TIMEOUT, sock.recv()) => match m {
                Err(_) | Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => break,
                Ok(Some(Ok(Message::Text(t)))) => {
                    // Backstop for revocation, expiry and disabled owners: re-verify the token
                    // every few pings (explicit revocation closes the channel at once).
                    if t.contains("\"ping\"") {
                        pings += 1;
                        if pings.is_multiple_of(REVERIFY_PINGS) && identify_quiet(&state, &hello.token).is_err() {
                            let _ = sock.send(Message::Close(Some(CloseFrame { code: CLOSE_BAD_TOKEN, reason: "revoked".into() }))).await;
                            hard = true;
                            break;
                        }
                    }
                    if t.len() < 64 && t.contains("\"bye\"") {
                        hard = true;
                        break;
                    }
                    b.on_text(id, &t).await
                }
                Ok(Some(Ok(Message::Binary(v)))) => b.on_binary(id, v.to_vec()).await,
                Ok(Some(Ok(_))) => {}
            },
        }
    }
    drop(out);
    if hard {
        b.close(id);
    } else {
        b.detach(id);
    }
    debug!("extension channel {id} closed");
    state.record_ext_audit(ExtAuditEvent {
        actor: user,
        action: if hard {
            "session_close"
        } else {
            "session_detach"
        }
        .into(),
        target: Some(id.to_string()),
    });
}

/// The live session this request's token and `X-Argus-Session` header name.
fn session_of(state: &AppState, p: &Principal, h: &HeaderMap) -> ApiResult<u64> {
    let b = bridge(state)?;
    let Actor::Token { token_id } = &p.actor else {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "ext_token_required",
            "The extension bridge needs an API token",
        ));
    };
    let sid = h
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    b.session_for(sid, token_id).ok_or_else(|| {
        ApiError::coded(
            StatusCode::FORBIDDEN,
            "ext_session_required",
            "No live extension session for this token",
        )
    })
}

/// The cookie store (Firefox container) of the popup's tab, as the opaque token the extension
/// used in its proxy credentials; empty for the default store.
fn store_of(h: &HeaderMap) -> String {
    h.get("x-argus-store")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 40 && v.bytes().all(|b| b.is_ascii_alphanumeric()))
        .unwrap_or("")
        .to_string()
}

fn map_err(e: ExtError) -> ApiError {
    match e {
        ExtError::Forbidden => ApiError::coded(
            StatusCode::FORBIDDEN,
            "ext_document_not_bound",
            "This document was not opened through your connected extension",
        ),
        ExtError::NotFound => ApiError::NotFound("Unknown document".into()),
    }
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MenuQuery {
    /// Public document id from the page's `Server-Timing: argus` entry.
    pub mdoc: String,
}

/// Menu commands the document's userscripts registered, plus host grants they are waiting for.
#[utoipa::path(
    get, path = "/ext/menu", tag = "ext",
    security(("bearer_auth" = ["userscripts:bridge"])),
    params(MenuQuery),
    responses(
        (status = 200, description = "Commands and grants", body = ExtMenuResponse),
        (status = 403, description = "No session, or the document is bound to another one"),
        (status = 404, description = "Unknown document")
    )
)]
pub async fn menu(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    headers: HeaderMap,
    Query(q): Query<MenuQuery>,
) -> ApiResult<Json<ExtMenuResponse>> {
    let session = session_of(&state, &p, &headers)?;
    let r = bridge(&state)?
        .menu(session, &store_of(&headers), &q.mdoc)
        .map_err(map_err)?;
    Ok(Json(r))
}

/// Run one menu command in the page.
#[utoipa::path(
    post, path = "/ext/menu/trigger", tag = "ext",
    security(("bearer_auth" = ["userscripts:bridge"])),
    request_body = ExtTriggerRequest,
    responses(
        (status = 200, description = "Queued for the page", body = ExtTriggerResponse),
        (status = 403, description = "No session, or the document is bound to another one"),
        (status = 404, description = "Unknown document or command")
    )
)]
pub async fn trigger(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    headers: HeaderMap,
    ApiJson(req): ApiJson<ExtTriggerRequest>,
) -> ApiResult<Json<ExtTriggerResponse>> {
    let session = session_of(&state, &p, &headers)?;
    let delivered = bridge(&state)?
        .trigger(session, &store_of(&headers), &req)
        .map_err(map_err)?;
    Ok(Json(ExtTriggerResponse { delivered }))
}

// ---------------------------------------------------------------------------
// Request log
// ---------------------------------------------------------------------------

/// Most entries one `GET /ext/log` returns.
const LOG_PAGE: usize = 500;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LogQuery {
    /// Return the entries after this sequence number (default: all that are kept).
    pub since: Option<u64>,
}

/// The requests of the calling extension session (blocks and allowed requests of the connections
/// bound to it), oldest first, with the matched rule and its list. Another session's requests
/// are never returned; the log holds the newest 1000 entries.
#[utoipa::path(
    get, path = "/ext/log", tag = "ext",
    security(("bearer_auth" = ["logs:read"])),
    params(LogQuery),
    responses(
        (status = 200, description = "Entries after `since`", body = ExtLogResponse),
        (status = 403, description = "No live extension session for this token")
    )
)]
pub async fn log(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    headers: HeaderMap,
    Query(q): Query<LogQuery>,
) -> ApiResult<Json<ExtLogResponse>> {
    let session = session_of(&state, &p, &headers)?;
    let (rows, next) = filter_engine::session_log().since(session, q.since.unwrap_or(0), LOG_PAGE);
    let st = state.clone();
    let entries = blocking(move || {
        Ok(rows
            .into_iter()
            .map(|r| {
                let list_id = r
                    .list_id
                    .as_deref()
                    .map(|id| crate::rule_origin::public_id(id).to_string());
                ExtLogEntry {
                    seq: r.seq,
                    time: r.ts.to_rfc3339(),
                    url: r.url,
                    method: r.method,
                    request_type: r.request_type,
                    third_party: r.third_party,
                    outcome: serde_json::to_value(r.kind)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_default(),
                    rule: r.rule,
                    list_name: list_id.as_deref().and_then(|id| st.list_name(id)),
                    user_rule: list_id.as_deref() == Some(crate::rule_origin::CUSTOM_ID),
                    list_id,
                    source_host: r.source_host,
                }
            })
            .collect::<Vec<_>>())
    })
    .await?;
    Ok(Json(ExtLogResponse { next, entries }))
}

// ---------------------------------------------------------------------------
// Cookie provenance
// ---------------------------------------------------------------------------

/// Most records one `GET /ext/cookies/provenance` returns.
const PROVENANCE_PAGE: usize = 500;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ProvenanceQuery {
    /// Return the records after this sequence number (default: all that are kept).
    pub since: Option<u64>,
    /// Only records of this site: its registrable domain and every subdomain.
    pub host: Option<String>,
    /// At most this many records (default and maximum 500).
    pub limit: Option<usize>,
}

/// Where the cookies of the calling extension session came from: for each `Set-Cookie` its name,
/// the response's host and path, the attributes the server sent, and whether a `$cookie` rule
/// left it alone, changed it or removed it, plus the cookies rules kept out of requests. Cookie
/// values are never recorded or returned. Recording is a setting that is off by default; while
/// it is off the answer is `{enabled: false}`. Another session's records are never returned;
/// the newest 3000 are kept per session, in memory only.
#[utoipa::path(
    get, path = "/ext/cookies/provenance", tag = "ext",
    security(("bearer_auth" = ["logs:read"])),
    params(ProvenanceQuery),
    responses(
        (status = 200, description = "Records after `since`; `enabled: false` while the setting is off", body = ExtCookieProvenance),
        (status = 403, description = "No live extension session for this token")
    )
)]
pub async fn cookie_provenance(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    headers: HeaderMap,
    Query(q): Query<ProvenanceQuery>,
) -> ApiResult<Json<ExtCookieProvenance>> {
    let session = session_of(&state, &p, &headers)?;
    let since = q.since.unwrap_or(0);
    let on = state
        .cookie_provenance
        .get()
        .is_some_and(|h| h.load(std::sync::atomic::Ordering::Relaxed));
    if !on {
        return Ok(Json(ExtCookieProvenance {
            enabled: false,
            records: Vec::new(),
            next_since: since,
            more: false,
        }));
    }
    let limit = q.limit.unwrap_or(PROVENANCE_PAGE).clamp(1, PROVENANCE_PAGE);
    let (rows, next_since, more) =
        filter_engine::cookie_log().since(session, since, limit, q.host.as_deref());
    let st = state.clone();
    let records = blocking(move || {
        Ok(rows
            .into_iter()
            .map(|r| {
                let list_id = r
                    .list_id
                    .as_deref()
                    .map(|id| crate::rule_origin::public_id(id).to_string());
                let a = r.attrs;
                ExtCookieRecord {
                    seq: r.seq,
                    time: r.ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    effect: r.effect.as_str().to_string(),
                    name: r.name,
                    host: r.host,
                    path: r.path,
                    page_host: r.page_host,
                    third_party: r.third_party,
                    attrs: ExtCookieAttrs {
                        domain: a.domain,
                        path: a.path,
                        secure: a.secure,
                        http_only: a.http_only,
                        same_site: a.same_site.map(|s| s.as_str().to_string()),
                        max_age: a.max_age,
                        expires: a.expires,
                        partitioned: a.partitioned,
                    },
                    changes: r
                        .changes
                        .into_iter()
                        .map(|c| {
                            let lid = c
                                .list_id
                                .as_deref()
                                .map(|id| crate::rule_origin::public_id(id).to_string());
                            ExtCookieChange {
                                attr: c.attr.to_string(),
                                from: c.from,
                                to: c.to,
                                rule: c.rule,
                                list_name: lid.as_deref().and_then(|id| st.list_name(id)),
                                user_rule: lid.as_deref() == Some(crate::rule_origin::CUSTOM_ID),
                                list_id: lid,
                            }
                        })
                        .collect(),
                    prefix: r.prefix.map(|(p, _)| p.to_string()),
                    prefix_valid: r.prefix.map(|(_, ok)| ok),
                    rule: r.rule,
                    list_name: list_id.as_deref().and_then(|id| st.list_name(id)),
                    user_rule: list_id.as_deref() == Some(crate::rule_origin::CUSTOM_ID),
                    list_id,
                }
            })
            .collect::<Vec<_>>())
    })
    .await?;
    Ok(Json(ExtCookieProvenance {
        enabled: true,
        records,
        next_since,
        more,
    }))
}

// ---------------------------------------------------------------------------
// Custom rules, one line at a time
// ---------------------------------------------------------------------------

/// Longest rule accepted.
pub const RULE_MAX: usize = 2048;
/// Serializes read-modify-write of the custom rules.
static RULES_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Network options the extension's one-line rules may carry (besides `domain=`, which has its
/// own check).
const FLAG_OPTIONS: [&str; 6] = [
    "third-party",
    "3p",
    "first-party",
    "1p",
    "important",
    "match-case",
];
/// Resource types a rule may be limited to.
const TYPE_OPTIONS: [&str; 17] = [
    "document",
    "doc",
    "subdocument",
    "frame",
    "stylesheet",
    "css",
    "script",
    "image",
    "font",
    "object",
    "xmlhttprequest",
    "xhr",
    "ping",
    "media",
    "websocket",
    "other",
    "fetch",
];

/// A host name a rule may be scoped to: letters, digits, `-` and `.` only, not an IP address,
/// and at least a registrable domain (`example.com`, `a.example.co.uk`; not `com`, `co.uk`).
fn registrable_host(h: &str) -> bool {
    let ok = !h.is_empty()
        && h.len() <= 253
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && !h.starts_with(['.', '-'])
        && !h.ends_with(['.', '-'])
        && !h.contains("..");
    if !ok || h.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    let h = h.to_ascii_lowercase();
    // A numeric last label is an (incomplete) IPv4 address, not a name.
    if h.rsplit('.')
        .next()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    psl::domain_str(&h).is_some() && psl::suffix(h.as_bytes()).is_some_and(|s| s.is_known())
}

/// Is `pat` (an anchored pattern, `@@` already removed) exactly a `||host...` or
/// `|scheme://host...` rule on a registrable host, with nothing that widens the host?
fn anchored_host_pattern(pat: &str) -> bool {
    let rest = if let Some(r) = pat.strip_prefix("||") {
        r
    } else if let Some(r) = pat.strip_prefix('|') {
        match ["https://", "http://", "wss://", "ws://"]
            .iter()
            .find_map(|sch| r.strip_prefix(sch))
        {
            Some(r) => r,
            None => return false,
        }
    } else {
        return false;
    };
    let end = rest
        .find(['^', '/', ':', '|', '?', '*'])
        .unwrap_or(rest.len());
    let (host, tail) = rest.split_at(end);
    // Only a separator, path or port may follow the host (a bare host or a wildcard is refused): `||example.com*` would also
    // match `example.com.evil.net`.
    registrable_host(host) && tail.starts_with(['^', '/', ':', '|'])
}

/// Characters of a pattern the one-line rules accept (no `$` options marker, no `#` cosmetic
/// marker, no regex or comment syntax).
fn pattern_chars_ok(pat: &str) -> bool {
    pat.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'.' | b'-'
                    | b'_'
                    | b'~'
                    | b':'
                    | b'/'
                    | b'?'
                    | b'&'
                    | b'='
                    | b'%'
                    | b'+'
                    | b','
                    | b';'
                    | b'!'
                    | b'^'
                    | b'*'
                    | b'|'
            )
    })
}

/// Parsed options of an extension rule.
#[derive(Default)]
struct ExtOptions {
    /// Positive `$domain=` entries (all registrable).
    domains: usize,
}

fn check_options(opts: &str) -> Result<ExtOptions, String> {
    let mut out = ExtOptions::default();
    let mut seen: Vec<String> = Vec::new();
    for o in opts.split(',') {
        let (neg, o) = o.strip_prefix('~').map_or((false, o), |r| (true, r));
        let (name, value) = o.split_once('=').map_or((o, None), |(n, v)| (n, Some(v)));
        let name = name.to_ascii_lowercase();
        if seen.contains(&name) {
            return Err(format!("The option '{name}' is given twice"));
        }
        seen.push(name.clone());
        match (name.as_str(), value) {
            ("domain", Some(v)) if !neg => {
                for d in v.split('|') {
                    let (dneg, d) = d.strip_prefix('~').map_or((false, d), |r| (true, r));
                    if !registrable_host(d) {
                        return Err(format!(
                            "'{d}' in $domain= must be a registrable domain such as example.com"
                        ));
                    }
                    if !dneg {
                        out.domains += 1;
                    }
                }
            }
            (n, None) if FLAG_OPTIONS.contains(&n) => {
                // Flags may be negated only where it means something (`~third-party`).
                if neg && !matches!(n, "third-party" | "3p" | "first-party" | "1p") {
                    return Err(format!("'~{n}' is not accepted here"));
                }
            }
            (n, None) if TYPE_OPTIONS.contains(&n) => {}
            _ => return Err(format!("The option '{o}' is not accepted here")),
        }
    }
    Ok(out)
}

/// Check that `rule` is one acceptable network rule; returns it trimmed.
///
/// An allowlist: the rule must be a plain network filter built from a pattern and a few options
/// (`domain=`, `third-party`/`1p`/`3p`, resource types, `important`, `match-case`). Its pattern
/// must either anchor a registrable host (`||example.com^`, `|https://example.com/x`) or, when it
/// is broader, be limited with `$domain=` to specific registrable domains. This holds for block
/// and `@@` exception rules alike, so one line cannot switch blocking off, or on, beyond a site.
/// Plain `domain##selector` hiding rules are checked by `check_ext_cosmetic`. Exception, scriptlet, redirect, rewrite, header, `$badfilter` and every other rule form fail
/// the allowlist.
pub fn check_ext_rule(rule: &str) -> Result<String, String> {
    if rule.len() > RULE_MAX {
        return Err("The rule is longer than 2 KB".into());
    }
    if rule.contains(['\n', '\r', '\0']) {
        return Err("Send exactly one line".into());
    }
    let r = rule.trim();
    if r.is_empty() {
        return Err("The rule is empty".into());
    }
    if r.starts_with('!') || r.starts_with('[') {
        return Err("Comments, includes and preprocessor lines are not accepted".into());
    }
    if let Some(c) = filter_engine::formats::split_cosmetic(r) {
        return check_ext_cosmetic(r, &c);
    }
    let body = r.strip_prefix("@@").unwrap_or(r);
    let (pat, opts) = match body.split_once('$') {
        Some((p, o)) => (p, Some(o)),
        None => (body, None),
    };
    if pat.is_empty() || !pattern_chars_ok(pat) {
        return Err(
            "Only a plain network pattern is accepted (no cosmetic, scriptlet or \
                    regex rules)"
                .into(),
        );
    }
    let parsed = match opts {
        Some("") => return Err("The options after '$' are empty".into()),
        Some(o) => check_options(o)?,
        None => ExtOptions::default(),
    };
    if !anchored_host_pattern(pat) && parsed.domains == 0 {
        return Err(
            "The rule must start with ||host or |https://host on a registrable domain \
                    (such as example.com), or be limited with $domain= to specific domains"
                .into(),
        );
    }
    let v = super::rules::validate_rules(r, filter_engine::ListFormat::Abp, false, false);
    match v.lines.as_slice() {
        [l] if l.outcome == "accepted" || l.outcome == "translated" => Ok(lower_host(r)),
        [l] => Err(l
            .error
            .clone()
            .unwrap_or_else(|| "The rule is not accepted".into())),
        _ => Err("Not a rule".into()),
    }
}

/// Cosmetic selector length limit (the whole rule is held to 1 KB).
const COSMETIC_MAX: usize = 1024;

/// Pseudo-classes a plain hide selector may use; everything else (`:has-text`, `:xpath`, `:style`,
/// `:remove`, `:upward`, `:matches-css`, `:-abp-*`, `:has`, ...) is procedural or extended.
const PLAIN_PSEUDOS: &[&str] = &[
    "not",
    "is",
    "where",
    "nth-child",
    "nth-of-type",
    "nth-last-child",
    "nth-last-of-type",
    "first-child",
    "last-child",
    "first-of-type",
    "last-of-type",
    "only-child",
    "only-of-type",
];

/// Split `s` at top-level commas (outside parentheses, brackets and quotes).
fn split_top_commas(s: &str) -> Vec<&str> {
    let (mut out, mut depth, mut quote, mut start) = (Vec::new(), 0i32, None::<char>, 0usize);
    let mut esc = false;
    for (i, ch) in s.char_indices() {
        if esc {
            esc = false;
            continue;
        }
        match (ch, quote) {
            ('\\', _) => esc = true,
            (c, Some(q)) if c == q => quote = None,
            (_, Some(_)) => {}
            ('"' | '\'', None) => quote = Some(ch),
            ('(' | '[', None) => depth += 1,
            (')' | ']', None) => depth -= 1,
            (',', None) if depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

/// `s` with every parenthesised group and quoted string removed (so `:not(.a)` carries nothing).
fn strip_groups(s: &str) -> String {
    let (mut out, mut depth, mut quote, mut esc) = (String::new(), 0i32, None::<char>, false);
    for ch in s.chars() {
        if esc {
            esc = false;
            continue;
        }
        match (ch, quote) {
            ('\\', _) => esc = true,
            (c, Some(q)) if c == q => quote = None,
            (_, Some(_)) => {}
            ('"' | '\'', None) => quote = Some(ch),
            ('(', None) => depth += 1,
            (')', None) => depth -= 1,
            (c, None) if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// Plain-syntax check of one hide selector: no declarations, comments or extended pseudos.
fn check_plain_selector(sel: &str) -> Result<(), String> {
    if sel.is_empty() {
        return Err("The selector is empty".into());
    }
    if sel.contains(['{', '}', ';', '`', '<']) {
        return Err("The selector contains characters a CSS selector cannot".into());
    }
    if sel.contains("/*") || sel.contains("url(") || sel.contains("expression(") {
        return Err("The selector is not a plain CSS selector".into());
    }
    if sel.starts_with('^') || sel.contains("+js(") {
        return Err("Only plain element hiding is accepted".into());
    }
    if sel.ends_with('\\') {
        return Err("The selector ends with a backslash".into());
    }
    let low = sel.to_ascii_lowercase();
    if ["__ab", "__adblock", "__argus", "argus"]
        .iter()
        .any(|n| low.contains(n))
    {
        return Err("The selector could target Argus's own interface".into());
    }
    // Every pseudo must be on the plain list.
    let b = sel.as_bytes();
    let (mut quote, mut esc, mut i) = (None::<u8>, false, 0);
    while i < b.len() {
        let c = b[i];
        if esc {
            esc = false;
        } else if c == b'\\' {
            esc = true;
        } else if let Some(q) = quote {
            if c == q {
                quote = None;
            }
        } else if c == b'"' || c == b'\'' {
            quote = Some(c);
        } else if c == b':' {
            let rest = &sel[i + 1..];
            if rest.starts_with(':') {
                return Err("Pseudo-elements are not accepted".into());
            }
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            if !PLAIN_PSEUDOS.contains(&name.to_ascii_lowercase().as_str()) {
                return Err(format!(
                    "':{name}' is procedural or extended syntax, not accepted here"
                ));
            }
        }
        i += 1;
    }
    if quote.is_some() {
        return Err("Unbalanced quotes in the selector".into());
    }
    let mut d = 0i32;
    for ch in sel.chars() {
        match ch {
            '(' | '[' => d += 1,
            ')' | ']' => d -= 1,
            _ => {}
        }
        if d < 0 {
            return Err("Unbalanced brackets in the selector".into());
        }
    }
    if d != 0 {
        return Err("Unbalanced brackets in the selector".into());
    }
    Ok(())
}

/// Attribute groups `[...]` of `s` (quote-aware), without the brackets.
fn attr_groups(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut quote, mut esc) = (Vec::new(), None::<String>, None::<char>, false);
    for ch in s.chars() {
        match (&mut cur, quote) {
            (None, _) => {
                if ch == '[' {
                    cur = Some(String::new());
                }
            }
            (Some(c), q) => {
                if esc {
                    esc = false;
                } else if ch == '\\' {
                    esc = true;
                } else if let Some(q) = q {
                    if ch == q {
                        quote = None;
                    }
                } else if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                } else if ch == ']' {
                    out.push(std::mem::take(c));
                    cur = None;
                    continue;
                }
                c.push(ch);
            }
        }
    }
    out
}

/// An attribute selector too loose for an all-sites rule: `*=`/`~=`, a value under 3 characters,
/// or one of the attributes every page has (`lang`, `dir`, `style`, `class`, `id`).
fn loose_attr(inner: &str) -> bool {
    let Some(eq) = inner.find('=') else {
        return false;
    };
    let head = &inner[..eq];
    let (name, op) = match head.chars().last() {
        Some(c @ ('*' | '~' | '^' | '$' | '|')) => (&head[..head.len() - 1], Some(c)),
        _ => (head, None),
    };
    if matches!(op, Some('*' | '~')) {
        return true;
    }
    if matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "lang" | "dir" | "style" | "class" | "id"
    ) {
        return true;
    }
    let v = inner[eq + 1..].trim();
    let v = v
        .strip_suffix(" i")
        .or_else(|| v.strip_suffix(" s"))
        .unwrap_or(v)
        .trim()
        .trim_matches(['"', '\'']);
    v.chars().count() < 3
}

/// Is the last compound selector of `part` specific: an id, a class or a valued attribute (not
/// a bare tag, `*`, or something only named inside `:not()`), and not one that can hide a whole
/// page (html, body, :root, loose or universal attributes)?
fn specific_compound(part: &str) -> bool {
    if attr_groups(part).iter().any(|a| loose_attr(a)) {
        return false;
    }
    let flat = strip_groups(part);
    // Attribute groups are bracketed, not parenthesised: take out their bodies but note a value.
    let last = flat
        .rsplit([' ', '>', '+', '~', '\t'])
        .find(|c| !c.is_empty())
        .unwrap_or("");
    let tag = last
        .split(['#', '.', '[', ':'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if tag == "html" || tag == "body" || last.to_ascii_lowercase().contains(":root") {
        return false;
    }
    let has_id_class = last.contains(['#', '.']);
    // An attribute selector counts only with a comparison (`[id]`/`[class]` alone match everything).
    let has_valued_attr = last.split('[').skip(1).any(|a| {
        let inner = a.split(']').next().unwrap_or("");
        inner.contains('=') && !inner.starts_with('=')
    });
    has_id_class || has_valued_attr
}

fn check_ext_cosmetic(r: &str, c: &filter_engine::formats::Cosmetic<'_>) -> Result<String, String> {
    if r.len() > COSMETIC_MAX {
        return Err("A cosmetic rule is limited to 1 KB".into());
    }
    if c.sep != "##" {
        return Err(
            "Only plain element hiding (domain##selector) is accepted; exceptions, procedural, \
             style, scriptlet and HTML-filter rules are not"
                .into(),
        );
    }
    let sel = c.body.trim();
    check_plain_selector(sel)?;
    let domains = c.domains;
    if domains.is_empty() {
        // Everywhere: every comma-separated selector must pin something specific.
        for part in split_top_commas(sel) {
            if !specific_compound(part.trim()) {
                return Err(
                    "A selector for all sites needs an id, a class or an attribute value on \
                     the element (not a bare tag or *)"
                        .into(),
                );
            }
        }
    } else {
        for d in domains.split(',') {
            if !registrable_host(d) {
                return Err(format!(
                    "'{d}' must be a registrable domain such as example.com"
                ));
            }
        }
    }
    let rule = format!("{}##{sel}", domains.to_ascii_lowercase());
    let v = super::rules::validate_rules(&rule, filter_engine::ListFormat::Abp, false, false);
    match v.lines.as_slice() {
        [l] if l.outcome == "accepted" => Ok(rule),
        [l] => Err(l
            .error
            .clone()
            .unwrap_or_else(|| "The selector is not accepted".into())),
        _ => Err("Not a rule".into()),
    }
}

/// The rule with its host part lowercased (hosts are case-insensitive; the stored line and the
/// remove comparison must not depend on case).
fn lower_host(r: &str) -> String {
    let at = if r.starts_with("@@") { 2 } else { 0 };
    let body = &r[at..];
    let skip = if body.starts_with("||") {
        2
    } else if let Some(i) = body.find("://").filter(|_| body.starts_with('|')) {
        i + 3
    } else {
        return r.to_string();
    };
    let start = at + skip;
    let end = r[start..]
        .find(['^', '/', ':', '|', '?', '*', '$'])
        .map_or(r.len(), |i| start + i);
    format!(
        "{}{}{}",
        &r[..start],
        r[start..end].to_ascii_lowercase(),
        &r[end..]
    )
}

/// Number of rules (non-blank, non-comment lines) in `text`.
fn rule_count(text: &str) -> usize {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('!'))
        .count()
}

fn audit_rule(state: &AppState, p: &Principal, op: &str, rule: &str) {
    let (actor_type, actor_id) = match &p.actor {
        Actor::Token { token_id } => ("token", token_id.clone()),
        Actor::Session { .. } => ("user", p.user_id.to_string()),
    };
    let entry = AuditEntry {
        id: String::new(),
        at: Utc::now().to_rfc3339(),
        actor_type: actor_type.into(),
        actor_id: Some(actor_id),
        actor_name: Some(p.username.clone()),
        method: "POST".into(),
        route: format!("/api/v1/ext/rules#{op}"),
        scope: Scope::RulesExt.as_str().into(),
        target: Some(rule.chars().take(200).collect()),
        status: 200,
        outcome: "success".into(),
        ip: None,
        user_agent: None,
        request_id: None,
    };
    if let Err(e) = state.audit.append(entry) {
        tracing::error!("Failed to write audit entry: {e}");
    }
}

/// Add or remove one line of the custom rules and rebuild the engine. The line is validated with
/// the rule parser: one network rule or plain element-hiding rule (no comments, includes, preprocessor lines,
/// procedural, scriptlet or response-rewriting rules), at most 2 KB (1 KB for hiding rules).
#[utoipa::path(
    post, path = "/ext/rules", tag = "ext",
    security(("bearer_auth" = ["rules:ext"])),
    request_body = ExtRuleRequest,
    responses(
        (status = 200, description = "Applied", body = ExtRuleResult),
        (status = 400, description = "Not exactly one acceptable rule")
    )
)]
pub async fn post_rule(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiJson(req): ApiJson<ExtRuleRequest>,
) -> ApiResult<Json<ExtRuleResult>> {
    let add = match req.op.as_str() {
        "add" => true,
        "remove" => false,
        _ => return Err(ApiError::ValidationError("op must be add or remove".into())),
    };
    // Removing is held to the same rules: only a line the extension could have added can go.
    let rule = check_ext_rule(&req.rule).map_err(ApiError::ValidationError)?;
    let (st, r) = (state.clone(), rule.clone());
    let (count, changed) = blocking(move || {
        let _g = RULES_LOCK.lock();
        let cur = st.filter_store.get_custom_rules()?;
        let present = cur.lines().any(|l| l.trim() == r);
        let new = if add {
            if present {
                return Ok((rule_count(&cur), false));
            }
            let mut n = cur.clone();
            if !n.is_empty() && !n.ends_with('\n') {
                n.push('\n');
            }
            n.push_str(&r);
            n.push('\n');
            n
        } else {
            if !present {
                return Ok((rule_count(&cur), false));
            }
            let mut n: String = cur
                .lines()
                .filter(|l| l.trim() != r)
                .collect::<Vec<_>>()
                .join("\n");
            if !n.is_empty() {
                n.push('\n');
            }
            n
        };
        st.filter_store.set_custom_rules(&new)?;
        Ok((rule_count(&new), true))
    })
    .await?;
    if changed {
        audit_rule(&state, &p, &req.op, &rule);
        tracing::info!("Custom rule {} by {} (extension)", req.op, p.username);
        state.list_service.trigger();
    }
    Ok(Json(ExtRuleResult {
        rule_count: count,
        changed,
    }))
}

/// Is `d` the site or a subdomain of it (`a.a.com` for `a.com`)?
fn is_site(d: &str, site: &str) -> bool {
    d == site || d.strip_suffix(site).is_some_and(|p| p.ends_with('.'))
}

/// How a custom rule is scoped to `site`: `None` when it is not, else `Some(exclusive)`, true when
/// it applies to this site only. Only rules scoped to the site count: a cosmetic rule whose domain
/// list has it, a network rule whose `$domain=` list has it or whose host anchor is it (and has no
/// `$domain=`). All-sites rules are not scoped to any site.
fn site_scope(line: &str, site: &str) -> Option<bool> {
    let line = line.to_ascii_lowercase();
    if let Some(c) = filter_engine::formats::split_cosmetic(&line) {
        let ds: Vec<&str> = c
            .domains
            .split(',')
            .map(str::trim)
            .filter(|d| !d.is_empty() && !d.starts_with('~'))
            .collect();
        return ds
            .iter()
            .any(|d| is_site(d, site))
            .then(|| ds.iter().all(|d| is_site(d, site)));
    }
    let body = line.strip_prefix("@@").unwrap_or(&line);
    let (pat, opts) = body.split_once('$').unwrap_or((body, ""));
    let doms: Vec<&str> = opts
        .split(',')
        .find_map(|o| o.strip_prefix("domain="))
        .map(|l| l.split('|').filter(|d| !d.starts_with('~')).collect())
        .unwrap_or_default();
    if !doms.is_empty() {
        return doms
            .iter()
            .any(|d| is_site(d, site))
            .then(|| doms.iter().all(|d| is_site(d, site)));
    }
    let rest = pat.strip_prefix("||").or_else(|| {
        pat.strip_prefix('|')
            .and_then(|p| p.split_once("://").map(|x| x.1))
    })?;
    let end = rest
        .find(['^', '/', ':', '|', '?', '*'])
        .unwrap_or(rest.len());
    is_site(&rest[..end], site).then_some(true)
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SiteQuery {
    /// Host name, lowercase punycode.
    pub site: String,
}

/// The custom rules scoped to a site (cosmetic domain list, `$domain=` or host anchor), each
/// marked `exclusive` when scoped to that site only, for resetting that site's rules.
#[utoipa::path(
    get, path = "/ext/rules", tag = "ext",
    security(("bearer_auth" = ["rules:ext"])),
    params(SiteQuery),
    responses(
        (status = 200, description = "Matching custom rules", body = ExtSiteRules),
        (status = 400, description = "Not a host name")
    )
)]
pub async fn get_rules(
    State(state): State<Arc<AppState>>,
    Query(q): Query<SiteQuery>,
) -> ApiResult<Json<ExtSiteRules>> {
    let site = q.site.trim().to_ascii_lowercase();
    if site.is_empty()
        || site.len() > 253
        || !site
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(ApiError::ValidationError("site must be a host name".into()));
    }
    let rules = blocking(move || {
        Ok(state
            .filter_store
            .get_custom_rules()?
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('!'))
            .filter_map(|l| {
                site_scope(l, &site).map(|exclusive| ExtSiteRule {
                    rule: l.to_string(),
                    exclusive,
                })
            })
            .collect::<Vec<_>>())
    })
    .await?;
    Ok(Json(ExtSiteRules {
        site: q.site.trim().to_ascii_lowercase(),
        rules,
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn ext_rule_allowlist() {
        use super::check_ext_rule as ok;
        // Site-scoped blocks and allows.
        for good in [
            "||ads.example.com^",
            "||example.com^$script,third-party,domain=example.com",
            "||example.com/ads/$image,important",
            "@@||example.com^$document",
            "@@||example.com^$domain=news.example.org",
            "|https://example.com/a.js?x=1|",
            "|https://example.co.uk/a.js|$xhr,~third-party",
            "/banner/*$domain=example.com|example.org",
            "*$script,domain=example.com",
            "||example.com^$3p,important",
        ] {
            assert!(ok(good).is_ok(), "{good}: {:?}", ok(good));
        }
        // Everything that would widen, run code, rewrite or hide.
        for bad in [
            "@@*$document",
            "@@||*^$important",
            "||com^$document",
            "@@||com^",
            "@@||co.uk^$document",
            "||*.example.com^",
            "||example.com*^",
            "||127.0.0.1^",
            "||[::1]^",
            "|https://localhost/x|",
            "/ads/",
            "*$script",
            "*$domain=com",
            "*$domain=~example.com",
            "||example.com^$domain=com",
            "@@*$important,domain=example.com|co.uk",
            "example.com#@#.ad",
            "example.com#$#body{x:y}",
            "example.com#?#div:has(a)",
            "example.com#$?#div:has(a)",
            "example.com#@?#div",
            "example.com#@$?#div",
            "example.com#%#//scriptlet('x')",
            "||example.com^##.ad",
            "example.com$$script[src]",
            "example.com$@$script[src]",
            "||example.com^$badfilter",
            "||example.com^$redirect=noopjs",
            "||example.com^$redirect-rule=noopjs",
            "||example.com^$removeparam=a",
            "||example.com^$urltransform=/a/b/",
            "||example.com^$header=x",
            "||example.com^$cookie",
            "||example.com^$csp=default-src 'none'",
            "||example.com^$replace=/a/b/",
            "||example.com^$removeheader=refresh",
            "||example.com^$permissions=camera=()",
            "||example.com^$important,important",
            "||example.com^$",
            "@@@@||example.com^",
            "!comment",
            "|https://example.co",
            "@@|https://a.co$document",
            "||example.com",
            "@@||example.com$document",
            "||example.c^",
        ] {
            assert!(ok(bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn ext_rule_host_lowercased() {
        assert_eq!(
            super::check_ext_rule("||Example.COM^").unwrap(),
            "||example.com^"
        );
        // Add and remove both go through this, so the case never matters.
        assert_eq!(
            super::check_ext_rule("||Example.com^").unwrap(),
            super::check_ext_rule("||example.com^").unwrap()
        );
        assert_eq!(
            super::check_ext_rule("|https://Example.com/A|").unwrap(),
            "|https://example.com/A|"
        );
    }

    #[test]
    fn ext_cosmetic_rules() {
        use super::check_ext_rule as ok;
        for good in [
            "example.com##.ad-banner",
            "example.com,example.org###sidebar",
            "example.com##div[data-ad=\"x\"]",
            "example.com##div.a > .b:nth-child(2)",
            "example.com##div",
            "example.com##.a:not(.b)",
            "##.ad-banner",
            "###promo",
            "##a[href^=\"https://ads.\"]",
            "##.a, .b",
        ] {
            assert!(ok(good).is_ok(), "{good}: {:?}", ok(good));
        }
        for bad in [
            "##*",
            "##body",
            "##html",
            "##div",
            "##div > *",
            "##.a *",
            "##[class]",
            "##div:not(.x)",
            "##.a, div",
            "##a:has-text(x)",
            "example.com##.a:has-text(x)",
            "example.com##:xpath(//a)",
            "example.com##.a:style(color:red)",
            "example.com##.a:remove()",
            "example.com##.a:upward(2)",
            "example.com##.a:matches-css(color: red)",
            "example.com##.a:-abp-has(b)",
            "example.com##.a:has(b)",
            "example.com##.a::before",
            "example.com##^script",
            "example.com#@#.ad",
            "example.com#?#.a",
            "example.com#$#.a{x:y}",
            "example.com#%#//scriptlet('x')",
            "example.com##+js(aopr, x)",
            "example.com##.a{color:red}",
            "example.com##.a; b",
            "example.com##",
            "example.com##.a[",
            "com##.a",
            "localhost##.a",
            "127.0.0.1##.a",
            "*##.a",
            "~example.com##.a",
            "example.com$$script",
        ] {
            assert!(ok(bad).is_err(), "{bad} was accepted");
        }
        let long = format!("example.com##.{}", "a".repeat(1100));
        assert!(ok(&long).is_err());
        assert_eq!(ok("Example.COM##.Ad").unwrap(), "example.com##.Ad");
    }
}

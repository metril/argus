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
    AuditEntry, ExtAuditEvent, ExtError, ExtIdent, ExtMenuResponse, ExtOut, ExtTriggerRequest,
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
use crate::state::{AppState, ExtBridge};

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
            .list(Some(user))
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
    state.tokens.mark_used(&cached);
    Ok(ExtIdent {
        token_id: cached.stored.id.clone(),
        user: user.username,
        profiles: cached.stored.profiles.clone(),
    })
}

/// How many pings pass between token re-verifications of a live channel.
const REVERIFY_PINGS: u32 = 3;

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
    let (id, sid, mut out) = b.open(ident);
    let welcome = serde_json::json!({"t": "welcome", "sid": sid, "v": 1}).to_string();
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
        action: "session_open".into(),
        target: Some(id.to_string()),
    });
    let mut pings = 0u32;
    loop {
        tokio::select! {
            o = out.recv() => match o {
                Some(ExtOut::Text(t)) => if sock.send(Message::Text(t.into())).await.is_err() { break },
                Some(ExtOut::Binary(v)) => if sock.send(Message::Binary(v.into())).await.is_err() { break },
                Some(ExtOut::Close(code)) => {
                    let _ = sock.send(Message::Close(Some(CloseFrame { code, reason: "closed".into() }))).await;
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
                            break;
                        }
                    }
                    b.on_text(id, &t).await
                }
                Ok(Some(Ok(Message::Binary(v)))) => b.on_binary(id, v.to_vec()).await,
                Ok(Some(Ok(_))) => {}
            },
        }
    }
    b.close(id);
    debug!("extension channel {id} closed");
    state.record_ext_audit(ExtAuditEvent {
        actor: user,
        action: "session_close".into(),
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

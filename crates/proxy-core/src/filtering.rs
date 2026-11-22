//! Request filtering and upstream forwarding.
//!
//! [`ProxyContext`] carries the shared, `Send + Sync` handles every connection needs: the
//! [`SharedEngine`] (one `Arc<Engine>` behind an `ArcSwap`) for block/allow decisions and a single
//! pooled [`reqwest::Client`] for forwarding requests upstream over real TLS.
//!
//! Per request the pipeline is: classify (resource type + source URL) -> engine check ->
//! block / `$redirect` resource / `$removeparam` rewrite -> stream upstream -> `$csp` header and
//! cosmetic injection on the way back.

use crate::inject::{build_payload, full_body, inject_body, passthrough_body, ProxyBody};
use crate::redirect::{block_response, redirect_response, rewrite_redirect};
use crate::request_ctx::{default_profile_slot, ProfileSlot, RequestCtx};
use crate::request_type::{classify, source_url, RequestType};
use crate::{Error, Result};
use bytes::Bytes;
use filter_engine::SharedEngine;
use futures_util::TryStreamExt;
use http_body_util::BodyExt;
use hyper::body::{Body, Incoming};
use hyper::header::{HeaderName, CONTENT_TYPE, HOST};
use hyper::{Request, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

/// Hop-by-hop headers that must not be forwarded (RFC 7230 §6.1), plus framing headers we
/// reconstruct ourselves.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Default cap on time-to-response-headers for an upstream call (includes uploading the body).
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 60_000;

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP
        .iter()
        .any(|h| name.as_str().eq_ignore_ascii_case(h))
}

/// Shared per-process filtering + forwarding context, cloned (via `Arc`) into every connection.
pub struct ProxyContext {
    engine: Arc<SharedEngine>,
    client: reqwest::Client,
    /// Context used by [`Self::forward`] (default profile, unattributed client).
    default_ctx: RequestCtx,
    /// Upstream request timeout in milliseconds; 0 disables it.
    request_timeout_ms: AtomicU64,
}

impl ProxyContext {
    /// `adblock_enabled == false` disables the engine at startup; afterwards the on/off state is
    /// the engine's live flag (see [`Self::set_adblock_enabled`]), so UI toggles take effect.
    pub fn new(engine: Arc<SharedEngine>, client: reqwest::Client, adblock_enabled: bool) -> Self {
        if !adblock_enabled {
            engine.set_enabled(false);
        }
        let default_ctx = RequestCtx::anonymous(default_profile_slot(engine.clone()));
        Self {
            engine,
            client,
            default_ctx,
            request_timeout_ms: AtomicU64::new(DEFAULT_REQUEST_TIMEOUT_MS),
        }
    }

    /// The shared engine handle (used by the WS/h3 paths too).
    pub fn engine(&self) -> &Arc<SharedEngine> {
        &self.engine
    }

    /// The shared pooled upstream client.
    pub fn client(&self) -> reqwest::Client {
        self.client.clone()
    }

    /// Whether ad blocking is currently enabled (live).
    pub fn adblock_enabled(&self) -> bool {
        self.engine.is_enabled()
    }

    /// Turn ad blocking on or off at runtime.
    pub fn set_adblock_enabled(&self, enabled: bool) {
        self.engine.set_enabled(enabled);
    }

    /// Set the upstream request timeout (time to response headers); `Duration::ZERO` disables it.
    pub fn set_request_timeout(&self, timeout: Duration) {
        self.request_timeout_ms
            .store(timeout.as_millis() as u64, Ordering::Relaxed);
    }

    /// The default profile's slot (what connections without a resolved profile use).
    pub fn default_profile(&self) -> &ProfileSlot {
        &self.default_ctx.profile
    }

    /// Context for a connection on the default profile.
    pub fn request_ctx_for(
        &self,
        client_addr: SocketAddr,
        auth_user: Option<Arc<str>>,
    ) -> RequestCtx {
        RequestCtx::new(self.default_ctx.profile.clone(), client_addr, auth_user)
    }

    /// Whether a request should be blocked (respects the master adblock toggle, records stats).
    ///
    /// Shared by the HTTP, WebSocket, and HTTP/3 paths.
    pub fn should_block(&self, url: &str, source_url: &str, resource_type: &str) -> bool {
        self.engine.is_enabled() && self.engine.check(url, source_url, resource_type).blocked
    }

    /// Forward a proxied request using the default request context.
    pub async fn forward(
        &self,
        req: Request<Incoming>,
        scheme: &str,
        fallback_authority: Option<(String, u16)>,
    ) -> Result<Response<ProxyBody>> {
        self.forward_with(req, scheme, fallback_authority, &self.default_ctx)
            .await
    }

    /// Forward a proxied request upstream, filtering it first with the profile in `rctx`.
    ///
    /// `scheme` is the upstream scheme (`http` for plain proxying, `https` for MITM'd traffic).
    /// `fallback_authority` supplies host/port for MITM requests whose URI is origin-form (path
    /// only) — the host then comes from the `Host` header or this fallback.
    pub async fn forward_with(
        &self,
        req: Request<Incoming>,
        scheme: &str,
        fallback_authority: Option<(String, u16)>,
        rctx: &RequestCtx,
    ) -> Result<Response<ProxyBody>> {
        let method = req.method().clone();
        let is_head = method == hyper::Method::HEAD;
        let uri = req.uri().clone();
        let headers = req.headers().clone();

        // Internal endpoints (dynamic cosmetic hiding callback) are answered locally, not forwarded.
        if uri.path().starts_with("/__adblock__/") {
            return Ok(self.handle_internal(req, &uri, rctx).await);
        }

        // Resolve target host/port from absolute-form URI, Host header, or the MITM fallback.
        let host = uri
            .host()
            .map(|h| h.to_string())
            .or_else(|| {
                headers
                    .get(HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(|h| h.split(':').next().unwrap_or(h).to_string())
            })
            .or_else(|| fallback_authority.as_ref().map(|(h, _)| h.clone()));

        let host = match host {
            Some(h) => h,
            None => return Ok(bad_request("Missing host")),
        };

        let port = uri
            .port_u16()
            .or_else(|| fallback_authority.as_ref().map(|(_, p)| *p))
            .unwrap_or(if scheme == "https" { 443 } else { 80 });

        let path_and_query = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");

        // Absolute URL: prefer the request's own absolute form, else synthesize one.
        let mut url = if uri.scheme().is_some() && uri.authority().is_some() {
            uri.to_string()
        } else {
            format!("{scheme}://{host}:{port}{path_and_query}")
        };

        // Filter decision. The profile guard is dropped before any `.await`.
        let rtype = classify(&method, &headers, path_and_query);
        let mut csp: Option<String> = None;
        {
            let profile = rctx.profile.load();
            let engine = &profile.engine;
            if engine.is_enabled() {
                let source = source_url(&headers, &url, rtype);
                let verdict = engine.check(&url, source, rtype.as_str());
                if verdict.blocked {
                    debug!("Blocked {} ({})", url, rtype.as_str());
                    if let Some(res) = verdict.redirect_resource() {
                        return Ok(redirect_response(res));
                    }
                    return Ok(block_response(rtype, &verdict, &url));
                }
                if let Some(new_url) = verdict.rewritten_url {
                    let navigation =
                        rtype == RequestType::Document && (method == hyper::Method::GET || is_head);
                    if navigation {
                        return Ok(rewrite_redirect(&new_url));
                    }
                    // Subresource: fetch the cleaned URL transparently.
                    url = new_url;
                }
                if rtype.is_frame() {
                    csp = engine.csp_for(&url, source_url(&headers, &url, rtype), rtype.as_str());
                }
            }
        }

        // Stream the request body upstream; nothing is buffered.
        let has_body = !req.body().is_end_stream();
        let body = req.into_body();

        let mut rb = self.client.request(method, &url);
        for (name, value) in headers.iter() {
            // reqwest sets Host itself; don't forward hop-by-hop headers. Content-Length is only
            // kept for streamed bodies (it keeps the upload un-chunked); reqwest derives it
            // otherwise.
            if is_hop_by_hop(name)
                || name == HOST
                || (!has_body && name.as_str().eq_ignore_ascii_case("content-length"))
            {
                continue;
            }
            rb = rb.header(name, value);
        }
        if has_body {
            let stream = body
                .into_data_stream()
                .map_err(|e| std::io::Error::other(e.to_string()));
            rb = rb.body(reqwest::Body::wrap_stream(stream));
        }

        let timeout_ms = self.request_timeout_ms.load(Ordering::Relaxed);
        let sent = if timeout_ms == 0 {
            rb.send().await.map_err(|e| e.to_string())
        } else {
            match tokio::time::timeout(Duration::from_millis(timeout_ms), rb.send()).await {
                Ok(r) => r.map_err(|e| e.to_string()),
                Err(_) => {
                    warn!("Upstream timeout for {url}");
                    return Ok(status_response(
                        StatusCode::GATEWAY_TIMEOUT,
                        "Upstream timeout",
                    ));
                }
            }
        };
        let resp = match sent {
            Ok(r) => r,
            Err(e) => {
                warn!("Upstream error for {}: {}", url, e);
                return Ok(bad_gateway(&format!("Upstream error: {e}")));
            }
        };

        let status = resp.status();
        let resp_headers = resp.headers().clone();

        // Decide whether to inject cosmetics into an HTML document.
        let is_html = resp_headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.to_ascii_lowercase().contains("text/html"))
            .unwrap_or(false);

        // Only inject into responses that actually carry an HTML body.
        let body_allowed = !is_head
            && status.as_u16() >= 200
            && status != StatusCode::NO_CONTENT
            && status != StatusCode::NOT_MODIFIED;
        let payload = if is_html && body_allowed {
            let profile = rctx.profile.load();
            if profile.engine.is_enabled() {
                let cos = profile.engine.cosmetic_for(&url);
                build_payload(&cos, !cos.generichide)
            } else {
                None
            }
        } else {
            None
        };

        let inject = payload.is_some();
        let content_encoding = resp_headers
            .get(hyper::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let mut builder = Response::builder().status(status);
        for (name, value) in resp_headers.iter() {
            // Always drop Content-Length (bodies are streamed/chunked). For injected HTML we also
            // drop Content-Encoding because the body is re-emitted as identity.
            if is_hop_by_hop(name) || name.as_str().eq_ignore_ascii_case("content-length") {
                continue;
            }
            if inject && name == hyper::header::CONTENT_ENCODING {
                continue;
            }
            builder = builder.header(name, value);
        }
        // `$csp`: an additional policy header; the browser enforces the intersection with any
        // policy the origin sent.
        if let Some(csp) = csp {
            if let Ok(v) = hyper::header::HeaderValue::from_str(&csp) {
                builder = builder.header("content-security-policy", v);
            }
        }

        let body = match payload {
            Some(p) => inject_body(resp, p, content_encoding.as_deref()),
            None => passthrough_body(resp),
        };

        builder
            .body(body)
            .map_err(|e| Error::Connection(format!("build response: {e}")))
    }

    /// Handle a `/__adblock__/...` internal request (never forwarded upstream).
    async fn handle_internal(
        &self,
        req: Request<Incoming>,
        uri: &hyper::Uri,
        rctx: &RequestCtx,
    ) -> Response<ProxyBody> {
        if uri.path() == "/__adblock__/cc" && req.method() == hyper::Method::POST {
            let bytes = match req.into_body().collect().await {
                Ok(c) => c.to_bytes(),
                Err(_) => return bad_request("body"),
            };
            #[derive(serde::Deserialize)]
            struct CcReq {
                url: String,
                #[serde(default)]
                classes: Vec<String>,
                #[serde(default)]
                ids: Vec<String>,
            }
            let parsed: CcReq = match serde_json::from_slice(&bytes) {
                Ok(p) => p,
                Err(_) => return bad_request("json"),
            };
            let selectors = rctx.profile.load().engine.dynamic_hide_selectors(
                &parsed.url,
                &parsed.classes,
                &parsed.ids,
            );
            let json = serde_json::json!({ "selectors": selectors }).to_string();
            return Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json")
                .body(full_body(Bytes::from(json)))
                .expect("internal json response");
        }
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full_body(Bytes::new()))
            .expect("internal 404")
    }
}

fn status_response(status: StatusCode, msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .body(full_body(Bytes::from(msg.to_string())))
        .expect("static status response")
}

fn bad_request(msg: &str) -> Response<ProxyBody> {
    status_response(StatusCode::BAD_REQUEST, msg)
}

fn bad_gateway(msg: &str) -> Response<ProxyBody> {
    status_response(StatusCode::BAD_GATEWAY, msg)
}

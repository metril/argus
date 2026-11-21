//! Request filtering and upstream forwarding.
//!
//! [`ProxyContext`] carries the shared, `Send + Sync` handles every connection needs: the
//! thread-local-backed [`SharedEngine`] for block/allow decisions and a single pooled
//! [`reqwest::Client`] for forwarding requests upstream over real TLS (replacing the previous
//! per-request plaintext `build_http()` client, which broke HTTPS origins).

use crate::inject::{build_payload, full_body, inject_body, passthrough_body, ProxyBody};
use crate::{Error, Result};
use bytes::Bytes;
use filter_engine::SharedEngine;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{HeaderName, CONTENT_TYPE, HOST, REFERER};
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
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

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP
        .iter()
        .any(|h| name.as_str().eq_ignore_ascii_case(h))
}

/// Shared per-process filtering + forwarding context, cloned (via `Arc`) into every connection.
pub struct ProxyContext {
    engine: Arc<SharedEngine>,
    client: reqwest::Client,
    /// Whether ad blocking is enabled (separate from the engine having rules).
    adblock_enabled: bool,
}

impl ProxyContext {
    pub fn new(engine: Arc<SharedEngine>, client: reqwest::Client, adblock_enabled: bool) -> Self {
        Self {
            engine,
            client,
            adblock_enabled,
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

    /// Whether ad blocking is enabled.
    pub fn adblock_enabled(&self) -> bool {
        self.adblock_enabled
    }

    /// Whether a request should be blocked (respects the master adblock toggle, records stats).
    ///
    /// Shared by the HTTP, WebSocket, and HTTP/3 paths.
    pub fn should_block(&self, url: &str, source_url: &str, resource_type: &str) -> bool {
        self.adblock_enabled && self.engine.check(url, source_url, resource_type).blocked
    }

    /// Forward a proxied request upstream, blocking it first if the filter engine says so.
    ///
    /// `scheme` is the upstream scheme (`http` for plain proxying, `https` for MITM'd traffic).
    /// `fallback_authority` supplies host/port for MITM requests whose URI is origin-form (path
    /// only) — the host then comes from the `Host` header or this fallback.
    pub async fn forward(
        &self,
        req: Request<Incoming>,
        scheme: &str,
        fallback_authority: Option<(String, u16)>,
    ) -> Result<Response<ProxyBody>> {
        let method = req.method().clone();
        let is_head = method == hyper::Method::HEAD;
        let uri = req.uri().clone();
        let headers = req.headers().clone();

        // Internal endpoints (dynamic cosmetic hiding callback) are answered locally, not forwarded.
        if uri.path().starts_with("/__adblock__/") {
            return Ok(self.handle_internal(req, &uri).await);
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
        let url = if uri.scheme().is_some() && uri.authority().is_some() {
            uri.to_string()
        } else {
            format!("{scheme}://{host}:{port}{path_and_query}")
        };

        // Filter decision.
        if self.adblock_enabled {
            let resource_type = resource_type_for(&headers, path_and_query);
            let source_url = headers
                .get(REFERER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or(&url);
            let verdict = self.engine.check(&url, source_url, resource_type);
            if verdict.blocked {
                debug!("Blocked {} ({})", url, resource_type);
                return Ok(blocked_response());
            }
        }

        // Forward upstream over the shared pooled client.
        let body = req
            .into_body()
            .collect()
            .await
            .map_err(|e| Error::Connection(format!("read request body: {e}")))?
            .to_bytes();

        let mut rb = self.client.request(method, &url);
        for (name, value) in headers.iter() {
            // reqwest sets Host/Content-Length itself; don't forward hop-by-hop headers.
            if is_hop_by_hop(name)
                || name == HOST
                || name.as_str().eq_ignore_ascii_case("content-length")
            {
                continue;
            }
            rb = rb.header(name, value);
        }
        if !body.is_empty() {
            rb = rb.body(body);
        }

        let resp = match rb.send().await {
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
        let payload = if self.adblock_enabled && is_html && body_allowed {
            let cos = self.engine.cosmetic_for(&url);
            build_payload(&cos, !cos.generichide)
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
            let selectors =
                self.engine
                    .dynamic_hide_selectors(&parsed.url, &parsed.classes, &parsed.ids);
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

/// Map request hints to a coarse adblock resource type (used for filter matching).
fn resource_type_for(headers: &hyper::HeaderMap, path: &str) -> &'static str {
    if let Some(dest) = headers.get("sec-fetch-dest").and_then(|v| v.to_str().ok()) {
        match dest {
            "document" => return "document",
            "iframe" | "frame" => return "sub_frame",
            "script" => return "script",
            "style" => return "stylesheet",
            "image" => return "image",
            "font" => return "font",
            "audio" | "video" | "track" => return "media",
            "empty" => return "xhr",
            "websocket" => return "websocket",
            _ => {}
        }
    }
    if let Some(accept) = headers
        .get(hyper::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
    {
        if accept.contains("text/html") {
            return "document";
        }
        if accept.contains("text/css") {
            return "stylesheet";
        }
        if accept.contains("image/") {
            return "image";
        }
    }
    // Fall back to the path extension.
    let p = path.split('?').next().unwrap_or(path);
    match p.rsplit('.').next() {
        Some("js" | "mjs") => "script",
        Some("css") => "stylesheet",
        Some("png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "ico") => "image",
        Some("woff" | "woff2" | "ttf" | "otf" | "eot") => "font",
        Some("mp4" | "webm" | "mp3" | "ogg" | "m4a") => "media",
        _ => "other",
    }
}

/// Response returned for blocked requests: an empty `204 No Content`.
fn blocked_response() -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("x-adblock", "blocked")
        .body(full_body(Bytes::new()))
        .expect("static blocked response")
}

fn bad_request(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(full_body(Bytes::from(msg.to_string())))
        .expect("static bad-request response")
}

fn bad_gateway(msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(full_body(Bytes::from(msg.to_string())))
        .expect("static bad-gateway response")
}

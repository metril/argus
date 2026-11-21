//! Filtering + upstream forwarding for the HTTP/3 proxy path.
//!
//! Mirrors the HTTP/1.1/2 path (`proxy-core`'s `ProxyContext`) but produces the buffered
//! `(status, headers, body)` triple the h3 response API needs. Shares the same [`SharedEngine`] so
//! block decisions are identical across protocols.

use std::sync::Arc;

use bytes::Bytes;
use filter_engine::SharedEngine;
use http::{HeaderMap, HeaderName, Method, StatusCode};

/// Hop-by-hop headers that must not be forwarded.
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

/// Shared filtering + forwarding context for HTTP/3 requests.
pub struct Http3Filter {
    engine: Arc<SharedEngine>,
    client: reqwest::Client,
    adblock_enabled: bool,
}

impl Http3Filter {
    pub fn new(engine: Arc<SharedEngine>, client: reqwest::Client, adblock_enabled: bool) -> Self {
        Self {
            engine,
            client,
            adblock_enabled,
        }
    }

    /// Whether this request should be blocked.
    pub fn is_blocked(&self, _method: &Method, url: &str, headers: &HeaderMap) -> bool {
        if !self.adblock_enabled {
            return false;
        }
        let resource_type = resource_type_for(headers, url);
        let source = headers
            .get(http::header::REFERER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(url);
        self.engine.check(url, source, resource_type).blocked
    }

    /// Forward the request upstream and return the buffered response.
    pub async fn forward(
        &self,
        method: Method,
        url: &str,
        headers: &HeaderMap,
        body: Vec<u8>,
    ) -> Result<(StatusCode, HeaderMap, Bytes), reqwest::Error> {
        let mut rb = self.client.request(method, url);
        for (name, value) in headers.iter() {
            if is_hop_by_hop(name)
                || name == http::header::HOST
                || name.as_str().eq_ignore_ascii_case("content-length")
                // skip HTTP/2/3 pseudo-headers if any leak through
                || name.as_str().starts_with(':')
            {
                continue;
            }
            rb = rb.header(name, value);
        }
        if !body.is_empty() {
            rb = rb.body(body);
        }

        let resp = rb.send().await?;
        let status = resp.status();
        let mut out_headers = HeaderMap::new();
        for (name, value) in resp.headers().iter() {
            if is_hop_by_hop(name) || name.as_str().eq_ignore_ascii_case("content-length") {
                continue;
            }
            out_headers.insert(name.clone(), value.clone());
        }
        let bytes = resp.bytes().await?;
        Ok((status, out_headers, bytes))
    }
}

/// Coarse adblock resource type from request hints (mirrors the HTTP/1.1 path).
fn resource_type_for(headers: &HeaderMap, url: &str) -> &'static str {
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
            _ => {}
        }
    }
    let path = url.split('?').next().unwrap_or(url);
    match path.rsplit('.').next() {
        Some("js" | "mjs") => "script",
        Some("css") => "stylesheet",
        Some("png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "ico") => "image",
        Some("woff" | "woff2" | "ttf" | "otf" | "eot") => "font",
        Some("mp4" | "webm" | "mp3" | "ogg" | "m4a") => "media",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use filter_engine::compile_engine;

    #[test]
    fn blocks_matching_and_respects_toggle() {
        let engine = Arc::new(SharedEngine::new());
        engine.install(compile_engine(&["||ads.example^\n".to_string()]));
        let f = Http3Filter::new(engine.clone(), reqwest::Client::new(), true);

        assert!(f.is_blocked(&Method::GET, "https://ads.example/x.js", &HeaderMap::new()));
        assert!(!f.is_blocked(&Method::GET, "https://cdn.example/x.js", &HeaderMap::new()));

        let off = Http3Filter::new(engine, reqwest::Client::new(), false);
        assert!(!off.is_blocked(&Method::GET, "https://ads.example/x.js", &HeaderMap::new()));
    }
}

//! Request context: request id (echoed in `X-Request-Id`) and the real client address.

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::Instrument;
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Clone)]
pub struct RequestId(pub String);

pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Request extension set by the listener for connections that used its own TLS (as opposed to
/// a proxy's `X-Forwarded-Proto`, which cannot be trusted without a configured proxy).
#[derive(Debug, Clone, Copy)]
pub struct NativeTls;

/// Per-request facts every handler and the audit log can rely on.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub ip: Option<IpAddr>,
    /// The request reached us over HTTPS (see [`request_is_https`]).
    pub https: bool,
    pub user_agent: Option<String>,
    pub request_id: String,
}

/// Client IP: the socket peer, unless the peer is a configured trusted proxy, in which case the
/// rightmost `X-Forwarded-For` entry that is not itself a trusted proxy (or `X-Real-IP`) is used.
pub fn client_ip(headers: &HeaderMap, peer: Option<IpAddr>, trusted: &[IpAddr]) -> Option<IpAddr> {
    let peer = peer?;
    if !trusted.contains(&peer) {
        return Some(peer);
    }
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split(',')
                .rev()
                .filter_map(|s| s.trim().parse::<IpAddr>().ok())
                .find(|ip| !trusted.contains(ip))
        });
    let real = || {
        headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok())
    };
    Some(forwarded.or_else(real).unwrap_or(peer))
}

/// Whether the request arrived over HTTPS: only a trusted proxy's `X-Forwarded-Proto: https` is
/// believed (the server itself speaks plain HTTP).
pub fn request_is_https(headers: &HeaderMap, peer: Option<IpAddr>, trusted: &[IpAddr]) -> bool {
    let Some(peer) = peer else { return false };
    trusted.contains(&peer)
        && headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("https"))
}

fn sanitize_id(raw: &str) -> Option<String> {
    (!raw.is_empty() && raw.len() <= 64 && raw.bytes().all(|b| b.is_ascii_graphic()))
        .then(|| raw.to_string())
}

pub async fn request_id_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let request_id = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(sanitize_id)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let info = ClientInfo {
        ip: client_ip(
            req.headers(),
            peer,
            &state.api_config.network.trusted_proxies,
        ),
        https: req.extensions().get::<NativeTls>().is_some()
            || request_is_https(
                req.headers(),
                peer,
                &state.api_config.network.trusted_proxies,
            ),
        user_agent: req
            .headers()
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(200).collect()),
        request_id: request_id.clone(),
    };
    req.extensions_mut().insert(RequestId(request_id.clone()));
    req.extensions_mut().insert(info);

    let span = tracing::info_span!(
        "request",
        request_id = %request_id,
        method = %req.method(),
        uri = %req.uri().path(),
    );
    let mut response = next.run(req).instrument(span).await;
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, v);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_is_only_believed_from_trusted_proxies() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        let proxy: IpAddr = "10.0.0.2".parse().unwrap();
        let other: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(request_is_https(&h, Some(proxy), &[proxy]));
        assert!(
            !request_is_https(&h, Some(other), &[proxy]),
            "spoofed header"
        );
        assert!(!request_is_https(&h, None, &[proxy]));
        assert!(!request_is_https(&HeaderMap::new(), Some(proxy), &[proxy]));
        h.insert("x-forwarded-proto", "http".parse().unwrap());
        assert!(!request_is_https(&h, Some(proxy), &[proxy]));
        h.insert("x-forwarded-proto", "http, https".parse().unwrap());
        assert!(request_is_https(&h, Some(proxy), &[proxy]));
    }

    #[test]
    fn forwarded_header_only_trusted_from_trusted_peers() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "9.9.9.9, 10.0.0.5".parse().unwrap());
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        let untrusted: IpAddr = "1.2.3.4".parse().unwrap();
        // Untrusted peer cannot spoof.
        assert_eq!(client_ip(&h, Some(untrusted), &[proxy]), Some(untrusted));
        // Trusted peer: rightmost non-proxy entry.
        assert_eq!(
            client_ip(&h, Some(proxy), &[proxy]),
            Some("10.0.0.5".parse().unwrap())
        );
        assert_eq!(client_ip(&h, None, &[proxy]), None);
    }
}

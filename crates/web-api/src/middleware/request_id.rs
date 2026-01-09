//! Request ID middleware
//!
//! Generates unique request IDs for tracing and logging.
//! Adds X-Request-ID header to responses.

use axum::{
    extract::Request,
    http::HeaderValue,
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

/// Request ID extension for access in handlers
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// Request ID header name
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Request ID middleware
///
/// Generates a unique request ID and:
/// 1. Adds it to request extensions for handler access
/// 2. Adds X-Request-ID header to response
/// 3. Includes it in tracing span
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    // Check if client provided a request ID
    let request_id = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Add to extensions for handler access
    req.extensions_mut().insert(RequestId(request_id.clone()));

    // Create tracing span with request ID
    let span = tracing::info_span!(
        "request",
        request_id = %request_id,
        method = %req.method(),
        uri = %req.uri(),
    );

    // Run the request
    let _guard = span.enter();
    let mut response = next.run(req).await;

    // Add request ID to response headers
    if let Ok(header_value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, header_value);
    }

    response
}

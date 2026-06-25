//! CA certificate download handler.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

/// Download the proxy's root CA certificate (PEM).
///
/// `GET /api/ca.crt` — intentionally **public**: the certificate is not secret
/// (the matching private key is never served), and keeping it unauthenticated
/// lets any device — a phone, another laptop — fetch and trust it by URL. A
/// trusted CA is what makes the proxy's MITM'd HTTPS validate.
pub async fn download_ca(State(state): State<Arc<AppState>>) -> Response {
    // Clone the path out of the config guard so it isn't held across the await.
    let path = state.proxy_state.config.read().mitm.ca_cert_path.clone();

    match tokio::fs::read(&path).await {
        Ok(pem) => (
            [
                (header::CONTENT_TYPE, "application/x-pem-file"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"adblocker-ca.crt\"",
                ),
                (header::CACHE_CONTROL, "no-store"),
            ],
            pem,
        )
            .into_response(),
        Err(e) => {
            tracing::warn!("CA certificate not available at {:?}: {}", path, e);
            (
                StatusCode::NOT_FOUND,
                "CA certificate not found. Start the proxy at least once so it can be generated.",
            )
                .into_response()
        }
    }
}

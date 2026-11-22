//! CA certificate: public PEM/DER download and authenticated details.

use std::sync::Arc;

use api_types::CaInfoResponse;
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

const NOT_FOUND_MSG: &str =
    "CA certificate not found. Start the proxy at least once so it can be generated.";

async fn read_pem(state: &AppState) -> ApiResult<Vec<u8>> {
    // Clone the path out of the config guard so it isn't held across the await.
    let path = state.proxy_state.config.read().mitm.ca_cert_path.clone();
    tokio::fs::read(&path).await.map_err(|e| {
        tracing::warn!("CA certificate not available at {:?}: {}", path, e);
        ApiError::NotFound(NOT_FOUND_MSG.into())
    })
}

fn der_of(pem: &[u8]) -> ApiResult<Vec<u8>> {
    x509_parser::pem::parse_x509_pem(pem)
        .map(|(_, p)| p.contents)
        .map_err(|e| ApiError::Internal(format!("CA certificate is not valid PEM: {e}")))
}

fn attachment(content_type: &'static str, filename: &'static str, body: Vec<u8>) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_DISPOSITION, filename),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

/// Download the CA certificate (PEM). Public so any device can fetch and trust it by URL.
#[utoipa::path(
    get, path = "/ca.crt", tag = "ca",
    security(()),
    responses((status = 200, description = "PEM certificate", content_type = "application/x-pem-file", body = String))
)]
pub async fn download_ca(State(state): State<Arc<AppState>>) -> ApiResult<Response> {
    let pem = read_pem(&state).await?;
    Ok(attachment(
        "application/x-pem-file",
        "attachment; filename=\"adblocker-ca.crt\"",
        pem,
    ))
}

/// Download the CA certificate (DER), as Android and Windows expect.
#[utoipa::path(
    get, path = "/ca.der", tag = "ca",
    security(()),
    responses((status = 200, description = "DER certificate", content_type = "application/x-x509-ca-cert", body = Vec<u8>))
)]
pub async fn download_ca_der(State(state): State<Arc<AppState>>) -> ApiResult<Response> {
    let der = der_of(&read_pem(&state).await?)?;
    Ok(attachment(
        "application/x-x509-ca-cert",
        "attachment; filename=\"adblocker-ca.der\"",
        der,
    ))
}

fn ts(t: x509_parser::time::ASN1Time) -> DateTime<Utc> {
    DateTime::from_timestamp(t.timestamp(), 0).unwrap_or_default()
}

/// Subject, issuer, validity and SHA-256 fingerprint of the CA certificate.
#[utoipa::path(
    get, path = "/ca", tag = "ca",
    security(("bearer_auth" = ["ca:read"])),
    responses((status = 200, description = "Certificate details", body = CaInfoResponse))
)]
pub async fn ca_info(State(state): State<Arc<AppState>>) -> ApiResult<Json<CaInfoResponse>> {
    let der = der_of(&read_pem(&state).await?)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| ApiError::Internal(format!("CA certificate is not valid X.509: {e}")))?;
    let validity = cert.validity();
    let fingerprint: String = Sha256::digest(&der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(Json(CaInfoResponse {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: cert.raw_serial_as_string(),
        not_before: ts(validity.not_before).to_rfc3339(),
        not_after: ts(validity.not_after).to_rfc3339(),
        expired: !validity.is_valid(),
        fingerprint_sha256: fingerprint,
        pem_url: "/api/v1/ca.crt".into(),
        der_url: "/api/v1/ca.der".into(),
    }))
}

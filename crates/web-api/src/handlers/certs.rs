//! Upstream server certificates the proxy has seen (the real certificate, not the one Argus
//! minted for the client).

use std::sync::Arc;

use api_types::CertInfo;
use axum::{extract::State, Json};
use common::certstore::CertInfo as Stored;

use crate::error::{ApiError, ApiPath, ApiResult};
use crate::state::AppState;

/// Same JSON shape on both sides; the DTO is the contract.
fn dto(info: &Stored) -> ApiResult<CertInfo> {
    serde_json::to_value(info)
        .and_then(serde_json::from_value)
        .map_err(|e| ApiError::Internal(format!("certificate info: {e}")))
}

/// A certificate by SHA-256 fingerprint (lowercase hex), as linked from the request log.
#[utoipa::path(
    get, path = "/certs/{fp}", tag = "certs",
    security(("bearer_auth" = ["logs:read"])),
    params(("fp" = String, Path, description = "SHA-256 fingerprint of the leaf, hex")),
    responses((status = 200, description = "Upstream certificate", body = CertInfo))
)]
pub async fn get_cert(
    State(state): State<Arc<AppState>>,
    ApiPath(fp): ApiPath<String>,
) -> ApiResult<Json<CertInfo>> {
    let info = state
        .certs()
        .get(&fp)
        .ok_or_else(|| ApiError::NotFound("Certificate not found".into()))?;
    Ok(Json(dto(&info)?))
}

/// The latest certificate a host presented to the proxy.
#[utoipa::path(
    get, path = "/certs/by-host/{host}", tag = "certs",
    security(("bearer_auth" = ["logs:read"])),
    params(("host" = String, Path, description = "Host name as dialed")),
    responses((status = 200, description = "Latest upstream certificate", body = CertInfo))
)]
pub async fn get_cert_by_host(
    State(state): State<Arc<AppState>>,
    ApiPath(host): ApiPath<String>,
) -> ApiResult<Json<CertInfo>> {
    let info = state
        .certs()
        .by_host(&host)
        .ok_or_else(|| ApiError::NotFound("No certificate recorded for this host".into()))?;
    Ok(Json(dto(&info)?))
}

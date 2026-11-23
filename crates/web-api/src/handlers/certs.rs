//! Upstream server certificates the proxy has seen (the real certificate, not the one Argus
//! minted for the client).

use std::sync::Arc;

use api_types::CertInfo;
use axum::{extract::State, Extension, Json};
use common::certstore::CertInfo as Stored;
use serde::Deserialize;
use utoipa::IntoParams;

use crate::auth::authz::Principal;

use crate::error::{ApiError, ApiPath, ApiQuery, ApiResult};
use crate::state::AppState;

/// Same JSON shape on both sides; the DTO is the contract.
/// `?host=`: whose verification verdict to report.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CertQuery {
    /// Host (optionally `host:port`) the certificate was presented to. Without it the verdict
    /// reflects the validity period only.
    pub host: Option<String>,
}

fn dto(info: &Stored) -> ApiResult<CertInfo> {
    serde_json::to_value(info)
        .and_then(serde_json::from_value)
        .map_err(|e| ApiError::Internal(format!("certificate info: {e}")))
}

/// A certificate by SHA-256 fingerprint (lowercase hex), as linked from the request log.
#[utoipa::path(
    get, path = "/certs/{fp}", tag = "certs",
    security(("bearer_auth" = ["logs:read"])),
    params(("fp" = String, Path, description = "SHA-256 fingerprint of the leaf, hex"), CertQuery),
    responses((status = 200, description = "Upstream certificate", body = CertInfo))
)]
pub async fn get_cert(
    State(state): State<Arc<AppState>>,
    ApiPath(fp): ApiPath<String>,
    ApiQuery(q): ApiQuery<CertQuery>,
) -> ApiResult<Json<CertInfo>> {
    let info = state
        .certs()
        .info(&fp, q.host.as_deref())
        .ok_or_else(|| ApiError::NotFound("Certificate not found".into()))?;
    Ok(Json(dto(&info)?))
}

/// The latest certificate a host presented to the proxy.
#[utoipa::path(
    get, path = "/certs/by-host/{host}", tag = "certs",
    security(("bearer_auth" = ["logs:read"])),
    params(("host" = String, Path, description = "Host name as dialed")),
    responses((status = 403, description = "Profile-restricted token"), (status = 200, description = "Latest upstream certificate", body = CertInfo))
)]
pub async fn get_cert_by_host(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(host): ApiPath<String>,
) -> ApiResult<Json<CertInfo>> {
    // Whether a host has been visited at all would reveal other profiles' browsing.
    if p.profiles.is_some() {
        return Err(ApiError::coded(
            axum::http::StatusCode::FORBIDDEN,
            "profile_forbidden",
            "Profile-restricted tokens cannot look certificates up by host",
        ));
    }
    let info = state
        .certs()
        .by_host(&host)
        .ok_or_else(|| ApiError::NotFound("No certificate recorded for this host".into()))?;
    Ok(Json(dto(&info)?))
}

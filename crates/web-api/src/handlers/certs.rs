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

/// `?host=`: whose verification verdict to report.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CertQuery {
    /// `host` or `host:port` (default port 443) the certificate was presented to. Without it the
    /// verdict reflects the validity period only. A profile-restricted token gets 404 for hosts
    /// its profiles have not visited.
    pub host: Option<String>,
}

/// Same JSON shape on both sides; the DTO is the contract.
fn dto(info: &Stored) -> ApiResult<CertInfo> {
    serde_json::to_value(info)
        .and_then(serde_json::from_value)
        .map_err(|e| ApiError::Internal(format!("certificate info: {e}")))
}

/// Whether the caller may learn about `host`: unrestricted tokens always, a profile-restricted
/// one only for hosts its profiles have seen (otherwise indistinguishable from unknown).
fn visible(state: &AppState, p: &Principal, host: &str) -> bool {
    p.profiles.is_none()
        || state
            .certs()
            .seen_by(host)
            .iter()
            .any(|id| p.may_access_profile(id))
}

/// A leaf-only record of `host` is upgraded to the full chain through one (cached, bounded)
/// probe. Only when the probe saw this very certificate; after a rotation the record is
/// returned unchanged, never with another certificate's chain. Callers check visibility first.
async fn with_chain(state: &AppState, host: &str, info: Stored) -> Stored {
    let Some(probe) = state.chain_probe.get() else {
        return info;
    };
    if !info.is_leaf_only() {
        return info;
    }
    let hp = common::certstore::parse_hostport(host);
    let Some((h, port)) = hp
        .rsplit_once(':')
        .and_then(|(h, p)| Some((h, p.parse().ok()?)))
    else {
        return info;
    };
    if probe.probe(h, port).await.as_deref() != Some(info.fp.as_str()) {
        return info;
    }
    state.certs().info(&info.fp, Some(host)).unwrap_or(info)
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
    Extension(p): Extension<Principal>,
    ApiPath(fp): ApiPath<String>,
    ApiQuery(q): ApiQuery<CertQuery>,
) -> ApiResult<Json<CertInfo>> {
    if let Some(h) = q.host.as_deref() {
        if !visible(&state, &p, h) {
            return Err(ApiError::NotFound("Certificate not found".into()));
        }
    }
    let info = state
        .certs()
        .info(&fp, q.host.as_deref())
        .ok_or_else(|| ApiError::NotFound("Certificate not found".into()))?;
    let info = match q.host.as_deref() {
        Some(h) => with_chain(&state, h, info).await,
        None => info,
    };
    Ok(Json(dto(&info)?))
}

/// The latest certificate a host presented to the proxy.
#[utoipa::path(
    get, path = "/certs/by-host/{host}", tag = "certs",
    security(("bearer_auth" = ["logs:read"])),
    params(("host" = String, Path, description = "`host` or `host:port` as dialed (default port 443)")),
    responses((status = 200, description = "Latest upstream certificate", body = CertInfo))
)]
pub async fn get_cert_by_host(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(host): ApiPath<String>,
) -> ApiResult<Json<CertInfo>> {
    let unknown = || ApiError::NotFound("No certificate recorded for this host".into());
    if !visible(&state, &p, &host) {
        return Err(unknown());
    }
    let info = state.certs().by_host(&host).ok_or_else(unknown)?;
    let info = with_chain(&state, &host, info).await;
    Ok(Json(dto(&info)?))
}

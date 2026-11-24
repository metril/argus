//! Built-in HTTPS for the web UI: status, mode and certificate upload. Certificate keys are
//! never returned; only subject, names, expiry and fingerprint are.

use std::sync::Arc;

use api_types::{WebUiTlsRequest, WebUiTlsStatus, WebUiTlsUpload};
use axum::{extract::State, http::StatusCode, Extension, Json};
use common::config::{WebUiTls, WebUiTlsMode};
use tracing::info;

use crate::auth::authz::Principal;
use crate::error::{ApiError, ApiJson, ApiResult};
use crate::state::AppState;
use crate::webui_tls as tls;

fn unprocessable(msg: impl Into<String>) -> ApiError {
    ApiError::Coded {
        status: StatusCode::UNPROCESSABLE_ENTITY,
        code: "unprocessable",
        message: msg.into(),
    }
}

/// Current HTTPS setting of the web UI and its certificate.
#[utoipa::path(
    get, path = "/settings/webui/tls", tag = "config",
    security(("bearer_auth" = ["config:read"])),
    responses((status = 200, description = "HTTPS status", body = WebUiTlsStatus))
)]
pub async fn get_tls(State(state): State<Arc<AppState>>) -> ApiResult<Json<WebUiTlsStatus>> {
    let s = state.clone();
    Ok(Json(
        tokio::task::spawn_blocking(move || tls::status(&s))
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?,
    ))
}

/// Set the HTTPS mode, certificate names and HTTP redirect. Applied live: the next connection
/// uses the new certificate. 422 keeps the old setting when the certificate cannot be used.
#[utoipa::path(
    put, path = "/settings/webui/tls", tag = "config",
    security(("bearer_auth" = ["config:write"])),
    request_body = WebUiTlsRequest,
    responses(
        (status = 200, description = "Applied", body = WebUiTlsStatus),
        (status = 409, description = "No certificate could be issued"),
        (status = 422, description = "Invalid names or certificate"),
    )
)]
pub async fn put_tls(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiJson(req): ApiJson<WebUiTlsRequest>,
) -> ApiResult<Json<WebUiTlsStatus>> {
    let new = WebUiTls {
        mode: tls::config_mode(req.mode),
        sans: req.sans,
        redirect_http: req.redirect_http,
    };
    Ok(Json(commit(&state, &p.username, new, None).await?))
}

/// Upload a certificate chain and private key (PEM) and switch to it. The key must match the
/// certificate; otherwise 422 and the old certificate keeps being served.
#[utoipa::path(
    post, path = "/settings/webui/tls/upload", tag = "config",
    security(("bearer_auth" = ["config:write"])),
    request_body = WebUiTlsUpload,
    responses(
        (status = 200, description = "Uploaded and applied", body = WebUiTlsStatus),
        (status = 422, description = "Not a valid certificate/key pair"),
    )
)]
pub async fn upload_tls(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiJson(req): ApiJson<WebUiTlsUpload>,
) -> ApiResult<Json<WebUiTlsStatus>> {
    let sans = state.proxy_state.config.read().webui.tls.sans.clone();
    let new = WebUiTls {
        mode: WebUiTlsMode::Uploaded,
        sans,
        redirect_http: req.redirect_http,
    };
    Ok(Json(
        commit(&state, &p.username, new, Some((req.cert_pem, req.key_pem))).await?,
    ))
}

/// Validate, write, swap live and persist; any failure puts everything back.
async fn commit(
    state: &Arc<AppState>,
    who: &str,
    mut new: WebUiTls,
    upload: Option<(String, String)>,
) -> ApiResult<WebUiTlsStatus> {
    let _g = state.config_lock.lock().await;
    if !new.sans.is_empty() || new.mode == WebUiTlsMode::ArgusCa {
        new.sans = tls::validate_sans(&new.sans).map_err(unprocessable)?;
    }

    let (up_c, up_k) = tls::uploaded_paths(state);
    let (is_c, is_k) = tls::issued_paths(state);
    let backup = tls::Backup::of(&[&up_c, &up_k, &is_c, &is_k]);

    if let Some((cert, key)) = &upload {
        tls::server_config(cert, key).map_err(unprocessable)?;
        tls::inspect(cert).map_err(unprocessable)?;
        let (c, k) = (cert.clone(), key.clone());
        tokio::task::spawn_blocking(move || {
            tls::write_private(&up_c, c.as_bytes())?;
            tls::write_private(&up_k, k.as_bytes())
        })
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(|e| ApiError::Internal(format!("could not store the certificate: {e}")))?;
    }

    let built = async {
        match tls::material(state, &new).await {
            Ok(Some(m)) => tls::server_config(&m.cert_pem, &m.key_pem).map(Some),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
    .await;
    let cfg = match built {
        Ok(c) => c,
        Err(e) => {
            backup.restore();
            return Err(if new.mode == WebUiTlsMode::ArgusCa {
                ApiError::Coded {
                    status: StatusCode::CONFLICT,
                    code: "tls_unavailable",
                    message: e,
                }
            } else {
                unprocessable(e)
            });
        }
    };

    let web = state.web_server.get().cloned();
    let old_live = web.as_ref().map(|w| w.tls_snapshot());
    if let Some(w) = &web {
        w.set_tls(cfg, new.redirect_http);
    }

    let mut config = state.proxy_state.config.read().clone();
    config.webui.tls = new;
    let overlay_path = state.overlay_path.read().clone();
    let base_path = state.config_path.read().clone();
    let c2 = config.clone();
    let save = tokio::task::spawn_blocking(move || c2.save_overlay(&base_path, &overlay_path))
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    if let Err(e) = save {
        if let (Some(w), Some((c, r))) = (&web, old_live) {
            w.set_tls(c, r);
        }
        backup.restore();
        return Err(ApiError::Internal(format!("Failed to save settings: {e}")));
    }
    info!("Web UI HTTPS set to {:?} by {who}", config.webui.tls.mode);
    *state.proxy_state.config.write() = config;
    let s = state.clone();
    tokio::task::spawn_blocking(move || tls::status(&s))
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))
}

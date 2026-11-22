//! Device handlers: a device is a set of addresses or a bearer token that selects a profile.
//!
//! A profile-restricted token sees and edits only devices assigned to its profiles and cannot
//! move a device to a profile it lacks. A device token is returned once, by `issue_token`, and
//! never appears in any other response, in the audit log or in logs.

use std::sync::Arc;

use api_types::{
    CreateDeviceRequest, DeviceDto, DeviceTokenCreated, MessageResponse, Page, UpdateDeviceRequest,
};
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use chrono::Utc;
use common::profile_store::DeviceRecord;
use ipnet::IpNet;
use tracing::info;
use validator::Validate;

use super::PageQuery;
use crate::auth::authz::Principal;
use crate::auth::profile::{forbidden_profile, parse_profile_id};
use crate::error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult};
use crate::state::{blocking, AppState};

pub fn device_dto(d: &DeviceRecord) -> DeviceDto {
    DeviceDto {
        id: d.id.to_string(),
        name: d.name.clone(),
        profile_id: d.profile_id.to_string(),
        ips: d.ips.iter().map(|n| n.to_string()).collect(),
        has_token: d.token_digest.is_some(),
        token_hint: d.token_hint.clone(),
        // The proxy does not record when a device was last seen; nothing is invented here.
        last_seen: None,
        created_at: d.created_at.to_rfc3339(),
    }
}

fn parse_device_id(s: &str) -> ApiResult<u64> {
    s.parse::<u64>().map_err(|_| {
        ApiError::coded(
            StatusCode::BAD_REQUEST,
            "invalid_device",
            "Invalid device id: expected a decimal number",
        )
    })
}

/// Parse `10.0.0.5`, `10.0.0.0/24`, `fd00::1` or `fd00::/64`.
fn parse_net(s: &str) -> ApiResult<IpNet> {
    let s = s.trim();
    s.parse::<IpNet>()
        .or_else(|_| s.parse::<std::net::IpAddr>().map(IpNet::from))
        .map_err(|_| ApiError::ValidationError(format!("'{s}' is not an address or CIDR prefix")))
}

fn parse_nets(v: &[String]) -> ApiResult<Vec<IpNet>> {
    v.iter().map(|s| parse_net(s)).collect()
}

/// Profile the caller may assign devices to: it must exist and pass the token restriction.
async fn target_profile(state: &Arc<AppState>, p: &Principal, raw: &str) -> ApiResult<u64> {
    let id = parse_profile_id(raw)?;
    if !p.may_access_profile(&id.to_string()) {
        return Err(forbidden_profile(id));
    }
    let st = state.clone();
    if blocking(move || Ok(st.profiles.get(id)?)).await?.is_none() {
        return Err(ApiError::ValidationError(format!(
            "Profile {id} does not exist"
        )));
    }
    Ok(id)
}

/// Load a device the caller may access (403 when its profile is out of reach, 404 when absent).
async fn load(state: &Arc<AppState>, p: &Principal, raw: &str) -> ApiResult<DeviceRecord> {
    let id = parse_device_id(raw)?;
    let st = state.clone();
    let d = blocking(move || Ok(st.profiles.device(id)?))
        .await?
        .ok_or_else(|| ApiError::NotFound("Device not found".into()))?;
    if !p.may_access_profile(&d.profile_id.to_string()) {
        return Err(forbidden_profile(d.profile_id));
    }
    Ok(d)
}

/// List the devices the caller may see.
#[utoipa::path(
    get, path = "/devices", tag = "devices",
    security(("bearer_auth" = ["devices:read"])),
    params(PageQuery),
    responses((status = 200, description = "Devices", body = Page<DeviceDto>))
)]
pub async fn list_devices(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiQuery(q): ApiQuery<PageQuery>,
) -> ApiResult<Json<Page<DeviceDto>>> {
    let st = state.clone();
    let all = blocking(move || Ok(st.profiles.devices()?)).await?;
    let items = all
        .iter()
        .filter(|d| p.may_access_profile(&d.profile_id.to_string()))
        .map(device_dto)
        .collect();
    Ok(Json(Page::from_vec(items, q.page, q.limit)))
}

/// Create a device (no token yet; issue one with `POST /devices/{device_id}/token`).
#[utoipa::path(
    post, path = "/devices", tag = "devices",
    security(("bearer_auth" = ["devices:write"])),
    request_body = CreateDeviceRequest,
    responses(
        (status = 201, description = "Created", body = DeviceDto),
        (status = 400, description = "Invalid name, profile or addresses"),
        (status = 403, description = "Token is not allowed to use that profile"),
        (status = 409, description = "An address is already used by another device"),
    )
)]
pub async fn create_device(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiJson(req): ApiJson<CreateDeviceRequest>,
) -> ApiResult<(StatusCode, Json<DeviceDto>)> {
    req.validate()?;
    let profile_id = target_profile(&state, &p, &req.profile_id).await?;
    let ips = parse_nets(&req.ips)?;
    let st = state.clone();
    let rec = blocking(move || {
        Ok(st.profiles.put_device(DeviceRecord {
            id: 0,
            name: req.name,
            profile_id,
            ips,
            token_digest: None,
            token_hint: None,
            created_at: Utc::now(),
        })?)
    })
    .await?;
    info!("Device {} created by {}", rec.id, p.username);
    Ok((StatusCode::CREATED, Json(device_dto(&rec))))
}

/// Get one device.
#[utoipa::path(
    get, path = "/devices/{device_id}", tag = "devices",
    security(("bearer_auth" = ["devices:read"])),
    params(("device_id" = String, Path, description = "Device id (decimal)")),
    responses(
        (status = 200, description = "Device", body = DeviceDto),
        (status = 403, description = "Device belongs to a profile this token cannot access"),
        (status = 404, description = "No such device"),
    )
)]
pub async fn get_device(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<DeviceDto>> {
    Ok(Json(device_dto(&load(&state, &p, &id).await?)))
}

/// Update a device's name, profile or addresses; omitted fields are unchanged.
#[utoipa::path(
    put, path = "/devices/{device_id}", tag = "devices",
    security(("bearer_auth" = ["devices:write"])),
    params(("device_id" = String, Path, description = "Device id (decimal)")),
    request_body = UpdateDeviceRequest,
    responses(
        (status = 200, description = "Updated", body = DeviceDto),
        (status = 400, description = "Invalid name, profile or addresses"),
        (status = 403, description = "Token is not allowed to use the device's or the new profile"),
        (status = 404, description = "No such device"),
        (status = 409, description = "An address is already used by another device"),
    )
)]
pub async fn update_device(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
    ApiJson(req): ApiJson<UpdateDeviceRequest>,
) -> ApiResult<Json<DeviceDto>> {
    req.validate()?;
    let mut rec = load(&state, &p, &id).await?;
    if let Some(pid) = &req.profile_id {
        rec.profile_id = target_profile(&state, &p, pid).await?;
    }
    if let Some(n) = req.name {
        rec.name = n;
    }
    if let Some(ips) = &req.ips {
        rec.ips = parse_nets(ips)?;
    }
    let st = state.clone();
    let rec = blocking(move || Ok(st.profiles.put_device(rec)?)).await?;
    info!("Device {} updated by {}", rec.id, p.username);
    Ok(Json(device_dto(&rec)))
}

/// Delete a device (its token stops working).
#[utoipa::path(
    delete, path = "/devices/{device_id}", tag = "devices",
    security(("bearer_auth" = ["devices:write"])),
    params(("device_id" = String, Path, description = "Device id (decimal)")),
    responses(
        (status = 200, description = "Deleted", body = MessageResponse),
        (status = 403, description = "Device belongs to a profile this token cannot access"),
        (status = 404, description = "No such device"),
    )
)]
pub async fn delete_device(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<MessageResponse>> {
    let d = load(&state, &p, &id).await?;
    let st = state.clone();
    let did = d.id;
    if !blocking(move || Ok(st.profiles.delete_device(did)?)).await? {
        return Err(ApiError::NotFound("Device not found".into()));
    }
    info!("Device {did} deleted by {}", p.username);
    Ok(Json(MessageResponse {
        message: "Device deleted".into(),
    }))
}

/// Issue a new token for a device, replacing the current one. The raw token is in this response
/// only (`Cache-Control: no-store`); it cannot be retrieved again. Use it as the proxy
/// credential: `http://device:<token>@<proxy-host>:<port>`.
#[utoipa::path(
    post, path = "/devices/{device_id}/token", tag = "devices",
    security(("bearer_auth" = ["devices:write"])),
    params(("device_id" = String, Path, description = "Device id (decimal)")),
    responses(
        (status = 201, description = "Issued; `token` is shown only here", body = DeviceTokenCreated),
        (status = 403, description = "Device belongs to a profile this token cannot access"),
        (status = 404, description = "No such device"),
    )
)]
pub async fn issue_device_token(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<impl IntoResponse> {
    let d = load(&state, &p, &id).await?;
    let st = state.clone();
    let did = d.id;
    let token = blocking(move || Ok(st.profiles.issue_token(did)?)).await?;
    info!("Token issued for device {did} by {}", p.username);
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(DeviceTokenCreated { token }),
    ))
}

/// Revoke a device's token; it stops working immediately.
#[utoipa::path(
    delete, path = "/devices/{device_id}/token", tag = "devices",
    security(("bearer_auth" = ["devices:write"])),
    params(("device_id" = String, Path, description = "Device id (decimal)")),
    responses(
        (status = 200, description = "Revoked", body = MessageResponse),
        (status = 403, description = "Device belongs to a profile this token cannot access"),
        (status = 404, description = "No such device, or it has no token"),
    )
)]
pub async fn revoke_device_token(
    State(state): State<Arc<AppState>>,
    Extension(p): Extension<Principal>,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<MessageResponse>> {
    let d = load(&state, &p, &id).await?;
    let st = state.clone();
    let did = d.id;
    if !blocking(move || Ok(st.profiles.revoke_token(did)?)).await? {
        return Err(ApiError::NotFound("Device has no token".into()));
    }
    info!("Token of device {did} revoked by {}", p.username);
    Ok(Json(MessageResponse {
        message: "Device token revoked".into(),
    }))
}

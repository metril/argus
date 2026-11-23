//! Per-device profiles: a named set of enabled lists plus custom overlay rules, and the devices
//! (addresses, prefixes or a bearer token) that select one.
//!
//! Profile id `"0"` is the built-in `default` profile; its lists and rules are the global ones.

use serde::{Deserialize, Serialize};

/// Largest accepted overlay rules text, in bytes.
pub const MAX_PROFILE_RULES_BYTES: usize = 256 * 1024;
/// Longest profile or device name, in characters.
pub const MAX_NAME_CHARS: usize = 64;
/// Most addresses/prefixes one device may list.
pub const MAX_DEVICE_IPS: usize = 64;

/// Whether `name` is a valid profile name: 1-64 characters of ASCII letters, digits, `_`, `-`,
/// `.` and inner spaces (so it is safe as a storage namespace and as a path segment).
pub fn validate_profile_name(name: &str) -> Result<(), String> {
    let n = name.chars().count();
    if !(1..=MAX_NAME_CHARS).contains(&n) {
        return Err(format!("name must be 1-{MAX_NAME_CHARS} characters"));
    }
    if name.starts_with(' ') || name.ends_with(' ') {
        return Err("name must not start or end with a space".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' '))
    {
        return Err("name may contain only letters, digits, space, '_', '-' and '.'".into());
    }
    Ok(())
}

#[cfg(feature = "server")]
fn v_profile_name(name: &str) -> Result<(), validator::ValidationError> {
    validate_profile_name(name).map_err(|m| {
        let mut e = validator::ValidationError::new("invalid_profile_name");
        e.message = Some(m.into());
        e
    })
}

/// A profile (response). `id` is the decimal profile id; `"0"` is the default profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ProfileDto {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Enabled filter list ids.
    #[serde(default)]
    pub lists: Vec<String>,
    /// Custom overlay rules (adblock syntax).
    #[serde(default)]
    pub rules: String,
    pub created_at: String,
    pub updated_at: String,
    /// Why the proxy's last build of this profile failed (it keeps serving the previous state);
    /// absent when the last build succeeded or the proxy reports no build status.
    #[serde(default)]
    pub last_error: Option<String>,
    /// When the proxy last built this profile successfully (RFC 3339).
    #[serde(default)]
    pub last_built: Option<String>,
}

/// Create a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct CreateProfileRequest {
    #[cfg_attr(feature = "server", validate(custom(function = "v_profile_name")))]
    pub name: String,
    #[serde(default)]
    #[cfg_attr(feature = "server", validate(length(max = 500)))]
    pub description: String,
    #[serde(default)]
    pub lists: Vec<String>,
    #[serde(default)]
    #[cfg_attr(feature = "server", validate(length(max = 262_144)))]
    pub rules: String,
}

/// Update a profile; omitted fields are unchanged. The default profile cannot be renamed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct UpdateProfileRequest {
    #[cfg_attr(feature = "server", validate(custom(function = "v_profile_name")))]
    pub name: Option<String>,
    #[cfg_attr(feature = "server", validate(length(max = 500)))]
    pub description: Option<String>,
    pub lists: Option<Vec<String>>,
    #[cfg_attr(feature = "server", validate(length(max = 262_144)))]
    pub rules: Option<String>,
}

/// A device (response).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct DeviceDto {
    pub id: String,
    pub name: String,
    pub profile_id: String,
    /// Addresses or CIDR prefixes identifying the device.
    #[serde(default)]
    pub ips: Vec<String>,
    pub has_token: bool,
    /// Last 4 characters of the current token, to tell tokens apart.
    #[serde(default)]
    pub token_hint: Option<String>,
    /// When a connection last resolved to this device (RFC 3339, second resolution). Kept in
    /// proxy memory: absent until the device connects after a proxy start.
    #[serde(default)]
    pub last_seen: Option<String>,
    pub created_at: String,
}

/// Devices per category, for the current search text.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct DeviceCounts {
    pub all: usize,
    pub with_token: usize,
    /// Connected since the proxy started.
    pub seen: usize,
    /// Devices per profile id.
    pub by_profile: std::collections::BTreeMap<String, usize>,
    /// First characters (`A`-`Z`, `#`) present among the rows matching the current filters.
    #[serde(default)]
    pub letters: Vec<String>,
}

/// A page of devices plus counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct DevicesPage {
    pub items: Vec<DeviceDto>,
    pub next_cursor: Option<String>,
    pub total: usize,
    pub counts: DeviceCounts,
    pub limit: u32,
    pub has_more: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
}

/// Create a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct CreateDeviceRequest {
    #[cfg_attr(feature = "server", validate(length(min = 1, max = 64)))]
    pub name: String,
    pub profile_id: String,
    #[serde(default)]
    #[cfg_attr(feature = "server", validate(length(max = 64)))]
    pub ips: Vec<String>,
}

/// Update a device; omitted fields are unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(validator::Validate, utoipa::ToSchema))]
pub struct UpdateDeviceRequest {
    #[cfg_attr(feature = "server", validate(length(min = 1, max = 64)))]
    pub name: Option<String>,
    pub profile_id: Option<String>,
    #[cfg_attr(feature = "server", validate(length(max = 64)))]
    pub ips: Option<Vec<String>>,
}

/// A freshly issued device token. The raw value is shown once and never stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct DeviceTokenCreated {
    pub token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(validate_profile_name("Kids tablet-2.0_a").is_ok());
        for bad in ["", " x", "x ", "a/b", "a\0b", "é", &"x".repeat(65)] {
            assert!(validate_profile_name(bad).is_err(), "{bad:?}");
        }
        assert!(validate_profile_name(&"x".repeat(64)).is_ok());
    }
}

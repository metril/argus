//! Profile and device API calls (`/api/v1/profiles`, `/api/v1/devices`)

use super::auth::MessageResponse;
use super::client::{ApiClient, ApiError};

pub use api_types::{
    CreateDeviceRequest, CreateProfileRequest, DeviceDto, DeviceTokenCreated, Page, ProfileDto,
    UpdateDeviceRequest, UpdateProfileRequest,
};

impl ApiClient {
    pub async fn list_profiles(&self) -> Result<Vec<ProfileDto>, ApiError> {
        let page: Page<ProfileDto> = self.get("/profiles?limit=200").await?;
        Ok(page.items)
    }

    pub async fn create_profile(&self, r: &CreateProfileRequest) -> Result<ProfileDto, ApiError> {
        self.post("/profiles", r).await
    }

    pub async fn update_profile(
        &self,
        id: &str,
        r: &UpdateProfileRequest,
    ) -> Result<ProfileDto, ApiError> {
        self.put(&format!("/profiles/{id}"), r).await
    }

    pub async fn delete_profile(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/profiles/{id}")).await
    }

    pub async fn list_devices(&self) -> Result<Vec<DeviceDto>, ApiError> {
        let page: Page<DeviceDto> = self.get("/devices?limit=200").await?;
        Ok(page.items)
    }

    /// Cursor-paged devices. `profile` empty = all; `sort`: name | last_seen; `from` seeks to a
    /// name prefix (name sort only).
    pub async fn list_devices_paged(
        &self,
        q: &str,
        profile: &str,
        sort: &str,
        cursor: Option<&str>,
        from: Option<&str>,
        limit: u32,
    ) -> Result<api_types::DevicesPage, ApiError> {
        let enc = |s: &str| String::from(js_sys::encode_uri_component(s));
        let mut url = format!("/devices?limit={limit}&sort={sort}&q={}", enc(q.trim()));
        if !profile.is_empty() {
            url.push_str(&format!("&profile={}", enc(profile)));
        }
        if let Some(c) = cursor {
            url.push_str(&format!("&cursor={}", enc(c)));
        }
        if let Some(f) = from {
            url.push_str(&format!("&from={}", enc(f)));
        }
        self.get(&url).await
    }

    pub async fn create_device(&self, r: &CreateDeviceRequest) -> Result<DeviceDto, ApiError> {
        self.post("/devices", r).await
    }

    pub async fn update_device(
        &self,
        id: &str,
        r: &UpdateDeviceRequest,
    ) -> Result<DeviceDto, ApiError> {
        self.put(&format!("/devices/{id}"), r).await
    }

    pub async fn delete_device(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/devices/{id}")).await
    }

    /// Issue (or replace) a device token. The raw token is only in this response.
    pub async fn issue_device_token(&self, id: &str) -> Result<DeviceTokenCreated, ApiError> {
        self.post(&format!("/devices/{id}/token"), &serde_json::json!({}))
            .await
    }

    pub async fn revoke_device_token(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/devices/{id}/token")).await
    }
}

/// Addresses typed one per line or separated by commas/spaces, as a clean list.
pub fn parse_addresses(text: &str) -> Vec<String> {
    text.split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// The proxy URL a device configures: `http://device:<token>@<host>:<port>`.
pub fn proxy_url(token: &str, host: &str, port: u16) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    format!("http://device:{token}@{host}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_split_on_lines_commas_and_spaces() {
        assert_eq!(
            parse_addresses("10.0.0.1, 10.0.0.2\n192.168.1.0/24  fd00::1\n"),
            vec!["10.0.0.1", "10.0.0.2", "192.168.1.0/24", "fd00::1"]
        );
        assert!(parse_addresses("  \n").is_empty());
    }

    #[test]
    fn proxy_url_brackets_ipv6_hosts() {
        assert_eq!(
            proxy_url("abd_x", "proxy.lan", 8080),
            "http://device:abd_x@proxy.lan:8080"
        );
        assert_eq!(
            proxy_url("abd_x", "fd00::1", 8080),
            "http://device:abd_x@[fd00::1]:8080"
        );
    }
}

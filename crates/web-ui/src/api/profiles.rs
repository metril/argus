//! Profile and device API calls (`/api/v1/profiles`, `/api/v1/devices`)

use super::auth::MessageResponse;
use super::client::{ApiClient, ApiError};

pub use api_types::{
    CreateDeviceRequest, CreateProfileRequest, DeviceDto, DeviceTokenCreated, Page, ProfileDto,
    UpdateDeviceRequest, UpdateProfileRequest,
};

/// Short-lived share of the unfiltered first page: the navbar and the page behind it both ask
/// for it on every navigation. Any profile write (and logout) drops it, and a fetch that was
/// already running when that happened is not stored.
struct FirstPage<T> {
    inflight: bool,
    at: f64,
    /// Bumped by every invalidation.
    gen: u64,
    page: Option<T>,
}

impl<T: Clone> FirstPage<T> {
    const fn new() -> Self {
        Self {
            inflight: false,
            at: 0.0,
            gen: 0,
            page: None,
        }
    }

    fn fresh(&self, now: f64, ttl: f64) -> Option<T> {
        self.page.clone().filter(|_| now - self.at < ttl)
    }

    fn invalidate(&mut self) {
        self.gen += 1;
        self.page = None;
    }

    /// Begin a fetch: returns the generation to hand back to [`Self::finish`].
    fn start(&mut self) -> u64 {
        self.inflight = true;
        self.gen
    }

    fn finish(&mut self, started_gen: u64, now: f64, result: Option<&T>) {
        self.inflight = false;
        if let (Some(p), true) = (result, started_gen == self.gen) {
            self.page = Some(p.clone());
            self.at = now;
        }
    }
}

thread_local! {
    static FIRST_PAGE: std::cell::RefCell<FirstPage<Page<ProfileDto>>> =
        const { std::cell::RefCell::new(FirstPage::new()) };
}

const FIRST_PAGE_TTL_MS: f64 = 2000.0;

fn invalidate_first_page() {
    FIRST_PAGE.with(|c| c.borrow_mut().invalidate());
}

/// Drop cached profile data (on logout, so the next user never sees it).
pub fn clear_profile_cache() {
    invalidate_first_page();
}

impl ApiClient {
    /// Every profile (for pickers), following the cursor.
    pub async fn list_profiles(&self) -> Result<Vec<ProfileDto>, ApiError> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = self.list_profiles_page("", cursor.as_deref()).await?;
            all.extend(page.items);
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => return Ok(all),
            }
        }
    }

    /// One page of profiles, A-Z, optionally filtered by name.
    pub async fn list_profiles_page(
        &self,
        q: &str,
        cursor: Option<&str>,
    ) -> Result<Page<ProfileDto>, ApiError> {
        if !q.trim().is_empty() || cursor.is_some() {
            return self.fetch_profiles_page(q, cursor).await;
        }
        // Unfiltered first page: reuse a fresh copy, or wait for the request already in flight.
        loop {
            let hit = FIRST_PAGE.with(|c| {
                let c = c.borrow();
                match c.fresh(js_sys::Date::now(), FIRST_PAGE_TTL_MS) {
                    Some(p) => Some(Some(p)),
                    None if c.inflight => Some(None),
                    None => None,
                }
            });
            match hit {
                Some(Some(p)) => return Ok(p),
                Some(None) => gloo_timers::future::TimeoutFuture::new(25).await,
                None => break,
            }
        }
        let g = FIRST_PAGE.with(|c| c.borrow_mut().start());
        let r = self.fetch_profiles_page("", None).await;
        FIRST_PAGE.with(|c| {
            c.borrow_mut()
                .finish(g, js_sys::Date::now(), r.as_ref().ok());
        });
        r
    }

    async fn fetch_profiles_page(
        &self,
        q: &str,
        cursor: Option<&str>,
    ) -> Result<Page<ProfileDto>, ApiError> {
        self.get(&format!(
            "/profiles?limit=100&q={}{}",
            js_sys::encode_uri_component(q.trim()),
            super::admin::cur(cursor)
        ))
        .await
    }

    pub async fn create_profile(&self, r: &CreateProfileRequest) -> Result<ProfileDto, ApiError> {
        invalidate_first_page();
        let out = self.post("/profiles", r).await;
        invalidate_first_page();
        out
    }

    pub async fn update_profile(
        &self,
        id: &str,
        r: &UpdateProfileRequest,
    ) -> Result<ProfileDto, ApiError> {
        invalidate_first_page();
        let out = self.put(&format!("/profiles/{id}"), r).await;
        invalidate_first_page();
        out
    }

    pub async fn delete_profile(&self, id: &str) -> Result<MessageResponse, ApiError> {
        invalidate_first_page();
        let out = self.delete(&format!("/profiles/{id}")).await;
        invalidate_first_page();
        out
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

#[cfg(test)]
mod first_page_tests {
    use super::FirstPage;

    #[test]
    fn fresh_page_is_served_until_ttl() {
        let mut c = FirstPage::<u32>::new();
        let g = c.start();
        c.finish(g, 100.0, Some(&7));
        assert_eq!(c.fresh(1000.0, 2000.0), Some(7));
        assert_eq!(c.fresh(2200.0, 2000.0), None);
    }

    #[test]
    fn write_during_fetch_keeps_stale_result_out_of_the_cache() {
        let mut c = FirstPage::<u32>::new();
        let g = c.start();
        // A profile write lands while the fetch is in flight.
        c.invalidate();
        c.finish(g, 100.0, Some(&1));
        assert_eq!(c.fresh(101.0, 2000.0), None);
        assert!(!c.inflight);
        // The next fetch started after the write is stored.
        let g = c.start();
        c.finish(g, 200.0, Some(&2));
        assert_eq!(c.fresh(201.0, 2000.0), Some(2));
    }

    #[test]
    fn invalidate_drops_a_cached_page() {
        let mut c = FirstPage::<u32>::new();
        let g = c.start();
        c.finish(g, 0.0, Some(&3));
        c.invalidate();
        assert_eq!(c.fresh(1.0, 2000.0), None);
    }
}

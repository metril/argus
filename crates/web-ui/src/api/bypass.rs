//! Bypass API calls (`/api/v1/bypass/*`)

use super::auth::MessageResponse;
use super::client::{ApiClient, ApiError};

pub use api_types::{
    ArgusListsStatus, BypassCheckResponse, BypassEntriesPage, BypassEntryDto, BypassHostsResponse,
    BypassMode, BypassSettings, BypassSubscriptionDto, CreateBypassEntry, CreateBypassSubscription,
    SuggestedSubscription, UpdateBypassCategory, UpdateBypassEntry, UpdateBypassSettings,
    UpdateBypassSubscription,
};

fn enc(s: &str) -> String {
    js_sys::encode_uri_component(s)
        .as_string()
        .unwrap_or_default()
}

pub fn mode_key(m: BypassMode) -> &'static str {
    match m {
        BypassMode::NoDecrypt => "no_decrypt",
        BypassMode::Full => "full",
    }
}

pub fn parse_mode(s: &str) -> BypassMode {
    if s == "full" {
        BypassMode::Full
    } else {
        BypassMode::NoDecrypt
    }
}

pub fn mode_label(m: BypassMode) -> &'static str {
    match m {
        BypassMode::NoDecrypt => "Don't decrypt",
        BypassMode::Full => "Bypass entirely",
    }
}

impl ApiClient {
    pub async fn argus_lists(&self) -> Result<ArgusListsStatus, ApiError> {
        self.get("/bypass/argus-lists").await
    }

    pub async fn refresh_argus_lists(&self) -> Result<ArgusListsStatus, ApiError> {
        self.post("/bypass/argus-lists/refresh", &()).await
    }

    pub async fn update_bypass_category(
        &self,
        id: &str,
        u: &UpdateBypassCategory,
    ) -> Result<api_types::BypassCategoryDto, ApiError> {
        self.put(&format!("/bypass/categories/{id}"), u).await
    }

    pub async fn bypass_category_hosts(
        &self,
        id: &str,
        q: &str,
    ) -> Result<BypassHostsResponse, ApiError> {
        self.get(&format!(
            "/bypass/categories/{id}/hosts?limit=200&q={}",
            enc(q)
        ))
        .await
    }

    pub async fn bypass_settings(&self) -> Result<BypassSettings, ApiError> {
        self.get("/bypass/settings").await
    }

    pub async fn update_bypass_settings(
        &self,
        u: &UpdateBypassSettings,
    ) -> Result<BypassSettings, ApiError> {
        self.put("/bypass/settings", u).await
    }

    pub async fn list_bypass_entries(
        &self,
        q: &str,
        mode: &str,
        sort: &str,
        cursor: Option<&str>,
        from: Option<&str>,
    ) -> Result<BypassEntriesPage, ApiError> {
        let mut p = format!("/bypass/entries?limit=40&q={}&sort={sort}", enc(q));
        if !mode.is_empty() {
            p.push_str(&format!("&mode={mode}"));
        }
        if let Some(c) = cursor {
            p.push_str(&format!("&cursor={}", enc(c)));
        }
        if let Some(f) = from {
            p.push_str(&format!("&from={}", enc(f)));
        }
        self.get(&p).await
    }

    pub async fn create_bypass_entry(
        &self,
        pattern: &str,
        mode: BypassMode,
    ) -> Result<BypassEntryDto, ApiError> {
        self.post(
            "/bypass/entries",
            &CreateBypassEntry {
                pattern: pattern.to_string(),
                mode: Some(mode),
                note: None,
            },
        )
        .await
    }

    pub async fn update_bypass_entry(
        &self,
        id: &str,
        mode: BypassMode,
    ) -> Result<BypassEntryDto, ApiError> {
        self.put(
            &format!("/bypass/entries/{id}"),
            &UpdateBypassEntry {
                mode: Some(mode),
                ..Default::default()
            },
        )
        .await
    }

    pub async fn delete_bypass_entry(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/bypass/entries/{id}")).await
    }

    pub async fn list_bypass_subscriptions(&self) -> Result<Vec<BypassSubscriptionDto>, ApiError> {
        self.get("/bypass/subscriptions").await
    }

    pub async fn suggested_bypass_subscriptions(
        &self,
    ) -> Result<Vec<SuggestedSubscription>, ApiError> {
        self.get("/bypass/subscriptions/suggested").await
    }

    pub async fn create_bypass_subscription(
        &self,
        r: &CreateBypassSubscription,
    ) -> Result<BypassSubscriptionDto, ApiError> {
        self.post("/bypass/subscriptions", r).await
    }

    pub async fn update_bypass_subscription(
        &self,
        id: &str,
        u: &UpdateBypassSubscription,
    ) -> Result<BypassSubscriptionDto, ApiError> {
        self.put(&format!("/bypass/subscriptions/{id}"), u).await
    }

    pub async fn delete_bypass_subscription(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/bypass/subscriptions/{id}")).await
    }

    pub async fn refresh_bypass_subscription(
        &self,
        id: &str,
    ) -> Result<BypassSubscriptionDto, ApiError> {
        self.post(&format!("/bypass/subscriptions/{id}/refresh"), &())
            .await
    }
}

//! Script policy API calls

use super::auth::MessageResponse;
use super::client::{ApiClient, ApiError};

pub use api_types::{
    ExplainResponse, Page, PanelSettingsDto, PanelSettingsInput, PolicySettingsDto,
    PolicySettingsResponse, PresetDto, SiteExceptionsResponse, SiteRuleDto, SiteRuleInput,
    SiteRuleUpdate, SourceRuleDto, SourceRuleInput, SourceRuleUpdate, TempGrantDto, TempGrantInput,
};

/// Percent-encode a query value.
fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

impl ApiClient {
    pub async fn get_panel_settings(&self) -> Result<PanelSettingsDto, ApiError> {
        self.get("/policy/panel").await
    }

    pub async fn put_panel_settings(
        &self,
        s: &PanelSettingsInput,
    ) -> Result<PanelSettingsDto, ApiError> {
        self.put("/policy/panel", s).await
    }

    pub async fn get_site_exceptions(&self) -> Result<SiteExceptionsResponse, ApiError> {
        self.get("/rules/site-exceptions").await
    }

    pub async fn set_site_exception(
        &self,
        site: &str,
        blocking_off: bool,
    ) -> Result<SiteExceptionsResponse, ApiError> {
        let path = format!("/rules/site-exceptions/{}", enc(site));
        if blocking_off {
            self.put(&path, &serde_json::json!({})).await
        } else {
            self.delete(&path).await
        }
    }

    pub async fn get_policy_settings(&self) -> Result<PolicySettingsResponse, ApiError> {
        self.get("/policy/settings").await
    }

    pub async fn put_policy_settings(
        &self,
        s: &PolicySettingsDto,
    ) -> Result<PolicySettingsResponse, ApiError> {
        self.put("/policy/settings", s).await
    }

    pub async fn list_site_rules(&self, q: &str) -> Result<Page<SiteRuleDto>, ApiError> {
        self.get(&format!("/policy/site-rules?limit=200&q={}", enc(q)))
            .await
    }

    pub async fn create_site_rule(&self, r: &SiteRuleInput) -> Result<SiteRuleDto, ApiError> {
        self.post("/policy/site-rules", r).await
    }

    pub async fn update_site_rule(
        &self,
        id: &str,
        r: &SiteRuleUpdate,
    ) -> Result<SiteRuleDto, ApiError> {
        self.put(&format!("/policy/site-rules/{id}"), r).await
    }

    pub async fn delete_site_rule(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/policy/site-rules/{id}")).await
    }

    pub async fn list_source_rules(
        &self,
        page_scope: &str,
    ) -> Result<Page<SourceRuleDto>, ApiError> {
        self.get(&format!(
            "/policy/source-rules?limit=200&page_scope={}",
            enc(page_scope)
        ))
        .await
    }

    pub async fn create_source_rule(&self, r: &SourceRuleInput) -> Result<SourceRuleDto, ApiError> {
        self.post("/policy/source-rules", r).await
    }

    pub async fn update_source_rule(
        &self,
        id: &str,
        r: &SourceRuleUpdate,
    ) -> Result<SourceRuleDto, ApiError> {
        self.put(&format!("/policy/source-rules/{id}"), r).await
    }

    pub async fn delete_source_rule(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/policy/source-rules/{id}")).await
    }

    pub async fn list_temp_grants(&self) -> Result<Vec<TempGrantDto>, ApiError> {
        self.get("/policy/temp").await
    }

    pub async fn grant_temp(&self, g: &TempGrantInput) -> Result<TempGrantDto, ApiError> {
        self.post("/policy/temp", g).await
    }

    pub async fn revoke_temp(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/policy/temp/{id}")).await
    }

    pub async fn revoke_all_temp(&self) -> Result<MessageResponse, ApiError> {
        self.delete("/policy/temp").await
    }

    pub async fn explain_policy(&self, url: &str) -> Result<ExplainResponse, ApiError> {
        self.get(&format!("/policy/explain?url={}", enc(url))).await
    }
}

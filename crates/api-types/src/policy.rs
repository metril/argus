//! Script policy DTOs (`/api/v1/policy/...`). Scopes are strings: `*`, `site:example.com`,
//! `host:www.example.com`, `https://www.example.com`. Capabilities are kebab-case names
//! (`script`, `inline-script`, `eval`, `wasm`, `object`, `media`, `frame`, `font`, `connect`,
//! `ping`, `worker`, `style`, `inline-style`, `image`, `form-action`, `noscript`, `camera`,
//! `microphone`, `geolocation`, `payment`, `usb`, `display-capture`).

use serde::{Deserialize, Serialize};

/// Capabilities a preset allows. Page-level ones apply to the document; the two source lists
/// apply to first-party (same registrable domain) and third-party sources.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PolicyProfileDto {
    pub page: Vec<String>,
    pub first_party: Vec<String>,
    pub third_party: Vec<String>,
}

/// A preset: `default`, `trusted`, `untrusted` or `custom` (with `profile`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PresetDto {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<PolicyProfileDto>,
}

/// Global policy settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PolicySettingsDto {
    /// Master switch; nothing is enforced while false.
    pub enabled: bool,
    /// Preset for sites without a rule.
    pub global: PresetDto,
    /// What the `default` preset means.
    pub default_profile: PolicyProfileDto,
    /// Remove blocked `<script>` elements from HTML (saves the download).
    pub strip_blocked_scripts: bool,
    /// Remove `<meta http-equiv="refresh">` from pages whose scripts are blocked.
    pub strip_meta_refresh: bool,
    /// Let the proxy block denied third-party subresources early.
    pub network_hints: bool,
}

/// Settings plus the change counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PolicySettingsResponse {
    pub settings: PolicySettingsDto,
    /// Bumped on every policy change (and when a temporary grant expires).
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct SiteRuleDto {
    pub id: String,
    pub scope: String,
    pub preset: PresetDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Unix seconds of the last create or change (0: unknown).
    #[serde(default)]
    pub updated_at: u64,
}

/// Site rules per mode, for the current search text.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct SiteRuleCounts {
    pub all: usize,
    pub trusted: usize,
    pub default: usize,
    pub untrusted: usize,
    pub custom: usize,
    /// First characters (`A`-`Z`, `#`) present among the rows matching the current filters.
    #[serde(default)]
    pub letters: Vec<String>,
}

/// A page of site rules plus per-mode counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct SiteRulesPage {
    pub items: Vec<SiteRuleDto>,
    /// Pass as `cursor` for the next page; `null` on the last page.
    pub next_cursor: Option<String>,
    /// Rules matching `q` and `mode`, across all pages.
    pub total: usize,
    pub counts: SiteRuleCounts,
    pub limit: u32,
    pub has_more: bool,
    /// Echoed only when the deprecated `page` parameter was used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
}

/// Create a site rule (also the export form).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct SiteRuleInput {
    pub scope: String,
    pub preset: PresetDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct SiteRuleUpdate {
    pub preset: PresetDto,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct SourceRuleDto {
    pub id: String,
    /// Page scope the rule applies on.
    pub page: String,
    /// Source scope (`*`, `site:...`, `host:...`, `https://host`).
    pub source: String,
    pub caps: Vec<String>,
    /// `allow` or `deny`.
    pub effect: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Create a source rule (also the export form).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct SourceRuleInput {
    pub page: String,
    pub source: String,
    /// Source-keyed capabilities only.
    pub caps: Vec<String>,
    pub effect: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct SourceRuleUpdate {
    pub caps: Vec<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct TempGrantDto {
    pub id: String,
    pub page: String,
    /// `site` (the page uses `preset`) or `source` (allow `caps` from `source`).
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<PresetDto>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default)]
    pub caps: Vec<String>,
    /// Unix seconds; absent for until-restart grants.
    pub expires_at: Option<u64>,
    pub remaining_secs: Option<u64>,
    pub until_restart: bool,
    pub persist: bool,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct TempGrantInput {
    pub page: String,
    /// `site` or `source`.
    pub kind: String,
    #[serde(default)]
    pub preset: Option<PresetDto>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub caps: Vec<String>,
    /// Seconds until expiry.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// Keep in memory only; dropped on restart.
    #[serde(default)]
    pub until_restart: bool,
    /// Survive a restart (needs `ttl_secs`).
    #[serde(default)]
    pub persist: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct CspDirectiveDto {
    pub name: String,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct HtmlRuleDto {
    pub selector: String,
    /// `unwrap`, `remove` or `remove-attribute:<name>`.
    pub op: String,
    /// `always` or `url-denied:<attr>:<capability>`.
    pub when: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct HtmlActionsDto {
    pub unwrap_noscript: bool,
    pub strip_scripts: bool,
    pub rules: Vec<HtmlRuleDto>,
}

/// What the policy does to one page URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct ExplainResponse {
    pub url: String,
    pub host: String,
    /// Registrable domain (or the host itself when it has none).
    pub site: String,
    /// False when the master switch is off.
    pub enabled: bool,
    pub matched_site_rules: Vec<SiteRuleDto>,
    pub matched_source_rules: Vec<SourceRuleDto>,
    pub active_temps: Vec<TempGrantDto>,
    /// The base profile in effect before source rules.
    pub effective: PolicyProfileDto,
    pub csp: Vec<CspDirectiveDto>,
    /// The extra `Content-Security-Policy` header value (proxy nonce shown as `PROXY_NONCE`).
    pub csp_header: Option<String>,
    pub permissions_policy: Option<String>,
    pub html_actions: HtmlActionsDto,
    /// Capabilities the proxy can block early for this page.
    pub network_enforce: Vec<String>,
    /// Denials CSP cannot express for this page.
    pub notes: Vec<String>,
    pub generation: u64,
}

/// A proposed change, evaluated without saving.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PreviewRequest {
    pub url: String,
    #[serde(default)]
    pub add_site_rule: Option<SiteRuleInput>,
    #[serde(default)]
    pub add_source_rule: Option<SourceRuleInput>,
    #[serde(default)]
    pub add_temp: Option<TempGrantInput>,
    /// Ids of site rules, source rules or temporary grants to drop.
    #[serde(default)]
    pub remove_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PreviewResponse {
    pub before: ExplainResponse,
    pub after: ExplainResponse,
    pub changed: bool,
    /// Rendered CSP directives only in `after`.
    pub csp_added: Vec<String>,
    /// Rendered CSP directives only in `before`.
    pub csp_removed: Vec<String>,
}

/// Portable policy document (temporary grants are not exported).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PolicyExportDto {
    pub version: u32,
    pub settings: PolicySettingsDto,
    pub site_rules: Vec<SiteRuleInput>,
    pub source_rules: Vec<SourceRuleInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PolicyImportRequest {
    /// `replace` (discard existing rules and settings) or `merge`.
    pub mode: String,
    pub document: PolicyExportDto,
}

/// The one-click allow for a blocked item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct SuggestedAllowDto {
    pub source: String,
    pub caps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct BlockedItemDto {
    pub capability: String,
    /// Host of the blocked source; absent for inline/eval/data:/blob:.
    pub source: Option<String>,
    pub count: u32,
    pub first_seen: u64,
    pub last_seen: u64,
    pub via_network: bool,
    pub via_csp: bool,
    pub sample: Option<String>,
    pub suggested_allow: Option<SuggestedAllowDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PolicyReportDto {
    pub page: String,
    pub items: Vec<BlockedItemDto>,
    /// Distinct items discarded by the per-page bound.
    pub dropped: u32,
    pub events: u64,
    pub last_seen: u64,
}

/// How the panel's confirmation page authenticates a change: `pin` (default), `session` (the panel
/// only links to the dashboard) or `none` (a click is enough; trusted LAN only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PanelSettingsDto {
    /// Offer the in-page panel on pages of this profile (off by default).
    pub enabled: bool,
    /// Corner button for userscript menu commands: `off`, `on_demand` (default; only when a script
    /// registered a command) or `always`. Independent of `enabled`.
    #[serde(default)]
    pub menu_button: String,
    /// Hotkey, for example `Alt+Shift+A`.
    pub hotkey: String,
    /// `pin`, `session` or `none`.
    pub auth: String,
    /// Whether a PIN is set (the PIN itself is never returned).
    pub pin_set: bool,
    /// The deployment switch `script_control.panel_enabled` is separate; this is per profile.
    #[serde(default)]
    pub reserved_host: String,
}

/// Change panel settings. Omitted fields keep their value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct PanelSettingsInput {
    pub enabled: Option<bool>,
    /// `off`, `on_demand` or `always`.
    #[serde(default)]
    pub menu_button: Option<String>,
    pub hotkey: Option<String>,
    pub auth: Option<String>,
    /// Set a new PIN (4 to 64 characters).
    pub pin: Option<String>,
    /// Remove the PIN.
    #[serde(default)]
    pub clear_pin: bool,
}

/// Sites for which ad blocking is switched off (document exceptions in the custom rules).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "server", derive(utoipa::ToSchema))]
pub struct SiteExceptionsResponse {
    pub sites: Vec<String>,
}

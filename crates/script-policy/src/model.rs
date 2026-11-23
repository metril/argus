//! The editable rule model: presets, site rules, source rules, temporary grants, settings.

use crate::caps::{CapSet, Profile};
use crate::scope::{site_of, Scheme, Scope};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A named capability profile. `Default` resolves to [`Settings::default_profile`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Preset {
    Default,
    Trusted,
    Untrusted,
    Custom { profile: Profile },
}

impl Preset {
    pub fn resolve(&self, settings: &Settings) -> Profile {
        match self {
            Preset::Default => settings.default_profile,
            Preset::Trusted => Profile::TRUSTED,
            Preset::Untrusted => Profile::UNTRUSTED,
            Preset::Custom { profile } => *profile,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Preset::Default => "default",
            Preset::Trusted => "trusted",
            Preset::Untrusted => "untrusted",
            Preset::Custom { .. } => "custom",
        }
    }
}

/// Allow or deny.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

/// "Pages in `scope` use this preset."
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteRule {
    pub id: String,
    pub scope: Scope,
    pub preset: Preset,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Unix seconds of the last create or change (0: unknown, e.g. imported).
    #[serde(default)]
    pub updated_at: u64,
}

/// One cell of the matrix: on pages in `page`, sources in `source` are allowed/denied `caps`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRule {
    pub id: String,
    pub page: Scope,
    pub source: Scope,
    /// Source-keyed capabilities only.
    pub caps: CapSet,
    pub effect: Effect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// What a temporary grant does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GrantKind {
    /// Pages use this preset (usually `Trusted`).
    Site { preset: Preset },
    /// Allow `caps` from `source` on these pages.
    Source { source: Scope, caps: CapSet },
}

/// A NoScript-style temporary permission. Outranks a permanent rule of the same specificity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempGrant {
    pub id: String,
    pub page: Scope,
    pub kind: GrantKind,
    /// Unix seconds; the grant is inactive at and after this instant.
    pub expires_at: Option<u64>,
    /// Dropped on restart (never persisted).
    pub until_restart: bool,
    /// Survive a restart (only meaningful with `expires_at`).
    pub persist: bool,
    pub created_at: u64,
}

impl TempGrant {
    pub fn active_at(&self, now: u64) -> bool {
        self.expires_at.is_none_or(|e| now < e)
    }
}

/// Global switches and the shipped/configurable default profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Master switch; when false no policy is applied anywhere.
    pub enabled: bool,
    /// Preset for sites with no rule.
    pub global: Preset,
    /// What the `Default` preset means (ships as [`Profile::SHIPPED_DEFAULT`]).
    pub default_profile: Profile,
    /// HTML "strip" mode: remove blocked `<script>` elements so they are never downloaded.
    pub strip_blocked_scripts: bool,
    /// Remove `<meta http-equiv="refresh">` from pages whose scripts are blocked.
    pub strip_meta_refresh: bool,
    /// Let the request path block denied third-party subresources early.
    pub network_hints: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            enabled: false,
            global: Preset::Default,
            default_profile: Profile::SHIPPED_DEFAULT,
            strip_blocked_scripts: false,
            strip_meta_refresh: false,
            network_hints: true,
        }
    }
}

/// Validation failure for a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError(pub String);
impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for RuleError {}

/// All editable policy state of one profile.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleSet {
    pub settings: Settings,
    pub site_rules: BTreeMap<String, SiteRule>,
    pub source_rules: BTreeMap<String, SourceRule>,
    pub temps: BTreeMap<String, TempGrant>,
}

impl SiteRule {
    pub fn validate(&self) -> Result<(), RuleError> {
        if self.scope == Scope::Global {
            return Err(RuleError(
                "a site rule needs a site, host or host+scheme scope (change the global default in the settings)".into(),
            ));
        }
        Ok(())
    }
}

impl SourceRule {
    pub fn validate(&self) -> Result<(), RuleError> {
        validate_source_caps(self.caps)
    }
}

fn validate_source_caps(caps: CapSet) -> Result<(), RuleError> {
    if caps.is_empty() {
        return Err(RuleError("no capabilities selected".into()));
    }
    if !caps.minus(CapSet::SOURCE_KEYED).is_empty() {
        return Err(RuleError(
            "source rules only take source-keyed capabilities (script, object, media, frame, font, connect, ping, worker, style, image, form-action); use a custom preset for page-level ones".into(),
        ));
    }
    Ok(())
}

impl TempGrant {
    pub fn validate(&self) -> Result<(), RuleError> {
        if self.expires_at.is_none() && !self.until_restart {
            return Err(RuleError(
                "a temporary grant needs an expiry or until_restart".into(),
            ));
        }
        if self.until_restart && self.persist {
            return Err(RuleError("until_restart grants cannot be persisted".into()));
        }
        if let GrantKind::Source { caps, .. } = &self.kind {
            validate_source_caps(*caps)?;
        }
        Ok(())
    }
}

impl RuleSet {
    pub fn site_rule_for_scope(&self, scope: &Scope) -> Option<&SiteRule> {
        self.site_rules.values().find(|r| &r.scope == scope)
    }

    pub fn source_rule_for(
        &self,
        page: &Scope,
        source: &Scope,
        effect: Effect,
    ) -> Option<&SourceRule> {
        self.source_rules
            .values()
            .find(|r| &r.page == page && &r.source == source && r.effect == effect)
    }

    /// Drop temporary grants that are no longer active.
    pub fn prune_temps(&mut self, now: u64) {
        self.temps.retain(|_, t| t.active_at(now));
    }
}

/// The rules that apply to a page, for "explain".
#[derive(Debug, Default)]
pub struct Matched<'a> {
    pub site_rules: Vec<&'a SiteRule>,
    pub source_rules: Vec<&'a SourceRule>,
    pub temps: Vec<&'a TempGrant>,
}

impl RuleSet {
    /// Rules whose page scope matches `(scheme, host)`; temporary grants only if active at `now`.
    pub fn matching(&self, scheme: Option<Scheme>, host: &str, now: u64) -> Matched<'_> {
        let site = site_of(host);
        Matched {
            site_rules: self
                .site_rules
                .values()
                .filter(|r| r.scope.matches(scheme, host, site))
                .collect(),
            source_rules: self
                .source_rules
                .values()
                .filter(|r| r.page.matches(scheme, host, site))
                .collect(),
            temps: self
                .temps
                .values()
                .filter(|t| t.active_at(now) && t.page.matches(scheme, host, site))
                .collect(),
        }
    }
}

/// JSON export/import document.
pub const EXPORT_VERSION: u32 = 1;

/// Portable form of a profile's rules (ids are regenerated on import; temporary grants are not
/// exported).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyExport {
    pub version: u32,
    pub settings: Settings,
    pub site_rules: Vec<ExportedSiteRule>,
    pub source_rules: Vec<ExportedSourceRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedSiteRule {
    pub scope: Scope,
    pub preset: Preset,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedSourceRule {
    pub page: Scope,
    pub source: Scope,
    pub caps: CapSet,
    pub effect: Effect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl RuleSet {
    pub fn export(&self) -> PolicyExport {
        let mut site_rules: Vec<_> = self
            .site_rules
            .values()
            .map(|r| ExportedSiteRule {
                scope: r.scope.clone(),
                preset: r.preset,
                note: r.note.clone(),
            })
            .collect();
        site_rules.sort_by(|a, b| a.scope.cmp(&b.scope));
        let mut source_rules: Vec<_> = self
            .source_rules
            .values()
            .map(|r| ExportedSourceRule {
                page: r.page.clone(),
                source: r.source.clone(),
                caps: r.caps,
                effect: r.effect,
                note: r.note.clone(),
            })
            .collect();
        source_rules.sort_by(|a, b| {
            (&a.page, &a.source, a.effect as u8).cmp(&(&b.page, &b.source, b.effect as u8))
        });
        PolicyExport {
            version: EXPORT_VERSION,
            settings: self.settings.clone(),
            site_rules,
            source_rules,
        }
    }

    /// Apply an export. `replace` discards existing rules and settings first; otherwise rules
    /// with the same key (scope / page+source+effect) are overwritten and settings are kept.
    /// `new_id` supplies fresh rule ids.
    pub fn import(
        &mut self,
        doc: PolicyExport,
        replace: bool,
        mut new_id: impl FnMut() -> String,
    ) -> Result<(), RuleError> {
        if doc.version != EXPORT_VERSION {
            return Err(RuleError(format!(
                "unsupported export version {} (expected {EXPORT_VERSION})",
                doc.version
            )));
        }
        // Validate everything before touching state.
        for r in &doc.site_rules {
            SiteRule {
                id: String::new(),
                scope: r.scope.clone(),
                preset: r.preset,
                note: None,
                updated_at: 0,
            }
            .validate()?;
        }
        for r in &doc.source_rules {
            validate_source_caps(r.caps)?;
        }
        if replace {
            self.settings = doc.settings;
            self.site_rules.clear();
            self.source_rules.clear();
        }
        for r in doc.site_rules {
            let id = self
                .site_rule_for_scope(&r.scope)
                .map(|e| e.id.clone())
                .unwrap_or_else(&mut new_id);
            self.site_rules.insert(
                id.clone(),
                SiteRule {
                    id,
                    scope: r.scope,
                    preset: r.preset,
                    note: r.note,
                    updated_at: 0,
                },
            );
        }
        for r in doc.source_rules {
            let id = self
                .source_rule_for(&r.page, &r.source, r.effect)
                .map(|e| e.id.clone())
                .unwrap_or_else(&mut new_id);
            self.source_rules.insert(
                id.clone(),
                SourceRule {
                    id,
                    page: r.page,
                    source: r.source,
                    caps: r.caps,
                    effect: r.effect,
                    note: r.note,
                },
            );
        }
        Ok(())
    }
}

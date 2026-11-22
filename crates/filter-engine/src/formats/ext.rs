//! Extended (AdGuard / uBO) rules that adblock-rust cannot express.
//!
//! These are not dropped: conversion and compilation divert them into a structured side list
//! ([`ExtRule`]) that a later phase (page rewriting, response-header rules, ...) implements.

use serde::{Deserialize, Serialize};

use super::abp;

/// What an unsupported rule asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExtKind {
    /// `$replace=/re/sub/` response body rewriting.
    Replace,
    /// `$jsonprune=` JSON response pruning.
    JsonPrune,
    /// `$xmlprune=` XML response pruning.
    XmlPrune,
    /// `$cookie` cookie removal / modification.
    Cookie,
    /// `$removeheader=` response header removal.
    RemoveHeader,
    /// `$hls=` HLS playlist pruning.
    Hls,
    /// `$permissions=` Permissions-Policy injection.
    Permissions,
    /// `$urltransform=` URL rewriting.
    UrlTransform,
    /// `$method=` request-method restricted rule.
    Method,
    /// `$popup` (needs window-opener context).
    Popup,
    /// `$to=` with a non-trivial pattern.
    To,
    /// `$denyallow`: no exact native translation exists (an exception would also unblock the
    /// hosts for unrelated rules), so every such rule is handed off.
    DenyAllow,
    /// HTML filters (`##^`, `$$`).
    HtmlFilter,
    /// AdGuard `#%#` JavaScript rules.
    JsInject,
    /// ABP snippets (`#$#name args`).
    Snippet,
    /// Scriptlet with no known uBO equivalent.
    Scriptlet,
    /// AdGuard extended CSS the engine rejected.
    ExtendedCss,
    /// A network modifier the engine does not know (`$network`, `$stealth`, `$referrerpolicy`, ...).
    UnsupportedOption,
    Other,
}

impl ExtKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Replace => "replace",
            Self::JsonPrune => "jsonprune",
            Self::XmlPrune => "xmlprune",
            Self::Cookie => "cookie",
            Self::RemoveHeader => "removeheader",
            Self::Hls => "hls",
            Self::Permissions => "permissions",
            Self::UrlTransform => "urltransform",
            Self::Method => "method",
            Self::Popup => "popup",
            Self::To => "to",
            Self::DenyAllow => "denyallow",
            Self::HtmlFilter => "html-filter",
            Self::JsInject => "js-inject",
            Self::Snippet => "snippet",
            Self::Scriptlet => "scriptlet",
            Self::ExtendedCss => "extended-css",
            Self::UnsupportedOption => "unsupported-option",
            Self::Other => "other",
        }
    }
}

/// One rule handed off for later implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtRule {
    pub kind: ExtKind,
    /// The rule exactly as written (after allowlist conversion, if any).
    pub raw: String,
    /// Domains the rule is restricted to: cosmetic domain list, or `$domain=`/`$from=` values
    /// (a leading `~` marks a negated domain).
    pub domains: Vec<String>,
}

impl ExtRule {
    pub fn new(kind: ExtKind, raw: &str) -> Self {
        Self {
            kind,
            raw: raw.to_string(),
            domains: abp::rule_domains(raw),
        }
    }
}

/// Classify a rule adblock-rust rejected. Returns `None` for plain garbage (counted as an error
/// by the caller rather than handed off).
pub fn classify_rejected(raw: &str) -> Option<ExtRule> {
    let raw = raw.trim();
    if let Some(c) = abp::split_cosmetic(raw) {
        let kind = if c.sep.contains('?') {
            ExtKind::ExtendedCss
        } else {
            ExtKind::Other
        };
        return Some(ExtRule::new(kind, raw));
    }
    let (_, opts) = abp::split_options(raw);
    opts.map(|_| ExtRule::new(ExtKind::UnsupportedOption, raw))
}

/// AdGuard scriptlet name -> uBO scriptlet name. Names equal in both are listed with themselves.
const ALIASES: &[(&str, &str)] = &[
    ("abort-current-inline-script", "abort-current-script"),
    ("abort-on-property-read", "abort-on-property-read"),
    ("abort-on-property-write", "abort-on-property-write"),
    ("abort-on-stack-trace", "abort-on-stack-trace"),
    ("adjust-setInterval", "nano-setInterval-booster"),
    ("adjust-setTimeout", "nano-setTimeout-booster"),
    ("close-window", "close-window"),
    ("disable-newtab-links", "disable-newtab-links"),
    ("json-prune", "json-prune"),
    ("log-addEventListener", "addEventListener-logger"),
    ("log-eval", "log-eval"),
    ("log-on-stack-trace", "log-on-stack-trace"),
    ("m3u-prune", "m3u-prune"),
    ("no-topics", "no-topics"),
    ("nowebrtc", "nowebrtc"),
    ("prevent-addEventListener", "addEventListener-defuser"),
    ("prevent-eval-if", "noeval-if"),
    ("prevent-fetch", "no-fetch-if"),
    ("prevent-refresh", "refresh-defuser"),
    (
        "prevent-requestAnimationFrame",
        "no-requestAnimationFrame-if",
    ),
    ("prevent-setInterval", "no-setInterval-if"),
    ("prevent-setTimeout", "no-setTimeout-if"),
    ("prevent-window-open", "window.open-defuser"),
    ("prevent-xhr", "no-xhr-if"),
    ("remove-attr", "remove-attr"),
    ("remove-class", "remove-class"),
    ("remove-cookie", "cookie-remover"),
    ("remove-node-text", "remove-node-text"),
    ("set-attr", "set-attr"),
    ("set-constant", "set-constant"),
    ("set-cookie", "set-cookie"),
    ("set-cookie-reload", "set-cookie-reload"),
    ("set-local-storage-item", "set-local-storage-item"),
    ("set-session-storage-item", "set-session-storage-item"),
    ("spoof-css", "spoof-css"),
    ("trusted-click-element", "trusted-click-element"),
    (
        "trusted-replace-fetch-response",
        "trusted-replace-fetch-response",
    ),
    (
        "trusted-replace-xhr-response",
        "trusted-replace-xhr-response",
    ),
    ("trusted-set-cookie", "trusted-set-cookie"),
    (
        "trusted-set-local-storage-item",
        "trusted-set-local-storage-item",
    ),
    ("xml-prune", "xml-prune"),
];

/// The AdGuard -> uBO scriptlet alias table (also used by tests and diagnostics).
pub fn scriptlet_alias_table() -> &'static [(&'static str, &'static str)] {
    ALIASES
}

pub(crate) fn ubo_scriptlet_name(adguard: &str) -> Option<&'static str> {
    let n = adguard.trim_end_matches(".js");
    ALIASES.iter().find(|(a, _)| *a == n).map(|(_, u)| *u)
}

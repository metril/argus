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
    /// `$header=` response-header match.
    Header,
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
            Self::Header => "header",
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
    /// Id of the list the rule came from (set by the build pipeline; empty when unknown).
    #[serde(default)]
    pub list: String,
    /// Whether the source list is trusted to run code in pages (`$replace`, `#%#`, ...). Set by
    /// the consumer; the build pipeline leaves it `false`.
    #[serde(default)]
    pub trusted: bool,
}

impl ExtRule {
    pub fn new(kind: ExtKind, raw: &str) -> Self {
        Self {
            kind,
            raw: raw.to_string(),
            domains: abp::rule_domains(raw),
            list: String::new(),
            trusted: false,
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
    ("evaldata-prune", "evaldata-prune"),
    ("href-sanitizer", "href-sanitizer"),
    ("json-prune", "json-prune"),
    ("json-prune-fetch-response", "json-prune-fetch-response"),
    ("json-prune-xhr-response", "json-prune-xhr-response"),
    ("log-addEventListener", "addEventListener-logger"),
    ("log-eval", "log-eval"),
    ("log-on-stack-trace", "log-on-stack-trace"),
    ("m3u-prune", "m3u-prune"),
    ("no-topics", "no-topics"),
    ("nowebrtc", "nowebrtc"),
    ("prevent-addEventListener", "addEventListener-defuser"),
    ("prevent-bab", "prevent-bab"),
    ("prevent-canvas", "prevent-canvas"),
    ("prevent-clipboard-write", "prevent-clipboard-write"),
    ("prevent-eval-if", "noeval-if"),
    ("prevent-innerHTML", "prevent-innerHTML"),
    ("prevent-navigation", "prevent-navigation"),
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
    ("trusted-json-edit", "trusted-json-edit"),
    (
        "trusted-json-edit-fetch-response",
        "trusted-json-edit-fetch-response",
    ),
    (
        "trusted-json-edit-xhr-response",
        "trusted-json-edit-xhr-response",
    ),
    (
        "trusted-prune-inbound-object",
        "trusted-prune-inbound-object",
    ),
    ("trusted-replace-argument", "trusted-replace-argument"),
    ("trusted-replace-node-text", "trusted-replace-node-text"),
    (
        "trusted-replace-outbound-text",
        "trusted-replace-outbound-text",
    ),
    (
        "trusted-replace-fetch-response",
        "trusted-replace-fetch-response",
    ),
    (
        "trusted-replace-xhr-response",
        "trusted-replace-xhr-response",
    ),
    ("trusted-set-attr", "trusted-set-attr"),
    ("trusted-set-constant", "trusted-set-constant"),
    ("trusted-set-cookie", "trusted-set-cookie"),
    ("trusted-set-cookie-reload", "trusted-set-cookie-reload"),
    (
        "trusted-set-local-storage-item",
        "trusted-set-local-storage-item",
    ),
    (
        "trusted-set-session-storage-item",
        "trusted-set-session-storage-item",
    ),
    (
        "trusted-suppress-native-method",
        "trusted-suppress-native-method",
    ),
    ("xml-prune", "xml-prune"),
];

/// The AdGuard -> uBO scriptlet alias table (also used by tests and diagnostics).
pub fn scriptlet_alias_table() -> &'static [(&'static str, &'static str)] {
    ALIASES
}

/// uBO scriptlet name for an AdGuard one. `ubo-<name>[.js]` is AdGuard's compatibility prefix
/// for uBO's own names and goes through unprefixed. `None` for AdGuard scriptlets uBO has no
/// equivalent of: the page runtime (`assets/natives.js`) implements those.
pub(crate) fn ubo_scriptlet_name(adguard: &str) -> Option<std::borrow::Cow<'static, str>> {
    let n = adguard.trim().trim_end_matches(".js");
    if let Some(u) = n.strip_prefix("ubo-").filter(|u| !u.is_empty()) {
        return Some(std::borrow::Cow::Owned(u.to_string()));
    }
    ALIASES
        .iter()
        .find(|(a, _)| *a == n)
        .map(|(_, u)| std::borrow::Cow::Borrowed(*u))
}

//! Pure evaluation of the extended (uBO / AdGuard) filter rules the network engine cannot run.
//!
//! `filter-engine` hands such rules off as [`filter_engine::ExtRule`]. This crate parses them into
//! typed rules ([`parse_rule`]), indexes them ([`ExtIndex`]) and evaluates them over plain data:
//! [`ExtIndex::request_decision`] before a request is sent, [`ExtIndex::response_plan`] once per
//! response. No I/O, no async, no HTTP types: callers adapt their own request / response types to
//! [`RequestInfo`] / [`ResponseInfo`] and apply the returned [`HeaderEdit`]s, [`BodyTransform`]s,
//! [`HtmlRemoval`]s and [`Injection`]s.
//!
//! # Trust
//! `$replace`, `$urltransform`, `#%#` scripts, unknown scriptlets and snippets let a list author
//! run code in every page or rewrite content arbitrarily. They are dropped at build time unless the
//! rule's list is trusted ([`ExtRule::trusted`] or [`BuildOptions::trusted_lists`]); drops are
//! counted per list in [`ExtStats`]. Exceptions never need trust.
//!
//! # Not detectable here
//! `$popup`: request headers carry no opener information, so [`RequestInfo::opened_as_popup`] must
//! be supplied by the caller; it is `false` by default and `$popup` rules are then inert.

mod cookie;
mod headers;
mod hls;
mod index;
mod jsonprune;
mod parse;
mod pattern;
mod permissions;
/// Merge `Permissions-Policy` headers restrictively (never widening the site's own).
pub use permissions::merge as merge_permissions_policy;
mod removeparam;
mod replace;
pub mod stealth;
mod style;
mod types;
mod util;
mod xmlprune;

pub use cookie::{
    apply_set_cookie, filter_request_cookie, CookieName, CookieSpec, SameSite, SetCookie,
};
pub use filter_engine::formats::{ExtKind, ExtRule};
pub use headers::{is_removable_header, HeaderEdit};
pub use hls::{apply_hls, HlsPrune, MAX_HLS_BYTES};
pub use index::{BuildOptions, ExtIndex, ExtStats, KindStats, RuleIssue, RuleState};
pub use jsonprune::{apply_jsonprune, JsonPrune, MAX_JSON_BYTES};
pub use parse::{
    parse_rule, target, Action, HeaderMatch, HtmlRemoval, Injection, ParsedRule, RuleError,
    TextPred, DEFAULT_MAX_ELEMENT_LEN,
};
pub use removeparam::{apply as apply_removeparam, restore_exempt, RemoveParam};
pub use replace::{apply_replace, is_textual_content_type, ReplaceSpec, MAX_REPLACE_BYTES};
pub use style::is_safe_style;
pub use types::{
    BodyTransform, RequestDecision, RequestInfo, ResourceType, ResponseInfo, ResponsePlan, RuleId,
};
pub use xmlprune::{apply_xmlprune, XmlPrune, MAX_XML_BYTES};

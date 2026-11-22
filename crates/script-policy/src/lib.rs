//! NoScript-style script policy, pure (no I/O, no async).
//!
//! * [`RuleSet`] is the editable model (presets, site rules, source rules, temporary grants).
//! * [`CompiledPolicy`] is its immutable, `Send + Sync` compiled form; [`CompiledPolicy::decide`]
//!   resolves a document to a [`PagePolicy`] without allocating.
//! * [`PagePolicy`] yields the extra CSP / Permissions-Policy, the HTML rewriter's instructions
//!   and the early network checks.
//! * [`ReportAggregator`] collects "what was blocked" per page.
//!
//! With the `store` feature, [`store::PolicyStore`] persists rules in redb.
//! See `docs/SCRIPT-POLICY.md` for what CSP can and cannot express.

pub mod caps;
pub mod compile;
pub mod csp;
pub mod hints;
pub mod html;
pub mod model;
pub mod report;
pub mod scope;
#[cfg(feature = "store")]
pub mod store;

pub use caps::{CapSet, Capability, Profile};
pub use compile::{CompiledPolicy, PagePolicy, Source};
pub use csp::{render_header, CspDirective, CspOutput, ProxyInject};
pub use hints::{
    FetchDest, HintVerdict, NetworkHints, PageContext, SubRequest, UnknownReason,
    DEFAULT_ENFORCEABLE,
};
pub use html::{HtmlActions, HtmlOp, HtmlRule, HtmlWhen};
pub use model::{
    Effect, GrantKind, Matched, PolicyExport, Preset, RuleError, RuleSet, Settings, SiteRule,
    SourceRule, TempGrant, EXPORT_VERSION,
};
pub use report::{
    BlockEvent, BlockedItem, CspViolation, PageReport, ReportAggregator, ReportLimits, Via,
};
pub use scope::{is_ip, normalize_host, parse_origin, site_of, Scheme, Scope, ScopeError};

/// The profile id callers use until profiles exist.
pub const DEFAULT_PROFILE: &str = "default";

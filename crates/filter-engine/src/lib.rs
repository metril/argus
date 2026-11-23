//! Adblocking filter engine with AdBlock Plus and AdGuard syntax support
//!
//! This module provides comprehensive adblocking capabilities using Brave's adblock-rust
//! engine as the foundation, with extensions for AdGuard-specific syntax.

/// Version of the adblock-rust crate whose engine serialization is persisted (part of the
/// persisted-engine cache key; a test checks it against `Cargo.lock`).
pub const ADBLOCK_CRATE_VERSION: &str = "0.12.5";

pub mod bundled;
pub mod compile;
pub mod domainset;
pub mod error;
pub mod events;
pub mod formats;
pub mod list;
pub mod matcher;
pub mod pipeline;
pub(crate) mod precheck;
pub mod reaper;
pub mod redirect_resources;
pub mod scriptlet_resources;
pub mod shared;
pub mod stats;

pub use arc_swap::{self, ArcSwap};
pub use bundled::{BUNDLED_AVAILABLE, BUNDLED_RESOURCES_COMMIT, BUNDLED_RESOURCES_JSON};
pub use compile::{
    compile_lists, compile_lists_with, route_domain_rules, Compiled, DomainRouted, ListCompileStats,
};
pub use domainset::{DomainHit, DomainSet, DomainSetBuilder, Scheme};
pub use error::{Error, Result};
pub use events::{
    BlockLog, ErrorKind, EventAction, EventMode, EventRef, LiveEvent, RequestEvent, RequestLog,
};
pub use formats::{
    convert, detect, ConvertOptions, ConvertStats, Converted, ExtKind, ExtRule, IpRange, IpSet,
    ListFormat, ListMeta,
};
pub use list::{catalogue, default_filter_lists, CatalogueEntry, FilterList};
pub use matcher::{MatchResult, RedirectResource, RequestMatcher};
pub use pipeline::{build_set, BuiltSet, ListInput, ListReport, ReportIssue};
pub use redirect_resources::builtin_redirect_resources;
pub use scriptlet_resources::{
    convert_ubo_scriptlets, convert_ubo_sources, ubo_scriptlets_to_json, ubo_sources_to_json,
    validate_resources, DroppedResource, ScriptletConversion, Validated, TRUSTED_PERMISSION,
};
pub use shared::{
    build_engine, compile_engine, overlay_from_rules, overlay_from_rules_shared, try_build_engine,
    Cosmetics, Generation, IpFilter, Query, ResourceReport, SharedEngine,
};
pub use stats::{BlockingStats, FilterStats};

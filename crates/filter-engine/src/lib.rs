//! Adblocking filter engine with AdBlock Plus and AdGuard syntax support
//!
//! This module provides comprehensive adblocking capabilities using Brave's adblock-rust
//! engine as the foundation, with extensions for AdGuard-specific syntax.

/// Version of the adblock-rust crate whose engine serialization is persisted (part of the
/// persisted-engine cache key; a test checks it against `Cargo.lock`).
pub const ADBLOCK_CRATE_VERSION: &str = "0.12.5";

pub mod bundled;
pub mod compile;
pub mod error;
pub mod formats;
pub mod list;
pub mod matcher;
pub mod pipeline;
pub mod redirect_resources;
pub mod scriptlet_resources;
pub mod shared;
pub mod stats;

pub use arc_swap::{self, ArcSwap};
pub use bundled::{BUNDLED_RESOURCES_COMMIT, BUNDLED_RESOURCES_JSON};
pub use compile::{compile_lists, Compiled, ListCompileStats};
pub use error::{Error, Result};
pub use formats::{
    convert, detect, ConvertOptions, ConvertStats, Converted, ExtKind, ExtRule, IpRange, IpSet,
    ListFormat, ListMeta,
};
pub use list::{catalogue, default_filter_lists, CatalogueEntry, FilterList};
pub use matcher::{MatchResult, RedirectResource, RequestMatcher};
pub use pipeline::{build_set, BuiltSet, ListInput, ListReport, ReportIssue};
pub use redirect_resources::builtin_redirect_resources;
pub use scriptlet_resources::{convert_ubo_scriptlets, ubo_scriptlets_to_json};
pub use shared::{
    build_engine, compile_engine, try_build_engine, Cosmetics, IpFilter, SharedEngine,
};
pub use stats::{BlockingStats, FilterStats};

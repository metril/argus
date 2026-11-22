//! Adblocking filter engine with AdBlock Plus and AdGuard syntax support
//!
//! This module provides comprehensive adblocking capabilities using Brave's adblock-rust
//! engine as the foundation, with extensions for AdGuard-specific syntax.

pub mod compile;
pub mod error;
pub mod formats;
pub mod list;
pub mod matcher;
pub mod redirect_resources;
pub mod scriptlet_resources;
pub mod shared;
pub mod stats;

pub use arc_swap::{self, ArcSwap};
pub use compile::{compile_lists, Compiled, ListCompileStats};
pub use error::{Error, Result};
pub use formats::{
    convert, detect, ConvertOptions, ConvertStats, Converted, ExtKind, ExtRule, IpRange, IpSet,
    ListFormat, ListMeta,
};
pub use list::{catalogue, default_filter_lists, CatalogueEntry, FilterList};
pub use matcher::{MatchResult, RedirectResource, RequestMatcher};
pub use redirect_resources::builtin_redirect_resources;
pub use scriptlet_resources::{convert_ubo_scriptlets, ubo_scriptlets_to_json};
pub use shared::{build_engine, compile_engine, Cosmetics, IpFilter, SharedEngine};
pub use stats::{BlockingStats, FilterStats};

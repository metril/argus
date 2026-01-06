//! Adblocking filter engine with AdBlock Plus and AdGuard syntax support
//!
//! This module provides comprehensive adblocking capabilities using Brave's adblock-rust
//! engine as the foundation, with extensions for AdGuard-specific syntax.

pub mod cosmetic;
pub mod engine;
pub mod error;
pub mod list;
pub mod matcher;
pub mod modifiers;
pub mod scriptlets;
pub mod stats;
pub mod update;

pub use cosmetic::{CosmeticFilterManager, CosmeticRule, CosmeticRuleType};
pub use engine::FilterEngine;
pub use error::{Error, Result};
pub use list::{FilterList, FilterListManager};
pub use matcher::{MatchResult, RequestMatcher};
pub use modifiers::{RemoveHeaderModifier, RemoveParamModifier, ReplaceModifier};
pub use scriptlets::{ScriptletManager, ScriptletRule};
pub use stats::{BlockingStats, FilterStats};
pub use update::{
    ListUpdateStats, UpdateAttempt, UpdateConfig, UpdateScheduler, UpdateStats,
};

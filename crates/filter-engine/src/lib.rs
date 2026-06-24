//! Adblocking filter engine with AdBlock Plus and AdGuard syntax support
//!
//! This module provides comprehensive adblocking capabilities using Brave's adblock-rust
//! engine as the foundation, with extensions for AdGuard-specific syntax.
//!
//! # Safety Features
//!
//! The engine includes protection against malicious filter rules:
//! - ReDoS (Regular Expression Denial of Service) detection
//! - Rule complexity validation
//! - Dangerous pattern blocking

pub mod cosmetic;
pub mod engine;
pub mod error;
pub mod list;
pub mod matcher;
pub mod modifiers;
pub mod safety;
pub mod scriptlets;
pub mod shared;
pub mod stats;
pub mod update;

pub use cosmetic::{CosmeticFilterManager, CosmeticRule, CosmeticRuleType};
pub use engine::FilterEngine;
pub use error::{Error, Result};
pub use list::{default_filter_lists, FilterList, FilterListManager};
pub use matcher::{MatchResult, RequestMatcher};
pub use modifiers::{RemoveHeaderModifier, RemoveParamModifier, ReplaceModifier};
pub use safety::{FilterSafetyConfig, FilterValidator, validate_filter_rule, validate_filter_rules};
pub use scriptlets::{ScriptletManager, ScriptletRule};
pub use shared::{compile_engine, Cosmetics, SharedEngine};
pub use stats::{BlockingStats, FilterStats};
pub use update::{
    ListUpdateStats, UpdateAttempt, UpdateConfig, UpdateScheduler, UpdateStats,
};

//! Adblocking filter engine with AdBlock Plus and AdGuard syntax support
//!
//! This module provides comprehensive adblocking capabilities using Brave's adblock-rust
//! engine as the foundation, with extensions for AdGuard-specific syntax.

pub mod engine;
pub mod error;
pub mod list;
pub mod matcher;
pub mod stats;

pub use engine::FilterEngine;
pub use error::{Error, Result};
pub use list::{FilterList, FilterListManager};
pub use matcher::RequestMatcher;
pub use stats::{BlockingStats, FilterStats};

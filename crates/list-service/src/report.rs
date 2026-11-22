//! Public report types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Totals of the last build, for the filters API.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSummary {
    pub built_at: Option<DateTime<Utc>>,
    pub duration_ms: u64,
    /// Lists compiled (including custom rules).
    pub lists: usize,
    pub network: usize,
    pub cosmetic: usize,
    /// Extended rules handed off (see `SharedEngine::ext_rules`).
    pub ext: usize,
    pub rejected: usize,
    pub ip_ranges: usize,
    /// Rules dropped as duplicates across all lists.
    pub duplicates: usize,
    /// True when the live engine was loaded from the persisted blob rather than compiled.
    pub from_persisted: bool,
    /// Hex cache key of the live engine.
    pub engine_key: String,
}

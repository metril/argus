//! Public report types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Where the list service is in its build cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BuildState {
    #[default]
    Idle,
    /// Downloading lists: `done` of `total` finished.
    Fetching { done: usize, total: usize },
    /// Converting and compiling.
    Compiling,
    /// The last build failed (the previous engine stays installed).
    Failed { error: String },
}

/// Totals of the last build, for the filters API.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSummary {
    /// Live build state (filled in by `ListService::summary`; not meaningful when persisted).
    #[serde(default)]
    pub state: BuildState,
    /// When the engine now installed was compiled.
    pub built_at: Option<DateTime<Utc>>,
    /// Compile time of that engine (conversion, deduplication, indexing), excluding downloads.
    pub duration_ms: u64,
    /// Wall-clock duration of the last whole build cycle (downloads and compile), success or not.
    #[serde(default)]
    pub last_build_ms: u64,
    /// When the last build cycle finished.
    #[serde(default)]
    pub last_build_at: Option<DateTime<Utc>>,
    /// Lists compiled (including custom rules).
    pub lists: usize,
    pub network: usize,
    pub cosmetic: usize,
    /// Extended rules handed off (see `SharedEngine::ext_rules`).
    pub ext: usize,
    pub rejected: usize,
    pub ip_ranges: usize,
    /// Pure domain rules held in the compact domain set instead of the engine.
    #[serde(default)]
    pub domain_set: usize,
    /// Rules dropped as duplicates across all lists.
    pub duplicates: usize,
    /// True when the live engine was loaded from the persisted blob rather than compiled.
    pub from_persisted: bool,
    /// Hex cache key of the live engine.
    pub engine_key: String,
}

/// Longest echoed source text kept in a stored report.
const MAX_ECHO: usize = 80;

/// Shorten text echoed from a fetched list (conversion errors repeat raw source lines) so a
/// report cannot be used to read a response back, and drop control characters.
pub(crate) fn clip_echo(s: &str) -> String {
    let mut out: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_ECHO)
        .collect();
    if s.chars().filter(|c| !c.is_control()).count() > MAX_ECHO {
        out.push_str("...");
    }
    out
}

/// Applied to every report before it is stored.
pub(crate) fn sanitize_report(r: &mut filter_engine::ListReport) {
    for e in &mut r.errors {
        e.reason = clip_echo(&e.reason);
    }
    r.skipped_reasons = std::mem::take(&mut r.skipped_reasons)
        .into_iter()
        .map(|(k, v)| (clip_echo(&k), v))
        .collect();
}

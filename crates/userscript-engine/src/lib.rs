//! Userscript engine for Greasemonkey-compatible userscript management
//!
//! Provides a complete Greasemonkey/Tampermonkey-compatible userscript engine with:
//! - Metadata parsing (@name, @match, @grant, etc.)
//! - Script storage and management
//! - Persistent data storage (GM_setValue/GM_getValue)

pub mod error;
pub mod manager;
pub mod metadata;
pub mod runtime;
pub mod script;
pub mod security;
pub mod storage;

pub use error::{Error, Result};
pub use manager::{UserscriptManager, UserscriptStats};
pub use metadata::{RunAt, UserscriptMetadata};
pub use runtime::{CacheStats, UserscriptRuntime};
pub use script::Userscript;
pub use security::{
    AuditEntry, AuditEvent, AuditStatistics, ScriptValidator, SecurityAuditor, SecurityPolicy,
};
pub use storage::{StorageValue, UserscriptStorage};

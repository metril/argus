//! Userscript engine: runs Tampermonkey / Violentmonkey / Greasemonkey userscripts through a
//! MITM proxy (no browser extension).
//!
//! Pipeline: [`metadata`] parses the header, [`matcher`] compiles URL rules once, [`index`]
//! answers "which scripts run on this document" per profile, [`bundle`] renders the JS the
//! proxy injects (with the hand-written `assets/gm.js` runtime), [`token`] mints the per-script
//! capability tokens the GM endpoints verify, [`backend`] implements those endpoints as pure
//! Rust, and [`install`] plans installs/updates (fetching is the caller's job).
//! The wire protocol is documented in `docs/USERSCRIPT-PROTOCOL.md`.

pub mod backend;
pub mod bundle;

pub mod error;
pub mod index;
pub mod install;
pub mod manager;
pub mod matcher;
pub mod metadata;
pub mod runtime;
pub mod script;
pub mod security;
pub mod storage;
pub mod token;

pub use error::{Error, Result};
pub use index::{CompiledScript, ScriptIndex};
pub use manager::{UserscriptManager, UserscriptStats};
pub use metadata::{RunAt, UserscriptMetadata};
pub use runtime::{CacheStats, UserscriptRuntime};
pub use script::{Userscript, DEFAULT_PROFILE};
pub use security::{
    AuditEntry, AuditEvent, AuditStatistics, ScriptValidator, SecurityAuditor, SecurityPolicy,
};
pub use storage::{StorageValue, UserscriptStorage};

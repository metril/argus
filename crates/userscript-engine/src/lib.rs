//! Userscript engine for Greasemonkey-compatible script execution
//!
//! Provides a complete Greasemonkey/Tampermonkey-compatible userscript engine with:
//! - Metadata parsing (@name, @match, @grant, etc.)
//! - Script storage and management
//! - Persistent data storage (GM_setValue/GM_getValue)
//! - JavaScript execution via Boa engine

pub mod error;
pub mod gm_api;
pub mod manager;
pub mod metadata;
pub mod script;
pub mod storage;

pub use error::{Error, Result};
pub use gm_api::GmApi;
pub use manager::{UserscriptManager, UserscriptStats};
pub use metadata::{RunAt, UserscriptMetadata};
pub use script::Userscript;
pub use storage::{StorageValue, UserscriptStorage};

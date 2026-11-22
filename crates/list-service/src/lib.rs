//! Filter-list service: list metadata and raw-content storage, default-list seeding, concurrent
//! conditional fetching, single-flight compile/install into a [`filter_engine::SharedEngine`],
//! scriptlet-resource loading and the auto-update ticker.
//!
//! Independent of the web UI: the proxy constructs and starts it unconditionally.

mod error;
mod persist;
mod report;
mod scriptlets;
mod service;
mod store;

pub use error::{Error, Result};
pub use report::{BuildState, BuildSummary};
pub use service::{ListService, ListServiceConfig};
pub use store::{ListStatus, ListStore};

/// Re-exported so API code needs no direct `filter-engine` dependency for these.
pub use filter_engine::{
    catalogue, CatalogueEntry, ExtKind, ExtRule, ListFormat, ListMeta, ListReport, ReportIssue,
};

//! Filter-list service: list metadata and raw-content storage, catalogue seeding, concurrent
//! conditional fetching, single-flight compile/install into a [`filter_engine::SharedEngine`],
//! scriptlet-resource loading and the auto-update ticker.
//!
//! Independent of the web UI: the proxy constructs and starts it unconditionally.

mod argus;
mod error;
pub mod inspect;
mod persist;
mod report;
mod scriptlets;
mod service;
mod sets;
mod signed;
pub mod site_exceptions;
mod store;

pub use argus::{
    check_public_key, verify as verify_minisign, verify_trusted, ArgusConfig, ArgusLists,
    RefreshOutcome,
};
pub use error::{Error, Result};
pub use report::{BuildState, BuildSummary};
pub use service::{ListService, ListServiceConfig};
pub use sets::SetKey;
#[cfg(any(test, feature = "testkit"))]
pub use signed::testkit;
pub use signed::{CatalogueDoc, FilterCatalogueEntry, Loaded, SignedDoc, UserscriptCatalogueEntry};
pub use store::{ListStatus, ListStore, CUSTOM_REPORT_ID};

/// Re-exported so API code needs no direct `filter-engine` dependency for these.
pub use filter_engine::{ExtKind, ExtRule, ListFormat, ListMeta, ListReport, ReportIssue};

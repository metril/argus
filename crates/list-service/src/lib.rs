//! Filter-list service: list metadata and raw-content storage, default-list seeding, concurrent
//! conditional fetching, single-flight compile/install into a [`filter_engine::SharedEngine`],
//! scriptlet-resource loading and the auto-update ticker.
//!
//! Independent of the web UI: the proxy constructs and starts it unconditionally.

mod argus;
mod default_profile;
mod error;
mod persist;
mod report;
mod scriptlets;
mod service;
mod sets;
mod signed;
pub mod site_exceptions;
mod store;
mod strict;

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
pub use store::{ListStatus, ListStore};
pub use strict::{StrictProfile, StrictState};

/// Re-exported so API code needs no direct `filter-engine` dependency for these.
pub use filter_engine::{
    catalogue, CatalogueEntry, ExtKind, ExtRule, ListFormat, ListMeta, ListReport, ReportIssue,
};

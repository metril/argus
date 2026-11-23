//! Web UI - Leptos SPA for Argus Proxy
//!
//! A reactive web interface for managing the argus proxy,
//! filter lists, and userscripts.

pub mod api;
pub mod app;
pub mod components;
pub mod pages;
pub mod router;
pub mod state;
pub mod utils;

pub use app::App;

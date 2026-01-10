//! Web UI - Leptos SPA for Adblocker Proxy
//!
//! A reactive web interface for managing the adblocker proxy,
//! filter lists, and userscripts.

pub mod api;
pub mod app;
pub mod components;
pub mod pages;
pub mod router;
pub mod state;
pub mod utils;

pub use app::App;

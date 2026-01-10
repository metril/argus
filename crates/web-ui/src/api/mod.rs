//! API client for communicating with the backend

pub mod auth;
pub mod client;
pub mod filters;
pub mod proxy;
pub mod userscripts;

pub use client::{ApiClient, ApiError};

//! Global state management

pub mod app;
pub mod auth;

pub use app::{provide_app_state, use_app_state, AppState, Theme, Toast, ToastType};
pub use auth::{provide_auth_state, use_auth_state, AuthState};

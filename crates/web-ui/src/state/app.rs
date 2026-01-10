//! Application-wide state

use leptos::prelude::*;
use gloo_storage::{LocalStorage, Storage};

/// Application theme
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    #[default]
    Light,
    Dark,
}

impl Theme {
    /// Get the CSS class for this theme
    pub fn class(&self) -> &'static str {
        match self {
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }

    /// Toggle the theme
    pub fn toggle(&self) -> Self {
        match self {
            Theme::Light => Theme::Dark,
            Theme::Dark => Theme::Light,
        }
    }
}

/// Toast notification type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastType {
    Success,
    Error,
    Warning,
    Info,
}

impl ToastType {
    /// Get the CSS class for this toast type
    pub fn class(&self) -> &'static str {
        match self {
            ToastType::Success => "toast-success",
            ToastType::Error => "toast-error",
            ToastType::Warning => "toast-warning",
            ToastType::Info => "toast-info",
        }
    }
}

/// Toast notification
#[derive(Debug, Clone)]
pub struct Toast {
    pub id: u32,
    pub message: String,
    pub toast_type: ToastType,
    pub duration_ms: u32,
}

impl Toast {
    /// Create a new toast
    pub fn new(message: impl Into<String>, toast_type: ToastType) -> Self {
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        Self {
            id: COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            message: message.into(),
            toast_type,
            duration_ms: 5000,
        }
    }

    /// Create a success toast
    pub fn success(message: impl Into<String>) -> Self {
        Self::new(message, ToastType::Success)
    }

    /// Create an error toast
    pub fn error(message: impl Into<String>) -> Self {
        Self::new(message, ToastType::Error)
    }

    /// Create a warning toast
    pub fn warning(message: impl Into<String>) -> Self {
        Self::new(message, ToastType::Warning)
    }

    /// Create an info toast
    pub fn info(message: impl Into<String>) -> Self {
        Self::new(message, ToastType::Info)
    }

    /// Set custom duration
    pub fn with_duration(mut self, duration_ms: u32) -> Self {
        self.duration_ms = duration_ms;
        self
    }
}

/// Application-wide state
#[derive(Clone)]
pub struct AppState {
    /// Current theme
    pub theme: RwSignal<Theme>,
    /// Sidebar open state
    pub sidebar_open: RwSignal<bool>,
    /// Toast notification queue
    pub toasts: RwSignal<Vec<Toast>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    /// Create new app state
    pub fn new() -> Self {
        // Load theme from localStorage
        let saved_theme = LocalStorage::get::<String>("theme")
            .ok()
            .and_then(|t| match t.as_str() {
                "dark" => Some(Theme::Dark),
                "light" => Some(Theme::Light),
                _ => None,
            })
            .unwrap_or_default();

        Self {
            theme: RwSignal::new(saved_theme),
            sidebar_open: RwSignal::new(true),
            toasts: RwSignal::new(Vec::new()),
        }
    }

    /// Toggle the theme
    pub fn toggle_theme(&self) {
        let new_theme = self.theme.get().toggle();
        self.theme.set(new_theme);

        // Save to localStorage
        let _ = LocalStorage::set("theme", new_theme.class());
    }

    /// Toggle sidebar
    pub fn toggle_sidebar(&self) {
        self.sidebar_open.update(|open| *open = !*open);
    }

    /// Show a toast notification
    pub fn show_toast(&self, toast: Toast) {
        self.toasts.update(|toasts| toasts.push(toast));
    }

    /// Remove a toast by ID
    pub fn remove_toast(&self, id: u32) {
        self.toasts.update(|toasts| toasts.retain(|t| t.id != id));
    }

    /// Show a success toast
    pub fn success(&self, message: impl Into<String>) {
        self.show_toast(Toast::success(message));
    }

    /// Show an error toast
    pub fn error(&self, message: impl Into<String>) {
        self.show_toast(Toast::error(message));
    }

    /// Show a warning toast
    pub fn warning(&self, message: impl Into<String>) {
        self.show_toast(Toast::warning(message));
    }

    /// Show an info toast
    pub fn info(&self, message: impl Into<String>) {
        self.show_toast(Toast::info(message));
    }
}

/// Provide app state context
pub fn provide_app_state() -> AppState {
    let state = AppState::new();
    provide_context(state.clone());
    state
}

/// Use app state from context
pub fn use_app_state() -> AppState {
    expect_context::<AppState>()
}

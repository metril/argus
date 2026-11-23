//! Application-wide state

use gloo_storage::{LocalStorage, Storage};
use leptos::prelude::*;

/// Application theme. `System` follows `prefers-color-scheme` (dark when unknown).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

impl Theme {
    /// Value for the `data-theme` attribute (`None` leaves the system preference in charge).
    pub fn attr(&self) -> Option<&'static str> {
        match self {
            Theme::System => None,
            Theme::Light => Some("light"),
            Theme::Dark => Some("dark"),
        }
    }

    /// Whether this theme renders dark, given the system preference.
    pub fn is_dark(&self, system_dark: bool) -> bool {
        match self {
            Theme::System => system_dark,
            Theme::Light => false,
            Theme::Dark => true,
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "dark" => Some(Theme::Dark),
            "light" => Some(Theme::Light),
            _ => None,
        }
    }
}

/// True when the OS asks for a light color scheme.
fn system_prefers_light() -> bool {
    web_sys::window()
        .and_then(|w| {
            w.match_media("(prefers-color-scheme: light)")
                .ok()
                .flatten()
        })
        .map(|m| m.matches())
        .unwrap_or(false)
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
            ToastType::Success | ToastType::Info => "",
            ToastType::Error => "bad",
            ToastType::Warning => "warn",
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
    /// Sidebar collapsed to the icon rail (desktop)
    pub collapsed: RwSignal<bool>,
    /// Off-canvas navigation open (under 760px)
    pub nav_open: RwSignal<bool>,
    /// Command palette open
    pub palette_open: RwSignal<bool>,
    /// Bumped when the navbar profile selector changes, so profile-scoped pages reload
    pub profile_reload: RwSignal<u32>,
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
        let saved_theme = LocalStorage::get::<String>("theme")
            .ok()
            .and_then(|t| Theme::parse(&t))
            .unwrap_or_default();
        let collapsed = LocalStorage::get::<bool>("sidebar_collapsed").unwrap_or(false);

        Self {
            theme: RwSignal::new(saved_theme),
            collapsed: RwSignal::new(collapsed),
            nav_open: RwSignal::new(false),
            palette_open: RwSignal::new(false),
            profile_reload: RwSignal::new(0),
            toasts: RwSignal::new(Vec::new()),
        }
    }

    /// Flip between light and dark (from whatever is currently displayed) and remember it.
    pub fn toggle_theme(&self) {
        let dark = self.theme.get_untracked().is_dark(!system_prefers_light());
        let next = if dark { Theme::Light } else { Theme::Dark };
        self.theme.set(next);
        let _ = LocalStorage::set("theme", next.attr().unwrap_or("dark"));
    }

    /// Collapse or expand the desktop sidebar.
    pub fn toggle_collapsed(&self) {
        let v = !self.collapsed.get_untracked();
        self.collapsed.set(v);
        let _ = LocalStorage::set("sidebar_collapsed", v);
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
    let theme = state.theme;
    Effect::new(move || {
        let t = theme.get();
        if let Some(el) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.document_element())
        {
            let _ = match t.attr() {
                Some(v) => el.set_attribute("data-theme", v),
                None => el.remove_attribute("data-theme"),
            };
        }
    });
    provide_context(state.clone());
    state
}

/// Use app state from context
pub fn use_app_state() -> AppState {
    expect_context::<AppState>()
}

//! Layout component

use leptos::prelude::*;

use super::{Navbar, Sidebar, ToastContainer};
use crate::state::{use_app_state, use_auth_state};

/// Main layout wrapper for authenticated pages
#[component]
pub fn Layout(children: Children) -> impl IntoView {
    let app_state = use_app_state();
    let auth_state = use_auth_state();

    let theme = app_state.theme;
    let sidebar_open = app_state.sidebar_open;
    let user = auth_state.user;

    // Check session on mount
    Effect::new(move || {
        let auth_state = auth_state.clone();
        wasm_bindgen_futures::spawn_local(async move {
            auth_state.check_session().await;
        });
    });

    // Store children view immediately since Children is FnOnce
    let children_view = children();

    view! {
        <div class=move || format!("app-container {}", theme.get().class())>
            <Navbar />
            <div class="app-body">
                <Sidebar />
                <main class=move || format!(
                    "main-content {}",
                    if sidebar_open.get() { "sidebar-open" } else { "sidebar-closed" }
                )>
                    {children_view}
                </main>
            </div>
            <ToastContainer />
            <Show when=move || user.get().is_none()>
                <leptos_router::components::Redirect path="/login" />
            </Show>
        </div>
    }
}

/// Auth layout for login/register pages
#[component]
pub fn AuthLayout(children: Children) -> impl IntoView {
    let app_state = use_app_state();
    let theme = app_state.theme;

    // Store children view immediately since Children is FnOnce
    let children_view = children();

    view! {
        <div class=move || format!("auth-container {}", theme.get().class())>
            <div class="auth-card">
                <div class="auth-logo">
                    <span class="logo-icon">"AD"</span>
                    <span class="logo-text">"Adblocker Proxy"</span>
                </div>
                {children_view}
            </div>
            <ToastContainer />
        </div>
    }
}

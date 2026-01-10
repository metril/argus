//! Navigation bar component

use leptos::prelude::*;

use crate::state::{use_app_state, use_auth_state};

/// Navbar component
#[component]
pub fn Navbar() -> impl IntoView {
    let app_state = use_app_state();
    let auth_state = use_auth_state();

    let user = auth_state.user;
    let theme = app_state.theme;

    // Signal-based logout trigger
    let do_logout = RwSignal::new(false);

    {
        let auth_state = auth_state.clone();
        Effect::new(move || {
            if do_logout.get() {
                let auth_state = auth_state.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    auth_state.logout().await;
                });
                do_logout.set(false);
            }
        });
    }

    // Clone app_state for multiple closures
    let app_state_sidebar = app_state.clone();
    let app_state_theme = app_state.clone();

    view! {
        <nav class="navbar">
            <div class="navbar-left">
                <button
                    type="button"
                    class="navbar-toggle"
                    on:click=move |_| app_state_sidebar.toggle_sidebar()
                    title="Toggle sidebar"
                >
                    "="
                </button>
                <a href="/" class="navbar-brand">
                    <span class="navbar-logo">"AD"</span>
                    <span class="navbar-title">"Adblocker Proxy"</span>
                </a>
            </div>

            <div class="navbar-right">
                <button
                    type="button"
                    class="navbar-btn"
                    on:click=move |_| app_state_theme.toggle_theme()
                    title=move || if theme.get() == crate::state::Theme::Dark {
                        "Switch to light mode"
                    } else {
                        "Switch to dark mode"
                    }
                >
                    {move || if theme.get() == crate::state::Theme::Dark {
                        "Light"
                    } else {
                        "Dark"
                    }}
                </button>

                <Show when=move || user.get().is_some()>
                    {move || user.get().map(|u| view! {
                        <div class="navbar-user">
                            <span class="navbar-username">{u.username}</span>
                            <span class="navbar-role">{format!("{:?}", u.role)}</span>
                        </div>
                    })}
                    <button
                        type="button"
                        class="navbar-btn navbar-logout"
                        on:click=move |_| do_logout.set(true)
                        title="Logout"
                    >
                        "Logout"
                    </button>
                </Show>
            </div>
        </nav>
    }
}

//! Top bar: menu button (mobile), title, health, profile selector, palette button, theme, user.

use leptos::prelude::*;
use leptos_router::hooks::use_location;

use super::icon::Icon;
use super::sidebar::page_meta;
use crate::api::client::{current_profile, set_current_profile};
use crate::api::profiles::ProfileDto;
use crate::api::ApiClient;
use crate::state::{use_app_state, use_auth_state};

#[component]
pub fn Navbar() -> impl IntoView {
    let app_state = use_app_state();
    let user = use_auth_state().user;
    let location = use_location();
    let profiles = RwSignal::new(Vec::<ProfileDto>::new());
    let selected = RwSignal::new(current_profile());
    // None = unknown yet, Some(true) = healthy
    let health = RwSignal::new(Option::<(bool, String)>::None);

    wasm_bindgen_futures::spawn_local(async move {
        if let Ok(list) = ApiClient::new().list_profiles().await {
            profiles.set(list);
        }
    });
    wasm_bindgen_futures::spawn_local(async move {
        loop {
            let r = ApiClient::new()
                .get::<api_types::HealthResponse>("/health")
                .await;
            health.set(Some(match r {
                Ok(h) => (
                    h.status == "ok" || h.status == "healthy",
                    format!("Version {}", h.version),
                ),
                Err(e) => (false, e.to_string()),
            }));
            gloo_timers::future::TimeoutFuture::new(30_000).await;
        }
    });

    let nav_open = app_state.nav_open;
    let palette_open = app_state.palette_open;
    let reload = app_state.profile_reload;
    let st = app_state.clone();

    view! {
        <header class="top">
            <button
                class="icon-btn menu-btn"
                type="button"
                aria-label="Open navigation"
                aria-expanded=move || nav_open.get().to_string()
                on:click=move |_| nav_open.update(|v| *v = !*v)
            >
                <Icon name="menu" />
            </button>
            <div class="crumb">
                <h2>{move || page_meta(&location.pathname.get()).0}</h2>
                <span>{move || page_meta(&location.pathname.get()).1}</span>
            </div>
            <div class="top-right">
                <div
                    class="health"
                    role="status"
                    title=move || health.get().map(|h| h.1).unwrap_or_default()
                >
                    <i class=move || match health.get() {
                        Some((true, _)) | None => "dot",
                        _ => "dot bad",
                    }></i>
                    <span class="htxt">{move || match health.get() {
                        None => "Checking",
                        Some((true, _)) => "Healthy",
                        Some((false, _)) => "Unreachable",
                    }}</span>
                </div>
                <div class="profile">
                    <label for="profileSel">"Profile"</label>
                    <select
                        id="profileSel"
                        class="select"
                        prop:value=move || selected.get()
                        on:change=move |ev| {
                            let id = event_target_value(&ev);
                            set_current_profile(&id);
                            selected.set(id);
                            reload.update(|n| *n += 1);
                        }
                    >
                        <For
                            each=move || profiles.get()
                            key=|p| format!("{}/{}", p.id, p.name)
                            children=move |p| {
                                let id = p.id.clone();
                                let sel = id.clone();
                                view! { <option value=id selected=move || selected.get() == sel>{p.name.clone()}</option> }
                            }
                        />
                    </select>
                </div>
                <button
                    class="kbtn"
                    type="button"
                    aria-label="Open command palette"
                    on:click=move |_| palette_open.set(true)
                >
                    <Icon name="search" />
                    <span class="kl">"Jump to..."</span>
                    <kbd>"Ctrl K"</kbd>
                </button>
                <button
                    class="icon-btn"
                    type="button"
                    aria-label="Switch theme"
                    title="Switch theme"
                    on:click=move |_| st.toggle_theme()
                >
                    <Icon name="sun" />
                </button>
                {move || user.get().map(|u| {
                    let initials: String = u.username.chars().take(2).collect::<String>().to_uppercase();
                    view! { <span class="avatar" title=format!("Signed in as {}", u.username)>{initials}</span> }
                })}
            </div>
        </header>
    }
}

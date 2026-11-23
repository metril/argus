//! Login page

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use crate::api::ApiClient;
use crate::components::layout::AuthLayout;
use crate::state::use_auth_state;

#[component]
pub fn LoginPage() -> impl IntoView {
    let auth_state = use_auth_state();
    let navigate = use_navigate();

    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let error = RwSignal::new(Option::<String>::None);
    let loading = RwSignal::new(false);

    let on_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        let (u, p) = (username.get(), password.get());
        if u.trim().is_empty() || p.is_empty() {
            error.set(Some("Enter your username and password.".to_string()));
            return;
        }
        loading.set(true);
        error.set(None);
        let (auth_state, navigate) = (auth_state.clone(), navigate.clone());
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().login(&u, &p).await {
                Ok(response) => {
                    auth_state.user.set(Some(response.user));
                    auth_state.checked.set(true);
                    let next = crate::pages::vlist::query_get("next")
                        .filter(|n| n.starts_with('/') && !n.starts_with("//") && !n.contains('\\'))
                        .unwrap_or_else(|| "/".to_string());
                    navigate(&next, Default::default());
                }
                Err(e) => error.set(Some(e.to_string())),
            }
            loading.set(false);
        });
    };

    view! {
        <AuthLayout>
            <h2>"Sign in"</h2>
            <form class="reg-card" style="width:auto" on:submit=on_submit novalidate>
                <div class="field">
                    <label for="lUser">"Username"</label>
                    <input class="input" id="lUser" autocomplete="username" disabled=move || loading.get()
                        aria-invalid=move || if error.get().is_some() { "true" } else { "false" }
                        prop:value=move || username.get() on:input=move |ev| username.set(event_target_value(&ev)) />
                </div>
                <div class="field">
                    <label for="lPass">"Password"</label>
                    <input class="input" id="lPass" type="password" autocomplete="current-password" disabled=move || loading.get()
                        aria-invalid=move || if error.get().is_some() { "true" } else { "false" }
                        prop:value=move || password.get() on:input=move |ev| password.set(event_target_value(&ev)) />
                    {move || error.get().map(|e| view! { <span class="err" role="alert">{e}</span> })}
                </div>
                <button class="btn primary" type="submit" style="height:36px" disabled=move || loading.get()>
                    {move || if loading.get() { "Signing in..." } else { "Sign in" }}
                </button>
                <p class="hint">"First time here? "<a href="/register" style="color:var(--accent)">"Create the admin account"</a>"."</p>
            </form>
        </AuthLayout>
    }
}

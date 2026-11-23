//! First-run page: create the admin account. After the first account exists the server closes
//! registration and this page says so.

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use crate::api::{ApiClient, ApiError};
use crate::components::layout::AuthLayout;
use crate::state::use_auth_state;

fn strength(p: &str) -> usize {
    let mut l = 0;
    if !p.is_empty() {
        l = 1;
    }
    if p.len() >= 12 {
        l = 2;
    }
    if p.len() >= 12
        && p.chars().any(|c| c.is_ascii_digit())
        && p.chars().any(|c| c.is_ascii_alphabetic())
    {
        l = 3;
    }
    if p.len() >= 16 && p.chars().any(|c| !c.is_ascii_alphanumeric()) {
        l = 4;
    }
    l
}

#[component]
pub fn RegisterPage() -> impl IntoView {
    let auth_state = use_auth_state();
    let navigate = use_navigate();

    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let user_err = RwSignal::new(Option::<String>::None);
    let pass_err = RwSignal::new(Option::<String>::None);
    let form_err = RwSignal::new(Option::<String>::None);
    let closed = RwSignal::new(false);
    let loading = RwSignal::new(false);
    let first_run = RwSignal::new(true);
    wasm_bindgen_futures::spawn_local(async move {
        if let Ok(r) = ApiClient::new()
            .get::<api_types::RegistrationStatus>("/auth/registration")
            .await
        {
            closed.set(!r.open);
            first_run.set(r.first_run);
        }
    });

    let level = move || strength(&password.get());
    let meter_text = move || {
        let p = password.get();
        match level() {
            0 => "At least 8 characters; 12 or more recommended".to_string(),
            1 => format!("Too short: {} of 8 minimum", p.len()),
            2 => "Long enough. Mix in digits for more strength.".to_string(),
            3 => "Strong".to_string(),
            _ => "Very strong".to_string(),
        }
    };

    let on_submit = Callback::new(move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        let (u, p, c) = (username.get(), password.get(), confirm.get());
        user_err.set(None);
        pass_err.set(None);
        form_err.set(None);
        let u = u.trim().to_string();
        if u.len() < 3 || u.len() > 50 {
            user_err.set(Some("Use 3 to 50 characters.".into()));
            return;
        }
        if p.len() < 8 {
            pass_err.set(Some("The password needs at least 8 characters.".into()));
            return;
        }
        if p != c {
            pass_err.set(Some("The two passwords don't match.".into()));
            return;
        }
        loading.set(true);
        let (auth_state, navigate) = (auth_state.clone(), navigate.clone());
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().register(&u, &p).await {
                Ok(r) => {
                    auth_state.user.set(Some(r.user));
                    auth_state.checked.set(true);
                    navigate("/", Default::default());
                }
                Err(ApiError::Forbidden(m)) if m.to_lowercase().contains("closed") => {
                    closed.set(true)
                }
                Err(e) => form_err.set(Some(e.to_string())),
            }
            loading.set(false);
        });
    });

    view! {
        <AuthLayout>
            <Show
                when=move || !closed.get()
                fallback=|| view! {
                    <h2>"Registration closed"</h2>
                    <p class="muted">"An admin account already exists on this server. Ask an administrator to create your account."</p>
                    <a class="btn primary" href="/login" style="height:36px">"Back to sign in"</a>
                }
            >
                <div class="steps" aria-label="Setup steps">
                    <span class="on">"1 admin account"</span><span>"2 install CA"</span><span>"3 point clients"</span>
                </div>
                <h2>"Create admin account"</h2>
                <p>"No users exist on this server yet. This account gets the Admin role and can add everyone else."</p>
                <form class="reg-card" style="width:auto" on:submit=move |ev| on_submit.run(ev) novalidate>
                    <div class="field">
                        <label for="rUser">"Username"</label>
                        <input class="input" id="rUser" autocomplete="username" placeholder="Choose a username"
                            aria-invalid=move || if user_err.get().is_some() { "true" } else { "false" }
                            prop:value=move || username.get() on:input=move |ev| username.set(event_target_value(&ev)) />
                        {move || user_err.get().map(|e| view! { <span class="err" role="alert">{e}</span> })}
                    </div>
                    <div class="field">
                        <label for="rPass">"Password"</label>
                        <input class="input" id="rPass" type="password" autocomplete="new-password" placeholder="At least 8 characters"
                            prop:value=move || password.get() on:input=move |ev| password.set(event_target_value(&ev)) />
                        <div class="meter" data-l=move || level().to_string() aria-hidden="true"><i></i><i></i><i></i><i></i></div>
                        <span class="hint">{meter_text}</span>
                    </div>
                    <div class="field">
                        <label for="rPass2">"Confirm password"</label>
                        <input class="input" id="rPass2" type="password" autocomplete="new-password"
                            aria-invalid=move || if pass_err.get().is_some() { "true" } else { "false" }
                            prop:value=move || confirm.get() on:input=move |ev| confirm.set(event_target_value(&ev)) />
                        {move || pass_err.get().map(|e| view! { <span class="err" role="alert">{e}</span> })}
                    </div>
                    {move || form_err.get().map(|e| view! { <span class="err" role="alert">{e}</span> })}
                    <button class="btn primary" type="submit" style="height:36px" disabled=move || loading.get()>
                        {move || if loading.get() { "Creating..." } else { "Create admin account" }}
                    </button>
                    <p class="hint">"Already have an account? "<a href="/login" style="color:var(--accent)">"Sign in"</a></p>
                </form>
            </Show>
        </AuthLayout>
    }
}

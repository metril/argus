//! Login page

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use web_sys::HtmlInputElement;

use crate::api::ApiClient;
use crate::components::layout::AuthLayout;
use crate::state::use_auth_state;

/// Login page component
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

        let username_val = username.get();
        let password_val = password.get();

        if username_val.trim().is_empty() || password_val.is_empty() {
            error.set(Some("Please fill in all fields".to_string()));
            return;
        }

        loading.set(true);
        error.set(None);

        let auth_state = auth_state.clone();
        let navigate = navigate.clone();

        wasm_bindgen_futures::spawn_local(async move {
            let client = ApiClient::new();
            match client.login(&username_val, &password_val).await {
                Ok(response) => {
                    auth_state.user.set(Some(response.user));
                    navigate("/", Default::default());
                }
                Err(e) => {
                    error.set(Some(e.to_string()));
                }
            }
            loading.set(false);
        });
    };

    view! {
        <AuthLayout>
            <h1 class="auth-title">"Sign In"</h1>

            {move || error.get().map(|e| view! {
                <div class="auth-error">{e}</div>
            })}

            <form class="auth-form" on:submit=on_submit>
                <div class="form-field">
                    <label class="form-label">"Username"</label>
                    <input
                        type="text"
                        class="form-input"
                        placeholder="Enter your username"
                        disabled=move || loading.get()
                        prop:value=move || username.get()
                        on:input=move |ev| {
                            let target = event_target::<HtmlInputElement>(&ev);
                            username.set(target.value());
                        }
                    />
                </div>

                <div class="form-field">
                    <label class="form-label">"Password"</label>
                    <input
                        type="password"
                        class="form-input"
                        placeholder="Enter your password"
                        disabled=move || loading.get()
                        prop:value=move || password.get()
                        on:input=move |ev| {
                            let target = event_target::<HtmlInputElement>(&ev);
                            password.set(target.value());
                        }
                    />
                </div>

                <button
                    type="submit"
                    class="btn btn-primary auth-submit"
                    disabled=move || loading.get()
                >
                    {move || if loading.get() { "Signing in..." } else { "Sign In" }}
                </button>
            </form>

            <p class="auth-footer">
                "Don't have an account? "
                <a href="/register" class="auth-link">"Register"</a>
            </p>
        </AuthLayout>
    }
}

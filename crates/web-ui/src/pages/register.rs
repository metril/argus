//! Registration page

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use web_sys::HtmlInputElement;

use crate::api::ApiClient;
use crate::components::layout::AuthLayout;
use crate::state::use_auth_state;

/// Registration page component
#[component]
pub fn RegisterPage() -> impl IntoView {
    let auth_state = use_auth_state();
    let navigate = use_navigate();

    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let password_confirm = RwSignal::new(String::new());
    let error = RwSignal::new(Option::<String>::None);
    let loading = RwSignal::new(false);

    let on_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        let username_val = username.get();
        let password_val = password.get();
        let password_confirm_val = password_confirm.get();

        // Validation
        if username_val.trim().is_empty() {
            error.set(Some("Username is required".to_string()));
            return;
        }
        if password_val.len() < 8 {
            error.set(Some("Password must be at least 8 characters".to_string()));
            return;
        }
        if password_val != password_confirm_val {
            error.set(Some("Passwords do not match".to_string()));
            return;
        }

        loading.set(true);
        error.set(None);

        let auth_state = auth_state.clone();
        let navigate = navigate.clone();

        wasm_bindgen_futures::spawn_local(async move {
            let client = ApiClient::new();
            match client.register(&username_val, &password_val).await {
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
            <h1 class="auth-title">"Create Account"</h1>

            {move || error.get().map(|e| view! {
                <div class="auth-error">{e}</div>
            })}

            <form class="auth-form" on:submit=on_submit>
                <div class="form-field">
                    <label class="form-label">"Username"</label>
                    <input
                        type="text"
                        class="form-input"
                        placeholder="Choose a username"
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
                        placeholder="Create a password"
                        disabled=move || loading.get()
                        prop:value=move || password.get()
                        on:input=move |ev| {
                            let target = event_target::<HtmlInputElement>(&ev);
                            password.set(target.value());
                        }
                    />
                </div>

                <div class="form-field">
                    <label class="form-label">"Confirm Password"</label>
                    <input
                        type="password"
                        class="form-input"
                        placeholder="Confirm your password"
                        disabled=move || loading.get()
                        prop:value=move || password_confirm.get()
                        on:input=move |ev| {
                            let target = event_target::<HtmlInputElement>(&ev);
                            password_confirm.set(target.value());
                        }
                    />
                </div>

                <button
                    type="submit"
                    class="btn btn-primary auth-submit"
                    disabled=move || loading.get()
                >
                    {move || if loading.get() { "Creating account..." } else { "Create Account" }}
                </button>
            </form>

            <p class="auth-footer">
                "Already have an account? "
                <a href="/login" class="auth-link">"Sign In"</a>
            </p>
        </AuthLayout>
    }
}

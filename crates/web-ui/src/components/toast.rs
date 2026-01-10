//! Toast notification component

use leptos::prelude::*;
use gloo_timers::callback::Timeout;

use crate::state::{use_app_state, Toast};

/// Toast container component - displays all active toasts
#[component]
pub fn ToastContainer() -> impl IntoView {
    let app_state = use_app_state();
    let toasts = app_state.toasts;

    view! {
        <div class="toast-container">
            <For
                each=move || toasts.get()
                key=|toast| toast.id
                children=move |toast| {
                    let toast_id = toast.id;
                    let duration = toast.duration_ms;
                    let app_state = app_state.clone();

                    // Auto-dismiss after duration
                    let app_state_timeout = app_state.clone();
                    let _ = Timeout::new(duration, move || {
                        app_state_timeout.remove_toast(toast_id);
                    });

                    view! {
                        <ToastItem
                            toast=toast
                            on_close=Callback::new(move |_| {
                                app_state.remove_toast(toast_id);
                            })
                        />
                    }
                }
            />
        </div>
    }
}

/// Individual toast item
#[component]
fn ToastItem(
    toast: Toast,
    on_close: Callback<()>,
) -> impl IntoView {
    view! {
        <div class=format!("toast {}", toast.toast_type.class())>
            <div class="toast-content">
                <span class="toast-icon">
                    {match toast.toast_type {
                        crate::state::ToastType::Success => "check",
                        crate::state::ToastType::Error => "x",
                        crate::state::ToastType::Warning => "!",
                        crate::state::ToastType::Info => "i",
                    }}
                </span>
                <span class="toast-message">{toast.message}</span>
            </div>
            <button
                type="button"
                class="toast-close"
                on:click=move |_| on_close.run(())
            >
                "x"
            </button>
        </div>
    }
}

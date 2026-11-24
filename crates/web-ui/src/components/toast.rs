//! Toast notifications (`role="status"`).

use gloo_timers::callback::Timeout;
use leptos::prelude::*;

use crate::state::{use_app_state, Toast};

/// Container showing all active toasts.
#[component]
pub fn ToastContainer() -> impl IntoView {
    let app_state = use_app_state();
    let toasts = app_state.toasts;

    view! {
        <div class="toasts" role="status" aria-live="polite">
            <For
                each=move || toasts.get()
                key=|toast| toast.id
                children=move |toast| {
                    let id = toast.id;
                    let state = app_state.clone();
                    let state2 = app_state.clone();
                    Timeout::new(toast.duration_ms, move || state.remove_toast(id)).forget();
                    view! { <ToastItem toast=toast on_close=Callback::new(move |_| state2.remove_toast(id)) /> }
                }
            />
        </div>
    }
}

#[component]
fn ToastItem(toast: Toast, on_close: Callback<()>) -> impl IntoView {
    view! {
        <div class=format!("toast {}", toast.toast_type.class())>
            <span>{toast.message}{(toast.count > 1).then(|| format!(" \u{d7}{}", toast.count))}</span>
            <button type="button" class="x" aria-label="Dismiss" on:click=move |_| on_close.run(())>"x"</button>
        </div>
    }
}

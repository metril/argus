//! Two-step inline confirm button (click once to arm, again within 4 s to confirm).

use gloo_timers::callback::Timeout;
use leptos::prelude::*;

#[component]
pub fn ConfirmButton(
    #[prop(into)] label: String,
    #[prop(into, optional)] confirm_label: Option<String>,
    on_confirm: Callback<()>,
    #[prop(into, optional)] class: String,
    #[prop(into, optional)] disabled: Signal<bool>,
) -> impl IntoView {
    let armed = RwSignal::new(false);
    let timer = StoredValue::new_local(None::<Timeout>);
    let confirm_label = confirm_label.unwrap_or_else(|| "Confirm".to_string());
    let l1 = label.clone();
    view! {
        <button
            type="button"
            class=move || format!("btn {} {}", if class.is_empty() { "danger sm" } else { &class }, if armed.get() { "armed" } else { "" })
            disabled=move || disabled.get()
            on:click=move |_| {
                if armed.get_untracked() {
                    armed.set(false);
                    timer.set_value(None);
                    on_confirm.run(());
                } else {
                    armed.set(true);
                    timer.set_value(Some(Timeout::new(4000, move || armed.set(false))));
                }
            }
            on:blur=move |_| armed.set(false)
        >
            {move || if armed.get() { confirm_label.clone() } else { l1.clone() }}
        </button>
    }
}

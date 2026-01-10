//! Form components

use leptos::prelude::*;
use web_sys::HtmlInputElement;

/// Input field component
#[component]
pub fn Input(
    #[prop(into)] label: String,
    #[prop(into, optional)] input_type: String,
    #[prop(into, optional)] placeholder: String,
    #[prop(into, optional)] error: Option<String>,
    #[prop(optional)] disabled: bool,
    #[prop(into, optional)] class: String,
    value: RwSignal<String>,
) -> impl IntoView {
    let input_type = if input_type.is_empty() {
        "text".to_string()
    } else {
        input_type
    };

    let has_error = error.is_some();
    let error_clone = error.clone();

    view! {
        <div class={format!("form-field {}", class)}>
            <label class="form-label">{label}</label>
            <input
                type={input_type}
                class={format!(
                    "form-input {}",
                    if has_error { "input-error" } else { "" }
                )}
                placeholder={placeholder}
                disabled={disabled}
                prop:value=move || value.get()
                on:input=move |ev| {
                    let target = event_target::<HtmlInputElement>(&ev);
                    value.set(target.value());
                }
            />
            {error_clone.map(|e| view! {
                <span class="form-error">{e}</span>
            })}
        </div>
    }
}

/// Checkbox component
#[component]
pub fn Checkbox(
    #[prop(into)] label: String,
    #[prop(optional)] disabled: bool,
    #[prop(into, optional)] class: String,
    checked: RwSignal<bool>,
) -> impl IntoView {
    view! {
        <label class={format!("form-checkbox {}", class)}>
            <input
                type="checkbox"
                class="checkbox-input"
                disabled={disabled}
                prop:checked=move || checked.get()
                on:change=move |_| {
                    checked.update(|c| *c = !*c);
                }
            />
            <span class="checkbox-label">{label}</span>
        </label>
    }
}

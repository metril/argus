//! Button component

use leptos::prelude::*;

/// Button variant
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ButtonVariant {
    #[default]
    Primary,
    Secondary,
    Danger,
    Ghost,
}

impl ButtonVariant {
    pub fn class(&self) -> &'static str {
        match self {
            ButtonVariant::Primary => "btn-primary",
            ButtonVariant::Secondary => "btn-secondary",
            ButtonVariant::Danger => "btn-danger",
            ButtonVariant::Ghost => "btn-ghost",
        }
    }
}

/// Button component
#[component]
pub fn Button(
    #[prop(optional)] variant: ButtonVariant,
    #[prop(optional)] disabled: bool,
    #[prop(optional)] loading: bool,
    #[prop(into, optional)] class: String,
    #[prop(into, optional)] button_type: String,
    #[prop(optional)] on_click: Option<Callback<()>>,
    children: Children,
) -> impl IntoView {
    let button_type = if button_type.is_empty() {
        "button".to_string()
    } else {
        button_type
    };

    let is_disabled = disabled || loading;

    view! {
        <button
            type={button_type}
            class={format!(
                "btn {} {} {}",
                variant.class(),
                if loading { "btn-loading" } else { "" },
                class
            )}
            disabled={is_disabled}
            on:click=move |_| {
                if let Some(cb) = &on_click {
                    cb.run(());
                }
            }
        >
            {children()}
        </button>
    }
}

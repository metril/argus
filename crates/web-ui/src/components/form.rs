//! Form controls: Input, Switch, Segmented, ChipSelect, TagInput.

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::HtmlInputElement;

use super::icon::Icon;

/// Labelled text input bound to a signal.
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
    let id = format!("in-{}", uuid::Uuid::new_v4().simple());
    view! {
        <div class=format!("field {class}")>
            <label for=id.clone()>{label}</label>
            <input
                id=id
                type=input_type
                class="input"
                aria-invalid=if has_error { "true" } else { "false" }
                placeholder=placeholder
                disabled=disabled
                prop:value=move || value.get()
                on:input=move |ev| value.set(event_target_value(&ev))
            />
            {error.map(|e| view! { <span class="err">{e}</span> })}
        </div>
    }
}

/// On/off toggle: `<button role="switch" aria-checked>`; Space and Enter flip it.
/// `label` is the accessible name; `text` (optional) is shown beside the track.
#[component]
pub fn Switch(
    #[prop(into)] checked: Signal<bool>,
    #[prop(into)] on_change: Callback<bool>,
    #[prop(into)] label: String,
    #[prop(into, optional)] disabled: Signal<bool>,
    #[prop(into, optional)] text: Option<Signal<String>>,
) -> impl IntoView {
    view! {
        <button
            type="button"
            class="sw"
            role="switch"
            aria-checked=move || checked.get().to_string()
            aria-label=label
            disabled=move || disabled.get()
            on:click=move |_| on_change.run(!checked.get_untracked())
        >
            <span class="sw-track"><span class="sw-thumb"></span></span>
            {text.map(|t| view! { <span class="dim">{move || t.get()}</span> })}
        </button>
    }
}

/// Single-select radio group with arrow-key movement and one tab stop.
#[component]
pub fn Segmented(
    /// `(value, label)` pairs.
    options: Vec<(String, String)>,
    #[prop(into)] value: Signal<String>,
    #[prop(into)] on_change: Callback<String>,
    #[prop(into)] label: String,
    #[prop(into, optional)] disabled: Signal<bool>,
) -> impl IntoView {
    let values: Vec<String> = options.iter().map(|(v, _)| v.clone()).collect();
    let move_by = {
        let values = values.clone();
        move |from: &str, delta: isize| {
            if values.is_empty() {
                return;
            }
            let i = values.iter().position(|v| v == from).unwrap_or(0) as isize;
            let n = values.len() as isize;
            let j = ((i + delta) % n + n) % n;
            on_change.run(values[j as usize].clone());
        }
    };
    view! {
        <div class="seg" role="radiogroup" aria-label=label>
            {options.into_iter().map(|(v, l)| {
                let v1 = v.clone();
                let v2 = v.clone();
                let v3 = v.clone();
                let move_by = move_by.clone();
                view! {
                    <button
                        type="button"
                        role="radio"
                        aria-checked=move || (value.get() == v1).to_string()
                        tabindex=move || if value.get() == v2 { "0" } else { "-1" }
                        disabled=move || disabled.get()
                        on:click={
                            let v = v.clone();
                            move |_| on_change.run(v.clone())
                        }
                        on:keydown=move |ev: web_sys::KeyboardEvent| {
                            let d = match ev.key().as_str() {
                                "ArrowRight" | "ArrowDown" => 1,
                                "ArrowLeft" | "ArrowUp" => -1,
                                _ => return,
                            };
                            ev.prevent_default();
                            move_by(&v3, d);
                            // Move focus to the newly checked radio.
                            if let Some(group) = ev
                                .current_target()
                                .and_then(|t| t.dyn_into::<web_sys::Element>().ok())
                                .and_then(|e| e.parent_element())
                            {
                                if let Ok(Some(n)) = group.query_selector("[role=radio][tabindex='0']") {
                                    let _ = n.dyn_into::<web_sys::HtmlElement>().map(|h| h.focus());
                                }
                            }
                        }
                    >
                        {l}
                    </button>
                }
            }).collect_view()}
        </div>
    }
}

/// Multi-select chip: a toggle button with `aria-pressed`.
#[component]
pub fn ChipSelect(
    #[prop(into)] pressed: Signal<bool>,
    #[prop(into)] on_toggle: Callback<bool>,
    #[prop(into, optional)] class: String,
    #[prop(into, optional)] title: String,
    /// Optional colour dot (CSS color value, e.g. `var(--allow)`).
    #[prop(into, optional)]
    dot: String,
    children: Children,
) -> impl IntoView {
    view! {
        <button
            type="button"
            class=format!("chip {class}")
            title=title
            aria-pressed=move || pressed.get().to_string()
            on:click=move |_| on_toggle.run(!pressed.get_untracked())
        >
            <span class="ck"><Icon name="check" /></span>
            {(!dot.is_empty()).then(|| view! { <i class="sw8" style=format!("background:{dot}")></i> })}
            {children()}
        </button>
    }
}

/// Free-form tag list. Enter or comma adds, Backspace on an empty field removes the last tag.
/// `validate` returns an error message to reject an entry.
#[component]
pub fn TagInput(
    #[prop(into)] tags: RwSignal<Vec<String>>,
    #[prop(into)] label: String,
    #[prop(into, optional)] placeholder: String,
    #[prop(optional)] validate: Option<Callback<String, Option<String>>>,
    /// Called after the list changes through user input.
    #[prop(optional)]
    on_change: Option<Callback<Vec<String>>>,
    #[prop(into, optional)] error: RwSignal<Option<String>>,
) -> impl IntoView {
    let draft = RwSignal::new(String::new());
    let input_ref: NodeRef<leptos::html::Input> = NodeRef::new();
    let notify = move || {
        if let Some(cb) = on_change {
            cb.run(tags.get_untracked());
        }
    };
    let commit = move || {
        let v = draft
            .get_untracked()
            .trim()
            .trim_end_matches(',')
            .trim()
            .to_string();
        if v.is_empty() {
            return;
        }
        if let Some(f) = validate {
            if let Some(msg) = f.run(v.clone()) {
                error.set(Some(msg));
                return;
            }
        }
        if tags.get_untracked().contains(&v) {
            error.set(Some(format!("{v} is already listed.")));
            return;
        }
        error.set(None);
        tags.update(|t| t.push(v));
        draft.set(String::new());
        notify();
    };
    view! {
        <div
            class="taginput"
            on:click=move |_| {
                if let Some(i) = input_ref.get() {
                    let _ = i.focus();
                }
            }
        >
            <For
                each=move || tags.get()
                key=|t| t.clone()
                children=move |t| {
                    let t2 = t.clone();
                    view! {
                        <span class="ti">
                            {t.clone()}
                            <button
                                type="button"
                                aria-label=format!("Remove {t}")
                                on:click=move |ev| {
                                    ev.stop_propagation();
                                    tags.update(|v| v.retain(|x| *x != t2));
                                    notify();
                                }
                            >
                                <Icon name="x" />
                            </button>
                        </span>
                    }
                }
            />
            <input
                node_ref=input_ref
                aria-label=label
                placeholder=placeholder
                autocomplete="off"
                prop:value=move || draft.get()
                on:input=move |ev| {
                    let t = event_target::<HtmlInputElement>(&ev);
                    draft.set(t.value());
                }
                on:keydown=move |ev: web_sys::KeyboardEvent| {
                    match ev.key().as_str() {
                        "Enter" | "," => {
                            ev.prevent_default();
                            commit();
                        }
                        "Backspace" if draft.get_untracked().is_empty() => {
                            if tags.get_untracked().last().is_some() {
                                tags.update(|t| { t.pop(); });
                                notify();
                            }
                        }
                        _ => {}
                    }
                }
                on:blur=move |_| commit()
            />
        </div>
    }
}

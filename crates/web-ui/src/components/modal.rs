//! Modal dialog component

use leptos::prelude::*;
use wasm_bindgen::JsCast;

const FOCUSABLE: &str = "a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex=\"-1\"])";

/// Visible, enabled focusable descendants of `dialog`.
fn focusables(dialog: &web_sys::HtmlElement) -> Vec<web_sys::HtmlElement> {
    let Ok(list) = dialog.query_selector_all(FOCUSABLE) else {
        return Vec::new();
    };
    (0..list.length())
        .filter_map(|i| list.item(i)?.dyn_into::<web_sys::HtmlElement>().ok())
        .filter(|e| e.offset_parent().is_some() && !e.has_attribute("disabled"))
        .collect()
}

/// Keep Tab / Shift+Tab inside `dialog`.
fn trap_tab(ev: &web_sys::KeyboardEvent, dialog: &web_sys::HtmlElement) {
    let items = focusables(dialog);
    let (Some(first), Some(last)) = (items.first(), items.last()) else {
        ev.prevent_default();
        let _ = dialog.focus();
        return;
    };
    let active = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.active_element());
    let on = |el: &web_sys::HtmlElement| active.as_ref().is_some_and(|a| a == el.as_ref());
    let outside = active.as_ref().is_none_or(|a| !dialog.contains(Some(a.as_ref())));
    if ev.shift_key() && (on(first) || outside || active.as_ref().is_some_and(|a| a == dialog.as_ref())) {
        ev.prevent_default();
        let _ = last.focus();
    } else if !ev.shift_key() && (on(last) || outside) {
        ev.prevent_default();
        let _ = first.focus();
    }
}

/// Modal component
#[component]
pub fn Modal(
    #[prop(into)] title: String,
    open: RwSignal<bool>,
    #[prop(optional)] on_close: Option<Callback<()>>,
    #[prop(into, optional)] class: String,
    children: Children,
) -> impl IntoView {
    let class_value = format!("modal {}", class);

    // Store children view immediately since Children is FnOnce
    let children_view = children();

    let dialog_ref: NodeRef<leptos::html::Div> = NodeRef::new();
    let opener = StoredValue::new_local(None::<web_sys::HtmlElement>);
    // Move focus into the dialog on open; give it back to the opener on close.
    Effect::new(move |was_open: Option<bool>| {
        let now = open.get();
        if now && !was_open.unwrap_or(false) {
            let active = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.active_element())
                .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok());
            opener.set_value(active);
            // Next tick: the overlay is still `display:none` until this update is applied.
            gloo_timers::callback::Timeout::new(0, move || {
                if let Some(d) = dialog_ref.get_untracked() {
                    let el: web_sys::HtmlElement = d.into();
                    let target = focusables(&el)
                        .into_iter()
                        .find(|e| !e.class_name().contains("modal-close"))
                        .or_else(|| focusables(&el).into_iter().next())
                        .unwrap_or(el);
                    let _ = target.focus();
                }
            })
            .forget();
        } else if !now && was_open.unwrap_or(false) {
            if let Some(el) = opener.get_value() {
                let _ = el.focus();
            }
            opener.set_value(None);
        }
        now
    });

    view! {
        <div
            class="modal-overlay"
            style=move || if open.get() { "display: flex" } else { "display: none" }
            on:click=move |_| {
                open.set(false);
                if let Some(cb) = on_close {
                    cb.run(());
                }
            }
        >
            <div
                class=class_value
                role="dialog"
                aria-modal="true"
                aria-label=title.clone()
                tabindex="-1"
                node_ref=dialog_ref
                on:keydown=move |ev: web_sys::KeyboardEvent| {
                    if ev.key() == "Escape" {
                        open.set(false);
                    } else if ev.key() == "Tab" {
                        if let Some(d) = dialog_ref.get_untracked() {
                            let el: web_sys::HtmlElement = d.into();
                            trap_tab(&ev, &el);
                        }
                    }
                }
                on:click=move |ev: web_sys::MouseEvent| ev.stop_propagation()
            >
                <div class="modal-header">
                    <h2 class="modal-title">{title.clone()}</h2>
                    <button
                        type="button"
                        class="modal-close"
                        aria-label="Close"
                        on:click=move |_| {
                            open.set(false);
                            if let Some(cb) = on_close {
                                cb.run(());
                            }
                        }
                    >
                        "x"
                    </button>
                </div>
                <div class="modal-body">
                    {children_view}
                </div>
            </div>
        </div>
    }
}

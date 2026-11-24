//! Right-side drawer with focus trap, Esc to close and focus return, plus shared trap helper.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

use super::icon::Icon;

const FOCUSABLE: &str = "button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),a[href],[tabindex='0']";

/// Keep Tab focus inside `container`. Call from a keydown handler.
pub fn trap_tab(ev: &web_sys::KeyboardEvent, container: &web_sys::Element) {
    if ev.key() != "Tab" {
        return;
    }
    let Ok(list) = container.query_selector_all(FOCUSABLE) else {
        return;
    };
    let items: Vec<web_sys::HtmlElement> = (0..list.length())
        .filter_map(|i| list.item(i))
        .filter_map(|n| n.dyn_into::<web_sys::HtmlElement>().ok())
        .filter(|e| e.offset_parent().is_some())
        .collect();
    let (Some(first), Some(last)) = (items.first(), items.last()) else {
        ev.prevent_default();
        return;
    };
    let active = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.active_element());
    let at = |el: &web_sys::HtmlElement| active.as_ref().map(|a| a == el.as_ref()).unwrap_or(false);
    if ev.shift_key() && (at(first) || active.as_ref().map(|a| a == container).unwrap_or(false)) {
        ev.prevent_default();
        let _ = last.focus();
    } else if !ev.shift_key() && at(last) {
        ev.prevent_default();
        let _ = first.focus();
    }
}

/// Remember the focused element when `open` turns true; restore it when it turns false.
pub fn use_focus_return(open: Signal<bool>) {
    let prev = StoredValue::new_local(None::<web_sys::HtmlElement>);
    Effect::new(move |was: Option<bool>| {
        let now = open.get();
        if now && !was.unwrap_or(false) {
            let el = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.active_element())
                .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok());
            prev.set_value(el);
        } else if !now && was.unwrap_or(false) {
            if let Some(el) = prev.get_value() {
                let _ = el.focus();
            }
            prev.set_value(None);
        }
        now
    });
}

/// Drawer. `children` is the body; `footer` (optional) renders in the footer bar.
#[component]
pub fn Drawer(
    open: RwSignal<bool>,
    #[prop(into)] title: Signal<String>,
    children: ChildrenFn,
    #[prop(optional)] footer: Option<ChildrenFn>,
    /// The body does not scroll itself: a `VList` child fills it and scrolls instead.
    #[prop(optional)]
    fill: bool,
) -> impl IntoView {
    use_focus_return(open.into());
    let node: NodeRef<leptos::html::Aside> = NodeRef::new();
    Effect::new(move |_| {
        if open.get() {
            if let Some(el) = node.get() {
                let el: web_sys::HtmlElement = el;
                let _ = el.focus();
            }
        }
    });
    let footer = StoredValue::new(footer);
    view! {
        <Show when=move || open.get()>
            <div class="scrim" on:click=move |_| open.set(false)></div>
            <aside
                class="drawer drawer-trap"
                role="dialog"
                aria-modal="true"
                aria-label=move || title.get()
                tabindex="-1"
                node_ref=node
                on:keydown=move |ev: web_sys::KeyboardEvent| {
                    if ev.key() == "Escape" {
                        ev.stop_propagation();
                        open.set(false);
                    } else if let Some(el) = node.get() {
                        let el: web_sys::Element = el.into();
                        trap_tab(&ev, &el);
                    }
                }
            >
                <div class="drawer-h">
                    <h3>{move || title.get()}</h3>
                    <button type="button" class="icon-btn" aria-label="Close" on:click=move |_| open.set(false)>
                        <Icon name="x" />
                    </button>
                </div>
                <div class=if fill { "drawer-b fill" } else { "drawer-b" }>{children()}</div>
                {move || footer.get_value().map(|f| view! { <div class="drawer-f">{f()}</div> })}
            </aside>
        </Show>
    }
}

//! Dropdown action menu (`role="menu"`): Esc and outside click close it, arrows move focus.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

use super::icon::Icon;

#[derive(Clone, Copy)]
struct MenuCtx {
    open: RwSignal<bool>,
}

fn items(menu: &web_sys::Element) -> Vec<web_sys::HtmlElement> {
    let Ok(list) = menu.query_selector_all("[role=menuitem]") else {
        return Vec::new();
    };
    (0..list.length())
        .filter_map(|i| list.item(i)?.dyn_into::<web_sys::HtmlElement>().ok())
        .collect()
}

/// Button that opens a menu of `MenuItem`s.
#[component]
pub fn Menu(#[prop(into)] label: String, children: ChildrenFn) -> impl IntoView {
    let open = RwSignal::new(false);
    provide_context(MenuCtx { open });
    let menu: NodeRef<leptos::html::Div> = NodeRef::new();
    let btn: NodeRef<leptos::html::Button> = NodeRef::new();
    Effect::new(move |_| {
        if open.get() {
            gloo_timers::callback::Timeout::new(0, move || {
                if let Some(m) = menu.get_untracked() {
                    let m: web_sys::Element = m.into();
                    if let Some(first) = items(&m).first() {
                        let _ = first.focus();
                    }
                }
            })
            .forget();
        }
    });
    let close = move || {
        open.set(false);
        if let Some(b) = btn.get_untracked() {
            let _ = b.focus();
        }
    };
    // Esc closes the menu even when focus has dropped to the page (an item went busy).
    let esc = StoredValue::new_local(Some(window_event_listener(
        leptos::ev::keydown,
        move |ev: web_sys::KeyboardEvent| {
            if open.try_get_untracked().unwrap_or(false) && ev.key() == "Escape" {
                close();
            }
        },
    )));
    on_cleanup(move || {
        esc.try_update_value(|h| {
            if let Some(h) = h.take() {
                h.remove();
            }
        });
    });
    view! {
        <div class="menu-wrap">
            <button type="button" class="btn" aria-haspopup="menu" node_ref=btn
                aria-expanded=move || open.get().to_string()
                on:click=move |_| open.update(|o| *o = !*o)>
                {label}
                <svg class="i" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 6 4 4 4-4"/></svg>
            </button>
            <Show when=move || open.get()>
                <div class="menu-scrim" on:click=move |_| open.set(false)></div>
                <div class="menu" role="menu" node_ref=menu
                    on:keydown=move |ev: web_sys::KeyboardEvent| {
                        let key = ev.key();
                        if key == "Escape" {
                            ev.stop_propagation();
                            close();
                        } else if key == "ArrowDown" || key == "ArrowUp" || key == "Home" || key == "End" {
                            ev.prevent_default();
                            let Some(m) = menu.get_untracked() else { return };
                            let m: web_sys::Element = m.into();
                            let list = items(&m);
                            if list.is_empty() { return }
                            let active = web_sys::window().and_then(|w| w.document()).and_then(|d| d.active_element());
                            let cur = list.iter().position(|e| active.as_ref().is_some_and(|a| a == e.as_ref()));
                            let n = list.len();
                            let next = match (key.as_str(), cur) {
                                ("Home", _) => 0,
                                ("End", _) => n - 1,
                                ("ArrowDown", Some(i)) => (i + 1) % n,
                                ("ArrowDown", None) => 0,
                                (_, Some(i)) => (i + n - 1) % n,
                                (_, None) => n - 1,
                            };
                            let _ = list[next].focus();
                        } else if key == "Tab" {
                            open.set(false);
                        }
                    }>
                    {children()}
                </div>
            </Show>
        </div>
    }
}

/// One entry of a `Menu`. Selecting it closes the menu unless `keep_open`.
#[component]
pub fn MenuItem(
    on_select: Callback<()>,
    #[prop(into, optional)] disabled: Signal<bool>,
    #[prop(optional)] keep_open: bool,
    #[prop(into, optional)] icon: String,
    children: Children,
) -> impl IntoView {
    let ctx = use_context::<MenuCtx>();
    view! {
        <button type="button" role="menuitem" class="menu-item" aria-disabled=move || disabled.get().to_string()
            on:click=move |_| {
                if disabled.get_untracked() {
                    return;
                }
                if !keep_open {
                    if let Some(c) = ctx { c.open.set(false); }
                }
                on_select.run(());
            }>
            {(!icon.is_empty()).then(|| view! { <Icon name=icon.clone() /> })}
            {children()}
        </button>
    }
}

/// Divider between menu entries.
#[component]
pub fn MenuDivider() -> impl IntoView {
    view! { <div class="menu-div" role="separator"></div> }
}

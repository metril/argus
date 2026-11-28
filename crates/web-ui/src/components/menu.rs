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

/// Keep the open menu 8px inside the viewport: it starts at the trigger's left edge, slides left
/// when it would cross the right edge, and opens upwards when there is no room below.
fn place(menu: &web_sys::Element) {
    const GAP: f64 = 8.0;
    let Some(win) = web_sys::window() else { return };
    let (vw, vh) = (
        win.inner_width()
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        win.inner_height()
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
    );
    let Some(wrap) = menu.parent_element() else {
        return;
    };
    let (w, m) = (
        wrap.get_bounding_client_rect(),
        menu.get_bounding_client_rect(),
    );
    let Ok(el) = menu.clone().dyn_into::<web_sys::HtmlElement>() else {
        return;
    };
    let style = el.style();
    // Horizontal: left edge of the trigger, then clamp into [GAP, vw - GAP - width].
    let left = w.left().min(vw - GAP - m.width()).max(GAP);
    let _ = style.set_property("left", &format!("{}px", left - w.left()));
    let _ = style.set_property("right", "auto");
    // Vertical: below the trigger, or above it when that does not fit and above does.
    if w.bottom() + 4.0 + m.height() > vh - GAP && w.top() - 4.0 - m.height() >= GAP {
        let _ = style.set_property("top", "auto");
        let _ = style.set_property("bottom", "calc(100% + 4px)");
    }
}

/// Button that opens a menu of `MenuItem`s.
#[component]
pub fn Menu(
    #[prop(into)] label: String,
    /// Show this icon in a compact square button instead of the label (the label stays the
    /// accessible name).
    #[prop(into, optional)]
    icon: String,
    children: ChildrenFn,
) -> impl IntoView {
    let open = RwSignal::new(false);
    provide_context(MenuCtx { open });
    let menu: NodeRef<leptos::html::Div> = NodeRef::new();
    let btn: NodeRef<leptos::html::Button> = NodeRef::new();
    Effect::new(move |_| {
        if open.get() {
            gloo_timers::callback::Timeout::new(0, move || {
                if let Some(m) = menu.get_untracked() {
                    let m: web_sys::Element = m.into();
                    place(&m);
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
            <button type="button" class=if icon.is_empty() { "btn" } else { "icon-btn sm" } aria-haspopup="menu" node_ref=btn
                aria-label=if icon.is_empty() { None } else { Some(label.clone()) }
                aria-expanded=move || open.get().to_string()
                on:click=move |ev: web_sys::MouseEvent| {
                    ev.stop_propagation();
                    open.update(|o| *o = !*o)
                }>
                {if icon.is_empty() {
                    view! {
                        {label.clone()}
                        <svg class="i" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 6 4 4 4-4"/></svg>
                    }.into_any()
                } else {
                    view! { <Icon name=icon.clone() /> }.into_any()
                }}
            </button>
            <Show when=move || open.get()>
                <div class="menu-scrim" on:click=move |_| close()></div>
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

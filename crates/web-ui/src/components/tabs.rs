//! Underline tab bar (`role="tablist"`), arrow-key navigation, synced to `?tab=` so Back works.

use leptos::prelude::*;
use wasm_bindgen::{closure::Closure, JsCast};

/// Record a tab change in the history (`?tab=id`, or no query for the default tab) so Back works.
pub fn push_tab(id: &str, is_default: bool) {
    if let Some(w) = web_sys::window() {
        if let (Ok(path), Ok(h)) = (w.location().pathname(), w.history()) {
            let url = if is_default {
                path
            } else {
                format!("{path}?tab={id}")
            };
            let _ = h.push_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&url));
        }
    }
}

/// `items`: `(id, label, count)`. The first item is the default and leaves no query value.
#[component]
pub fn Tabs(
    #[prop(into)] items: Signal<Vec<(String, String, Option<usize>)>>,
    active: RwSignal<String>,
    #[prop(into)] label: String,
) -> impl IntoView {
    let from_url = move || {
        let search = web_sys::window()
            .and_then(|w| w.location().search().ok())
            .unwrap_or_default();
        let t = search
            .trim_start_matches('?')
            .split('&')
            .find_map(|kv| kv.strip_prefix("tab="))
            .map(str::to_string);
        let ids = items.get_untracked();
        match t {
            Some(t) if ids.iter().any(|i| i.0 == t) => t,
            _ => ids.first().map(|i| i.0.clone()).unwrap_or_default(),
        }
    };
    active.set(from_url());
    // Back / Forward restore the tab.
    let listener = StoredValue::new_local(None::<Closure<dyn FnMut()>>);
    if let Some(w) = web_sys::window() {
        let cb = Closure::<dyn FnMut()>::new(move || active.set(from_url()));
        let _ = w.add_event_listener_with_callback("popstate", cb.as_ref().unchecked_ref());
        listener.set_value(Some(cb));
    }
    on_cleanup(move || {
        if let Some(w) = web_sys::window() {
            listener.try_with_value(|cb| {
                if let Some(cb) = cb {
                    let _ = w.remove_event_listener_with_callback(
                        "popstate",
                        cb.as_ref().unchecked_ref(),
                    );
                }
            });
        }
    });
    let select = move |id: String| {
        if active.get_untracked() == id {
            return;
        }
        let first = items.get_untracked().first().map(|i| i.0.clone());
        push_tab(&id, first.as_deref() == Some(id.as_str()));
        active.set(id);
    };
    let list: NodeRef<leptos::html::Div> = NodeRef::new();
    view! {
        <div class="tabs" role="tablist" aria-label=label node_ref=list
            on:keydown=move |ev: web_sys::KeyboardEvent| {
                let key = ev.key();
                if key != "ArrowRight" && key != "ArrowLeft" { return }
                let v = items.get_untracked();
                let Some(i) = v.iter().position(|t| t.0 == active.get_untracked()) else { return };
                let n = v.len();
                let j = if key == "ArrowRight" { (i + 1) % n } else { (i + n - 1) % n };
                ev.prevent_default();
                select(v[j].0.clone());
                if let Some(l) = list.get_untracked() {
                    if let Ok(Some(b)) = l.query_selector(&format!("#tab-{}", v[j].0)) {
                        if let Ok(b) = b.dyn_into::<web_sys::HtmlElement>() { let _ = b.focus(); }
                    }
                }
            }>
            {move || items.get().into_iter().map(|(id, name, n)| {
                let (id1, id2, id3, id4) = (id.clone(), id.clone(), id.clone(), id.clone());
                view! {
                    <button type="button" role="tab" class="tab" id=format!("tab-{id1}")
                        aria-controls=format!("panel-{id2}")
                        aria-selected=move || (active.get() == id3).to_string()
                        tabindex=move || if active.get() == id4 { "0" } else { "-1" }
                        on:click=move |_| select(id.clone())>
                        {name}
                        {n.map(|n| view! { <span class="n">{n}</span> })}
                    </button>
                }
            }).collect_view()}
        </div>
    }
}

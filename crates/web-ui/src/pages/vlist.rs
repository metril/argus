//! Windowed, cursor-paged list used by Site rules and Filter lists: fixed row height with
//! spacer padding, only rows near the viewport in the DOM, next page fetched near the bottom.
//! Also URL-query persistence helpers (replaceState).

use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

use leptos::prelude::*;

use crate::api::ApiError;

/// `(items, next_cursor, total)` of one fetched page.
pub type FetchResult<T> = Result<(Vec<T>, Option<String>, usize), ApiError>;
pub type FetchFut<T> = Pin<Box<dyn Future<Output = FetchResult<T>>>>;
/// `fetch(cursor, from)`.
pub type Fetcher<T> = Rc<dyn Fn(Option<String>, Option<String>) -> FetchFut<T>>;

/// Loaded rows plus paging state.
pub struct Feed<T: Send + Sync + 'static> {
    pub items: RwSignal<Vec<T>>,
    pub next: RwSignal<Option<String>>,
    pub total: RwSignal<usize>,
    pub loading: RwSignal<bool>,
    /// Message of the last failed fetch (cleared by the next success or retry).
    pub error: RwSignal<Option<String>>,
    /// Bumped when the list restarts so the scroller jumps to the top.
    pub tok: RwSignal<u32>,
    gen: RwSignal<u64>,
    fetch: StoredValue<Fetcher<T>, LocalStorage>,
}
impl<T: Send + Sync + 'static> Clone for Feed<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T: Send + Sync + 'static> Copy for Feed<T> {}

impl<T: Clone + Send + Sync + 'static> Feed<T> {
    pub fn new(fetch: Fetcher<T>) -> Self {
        Self {
            items: RwSignal::new(Vec::new()),
            next: RwSignal::new(None),
            total: RwSignal::new(0),
            loading: RwSignal::new(false),
            error: RwSignal::new(None),
            tok: RwSignal::new(0),
            gen: RwSignal::new(0),
            fetch: StoredValue::new_local(fetch),
        }
    }

    /// Start over (optionally seeking to `from`). If `keep_if_empty` and the seek returns
    /// nothing, the current rows stay and `on_done(0)` is called.
    pub fn reload(
        &self,
        from: Option<String>,
        keep_if_empty: bool,
        on_done: Option<Callback<usize>>,
    ) {
        let me = *self;
        let g = me.gen.get_untracked() + 1;
        me.gen.set(g);
        me.loading.set(true);
        let fut = (me.fetch.get_value())(None, from);
        wasm_bindgen_futures::spawn_local(async move {
            let r = fut.await;
            if me.gen.get_untracked() != g {
                return;
            }
            me.loading.set(false);
            if let Err(e) = &r {
                me.error.set(Some(e.to_string()));
            }
            if let Ok((items, next, total)) = r {
                me.error.set(None);
                let n = items.len();
                if n == 0 && keep_if_empty {
                    if let Some(cb) = on_done {
                        cb.run(0);
                    }
                    return;
                }
                me.items.set(items);
                me.next.set(next);
                me.total.set(total);
                me.tok.update(|t| *t += 1);
                if let Some(cb) = on_done {
                    cb.run(n);
                }
            }
        });
    }

    /// Retry after a failed fetch: restart when nothing is loaded, else fetch the next page.
    pub fn retry(&self) {
        let had_items = self.items.with_untracked(|v| !v.is_empty());
        self.error.set(None);
        // A superseded in-flight fetch must not leave `loading` stuck and block the retry.
        self.loading.set(false);
        if had_items {
            self.more();
        } else {
            self.reload(None, false, None);
        }
    }

    /// Fetch the next page, if any.
    pub fn more(&self) {
        let me = *self;
        let Some(cursor) = me.next.get_untracked() else {
            return;
        };
        // After a failure, paging resumes only through `retry` (no hot loop on a dead endpoint).
        if me.loading.get_untracked() || me.error.get_untracked().is_some() {
            return;
        }
        let g = me.gen.get_untracked();
        me.loading.set(true);
        let fut = (me.fetch.get_value())(Some(cursor), None);
        wasm_bindgen_futures::spawn_local(async move {
            let r = fut.await;
            if me.gen.get_untracked() != g {
                return;
            }
            me.loading.set(false);
            if let Err(e) = &r {
                me.error.set(Some(e.to_string()));
            }
            if let Ok((items, next, total)) = r {
                me.error.set(None);
                me.items.update(|v| v.extend(items));
                me.next.set(next);
                me.total.set(total);
            }
        });
    }

    #[allow(unused_assignments)]
    /// Re-fetch everything currently loaded in place (scroll position kept).
    pub fn refresh_loaded(&self) {
        let me = *self;
        let want = me.items.get_untracked().len().max(1);
        let g = me.gen.get_untracked() + 1;
        me.gen.set(g);
        let fetch = me.fetch.get_value();
        wasm_bindgen_futures::spawn_local(async move {
            let (mut all, mut cursor, mut total) = (Vec::new(), None::<String>, None::<usize>);
            loop {
                match fetch(cursor.clone(), None).await {
                    Ok((items, next, t)) => {
                        all.extend(items);
                        total = Some(t);
                        cursor = next;
                    }
                    Err(_) => return,
                }
                if cursor.is_none() || all.len() >= want {
                    break;
                }
            }
            if me.gen.get_untracked() != g {
                return;
            }
            me.items.set(all);
            me.next.set(cursor);
            me.total.set(total.unwrap_or(0));
            me.error.set(None);
            me.loading.set(false);
        });
    }
}

/// The row with this id, if loaded.
pub fn find_by_id<'a, T>(items: &'a [T], id: &str, id_of: fn(&T) -> &str) -> Option<&'a T> {
    items.iter().find(|x| id_of(x) == id)
}

/// Live view of one row: follows the newest copy of the item with `initial`'s id, so a row keyed
/// by id updates in place (no remount, scroll position kept). If the item is gone it keeps the
/// initial value until its row is removed.
pub fn live_row<T>(items: impl Into<Signal<Vec<T>>>, initial: T, id_of: fn(&T) -> &str) -> Signal<T>
where
    T: Clone + Send + Sync + 'static,
{
    let items: Signal<Vec<T>> = items.into();
    let id = id_of(&initial).to_string();
    Signal::derive(move || {
        items
            .with(|v| find_by_id(v, &id, id_of).cloned())
            .unwrap_or_else(|| initial.clone())
    })
}

#[cfg(test)]
mod row_tests {
    use super::*;

    #[derive(Clone)]
    struct R(String, u32);
    fn id(r: &R) -> &str {
        &r.0
    }

    #[test]
    fn a_row_follows_edits_by_id_and_keeps_its_value_when_dropped() {
        let items = RwSignal::new(vec![R("a".into(), 1), R("b".into(), 2)]);
        let b = live_row(items, R("b".into(), 2), id);
        assert_eq!(b.get().1, 2);
        items.update(|v| v[1].1 = 5);
        assert_eq!(b.get().1, 5, "edit shows without a new key");
        items.update(|v| v.insert(0, R("z".into(), 9)));
        assert_eq!(b.get().1, 5, "position changes do not matter");
        items.set(vec![]);
        assert_eq!(
            b.get().1,
            2,
            "gone: initial value stays until the row is removed"
        );
        assert!(find_by_id(&[R("a".into(), 1)], "q", id).is_none());
    }
}

/// Windowed scroller. `render` makes one row; rows must be direct children of the wrapper
/// (their height is forced to `row_h` by CSS via `--rowh`).
#[component]
pub fn VList<T>(
    items: RwSignal<Vec<T>>,
    #[prop(into)] row_h: Signal<f64>,
    key: fn(&T) -> String,
    render: Callback<T, AnyView>,
    on_end: Callback<()>,
    on_anchor: Callback<usize>,
    #[prop(into)] reset: Signal<u32>,
    #[prop(into)] label: String,
    /// Render rows inside `<ul class="flist">` (for `<li>` rows) instead of a `<div>`.
    #[prop(optional)]
    as_list: bool,
    /// Feed error to show with a Retry button.
    #[prop(optional)]
    error: Option<RwSignal<Option<String>>>,
    #[prop(optional)] on_retry: Option<Callback<()>>,
) -> impl IntoView
where
    T: Clone + Send + Sync + 'static,
{
    let node: NodeRef<leptos::html::Div> = NodeRef::new();
    let top = RwSignal::new(0.0f64);
    let height = RwSignal::new(560.0f64);

    let check_end = move || {
        if let Some(el) = node.get_untracked() {
            let el: web_sys::HtmlElement = el.into();
            let (t, h, s) = (
                el.scroll_top() as f64,
                el.client_height() as f64,
                el.scroll_height() as f64,
            );
            top.set(t);
            height.set(h.max(100.0));
            if t + h >= s - 160.0 {
                on_end.run(());
            }
        }
    };
    // After rows arrive, a short list may still not fill the viewport: ask for more.
    Effect::new(move |_| {
        items.track();
        check_end();
    });
    Effect::new(move |_| {
        reset.track();
        if let Some(el) = node.get() {
            let el: web_sys::HtmlElement = el.into();
            el.set_scroll_top(0);
            top.set(0.0);
        }
    });

    // Window of rows to keep in the DOM: ~1 screen above and below the viewport.
    let range = Memo::new(move |_| {
        let rh = row_h.get();
        let n = items.with(|v| v.len());
        let first = (top.get() / rh) as usize;
        let vis = (height.get() / rh).ceil() as usize + 1;
        let start = first.saturating_sub(vis) / 8 * 8;
        let end = (first + 2 * vis).div_ceil(8) * 8;
        (start.min(n), end.min(n))
    });
    Effect::new(move |_| {
        let rh = row_h.get_untracked();
        on_anchor.run((top.get() / rh) as usize);
    });

    let rows = move || {
        let (s, e) = range.get();
        items.with(|v| v[s..e].to_vec())
    };
    let pad = move || {
        let (s, e) = range.get();
        let n = items.with(|v| v.len());
        let rh = row_h.get();
        format!(
            "padding-top:{}px;padding-bottom:{}px",
            s as f64 * rh,
            (n - e) as f64 * rh
        )
    };
    let body = move || {
        view! {
            <For each=rows key=move |t| key(t) children=move |t| render.run(t) />
        }
    };

    let banner = move || {
        error.and_then(|e| e.get()).map(|msg| {
            view! {
                <div class="vlist-err" role="alert">
                    <span>{format!("Failed to load: {msg}")}</span>
                    <button type="button" class="btn sm" on:click=move |_| {
                        if let Some(cb) = on_retry { cb.run(()); }
                    }>"Retry"</button>
                </div>
            }
        })
    };

    view! {
        {banner}
        <div
            class="vlist"
            node_ref=node
            tabindex="0"
            role="region"
            aria-label=label
            style=move || format!("--rowh:{}px", row_h.get())
            on:scroll=move |_| check_end()
        >
            {if as_list {
                view! { <ul class="flist" style=pad>{body}</ul> }.into_any()
            } else {
                view! { <div style=pad>{body}</div> }.into_any()
            }}
        </div>
    }
}

/// Scroll box for tables and chip lists whose rows have no fixed height: asks the feed for the
/// next page near the bottom and shows its error and a loaded-of-total line.
#[component]
pub fn Scroller<T>(
    feed: Feed<T>,
    #[prop(optional)] class: &'static str,
    children: ChildrenFn,
) -> impl IntoView
where
    T: Clone + Send + Sync + 'static,
{
    let node: NodeRef<leptos::html::Div> = NodeRef::new();
    let check_end = move || {
        if let Some(el) = node.get_untracked() {
            let el: web_sys::HtmlElement = el.into();
            if (el.scroll_top() + el.client_height()) as f64 >= el.scroll_height() as f64 - 160.0 {
                feed.more();
            }
        }
    };
    // A short first page may not fill the box: keep asking until it does or the list ends.
    Effect::new(move |_| {
        feed.items.track();
        check_end();
    });
    // The list restarted (new filter, reload): back to the top.
    Effect::new(move |_| {
        feed.tok.track();
        if let Some(el) = node.get() {
            let el: web_sys::HtmlElement = el.into();
            el.set_scroll_top(0);
        }
    });
    view! {
        {move || feed.error.get().map(|msg| view! {
            <div class="vlist-err" role="alert">
                <span>{format!("Failed to load: {msg}")}</span>
                <button type="button" class="btn sm" on:click=move |_| feed.retry()>"Retry"</button>
            </div>
        })}
        <div class=format!("scrollbox {class}") node_ref=node tabindex="0" on:scroll=move |_| check_end()>
            {children()}
        </div>
        <div class="vfoot" aria-live="polite">
            <span>{move || if feed.loading.get() { "Loading...".to_string() } else { format!("{} loaded", feed.items.with(|v| v.len())) }}</span>
            <span>{move || if feed.next.get().is_some() { "scroll for more" } else { "end of list" }}</span>
        </div>
    }
}

/// True under the 760px breakpoint.
pub fn is_narrow() -> bool {
    web_sys::window()
        .and_then(|w| w.inner_width().ok())
        .and_then(|v| v.as_f64())
        .map(|w| w < 760.0)
        .unwrap_or(false)
}

fn dec(s: &str) -> String {
    js_sys::decode_uri_component(s)
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_else(|| s.to_string())
}

/// Read a key of the page's query string.
pub fn query_get(key: &str) -> Option<String> {
    let search = web_sys::window()?.location().search().ok()?;
    search
        .trim_start_matches('?')
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| dec(&v.replace('+', " ")))
        .filter(|v| !v.is_empty())
}

/// Set (`Some`) or remove (`None`) keys of the query string with `history.replaceState`,
/// leaving every other key and the path alone.
pub fn query_set(pairs: &[(&str, Option<String>)]) {
    let Some(w) = web_sys::window() else { return };
    let loc = w.location();
    let (Ok(path), Ok(search), Ok(hash)) = (loc.pathname(), loc.search(), loc.hash()) else {
        return;
    };
    let mut kept: Vec<(String, String)> = search
        .trim_start_matches('?')
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .filter(|(k, _)| !pairs.iter().any(|(pk, _)| pk == k))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    for (k, v) in pairs {
        if let Some(v) = v.as_ref().filter(|v| !v.is_empty()) {
            kept.push((k.to_string(), String::from(js_sys::encode_uri_component(v))));
        }
    }
    let q = kept
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let url = if q.is_empty() {
        format!("{path}{hash}")
    } else {
        format!("{path}?{q}{hash}")
    };
    if let Ok(h) = w.history() {
        let _ = h.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&url));
    }
}

/// Letters for the A-Z rail.
pub const LETTERS: [char; 26] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z',
];

/// Rail letters with no rows, from the server's `counts.letters` (first characters present).
/// An empty list means the server did not say, so nothing is disabled.
pub fn dead_letters(letters: &[String]) -> Vec<char> {
    if letters.is_empty() {
        return Vec::new();
    }
    LETTERS
        .iter()
        .copied()
        .filter(|l| {
            !letters
                .iter()
                .any(|s| s.chars().next().is_some_and(|c| c.eq_ignore_ascii_case(l)))
        })
        .collect()
}

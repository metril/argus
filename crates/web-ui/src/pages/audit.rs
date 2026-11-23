//! Admin: audit log, newest first, filtered on the server, infinite scroll.

use std::rc::Rc;

use gloo_timers::callback::Timeout;
use leptos::prelude::*;

use super::vlist::{Feed, Fetcher, Scroller};
use crate::api::admin::AuditEntry;
use crate::api::ApiClient;
use crate::components::{Icon, Layout, Pill, RequireAdmin, Segmented};
use crate::state::use_app_state;
use crate::utils::fmt_datetime;

/// RFC 3339 lower bound for a window like `1h`, `24h`, `7d`, `30d`; empty for all time.
fn since_of(window: &str) -> String {
    let hours = match window {
        "1h" => 1.0,
        "24h" => 24.0,
        "7d" => 168.0,
        "30d" => 720.0,
        _ => return String::new(),
    };
    let ms = js_sys::Date::now() - hours * 3_600_000.0;
    js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(ms))
        .to_iso_string()
        .as_string()
        .unwrap_or_default()
}

/// A text filter that reaches the server 300 ms after typing stops.
fn debounced(
    raw: RwSignal<String>,
    out: RwSignal<String>,
    t: StoredValue<Option<Timeout>, LocalStorage>,
) -> impl Fn(web_sys::Event) {
    move |ev| {
        let v = event_target_value(&ev);
        raw.set(v.clone());
        t.set_value(Some(Timeout::new(300, move || out.set(v))));
    }
}

#[component]
pub fn AuditPage() -> impl IntoView {
    view! { <Layout><RequireAdmin><AuditInner /></RequireAdmin></Layout> }
}

#[component]
fn AuditInner() -> impl IntoView {
    let app = use_app_state();
    let outcome = RwSignal::new(String::new());
    let window = RwSignal::new(String::new());
    let (q_raw, q) = (RwSignal::new(String::new()), RwSignal::new(String::new()));
    let (actor_raw, actor) = (RwSignal::new(String::new()), RwSignal::new(String::new()));
    let (action_raw, action) = (RwSignal::new(String::new()), RwSignal::new(String::new()));
    let (tq, ta, tc) = (
        StoredValue::new_local(None::<Timeout>),
        StoredValue::new_local(None::<Timeout>),
        StoredValue::new_local(None::<Timeout>),
    );

    let fetch: Fetcher<AuditEntry> = Rc::new(move |cursor, _| {
        let app = app.clone();
        let (o, a, ac, qv, w) = (
            outcome.get_untracked(),
            actor.get_untracked(),
            action.get_untracked(),
            q.get_untracked(),
            window.get_untracked(),
        );
        Box::pin(async move {
            match ApiClient::new()
                .list_audit(cursor.as_deref(), &o, &a, &ac, &qv, &since_of(&w))
                .await
            {
                Ok(r) => Ok((r.items, r.next_cursor, r.total)),
                Err(e) => {
                    app.error(format!("Failed to load audit log: {e}"));
                    Err(e)
                }
            }
        })
    });
    let feed = Feed::new(fetch);
    Effect::new(move |_| {
        outcome.track();
        actor.track();
        action.track();
        q.track();
        window.track();
        feed.reload(None, false, None);
    });

    view! {
        <div class="toolbar">
            <div class="search grow">
                <Icon name="search" />
                <label class="sr" for="audQ">"Search audit log"</label>
                <input class="input mono" id="audQ" placeholder="actor, route, target or IP" prop:value=move || q_raw.get() on:input=debounced(q_raw, q, tq) />
            </div>
            <input class="input" aria-label="Actor" placeholder="Actor (name or id)" prop:value=move || actor_raw.get() on:input=debounced(actor_raw, actor, ta) />
            <input class="input mono" aria-label="Action" placeholder="Action, e.g. DELETE /lists" prop:value=move || action_raw.get() on:input=debounced(action_raw, action, tc) />
            <select class="select" aria-label="Time window" prop:value=move || window.get() on:change=move |ev| window.set(event_target_value(&ev))>
                <option value="">"All time"</option>
                <option value="1h">"Last hour"</option>
                <option value="24h">"Last 24 hours"</option>
                <option value="7d">"Last 7 days"</option>
                <option value="30d">"Last 30 days"</option>
            </select>
            <Segmented
                label="Result"
                options=vec![("".into(), "All".into()), ("success".into(), "Success".into()), ("denied".into(), "Denied".into()), ("error".into(), "Error".into())]
                value=outcome
                on_change=Callback::new(move |v| outcome.set(v))
            />
        </div>
        <div class="card">
            <Scroller feed=feed class="tbl-wrap">
                <table class="tbl">
                    <thead><tr><th>"Time"</th><th>"Actor"</th><th>"Action"</th><th>"Target"</th><th>"IP"</th><th>"Result"</th></tr></thead>
                    <tbody>
                        <For each=move || feed.items.get() key=|e| e.id.clone() children=move |e| {
                            let who = e.actor_name.clone().unwrap_or_else(|| e.actor_type.clone());
                            let ok = e.outcome == "success";
                            view! {
                                <tr>
                                    <td class="mono num dim">{fmt_datetime(&e.at)}</td>
                                    <td>{who}</td>
                                    <td class="mono">{format!("{} {}", e.method, e.route)}</td>
                                    <td class="mono" style="white-space:normal;min-width:160px">{e.target.clone().unwrap_or_default()}</td>
                                    <td class="mono dim">{e.ip.clone().unwrap_or_default()}</td>
                                    <td><Pill kind=if ok { "ok" } else { "failed" } text=if ok { "ok".to_string() } else { e.outcome.clone() } /></td>
                                </tr>
                            }
                        } />
                    </tbody>
                </table>
                <Show when=move || feed.items.with(|v| v.is_empty()) && !feed.loading.get()>
                    <div class="empty"><b>"No entries match"</b>"Clear a filter to see more."</div>
                </Show>
            </Scroller>
        </div>
    }
}

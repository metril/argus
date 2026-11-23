//! Admin: audit log with numbered pages.

use leptos::prelude::*;

use crate::api::admin::AuditEntry;
use crate::api::ApiClient;
use crate::components::{ChipSelect, Icon, Layout, Pill, RequireAdmin, Segmented};
use crate::state::use_app_state;
use crate::utils::fmt_datetime;

const PAGE: usize = 100;

fn area(route: &str) -> String {
    route
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

#[component]
pub fn AuditPage() -> impl IntoView {
    view! { <Layout><RequireAdmin><AuditInner /></RequireAdmin></Layout> }
}

#[component]
fn AuditInner() -> impl IntoView {
    let app = use_app_state();
    let entries = RwSignal::new(Vec::<AuditEntry>::new());
    let total = RwSignal::new(0usize);
    let page = RwSignal::new(1u32);
    let outcome = RwSignal::new(String::new());
    let search = RwSignal::new(String::new());
    let actor = RwSignal::new(String::new());
    let hidden_areas = RwSignal::new(Vec::<String>::new());

    Effect::new(move |_| {
        let (p, o) = (page.get(), outcome.get());
        let app = app.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().list_audit(p, &o, "", "").await {
                Ok(r) => {
                    total.set(r.total);
                    entries.set(r.items);
                }
                Err(e) => app.error(format!("Failed to load audit log: {e}")),
            }
        });
    });

    let actor_name = |e: &AuditEntry| e.actor_name.clone().unwrap_or_else(|| e.actor_type.clone());
    let actors = Memo::new(move |_| {
        let mut v: Vec<String> = entries.read().iter().map(actor_name).collect();
        v.sort();
        v.dedup();
        v
    });
    let areas = Memo::new(move |_| {
        let mut v: Vec<String> = entries.read().iter().map(|e| area(&e.route)).collect();
        v.sort();
        v.dedup();
        v
    });
    let visible = Signal::derive(move || {
        let q = search.get().to_lowercase();
        let a = actor.get();
        let h = hidden_areas.get();
        entries
            .get()
            .into_iter()
            .filter(|e| {
                (a.is_empty() || actor_name(e) == a)
                    && !h.contains(&area(&e.route))
                    && (q.is_empty()
                        || format!(
                            "{} {} {} {}",
                            e.method,
                            e.route,
                            e.target.clone().unwrap_or_default(),
                            e.ip.clone().unwrap_or_default()
                        )
                        .to_lowercase()
                        .contains(&q))
            })
            .collect::<Vec<_>>()
    });
    let pages = move || total.get().max(1).div_ceil(PAGE);

    view! {
        <div class="toolbar">
            <div class="search grow">
                <Icon name="search" />
                <label class="sr" for="audQ">"Search audit log"</label>
                <input class="input mono" id="audQ" placeholder="action, target or IP" prop:value=move || search.get() on:input=move |ev| search.set(event_target_value(&ev)) />
            </div>
            <select class="select" aria-label="Actor" prop:value=move || actor.get() on:change=move |ev| actor.set(event_target_value(&ev))>
                <option value="">"All actors"</option>
                <For each=move || actors.get() key=|a| a.clone() children=|a| { let v = a.clone(); view! { <option value=v>{a}</option> } } />
            </select>
            <Segmented
                label="Result"
                options=vec![("".into(), "All".into()), ("success".into(), "Success".into()), ("denied".into(), "Denied".into()), ("error".into(), "Error".into())]
                value=outcome
                on_change=Callback::new(move |v| { outcome.set(v); page.set(1); })
            />
        </div>
        <div class="chips" role="group" aria-label="Area">
            <For each=move || areas.get() key=|a| a.clone() children=move |a| {
                let a1 = a.clone();
                let a2 = a.clone();
                view! {
                    <ChipSelect
                        class="mono"
                        pressed=Signal::derive(move || !hidden_areas.read().contains(&a1))
                        on_toggle=Callback::new(move |on: bool| hidden_areas.update(|h| { h.retain(|x| *x != a2); if !on { h.push(a2.clone()); } }))
                    >{a}</ChipSelect>
                }
            } />
        </div>
        <div class="card">
            <div class="tbl-wrap">
                <table class="tbl">
                    <thead><tr><th>"Time"</th><th>"Actor"</th><th>"Action"</th><th>"Target"</th><th>"IP"</th><th>"Result"</th></tr></thead>
                    <tbody>
                        <For each=move || visible.get() key=|e| e.id.clone() children=move |e| {
                            let who = actor_name(&e);
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
            </div>
            <Show when=move || visible.get().is_empty()>
                <div class="empty"><b>"No entries match"</b>"Clear a filter to see more."</div>
            </Show>
            <div class="pager">
                <span class="num">{move || format!("{} entries", total.get())}</span>
                <div class="r">
                    <button class="btn sm" type="button" disabled={move || page.get() <= 1} on:click=move |_| page.update(|p| *p -= 1)>"Previous"</button>
                    <span class="num">{move || format!("Page {} of {}", page.get(), pages())}</span>
                    <button class="btn sm" type="button" disabled={move || page.get() as usize >= pages()} on:click=move |_| page.update(|p| *p += 1)>"Next"</button>
                </div>
            </div>
        </div>
    }
}

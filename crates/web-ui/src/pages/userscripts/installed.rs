//! Installed tab: toolbar, windowed list, rows, empty states.

use std::rc::Rc;

use gloo_timers::callback::Timeout;
use leptos::prelude::*;

use super::model::*;
use super::plan::Review;
use super::Ctx;
use crate::api::userscripts::{encode_component, Userscript};
use crate::api::ApiClient;
use crate::components::{push_tab, Icon, Switch};
use crate::pages::vlist::*;
use crate::state::use_app_state;
use crate::utils::format_number;

/// The page for one script.
pub fn script_href(id: &str) -> String {
    format!("/userscripts/{}", encode_component(id))
}

/// Nothing installed yet.
#[component]
pub fn UsEmpty(ctx: Ctx) -> impl IntoView {
    view! {
        <div class="us-empty">
            <svg class="i big" viewBox="0 0 16 16" aria-hidden="true"
                inner_html=r#"<path d="M5.5 4 2 8l3.5 4M10.5 4 14 8l-3.5 4M9 3 7 13"/>"#></svg>
            <b>"No userscripts yet"</b>
            <p class="muted">"Userscripts change how sites behave: remove annoyances, add features. Pick one from the signed catalogue or install from a URL."</p>
            <div class="row-gap">
                <button type="button" class="btn primary" on:click=move |_| {
                    push_tab("browse", false);
                    ctx.tab.set("browse".into());
                }>"Browse catalogue"</button>
                <button type="button" class="btn ghost" on:click=move |_| ctx.import_open.set(true)>"Import backup"</button>
            </div>
        </div>
    }
}

#[component]
fn UsRow(
    script: Userscript,
    ctx: Ctx,
    busy: RwSignal<Vec<String>>,
    on_toggle: Callback<(String, bool)>,
) -> impl IntoView {
    let id = script.id.clone();
    let href = script_href(&id);
    let st = {
        let s = script.clone();
        Memo::new(move |_| update_status(&s))
    };
    let hint_id = format!(
        "ap-{}",
        id.bytes()
            .fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(b as u32))
    );
    let desc = script.description.clone().unwrap_or_default();
    let (sites, every) = site_list(&script.match_patterns);
    let n_sites = if every { None } else { Some(sites.len()) };
    let checking = {
        let id = id.clone();
        move || ctx.checking.with(|c| c.contains(&id))
    };
    let failed = {
        let id = id.clone();
        move || ctx.failed.with(|c| c.contains(&id))
    };
    let (id_sw, id_busy, id_btn) = (id.clone(), id.clone(), id.clone());
    let s_btn = script.clone();
    let s_meta = script.clone();
    let err_text = script
        .unsupported
        .first()
        .cloned()
        .unwrap_or_else(|| "The last run failed".into());
    let has_src = script.update_url.is_some();
    let enabled = script.enabled;
    let name = script.name.clone();
    let name_sw = name.clone();
    let hint = hint_id.clone();
    view! {
        <li class=move || if enabled { "usrow" } else { "usrow off" }>
            <div class="swcell">
                <Switch
                    checked=enabled
                    label=format!("Enable {name_sw}")
                    disabled=Signal::derive(move || st.get() == UpdateState::NeedsApproval || busy.with(|b| b.contains(&id_busy)))
                    on_change=Callback::new(move |v: bool| on_toggle.run((id_sw.clone(), v))) />
                {move || (st.get() == UpdateState::NeedsApproval).then(|| view! {
                    <span id=hint_id.clone() class="sr">"Approve this imported script before enabling it"</span>
                })}
            </div>
            <div class="usbody">
                <div class="hd">
                    <a class="nm" title=name.clone() href=href.clone() aria-describedby=move || (st.get() == UpdateState::NeedsApproval).then(|| hint.clone())>{name.clone()}</a>
                    {script.version.clone().map(|v| view! { <span class="ver">{v}</span> })}
                    {move || state_pill(&st.get()).map(|(c, t)| view! { <span class=format!("pill {c}")>{t}</span> })}
                </div>
                <div class="desc" title=desc.clone()>{desc.clone()}</div>
                <div class="meta">
                    {move || checking().then(|| view! { <span><span class="spin"></span>" Checking\u{2026}"</span> })}
                    {move || failed().then(|| view! { <span class="bad">"Update check failed"</span> })}
                    {(!enabled).then(|| view! { <span>"Disabled"</span> })}
                    {move || (st.get() == UpdateState::Error).then(|| view! {
                        <span class="bad" title=err_text.clone()>{err_text.clone()}</span>
                    })}
                    <span>{match n_sites { None => "every site".to_string(), Some(n) => format!("{n} site{}", if n == 1 { "" } else { "s" }) }}</span>
                    <span class="x">{format!("runs {}\u{d7}", format_number(s_meta.execution_count))}</span>
                    <span>{format!("{} stored", fmt_bytes(s_meta.storage_bytes))}</span>
                    {s_meta.last_update_check.clone().map(|t| view! { <span class="x" title=fmt_abs(&t)>{format!("checked {}", rel_time(&t))}</span> })}
                    {if has_src {
                        view! { <span class="x">"Auto-updates"</span> }.into_any()
                    } else {
                        view! { <span class="x" title=NO_SOURCE_HINT>"No update source"</span> }.into_any()
                    }}
                </div>
            </div>
            <div class="trail">
                {move || match st.get() {
                    UpdateState::Update(_) => {
                        let s = s_btn.clone();
                        Some(view! {
                            <button type="button" class="btn sm primary" on:click=move |_| {
                                if let Some(r) = Review::from_update(&s) {
                                    ctx.review.set(Some(r));
                                    ctx.show_review.set(true);
                                }
                            }>"Review update"</button>
                        }.into_any())
                    }
                    UpdateState::NeedsApproval => {
                        let s = s_btn.clone();
                        Some(view! {
                            <button type="button" class="btn sm primary" on:click=move |_| {
                                ctx.review.set(Some(Review::from_approval(&s)));
                                ctx.show_review.set(true);
                            }>"Review"</button>
                        }.into_any())
                    }
                    UpdateState::Error => Some(view! {
                        <a class="btn sm" href=format!("{}#updates", script_href(&id_btn))>"View"</a>
                    }.into_any()),
                    _ => None,
                }}
                <Icon name="chev-r" />
            </div>
        </li>
    }
}

/// The Installed tab body.
#[component]
pub fn InstalledPanel(ctx: Ctx) -> impl IntoView {
    let app = StoredValue::new(use_app_state());
    let q = RwSignal::new(query_get("uq").unwrap_or_default());
    let status = ctx.status;
    let sort = RwSignal::new(query_get("us").unwrap_or_else(|| "name".into()));
    let anchor0 = query_get("ua");
    let debounce = StoredValue::new_local(None::<Timeout>);
    let anchor_t = StoredValue::new_local(None::<Timeout>);
    let dead = RwSignal::new(Vec::<char>::new());
    let row_h = Signal::derive(move || {
        let w = web_sys::window()
            .and_then(|w| w.inner_width().ok())
            .and_then(|v| v.as_f64())
            .unwrap_or(1400.0);
        if w <= 480.0 {
            84.0
        } else {
            76.0
        }
    });
    let busy = RwSignal::new(Vec::<String>::new());
    let list_err = RwSignal::new(Option::<String>::None);
    let counts = ctx.counts;

    let fetch: Fetcher<Userscript> = Rc::new(move |cursor, from| {
        let (qv, st, so) = (
            q.get_untracked(),
            status.get_untracked(),
            sort.get_untracked(),
        );
        Box::pin(async move {
            ApiClient::new()
                .list_userscripts_paged(&qv, &st, &so, cursor.as_deref(), from.as_deref(), 40)
                .await
                .map(|r| {
                    dead.set(dead_letters(&r.counts.letters));
                    counts.set(Some(r.counts));
                    (r.items, r.next_cursor, r.total)
                })
        })
    });
    let feed = Feed::new(fetch);

    let first = StoredValue::new_local(true);
    Effect::new(move |_| {
        ctx.reload.track();
        q.track();
        status.track();
        sort.track();
        let from = if first.get_value() {
            first.set_value(false);
            if sort.get_untracked() == "name" {
                anchor0.clone()
            } else {
                None
            }
        } else {
            None
        };
        dead.set(Vec::new());
        feed.reload(from, false, None);
    });
    Effect::new(move |_| {
        let so = sort.get();
        query_set(&[
            ("uq", Some(q.get())),
            ("um", Some(status.get())),
            ("us", (so != "name").then_some(so)),
            ("ua", None),
        ]);
    });
    let on_anchor = Callback::new(move |i: usize| {
        if sort.get_untracked() != "name" {
            return;
        }
        let label = feed
            .items
            .with_untracked(|v| v.get(i).filter(|_| i > 0).map(|r| r.name.clone()));
        anchor_t.set_value(Some(Timeout::new(250, move || query_set(&[("ua", label)]))));
    });

    let toggle = Callback::new(move |(id, enabled): (String, bool)| {
        busy.update(|b| b.push(id.clone()));
        list_err.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().set_userscript_enabled(&id, enabled).await {
                Ok(updated) => {
                    counts.update(|c| {
                        if let Some(c) = c {
                            if enabled {
                                c.enabled += 1;
                                c.disabled = c.disabled.saturating_sub(1);
                            } else {
                                c.disabled += 1;
                                c.enabled = c.enabled.saturating_sub(1);
                            }
                        }
                    });
                    let st = status.get_untracked();
                    let gone = (st == "enabled" && !updated.enabled)
                        || (st == "disabled" && updated.enabled);
                    if gone {
                        feed.items.update(|v| v.retain(|x| x.id != id));
                        feed.total.update(|t| *t = t.saturating_sub(1));
                    } else {
                        feed.items.update(|v| {
                            if let Some(x) = v.iter_mut().find(|x| x.id == id) {
                                *x = updated;
                            }
                        });
                    }
                    // Keep the overview in step without refetching it.
                    ctx.all.update(|v| {
                        if let Some(x) = v.iter_mut().find(|x| x.id == id) {
                            x.enabled = enabled;
                            x.pending_approval = false;
                        }
                    });
                }
                Err(e) => list_err.set(Some(format!(
                    "Couldn't {} the script: {e}",
                    if enabled { "enable" } else { "disable" }
                ))),
            }
            busy.update(|b| b.retain(|x| x != &id));
        });
    });

    let none_installed = move || {
        counts.get().is_some_and(|c| c.all == 0)
            && q.with(|q| q.is_empty())
            && status.with(|s| s.is_empty())
    };
    let filtered = move || !q.with(|q| q.is_empty()) || !status.with(|s| s.is_empty());
    let clear = move |_| {
        q.set(String::new());
        status.set(String::new());
    };
    let seg_n = move |val: &'static str| {
        counts.get().map(|c| match val {
            "enabled" => c.enabled,
            "disabled" => c.disabled,
            "attention" => c.attention,
            _ => c.all,
        })
    };

    view! {
        <div class="card">
            <Show when=move || !none_installed() fallback=move || view! { <UsEmpty ctx=ctx /> }>
                <div class="card-b sitebar us-bar">
                    <div class="toolbar">
                        <div class="search grow">
                            <Icon name="search" />
                            <label class="sr" for="usQ">"Search userscripts"</label>
                            <input id="usQ" class="input" placeholder="Search by name or description" autocomplete="off"
                                prop:value=move || q.get()
                                on:input=move |ev| {
                                    let v = event_target_value(&ev);
                                    debounce.set_value(Some(Timeout::new(150, move || q.set(v))));
                                } />
                        </div>
                        <div class="seg" role="radiogroup" aria-label="Filter by status">
                            {[("", "All"), ("enabled", "Enabled"), ("disabled", "Disabled"), ("attention", "Needs attention")]
                                .into_iter()
                                .map(|(val, name)| view! {
                                    <button type="button" role="radio"
                                        aria-checked=move || (status.get() == val).to_string()
                                        on:click=move |_| status.set(val.to_string())>
                                        {name}
                                        {move || seg_n(val).filter(|n| val != "attention" || *n > 0).map(|n| view! { <span class="n">{format_number(n as u64)}</span> })}
                                    </button>
                                })
                                .collect_view()}
                        </div>
                        <select class="select" aria-label="Sort" prop:value=move || sort.get()
                            on:change=move |ev| sort.set(event_target_value(&ev))>
                            <option value="name">"Name"</option>
                            <option value="updated">"Recently updated"</option>
                        </select>
                    </div>
                    {move || list_err.get().map(|e| view! {
                        <div class="err row-gap" role="alert">
                            <span>{e}</span>
                            <button type="button" class="btn sm ghost" on:click=move |_| list_err.set(None)>"Dismiss"</button>
                        </div>
                    })}
                </div>
                <Show
                    when=move || !feed.items.with(|v| v.is_empty()) || feed.error.get().is_some()
                    fallback=move || view! {
                        <div class="empty">
                            {move || if feed.loading.get() {
                                view! { <span class="row-gap" style="justify-content:center"><span class="spin"></span>"Loading\u{2026}"</span> }.into_any()
                            } else if filtered() {
                                view! {
                                    <b>{move || {
                                        let t = q.get();
                                        if t.is_empty() { "No scripts match this filter".to_string() } else { format!("No scripts match \"{t}\"") }
                                    }}</b>
                                    <button type="button" class="btn sm ghost" on:click=clear>"Clear filters"</button>
                                }.into_any()
                            } else {
                                view! { <b>"No userscripts"</b> }.into_any()
                            }}
                        </div>
                    }
                >
                    <div class="vwrap">
                        <VList
                            items=feed.items
                            row_h=row_h
                            as_list=true
                            key=|s: &Userscript| format!("{}|{}|{}|{}|{}|{}|{}|{}", s.id, s.enabled, s.version.clone().unwrap_or_default(), s.pending_update.is_some(), s.error, s.updated_at, s.last_update_check.clone().unwrap_or_default(), s.execution_count)
                            render=Callback::new(move |script: Userscript| view! { <UsRow script=script ctx=ctx busy=busy on_toggle=toggle /> }.into_any())
                            on_end=Callback::new(move |()| feed.more())
                            error=feed.error
                            on_retry=Callback::new(move |()| feed.retry())
                            on_anchor=on_anchor
                            reset=feed.tok
                            label="Userscripts"
                        />
                        <nav class="azrail" aria-label="Jump to letter" hidden=move || !(sort.get() == "name" && feed.total.get() > 12)>
                            {LETTERS.iter().map(|&l| view! {
                                <button type="button" disabled=move || dead.get().contains(&l)
                                    on:click=move |_| feed.reload(
                                        Some(l.to_string()), true,
                                        Some(Callback::new(move |n: usize| {
                                            if n == 0 {
                                                dead.update(|d| d.push(l));
                                                app.get_value().info(format!("No userscripts starting with {}", l.to_ascii_uppercase()));
                                            }
                                        })),
                                    )>{l.to_ascii_uppercase().to_string()}</button>
                            }).collect_view()}
                        </nav>
                    </div>
                </Show>
                <div class="vfoot" aria-live="polite">
                    <span>{move || {
                        let n = feed.total.get();
                        if filtered() { format!("{n} matches") } else { format!("{n} scripts") }
                    }}</span>
                    <span>{move || {
                        let n = feed.items.with(|v| v.len());
                        if feed.next.get().is_some() { format!("showing 1-{n} \u{b7} scroll for more") } else { "end of list".to_string() }
                    }}</span>
                </div>
            </Show>
        </div>
    }
}

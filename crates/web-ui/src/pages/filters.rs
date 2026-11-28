//! Filter lists page: searchable/paged list (server side), add list, explain URL, custom rules,
//! catalogue and build state.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use gloo_timers::callback::Timeout;
use leptos::prelude::*;
use uuid::Uuid;

use super::vlist::*;
use crate::api::filters::{
    ago_rfc3339, BuildState, BuildSummary, CatalogueEntryResponse, FilterList, FilterListCounts,
    ListReport, TestUrlResponse,
};
use crate::api::ApiClient;
use crate::components::{ConfirmButton, Drawer, Icon, Layout, Modal, Pill, Switch};
use crate::state::use_app_state;
use crate::utils::format_number;
use std::rc::Rc;

const PAGE_SIZE: u32 = 40;

/// Formats offered when adding a list.
const FORMATS: &[&str] = &[
    "auto",
    "abp",
    "ubo",
    "adguard",
    "hosts",
    "domains",
    "dnsmasq",
    "unbound",
    "rpz",
    "pihole",
    "adguard-home",
    "little-snitch",
    "surge",
    "clash",
    "ip-list",
];

/// Filters page component
#[component]
pub fn FiltersPage() -> impl IntoView {
    let app_state = use_app_state();

    let counts = RwSignal::new(Option::<FilterListCounts>::None);
    let q = RwSignal::new(query_get("fq").unwrap_or_default()); // debounced
    let mode = RwSignal::new(query_get("fm").unwrap_or_default());
    let sort = RwSignal::new(query_get("fs").unwrap_or_else(|| "name".into()));
    let anchor0 = query_get("fa");
    let reload = RwSignal::new(0u32);
    let debounce = StoredValue::new_local(None::<Timeout>);
    let anchor_t = StoredValue::new_local(None::<Timeout>);
    let dead = RwSignal::new(Vec::<char>::new());
    let sel = RwSignal::new(Option::<String>::None);
    let sel_open = RwSignal::new(false);
    let row_h = Signal::derive(move || if is_narrow() { 104.0 } else { 62.0 });

    let build = RwSignal::new(Option::<BuildSummary>::None);
    let show_catalogue = RwSignal::new(false);
    let catalogue = RwSignal::new(Vec::<CatalogueEntryResponse>::new());
    let catalogue_add = RwSignal::new(Option::<String>::None);
    // The catalogue modal and the list-options drawer never stack.
    Effect::new(move |_| {
        if show_catalogue.get() {
            sel_open.set(false);
        }
    });
    Effect::new(move |_| {
        if sel_open.get() {
            show_catalogue.set(false);
        }
    });
    let cat_source = RwSignal::new(String::new());
    let cat_fetched = RwSignal::new(Option::<String>::None);
    let cat_version = RwSignal::new(Option::<String>::None);
    let cat_q = RwSignal::new(String::new());
    let cat_category = RwSignal::new(String::new());
    let cat_region = RwSignal::new(String::new());
    let cat_filtered = Signal::derive(move || {
        let q = cat_q.get().to_lowercase();
        let (c, r) = (cat_category.get(), cat_region.get());
        catalogue
            .get()
            .into_iter()
            .filter(|e| {
                (c.is_empty() || e.category == c)
                    && !e.installed
                    && (r.is_empty() || e.region.as_deref() == Some(r.as_str()))
                    && (q.is_empty()
                        || e.name.to_lowercase().contains(&q)
                        || e.description.to_lowercase().contains(&q)
                        || e.id.to_lowercase().contains(&q))
            })
            .collect::<Vec<_>>()
    });
    // Not-installed entries grouped by category (alphabetical, entries by name).
    let cat_groups = Signal::derive(move || {
        let mut v = cat_filtered.get();
        v.sort_by(|a, b| {
            (a.category.as_str(), a.name.to_lowercase())
                .cmp(&(b.category.as_str(), b.name.to_lowercase()))
        });
        let mut groups: Vec<(String, Vec<CatalogueEntryResponse>)> = Vec::new();
        for e in v {
            match groups.last_mut() {
                Some((c, items)) if *c == e.category => items.push(e),
                _ => groups.push((e.category.clone(), vec![e])),
            }
        }
        groups
    });
    let cat_categories = Memo::new(move |_| {
        let mut v: Vec<String> = catalogue.get().iter().map(|e| e.category.clone()).collect();
        v.sort();
        v.dedup();
        v
    });
    let cat_regions = Memo::new(move |_| {
        let mut v: Vec<String> = catalogue
            .get()
            .iter()
            .filter_map(|e| e.region.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    });

    // Add-list form
    let add_name = RwSignal::new(String::new());
    let add_url = RwSignal::new(String::new());
    let add_format = RwSignal::new("auto".to_string());
    let add_allowlist = RwSignal::new(false);
    let add_trusted = RwSignal::new(false);

    // Explain
    let ex_url = RwSignal::new(String::new());
    let ex_out = RwSignal::new(Option::<TestUrlResponse>::None);

    // Custom rules
    let custom_rules = RwSignal::new(String::new());
    let rules_etag = RwSignal::new(Option::<String>::None);
    let saving_rules = RwSignal::new(false);

    // Cursor-paged feed of lists
    let fetch: Fetcher<FilterList> = {
        let app_state = app_state.clone();
        Rc::new(move |cursor, from| {
            let (qv, m, s) = (
                q.get_untracked(),
                mode.get_untracked(),
                sort.get_untracked(),
            );
            let app_state = app_state.clone();
            Box::pin(async move {
                match ApiClient::new()
                    .list_filter_lists_paged(
                        &qv,
                        &m,
                        &s,
                        cursor.as_deref(),
                        from.as_deref(),
                        PAGE_SIZE,
                    )
                    .await
                {
                    Ok(r) => {
                        dead.set(dead_letters(&r.counts.letters));
                        counts.set(Some(r.counts));
                        Ok((r.items, r.next_cursor, r.total))
                    }
                    Err(e) => {
                        app_state.error(format!("Failed to load filters: {e}"));
                        Err(e)
                    }
                }
            })
        })
    };
    let feed = Feed::new(fetch);
    let first = StoredValue::new_local(true);
    Effect::new(move |_| {
        reload.track();
        q.track();
        mode.track();
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
        let s = sort.get();
        query_set(&[
            ("fq", Some(q.get())),
            ("fm", Some(mode.get())),
            ("fs", (s != "name").then_some(s)),
            ("fa", None),
        ]);
    });
    let on_anchor = Callback::new(move |i: usize| {
        if sort.get_untracked() != "name" {
            return;
        }
        let label = feed
            .items
            .with_untracked(|v| v.get(i).filter(|_| i > 0).map(|r| r.name.clone()));
        anchor_t.set_value(Some(Timeout::new(250, move || query_set(&[("fa", label)]))));
    });
    // Custom rules (once)
    let app_cr = app_state.clone();
    wasm_bindgen_futures::spawn_local(async move {
        match ApiClient::new().get_custom_rules().await {
            Ok((resp, etag)) => {
                custom_rules.set(resp.rules);
                rules_etag.set(etag);
            }
            Err(e) => app_cr.error(format!("Failed to load custom rules: {e}")),
        }
    });

    // Poll the build state while the page is open; reload lists when a build finishes.
    {
        let alive = Arc::new(AtomicBool::new(true));
        let flag = alive.clone();
        let app_b = app_state.clone();
        on_cleanup(move || flag.store(false, Ordering::Relaxed));
        wasm_bindgen_futures::spawn_local(async move {
            let client = ApiClient::new();
            let mut was_building = false;
            let mut seen_built = false;
            let mut last_built = None;
            let mut failing = false;
            // Poll fast while a build runs; back off while idle (3s, 6s, 12s, then 15s), and
            // pause entirely while the tab is hidden. Any user action (nudge) resets it.
            let mut idle_ms = 3000u32;
            while alive.load(Ordering::Relaxed) {
                if take_nudge() {
                    idle_ms = 3000;
                }
                if tab_hidden() {
                    gloo_timers::future::TimeoutFuture::new(2000).await;
                    continue;
                }
                match client.get_build_summary().await {
                    Ok(b) => {
                        failing = false;
                        let built_at = b.built_at.clone();
                        if (was_building && !b.building) || (seen_built && built_at != last_built) {
                            feed.refresh_loaded();
                        }
                        seen_built = true;
                        last_built = built_at;
                        was_building = b.building;
                        idle_ms = if b.building {
                            3000
                        } else {
                            (idle_ms * 2).min(15_000)
                        };
                        build.set(Some(b));
                    }
                    Err(e) => {
                        // Toast once per outage, not every poll.
                        if !failing {
                            app_b.error(format!("Build status unavailable: {e}"));
                        }
                        failing = true;
                    }
                }
                // Sleep in 1s steps so a nudge cuts the wait short.
                let mut waited = 0;
                while waited < idle_ms && alive.load(Ordering::Relaxed) && !peek_nudge() {
                    gloo_timers::future::TimeoutFuture::new(1000).await;
                    waited += 1000;
                }
            }
        });
    }

    // Add from the catalogue
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            if let Some(id) = catalogue_add.get() {
                let app_state = app_state.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    match ApiClient::new().add_from_catalogue(&id).await {
                        Ok(_) => {
                            catalogue.update(|c| {
                                if let Some(e) = c.iter_mut().find(|e| e.id == id) {
                                    e.installed = true;
                                }
                            });
                            reload.update(|n| *n += 1);
                            nudge_build_poll();
                            app_state.success("List added from the catalogue");
                        }
                        Err(e) => app_state.error(format!("Failed to add list: {e}")),
                    }
                    catalogue_add.set(None);
                });
            }
        });
    }

    let add_list = {
        let app_state = app_state.clone();
        move |_| {
            let (name, url) = (add_name.get_untracked(), add_url.get_untracked());
            if name.trim().is_empty() || url.trim().is_empty() {
                app_state.error("Give the list a name and a URL");
                return;
            }
            let (format, allow, trusted) = (
                add_format.get_untracked(),
                add_allowlist.get_untracked(),
                add_trusted.get_untracked(),
            );
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let id = Uuid::new_v4().to_string();
                match ApiClient::new()
                    .add_filter_list(&id, &name, &url, true, &format, allow, trusted)
                    .await
                {
                    Ok(_) => {
                        nudge_build_poll();
                        app_state.success("Filter list added");
                        add_name.set(String::new());
                        add_url.set(String::new());
                        add_trusted.set(false);
                        add_allowlist.set(false);
                        reload.update(|n| *n += 1);
                    }
                    Err(e) => app_state.error(format!("Failed to add filter: {e}")),
                }
            });
        }
    };

    let update_all = {
        let app_state = app_state.clone();
        move |_| {
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().refresh_all_lists().await {
                    Ok(_) => {
                        nudge_build_poll();
                        app_state.success("Updating enabled lists")
                    }
                    Err(e) => app_state.error(format!("Update failed: {e}")),
                }
            });
        }
    };

    let explain = {
        let app_state = app_state.clone();
        move || {
            let u = ex_url.get_untracked();
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().test_url(&u).await {
                    Ok(r) => ex_out.set(Some(r)),
                    Err(e) => {
                        ex_out.set(None);
                        app_state.error(e.to_string());
                    }
                }
            });
        }
    };
    let explain2 = explain.clone();

    let save_rules = {
        let app_state = app_state.clone();
        move |_| {
            saving_rules.set(true);
            let app_state = app_state.clone();
            let rules = custom_rules.get_untracked();
            let etag = rules_etag.get_untracked().unwrap_or_default();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().update_custom_rules(&rules, &etag).await {
                    Ok((_, new_etag)) => {
                        rules_etag.set(new_etag);
                        nudge_build_poll();
                        app_state.success("Custom rules saved, engine recompiling");
                    }
                    Err(e) => app_state.error(format!("Failed to save rules: {e}")),
                }
                saving_rules.set(false);
            });
        }
    };

    let app_state_rail = app_state.clone();
    let rule_count = move || {
        custom_rules
            .get()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count()
    };
    let pin_custom = move || sort.get() == "name" && q.get().is_empty() && mode.get().is_empty();

    view! {
        <Layout>
            <BuildIndicator summary=build />

            <div class="card">
                <div class="card-h">
                    <h3>"Filter lists"</h3>
                    <span class="sub">{move || format!("{} lists", format_number(counts.get().map(|c| c.all).unwrap_or(0) as u64))}</span>
                    <div class="r">
                        <button type="button" class="btn sm" on:click=update_all>"Update all"</button>
                        <button
                            type="button"
                            class="btn sm"
                            on:click=move |_| {
                                show_catalogue.set(true);
                                let app_c = app_state.clone();
                                wasm_bindgen_futures::spawn_local(async move {
                                    match ApiClient::new().get_catalogue().await {
                                        Ok(c) => {
                                            cat_source.set(c.source);
                                            cat_fetched.set(c.fetched_at);
                                            cat_version.set(c.version);
                                            catalogue.set(c.entries);
                                        }
                                        Err(e) => app_c.error(format!("Failed to load catalogue: {e}")),
                                    }
                                });
                            }
                        >
                            "Browse catalogue"
                        </button>
                    </div>
                </div>
                <div class="card-b sitebar">
                    <div class="toolbar">
                        <div class="search grow">
                            <Icon name="search" />
                            <label class="sr" for="flQ">"Search lists"</label>
                            <input
                                id="flQ"
                                class="input mono"
                                placeholder="Search lists by name or URL"
                                autocomplete="off"
                                value=q.get_untracked()
                                on:input=move |ev| {
                                    let v = event_target_value(&ev);
                                    debounce.set_value(Some(Timeout::new(150, move || q.set(v))));
                                }
                            />
                        </div>
                        <div class="seg" role="radiogroup" aria-label="Filter by status">
                            {[("", "All"), ("on", "Enabled"), ("off", "Disabled"), ("attn", "Needs attention")]
                                .into_iter()
                                .map(|(val, name)| view! {
                                    <button
                                        type="button"
                                        role="radio"
                                        aria-checked=move || (mode.get() == val).to_string()
                                        on:click=move |_| mode.set(val.to_string())
                                    >
                                        {name}
                                        {move || counts.get().map(|c| match val {
                                            "on" => c.on,
                                            "off" => c.off,
                                            "attn" => c.attn,
                                            _ => c.all,
                                        }).map(|n| view! { <span class="n">{format_number(n as u64)}</span> })}
                                    </button>
                                })
                                .collect_view()}
                        </div>
                        <select
                            class="select"
                            aria-label="Sort"
                            prop:value=move || sort.get()
                            on:change=move |ev| sort.set(event_target_value(&ev))
                        >
                            <option value="name">"Name"</option>
                            <option value="rules">"Most rules"</option>
                            <option value="updated">"Last updated"</option>
                        </select>
                    </div>
                </div>
                <Show when=pin_custom>
                    <ul class="flist pin">
                        <li style=move || format!("--rowh:{}px", row_h.get())>
                            <span class="dim ficon" aria-hidden="true"><Icon name="audit" /></span>
                            <div style="min-width:0">
                                <div class="nm">"Custom rules"</div>
                                <div class="url">"Your own rules, edited below"</div>
                            </div>
                            <div class="meta">
                                <Pill kind="ok" text="local" />
                                <span class="cnt num">{move || format!("{} rules", rule_count())}</span>
                                <span class="tm"></span>
                            </div>
                            <div class="meta">
                                <button type="button" class="btn sm ghost act" on:click=move |_| scroll_to("custom-rules")>"Edit"</button>
                            </div>
                        </li>
                    </ul>
                </Show>
                <Show
                    when=move || !feed.items.with(|v| v.is_empty()) || feed.error.get().is_some()
                    fallback=move || view! {
                        <div class="empty">
                            <b>{move || if feed.loading.get() { "Loading..." } else { "No lists match" }}</b>
                            <button type="button" class="btn sm" style="margin-top:8px" on:click=move |_| {
                                q.set(String::new());
                                mode.set(String::new());
                            }>"Clear filters"</button>
                        </div>
                    }
                >
                    <div class="vwrap">
                        <VList
                            items=feed.items
                            row_h=row_h
                            key=|f: &FilterList| f.id.clone()
                            render=Callback::new(move |f: FilterList| view! { <FilterRow filter=f sel=sel sel_open=sel_open feed=feed /> }.into_any())
                            on_end=Callback::new(move |()| feed.more())
                            error=feed.error
                            on_retry=Callback::new(move |()| feed.retry())
                            on_anchor=on_anchor
                            reset=feed.tok
                            label="Filter lists"
                            as_list=true
                        />
                        <nav class="azrail" aria-label="Jump to letter" hidden=move || !(sort.get() == "name" && feed.total.get() > 12)>
                            {LETTERS.iter().map(|&l| {
                                let app_state = app_state_rail.clone();
                                view! {
                                    <button type="button" disabled=move || dead.get().contains(&l)
                                        on:click=move |_| {
                                            let app_state = app_state.clone();
                                            feed.reload(
                                                Some(l.to_string()),
                                                true,
                                                Some(Callback::new(move |n: usize| {
                                                    if n == 0 {
                                                        dead.update(|d| d.push(l));
                                                        app_state.info(format!("No lists starting with {}", l.to_ascii_uppercase()));
                                                    }
                                                })),
                                            );
                                        }>{l.to_ascii_uppercase().to_string()}</button>
                                }
                            }).collect_view()}
                        </nav>
                    </div>
                </Show>
                <div class="vfoot" aria-live="polite">
                    <span>{move || {
                        let n = format_number(feed.total.get() as u64);
                        if !q.get().is_empty() || !mode.get().is_empty() { format!("{n} matches") } else { format!("{n} lists") }
                    }}</span>
                    <span>{move || {
                        let n = feed.items.with(|v| v.len());
                        if feed.next.get().is_some() { format!("showing 1-{n} \u{b7} scroll for more") } else { "end of list".to_string() }
                    }}</span>
                </div>
                <FilterDrawer sel=sel open=sel_open feed=feed counts=counts />
            </div>

            <div class="grid2">
                <div class="card">
                    <div class="card-h"><h3>"Add filter list"</h3></div>
                    <div class="card-b">
                        <div class="field">
                            <label for="flUrl">"URL"</label>
                            <input id="flUrl" class="input mono" placeholder="https://example.com/filters.txt"
                                prop:value=move || add_url.get() on:input=move |ev| add_url.set(event_target_value(&ev)) />
                        </div>
                        <div class="field">
                            <label for="flName">"Name"</label>
                            <input id="flName" class="input" placeholder="e.g., EasyList"
                                prop:value=move || add_name.get() on:input=move |ev| add_name.set(event_target_value(&ev)) />
                        </div>
                        <div class="field">
                            <label for="flFmt">"Format"</label>
                            <select id="flFmt" class="select" on:change=move |ev| add_format.set(event_target_value(&ev))>
                                {FORMATS.iter().map(|f| view! { <option value=*f>{*f}</option> }).collect_view()}
                            </select>
                            <span class="hint">"auto detects the format from the content."</span>
                        </div>
                        <div class="srow" style="border-top:0;padding:0">
                            <div class="txt"><b>"Allowlist"</b><small>"Every rule becomes an exception"</small></div>
                            <Switch checked=add_allowlist label="Allowlist" on_change=Callback::new(move |v: bool| add_allowlist.set(v)) />
                        </div>
                        <div class="srow" style="border-top:0;padding:0">
                            <div class="txt"><b>"Trusted list"</b><small>"Lets its rules inject scriptlets (#%#) into pages you visit"</small></div>
                            <Switch checked=add_trusted label="Trusted list" on_change=Callback::new(move |v: bool| add_trusted.set(v)) />
                        </div>
                        <div>
                            <button type="button" class="btn primary" on:click=add_list><Icon name="plus" />"Add list"</button>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-h"><h3>"Explain this URL"</h3><span class="sub">"Shows which rule decides a request"</span></div>
                    <div class="card-b">
                        <div class="field">
                            <label for="exUrl">"URL"</label>
                            <input id="exUrl" class="input mono" placeholder="https://example.com/ads.js"
                                prop:value=move || ex_url.get()
                                on:input=move |ev| ex_url.set(event_target_value(&ev))
                                on:keydown=move |ev: web_sys::KeyboardEvent| if ev.key() == "Enter" { explain2() } />
                        </div>
                        <div><button type="button" class="btn" on:click=move |_| explain()>"Explain"</button></div>
                        <div class="explain-out" aria-live="polite">
                            {move || match ex_out.get() {
                                None => view! { <span class="dim">"Enter a URL and press Explain."</span> }.into_any(),
                                Some(r) => view! {
                                    <div><Pill kind=if r.blocked { "blocked" } else { "allowed" } /></div>
                                    {r.matched_rule.clone().map(|m| view! { <div class="mono">{m}</div> })}
                                    {r.exception_rule.clone().map(|m| view! { <div class="dim">"Exception: "<span class="mono">{m}</span></div> })}
                                    {r.important.then(|| view! { <div class="dim">"Important rule"</div> })}
                                    {r.redirected.then(|| view! { <div class="dim">"Redirected to a neutered resource"</div> })}
                                    {r.rewritten_url.clone().map(|m| view! { <div class="dim">"Rewritten to "<span class="mono">{m}</span></div> })}
                                }.into_any(),
                            }}
                        </div>
                    </div>
                </div>
            </div>

            <div class="card" id="custom-rules">
                <div class="card-h">
                    <h3>"Custom rules"</h3>
                    <span class="sub">"uBO / ABP syntax, one per line"</span>
                    <div class="r">
                        <span class="dim num">{move || format!("{} rules", rule_count())}</span>
                        <button type="button" class="btn sm primary" disabled=move || saving_rules.get() on:click=save_rules>
                            {move || if saving_rules.get() { "Saving..." } else { "Save rules" }}
                        </button>
                    </div>
                </div>
                <div class="card-b">
                    <label class="sr" for="crText">"Custom rules"</label>
                    <textarea
                        id="crText"
                        class="input"
                        rows="8"
                        spellcheck="false"
                        placeholder="||ads.example^\n@@||good.example^\nexample.com##.sponsored"
                        prop:value=move || custom_rules.get()
                        on:input=move |ev| custom_rules.set(event_target_value(&ev))
                    ></textarea>
                </div>
            </div>

            <Modal
                title="List Catalogue"
                open=show_catalogue
                on_close=Callback::new(move |_| show_catalogue.set(false))
            >
                <p class="hint">
                    {move || if cat_source.get() == "snapshot" {
                        format!("Built-in copy, release {}", cat_version.get().unwrap_or_default())
                    } else if cat_source.get() == "signed" && cat_fetched.get().is_some() {
                        format!("Signed · {}", cat_fetched.get().map(|d| d.chars().take(10).collect::<String>()).unwrap_or_default())
                    } else {
                        "Catalogue not loaded yet".to_string()
                    }}
                    " · Check each list's licence before use."
                </p>
                <div class="chips" style="margin-bottom:8px">
                    <input class="input" placeholder="Search" aria-label="Search the catalogue"
                        prop:value=move || cat_q.get() on:input=move |ev| cat_q.set(event_target_value(&ev)) />
                    <select class="select" aria-label="Category" on:change=move |ev| cat_category.set(event_target_value(&ev))>
                        <option value="">"All categories"</option>
                        {move || cat_categories.get().into_iter().map(|c| view! { <option value=c.clone()>{c.clone()}</option> }).collect_view()}
                    </select>
                    <select class="select" aria-label="Region" on:change=move |ev| cat_region.set(event_target_value(&ev))>
                        <option value="">"All regions"</option>
                        {move || cat_regions.get().into_iter().map(|c| view! { <option value=c.clone()>{c.clone()}</option> }).collect_view()}
                    </select>
                </div>
                {move || cat_groups.get().is_empty().then(|| view! { <p class="hint">"Every catalogue list is already installed."</p> })}
                <For
                    each=move || cat_groups.get()
                    key=|(c, items)| (c.clone(), items.iter().map(|e| e.id.clone()).collect::<Vec<_>>())
                    children=move |(cat, items)| view! {
                        <h4 style="margin:12px 0 4px">{cat}</h4>
                        <ul class="flist">
                            {items.into_iter().map(|e| {
                                let id = e.id.clone();
                                let tip = e.licence_note.clone().unwrap_or_else(|| format!("Licence {} forbids commercial use", e.licence));
                                view! {
                                    <li style="grid-template-columns:minmax(0,1fr) auto">
                                        <div style="min-width:0">
                                            <div class="nm">
                                                {e.name.clone()}
                                                {e.default_enabled.then(|| view! { " " <span class="badge" title="Recommended: enabled on a fresh install">"recommended"</span> })}
                                                {e.noncommercial.then(|| view! { " " <span class="badge" title=tip.clone()>"non-commercial"</span> })}
                                            </div>
                                            <div class="url">
                                                {e.format.clone()}
                                                {e.region.clone().map(|r| format!(" | {r}"))}
                                                " | "{e.licence.clone()}
                                            </div>
                                            {(!e.description.is_empty()).then(|| view! { <div class="url">{e.description.clone()}</div> })}
                                        </div>
                                        <button type="button" class="btn sm primary" on:click=move |_| catalogue_add.set(Some(id.clone()))>"Add"</button>
                                    </li>
                                }
                            }).collect_view()}
                        </ul>
                    }
                />
            </Modal>
        </Layout>
    }
}

fn scroll_to(id: &str) {
    if let Some(el) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.get_element_by_id(id))
    {
        el.scroll_into_view();
    }
}

/// One filter list row (fixed height; options live in the drawer).
#[component]
fn FilterRow(
    filter: FilterList,
    sel: RwSignal<Option<String>>,
    sel_open: RwSignal<bool>,
    feed: Feed<FilterList>,
) -> impl IntoView {
    let app_state = use_app_state();
    let id = filter.id.clone();
    let r = live_row(feed.items, filter, |f: &FilterList| f.id.as_str());
    let on_flag = {
        let (app_state, id) = (app_state.clone(), id.clone());
        Callback::new(move |v: bool| {
            let (app_state, id) = (app_state.clone(), id.clone());
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().set_list_flags(&id, Some(v), None).await {
                    Ok(updated) => {
                        apply_update(feed, updated);
                        nudge_build_poll();
                    }
                    Err(e) => app_state.error(format!("Failed to update list: {e}")),
                }
            });
        })
    };
    let update = {
        let (app_state, id) = (app_state.clone(), id.clone());
        move |_| {
            let (app_state, id) = (app_state.clone(), id.clone());
            let name = r.with_untracked(|f| f.name.clone());
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().refresh_list(&id).await {
                    Ok(_) => {
                        nudge_build_poll();
                        app_state.success(format!("Fetching {name}"))
                    }
                    Err(e) => app_state.error(format!("Update failed: {e}")),
                }
            });
        }
    };
    let pill = move || {
        r.with(|f| {
            let (kind, text) = if f.last_error.is_some() {
                ("error", "error")
            } else if !f.enabled {
                ("neutral", "disabled")
            } else {
                ("ok", "ok")
            };
            view! { <Pill kind=kind text=text /> }
        })
    };
    let count = move || {
        r.with(|f| {
            if f.rule_count > 0 {
                if f.duplicate_count.is_some_and(|d| d > 0) {
                    format!("{} unique", format_number(f.rule_count as u64))
                } else {
                    format!("{} rules", format_number(f.rule_count as u64))
                }
            } else {
                "-".to_string()
            }
        })
    };
    let count_title = move || {
        r.with(|f| {
            f.duplicate_count.filter(|d| *d > 0).map(|dup| {
                format!(
                    "{} unique rules ({} total). {} duplicate rules were dropped because an earlier list, or this one, already has them.",
                    format_number(f.rule_count as u64),
                    format_number((f.rule_count + dup) as u64),
                    format_number(dup as u64)
                )
            })
        })
    };
    let open_id = id.clone();

    view! {
        <li>
            <Switch checked=Signal::derive(move || r.with(|f| f.enabled)) label=format!("Enable {}", r.with_untracked(|f| f.name.clone())) on_change=on_flag />
            <div style="min-width:0">
                <div class="nm">
                    <button type="button" class="nmbtn" title="Options" on:click=move |_| {
                        sel.set(Some(open_id.clone()));
                        sel_open.set(true);
                    }>{move || r.with(|f| f.name.clone())}</button>
                    " "
                    {move || r.with(|f| f.trusted).then(|| view! { <span class="badge" title="Rules may inject scriptlets">"trusted"</span> })}
                    {move || r.with(|f| f.allowlist).then(|| view! { <span class="badge">"allowlist"</span> })}
                </div>
                <div class="url" title=move || r.with(|f| f.last_error.clone().unwrap_or_default())>{move || r.with(|f| f.url.clone())}</div>
            </div>
            <div class="meta">
                {pill}
                <span class="cnt num" title=move || count_title().unwrap_or_default()>{count}</span>
                <span class="tm">{move || r.with(|f| ago_rfc3339(f.last_updated.as_deref()))}</span>
            </div>
            <div class="meta">
                <button type="button" class="btn sm ghost act" on:click=update>"Update"</button>
            </div>
        </li>
    }
}

/// Replace one row in place after an edit; drop it only if it no longer matches the status filter.
fn apply_update(feed: Feed<FilterList>, updated: FilterList) {
    let mode = query_get("fm").unwrap_or_default();
    let gone = (mode == "on" && !updated.enabled) || (mode == "off" && updated.enabled);
    if gone {
        feed.items.update(|v| v.retain(|x| x.id != updated.id));
        feed.total.update(|t| *t = t.saturating_sub(1));
    } else {
        feed.items.update(|v| {
            if let Some(x) = v.iter_mut().find(|x| x.id == updated.id) {
                *x = updated;
            }
        });
    }
}

/// Options for the selected list: trusted, allowlist, build report, delete.
#[component]
fn FilterDrawer(
    sel: RwSignal<Option<String>>,
    open: RwSignal<bool>,
    feed: Feed<FilterList>,
    counts: RwSignal<Option<FilterListCounts>>,
) -> impl IntoView {
    let app_state = use_app_state();
    let report = RwSignal::new(HashMap::<String, ListReport>::new());
    let app_rep = app_state.clone();
    Effect::new(move |_| {
        if let Some(id) = sel.get().filter(|_| open.get()) {
            let app_r = app_rep.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().get_list_report(&id).await {
                    Ok(r) => report.update(|m| {
                        m.insert(id, r);
                    }),
                    Err(e) => app_r.error(format!("Failed to load list report: {e}")),
                }
            });
        }
    });
    let rules_open = RwSignal::new(false);
    let current = move || {
        let id = sel.get()?;
        feed.items.with(|v| v.iter().find(|f| f.id == id).cloned())
    };
    let title = Signal::derive(move || current().map(|f| f.name).unwrap_or_else(|| "List".into()));
    let set_flag = {
        let app_state = app_state.clone();
        Callback::new(move |(trust, v): (bool, bool)| {
            let Some(f) = current() else { return };
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let r = if trust {
                    ApiClient::new().set_list_trusted(&f.id, v).await
                } else {
                    ApiClient::new().set_list_flags(&f.id, None, Some(v)).await
                };
                match r {
                    Ok(updated) => {
                        apply_update(feed, updated);
                        nudge_build_poll();
                    }
                    Err(e) => app_state.error(format!("Failed to update list: {e}")),
                }
            });
        })
    };
    let delete = {
        let app_state = app_state.clone();
        Callback::new(move |()| {
            let Some(f) = current() else { return };
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().delete_filter_list(&f.id).await {
                    Ok(_) => {
                        nudge_build_poll();
                        app_state.success("Filter list deleted");
                        counts.update(|c| {
                            if let Some(c) = c {
                                c.all = c.all.saturating_sub(1);
                                if f.enabled {
                                    c.on = c.on.saturating_sub(1)
                                } else {
                                    c.off = c.off.saturating_sub(1)
                                }
                            }
                        });
                        feed.items.update(|v| v.retain(|x| x.id != f.id));
                        feed.total.update(|t| *t = t.saturating_sub(1));
                        open.set(false);
                    }
                    Err(e) => app_state.error(format!("Failed to delete filter: {e}")),
                }
            });
        })
    };
    view! {
        <Drawer open=open title=title>
            {move || current().map(|f| {
                let rid = f.id.clone();
                view! {
                    <div class="stack">
                        <div class="mono" style="overflow-wrap:anywhere">{f.url.clone()}</div>
                        {f.last_error.clone().map(|e| view! { <span class="err">"Last error: "{e}</span> })}
                        <div class="srow" style="border-top:0">
                            <div class="txt"><b>"Trusted"</b><small>"May run scripts in pages and rewrite responses and URLs; an untrusted list's such rules are dropped."</small></div>
                            <Switch checked=f.trusted label="Trusted" on_change=Callback::new(move |v: bool| set_flag.run((true, v))) />
                        </div>
                        <div class="srow">
                            <div class="txt"><b>"Allowlist"</b><small>"Every rule in this list becomes an exception"</small></div>
                            <Switch checked=f.allowlist label="Allowlist" on_change=Callback::new(move |v: bool| set_flag.run((false, v))) />
                        </div>
                        <div class="hint">{format!("format: {}", f.format)}</div>
                        {f.duplicate_count.filter(|d| *d > 0).map(|dup| view! {
                            <div class="hint">{format!(
                                "{} unique rules ({} total). {} duplicates were dropped because an earlier list already has them, so a list loaded after a broader one shows fewer.",
                                format_number(f.rule_count as u64),
                                format_number((f.rule_count + dup) as u64),
                                format_number(dup as u64)
                            )}</div>
                        })}
                        <ReportSummary id=rid reports=report />
                        <div><button class="btn" type="button" on:click=move |_| rules_open.set(true)>"View rules"</button></div>
                        <div><ConfirmButton label="Delete list" confirm_label="Delete?" on_confirm=delete /></div>
                    </div>
                }
            })}
        </Drawer>
        <RulesDrawer list=Signal::derive(move || current().map(|f| (f.id, f.name))) open=rules_open />
    }
}

/// The extended rules (cosmetic, scriptlet, replace, ...) a list contributes: search plus
/// infinite scroll over `/rules/ext`. Plain network rules are compiled into the engine and are
/// not listed there.
#[component]
fn RulesDrawer(list: Signal<Option<(String, String)>>, open: RwSignal<bool>) -> impl IntoView {
    let app = StoredValue::new(use_app_state());
    let q = RwSignal::new(String::new());
    // The query the loaded pages were fetched with: later pages must not mix in a newer one.
    let q_snap = RwSignal::new(String::new());
    let t = StoredValue::new_local(None::<Timeout>);
    let rules_cell = StoredValue::new_local(None::<Feed<api_types::ExtRuleResponse>>);
    let fetch: Fetcher<api_types::ExtRuleResponse> = Rc::new(move |cursor, _| {
        let id = list.get_untracked().map(|l| l.0).unwrap_or_default();
        let qv = q_snap.get_untracked();
        Box::pin(async move {
            // An empty id would list every list's rules.
            if id.is_empty() {
                return Ok((Vec::new(), None, 0));
            }
            match ApiClient::new()
                .list_ext_rules(&id, &qv, cursor.as_deref())
                .await
            {
                Ok(p) => Ok((p.items, p.next_cursor, p.total)),
                Err(e) => {
                    if matches!(e, crate::api::ApiError::Conflict(_)) {
                        // The rule set was rebuilt under the cursor: start over.
                        app.get_value()
                            .info("Filter lists were rebuilt; reloading the rules");
                        if let Some(f) = rules_cell.get_value() {
                            f.reload(None, false, None);
                        }
                    } else {
                        app.get_value().error(format!("Failed to load rules: {e}"));
                    }
                    Err(e)
                }
            }
        })
    });
    let rules = Feed::new(fetch);
    rules_cell.set_value(Some(rules));
    Effect::new(move |_| {
        if open.get() {
            let _ = list.get();
            rules.items.set(Vec::new());
            q_snap.set(q.get_untracked());
            rules.reload(None, false, None);
        }
    });
    let title =
        Signal::derive(move || format!("Rules in {}", list.get().map(|l| l.1).unwrap_or_default()));
    view! {
        <Drawer fill=true open=open title=title>
            <div class="search">
                <Icon name="search" />
                <label class="sr" for="ruleQ">"Search rules"</label>
                <input class="input mono" id="ruleQ" placeholder="Search rules" autocomplete="off"
                    prop:value=move || q.get()
                    on:input=move |ev| {
                        q.set(event_target_value(&ev));
                        t.set_value(Some(Timeout::new(250, move || {
                            q_snap.set(q.get_untracked());
                            rules.reload(None, false, None);
                        })));
                    } />
            </div>
            <span class="hint" aria-live="polite">{move || format!(
                "Showing {} of {} cosmetic, scriptlet and other extended rules",
                format_number(rules.items.with(|v| v.len()) as u64), format_number(rules.total.get() as u64))}</span>
            <VList
                items=rules.items
                row_h=Signal::derive(|| 52.0)
                key=|r: &api_types::ExtRuleResponse| r.index.to_string()
                render=Callback::new(|r: api_types::ExtRuleResponse| view! {
                    <div class="hrow rrow" title=r.raw.clone()>
                        <code>{r.raw.clone()}</code>
                        <small>{r.kind.clone()}" \u{b7} "{rule_state_label(&r.state)}{r.reason.clone().map(|x| format!(" ({x})"))}</small>
                    </div>
                }.into_any())
                on_end=Callback::new(move |()| rules.more())
                error=rules.error
                on_retry=Callback::new(move |()| rules.retry())
                on_anchor=Callback::new(|_| ())
                reset=rules.tok
                label="Rules"
            />
        </Drawer>
    }
}

thread_local! {
    static NUDGE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Ask the build poll to check again soon (call after a write succeeds).
fn nudge_build_poll() {
    NUDGE.with(|n| n.set(true));
}

fn take_nudge() -> bool {
    NUDGE.with(|n| n.replace(false))
}

fn peek_nudge() -> bool {
    NUDGE.with(|n| n.get())
}

/// True while the page is in a background tab.
fn tab_hidden() -> bool {
    web_sys::window()
        .and_then(|w| w.document())
        .is_some_and(|d| d.hidden())
}

/// Readable label for a rule state code.
fn rule_state_label(state: &str) -> String {
    match state {
        "active" => "active",
        "dropped_untrusted" => "dropped (list not trusted)",
        "unsupported" => "unsupported",
        "invalid" => "invalid",
        "badfiltered" => "disabled by $badfilter",
        "badfilter" => "$badfilter",
        "not_enforced" => "matched, not enforced yet",
        "not_applicable" => "not applicable to a proxy",
        "unknown" => "unknown (index rebuilt)",
        other => return other.replace('_', " "),
    }
    .to_string()
}

/// One-line build state: idle totals, download progress, compiling or the last failure.
#[component]
fn BuildIndicator(summary: RwSignal<Option<BuildSummary>>) -> impl IntoView {
    view! {
        <div class="explain-out" role="status">
            {move || match summary.get() {
                None => view! { <span class="dim">"Build state unknown"</span> }.into_any(),
                Some(b) => {
                    let state = match &b.state {
                        BuildState::Idle => "Idle".to_string(),
                        BuildState::Fetching { done, total } => format!("Fetching lists {done}/{total}"),
                        BuildState::Compiling => "Compiling".to_string(),
                        BuildState::Failed { error } => format!("Last build failed (previous rules still active): {error}"),
                    };
                    let failed = matches!(b.state, BuildState::Failed { .. });
                    let totals = format!(
                        "{} network, {} cosmetic, {} domains, {} handed off (not enforced yet), built in {} ms",
                        format_number(b.network as u64), format_number(b.cosmetic as u64),
                        format_number(b.domain_set as u64), format_number(b.ext as u64),
                        format_number(b.compile_ms)
                    );
                    view! {
                        <div>
                            <Pill kind=if failed { "error" } else if b.building { "passthrough" } else { "ok" } text=state />
                            " "<span class="dim">{if b.building { "Building... ".to_string() } else { String::new() }}{totals}</span>
                        </div>
                    }.into_any()
                }
            }}
        </div>
    }
}

/// Rule counts and the first parse issues of a list's last build.
#[component]
fn ReportSummary(id: String, reports: RwSignal<HashMap<String, ListReport>>) -> impl IntoView {
    move || {
        reports.get().get(&id).map(|r| {
            let counts = format!(
                "{} network, {} cosmetic, {} handed off, {} skipped, {} deduped, {} compressed, {} rejected",
                format_number(r.network as u64),
                format_number(r.cosmetic as u64),
                format_number(r.ext as u64),
                format_number(r.skipped as u64),
                format_number(r.deduped as u64),
                format_number(r.compressed as u64),
                format_number(r.rejected as u64)
            );
            let issues = r.issues.clone();
            let n = r.error_count;
            view! {
                <div class="hint">{counts}</div>
                {(n > 0).then(|| view! {
                    <details>
                        <summary>{format!("{n} parse issue(s)")}</summary>
                        <ul>
                            {issues.into_iter().map(|i| view! {
                                <li>{format!("line {}: {}", i.line, i.reason)}</li>
                            }).collect_view()}
                        </ul>
                    </details>
                })}
            }
        })
    }
}

#[cfg(test)]
mod state_label_tests {
    use super::rule_state_label;

    #[test]
    fn rule_states_read_as_words() {
        assert_eq!(
            rule_state_label("dropped_untrusted"),
            "dropped (list not trusted)"
        );
        assert_eq!(rule_state_label("some_new_state"), "some new state");
    }
}

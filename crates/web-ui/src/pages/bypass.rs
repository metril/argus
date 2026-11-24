//! Bypass: Argus lists, fail-safe banner, your entries (vlist), subscriptions.

use std::rc::Rc;

use gloo_timers::callback::Timeout;
use leptos::prelude::*;

use super::vlist::*;
use crate::api::bypass::*;
use crate::api::ApiClient;
use crate::components::{ConfirmButton, Drawer, Icon, Layout, Pill, Segmented, Switch};
use crate::state::use_app_state;
use crate::utils::{fmt_ago, format_number};

fn mode_opts() -> Vec<(String, String)> {
    vec![
        ("no_decrypt".into(), "Don't decrypt".into()),
        ("full".into(), "Bypass entirely".into()),
    ]
}

#[component]
pub fn BypassPage() -> impl IntoView {
    let app = StoredValue::new(use_app_state());
    let argus = RwSignal::new(Option::<ArgusListsStatus>::None);
    let settings = RwSignal::new(Option::<BypassSettings>::None);
    let subs = RwSignal::new(Vec::<BypassSubscriptionDto>::new());
    let suggested = RwSignal::new(Vec::<SuggestedSubscription>::new());
    let cats = Signal::derive(move || {
        argus
            .read()
            .as_ref()
            .map(|a| a.categories.clone())
            .unwrap_or_default()
    });
    let counts = RwSignal::new(api_types::BypassEntryCounts::default());
    let checking = RwSignal::new(false);

    let load_top = move || {
        wasm_bindgen_futures::spawn_local(async move {
            let c = ApiClient::new();
            let mut errs = Vec::<String>::new();
            match c.argus_lists().await {
                Ok(a) => argus.set(Some(a)),
                Err(e) => errs.push(e.to_string()),
            }
            match c.bypass_settings().await {
                Ok(s) => settings.set(Some(s)),
                Err(e) => errs.push(e.to_string()),
            }
            match c.list_bypass_subscriptions().await {
                Ok(s) => subs.set(s),
                Err(e) => errs.push(e.to_string()),
            }
            match c.suggested_bypass_subscriptions().await {
                Ok(s) => suggested.set(s),
                Err(e) => errs.push(e.to_string()),
            }
            if let Some(e) = errs.first() {
                app.get_value()
                    .error(format!("Failed to load bypass data: {e}"));
            }
        });
    };
    load_top();

    let check_now = move || {
        checking.set(true);
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().refresh_argus_lists().await {
                Ok(a) => {
                    argus.set(Some(a));
                    app.get_value().success("Argus lists are up to date");
                }
                Err(e) => app.get_value().error(format!("Update check failed: {e}")),
            }
            if let Ok(s) = ApiClient::new().bypass_settings().await {
                settings.set(Some(s));
            }
            checking.set(false);
        });
    };

    let set_setting = move |u: UpdateBypassSettings, ok: &'static str| {
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().update_bypass_settings(&u).await {
                Ok(s) => {
                    settings.set(Some(s));
                    app.get_value().success(ok);
                }
                Err(e) => app.get_value().error(format!("Failed to save: {e}")),
            }
        });
    };

    // ---- category hosts drawer ----
    let hosts_open = RwSignal::new(false);
    let hosts_title = RwSignal::new(String::new());
    let hosts_id = RwSignal::new(String::new());
    let hosts_q = RwSignal::new(String::new());
    // The query the loaded pages were fetched with (see the rules drawer).
    let hosts_q_snap = RwSignal::new(String::new());
    let hosts_t = StoredValue::new_local(None::<Timeout>);
    let hosts_fetch: Fetcher<String> = Rc::new(move |cursor, _| {
        let (id, q) = (hosts_id.get_untracked(), hosts_q_snap.get_untracked());
        Box::pin(async move {
            match ApiClient::new()
                .bypass_category_hosts(&id, &q, cursor.as_deref())
                .await
            {
                Ok(r) => Ok((r.items, r.next_cursor, r.total)),
                Err(e) => {
                    app.get_value().error(format!("Failed to load hosts: {e}"));
                    Err(e)
                }
            }
        })
    });
    let hosts = Feed::new(hosts_fetch);
    let load_hosts = move || {
        hosts_q_snap.set(hosts_q.get_untracked());
        hosts.reload(None, false, None);
    };

    // ---- entries (vlist) ----
    let q = RwSignal::new(query_get("bq").unwrap_or_default());
    let mode = RwSignal::new(query_get("bm").unwrap_or_default());
    let sort = RwSignal::new(query_get("bs").unwrap_or_else(|| "az".into()));
    let anchor0 = query_get("ba");
    let debounce = StoredValue::new_local(None::<Timeout>);
    let anchor_t = StoredValue::new_local(None::<Timeout>);
    let dead = RwSignal::new(Vec::<char>::new());
    let row_h = Signal::derive(move || if is_narrow() { 92.0 } else { 52.0 });
    let q_in = RwSignal::new(q.get_untracked());
    let new_host = RwSignal::new(String::new());
    let new_mode = RwSignal::new("no_decrypt".to_string());
    let reload = RwSignal::new(0u32);

    let fetch: Fetcher<BypassEntryDto> = Rc::new(move |cursor, from| {
        let (qv, m, so) = (
            q.get_untracked(),
            mode.get_untracked(),
            sort.get_untracked(),
        );
        Box::pin(async move {
            match ApiClient::new()
                .list_bypass_entries(&qv, &m, &so, cursor.as_deref(), from.as_deref())
                .await
            {
                Ok(r) => {
                    dead.set(dead_letters(&r.counts.letters));
                    counts.set(r.counts);
                    Ok((r.items, r.next_cursor, r.total))
                }
                Err(e) => {
                    app.get_value()
                        .error(format!("Failed to load entries: {e}"));
                    Err(e)
                }
            }
        })
    });
    let feed = Feed::new(fetch);
    let first = StoredValue::new_local(true);
    Effect::new(move |_| {
        reload.track();
        q.track();
        mode.track();
        sort.track();
        let from = if first.get_value() {
            first.set_value(false);
            if sort.get_untracked() == "az" {
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
            ("bq", Some(q.get())),
            ("bm", Some(mode.get())),
            ("bs", (so != "az").then_some(so)),
            ("ba", None),
        ]);
    });
    let on_anchor = Callback::new(move |i: usize| {
        if sort.get_untracked() != "az" {
            return;
        }
        let label = feed
            .items
            .with_untracked(|v: &Vec<BypassEntryDto>| v.get(i).map(|r| r.pattern.clone()));
        anchor_t.set_value(Some(Timeout::new(250, move || query_set(&[("ba", label)]))));
    });

    let add_entry = move || {
        let host = new_host.get_untracked().trim().to_string();
        if host.is_empty() {
            return;
        }
        let m = parse_mode(&new_mode.get_untracked());
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().create_bypass_entry(&host, m).await {
                Ok(_) => {
                    new_host.set(String::new());
                    app.get_value().success(format!("Added {host}"));
                    reload.update(|n| *n += 1);
                }
                Err(e) => app.get_value().error(format!("Could not add: {e}")),
            }
        });
    };
    // Focus the add field when arriving via the palette (#add).
    if web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .is_some_and(|h| h == "#add")
    {
        gloo_timers::callback::Timeout::new(300, || {
            if let Some(el) = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.get_element_by_id("bpNew"))
            {
                use wasm_bindgen::JsCast;
                if let Ok(h) = el.dyn_into::<web_sys::HtmlElement>() {
                    let _ = h.focus();
                }
            }
        })
        .forget();
    }

    // ---- subscriptions ----
    let sub_open = RwSignal::new(false);
    let sub_name = RwSignal::new(String::new());
    let sub_url = RwSignal::new(String::new());
    let sub_mode = RwSignal::new("no_decrypt".to_string());
    let add_sub = move |r: CreateBypassSubscription| {
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().create_bypass_subscription(&r).await {
                Ok(s) => {
                    app.get_value().success(format!("Subscribed to {}", s.name));
                    sub_open.set(false);
                    load_top();
                }
                Err(e) => app.get_value().error(format!("Could not subscribe: {e}")),
            }
        });
    };

    let total_hosts = move || {
        argus
            .read()
            .as_ref()
            .map(|a| {
                a.categories
                    .iter()
                    .filter(|c| c.enabled)
                    .map(|c| c.host_count)
                    .sum::<usize>()
            })
            .unwrap_or(0)
            + counts.read().all
            + subs
                .read()
                .iter()
                .filter(|s| s.enabled)
                .map(|s| s.host_count)
                .sum::<usize>()
    };
    let failsafe = move || {
        settings
            .read()
            .as_ref()
            .map(|s| s.failsafe.clone())
            .unwrap_or_default()
    };
    let mode_counts = move |m: &str| {
        let c = counts.get();
        match m {
            "no_decrypt" => c.no_decrypt,
            "full" => c.full,
            _ => c.all,
        }
    };

    view! {
        <Layout>
            <div class="card bpstrip">
                <p class="bpex">
                    <b>"Don't decrypt"</b>" (the default, as in AdGuard) tunnels a site as is: host blocking still applies and it is logged by host. "
                    <b>"Bypass entirely"</b>" also skips filtering and logging. Choose it per category or entry."
                </p>
                <p class="bpcnt" aria-live="polite"><b>{move || format_number(total_hosts() as u64)}</b>" hosts bypassed"</p>
            </div>

            <div class="card">
                <div class="card-h">
                    <h3>"Argus lists"</h3>
                    <span class="sub">{move || argus.read().as_ref().map(|a| format!(
                        "Subscribed by default \u{b7} {} \u{b7} updated {}",
                        a.version.clone().map(|v| if v.starts_with('v') { v } else { format!("v{v}") }).unwrap_or_else(|| "not loaded".into()),
                        a.updated_at.as_deref().map(fmt_ago).unwrap_or_else(|| "never".into())
                    )).unwrap_or_default()}</span>
                    <div class="r">
                        <button class="btn sm" type="button" disabled=move || checking.get() on:click=move |_| check_now()>
                            {move || if checking.get() { "Checking..." } else { "Check now" }}
                        </button>
                    </div>
                </div>
                <div class="card-b">
                    {move || argus.read().as_ref().filter(|a| a.skipped_lines > 0).map(|a| view! {
                        <span class="dim" title=a.skipped_sample.join("\n")>{format!("{} lines skipped (too broad or invalid)", a.skipped_lines)}</span>
                    })}
                    {move || argus.read().as_ref().and_then(|a| a.last_error.clone()).map(|e| view! { <span class="err" role="alert">{format!("Last update failed: {e}")}</span> })}
                    {move || argus.read().as_ref().and_then(|a| a.roots.clone()).map(|r| view! {
                        <span class="dim">{format!("Trusted roots: {} ({} roots{})", if r.signed { format!("signed set {}", r.serial) } else { "built-in set".to_string() }, r.roots, r.last_checked.as_deref().map(|t| format!(", checked {}", crate::utils::fmt_datetime(t))).unwrap_or_default())}</span>
                        {r.last_error.clone().map(|e| view! { <span class="err" role="alert">{format!("Trusted roots update failed: {e}")}</span> })}
                    })}
                    <div class="srow cat">
                        <Switch
                            checked=Signal::derive(move || settings.read().as_ref().map(|s| s.ev_no_decrypt).unwrap_or(false))
                            label="Don't decrypt sites with EV certificates"
                            on_change=Callback::new(move |v| set_setting(UpdateBypassSettings { ev_no_decrypt: Some(v), ..Default::default() }, "EV setting saved"))
                        />
                        <div class="txt">
                            <b>"Sites with EV certificates"</b>
                            <small>"Banks often use Extended Validation certificates. Argus checks the real certificate before decrypting and tunnels these instead."</small>
                        </div>
                        <Pill kind="passthrough" text="don't decrypt" />
                    </div>
                    <For
                        each=move || cats.get()
                        key=|c| c.id.clone()
                        children=move |c| {
                            let (id1, id2, id3) = (c.id.clone(), c.id.clone(), c.id.clone());
                            let (title, title2) = (c.name.clone(), c.name.clone());
                            let r = live_row(cats, c, |c: &api_types::ArgusCategoryDto| c.id.as_str());
                            let update = move |id: String, u: UpdateBypassCategory| {
                                wasm_bindgen_futures::spawn_local(async move {
                                    match ApiClient::new().update_bypass_category(&id, &u).await {
                                        Ok(_) => {
                                            if let Ok(a) = ApiClient::new().argus_lists().await { argus.set(Some(a)); }
                                        }
                                        Err(e) => app.get_value().error(format!("Failed to save: {e}")),
                                    }
                                });
                            };
                            view! {
                                <div class=move || if r.with(|c| c.enabled) { "srow cat" } else { "srow cat off" }>
                                    <Switch
                                        checked=Signal::derive(move || r.with(|c| c.enabled))
                                        label=format!("{title}")
                                        on_change=Callback::new(move |v| update(id1.clone(), UpdateBypassCategory { enabled: Some(v), ..Default::default() }))
                                    />
                                    <div class="txt"><b>{move || r.with(|c| c.name.clone())}</b><small>{move || r.with(|c| c.description.clone())}</small></div>
                                    <Segmented
                                        label=format!("Mode, {title2}")
                                        options=mode_opts()
                                        value=Signal::derive(move || r.with(|c| mode_key(c.mode).to_string()))
                                        on_change=Callback::new(move |v: String| update(id2.clone(), UpdateBypassCategory { mode: Some(parse_mode(&v)), ..Default::default() }))
                                    />
                                    <span class="cnt dim num">{move || r.with(|c| if c.loaded { format!("{} hosts", format_number(c.host_count as u64)) } else { "not loaded".to_string() })}</span>
                                    <button class="btn sm ghost" type="button" on:click={
                                        let name = r.with_untracked(|c| c.name.clone());
                                        move |_| {
                                            hosts_id.set(id3.clone());
                                            hosts_title.set(name.clone());
                                            hosts_q.set(String::new());
                                            hosts.items.set(Vec::new());
                                            hosts_open.set(true);
                                            load_hosts();
                                        }
                                    }>"View hosts"</button>
                                </div>
                            }
                        }
                    />
                </div>
            </div>
            <span class="hint" style="margin-top:-8px">"Downloaded from the metril/argus-lists repo and checked against Argus's signing key. Nothing is bundled. Until these lists first load, Argus decrypts nothing (hostname blocking still works)."</span>

            <Show when=move || failsafe().active>
                <div class="suggest" role="note">
                    <span>
                        <b>"Decryption is paused."</b>
                        " Bypass lists haven't loaded yet, so Argus is tunnelling all HTTPS. Hostname blocking still works."
                        {move || failsafe().reason.map(|r| view! { <span class="dim">" "{r}</span> })}
                    </span>
                    <button class="btn sm" type="button" on:click=move |_| check_now()>"Retry now"</button>
                    <ConfirmButton
                        label="Decrypt anyway"
                        confirm_label="Decrypt anyway?"
                        on_confirm=Callback::new(move |()| set_setting(UpdateBypassSettings { decrypt_without_lists: Some(true), ..Default::default() }, "Decryption enabled without bypass lists"))
                    />
                </div>
            </Show>

            <div class="card">
                <div class="card-h">
                    <h3>"Your entries"</h3>
                    <span class="sub">{move || format!("{} entries", format_number(counts.get().all as u64))}</span>
                </div>
                <div class="card-b sitebar">
                    <div class="toolbar addsite">
                        <label class="sr" for="bpNew">"Host to bypass"</label>
                        <input class="input mono grow" id="bpNew" placeholder="Host or *.suffix, e.g. *.mybank.example" autocomplete="off"
                            prop:value=move || new_host.get()
                            on:input=move |ev| new_host.set(event_target_value(&ev))
                            on:keydown=move |ev: web_sys::KeyboardEvent| if ev.key() == "Enter" { add_entry() } />
                        <Segmented label="Mode for the new entry" options=mode_opts() value=new_mode on_change=Callback::new(move |v| new_mode.set(v)) />
                        <button class="btn primary" type="button" on:click=move |_| add_entry()><Icon name="plus" />"Add"</button>
                    </div>
                    <div class="toolbar">
                        <div class="search grow">
                            <Icon name="search" />
                            <label class="sr" for="bpQ">"Search entries"</label>
                            <input class="input mono" id="bpQ" placeholder="Search entries" autocomplete="off"
                                prop:value=move || q_in.get()
                                on:input=move |ev| {
                                    let v = event_target_value(&ev);
                                    q_in.set(v.clone());
                                    debounce.set_value(Some(Timeout::new(150, move || q.set(v))));
                                } />
                        </div>
                        <div class="seg" role="radiogroup" aria-label="Filter by mode">
                            {[("", "All"), ("no_decrypt", "Don't decrypt"), ("full", "Bypass entirely")].into_iter().map(|(v, l)| view! {
                                <button type="button" role="radio"
                                    aria-checked=move || (mode.get() == v).to_string()
                                    on:click=move |_| mode.set(v.to_string())>
                                    {l}<span class="n">{move || mode_counts(v)}</span>
                                </button>
                            }).collect_view()}
                        </div>
                        <select class="select" aria-label="Sort" prop:value=move || sort.get() on:change=move |ev| sort.set(event_target_value(&ev))>
                            <option value="az">"A to Z"</option>
                            <option value="recent">"Recent"</option>
                        </select>
                    </div>
                </div>
                <Show
                    when=move || !feed.items.with(|v| v.is_empty()) || feed.error.get().is_some()
                    fallback=move || view! {
                        <div class="empty">
                            <b>{move || if feed.loading.get() { "Loading..." } else { "No entries match" }}</b>
                            {move || (!feed.loading.get() && q.get().is_empty() && mode.get().is_empty()).then_some("Add a host above.")}
                        </div>
                    }
                >
                    <div class="vwrap">
                        <VList
                            items=feed.items
                            row_h=row_h
                            key=|e: &BypassEntryDto| e.id.clone()
                            render=Callback::new(move |e: BypassEntryDto| {
                                let (id1, id2) = (e.id.clone(), e.id.clone());
                                let pat = e.pattern.clone();
                                let r = live_row(feed.items, e, |e: &BypassEntryDto| e.id.as_str());
                                view! {
                                    <div class="siterow">
                                        <div class="h">
                                            <b title=pat.clone()>{pat.clone()}</b>
                                            <small>{move || r.with(|e| format!("{}{}", e.source, e.note.as_ref().map(|n| format!(" \u{b7} {n}")).unwrap_or_default()))}</small>
                                        </div>
                                        <Segmented
                                            label=format!("Mode for {pat}")
                                            options=mode_opts()
                                            value=Signal::derive(move || r.with(|e| mode_key(e.mode).to_string()))
                                            on_change=Callback::new(move |v: String| {
                                                let id = id1.clone();
                                                wasm_bindgen_futures::spawn_local(async move {
                                                    match ApiClient::new().update_bypass_entry(&id, parse_mode(&v)).await {
                                                        Ok(_) => reload.update(|n| *n += 1),
                                                        Err(e) => app.get_value().error(format!("Failed to save: {e}")),
                                                    }
                                                });
                                            })
                                        />
                                        <ConfirmButton label="Delete" confirm_label="Delete?" on_confirm=Callback::new(move |()| {
                                            let id = id2.clone();
                                            wasm_bindgen_futures::spawn_local(async move {
                                                match ApiClient::new().delete_bypass_entry(&id).await {
                                                    Ok(_) => { app.get_value().success("Entry deleted"); reload.update(|n| *n += 1); }
                                                    Err(e) => app.get_value().error(format!("Failed to delete: {e}")),
                                                }
                                            });
                                        }) />
                                    </div>
                                }.into_any()
                            })
                            on_end=Callback::new(move |()| feed.more())
                            error=feed.error
                            on_retry=Callback::new(move |()| feed.retry())
                            on_anchor=on_anchor
                            reset=feed.tok
                            label="Your bypass entries"
                        />
                        <nav class="azrail" aria-label="Jump to letter" hidden=move || !(sort.get() == "az" && feed.total.get() > 12)>
                            {LETTERS.iter().map(|&l| view! {
                                <button type="button" disabled=move || dead.get().contains(&l)
                                    on:click=move |_| feed.reload(
                                        Some(l.to_string()), true,
                                        Some(Callback::new(move |n: usize| {
                                            if n == 0 {
                                                dead.update(|d| d.push(l));
                                                app.get_value().info(format!("No entries starting with {}", l.to_ascii_uppercase()));
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
                        if !q.get().is_empty() || !mode.get().is_empty() { format!("{n} matches") } else { format!("{n} entries") }
                    }}</span>
                    <span>{move || {
                        let n = feed.items.with(|v| v.len());
                        if feed.next.get().is_some() { format!("showing 1-{n} \u{b7} scroll for more") } else { "end of list".to_string() }
                    }}</span>
                </div>
            </div>

            <div class="card">
                <div class="card-h">
                    <h3>"Subscriptions"</h3>
                    <span class="sub">"External exclusion lists, fetched when Argus runs"</span>
                    <div class="r">
                        <button class="btn sm primary" type="button" on:click=move |_| { sub_name.set(String::new()); sub_url.set(String::new()); sub_mode.set("no_decrypt".into()); sub_open.set(true); }>
                            <Icon name="plus" />"Add subscription"
                        </button>
                    </div>
                </div>
                <div class="card-b sitebar">
                    <span class="lbl">"Suggested lists"</span>
                    <div class="chips" role="group" aria-label="Suggested subscriptions">
                        <For each=move || suggested.get() key=|s| s.id.clone() children=move |s| {
                            let id = s.id.clone();
                            let r = live_row(suggested, s, |s: &SuggestedSubscription| s.id.as_str());
                            let subscribed = move || r.with(|s| s.subscribed);
                            view! {
                                <button type="button" class="chip" aria-pressed=move || subscribed().to_string() disabled=subscribed title=r.with_untracked(|s| s.description.clone())
                                    on:click=move |_| add_sub(CreateBypassSubscription { suggested_id: Some(id.clone()), ..Default::default() })>
                                    <span class="ck"><Icon name="check" /></span>
                                    {move || r.with(|s| if s.subscribed { s.name.clone() } else { format!("+ {}", s.name) })}
                                </button>
                            }
                        } />
                    </div>
                    <span class="hint">"Maintained by AdGuard and downloaded when Argus runs. Nothing is bundled."</span>
                </div>
                <ul class="flist" aria-label="Bypass subscriptions">
                    <For each=move || subs.get() key=|s| s.id.clone() children=move |s| {
                        let (id1, id2, id3) = (s.id.clone(), s.id.clone(), s.id.clone());
                        let name0 = s.name.clone();
                        let r = live_row(subs, s, |s: &BypassSubscriptionDto| s.id.as_str());
                        view! {
                            <li>
                                <Switch
                                    checked=Signal::derive(move || r.with(|s| s.enabled))
                                    label=format!("Enable {name0}")
                                    on_change=Callback::new(move |v| {
                                        let id = id1.clone();
                                        wasm_bindgen_futures::spawn_local(async move {
                                            match ApiClient::new().update_bypass_subscription(&id, &UpdateBypassSubscription { enabled: Some(v), ..Default::default() }).await {
                                                Ok(_) => load_top(),
                                                Err(e) => app.get_value().error(format!("Failed to save: {e}")),
                                            }
                                        });
                                    })
                                />
                                <div style="min-width:0"><div class="nm">{move || r.with(|s| s.name.clone())}</div><div class="url">{move || r.with(|s| s.url.clone())}</div></div>
                                <div class="meta">
                                    {move || r.with(|s| match s.last_error.clone() {
                                        Some(e) => view! { <span title=e><Pill kind="error" text="error" /></span> }.into_any(),
                                        None => view! { <Pill kind="passthrough" text=mode_label(s.mode) /> }.into_any(),
                                    })}
                                    <span class="cnt num">{move || r.with(|s| format!("{} hosts", format_number(s.host_count as u64)))}</span>
                                    <span class="tm">{move || r.with(|s| s.last_fetched.as_deref().map(fmt_ago).unwrap_or_else(|| "never".into()))}</span>
                                </div>
                                <div class="meta">
                                    <button class="btn sm ghost act" type="button" on:click=move |_| {
                                        let id = id2.clone();
                                        wasm_bindgen_futures::spawn_local(async move {
                                            match ApiClient::new().refresh_bypass_subscription(&id).await {
                                                Ok(_) => { app.get_value().success("Subscription refreshed"); load_top(); }
                                                Err(e) => app.get_value().error(format!("Refresh failed: {e}")),
                                            }
                                        });
                                    }>"Update"</button>
                                    <ConfirmButton label="Delete" confirm_label="Delete?" on_confirm=Callback::new(move |()| {
                                        let id = id3.clone();
                                        wasm_bindgen_futures::spawn_local(async move {
                                            match ApiClient::new().delete_bypass_subscription(&id).await {
                                                Ok(_) => load_top(),
                                                Err(e) => app.get_value().error(format!("Delete failed: {e}")),
                                            }
                                        });
                                    }) />
                                </div>
                                {move || r.with(|s| s.last_error.clone()).map(|e| view! { <div class="err" style="grid-column:2/-1">{e}</div> })}
                                {move || r.with(|s| (s.skipped_lines > 0).then(|| view! {
                                    <div class="dim" style="grid-column:2/-1" title=s.skipped_sample.join("\n")>{format!("{} lines skipped (too broad or invalid)", s.skipped_lines)}</div>
                                }))}
                            </li>
                        }
                    } />
                </ul>
                <Show when=move || subs.read().is_empty()>
                    <div class="empty"><b>"No subscriptions"</b>"Pick a suggested list or add your own."</div>
                </Show>
            </div>

            <Drawer fill=true open=hosts_open title=Signal::derive(move || format!("{} hosts", hosts_title.get()))>
                <div class="search">
                    <Icon name="search" />
                    <label class="sr" for="hostQ">"Search hosts"</label>
                    <input class="input mono" id="hostQ" placeholder="Search hosts" autocomplete="off"
                        prop:value=move || hosts_q.get()
                        on:input=move |ev| {
                            hosts_q.set(event_target_value(&ev));
                            hosts_t.set_value(Some(Timeout::new(200, load_hosts)));
                        } />
                </div>
                <span class="hint" aria-live="polite">{move || format!("Showing {} of {}", hosts.items.with(|h| h.len()), format_number(hosts.total.get() as u64))}</span>
                <VList
                    items=hosts.items
                    row_h=Signal::derive(|| 34.0)
                    key=|h: &String| h.clone()
                    render=Callback::new(|h: String| view! { <div class="hrow" title=h.clone()>{h.clone()}</div> }.into_any())
                    on_end=Callback::new(move |()| hosts.more())
                    error=hosts.error
                    on_retry=Callback::new(move |()| hosts.retry())
                    on_anchor=Callback::new(|_| ())
                    reset=hosts.tok
                    label="Hosts"
                />
            </Drawer>

            <Drawer
                open=sub_open
                title="Add subscription"
                footer=std::sync::Arc::new(move || view! {
                    <button class="btn ghost" type="button" on:click=move |_| sub_open.set(false)>"Cancel"</button>
                    <button class="btn primary" type="button" on:click=move |_| add_sub(CreateBypassSubscription {
                        name: Some(sub_name.get_untracked()),
                        url: Some(sub_url.get_untracked()),
                        mode: Some(parse_mode(&sub_mode.get_untracked())),
                        ..Default::default()
                    })>"Subscribe"</button>
                }.into_any())
            >
                <div class="field"><label for="subName">"Name"</label>
                    <input class="input" id="subName" prop:value=move || sub_name.get() on:input=move |ev| sub_name.set(event_target_value(&ev)) /></div>
                <div class="field"><label for="subUrl">"URL"</label>
                    <input class="input mono" id="subUrl" placeholder="https://example.com/exclusions.txt" prop:value=move || sub_url.get() on:input=move |ev| sub_url.set(event_target_value(&ev)) /></div>
                <div class="field"><span class="lbl">"Mode"</span>
                    <Segmented label="Mode" options=mode_opts() value=sub_mode on_change=Callback::new(move |v| sub_mode.set(v)) /></div>
            </Drawer>
        </Layout>
    }
}

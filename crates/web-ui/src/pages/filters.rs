//! Filter lists management page

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use leptos::prelude::*;
use uuid::Uuid;
use web_sys::{HtmlInputElement, HtmlTextAreaElement};

use crate::api::filters::{
    BuildState, BuildSummary, CatalogueEntryResponse, FilterList, ListReport,
};
use crate::api::ApiClient;
use crate::components::{Card, Layout, Modal};
use crate::state::use_app_state;

/// Filters page component
#[component]
pub fn FiltersPage() -> impl IntoView {
    let app_state = use_app_state();

    let filters = RwSignal::new(Vec::<FilterList>::new());
    let loading = RwSignal::new(true);

    // Modal state
    let show_modal = RwSignal::new(false);
    let add_name = RwSignal::new(String::new());
    let add_url = RwSignal::new(String::new());
    let add_format = RwSignal::new("auto".to_string());
    let add_allowlist = RwSignal::new(false);

    // Build state (polled), per-list reports, catalogue
    let build = RwSignal::new(Option::<BuildSummary>::None);
    let reports = RwSignal::new(HashMap::<String, ListReport>::new());
    let show_catalogue = RwSignal::new(false);
    let catalogue = RwSignal::new(Vec::<CatalogueEntryResponse>::new());
    let flag_change = RwSignal::new(Option::<(String, Option<bool>, Option<bool>)>::None);
    let catalogue_add = RwSignal::new(Option::<String>::None);
    let reload_lists = RwSignal::new(0u32);

    // Stats
    let total_requests = RwSignal::new(0u64);
    let requests_blocked = RwSignal::new(0u64);

    // Custom rules editor
    let custom_rules = RwSignal::new(String::new());
    // ETag of the rules as last read; sent as If-Match so concurrent edits are not overwritten.
    let rules_etag = RwSignal::new(Option::<String>::None);
    let saving_rules = RwSignal::new(false);
    let do_save_rules = RwSignal::new(false);

    // Action signals
    let do_add = RwSignal::new(false);
    let delete_id = RwSignal::new(Option::<String>::None);

    // Load filters
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            let _ = reload_lists.get();
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let client = ApiClient::new();

                match client.list_filter_lists(1, 100).await {
                    Ok(response) => {
                        for l in &response.items {
                            if let Ok(r) = client.get_list_report(&l.id).await {
                                reports.update(|m| {
                                    m.insert(l.id.clone(), r);
                                });
                            }
                        }
                        filters.set(response.items);
                    }
                    Err(e) => {
                        app_state.error(format!("Failed to load filters: {}", e));
                    }
                }

                if let Ok(stats) = client.get_filter_stats().await {
                    total_requests.set(stats.total_requests);
                    requests_blocked.set(stats.blocked_requests);
                }

                if let Ok((resp, etag)) = client.get_custom_rules().await {
                    custom_rules.set(resp.rules);
                    rules_etag.set(etag);
                }

                loading.set(false);
            });
        });
    }

    // Poll the build state while the page is open; reload lists when a build finishes.
    {
        let alive = Arc::new(AtomicBool::new(true));
        let flag = alive.clone();
        on_cleanup(move || flag.store(false, Ordering::Relaxed));
        wasm_bindgen_futures::spawn_local(async move {
            let client = ApiClient::new();
            let mut was_building = false;
            while alive.load(Ordering::Relaxed) {
                if let Ok(b) = client.get_build_summary().await {
                    if was_building && !b.building {
                        reload_lists.update(|n| *n += 1);
                    }
                    was_building = b.building;
                    build.set(Some(b));
                }
                gloo_timers::future::TimeoutFuture::new(3000).await;
            }
        });
    }

    // Toggle enabled / allowlist
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            if let Some((id, enabled, allowlist)) = flag_change.get() {
                let app_state = app_state.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    match ApiClient::new()
                        .set_list_flags(&id, enabled, allowlist)
                        .await
                    {
                        Ok(updated) => filters.update(|f| {
                            if let Some(x) = f.iter_mut().find(|x| x.id == id) {
                                *x = updated;
                            }
                        }),
                        Err(e) => app_state.error(format!("Failed to update list: {}", e)),
                    }
                    flag_change.set(None);
                });
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
                    let client = ApiClient::new();
                    match client.add_from_catalogue(&id).await {
                        Ok(list) => {
                            catalogue.update(|c| {
                                if let Some(e) = c.iter_mut().find(|e| e.id == id) {
                                    e.added = true;
                                }
                            });
                            filters.update(|f| f.push(list));
                            app_state.success("List added from the catalogue");
                        }
                        Err(e) => app_state.error(format!("Failed to add list: {}", e)),
                    }
                    catalogue_add.set(None);
                });
            }
        });
    }

    // Add filter effect
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            if do_add.get() {
                let name = add_name.get();
                let url = add_url.get();
                let app_state = app_state.clone();

                wasm_bindgen_futures::spawn_local(async move {
                    let client = ApiClient::new();
                    let filter_id = Uuid::new_v4().to_string();

                    let format = add_format.get_untracked();
                    let allow = add_allowlist.get_untracked();
                    match client
                        .add_filter_list(&filter_id, &name, &url, true, &format, allow)
                        .await
                    {
                        Ok(filter) => {
                            filters.update(|f| f.push(filter));
                            app_state.success("Filter list added");
                            show_modal.set(false);
                            add_name.set(String::new());
                            add_url.set(String::new());
                        }
                        Err(e) => {
                            app_state.error(format!("Failed to add filter: {}", e));
                        }
                    }
                    do_add.set(false);
                });
            }
        });
    }

    // Save custom rules effect
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            if do_save_rules.get() {
                saving_rules.set(true);
                let app_state = app_state.clone();
                let rules = custom_rules.get();
                let etag = rules_etag.get_untracked().unwrap_or_default();
                wasm_bindgen_futures::spawn_local(async move {
                    let client = ApiClient::new();
                    match client.update_custom_rules(&rules, &etag).await {
                        Ok((_, new_etag)) => {
                            rules_etag.set(new_etag);
                            app_state.success("Custom rules saved")
                        }
                        Err(e) => app_state.error(format!("Failed to save rules: {}", e)),
                    }
                    saving_rules.set(false);
                    do_save_rules.set(false);
                });
            }
        });
    }

    // Delete filter effect
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            if let Some(id) = delete_id.get() {
                let app_state = app_state.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let client = ApiClient::new();

                    match client.delete_filter_list(&id).await {
                        Ok(_) => {
                            filters.update(|f| f.retain(|filter| filter.id != id));
                            app_state.success("Filter list deleted");
                        }
                        Err(e) => {
                            app_state.error(format!("Failed to delete filter: {}", e));
                        }
                    }
                    delete_id.set(None);
                });
            }
        });
    }

    view! {
        <Layout>
            <div class="page-header">
                <h1 class="page-title">"Filter Lists"</h1>
                <div>
                    <button
                        class="btn btn-secondary"
                        on:click=move |_| {
                            show_catalogue.set(true);
                            wasm_bindgen_futures::spawn_local(async move {
                                if let Ok(c) = ApiClient::new().get_catalogue().await {
                                    catalogue.set(c);
                                }
                            });
                        }
                    >
                        "Catalogue"
                    </button>
                    " "
                    <button class="btn btn-primary" on:click=move |_| show_modal.set(true)>
                        "+ Add Filter List"
                    </button>
                </div>
            </div>

            <BuildIndicator summary=build />

            <div class="filters-stats">
                <div class="stat-badge">
                    <span class="stat-value">{total_requests}</span>
                    <span class="stat-label">"Requests Checked"</span>
                </div>
                <div class="stat-badge">
                    <span class="stat-value">{requests_blocked}</span>
                    <span class="stat-label">"Requests Blocked"</span>
                </div>
            </div>

            <Card class="filters-card">
                <Show when=move || !loading.get() fallback=|| view! {
                    <div class="loading">"Loading..."</div>
                }>
                    <For
                        each=move || filters.get()
                        key=|f| (f.id.clone(), f.enabled, f.allowlist, f.format.clone(), f.rule_count, f.last_error.clone())
                        children=move |filter| {
                            let id_for_delete = filter.id.clone();
                            let id_report = filter.id.clone();
                            let id_allow = filter.id.clone();
                            let id_enable = filter.id.clone();
                            let (allowlist, enabled) = (filter.allowlist, filter.enabled);
                            let format = filter.format.clone();
                            let last_error = filter.last_error.clone();
                            view! {
                                <div class={format!(
                                    "filter-item {}",
                                    if filter.enabled { "" } else { "disabled" }
                                )}>
                                    <div class="filter-info">
                                        <h3 class="filter-name">{filter.name.clone()}</h3>
                                        <p class="filter-url">{filter.url.clone()}</p>
                                        <div class="filter-meta">
                                            <span class="filter-rules">{filter.rule_count}" rules"</span>
                                            " | format: "
                                            {move || {
                                                let used = reports
                                                    .get()
                                                    .get(&id_report)
                                                    .map(|r| r.format.clone());
                                                match used {
                                                    Some(u) if format == "auto" => format!("auto ({u})"),
                                                    _ => format.clone(),
                                                }
                                            }}
                                        </div>
                                        <ReportSummary id=filter.id.clone() reports=reports />
                                        {last_error.map(|e| view! {
                                            <p class="form-error">"Last error: "{e}</p>
                                        })}
                                    </div>
                                    <div class="filter-actions">
                                        <label class="form-label">
                                            <input
                                                type="checkbox"
                                                prop:checked=enabled
                                                on:change=move |ev| {
                                                    let on = event_target::<HtmlInputElement>(&ev).checked();
                                                    flag_change.set(Some((id_enable.clone(), Some(on), None)));
                                                }
                                            />
                                            " Enabled"
                                        </label>
                                        <label class="form-label">
                                            <input
                                                type="checkbox"
                                                prop:checked=allowlist
                                                on:change=move |ev| {
                                                    let on = event_target::<HtmlInputElement>(&ev).checked();
                                                    flag_change.set(Some((id_allow.clone(), None, Some(on))));
                                                }
                                            />
                                            " Allowlist"
                                        </label>
                                        <button
                                            class="btn btn-danger"
                                            on:click=move |_| delete_id.set(Some(id_for_delete.clone()))
                                        >
                                            "Delete"
                                        </button>
                                    </div>
                                </div>
                            }
                        }
                    />

                    <Show when=move || filters.get().is_empty()>
                        <div class="empty-state">
                            <p>"No filter lists configured"</p>
                        </div>
                    </Show>
                </Show>
            </Card>

            <Card title="Custom Rules" class="filters-card">
                <p class="form-help">
                    "One rule per line in Adblock Plus / uBlock syntax. Use "
                    <code>"||ads.example^"</code>" to block, "<code>"@@||good.example^"</code>
                    " to allow (exceptions win over blocklists), or "<code>"example.com##.banner"</code>
                    " to hide elements. Changes apply after saving."
                </p>
                <textarea
                    class="form-input"
                    rows="8"
                    style="font-family: monospace; width: 100%;"
                    placeholder="||ads.example^&#10;@@||good.example^&#10;example.com##.sponsored"
                    prop:value=move || custom_rules.get()
                    on:input=move |ev| {
                        let target = event_target::<HtmlTextAreaElement>(&ev);
                        custom_rules.set(target.value());
                    }
                ></textarea>
                <div class="modal-actions">
                    <button
                        class="btn btn-primary"
                        disabled=move || saving_rules.get()
                        on:click=move |_| do_save_rules.set(true)
                    >
                        {move || if saving_rules.get() { "Saving..." } else { "Save Rules" }}
                    </button>
                </div>
            </Card>

            <Modal
                title="Add Filter List"
                open=show_modal
                on_close=Callback::new(move |_| show_modal.set(false))
            >
                <div class="form-field">
                    <label class="form-label">"Name"</label>
                    <input
                        type="text"
                        class="form-input"
                        placeholder="e.g., EasyList"
                        prop:value=move || add_name.get()
                        on:input=move |ev| {
                            let target = event_target::<HtmlInputElement>(&ev);
                            add_name.set(target.value());
                        }
                    />
                </div>
                <div class="form-field">
                    <label class="form-label">"URL"</label>
                    <input
                        type="text"
                        class="form-input"
                        placeholder="https://example.com/filters.txt"
                        prop:value=move || add_url.get()
                        on:input=move |ev| {
                            let target = event_target::<HtmlInputElement>(&ev);
                            add_url.set(target.value());
                        }
                    />
                </div>
                <div class="form-field">
                    <label class="form-label">"Format"</label>
                    <select
                        class="form-input"
                        on:change=move |ev| add_format.set(event_target_value(&ev))
                    >
                        {FORMATS.iter().map(|f| view! {
                            <option value=*f selected=move || add_format.get() == *f>{*f}</option>
                        }).collect_view()}
                    </select>
                    <p class="form-help">"auto detects the format from the content."</p>
                </div>
                <div class="form-field">
                    <label class="form-label">
                        <input
                            type="checkbox"
                            prop:checked=move || add_allowlist.get()
                            on:change=move |ev| add_allowlist.set(event_target::<HtmlInputElement>(&ev).checked())
                        />
                        " Allowlist (every rule becomes an exception)"
                    </label>
                </div>
                <div class="modal-actions">
                    <button class="btn btn-secondary" on:click=move |_| show_modal.set(false)>
                        "Cancel"
                    </button>
                    <button class="btn btn-primary" on:click=move |_| do_add.set(true)>
                        "Add"
                    </button>
                </div>
            </Modal>

            <Modal
                title="List Catalogue"
                open=show_catalogue
                on_close=Callback::new(move |_| show_catalogue.set(false))
            >
                <p class="form-help">
                    "Well-known hosts, domain and IP lists. Check each list's licence before use."
                </p>
                <For
                    each=move || catalogue.get()
                    key=|e| (e.id.clone(), e.added)
                    children=move |e| {
                        let id = e.id.clone();
                        view! {
                            <div class="filter-item">
                                <div class="filter-info">
                                    <h3 class="filter-name">{e.name.clone()}</h3>
                                    <div class="filter-meta">
                                        {e.format.clone()}" | "{e.category.clone()}" | "{e.licence.clone()}
                                    </div>
                                </div>
                                <div class="filter-actions">
                                    {if e.added {
                                        view! { <span class="filter-rules">"Added"</span> }.into_any()
                                    } else {
                                        view! {
                                            <button
                                                class="btn btn-primary"
                                                on:click=move |_| catalogue_add.set(Some(id.clone()))
                                            >
                                                "Add"
                                            </button>
                                        }.into_any()
                                    }}
                                </div>
                            </div>
                        }
                    }
                />
            </Modal>
        </Layout>
    }
}

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

/// One-line build state: idle totals, download progress, compiling or the last failure.
#[component]
fn BuildIndicator(summary: RwSignal<Option<BuildSummary>>) -> impl IntoView {
    view! {
        <div class="filters-stats">
            {move || match summary.get() {
                None => view! { <div class="stat-badge"><span class="stat-label">"Build state unknown"</span></div> }.into_any(),
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
                        b.network, b.cosmetic, b.domain_set, b.ext, b.compile_ms
                    );
                    view! {
                        <div class="stat-badge">
                            <span class="stat-value">{state}</span>
                            <span class="stat-label">
                                {if b.building { "Building... ".to_string() } else { String::new() }}
                                {totals}
                            </span>
                            {failed.then(|| view! { <span class="form-error">"See the server log for details"</span> })}
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
                "{} network, {} cosmetic, {} handed off, {} skipped, {} deduped, {} rejected",
                r.network, r.cosmetic, r.ext, r.skipped, r.deduped, r.rejected
            );
            let issues = r.issues.clone();
            let n = r.error_count;
            view! {
                <div class="filter-meta">{counts}</div>
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

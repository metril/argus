//! Userscripts management page: two-step install, updates, details, storage, import/export.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

use super::vlist::*;
use crate::api::userscripts::{
    ImportUserscriptsResponse, UpdateDiffDto, Userscript, UserscriptBundle, UserscriptCounts,
    UserscriptPlanResponse,
};
use crate::api::ApiClient;
use crate::components::{ConfirmButton, Drawer, Icon, Layout, ProfileSelector, Switch};
use crate::state::use_app_state;
use gloo_timers::callback::Timeout;
use std::rc::Rc;

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Grants that deserve a warning highlight.
pub fn is_sensitive_grant(grant: &str) -> bool {
    let g = grant.trim_start_matches("GM.").trim_start_matches("GM_");
    matches!(
        g,
        "xmlHttpRequest"
            | "xmlhttpRequest"
            | "cookie"
            | "download"
            | "setClipboard"
            | "notification"
    )
}

/// Human readable byte size.
pub fn fmt_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", n as f64 / 1048576.0)
    }
}

/// Counts of results by status, as `(ok, skipped, errors)`.
pub fn import_summary(r: &ImportUserscriptsResponse) -> (usize, usize, usize) {
    let mut t = (0, 0, 0);
    for x in &r.results {
        match x.status.as_str() {
            "installed" | "replaced" => t.0 += 1,
            "skipped" => t.1 += 1,
            _ => t.2 += 1,
        }
    }
    t
}

/// Update status label for the list column.
pub fn update_status(s: &Userscript) -> &'static str {
    if s.pending_update.is_some() {
        "Update pending approval"
    } else if s.update_url.is_some() {
        "Checkable"
    } else {
        "No update URL"
    }
}

/// Offer a text file as a browser download via Blob + anchor.
pub(crate) fn download_text(filename: &str, text: &str) -> Result<(), String> {
    let err = |e: wasm_bindgen::JsValue| format!("{:?}", e);
    let parts = js_sys::Array::new();
    parts.push(&wasm_bindgen::JsValue::from_str(text));
    let opts = web_sys::BlobPropertyBag::new();
    opts.set_type("application/json");
    let blob = web_sys::Blob::new_with_str_sequence_and_options(&parts, &opts).map_err(err)?;
    let url = web_sys::Url::create_object_url_with_blob(&blob).map_err(err)?;
    let doc = web_sys::window()
        .and_then(|w| w.document())
        .ok_or("no document")?;
    let a: web_sys::HtmlAnchorElement = doc
        .create_element("a")
        .map_err(err)?
        .dyn_into()
        .map_err(|_| "anchor")?;
    a.set_href(&url);
    a.set_download(filename);
    a.click();
    let _ = web_sys::Url::revoke_object_url(&url);
    Ok(())
}

/// The change sets of an update diff (added in red, removed plain, other widening flagged).
fn diff_rows(d: UpdateDiffDto) -> impl IntoView {
    let row = |label: &'static str, items: Vec<String>, cls: &'static str| {
        (!items.is_empty()).then(|| {
            view! {
                <div class="us-section"><h4>{label}</h4>
                    <div class="userscript-matches">
                        {items.into_iter().map(|i| view! { <span class=format!("match-pattern {cls}")>{i}</span> }).collect_view()}
                    </div></div>
            }
        })
    };
    view! {
        {row("Added matches", d.added_matches, "us-hot")}
        {row("Added connect", d.added_connect, "us-hot")}
        {row("Added grants", d.added_grants, "us-hot")}
        {row("Removed matches", d.removed_matches, "")}
        {row("Removed connect", d.removed_connect, "")}
        {row("Removed grants", d.removed_grants, "")}
        {row("Other widening", d.widened, "us-hot")}
    }
}

fn tag_list(items: Vec<String>, sensitive: bool) -> impl IntoView {
    items
        .into_iter()
        .map(|i| {
            let hot = sensitive && is_sensitive_grant(&i);
            view! {
                <span class=if hot { "match-pattern us-hot" } else { "match-pattern" }>{i}</span>
            }
        })
        .collect_view()
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

/// Userscripts page component
#[component]
pub fn UserscriptsPage() -> impl IntoView {
    let app = StoredValue::new(use_app_state());

    let counts = RwSignal::new(Option::<UserscriptCounts>::None);
    let q = RwSignal::new(query_get("uq").unwrap_or_default()); // debounced
    let status = RwSignal::new(query_get("um").unwrap_or_default());
    let sort = RwSignal::new(query_get("us").unwrap_or_else(|| "name".into()));
    let anchor0 = query_get("ua");
    let debounce = StoredValue::new_local(None::<Timeout>);
    let anchor_t = StoredValue::new_local(None::<Timeout>);
    let dead = RwSignal::new(Vec::<char>::new());
    let row_h = Signal::derive(move || if is_narrow() { 170.0 } else { 84.0 });
    let reload = RwSignal::new(0u32);

    let fetch: Fetcher<Userscript> = Rc::new(move |cursor, from| {
        let (qv, st, so) = (
            q.get_untracked(),
            status.get_untracked(),
            sort.get_untracked(),
        );
        Box::pin(async move {
            match ApiClient::new()
                .list_userscripts_paged(&qv, &st, &so, cursor.as_deref(), from.as_deref(), 40)
                .await
            {
                Ok(r) => {
                    dead.set(dead_letters(&r.counts.letters));
                    counts.set(Some(r.counts));
                    Ok((r.items, r.next_cursor, r.total))
                }
                Err(e) => {
                    app.get_value()
                        .error(format!("Failed to load userscripts: {}", e));
                    Err(e)
                }
            }
        })
    });
    let feed = Feed::new(fetch);
    let scripts = feed.items;
    let total_executions = RwSignal::new(0u64);

    // Install
    let show_install = RwSignal::new(false);
    let url_mode = RwSignal::new(false);
    let install_source = RwSignal::new(String::new());
    let install_url = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let plan = RwSignal::new(Option::<UserscriptPlanResponse>::None);
    let show_plan = RwSignal::new(false);
    let allow_all = RwSignal::new(false);

    // Details / source / storage
    let show_detail = RwSignal::new(false);
    let detail_id = RwSignal::new(Option::<String>::None);
    // (used, quota) bytes of the open script's storage; its values are paged and searchable.
    let storage = RwSignal::new(Option::<(u64, u64)>::None);
    let storage_q = RwSignal::new(String::new());
    let storage_t = StoredValue::new_local(None::<Timeout>);
    let storage_fetch: Fetcher<api_types::StorageValueDto> = Rc::new(move |cursor, _| {
        let id = detail_id.get_untracked().unwrap_or_default();
        let q = storage_q.get_untracked();
        Box::pin(async move {
            match ApiClient::new()
                .get_userscript_storage(&id, &q, cursor.as_deref())
                .await
            {
                Ok(s) => {
                    storage.set(Some((s.used_bytes, s.quota_bytes)));
                    Ok((s.values, s.next_cursor, s.total))
                }
                Err(e) => {
                    app.get_value()
                        .error(format!("Failed to load storage: {}", e));
                    Err(e)
                }
            }
        })
    });
    let sfeed = Feed::new(storage_fetch);
    let show_source = RwSignal::new(false);
    let source_content = RwSignal::new(String::new());

    // Pending update dialog
    let show_update = RwSignal::new(false);
    let update_id = RwSignal::new(Option::<String>::None);
    let update_allow_all = RwSignal::new(false);

    // Import / export
    let export_values = RwSignal::new(false);
    let show_import = RwSignal::new(false);
    let import_text = RwSignal::new(String::new());
    let import_replace = RwSignal::new(false);
    let import_results = RwSignal::new(Option::<ImportUserscriptsResponse>::None);

    // Load list (restarts on search/filter/sort/profile change)
    let first = StoredValue::new_local(true);
    Effect::new(move |_| {
        reload.track();
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
        reload.track();
        wasm_bindgen_futures::spawn_local(async move {
            if let Ok(stats) = ApiClient::new().get_userscript_stats().await {
                total_executions.set(stats.total_executions);
            }
        });
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
            .with_untracked(|v| v.get(i).map(|r| r.name.clone()));
        anchor_t.set_value(Some(Timeout::new(250, move || query_set(&[("ua", label)]))));
    });

    let by_id =
        move |id: Option<String>| id.and_then(|id| scripts.get().into_iter().find(|s| s.id == id));

    let load_storage = move |_id: String| sfeed.reload(None, false, None);

    let open_detail = move |id: String| {
        storage.set(None);
        sfeed.items.set(Vec::new());
        storage_q.set(String::new());
        detail_id.set(Some(id.clone()));
        show_detail.set(true);
        load_storage(id);
    };

    let do_plan = move |_| {
        let (source, url) = if url_mode.get() {
            (None, Some(install_url.get().trim().to_string()))
        } else {
            (Some(install_source.get()), None)
        };
        busy.set(true);
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().plan_userscript(source, url).await {
                Ok(p) => {
                    allow_all.set(false);
                    plan.set(Some(p));
                    show_plan.set(true);
                }
                Err(e) => app
                    .get_value()
                    .error(format!("Failed to plan install: {}", e)),
            }
            busy.set(false);
        });
    };

    let do_confirm = move |_| {
        let Some(p) = plan.get() else { return };
        let allow = allow_all.get();
        busy.set(true);
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new()
                .confirm_userscript_plan(&p.plan_id, allow)
                .await
            {
                Ok(_) => {
                    app.get_value().success("Userscript installed");
                    show_plan.set(false);
                    show_install.set(false);
                    plan.set(None);
                    install_source.set(String::new());
                    install_url.set(String::new());
                    reload.update(|n| *n += 1);
                }
                Err(e) => app.get_value().error(format!("Failed to install: {}", e)),
            }
            busy.set(false);
        });
    };

    let toggle = move |id: String, enabled: bool| {
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
                }
                Err(e) => app.get_value().error(format!("Failed to update: {}", e)),
            }
        });
    };

    let check_update = move |id: String| {
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().check_userscript_update(&id).await {
                Ok(r) => {
                    let msg = match r.status.as_str() {
                        "up_to_date" => "Already up to date".to_string(),
                        "pending_approval" => {
                            format!(
                                "Update {} needs approval",
                                r.new_version.unwrap_or_default()
                            )
                        }
                        s => format!("Update check: {}", s),
                    };
                    app.get_value().success(msg);
                }
                Err(e) => app.get_value().error(format!("Update check failed: {}", e)),
            }
            feed.refresh_loaded();
        });
    };

    let check_all = move |_| {
        let ids: Vec<String> = scripts
            .get()
            .into_iter()
            .filter(|s| s.update_url.is_some())
            .map(|s| s.id)
            .collect();
        wasm_bindgen_futures::spawn_local(async move {
            let client = ApiClient::new();
            let (mut pending, mut failed) = (0, 0);
            for id in &ids {
                match client.check_userscript_update(id).await {
                    Ok(r) if r.status == "pending_approval" => pending += 1,
                    Ok(_) => {}
                    Err(_) => failed += 1,
                }
            }
            let msg = format!(
                "Checked {} scripts: {} pending approval, {} failed",
                ids.len(),
                pending,
                failed
            );
            if failed > 0 {
                app.get_value().error(msg);
            } else {
                app.get_value().success(msg);
            }
            feed.refresh_loaded();
        });
    };

    let resolve_update = move |approve: bool| {
        let Some(id) = update_id.get() else { return };
        let allow = update_allow_all.get();
        wasm_bindgen_futures::spawn_local(async move {
            let client = ApiClient::new();
            let res = if approve {
                client
                    .approve_userscript_update(&id, allow)
                    .await
                    .map(|_| ())
            } else {
                client.discard_userscript_update(&id).await.map(|_| ())
            };
            match res {
                Ok(()) => {
                    app.get_value().success(if approve {
                        "Update applied"
                    } else {
                        "Update discarded"
                    });
                    show_update.set(false);
                    update_id.set(None);
                }
                Err(e) => app.get_value().error(format!("Update failed: {}", e)),
            }
            feed.refresh_loaded();
        });
    };

    let view_source = move |id: String| {
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().get_userscript_source(&id).await {
                Ok(r) => {
                    source_content.set(r.source);
                    show_source.set(true);
                }
                Err(e) => app
                    .get_value()
                    .error(format!("Failed to get source: {}", e)),
            }
        });
    };

    let uninstall = move |id: String| {
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().uninstall_userscript(&id).await {
                Ok(_) => {
                    app.get_value().success("Userscript uninstalled");
                    show_detail.set(false);
                    counts.update(|c| {
                        if let Some(c) = c {
                            c.all = c.all.saturating_sub(1);
                        }
                    });
                    feed.items.update(|v| v.retain(|x| x.id != id));
                    feed.total.update(|t| *t = t.saturating_sub(1));
                    feed.refresh_loaded();
                }
                Err(e) => app.get_value().error(format!("Failed to uninstall: {}", e)),
            }
        });
    };

    let clear_storage = move |id: String, name: Option<String>| {
        wasm_bindgen_futures::spawn_local(async move {
            let client = ApiClient::new();
            let res = match &name {
                Some(n) => client.delete_userscript_value(&id, n).await,
                None => client.clear_userscript_storage(&id).await,
            };
            match res {
                Ok(_) => load_storage(id),
                Err(e) => app
                    .get_value()
                    .error(format!("Failed to clear storage: {}", e)),
            }
            feed.refresh_loaded();
        });
    };

    let do_export = move |_| {
        let values = export_values.get();
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().export_userscripts(values).await {
                Ok(b) => {
                    let text = serde_json::to_string_pretty(&b).unwrap_or_default();
                    match download_text("userscripts-export.json", &text) {
                        Ok(()) => app.get_value().success("Exported"),
                        Err(e) => app.get_value().error(format!("Download failed: {}", e)),
                    }
                }
                Err(e) => app.get_value().error(format!("Export failed: {}", e)),
            }
        });
    };

    let on_file = move |ev: web_sys::Event| {
        let input = event_target::<web_sys::HtmlInputElement>(&ev);
        if let Some(file) = input.files().and_then(|f| f.get(0)) {
            wasm_bindgen_futures::spawn_local(async move {
                match wasm_bindgen_futures::JsFuture::from(file.text()).await {
                    Ok(v) => import_text.set(v.as_string().unwrap_or_default()),
                    Err(_) => app.get_value().error("Failed to read file"),
                }
            });
        }
    };

    let do_import = move |_| {
        let mut bundle: UserscriptBundle = match serde_json::from_str(&import_text.get()) {
            Ok(b) => b,
            Err(e) => {
                app.get_value().error(format!("Invalid bundle JSON: {}", e));
                return;
            }
        };
        bundle.on_conflict = Some(
            if import_replace.get() {
                "replace"
            } else {
                "skip"
            }
            .into(),
        );
        busy.set(true);
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().import_userscripts(&bundle).await {
                Ok(r) => {
                    let (ok, skipped, errs) = import_summary(&r);
                    let msg = format!("Import: {ok} done, {skipped} skipped, {errs} failed");
                    if errs > 0 {
                        app.get_value().error(msg);
                    } else {
                        app.get_value().success(msg);
                    }
                    import_results.set(Some(r));
                    reload.update(|n| *n += 1);
                }
                Err(e) => app.get_value().error(format!("Import failed: {}", e)),
            }
            busy.set(false);
        });
    };

    view! {
        <Layout>
            <div class="page-header">
                <h1 class="page-title">"Userscripts"</h1>
                <ProfileSelector reload=reload />
                <div class="userscript-actions">
                    <button class="btn" on:click=move |_| {
                        import_results.set(None);
                        show_import.set(true);
                    }>"Import"</button>
                    <button class="btn" on:click=do_export>"Export"</button>
                    <Switch checked=export_values label="Include stored values" text="include stored values"
                        on_change=Callback::new(move |v: bool| export_values.set(v)) />
                    <button class="btn" on:click=check_all>"Check all"</button>
                    <button class="btn primary" on:click=move |_| show_install.set(true)>
                        "+ Install Userscript"
                    </button>
                </div>
            </div>

            <div class="tiles">
                <div class="stat-badge">
                    <span class="stat-value">{move || counts.get().map(|c| c.all).unwrap_or(0)}</span>
                    <span class="stat-label">"Installed"</span>
                </div>
                <div class="stat-badge">
                    <span class="stat-value">{total_executions}</span>
                    <span class="stat-label">"Total Executions"</span>
                </div>
            </div>

            <div class="card">
                <div class="card-h">
                    <h3>"Installed userscripts"</h3>
                    <span class="sub">{move || format!("{} scripts", counts.get().map(|c| c.all).unwrap_or(0))}</span>
                </div>
                <div class="card-b sitebar">
                    <div class="toolbar">
                        <div class="search grow">
                            <Icon name="search" />
                            <label class="sr" for="usQ">"Search userscripts"</label>
                            <input id="usQ" class="input mono" placeholder="Search by name or description" autocomplete="off"
                                value=q.get_untracked()
                                on:input=move |ev| {
                                    let v = event_target_value(&ev);
                                    debounce.set_value(Some(Timeout::new(150, move || q.set(v))));
                                } />
                        </div>
                        <div class="seg" role="radiogroup" aria-label="Filter by status">
                            {[("", "All"), ("enabled", "Enabled"), ("disabled", "Disabled"), ("error", "Errors")]
                                .into_iter()
                                .map(|(val, name)| view! {
                                    <button type="button" role="radio"
                                        aria-checked=move || (status.get() == val).to_string()
                                        on:click=move |_| status.set(val.to_string())>
                                        {name}
                                        {move || counts.get().map(|c| match val {
                                            "enabled" => c.enabled,
                                            "disabled" => c.disabled,
                                            "error" => c.error,
                                            _ => c.all,
                                        }).map(|n| view! { <span class="n">{n}</span> })}
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
                </div>
                <Show
                    when=move || !feed.items.with(|v| v.is_empty())
                    fallback=move || view! {
                        <div class="empty">
                            <b>{move || if feed.loading.get() { "Loading..." } else { "No userscripts match" }}</b>
                        </div>
                    }
                >
                    <div class="vwrap">
                        <VList
                            items=feed.items
                            row_h=row_h
                            key=|s: &Userscript| format!("{}|{}|{}|{}|{}|{}", s.id, s.enabled, s.version.clone().unwrap_or_default(), s.pending_update.is_some(), s.error, s.updated_at)
                            render=Callback::new(move |script: Userscript| {

                            let id = script.id.clone();
                            let (id_t, id_c, id_d, id_u) = (id.clone(), id.clone(), id.clone(), id.clone());
                            let enabled = script.enabled;
                            let pending = script.pending_update.clone();
                            let has_url = script.update_url.is_some();
                            let status = update_status(&script);
                            view! {
                                <div class=format!("userscript-item {}", if enabled { "" } else { "disabled" })>
                                    <div class="userscript-info">
                                        <h3 class="userscript-name">
                                            {script.name.clone()}
                                            {script.version.clone().map(|v| view! {
                                                <span class="userscript-version">{v}</span>
                                            })}
                                        </h3>
                                        {script.description.clone().map(|d| view! {
                                            <p class="userscript-description">{d}</p>
                                        })}
                                        <div class="userscript-meta">
                                            <span>{script.execution_count}" executions"</span>
                                            <span>"Storage: "{fmt_bytes(script.storage_bytes)}</span>
                                            <span>{status}</span>
                                            {pending.map(|p| {
                                                let cls = if p.needs_reapproval { "us-badge us-badge-warn" } else { "us-badge" };
                                                let idu = id_u.clone();
                                                view! {
                                                    <button class=cls on:click=move |_| {
                                                        update_allow_all.set(false);
                                                        update_id.set(Some(idu.clone()));
                                                        show_update.set(true);
                                                    }>"Update pending approval"</button>
                                                }
                                            })}
                                        </div>
                                    </div>
                                    <div class="userscript-actions">
                                        <Switch checked=enabled label="Enabled" text="Enabled"
                                            on_change=Callback::new(move |v: bool| toggle(id_t.clone(), v)) />
                                        <button class="btn ghost" disabled=!has_url
                                            on:click=move |_| check_update(id_c.clone())>
                                            "Check for update"
                                        </button>
                                        <button class="btn ghost"
                                            on:click=move |_| open_detail(id_d.clone())>
                                            "Details"
                                        </button>
                                    </div>
                                </div>
                            }.into_any()
                            })
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
                        if !q.get().is_empty() || !status.get().is_empty() { format!("{n} matches") } else { format!("{n} scripts") }
                    }}</span>
                    <span>{move || {
                        let n = feed.items.with(|v| v.len());
                        if feed.next.get().is_some() { format!("showing 1-{n} \u{b7} scroll for more") } else { "end of list".to_string() }
                    }}</span>
                </div>
            </div>

            // Install modal
            <Drawer title="Install Userscript" open=show_install>
                <div class="us-tabs">
                    <button class=move || if url_mode.get() { "btn ghost" } else { "btn" }
                        on:click=move |_| url_mode.set(false)>"Paste source"</button>
                    <button class=move || if url_mode.get() { "btn" } else { "btn ghost" }
                        on:click=move |_| url_mode.set(true)>"From URL"</button>
                </div>
                <Show when=move || url_mode.get() fallback=move || view! {
                    <textarea class="source-input"
                        placeholder="// ==UserScript==\n// @name        My Script\n// @match       https://example.com/*\n// ==/UserScript=="
                        prop:value=move || install_source.get()
                        on:input=move |ev| install_source.set(event_target_value(&ev))></textarea>
                }>
                    <input class="input" type="url" placeholder="https://example.com/script.user.js"
                        prop:value=move || install_url.get()
                        on:input=move |ev| install_url.set(event_target_value(&ev)) />
                </Show>
                <p class="hint">"Nothing is installed until you approve the plan."</p>
                <div class="row-gap">
                    <button class="btn" on:click=move |_| show_install.set(false)>"Cancel"</button>
                    <button class="btn primary" disabled=move || busy.get() on:click=do_plan>
                        "Review"
                    </button>
                </div>
            </Drawer>

            // Approval dialog
            <Drawer title="Approve installation" open=show_plan>
                {move || plan.get().map(|p| {
                    let sensitive: Vec<(&str, bool)> = vec![
                        ("Network", p.network), ("Cookies", p.cookies), ("Downloads", p.downloads),
                        ("Clipboard", p.clipboard), ("Notifications", p.notifications),
                    ];
                    view! {
                        <div class="us-section">
                            <h3>{p.name.clone()}
                                {p.version.clone().map(|v| view! { <span class="userscript-version">{v}</span> })}
                            </h3>
                            {p.description.clone().map(|d| view! { <p class="userscript-description">{d}</p> })}
                            {p.already_installed.then(|| view! {
                                <div class="us-warn">
                                    <span class="us-badge us-badge-warn">"update"</span>
                                    " Already installed"
                                    {p.installed_version.clone().map(|v| format!(" (version {v})"))}
                                    ". Confirming replaces it with this version."
                                    {p.update.as_ref().filter(|u| !u.is_newer).map(|_| " This is not a newer version.")}
                                </div>
                            })}
                            {p.update.clone().map(|u| view! {
                                {u.needs_reapproval.then(|| view! {
                                    <div class="us-danger">
                                        <span class="us-badge us-badge-warn">"widened"</span>
                                        " This version widens what the script may match, reach or run; confirming approves it."
                                    </div>
                                })}
                                {diff_rows(u.diff)}
                            })}
                        </div>
                        <div class="us-section">
                            <h4>"Requested capabilities"</h4>
                            <div class="userscript-matches">
                                {sensitive.into_iter().filter(|(_, on)| *on)
                                    .map(|(n, _)| view! { <span class="match-pattern us-hot">{n}</span> })
                                    .collect_view()}
                                {tag_list(p.grants.clone(), true)}
                            </div>
                        </div>
                        <div class="us-section">
                            <h4>"@connect hosts"</h4>
                            {p.connect_all.then(|| view! {
                                <div class="us-danger">
                                    "This script asks to connect to ANY host (@connect *). It can send data anywhere."
                                    <Switch checked=allow_all label="Allow @connect *" text="Allow @connect *"
                                        on_change=Callback::new(move |v: bool| allow_all.set(v)) />
                                </div>
                            })}
                            <div class="userscript-matches">{tag_list(p.connect.clone(), false)}</div>
                        </div>
                        <div class="us-section">
                            <h4>"Runs on "
                                {p.broad_match.then(|| view! { <span class="us-badge us-badge-warn">"broad match"</span> })}
                            </h4>
                            <div class="userscript-matches">{tag_list(p.matches.clone(), false)}</div>
                        </div>
                        {(!p.unsupported.is_empty() || !p.warnings.is_empty()).then(|| view! {
                            <div class="us-section us-warn">
                                <h4>"Warnings"</h4>
                                <ul>
                                    {p.unsupported.iter().map(|u| view! { <li>"Unsupported: "{u.clone()}</li> }).collect_view()}
                                    {p.warnings.iter().map(|w| view! { <li>{w.clone()}</li> }).collect_view()}
                                </ul>
                            </div>
                        })}
                        {(!p.requires.is_empty() || !p.resources.is_empty()).then(|| view! {
                            <div class="us-section">
                                <h4>"Dependencies"</h4>
                                <ul>
                                    {p.requires.iter().map(|r| view! {
                                        <li>"@require "{r.url.clone()}" ("{fmt_bytes(r.size_bytes as u64)}
                                            {if r.sri_verified { ", integrity verified" } else { ", no integrity hash" }}")"</li>
                                    }).collect_view()}
                                    {p.resources.iter().map(|r| view! {
                                        <li>"@resource "{r.name.clone()}": "{r.url.clone()}" ("{fmt_bytes(r.size_bytes as u64)}
                                            {if r.sri_verified { ", integrity verified" } else { ", no integrity hash" }}")"</li>
                                    }).collect_view()}
                                </ul>
                            </div>
                        })}
                    }
                })}
                <div class="row-gap">
                    <button class="btn" on:click=move |_| show_plan.set(false)>"Cancel"</button>
                    <button class="btn primary"
                        disabled=move || busy.get() || plan.get().is_some_and(|p| p.connect_all && !allow_all.get())
                        on:click=do_confirm>"Approve & install"</button>
                </div>
            </Drawer>

            // Pending update dialog
            <Drawer title="Pending update" open=show_update>
                {move || by_id(update_id.get()).and_then(|s| s.pending_update.clone().map(|p| (s, p))).map(|(s, p)| {
                    let d = p.diff.clone();
                    let adds_all = d.added_connect.iter().any(|c| c == "*");
                    let row = |label: &'static str, items: Vec<String>, cls: &'static str| {
                        (!items.is_empty()).then(|| view! {
                            <div class="us-section"><h4>{label}</h4>
                                <div class="userscript-matches">
                                    {items.into_iter().map(|i| view! { <span class=format!("match-pattern {cls}")>{i}</span> }).collect_view()}
                                </div></div>
                        })
                    };
                    view! {
                        <p>{s.name.clone()}": "{s.version.clone().unwrap_or_default()}" -> "
                            {p.new_version.clone().unwrap_or_else(|| "?".into())}
                            <span class="userscript-version">"found "{p.found_at.clone()}</span></p>
                        {p.needs_reapproval.then(|| view! {
                            <div class="us-danger">"This update widens what the script may do and needs your approval."</div>
                        })}
                        {row("Added matches", d.added_matches, "us-hot")}
                        {row("Added connect", d.added_connect, "us-hot")}
                        {row("Added grants", d.added_grants, "us-hot")}
                        {row("Removed matches", d.removed_matches, "")}
                        {row("Removed connect", d.removed_connect, "")}
                        {row("Removed grants", d.removed_grants, "")}
                        {row("Other widening", d.widened, "us-hot")}
                        {adds_all.then(|| view! {
                            <Switch checked=update_allow_all label="Allow @connect *" text="Allow @connect *"
                                on_change=Callback::new(move |v: bool| update_allow_all.set(v)) />
                        })}
                    }
                })}
                <div class="row-gap">
                    <button class="btn danger sm" on:click=move |_| resolve_update(false)>"Discard"</button>
                    <button class="btn primary" on:click=move |_| resolve_update(true)>"Approve"</button>
                </div>
            </Drawer>

            // Details modal
            <Drawer title="Userscript details" open=show_detail>
                {move || by_id(detail_id.get()).map(|s| {
                    let (id_src, id_un, id_clear) = (s.id.clone(), s.id.clone(), s.id.clone());
                    let sid = s.id.clone();
                    view! {
                        <h3>{s.name.clone()}
                            {s.version.clone().map(|v| view! { <span class="userscript-version">{v}</span> })}</h3>
                        {s.description.clone().map(|d| view! { <p class="userscript-description">{d}</p> })}
                        <div class="userscript-meta">
                            {s.author.clone().map(|a| view! { <span>"Author: "{a}</span> })}
                            {s.namespace.clone().map(|a| view! { <span>"Namespace: "{a}</span> })}
                            {s.homepage.clone().map(|a| view! { <span>"Homepage: "{a}</span> })}
                            {s.update_url.clone().map(|a| view! { <span>"Update URL: "{a}</span> })}
                            {s.last_update_check.clone().map(|a| view! { <span>"Last check: "{a}</span> })}
                        </div>
                        <div class="userscript-meta">
                            <span>"run-at: "{s.run_at.clone().unwrap_or_else(|| "document-idle".into())}</span>
                            <span>{if s.noframes { "top frame only (noframes)" } else { "runs in frames" }}</span>
                            <span>{s.require_count}" requires, "{s.resource_count}" resources"</span>
                            {s.connect_all_approved.then(|| view! { <span class="us-badge us-badge-warn">"@connect * approved"</span> })}
                        </div>
                        <div class="us-section"><h4>"Grants"</h4>
                            <div class="userscript-matches">{tag_list(s.grants.clone(), true)}</div></div>
                        <div class="us-section"><h4>"@connect"</h4>
                            <div class="userscript-matches">{tag_list(s.connect.clone(), false)}</div></div>
                        <div class="us-section"><h4>"Matches"</h4>
                            <div class="userscript-matches">{tag_list(s.match_patterns.clone(), false)}</div></div>
                        {(!s.unsupported.is_empty() || !s.warnings.is_empty()).then(|| view! {
                            <div class="us-section us-warn"><h4>"Warnings"</h4><ul>
                                {s.unsupported.iter().map(|u| view! { <li>"Unsupported: "{u.clone()}</li> }).collect_view()}
                                {s.warnings.iter().map(|w| view! { <li>{w.clone()}</li> }).collect_view()}
                            </ul></div>
                        })}
                        <div class="us-section">
                            <h4>"Stored values"
                                {move || storage.get().map(|(used, quota)| view! {
                                    <span class="userscript-version">
                                        {fmt_bytes(used)}" / "{fmt_bytes(quota)}</span>
                                })}
                            </h4>
                            <input class="input mono" placeholder="Search values" aria-label="Search stored values"
                                prop:value=move || storage_q.get()
                                on:input=move |ev| {
                                    storage_q.set(event_target_value(&ev));
                                    storage_t.set_value(Some(Timeout::new(250, move || sfeed.reload(None, false, None))));
                                } />
                            <Show when=move || sfeed.items.with(|v| v.is_empty()) fallback=|| ()>
                                <p class="hint">{move || if sfeed.loading.get() { "Loading..." } else { "No stored values" }}</p>
                            </Show>
                            <Scroller feed=sfeed>
                                <table class="tbl">
                                    <thead><tr><th>"Name"</th><th>"Size"</th><th>"Preview"</th><th></th></tr></thead>
                                    <tbody>
                                        <For each=move || sfeed.items.get() key=|v| format!("{}/{}", v.name, v.size_bytes) children={
                                            let sid = sid.clone();
                                            move |v| {
                                                let (sid, name) = (sid.clone(), v.name.clone());
                                                view! { <tr>
                                                    <td>{v.name.clone()}</td>
                                                    <td>{fmt_bytes(v.size_bytes as u64)}</td>
                                                    <td><code>{v.preview.clone()}</code></td>
                                                    <td><ConfirmButton label="Delete" confirm_label="Delete?"
                                                        on_confirm=Callback::new(move |()| clear_storage(sid.clone(), Some(name.clone()))) /></td>
                                                </tr> }
                                            }
                                        } />
                                    </tbody>
                                </table>
                            </Scroller>
                            <ConfirmButton label="Clear all" confirm_label="Clear all?"
                                on_confirm=Callback::new(move |()| clear_storage(id_clear.clone(), None)) />
                        </div>
                        <div class="row-gap">
                            <button class="btn ghost" on:click=move |_| view_source(id_src.clone())>"View source"</button>
                            <ConfirmButton label="Uninstall" confirm_label="Uninstall?" on_confirm=Callback::new(move |()| uninstall(id_un.clone())) />
                        </div>
                    }
                })}
            </Drawer>

            // Import modal
            <Drawer title="Import userscripts" open=show_import>
                <p class="hint">"Choose an exported bundle file or paste its JSON."</p>
                <input type="file" accept=".json,application/json" on:change=on_file />
                <textarea class="source-input" placeholder="{\"format\": \"argus-userscripts-v1\", ...}"
                    prop:value=move || import_text.get()
                    on:input=move |ev| import_text.set(event_target_value(&ev))></textarea>
                <Switch checked=import_replace label="Replace existing scripts" text="Replace existing scripts (default: skip)"
                    on_change=Callback::new(move |v: bool| import_replace.set(v)) />
                {move || import_results.get().map(|r| view! {
                    <ul class="us-results">
                        {r.results.into_iter().map(|x| view! {
                            <li>
                                <strong>{x.name.unwrap_or_else(|| x.id.unwrap_or_default())}</strong>": "{x.status}
                                {x.error.map(|e| format!(" - {e}"))}
                            </li>
                        }).collect_view()}
                    </ul>
                })}
                <div class="row-gap">
                    <button class="btn" on:click=move |_| show_import.set(false)>"Close"</button>
                    <button class="btn primary" disabled=move || busy.get() on:click=do_import>"Import"</button>
                </div>
            </Drawer>

            <Drawer title="Userscript Source" open=show_source>
                <pre class="source-code">{source_content}</pre>
            </Drawer>
        </Layout>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::userscripts::ImportUserscriptsResponse;
    use api_types::ImportResultDto;

    #[test]
    fn sensitive_grants() {
        assert!(is_sensitive_grant("GM_xmlhttpRequest"));
        assert!(is_sensitive_grant("GM.cookie"));
        assert!(is_sensitive_grant("GM_setClipboard"));
        assert!(!is_sensitive_grant("GM_getValue"));
    }

    #[test]
    fn bytes() {
        assert_eq!(fmt_bytes(10), "10 B");
        assert_eq!(fmt_bytes(2048), "2.0 KiB");
        assert_eq!(fmt_bytes(3 * 1048576), "3.0 MiB");
    }

    #[test]
    fn summary() {
        let r = |s: &str| ImportResultDto {
            id: None,
            name: None,
            status: s.into(),
            error: None,
            pending_approval: false,
        };
        let resp = ImportUserscriptsResponse {
            results: vec![r("installed"), r("replaced"), r("skipped"), r("error")],
        };
        assert_eq!(import_summary(&resp), (2, 1, 1));
    }
}

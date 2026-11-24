//! Userscripts: Installed | Browse tabs, install from URL, import/export, and (in `detail`)
//! one page per script.

mod browse;
mod detail;
mod installed;
mod model;
mod plan;

pub use detail::UserscriptDetailPage;
pub(crate) use model::download_text;
pub use model::{fmt_bytes, is_sensitive_grant, url_key};

use leptos::prelude::*;

use super::vlist::*;
use crate::api::userscripts::{
    ImportUserscriptsResponse, Userscript, UserscriptBundle, UserscriptCounts,
};
use crate::api::ApiClient;
use crate::components::{
    Drawer, Icon, Layout, Menu, MenuDivider, MenuItem, Modal, ProfileSelector, Switch, Tabs,
};
use crate::state::use_app_state;
use crate::utils::format_number;
use browse::BrowsePanel;
use installed::InstalledPanel;
use model::*;
use plan::{PlanDrawer, Review};

/// State shared by the page's panels.
#[derive(Clone, Copy)]
pub struct Ctx {
    /// Restart the list and the overview.
    pub reload: RwSignal<u32>,
    /// Every installed script (for tiles, the catalogue's installed state, attention counts).
    pub all: RwSignal<Vec<Userscript>>,
    pub counts: RwSignal<Option<UserscriptCounts>>,
    /// Total executions (stats endpoint).
    pub runs: RwSignal<u64>,
    /// The overview could not be (re)loaded; the previous data stays on screen.
    pub ov_err: RwSignal<Option<String>>,
    pub status: RwSignal<String>,
    /// Ids whose update check is running.
    pub checking: RwSignal<Vec<String>>,
    /// Ids whose last update check failed.
    pub failed: RwSignal<Vec<String>>,
    pub review: RwSignal<Option<Review>>,
    pub show_review: RwSignal<bool>,
    pub tab: RwSignal<String>,
    pub import_open: RwSignal<bool>,
    pub cat_n: RwSignal<Option<usize>>,
}

/// Userscripts page component
#[component]
pub fn UserscriptsPage() -> impl IntoView {
    let app = StoredValue::new(use_app_state());
    let all = RwSignal::new(Vec::<Userscript>::new());
    let ctx = Ctx {
        reload: RwSignal::new(0),
        all,
        counts: RwSignal::new(None),
        runs: RwSignal::new(0),
        ov_err: RwSignal::new(None),
        status: RwSignal::new(query_get("um").unwrap_or_default()),
        checking: RwSignal::new(Vec::new()),
        failed: RwSignal::new(Vec::new()),
        review: RwSignal::new(None),
        show_review: RwSignal::new(false),
        tab: RwSignal::new("installed".to_string()),
        import_open: RwSignal::new(false),
        cat_n: RwSignal::new(None),
    };
    let (reload, counts) = (ctx.reload, ctx.counts);

    // Overview: every installed script, 200 at a time, no cap. A newer load supersedes an older
    // one, and a failed load keeps the previous data (with an error banner).
    let generation = StoredValue::new(0u64);
    Effect::new(move |_| {
        reload.track();
        let my = generation.get_value() + 1;
        generation.set_value(my);
        wasm_bindgen_futures::spawn_local(async move {
            let client = ApiClient::new();
            let mut v = Vec::new();
            let mut cursor: Option<String> = None;
            let mut failed = None;
            loop {
                match client
                    .list_userscripts_paged("", "", "name", cursor.as_deref(), None, 200)
                    .await
                {
                    Ok(r) => {
                        v.extend(r.items);
                        cursor = r.next_cursor;
                        if cursor.is_none() {
                            break;
                        }
                    }
                    Err(e) => {
                        failed = Some(e.to_string());
                        break;
                    }
                }
            }
            if generation.get_value() != my {
                return;
            }
            match failed {
                None => {
                    all.set(v);
                    ctx.ov_err.set(None);
                }
                Some(e) => ctx.ov_err.set(Some(e)),
            }
            if let Ok(st) = client.get_userscript_stats().await {
                if generation.get_value() == my {
                    ctx.runs.set(st.total_executions);
                }
            }
        });
    });

    // Install
    let show_install = RwSignal::new(false);
    let url_mode = RwSignal::new(true);
    let install_source = RwSignal::new(String::new());
    let install_url = RwSignal::new(String::new());
    let planning = RwSignal::new(false);
    let install_err = RwSignal::new(Option::<String>::None);
    let do_plan = move |_| {
        if planning.get_untracked() {
            return;
        }
        let (source, url) = if url_mode.get() {
            (None, Some(install_url.get().trim().to_string()))
        } else {
            (Some(install_source.get()), None)
        };
        let src_url = url.clone();
        planning.set(true);
        install_err.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().plan_userscript(source, url).await {
                Ok(p) => {
                    ctx.review
                        .set(Some(Review::from_plan(p, src_url.as_deref())));
                    show_install.set(false);
                    ctx.show_review.set(true);
                }
                Err(e) => install_err.set(Some(format!("Couldn't prepare the install: {e}"))),
            }
            planning.set(false);
        });
    };
    let on_done = Callback::new(move |()| {
        install_source.set(String::new());
        install_url.set(String::new());
        reload.update(|n| *n += 1);
    });

    // Check all
    let progress = RwSignal::new(Option::<(usize, usize)>::None);
    let check_all = move |()| {
        if progress.get_untracked().is_some() {
            return;
        }
        let ids: Vec<String> = all.with_untracked(|a| {
            a.iter()
                .filter(|s| s.update_url.is_some())
                .map(|s| s.id.clone())
                .collect()
        });
        if ids.is_empty() {
            app.get_value()
                .info("No installed script has an update source");
            return;
        }
        let total = ids.len();
        progress.set(Some((0, total)));
        ctx.checking.set(ids.clone());
        wasm_bindgen_futures::spawn_local(async move {
            let client = ApiClient::new();
            let (mut pending, mut failed) = (0, 0);
            ctx.failed.set(Vec::new());
            for (i, id) in ids.iter().enumerate() {
                match client.check_userscript_update(id).await {
                    Ok(r) if r.status == "pending_approval" => pending += 1,
                    Ok(_) => {}
                    Err(_) => {
                        failed += 1;
                        ctx.failed.update(|f| f.push(id.clone()));
                    }
                }
                ctx.checking.update(|c| c.retain(|x| x != id));
                progress.set(Some((i + 1, total)));
            }
            progress.set(None);
            let msg = format!(
                "Checked {total} script{}: {pending} with updates, {failed} failed",
                if total == 1 { "" } else { "s" }
            );
            if failed > 0 {
                app.get_value().error(msg);
            } else {
                app.get_value().success(msg);
            }
            reload.update(|n| *n += 1);
        });
    };

    // Import
    let import_text = RwSignal::new(String::new());
    let import_replace = RwSignal::new(false);
    let import_results = RwSignal::new(Option::<ImportUserscriptsResponse>::None);
    let importing = RwSignal::new(false);
    let import_err = RwSignal::new(Option::<String>::None);
    let on_file = move |ev: web_sys::Event| {
        let input = event_target::<web_sys::HtmlInputElement>(&ev);
        if let Some(file) = input.files().and_then(|f| f.get(0)) {
            import_err.set(None);
            wasm_bindgen_futures::spawn_local(async move {
                match wasm_bindgen_futures::JsFuture::from(file.text()).await {
                    Ok(v) => import_text.set(v.as_string().unwrap_or_default()),
                    Err(_) => import_err.set(Some("Couldn't read that file".into())),
                }
            });
        }
    };
    let do_import = move |_| {
        if importing.get_untracked() {
            return;
        }
        import_err.set(None);
        let mut bundle: UserscriptBundle = match serde_json::from_str(&import_text.get()) {
            Ok(b) => b,
            Err(e) => {
                import_err.set(Some(format!("That isn't a valid bundle: {e}")));
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
        importing.set(true);
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
                Err(e) => import_err.set(Some(format!("Import failed: {e}"))),
            }
            importing.set(false);
        });
    };
    let approve_from_import = move |id: String| {
        import_err.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().get_userscript(&id).await {
                Ok(s) => {
                    ctx.review.set(Some(Review::from_approval(&s)));
                    ctx.import_open.set(false);
                    ctx.show_review.set(true);
                }
                Err(e) => import_err.set(Some(format!("Couldn't open the script: {e}"))),
            }
        });
    };

    // Export
    let show_export = RwSignal::new(false);
    let export_values = RwSignal::new(false);
    let exporting = RwSignal::new(false);
    let export_err = RwSignal::new(Option::<String>::None);
    let do_export = move |_| {
        if exporting.get_untracked() {
            return;
        }
        let values = export_values.get_untracked();
        exporting.set(true);
        export_err.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().export_userscripts(values).await {
                Ok(b) => {
                    let text = serde_json::to_string_pretty(&b).unwrap_or_default();
                    match download_text("userscripts-export.json", &text) {
                        Ok(()) => {
                            app.get_value().success("Exported");
                            show_export.set(false);
                        }
                        Err(e) => export_err.set(Some(format!("Download failed: {e}"))),
                    }
                }
                Err(e) => export_err.set(Some(format!("Export failed: {e}"))),
            }
            exporting.set(false);
        });
    };

    let none_installed = move || counts.get().is_some_and(|c| c.all == 0);
    let tab_items = Signal::derive(move || {
        vec![
            (
                "installed".to_string(),
                "Installed".to_string(),
                counts.get().map(|c| c.all),
            ),
            ("browse".to_string(), "Browse".to_string(), ctx.cat_n.get()),
        ]
    });
    let updates = move || counts.get().map(|c| c.updates).unwrap_or(0);
    let upd_style = move || {
        if updates() > 0 {
            "color:var(--error)"
        } else {
            ""
        }
    };

    view! {
        <Layout>
            <ProfileSelector reload=reload />
            <div class="us-head">
                <h1 class="page-title">"Userscripts"</h1>
                <div class="acts">
                    <button type="button" class="btn primary" aria-label="Install from URL" on:click=move |_| show_install.set(true)>
                        <Icon name="plus" />
                        <span class="lbl-full">"Install from URL"</span>
                        <span class="lbl-short">"Install"</span>
                    </button>
                    <Menu label="More">
                        {move || (!none_installed()).then(|| view! {
                            <MenuItem keep_open=true icon="refresh"
                                disabled=Signal::derive(move || progress.get().is_some())
                                on_select=Callback::new(check_all)>
                                {move || match progress.get() {
                                    Some((d, t)) => view! { <span class="spin"></span>{format!("Checking {d}/{t}\u{2026}")} }.into_any(),
                                    None => view! { "Check all for updates" }.into_any(),
                                }}
                            </MenuItem>
                            <MenuDivider />
                        })}
                        <MenuItem icon="upload" on_select=Callback::new(move |()| {
                            import_results.set(None);
                            import_err.set(None);
                            ctx.import_open.set(true);
                        })>"Import\u{2026}"</MenuItem>
                        {move || (!none_installed()).then(|| view! {
                            <MenuItem icon="download" on_select=Callback::new(move |()| {
                                export_err.set(None);
                                show_export.set(true);
                            })>"Export\u{2026}"</MenuItem>
                        })}
                    </Menu>
                </div>
            </div>
            <Tabs items=tab_items active=ctx.tab label="Userscripts sections" />

            <div role="tabpanel" id="panel-installed" aria-labelledby="tab-installed" class="us-panel" hidden=move || ctx.tab.get() != "installed">
                <Show when=move || !none_installed()>
                    <div class="tiles compact">
                        <div class="tile"><span class="k">"Installed"</span>
                            <span class="v">{move || format_number(counts.get().map(|c| c.all).unwrap_or(0) as u64)}</span></div>
                        <div class="tile"><span class="k">"Enabled"</span>
                            <span class="v">{move || format_number(counts.get().map(|c| c.enabled).unwrap_or(0) as u64)}</span></div>
                        <div class="tile"><span class="k">"Updates available"</span>
                            <span class="v" style=upd_style>{updates}</span>
                            <span class="d">{move || (updates() > 0).then(|| view! {
                                <button type="button" class="linkish" on:click=move |_| ctx.status.set("attention".into())>"Review"</button>
                            })}</span></div>
                        <div class="tile"><span class="k">"Runs (total)"</span>
                            <span class="v">{move || format_number(ctx.runs.get())}</span></div>
                    </div>
                </Show>
                {move || ctx.ov_err.get().map(|e| view! {
                    <div class="err row-gap" role="alert">
                        <span>{format!("Couldn't refresh the overview (showing the last data): {e}")}</span>
                        <button type="button" class="btn sm" on:click=move |_| reload.update(|n| *n += 1)>"Retry"</button>
                    </div>
                })}
                <InstalledPanel ctx=ctx />
            </div>
            <div role="tabpanel" id="panel-browse" aria-labelledby="tab-browse" class="us-panel" hidden=move || ctx.tab.get() != "browse">
                <BrowsePanel ctx=ctx />
            </div>

            // Install from URL / pasted source
            <Drawer title="Install userscript" open=show_install>
                <div class="seg" role="radiogroup" aria-label="Install source">
                    <button type="button" role="radio" aria-checked=move || url_mode.get().to_string() on:click=move |_| url_mode.set(true)>"From URL"</button>
                    <button type="button" role="radio" aria-checked=move || (!url_mode.get()).to_string() on:click=move |_| url_mode.set(false)>"Paste source"</button>
                </div>
                <Show when=move || url_mode.get() fallback=move || view! {
                    <label class="sr" for="usSrc">"Userscript source"</label>
                    <textarea id="usSrc" class="source-input"
                        placeholder="// ==UserScript==\n// @name        My Script\n// @match       https://example.com/*\n// ==/UserScript=="
                        prop:value=move || install_source.get()
                        on:input=move |ev| install_source.set(event_target_value(&ev))></textarea>
                }>
                    <label class="sr" for="usUrl">"Script URL"</label>
                    <input id="usUrl" class="input" type="url" placeholder="https://example.com/script.user.js"
                        prop:value=move || install_url.get()
                        on:input=move |ev| install_url.set(event_target_value(&ev)) />
                </Show>
                <p class="hint">"Nothing is installed until you review its permissions and approve."</p>
                {move || install_err.get().map(|e| view! { <div class="err" role="alert">{e}</div> })}
                <div class="row-gap">
                    <button type="button" class="btn ghost" on:click=move |_| show_install.set(false)>"Cancel"</button>
                    <button type="button" class="btn primary"
                        aria-disabled=move || planning.get().to_string() disabled=move || (url_mode.get() && install_url.with(|u| u.trim().is_empty())) || (!url_mode.get() && install_source.with(|s| s.trim().is_empty()))
                        on:click=do_plan>
                        {move || planning.get().then(|| view! { <span class="spin"></span> })}
                        "Review"
                    </button>
                </div>
            </Drawer>

            <PlanDrawer review=ctx.review open=ctx.show_review on_done=on_done />

            // Import
            <Drawer title="Import userscripts" open=ctx.import_open>
                <p class="hint">"Choose an exported bundle file or paste its JSON. Imported scripts stay off until you approve them."</p>
                <label class="sr" for="usFile">"Bundle file"</label>
                <input id="usFile" type="file" accept=".json,application/json" on:change=on_file />
                <label class="sr" for="usBundle">"Bundle JSON"</label>
                <textarea id="usBundle" class="source-input" placeholder="{\"format\": \"argus-userscripts-v1\", ...}"
                    prop:value=move || import_text.get()
                    on:input=move |ev| import_text.set(event_target_value(&ev))></textarea>
                <Switch checked=import_replace label="Replace existing scripts" text="Replace existing scripts (default: skip)"
                    on_change=Callback::new(move |v: bool| import_replace.set(v)) />
                {move || import_err.get().map(|e| view! { <div class="err" role="alert">{e}</div> })}
                {move || import_results.get().map(|r| view! {
                    <ul class="us-results">
                        {r.results.into_iter().map(|x| {
                            let id = x.id.clone();
                            let needs = x.pending_approval && matches!(x.status.as_str(), "installed" | "replaced");
                            view! {
                                <li>
                                    <span class="nm">{x.name.clone().unwrap_or_else(|| x.id.clone().unwrap_or_default())}</span>
                                    <span class="muted">{x.status.clone()}</span>
                                    {needs.then(|| view! { <span class="pill p-error">"Needs approval"</span> })}
                                    {x.error.clone().map(|e| view! { <span class="bad">{e}</span> })}
                                    {needs.then(|| {
                                        let id = id.clone().unwrap_or_default();
                                        view! { <button type="button" class="btn sm primary" on:click=move |_| approve_from_import(id.clone())>"Approve"</button> }
                                    })}
                                </li>
                            }
                        }).collect_view()}
                    </ul>
                })}
                <div class="row-gap">
                    <button type="button" class="btn ghost" on:click=move |_| ctx.import_open.set(false)>"Close"</button>
                    <button type="button" class="btn primary" aria-disabled=move || importing.get().to_string() disabled=move || import_text.with(|t| t.trim().is_empty()) on:click=do_import>
                        {move || importing.get().then(|| view! { <span class="spin"></span> })}
                        "Import"
                    </button>
                </div>
            </Drawer>

            <Modal title="Export userscripts" open=show_export>
                <Switch checked=export_values label="Include stored values" text="Include stored values"
                    on_change=Callback::new(move |v: bool| export_values.set(v)) />
                <p class="hint">"Stored values may contain tokens or other private data. Keep the file somewhere safe."</p>
                {move || export_err.get().map(|e| view! { <div class="err" role="alert">{e}</div> })}
                <div class="row-gap">
                    <button type="button" class="btn ghost" on:click=move |_| show_export.set(false)>"Cancel"</button>
                    <button type="button" class="btn primary" aria-disabled=move || exporting.get().to_string() on:click=do_export>
                        {move || exporting.get().then(|| view! { <span class="spin"></span> })}
                        "Export"
                    </button>
                </div>
            </Modal>
        </Layout>
    }
}

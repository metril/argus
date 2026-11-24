//! Script policy page: script policy + page changes, temporary permissions, site rules (server
//! side search/filter/sort/paging), third-party source matrix and an "explain this URL" box.

use gloo_timers::callback::Timeout;
use leptos::prelude::*;

use crate::api::policy::*;
use crate::api::ApiClient;
use crate::components::{
    Card, ConfirmButton, Drawer, Icon, Layout, ProfileSelector, Segmented, Switch,
};
use crate::state::{use_app_state, AppState};

/// Capabilities that can be allowed or denied per third-party source.
const SOURCE_CAPS: [&str; 11] = [
    "script",
    "object",
    "media",
    "frame",
    "font",
    "connect",
    "ping",
    "worker",
    "style",
    "image",
    "form-action",
];

const SITE_PAGE: u32 = 40;

use super::vlist::*;
use crate::utils::format_number;
use std::rc::Rc;

fn preset(kind: &str) -> PresetDto {
    PresetDto {
        kind: kind.to_string(),
        profile: None,
    }
}

fn presets() -> Vec<(String, String)> {
    [
        ("trusted", "Trusted"),
        ("default", "Default"),
        ("untrusted", "Untrusted"),
    ]
    .iter()
    .map(|(a, b)| (a.to_string(), b.to_string()))
    .collect()
}

fn fmt_remaining(secs: Option<u64>) -> String {
    match secs {
        None => "until restart".into(),
        Some(s) if s >= 3600 => format!("expires in {}h {}m", s / 3600, (s % 3600) / 60),
        Some(s) if s >= 60 => format!("expires in {}m", s / 60),
        Some(s) => format!("expires in {s}s"),
    }
}

/// Run `fut` and report an error as a toast.
fn run<F>(app: &AppState, fut: F)
where
    F: std::future::Future<Output = Result<String, crate::api::ApiError>> + 'static,
{
    let app = app.clone();
    wasm_bindgen_futures::spawn_local(async move {
        match fut.await {
            Ok(msg) if !msg.is_empty() => app.success(msg),
            Ok(_) => {}
            Err(e) => app.error(e.to_string()),
        }
    });
}

#[component]
pub fn PolicyPage() -> impl IntoView {
    let reload = RwSignal::new(0u32);
    view! {
        <Layout>
            <div class="page-header">
                <h1 class="page-title">"Script policy"</h1>
                <ProfileSelector reload=reload />
            </div>
            <PolicyTop reload=reload />
            <TempCard reload=reload />
            <SitesCard reload=reload />
            <PanelSites reload=reload />
            <ExplainCard />
        </Layout>
    }
}

/// Inline-save row: label, text input, Revert/Save. `saved` is the stored value.
#[component]
fn InlineRow(
    #[prop(into)] label: String,
    #[prop(into)] sub: String,
    #[prop(into)] saved: Signal<String>,
    #[prop(into, optional)] placeholder: String,
    #[prop(optional)] secret: bool,
    on_save: Callback<String>,
) -> impl IntoView {
    let draft = RwSignal::new(String::new());
    Effect::new(move |_| draft.set(saved.get()));
    let dirty = move || draft.get() != saved.get();
    let id = format!("ir-{}", uuid::Uuid::new_v4().simple());
    view! {
        <div class=move || if dirty() { "irow dirty" } else { "irow" }>
            <div class="lbl"><label for=id.clone()>{label}</label><small>{sub}</small></div>
            <input
                id=id
                class="input mono"
                type=if secret { "password" } else { "text" }
                autocomplete=if secret { "new-password" } else { "off" }
                placeholder=placeholder
                prop:value=move || draft.get()
                on:input=move |ev| draft.set(event_target_value(&ev))
            />
            <div class="irow-act">
                <button type="button" class="btn sm ghost" on:click=move |_| draft.set(saved.get_untracked())>"Revert"</button>
                <button type="button" class="btn sm primary" on:click=move |_| on_save.run(draft.get_untracked())>"Save"</button>
            </div>
        </div>
    }
}

/// "Script policy" and "Page changes" cards (policy settings + the in-page panel settings).
#[component]
fn PolicyTop(reload: RwSignal<u32>) -> impl IntoView {
    let app = use_app_state();
    let full = RwSignal::new(Option::<PolicySettingsDto>::None);
    let panel = RwSignal::new(Option::<PanelSettingsDto>::None);

    {
        let app = app.clone();
        Effect::new(move || {
            reload.track();
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().get_policy_settings().await {
                    Ok(r) => full.set(Some(r.settings)),
                    Err(e) => app.error(format!("Failed to load policy settings: {e}")),
                }
                match ApiClient::new().get_panel_settings().await {
                    Ok(r) => panel.set(Some(r)),
                    Err(e) => app.error(format!("Failed to load panel settings: {e}")),
                }
            });
        });
    }

    // Apply a change to the policy settings and save it immediately.
    let edit = {
        let app = app.clone();
        move |f: Box<dyn Fn(&mut PolicySettingsDto)>| {
            let Some(mut s) = full.get_untracked() else {
                return;
            };
            f(&mut s);
            full.set(Some(s.clone()));
            run(&app, async move {
                let r = ApiClient::new().put_policy_settings(&s).await?;
                full.set(Some(r.settings));
                Ok("Policy saved".into())
            });
        }
    };
    let edit_panel = {
        let app = app.clone();
        move |input: PanelSettingsInput| {
            run(&app, async move {
                panel.set(Some(ApiClient::new().put_panel_settings(&input).await?));
                Ok("Panel settings saved".into())
            });
        }
    };

    let sw = {
        let edit = edit.clone();
        move |label: &'static str,
              sub: &'static str,
              get: fn(&PolicySettingsDto) -> bool,
              set: fn(&mut PolicySettingsDto, bool)| {
            let edit = edit.clone();
            view! {
                <div class="srow">
                    <div class="txt"><b>{label}</b><small>{sub}</small></div>
                    <Switch
                        checked=Signal::derive(move || full.get().is_some_and(|s| get(&s)))
                        label=label
                        on_change=Callback::new(move |v: bool| edit(Box::new(move |s| set(s, v))))
                    />
                </div>
            }
        }
    };

    let edit_global = edit.clone();
    let ep_auth = edit_panel.clone();
    let ep_pin = edit_panel.clone();
    let ep_hot = edit_panel.clone();
    let ep_on = edit_panel.clone();

    view! {
        <div class="card">
            <div class="card-h">
                <h3>"Script policy"</h3>
                <span class="sub">"Enforced with a Content-Security-Policy added to each page"</span>
            </div>
            <div class="card-b">
                <div class="irow">
                    <div class="lbl">"Sites without a rule use"</div>
                    <Segmented
                        label="Sites without a rule use"
                        options=presets()
                        value=Signal::derive(move || full.get().map(|s| s.global.kind).unwrap_or_default())
                        on_change=Callback::new(move |k: String| edit_global(Box::new(move |s| s.global = preset(&k))))
                    />
                    <div></div>
                </div>
                <div class="irow">
                    <div class="lbl">"Confirm changes with"</div>
                    <Segmented
                        label="Confirm changes with"
                        options=vec![
                            ("none".to_string(), "Click (trusted LAN)".to_string()),
                            ("pin".to_string(), "PIN".to_string()),
                            ("session".to_string(), "Dashboard only".to_string()),
                        ]
                        value=Signal::derive(move || panel.get().map(|p| p.auth).unwrap_or_default())
                        on_change=Callback::new(move |a: String| ep_auth(PanelSettingsInput {
                            enabled: None, hotkey: None, auth: Some(a), pin: None, clear_pin: false,
                        }))
                    />
                    <div></div>
                </div>
                {move || panel.get().filter(|p| p.auth == "pin" && !p.pin_set).map(|_| view! {
                    <p class="hint" role="alert" style="color:var(--error)">
                        "No PIN is set, so the in-page panel cannot apply changes (they are refused). Set a PIN below, or choose another confirmation method."
                    </p>
                })}
                <InlineRow
                    label="PIN"
                    sub="4 to 8 digits. Empty and Save removes it."
                    saved=Signal::derive(String::new)
                    placeholder="none set"
                    secret=true
                    on_save=Callback::new(move |p: String| {
                        let clear = p.is_empty();
                        ep_pin(PanelSettingsInput {
                            enabled: None, hotkey: None, auth: None,
                            pin: (!clear).then_some(p), clear_pin: clear,
                        })
                    })
                />
                <InlineRow
                    label="Panel hotkey"
                    sub="Opens the in-page panel"
                    saved=Signal::derive(move || panel.get().map(|p| p.hotkey).unwrap_or_default())
                    on_save=Callback::new(move |h: String| ep_hot(PanelSettingsInput {
                        enabled: None, hotkey: Some(h), auth: None, pin: None, clear_pin: false,
                    }))
                />
                <span class="hint">
                    {move || panel.get().map(|p| format!(
                        "{} Confirmation host: {}",
                        if p.pin_set { "A PIN is set." } else { "No PIN set." },
                        p.reserved_host
                    ))}
                </span>
            </div>
        </div>

        <div class="card">
            <div class="card-h"><h3>"Page changes"</h3></div>
            <div class="card-b">
                {sw("Enforce script policy", "Master switch. Off means nothing is added to any page", |s| s.enabled, |s, v| s.enabled = v)}
                {sw("Remove blocked script elements", "Strips <script> tags whose source the policy denies", |s| s.strip_blocked_scripts, |s, v| s.strip_blocked_scripts = v)}
                {sw("Remove meta refresh", "On pages whose scripts are blocked", |s| s.strip_meta_refresh, |s, v| s.strip_meta_refresh = v)}
                {sw("Block denied third-party requests at the proxy", "When the page is known, instead of relying on CSP alone", |s| s.network_hints, |s, v| s.network_hints = v)}
                <div class="srow">
                    <div class="txt"><b>"Offer the in-page panel"</b><small>"Off by default"</small></div>
                    <Switch
                        checked=Signal::derive(move || panel.get().is_some_and(|p| p.enabled))
                        label="Offer the in-page panel"
                        on_change=Callback::new(move |v: bool| ep_on(PanelSettingsInput {
                            enabled: Some(v), hotkey: None, auth: None, pin: None, clear_pin: false,
                        }))
                    />
                </div>
            </div>
        </div>
    }
}

#[component]
fn TempCard(reload: RwSignal<u32>) -> impl IntoView {
    let app = use_app_state();
    let grants = RwSignal::new(Vec::<TempGrantDto>::new());

    {
        let app = app.clone();
        Effect::new(move || {
            reload.track();
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().list_temp_grants().await {
                    Ok(g) => grants.set(g),
                    Err(e) => app.error(format!("Failed to load temporary permissions: {e}")),
                }
            });
        });
    }
    let revoke_all = {
        let app = app.clone();
        Callback::new(move |()| {
            run(&app, async move {
                ApiClient::new().revoke_all_temp().await?;
                reload.update(|n| *n += 1);
                Ok("All temporary permissions revoked".into())
            });
        })
    };

    view! {
        <div class="card">
            <div class="card-h">
                <h3>"Temporary permissions"</h3>
                <span class="sub">"Granted from the in-page panel. They expire on their own."</span>
                <div class="r">
                    <Show when=move || !grants.get().is_empty()>
                        <ConfirmButton label="Revoke all" confirm_label="Revoke all?" on_confirm=revoke_all />
                    </Show>
                </div>
            </div>
            <div>
                <For
                    each=move || grants.get()
                    key=|g| g.id.clone()
                    children={
                        let app = app.clone();
                        move |g| {
                            let (id, app) = (g.id.clone(), app.clone());
                            let what = match g.kind.as_str() {
                                "source" => format!(
                                    "{} from {} on {}",
                                    g.caps.join(", "),
                                    g.source.clone().unwrap_or_default(),
                                    g.page
                                ),
                                _ => g.page.clone(),
                            };
                            let title = what.clone();
                            view! {
                                <div class="trow">
                                    <span class="mono th" title=title>{what}</span>
                                    <span class="tm dim">{fmt_remaining(g.remaining_secs)}</span>
                                    <ConfirmButton
                                        label="Revoke"
                                        on_confirm=Callback::new(move |()| {
                                            let id = id.clone();
                                            run(&app, async move {
                                                ApiClient::new().revoke_temp(&id).await?;
                                                reload.update(|n| *n += 1);
                                                Ok("Revoked".into())
                                            });
                                        })
                                    />
                                </div>
                            }
                        }
                    }
                />
                <Show when=move || grants.get().is_empty()>
                    <div class="empty"><b>"No temporary permissions"</b>"Grants made from the in-page panel appear here."</div>
                </Show>
            </div>
        </div>
    }
}

fn bump_counts(counts: RwSignal<Option<SiteRuleCounts>>, kind: &str, d: i64) {
    counts.update(|c| {
        if let Some(c) = c {
            let f = |x: &mut usize| *x = (*x as i64 + d).max(0) as usize;
            match kind {
                "trusted" => f(&mut c.trusted),
                "default" => f(&mut c.default),
                "untrusted" => f(&mut c.untrusted),
                "custom" => f(&mut c.custom),
                _ => {}
            }
            f(&mut c.all);
        }
    });
}

#[component]
fn SitesCard(reload: RwSignal<u32>) -> impl IntoView {
    let app = use_app_state();
    let counts = RwSignal::new(Option::<SiteRuleCounts>::None);
    let q = RwSignal::new(query_get("sq").unwrap_or_default()); // debounced value
    let mode = RwSignal::new(query_get("sm").unwrap_or_default());
    let sort = RwSignal::new(query_get("ss").unwrap_or_else(|| "recent".into()));
    let anchor0 = query_get("sa");
    let new_scope = RwSignal::new(String::new());
    let new_preset = RwSignal::new("trusted".to_string());
    let debounce = StoredValue::new_local(None::<Timeout>);
    let anchor_t = StoredValue::new_local(None::<Timeout>);
    let file_ref: NodeRef<leptos::html::Input> = NodeRef::new();
    let dead = RwSignal::new(Vec::<char>::new());
    let matrix_open = RwSignal::new(false);
    let matrix_scope = RwSignal::new(Option::<String>::None);
    let row_h = Signal::derive(move || if is_narrow() { 100.0 } else { 52.0 });

    let fetch: Fetcher<SiteRuleDto> = {
        let app = app.clone();
        Rc::new(move |cursor, from| {
            let (qv, m, s) = (
                q.get_untracked(),
                mode.get_untracked(),
                sort.get_untracked(),
            );
            let app = app.clone();
            Box::pin(async move {
                match ApiClient::new()
                    .list_site_rules_paged(
                        &qv,
                        &m,
                        &s,
                        cursor.as_deref(),
                        from.as_deref(),
                        SITE_PAGE,
                    )
                    .await
                {
                    Ok(r) => {
                        dead.set(dead_letters(&r.counts.letters));
                        counts.set(Some(r.counts));
                        Ok((r.items, r.next_cursor, r.total))
                    }
                    Err(e) => {
                        app.error(format!("Failed to load site rules: {e}"));
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
        let s = sort.get();
        query_set(&[
            ("sq", Some(q.get())),
            ("sm", Some(mode.get())),
            ("ss", (s != "recent").then_some(s)),
            ("sa", None),
        ]);
    });
    let on_anchor = Callback::new(move |i: usize| {
        if sort.get_untracked() != "az" {
            return;
        }
        let label = feed
            .items
            .with_untracked(|v| v.get(i).filter(|_| i > 0).map(|r| r.scope.clone()));
        anchor_t.set_value(Some(Timeout::new(250, move || query_set(&[("sa", label)]))));
    });

    let add = {
        let app = app.clone();
        move || {
            let (scope, kind) = (new_scope.get_untracked(), new_preset.get_untracked());
            if scope.trim().is_empty() {
                return;
            }
            run(&app, async move {
                ApiClient::new()
                    .create_site_rule(&SiteRuleInput {
                        scope,
                        preset: preset(&kind),
                        note: None,
                    })
                    .await?;
                new_scope.set(String::new());
                reload.update(|n| *n += 1);
                Ok("Site rule added".into())
            });
        }
    };
    let add2 = add.clone();

    let export = {
        let app = app.clone();
        move |_| {
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().export_policy().await {
                    Ok(d) => {
                        let text = serde_json::to_string_pretty(&d).unwrap_or_default();
                        match super::userscripts::download_text("policy-export.json", &text) {
                            Ok(()) => app.success("Exported policy"),
                            Err(e) => app.error(format!("Download failed: {e}")),
                        }
                    }
                    Err(e) => app.error(format!("Export failed: {e}")),
                }
            });
        }
    };
    let on_file = {
        let app = app.clone();
        move |ev: web_sys::Event| {
            let input = event_target::<web_sys::HtmlInputElement>(&ev);
            let Some(file) = input.files().and_then(|f| f.get(0)) else {
                return;
            };
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let text = match wasm_bindgen_futures::JsFuture::from(file.text()).await {
                    Ok(v) => v.as_string().unwrap_or_default(),
                    Err(_) => return app.error("Failed to read file"),
                };
                let document: PolicyExportDto = match serde_json::from_str(&text) {
                    Ok(d) => d,
                    Err(e) => return app.error(format!("Invalid policy JSON: {e}")),
                };
                match ApiClient::new()
                    .import_policy(&PolicyImportRequest {
                        mode: "merge".into(),
                        document,
                    })
                    .await
                {
                    Ok(_) => {
                        app.success("Policy imported (merged)");
                        reload.update(|n| *n += 1);
                    }
                    Err(e) => app.error(format!("Import failed: {e}")),
                }
            });
            input.set_value("");
        }
    };

    // Edits keep the list: update counts, and drop the row only if it no longer matches.
    let on_change = Callback::new(move |(id, new): (String, String)| {
        let old = feed
            .items
            .with_untracked(|v| v.iter().find(|r| r.id == id).map(|r| r.preset.kind.clone()));
        if let Some(old) = old {
            bump_counts(counts, &old, -1);
            bump_counts(counts, &new, 1);
            // `all` was decremented and incremented: net zero.
        }
        let m = mode.get_untracked();
        if !m.is_empty() && m != new {
            feed.items.update(|v| v.retain(|r| r.id != id));
            feed.total.update(|t| *t = t.saturating_sub(1));
        } else {
            let now = (js_sys::Date::now() / 1000.0) as u64;
            feed.items.update(|v| {
                if let Some(r) = v.iter_mut().find(|r| r.id == id) {
                    r.preset.kind = new;
                    r.updated_at = now;
                }
            });
        }
    });
    let on_delete = Callback::new(move |id: String| {
        let old = feed
            .items
            .with_untracked(|v| v.iter().find(|r| r.id == id).map(|r| r.preset.kind.clone()));
        if let Some(old) = old {
            bump_counts(counts, &old, -1);
        }
        feed.items.update(|v| v.retain(|r| r.id != id));
        feed.total.update(|t| *t = t.saturating_sub(1));
    });
    let on_matrix = Callback::new(move |scope: String| {
        matrix_scope.set(Some(scope));
        matrix_open.set(true);
    });
    let render = Callback::new(move |r: SiteRuleDto| {
        view! { <SiteRow rule=r on_change=on_change on_delete=on_delete on_matrix=on_matrix /> }
            .into_any()
    });

    let seek = {
        let app = app.clone();
        move |l: char| {
            let app = app.clone();
            feed.reload(
                Some(l.to_string()),
                true,
                Some(Callback::new(move |n: usize| {
                    if n == 0 {
                        dead.update(|d| d.push(l));
                        app.info(format!("No sites starting with {}", l.to_ascii_uppercase()));
                    }
                })),
            );
        }
    };
    let filtering = move || !q.get().is_empty() || !mode.get().is_empty();

    view! {
        <div class="card">
            <div class="card-h">
                <h3>"Site rules"</h3>
                <span class="sub">{move || format!("{} sites", format_number(counts.get().map(|c| c.all).unwrap_or(0) as u64))}</span>
                <div class="r">
                    <button type="button" class="btn sm ghost" on:click=move |_| on_matrix.run("*".to_string())>"Global third-party rules"</button>
                    <button type="button" class="btn sm ghost" on:click=export>"Export"</button>
                    <button type="button" class="btn sm ghost" on:click=move |_| {
                        if let Some(i) = file_ref.get() { i.click(); }
                    }>"Import"</button>
                    <input node_ref=file_ref type="file" accept="application/json,.json" hidden on:change=on_file />
                </div>
            </div>
            <div class="card-b sitebar">
                <div class="toolbar addsite">
                    <label class="sr" for="newSite">"New site"</label>
                    <input
                        id="newSite"
                        class="input mono grow"
                        placeholder="Add a site, e.g. example.com"
                        prop:value=move || new_scope.get()
                        on:input=move |ev| new_scope.set(event_target_value(&ev))
                        on:keydown=move |ev: web_sys::KeyboardEvent| if ev.key() == "Enter" { add2() }
                    />
                    <Segmented label="Policy for the new site" options=presets() value=new_preset on_change=Callback::new(move |v: String| new_preset.set(v)) />
                    <button type="button" class="btn primary" on:click=move |_| add()><Icon name="plus" />"Add rule"</button>
                </div>
                <div class="toolbar">
                    <div class="search grow">
                        <Icon name="search" />
                        <label class="sr" for="siteQ">"Search sites"</label>
                        <input
                            id="siteQ"
                            class="input mono"
                            placeholder="Search sites"
                            autocomplete="off"
                            value=q.get_untracked()
                            on:input=move |ev| {
                                let v = event_target_value(&ev);
                                debounce.set_value(Some(Timeout::new(150, move || q.set(v))));
                            }
                        />
                    </div>
                    <div class="seg" role="radiogroup" aria-label="Filter by policy">
                        {[("", "all", "All"), ("trusted", "trusted", "Trusted"), ("default", "default", "Default"), ("untrusted", "untrusted", "Untrusted")]
                            .into_iter()
                            .map(|(val, key, name)| view! {
                                <button
                                    type="button"
                                    role="radio"
                                    aria-checked=move || (mode.get() == val).to_string()
                                    on:click=move |_| mode.set(val.to_string())
                                >
                                    {name}
                                    {move || counts.get().map(|c| match key {
                                        "trusted" => c.trusted,
                                        "default" => c.default,
                                        "untrusted" => c.untrusted,
                                        _ => c.all,
                                    }).map(|n| view! { <span class="n">{format_number(n as u64)}</span> })}
                                </button>
                            })
                            .collect_view()}
                    </div>
                    <select class="select" aria-label="Sort" prop:value=move || sort.get()
                        on:change=move |ev| sort.set(event_target_value(&ev))>
                        <option value="recent">"Recently changed"</option>
                        <option value="az">"A to Z"</option>
                    </select>
                </div>
            </div>
            <Show
                when=move || !feed.items.with(|v| v.is_empty()) || feed.error.get().is_some()
                fallback=move || view! {
                    <div class="empty">
                        <b>{move || if feed.loading.get() { "Loading..." } else { "No sites match" }}</b>
                        {move || if filtering() { "Clear a filter to see more." } else { "Add one above." }}
                    </div>
                }
            >
                <div class="vwrap">
                    <VList
                        items=feed.items
                        row_h=row_h
                        key=|r: &SiteRuleDto| format!("{}:{}", r.id, r.preset.kind)
                        render=render
                        on_end=Callback::new(move |()| feed.more())
                        error=feed.error
                        on_retry=Callback::new(move |()| feed.retry())
                        on_anchor=on_anchor
                        reset=feed.tok
                        label="Site rules"
                    />
                    <nav class="azrail" aria-label="Jump to letter" hidden=move || !(sort.get() == "az" && feed.total.get() > 12)>
                        {LETTERS.iter().map(|&l| {
                            let seek = seek.clone();
                            view! {
                                <button type="button" disabled=move || dead.get().contains(&l)
                                    on:click=move |_| seek(l)>{l.to_ascii_uppercase().to_string()}</button>
                            }
                        }).collect_view()}
                    </nav>
                </div>
            </Show>
            <div class="vfoot" aria-live="polite">
                <span>{move || {
                    let n = format_number(feed.total.get() as u64);
                    if filtering() { format!("{n} matches") } else { format!("{n} sites") }
                }}</span>
                <span>{move || {
                    let n = feed.items.with(|v| v.len());
                    if feed.next.get().is_some() { format!("showing 1-{n} \u{b7} scroll for more") } else { "end of list".to_string() }
                }}</span>
            </div>
            <Drawer
                open=matrix_open
                title=Signal::derive(move || match matrix_scope.get().as_deref() {
                    Some("*") | None => "Global third-party rules".to_string(),
                    Some(s) => format!("Third-party rules: {s}"),
                })
            >
                {move || matrix_scope.get().map(|s| view! { <SourceMatrix page_scope=s /> })}
            </Drawer>
        </div>
    }
}

/// One site rule row.
#[component]
fn SiteRow(
    rule: SiteRuleDto,
    on_change: Callback<(String, String)>,
    on_delete: Callback<String>,
    on_matrix: Callback<String>,
) -> impl IntoView {
    let app = use_app_state();
    let id = rule.id.clone();
    let scope = rule.scope.clone();
    let cur = RwSignal::new(rule.preset.kind.clone());

    let change = {
        let (app, id) = (app.clone(), id.clone());
        move |kind: String| {
            let (app, id) = (app.clone(), id.clone());
            cur.set(kind.clone());
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new()
                    .update_site_rule(
                        &id,
                        &SiteRuleUpdate {
                            preset: preset(&kind),
                            note: None,
                        },
                    )
                    .await
                {
                    Ok(_) => {
                        app.success("Preset changed");
                        on_change.run((id, kind));
                    }
                    Err(e) => app.error(e.to_string()),
                }
            });
        }
    };
    let remove = {
        let (app, id) = (app.clone(), id.clone());
        Callback::new(move |()| {
            let (app, id) = (app.clone(), id.clone());
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().delete_site_rule(&id).await {
                    Ok(_) => {
                        app.success("Site rule deleted");
                        on_delete.run(id);
                    }
                    Err(e) => app.error(e.to_string()),
                }
            });
        })
    };
    let (title, label, sc) = (scope.clone(), scope.clone(), scope.clone());

    view! {
        <div class="siterow">
            <div class="h">
                <b title=title>{label}</b>
                <small>
                    {format!("changed {} - ", ago_secs(rule.updated_at))}
                    <button type="button" class="btn sm ghost" on:click=move |_| on_matrix.run(sc.clone())>"Third-party rules"</button>
                </small>
            </div>
            <Segmented
                label=format!("Policy for {scope}")
                options=presets()
                value=cur
                on_change=Callback::new(move |k: String| change(k))
            />
            <ConfirmButton label="Delete" confirm_label="Delete?" on_confirm=remove />
        </div>
    }
}

/// Third-party sources x capabilities for one page scope.
#[component]
fn SourceMatrix(page_scope: String) -> impl IntoView {
    let app = use_app_state();
    let reload = RwSignal::new(0u32);
    let new_source = RwSignal::new(String::new());
    let new_effect = RwSignal::new("allow".to_string());
    let new_cap = RwSignal::new("script".to_string());

    let fetch: Fetcher<SourceRuleDto> = {
        let (app, scope) = (app.clone(), page_scope.clone());
        std::rc::Rc::new(move |cursor, _| {
            let (app, scope) = (app.clone(), scope.clone());
            Box::pin(async move {
                match ApiClient::new()
                    .list_source_rules(&scope, cursor.as_deref())
                    .await
                {
                    Ok(p) => Ok((p.items, p.next_cursor, p.total)),
                    Err(e) => {
                        app.error(format!("Failed to load source rules: {e}"));
                        Err(e)
                    }
                }
            })
        })
    };
    let rules = Feed::new(fetch);
    Effect::new(move || {
        reload.track();
        rules.reload(None, false, None);
    });

    let add = {
        let (app, scope) = (app.clone(), page_scope.clone());
        move || {
            let (source, effect, cap) = (
                new_source.get_untracked(),
                new_effect.get_untracked(),
                new_cap.get_untracked(),
            );
            let scope = scope.clone();
            run(&app, async move {
                ApiClient::new()
                    .create_source_rule(&SourceRuleInput {
                        page: scope,
                        source,
                        caps: vec![cap],
                        effect,
                        note: None,
                    })
                    .await?;
                new_source.set(String::new());
                reload.update(|n| *n += 1);
                Ok("Source rule added".into())
            });
        }
    };

    view! {
            <div class="policy-matrix">
                <Scroller feed=rules class="table-container">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>"Source"</th>
                                <th>"Effect"</th>
                                {SOURCE_CAPS.iter().map(|c| view! { <th>{*c}</th> }).collect_view()}
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            <For
                                each=move || rules.items.get()
                                key=|r| (r.id.clone(), r.caps.clone())
                                children={
                                    let app = app.clone();
                                    move |r| {
                                        let (rid, caps) = (r.id.clone(), r.caps.clone());
                                        let app2 = app.clone();
                                        let rid_del = rid.clone();
                                        let app_del = app.clone();
                                        view! {
                                            <tr>
                                                <td>{r.source.clone()}</td>
                                                <td>{r.effect.clone()}</td>
                                                {SOURCE_CAPS.iter().map(|cap| {
                                                    let (rid, caps, app) = (rid.clone(), caps.clone(), app2.clone());
                                                    let on = caps.iter().any(|c| c == cap);
                                                    view! {
                                                        <td>
    <Switch
                                                                checked=on
                                                                label=format!("{cap} for {}", r.source)
                                                                on_change=Callback::new(move |checked: bool| {
                                                                    let mut next: Vec<String> =
                                                                        caps.iter().filter(|c| *c != cap).cloned().collect();
                                                                    if checked {
                                                                        next.push(cap.to_string());
                                                                    }
                                                                    let rid = rid.clone();
                                                                    run(&app, async move {
                                                                        ApiClient::new()
                                                                            .update_source_rule(&rid, &SourceRuleUpdate { caps: next, note: None })
                                                                            .await?;
                                                                        reload.update(|n| *n += 1);
                                                                        Ok(String::new())
                                                                    });
                                                                })
                                                            />
                                                        </td>
                                                    }
                                                }).collect_view()}
                                                <td>
                                                    <ConfirmButton
                                                        label="Remove"
                                                        confirm_label="Remove?"
                                                        on_confirm=Callback::new(move |()| {
                                                            let rid = rid_del.clone();
                                                            run(&app_del, async move {
                                                                ApiClient::new().delete_source_rule(&rid).await?;
                                                                reload.update(|n| *n += 1);
                                                                Ok(String::new())
                                                            });
                                                        })
                                                    />
                                                </td>
                                            </tr>
                                        }
                                    }
                                }
                            />
                        </tbody>
                    </table>
                    <Show when=move || rules.items.with(|v| v.is_empty()) && !rules.loading.get()>
                        <div class="empty"><p>"No third-party rules for this scope"</p></div>
                    </Show>
                </Scroller>
                <div class="policy-add">
                    <input
                        class="input"
                        placeholder="cdn.example.net (host), site:example.net or *"
                        prop:value=move || new_source.get()
                        on:input=move |ev| new_source.set(event_target_value(&ev))
                    />
                    <select class="select" on:change=move |ev| new_effect.set(event_target_value(&ev))>
                        <option value="allow">"allow"</option>
                        <option value="deny">"deny"</option>
                    </select>
                    <select class="select" on:change=move |ev| new_cap.set(event_target_value(&ev))>
                        {SOURCE_CAPS.iter().map(|c| view! { <option value=*c>{*c}</option> }).collect_view()}
                    </select>
                    <button class="btn primary" on:click=move |_| add()>"Add rule"</button>
                </div>
                <p class="stat-label">
                    "A bare host such as cdn.example.net is read as a site (its registrable domain); \
                     write host:cdn.example.net for exactly that host."
                </p>
            </div>
        }
}

#[component]
fn ExplainCard() -> impl IntoView {
    let app = use_app_state();
    let url = RwSignal::new(String::new());
    let result = RwSignal::new(Option::<ExplainResponse>::None);

    let go = {
        let app = app.clone();
        move || {
            let u = url.get_untracked();
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().explain_policy(&u).await {
                    Ok(r) => result.set(Some(r)),
                    Err(e) => {
                        result.set(None);
                        app.error(e.to_string());
                    }
                }
            });
        }
    };

    view! {
        <Card title="Explain this URL">
            <div class="policy-add">
                <input
                    class="input"
                    placeholder="https://www.example.com/page"
                    prop:value=move || url.get()
                    on:input=move |ev| url.set(event_target_value(&ev))
                    on:keydown={
                        let go = go.clone();
                        move |ev| if ev.key() == "Enter" { go() }
                    }
                />
                <button class="btn primary" on:click=move |_| go()>"Explain"</button>
            </div>
            <Show when=move || result.get().is_some()>
                {move || result.get().map(|r| view! {
                    <div class="policy-explain">
                        <p>
                            <strong>{r.site.clone()}</strong>
                            {if r.enabled { " (policy enforced)" } else { " (policy switched off: nothing is added)" }}
                        </p>
                        <p class="stat-label">
                            {format!(
                                "{} site rule(s), {} source rule(s), {} temporary grant(s) match",
                                r.matched_site_rules.len(),
                                r.matched_source_rules.len(),
                                r.active_temps.len()
                            )}
                        </p>
                        <h4>"Content-Security-Policy added"</h4>
                        <pre class="source-code">{r.csp_header.clone().unwrap_or_else(|| "(none)".into())}</pre>
                        {r.permissions_policy.clone().map(|p| view! {
                            <h4>"Permissions-Policy added"</h4>
                            <pre class="source-code">{p}</pre>
                        })}
                        <h4>"HTML changes"</h4>
                        <ul>
                            {r.html_actions.unwrap_noscript.then(|| view! { <li>"Reveal <noscript> content"</li> })}
                            {r.html_actions.strip_scripts.then(|| view! { <li>"Remove blocked script elements"</li> })}
                            {r.html_actions.rules.iter().map(|h| view! {
                                <li><code>{h.selector.clone()}</code>" "{h.op.clone()}</li>
                            }).collect_view()}
                        </ul>
                        <h4>"Blocked early by the proxy"</h4>
                        <p>{if r.network_enforce.is_empty() { "nothing".to_string() } else { r.network_enforce.join(", ") }}</p>
                        {(!r.notes.is_empty()).then(|| view! {
                            <h4>"Not expressible in CSP"</h4>
                            <ul>{r.notes.iter().map(|n| view! { <li>{n.clone()}</li> }).collect_view()}</ul>
                        })}
                    </div>
                })}
            </Show>
        </Card>
    }
}

/// Per-site "ad blocking off" list (engine site exceptions).
#[component]
fn PanelSites(reload: RwSignal<u32>) -> impl IntoView {
    let app = use_app_state();
    let sites = RwSignal::new(Vec::<String>::new());
    let new_site = RwSignal::new(String::new());
    {
        Effect::new(move || {
            reload.track();
            wasm_bindgen_futures::spawn_local(async move {
                if let Ok(r) = ApiClient::new().get_site_exceptions().await {
                    sites.set(r.sites);
                }
            });
        });
    }
    let toggle_site = {
        let app = app.clone();
        Callback::new(move |(site, off): (String, bool)| {
            run(&app, async move {
                sites.set(ApiClient::new().set_site_exception(&site, off).await?.sites);
                Ok(String::new())
            });
        })
    };
    view! {
        <div class="card">
            <div class="card-h"><h3>"Ad blocking off for"</h3><span class="sub">"Sites where network and cosmetic filters are skipped"</span></div>
            <div>
                <For each=move || sites.get() key=|s| s.clone() let:site>
                    {
                        let s2 = site.clone();
                        view! {
                            <div class="trow">
                                <span class="mono th">{site}</span>
                                <span></span>
                                <button type="button" class="btn sm" on:click=move |_| toggle_site.run((s2.clone(), false))>"Turn on"</button>
                            </div>
                        }
                    }
                </For>
            </div>
            <div class="card-b" style="border-top:1px solid var(--line)">
                <div class="toolbar">
                    <label class="sr" for="offSite">"Site"</label>
                    <input id="offSite" class="input mono grow" placeholder="example.com" prop:value=move || new_site.get()
                        on:input=move |ev| new_site.set(event_target_value(&ev)) />
                    <button type="button" class="btn" on:click=move |_| {
                        let s = new_site.get_untracked();
                        if !s.is_empty() { toggle_site.run((s, true)); new_site.set(String::new()); }
                    }>"Turn ad blocking off"</button>
                </div>
            </div>
        </div>
    }
}

//! Script policy page: global default, per-site presets, third-party source matrix, temporary
//! permissions and an "explain this URL" box. Uses only the public API.

use leptos::prelude::*;

use crate::api::policy::*;
use crate::api::ApiClient;
use crate::components::{Card, Layout, ProfileSelector};
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

fn preset(kind: &str) -> PresetDto {
    PresetDto {
        kind: kind.to_string(),
        profile: None,
    }
}

fn fmt_remaining(secs: Option<u64>) -> String {
    match secs {
        None => "until restart".into(),
        Some(s) if s >= 3600 => format!("{}h {}m left", s / 3600, (s % 3600) / 60),
        Some(s) if s >= 60 => format!("{}m left", s / 60),
        Some(s) => format!("{s}s left"),
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
            <p class="modal-help">
                "NoScript-style control, enforced with a Content-Security-Policy added to each page. \
                 The browser enforces it; the proxy also blocks denied third-party requests early \
                 when it can tell which page made them."
            </p>
            <SettingsCard reload=reload />
            <PanelCard reload=reload />
            <SitesCard reload=reload />
            <TempCard reload=reload />
            <ExplainCard />
        </Layout>
    }
}

#[component]
fn SettingsCard(reload: RwSignal<u32>) -> impl IntoView {
    let app = use_app_state();
    let full = RwSignal::new(Option::<PolicySettingsDto>::None);
    let generation = RwSignal::new(0u64);

    {
        let app = app.clone();
        Effect::new(move || {
            reload.track();
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().get_policy_settings().await {
                    Ok(r) => {
                        generation.set(r.generation);
                        full.set(Some(r.settings));
                    }
                    Err(e) => app.error(format!("Failed to load policy settings: {e}")),
                }
            });
        });
    }

    let save = {
        let app = app.clone();
        Callback::new(move |()| {
            let Some(s) = full.get_untracked() else {
                return;
            };
            run(&app, async move {
                let r = ApiClient::new().put_policy_settings(&s).await?;
                generation.set(r.generation);
                full.set(Some(r.settings));
                Ok("Policy settings saved".into())
            });
        })
    };

    let edit = move |f: Box<dyn Fn(&mut PolicySettingsDto)>| {
        full.update(|s| {
            if let Some(s) = s {
                f(s)
            }
        })
    };

    view! {
        <Card title="Global default">
            <Show when=move || full.get().is_some() fallback=|| view! { <div class="loading">"Loading..."</div> }>
                <div class="form-toggles">
                    <label class="form-checkbox">
                        <input
                            type="checkbox"
                            class="checkbox-input"
                            prop:checked=move || full.get().is_some_and(|s| s.enabled)
                            on:change=move |ev| {
                                let v = event_target_checked(&ev);
                                edit(Box::new(move |s| s.enabled = v));
                            }
                        />
                        <span>"Enforce script policy (master switch; off means nothing is added to any page)"</span>
                    </label>
                    <label class="form-checkbox">
                        <input
                            type="checkbox"
                            class="checkbox-input"
                            prop:checked=move || full.get().is_some_and(|s| s.strip_blocked_scripts)
                            on:change=move |ev| {
                                let v = event_target_checked(&ev);
                                edit(Box::new(move |s| s.strip_blocked_scripts = v));
                            }
                        />
                        <span>"Strip blocked scripts from HTML (saves the download; otherwise the browser blocks them)"</span>
                    </label>
                    <label class="form-checkbox">
                        <input
                            type="checkbox"
                            class="checkbox-input"
                            prop:checked=move || full.get().is_some_and(|s| s.strip_meta_refresh)
                            on:change=move |ev| {
                                let v = event_target_checked(&ev);
                                edit(Box::new(move |s| s.strip_meta_refresh = v));
                            }
                        />
                        <span>"Remove meta refresh from pages whose scripts are blocked"</span>
                    </label>
                    <label class="form-checkbox">
                        <input
                            type="checkbox"
                            class="checkbox-input"
                            prop:checked=move || full.get().is_some_and(|s| s.network_hints)
                            on:change=move |ev| {
                                let v = event_target_checked(&ev);
                                edit(Box::new(move |s| s.network_hints = v));
                            }
                        />
                        <span>"Block denied third-party requests at the proxy when the page is known"</span>
                    </label>
                </div>
                <div class="form-field">
                    <label class="form-label">"Sites without a rule use"</label>
                    <select
                        class="form-select"
                        prop:value=move || full.get().map(|s| s.global.kind).unwrap_or_default()
                        on:change=move |ev| {
                            let kind = event_target_value(&ev);
                            edit(Box::new(move |s| s.global = preset(&kind)));
                        }
                    >
                        <option value="default">"Default (first-party scripts only)"</option>
                        <option value="trusted">"Trusted (allow everything)"</option>
                        <option value="untrusted">"Untrusted (block scripts)"</option>
                        <Show when=move || full.get().is_some_and(|s| s.global.kind == "custom")>
                            <option value="custom">"Custom"</option>
                        </Show>
                    </select>
                </div>
                <div class="form-actions">
                    <button class="btn btn-primary" on:click=move |_| save.run(())>"Save"</button>
                    <span class="stat-label">" policy generation "{generation}</span>
                </div>
            </Show>
        </Card>
    }
}

#[component]
fn SitesCard(reload: RwSignal<u32>) -> impl IntoView {
    let app = use_app_state();
    let rules = RwSignal::new(Vec::<SiteRuleDto>::new());
    let total = RwSignal::new(0usize);
    let search = RwSignal::new(String::new());
    let new_scope = RwSignal::new(String::new());
    let new_preset = RwSignal::new("trusted".to_string());

    {
        let app = app.clone();
        Effect::new(move || {
            reload.track();
            let q = search.get();
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().list_site_rules(&q).await {
                    Ok(p) => {
                        total.set(p.total);
                        rules.set(p.items);
                    }
                    Err(e) => app.error(format!("Failed to load site rules: {e}")),
                }
            });
        });
    }

    let add = {
        let app = app.clone();
        move || {
            let (scope, kind) = (new_scope.get_untracked(), new_preset.get_untracked());
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

    view! {
        <Card title="Sites">
            <div class="form-row">
                <div class="form-field">
                    <input
                        class="form-input"
                        placeholder="Search sites"
                        prop:value=move || search.get()
                        on:input=move |ev| search.set(event_target_value(&ev))
                    />
                </div>
                <div class="form-field policy-add">
                    <input
                        class="form-input"
                        placeholder="example.com, host:www.example.com or https://host"
                        prop:value=move || new_scope.get()
                        on:input=move |ev| new_scope.set(event_target_value(&ev))
                    />
                    <select
                        class="form-select"
                        prop:value=move || new_preset.get()
                        on:change=move |ev| new_preset.set(event_target_value(&ev))
                    >
                        <option value="trusted">"Trusted"</option>
                        <option value="untrusted">"Untrusted"</option>
                        <option value="default">"Default"</option>
                    </select>
                    <button class="btn btn-primary" on:click=move |_| add()>"Add"</button>
                </div>
            </div>
            <div class="table-container">
                <table class="table">
                    <thead>
                        <tr>
                            <th></th>
                            <th>"Site"</th>
                            <th>"Preset"</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <PolicyRow scope="*".to_string() id=None kind=String::new() reload=reload />
                        <For
                            each=move || rules.get()
                            key=|r| (r.id.clone(), r.preset.kind.clone())
                            children=move |r| view! {
                                <PolicyRow scope=r.scope.clone() id=Some(r.id.clone()) kind=r.preset.kind.clone() reload=reload />
                            }
                        />
                    </tbody>
                </table>
                <Show when=move || rules.get().is_empty()>
                    <div class="empty-state"><p>"No site rules"</p></div>
                </Show>
                <p class="stat-label">{move || format!("{} site rule(s)", total.get())}</p>
            </div>
        </Card>
    }
}

/// One row (a site rule, or the "All sites" row for global source rules) plus its expandable
/// third-party matrix.
#[component]
fn PolicyRow(
    scope: String,
    id: Option<String>,
    kind: String,
    reload: RwSignal<u32>,
) -> impl IntoView {
    let app = use_app_state();
    let expanded = RwSignal::new(false);
    let is_global = id.is_none();
    let label = if is_global {
        "All sites (global source rules)".to_string()
    } else {
        scope.clone()
    };

    let change = {
        let (app, id) = (app.clone(), id.clone());
        move |kind: String| {
            let Some(id) = id.clone() else { return };
            run(&app, async move {
                ApiClient::new()
                    .update_site_rule(
                        &id,
                        &SiteRuleUpdate {
                            preset: preset(&kind),
                            note: None,
                        },
                    )
                    .await?;
                reload.update(|n| *n += 1);
                Ok("Preset changed".into())
            });
        }
    };
    let remove = {
        let (app, id) = (app.clone(), id.clone());
        move || {
            let Some(id) = id.clone() else { return };
            run(&app, async move {
                ApiClient::new().delete_site_rule(&id).await?;
                reload.update(|n| *n += 1);
                Ok("Site rule deleted".into())
            });
        }
    };
    let scope_for_matrix = scope.clone();

    view! {
        <tr>
            <td>
                <button class="btn btn-ghost" on:click=move |_| expanded.update(|e| *e = !*e)>
                    {move || if expanded.get() { "v" } else { ">" }}
                </button>
            </td>
            <td>{label}</td>
            <td>
                {if is_global {
                    view! { <span class="stat-label">"-"</span> }.into_any()
                } else {
                    let current = kind.clone();
                    view! {
                        <select
                            class="form-select"
                            on:change=move |ev| change(event_target_value(&ev))
                        >
                            {["default", "trusted", "untrusted", "custom"].into_iter().map(|k| view! {
                                <option value=k selected=k == current disabled=k == "custom">{k}</option>
                            }).collect_view()}
                        </select>
                    }.into_any()
                }}
            </td>
            <td>
                {(!is_global).then(|| view! {
                    <button class="btn btn-danger" on:click=move |_| remove()>"Delete"</button>
                })}
            </td>
        </tr>
        <Show when=move || expanded.get()>
            <tr>
                <td colspan="4">
                    <SourceMatrix page_scope=scope_for_matrix.clone() />
                </td>
            </tr>
        </Show>
    }
}

/// Third-party sources x capabilities for one page scope.
#[component]
fn SourceMatrix(page_scope: String) -> impl IntoView {
    let app = use_app_state();
    let rules = RwSignal::new(Vec::<SourceRuleDto>::new());
    let reload = RwSignal::new(0u32);
    let new_source = RwSignal::new(String::new());
    let new_effect = RwSignal::new("allow".to_string());
    let new_cap = RwSignal::new("script".to_string());

    {
        let (app, scope) = (app.clone(), page_scope.clone());
        Effect::new(move || {
            reload.track();
            let (app, scope) = (app.clone(), scope.clone());
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().list_source_rules(&scope).await {
                    Ok(p) => rules.set(p.items),
                    Err(e) => app.error(format!("Failed to load source rules: {e}")),
                }
            });
        });
    }

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
            <div class="table-container">
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
                            each=move || rules.get()
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
                                                        <input
                                                            type="checkbox"
                                                            class="checkbox-input"
                                                            prop:checked=on
                                                            on:change=move |ev| {
                                                                let checked = event_target_checked(&ev);
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
                                                            }
                                                        />
                                                    </td>
                                                }
                                            }).collect_view()}
                                            <td>
                                                <button
                                                    class="btn btn-danger"
                                                    on:click=move |_| {
                                                        let rid = rid_del.clone();
                                                        run(&app_del, async move {
                                                            ApiClient::new().delete_source_rule(&rid).await?;
                                                            reload.update(|n| *n += 1);
                                                            Ok(String::new())
                                                        });
                                                    }
                                                >
                                                    "Remove"
                                                </button>
                                            </td>
                                        </tr>
                                    }
                                }
                            }
                        />
                    </tbody>
                </table>
                <Show when=move || rules.get().is_empty()>
                    <div class="empty-state"><p>"No third-party rules for this scope"</p></div>
                </Show>
            </div>
            <div class="policy-add">
                <input
                    class="form-input"
                    placeholder="cdn.example.net (host), site:example.net or *"
                    prop:value=move || new_source.get()
                    on:input=move |ev| new_source.set(event_target_value(&ev))
                />
                <select class="form-select" on:change=move |ev| new_effect.set(event_target_value(&ev))>
                    <option value="allow">"allow"</option>
                    <option value="deny">"deny"</option>
                </select>
                <select class="form-select" on:change=move |ev| new_cap.set(event_target_value(&ev))>
                    {SOURCE_CAPS.iter().map(|c| view! { <option value=*c>{*c}</option> }).collect_view()}
                </select>
                <button class="btn btn-primary" on:click=move |_| add()>"Add rule"</button>
            </div>
            <p class="stat-label">
                "A bare host such as cdn.example.net is read as a site (its registrable domain); \
                 write host:cdn.example.net for exactly that host."
            </p>
        </div>
    }
}

#[component]
fn TempCard(reload: RwSignal<u32>) -> impl IntoView {
    let app = use_app_state();
    let grants = RwSignal::new(Vec::<TempGrantDto>::new());
    let page = RwSignal::new(String::new());
    let ttl = RwSignal::new("3600".to_string());

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

    let grant = {
        let app = app.clone();
        move || {
            let (p, t) = (page.get_untracked(), ttl.get_untracked());
            run(&app, async move {
                let until_restart = t == "restart";
                ApiClient::new()
                    .grant_temp(&TempGrantInput {
                        page: p,
                        kind: "site".into(),
                        preset: Some(preset("trusted")),
                        source: None,
                        caps: vec![],
                        ttl_secs: (!until_restart).then(|| t.parse().unwrap_or(3600)),
                        until_restart,
                        persist: false,
                    })
                    .await?;
                page.set(String::new());
                reload.update(|n| *n += 1);
                Ok("Temporarily trusted".into())
            });
        }
    };
    let revoke_all = {
        let app = app.clone();
        move || {
            run(&app, async move {
                ApiClient::new().revoke_all_temp().await?;
                reload.update(|n| *n += 1);
                Ok("All temporary permissions revoked".into())
            });
        }
    };

    view! {
        <Card title="Temporary permissions">
            <div class="policy-add">
                <input
                    class="form-input"
                    placeholder="Site to trust temporarily, e.g. example.com"
                    prop:value=move || page.get()
                    on:input=move |ev| page.set(event_target_value(&ev))
                />
                <select class="form-select" on:change=move |ev| ttl.set(event_target_value(&ev))>
                    <option value="3600">"1 hour"</option>
                    <option value="300">"5 minutes"</option>
                    <option value="86400">"1 day"</option>
                    <option value="restart">"until restart"</option>
                </select>
                <button class="btn btn-primary" on:click=move |_| grant()>"Trust temporarily"</button>
            </div>
            <div class="policy-badges">
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
                                _ => format!(
                                    "{}: {}",
                                    g.page,
                                    g.preset.as_ref().map(|p| p.kind.clone()).unwrap_or_default()
                                ),
                            };
                            view! {
                                <span class="stat-badge policy-badge">
                                    <span class="stat-value">{what}</span>
                                    <span class="stat-label">{fmt_remaining(g.remaining_secs)}</span>
                                    <button
                                        class="btn btn-ghost"
                                        on:click=move |_| {
                                            let id = id.clone();
                                            run(&app, async move {
                                                ApiClient::new().revoke_temp(&id).await?;
                                                reload.update(|n| *n += 1);
                                                Ok("Revoked".into())
                                            });
                                        }
                                    >
                                        "Revoke"
                                    </button>
                                </span>
                            }
                        }
                    }
                />
            </div>
            <Show when=move || grants.get().is_empty()>
                <div class="empty-state"><p>"No temporary permissions"</p></div>
            </Show>
            <Show when=move || !grants.get().is_empty()>
                <button class="btn btn-danger" on:click={
                    let revoke_all = revoke_all.clone();
                    move |_| revoke_all()
                }>"Revoke all"</button>
            </Show>
        </Card>
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
                    class="form-input"
                    placeholder="https://www.example.com/page"
                    prop:value=move || url.get()
                    on:input=move |ev| url.set(event_target_value(&ev))
                    on:keydown={
                        let go = go.clone();
                        move |ev| if ev.key() == "Enter" { go() }
                    }
                />
                <button class="btn btn-primary" on:click=move |_| go()>"Explain"</button>
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

/// The in-page panel (hotkey) and per-site "ad blocking off".
#[component]
fn PanelCard(reload: RwSignal<u32>) -> impl IntoView {
    let app = use_app_state();
    let cur = RwSignal::new(Option::<PanelSettingsDto>::None);
    let pin = RwSignal::new(String::new());
    let sites = RwSignal::new(Vec::<String>::new());
    let new_site = RwSignal::new(String::new());

    {
        let app = app.clone();
        Effect::new(move || {
            reload.track();
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().get_panel_settings().await {
                    Ok(r) => cur.set(Some(r)),
                    Err(e) => app.error(format!("Failed to load panel settings: {e}")),
                }
                if let Ok(r) = ApiClient::new().get_site_exceptions().await {
                    sites.set(r.sites);
                }
            });
        });
    }
    let save = {
        let app = app.clone();
        Callback::new(move |clear_pin: bool| {
            let Some(c) = cur.get_untracked() else { return };
            let p = pin.get_untracked();
            let input = PanelSettingsInput {
                enabled: Some(c.enabled),
                hotkey: Some(c.hotkey),
                auth: Some(c.auth),
                pin: (!p.is_empty()).then_some(p),
                clear_pin,
            };
            run(&app, async move {
                cur.set(Some(ApiClient::new().put_panel_settings(&input).await?));
                pin.set(String::new());
                Ok("Panel settings saved".into())
            });
        })
    };
    let edit = move |f: Box<dyn Fn(&mut PanelSettingsDto)>| {
        cur.update(|s| {
            if let Some(s) = s {
                f(s)
            }
        })
    };
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
        <Card title="In-page panel">
            <p class="modal-help">
                "A hotkey opens a read-only panel on the page itself (no toolbar button on a proxy). \
                 It cannot change anything: a change is confirmed on the proxy-owned host, which a \
                 page cannot script. Needs the master switch above only for presets and sources."
            </p>
            <Show when=move || cur.get().is_some() fallback=|| view! { <div class="loading">"Loading..."</div> }>
                <div class="form-toggles">
                    <label class="form-checkbox">
                        <input type="checkbox" class="checkbox-input"
                            prop:checked=move || cur.get().is_some_and(|s| s.enabled)
                            on:change=move |ev| { let v = event_target_checked(&ev); edit(Box::new(move |s| s.enabled = v)); } />
                        <span>"Offer the panel on pages (off by default)"</span>
                    </label>
                </div>
                <div class="form-field">
                    <label class="form-label">"Hotkey"</label>
                    <input class="form-input" prop:value=move || cur.get().map(|s| s.hotkey).unwrap_or_default()
                        on:input=move |ev| { let v = event_target_value(&ev); edit(Box::new(move |s| s.hotkey = v.clone())); } />
                </div>
                <div class="form-field">
                    <label class="form-label">"Confirm changes with"</label>
                    <select class="form-select" prop:value=move || cur.get().map(|s| s.auth).unwrap_or_default()
                        on:change=move |ev| { let v = event_target_value(&ev); edit(Box::new(move |s| s.auth = v.clone())); }>
                        <option value="pin">"A PIN entered on the confirmation page"</option>
                        <option value="session">"The dashboard only (the panel links here)"</option>
                        <option value="none">"A click (trusted LAN only)"</option>
                    </select>
                </div>
                <div class="form-field">
                    <label class="form-label">
                        {move || if cur.get().is_some_and(|s| s.pin_set) { "New PIN (a PIN is set)" } else { "PIN (none set)" }}
                    </label>
                    <input class="form-input" type="password" autocomplete="new-password"
                        prop:value=move || pin.get() on:input=move |ev| pin.set(event_target_value(&ev)) />
                </div>
                <div class="form-actions">
                    <button class="btn btn-primary" on:click=move |_| save.run(false)>"Save"</button>
                    <button class="btn" on:click=move |_| save.run(true)>"Remove PIN"</button>
                    <span class="stat-label">" confirmation host: "{move || cur.get().map(|s| s.reserved_host).unwrap_or_default()}</span>
                </div>
            </Show>
            <h3>"Ad blocking off for"</h3>
            <ul>
                <For each=move || sites.get() key=|s| s.clone() let:site>
                    {
                        let s2 = site.clone();
                        view! { <li>{site} " " <button class="btn" on:click=move |_| toggle_site.run((s2.clone(), false))>"Turn on"</button></li> }
                    }
                </For>
            </ul>
            <div class="form-field">
                <input class="form-input" placeholder="example.com" prop:value=move || new_site.get()
                    on:input=move |ev| new_site.set(event_target_value(&ev)) />
                <button class="btn" on:click=move |_| { let s = new_site.get_untracked(); if !s.is_empty() { toggle_site.run((s, true)); new_site.set(String::new()); } }>
                    "Turn ad blocking off"
                </button>
            </div>
        </Card>
    }
}

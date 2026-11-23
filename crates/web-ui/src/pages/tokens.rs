//! API tokens page: create (scope chips grouped by resource), show the secret once, list, revoke.

use std::collections::BTreeMap;

use leptos::prelude::*;

use crate::api::tokens::{ApiTokenInfo, Scope};
use crate::api::ApiClient;
use crate::components::{Card, ChipSelect, ConfirmButton, Icon, Layout, Segmented};
use crate::state::{use_app_state, use_auth_state};
use crate::utils::{copy_text, fmt_ago, fmt_datetime};

/// Scopes grouped by resource, in declaration order within each group.
fn grouped(scopes: &[Scope]) -> Vec<(&'static str, Vec<Scope>)> {
    let mut map: BTreeMap<&'static str, Vec<Scope>> = BTreeMap::new();
    for s in scopes {
        map.entry(s.resource()).or_default().push(*s);
    }
    map.into_iter().collect()
}

fn is_admin_scope(s: &Scope) -> bool {
    s.action() == "admin"
}

/// Scope tags for a token row.
pub fn scope_tags(scopes: &[Scope]) -> impl IntoView {
    scopes
        .iter()
        .map(|s| view! { <span class="tag">{s.as_str()}</span>" " })
        .collect_view()
}

#[component]
pub fn TokensPage() -> impl IntoView {
    let app_state = use_app_state();
    let user = use_auth_state().user;

    let tokens = RwSignal::new(Vec::<ApiTokenInfo>::new());
    let name = RwSignal::new(String::new());
    let expiry = RwSignal::new("90".to_string());
    let selected = RwSignal::new(Vec::<Scope>::new());
    let new_secret = RwSignal::new(Option::<String>::None);
    let reload = RwSignal::new(0u32);

    let available = Memo::new(move |_| user.get().map(|u| grouped(&u.scopes)).unwrap_or_default());

    {
        let app_state = app_state.clone();
        Effect::new(move |_| {
            reload.get();
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().list_tokens().await {
                    Ok(page) => tokens.set(page.items),
                    Err(e) => app_state.error(format!("Failed to load tokens: {e}")),
                }
            });
        });
    }

    let create = {
        let app_state = app_state.clone();
        move |_| {
            let scopes = selected.get_untracked();
            let token_name = name.get_untracked();
            if token_name.trim().is_empty() || scopes.is_empty() {
                app_state.error("Give the token a name and select at least one scope");
                return;
            }
            let days = expiry.get_untracked().parse::<u32>().ok();
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new()
                    .create_token(&token_name, scopes, days)
                    .await
                {
                    Ok(created) => {
                        new_secret.set(Some(created.secret));
                        name.set(String::new());
                        selected.set(Vec::new());
                        reload.update(|n| *n += 1);
                    }
                    Err(e) => app_state.error(format!("Failed to create token: {e}")),
                }
            });
        }
    };

    let revoke = {
        let app_state = app_state.clone();
        move |id: String| {
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().revoke_token(&id).await {
                    Ok(_) => {
                        app_state.success("Token revoked");
                        reload.update(|n| *n += 1);
                    }
                    Err(e) => app_state.error(format!("Failed to revoke: {e}")),
                }
            });
        }
    };

    let app_copy = app_state.clone();
    let scope_count = move || selected.read().len();

    view! {
        <Layout>
            <Show when=move || new_secret.get().is_some()>
                <div class="newtoken" role="status">
                    <code>{move || new_secret.get().unwrap_or_default()}</code>
                    <button class="btn sm" type="button" on:click={
                        let app = app_copy.clone();
                        move |_| {
                            if copy_text(&new_secret.get_untracked().unwrap_or_default()) {
                                app.success("Token copied");
                            }
                        }
                    }><Icon name="copy" />"Copy"</button>
                    <button class="btn sm ghost" type="button" on:click=move |_| new_secret.set(None)>"I have copied it"</button>
                    <span class="hint" style="flex-basis:100%">"Copy it now. You can't view this token again."</span>
                </div>
            </Show>

            <Card title="Create token" sub="For scripts and integrations. Shown once.">
                <div class="grid2" style="gap:var(--s3)">
                    <div class="field">
                        <label for="tkName">"Name"</label>
                        <input
                            class="input"
                            id="tkName"
                            prop:value=move || name.get()
                            on:input=move |ev| name.set(event_target_value(&ev))
                        />
                    </div>
                    <div class="field">
                        <span class="lbl">"Expires"</span>
                        <Segmented
                            label="Expires"
                            options=vec![
                                ("7".into(), "7 days".into()),
                                ("30".into(), "30 days".into()),
                                ("90".into(), "90 days".into()),
                                ("".into(), "Never".into()),
                            ]
                            value=expiry
                            on_change=Callback::new(move |v| expiry.set(v))
                        />
                    </div>
                </div>
                <div class="field">
                    <span class="lbl">"Scopes "<span class="dim">{move || format!("({} selected)", scope_count())}</span></span>
                    {move || available.get().into_iter().map(|(resource, scopes)| {
                        let group_scopes = scopes.clone();
                        view! {
                            <div class="scopegrp">
                                <div class="gname">
                                    {resource}
                                    <button type="button" on:click=move |_| selected.update(|v| {
                                        let all = group_scopes.iter().all(|s| v.contains(s));
                                        v.retain(|s| !group_scopes.contains(s));
                                        if !all { v.extend(group_scopes.iter().copied()); }
                                    })>"toggle all"</button>
                                </div>
                                <div class="chips">
                                    {scopes.into_iter().map(|scope| view! {
                                        <ChipSelect
                                            class=if is_admin_scope(&scope) { "mono adminscope" } else { "mono" }
                                            title=scope.description()
                                            pressed=Signal::derive(move || selected.read().contains(&scope))
                                            on_toggle=Callback::new(move |on: bool| selected.update(|v| {
                                                v.retain(|s| *s != scope);
                                                if on { v.push(scope); }
                                            }))
                                        >{scope.action()}</ChipSelect>
                                    }).collect_view()}
                                </div>
                            </div>
                        }
                    }).collect_view()}
                    <span class="hint">"Dashed chips are admin scopes. They grant access to other users' data."</span>
                </div>
                <div class="toolbar">
                    <button class="btn primary" type="button" on:click=create>"Create token"</button>
                    <button class="btn ghost" type="button" on:click=move |_| {
                        let ro: Vec<Scope> = user.get_untracked().map(|u| u.scopes).unwrap_or_default()
                            .into_iter().filter(|s| s.action() == "read").collect();
                        selected.set(ro);
                    }>"Read-only preset"</button>
                </div>
            </Card>

            <div class="card">
                <div class="card-h"><h3>"Your tokens"</h3></div>
                <div class="tbl-wrap">
                    <table class="tbl">
                        <thead><tr><th>"Name"</th><th>"Scopes"</th><th>"Last used"</th><th>"Expires"</th><th></th></tr></thead>
                        <tbody>
                            <For
                                each=move || tokens.get()
                                key=|t| format!("{}{}", t.id, t.revoked)
                                children={
                                    let revoke = revoke.clone();
                                    move |t| {
                                        let id = t.id.clone();
                                        let revoke = revoke.clone();
                                        view! {
                                            <tr>
                                                <td>{t.name.clone()}</td>
                                                <td style="white-space:normal">{scope_tags(&t.scopes)}</td>
                                                <td class="num">{t.last_used_at.as_deref().map(fmt_ago).unwrap_or_else(|| "never".into())}</td>
                                                <td class="num">{t.expires_at.as_deref().map(fmt_datetime).unwrap_or_else(|| "never".into())}</td>
                                                <td class="r">
                                                    {if t.revoked {
                                                        view! { <span class="dim">"revoked"</span> }.into_any()
                                                    } else {
                                                        view! { <ConfirmButton label="Revoke" confirm_label="Confirm revoke" on_confirm=Callback::new(move |_| revoke(id.clone())) /> }.into_any()
                                                    }}
                                                </td>
                                            </tr>
                                        }
                                    }
                                }
                            />
                        </tbody>
                    </table>
                    <Show when=move || tokens.read().is_empty()>
                        <div class="empty"><b>"No tokens yet"</b>"Create one above."</div>
                    </Show>
                </div>
            </div>
        </Layout>
    }
}

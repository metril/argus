//! API tokens page: create (with a scope checklist grouped by resource), show the secret once,
//! list and revoke. Uses only the public `/api/v1/tokens` API.

use std::collections::BTreeMap;

use leptos::prelude::*;

use crate::api::tokens::{ApiTokenInfo, Scope};
use crate::api::ApiClient;
use crate::components::{Card, Layout};
use crate::state::{use_app_state, use_auth_state};

/// Scopes grouped by resource, in declaration order within each group.
fn grouped(scopes: &[Scope]) -> Vec<(&'static str, Vec<Scope>)> {
    let mut map: BTreeMap<&'static str, Vec<Scope>> = BTreeMap::new();
    for s in scopes {
        map.entry(s.resource()).or_default().push(*s);
    }
    map.into_iter().collect()
}

/// API tokens page
#[component]
pub fn TokensPage() -> impl IntoView {
    let app_state = use_app_state();
    let auth_state = use_auth_state();
    let user = auth_state.user;

    let tokens = RwSignal::new(Vec::<ApiTokenInfo>::new());
    let name = RwSignal::new(String::new());
    let expiry = RwSignal::new("30".to_string());
    let selected = RwSignal::new(Vec::<Scope>::new());
    // The one-time secret of the token that was just created.
    let new_secret = RwSignal::new(Option::<String>::None);
    let reload = RwSignal::new(0u32);

    // Only scopes the current user holds can be granted.
    let available = move || user.get().map(|u| grouped(&u.scopes)).unwrap_or_default();

    {
        let app_state = app_state.clone();
        Effect::new(move || {
            reload.get();
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().list_tokens().await {
                    Ok(page) => tokens.set(page.items),
                    Err(e) => app_state.error(format!("Failed to load tokens: {}", e)),
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
                    Err(e) => app_state.error(format!("Failed to create token: {}", e)),
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
                    Err(e) => app_state.error(format!("Failed to revoke: {}", e)),
                }
            });
        }
    };

    view! {
        <Layout>
            <div class="page-header">
                <h1 class="page-title">"API Tokens"</h1>
            </div>

            <Show when=move || new_secret.get().is_some()>
                <Card title="Copy your new token now" class="settings-card">
                    <p class="form-help">
                        "This is the only time the secret is shown. Use it as "
                        <code>"Authorization: Bearer <token>"</code>"."
                    </p>
                    <p><code>{move || new_secret.get().unwrap_or_default()}</code></p>
                    <button class="btn btn-secondary" on:click=move |_| new_secret.set(None)>
                        "I have copied it"
                    </button>
                </Card>
            </Show>

            <Card title="Create token" class="settings-card">
                <div class="form-group">
                    <label>"Name"</label>
                    <input
                        class="form-input"
                        type="text"
                        prop:value=move || name.get()
                        on:input=move |ev| name.set(event_target_value(&ev))
                    />
                </div>
                <div class="form-group">
                    <label>"Expires"</label>
                    <select
                        class="form-input"
                        on:change=move |ev| expiry.set(event_target_value(&ev))
                    >
                        <option value="30" selected>"in 30 days"</option>
                        <option value="90">"in 90 days"</option>
                        <option value="365">"in 1 year"</option>
                        <option value="">"never"</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>"Scopes"</label>
                    {move || available().into_iter().map(|(resource, scopes)| view! {
                        <fieldset>
                            <legend>{resource}</legend>
                            {scopes.into_iter().map(|scope| view! {
                                <label class="checkbox-label" title=scope.description()>
                                    <input
                                        type="checkbox"
                                        prop:checked=move || selected.get().contains(&scope)
                                        on:change=move |ev| {
                                            let on = event_target_checked(&ev);
                                            selected.update(|v| {
                                                v.retain(|s| *s != scope);
                                                if on {
                                                    v.push(scope);
                                                }
                                            });
                                        }
                                    />
                                    {format!(" {} ", scope.as_str())}
                                    <span class="form-help">{scope.description()}</span>
                                </label>
                            }).collect_view()}
                        </fieldset>
                    }).collect_view()}
                </div>
                <button class="btn btn-primary" on:click=create>"Create token"</button>
            </Card>

            <Card title="Your tokens" class="settings-card">
                <Show
                    when=move || !tokens.get().is_empty()
                    fallback=|| view! { <p class="no-sessions">"No tokens yet"</p> }
                >
                    <table class="table">
                        <thead>
                            <tr>
                                <th>"Name"</th>
                                <th>"Scopes"</th>
                                <th>"Expires"</th>
                                <th>"Last used"</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            <For
                                each=move || tokens.get()
                                key=|t| format!("{}{}", t.id, t.revoked)
                                children={
                                    let revoke = revoke.clone();
                                    move |t| {
                                        let id = t.id.clone();
                                        let revoke = revoke.clone();
                                        let scopes = t
                                            .scopes
                                            .iter()
                                            .map(|s| s.as_str())
                                            .collect::<Vec<_>>()
                                            .join(", ");
                                        view! {
                                            <tr>
                                                <td>{t.name.clone()}</td>
                                                <td>{scopes}</td>
                                                <td>{t.expires_at.clone().unwrap_or_else(|| "never".into())}</td>
                                                <td>{t.last_used_at.clone().unwrap_or_else(|| "never".into())}</td>
                                                <td>
                                                    {if t.revoked {
                                                        view! { <span>"revoked"</span> }.into_any()
                                                    } else {
                                                        view! {
                                                            <button
                                                                class="btn btn-danger"
                                                                on:click=move |_| revoke(id.clone())
                                                            >
                                                                "Revoke"
                                                            </button>
                                                        }.into_any()
                                                    }}
                                                </td>
                                            </tr>
                                        }
                                    }
                                }
                            />
                        </tbody>
                    </table>
                </Show>
            </Card>
        </Layout>
    }
}

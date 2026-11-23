//! Admin: all sessions and all API tokens.

use leptos::prelude::*;

use crate::api::admin::ApiTokenInfo;
use crate::api::auth::SessionInfo;
use crate::api::ApiClient;
use crate::components::{ConfirmButton, Layout, RequireAdmin};
use crate::pages::tokens::scope_tags;
use crate::state::use_app_state;
use crate::utils::{fmt_ago, fmt_datetime};

#[component]
pub fn SessionsPage() -> impl IntoView {
    view! { <Layout><RequireAdmin><SessionsInner /></RequireAdmin></Layout> }
}

#[component]
fn SessionsInner() -> impl IntoView {
    let app = use_app_state();
    let sessions = RwSignal::new(Vec::<SessionInfo>::new());
    let tokens = RwSignal::new(Vec::<ApiTokenInfo>::new());
    let reload = RwSignal::new(0u32);

    {
        let app = app.clone();
        Effect::new(move |_| {
            reload.get();
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let c = ApiClient::new();
                match c.admin_list_sessions().await {
                    Ok(p) => sessions.set(p.items),
                    Err(e) => app.error(format!("Failed to load sessions: {e}")),
                }
                match c.admin_list_tokens().await {
                    Ok(p) => tokens.set(p.items),
                    Err(e) => app.error(format!("Failed to load tokens: {e}")),
                }
            });
        });
    }

    let revoke_session = {
        let app = app.clone();
        move |id: String| {
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().admin_revoke_session(&id).await {
                    Ok(_) => {
                        app.success("Session revoked");
                        reload.update(|n| *n += 1);
                    }
                    Err(e) => app.error(e.to_string()),
                }
            });
        }
    };
    let revoke_others = {
        let app = app.clone();
        Callback::new(move |_| {
            let ids: Vec<String> = sessions
                .get_untracked()
                .into_iter()
                .filter(|s| !s.current)
                .map(|s| s.id)
                .collect();
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let c = ApiClient::new();
                let (mut n, total) = (0, ids.len());
                for id in ids {
                    if c.admin_revoke_session(&id).await.is_ok() {
                        n += 1;
                    }
                }
                if n == total {
                    app.success(format!("{n} sessions revoked"));
                } else {
                    app.error(format!(
                        "{} of {total} sessions failed to revoke",
                        total - n
                    ));
                }
                reload.update(|n| *n += 1);
            });
        })
    };
    let revoke_token = {
        let app = app.clone();
        move |id: String| {
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().admin_revoke_token(&id).await {
                    Ok(_) => {
                        app.success("Token revoked");
                        reload.update(|n| *n += 1);
                    }
                    Err(e) => app.error(e.to_string()),
                }
            });
        }
    };

    view! {
        <div class="card">
            <div class="card-h">
                <h3>"Active sessions"</h3><span class="sub">"All users"</span>
                <div class="r"><ConfirmButton label="Revoke all except mine" confirm_label="Sign out others?" on_confirm=revoke_others /></div>
            </div>
            <div class="tbl-wrap">
                <table class="tbl">
                    <thead><tr><th>"User"</th><th>"Device"</th><th>"IP"</th><th>"Signed in"</th><th>"Last active"</th><th></th></tr></thead>
                    <tbody>
                        <For each=move || sessions.get() key=|s| s.id.clone() children={
                            let revoke = revoke_session.clone();
                            move |s| {
                                let id = s.id.clone();
                                let revoke = revoke.clone();
                                view! {
                                    <tr>
                                        <td>{s.username.clone()}{s.current.then(|| view! { " " <span class="badge">"this session"</span> })}</td>
                                        <td>{s.user_agent.clone().unwrap_or_else(|| "Unknown".into())}</td>
                                        <td class="mono">{s.ip_address.clone().unwrap_or_default()}</td>
                                        <td class="num">{fmt_datetime(&s.created_at)}</td>
                                        <td class="num">{fmt_ago(&s.last_activity)}</td>
                                        <td class="r">{if s.current {
                                            view! { <span class="dim">"current"</span> }.into_any()
                                        } else {
                                            view! { <ConfirmButton label="Revoke" on_confirm=Callback::new(move |_| revoke(id.clone())) /> }.into_any()
                                        }}</td>
                                    </tr>
                                }
                            }
                        } />
                    </tbody>
                </table>
                <Show when=move || sessions.read().is_empty()><div class="empty"><b>"No sessions"</b></div></Show>
            </div>
        </div>
        <div class="card">
            <div class="card-h"><h3>"API tokens"</h3><span class="sub">"All users"</span></div>
            <div class="tbl-wrap">
                <table class="tbl">
                    <thead><tr><th>"Name"</th><th>"Owner"</th><th>"Scopes"</th><th>"Last used"</th><th>"Expires"</th><th></th></tr></thead>
                    <tbody>
                        <For each=move || tokens.get() key=|t| format!("{}{}", t.id, t.revoked) children={
                            let revoke = revoke_token.clone();
                            move |t| {
                                let id = t.id.clone();
                                let revoke = revoke.clone();
                                view! {
                                    <tr>
                                        <td>{t.name.clone()}</td>
                                        <td>{t.created_by_name.clone()}</td>
                                        <td style="white-space:normal;min-width:200px">{scope_tags(&t.scopes)}</td>
                                        <td class="num">{t.last_used_at.as_deref().map(fmt_ago).unwrap_or_else(|| "never".into())}</td>
                                        <td class="num">{t.expires_at.as_deref().map(fmt_datetime).unwrap_or_else(|| "never".into())}</td>
                                        <td class="r">{if t.revoked {
                                            view! { <span class="dim">"revoked"</span> }.into_any()
                                        } else {
                                            view! { <ConfirmButton label="Revoke" confirm_label="Confirm revoke" on_confirm=Callback::new(move |_| revoke(id.clone())) /> }.into_any()
                                        }}</td>
                                    </tr>
                                }
                            }
                        } />
                    </tbody>
                </table>
                <Show when=move || tokens.read().is_empty()><div class="empty"><b>"No tokens"</b></div></Show>
            </div>
        </div>
    }
}

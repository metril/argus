//! Settings page

use leptos::prelude::*;

use crate::api::auth::SessionInfo;
use crate::api::ApiClient;
use crate::components::{Card, Layout};
use crate::state::{use_app_state, use_auth_state};

/// Settings page component
#[component]
pub fn SettingsPage() -> impl IntoView {
    let app_state = use_app_state();
    let auth_state = use_auth_state();

    let sessions = RwSignal::new(Vec::<SessionInfo>::new());
    let loading_sessions = RwSignal::new(true);

    let user = auth_state.user;
    let theme = app_state.theme;

    // Action signal for session revocation
    let revoke_id = RwSignal::new(Option::<String>::None);

    // Load sessions
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let client = ApiClient::new();

                match client.list_sessions().await {
                    Ok(response) => {
                        sessions.set(response.sessions);
                    }
                    Err(e) => {
                        app_state.error(format!("Failed to load sessions: {}", e));
                    }
                }

                loading_sessions.set(false);
            });
        });
    }

    // Revoke session effect
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            if let Some(session_id) = revoke_id.get() {
                let app_state = app_state.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let client = ApiClient::new();

                    match client.revoke_session(&session_id).await {
                        Ok(_) => {
                            sessions.update(|s| s.retain(|sess| sess.id != session_id));
                            app_state.success("Session revoked");
                        }
                        Err(e) => {
                            app_state.error(format!("Failed to revoke: {}", e));
                        }
                    }
                    revoke_id.set(None);
                });
            }
        });
    }

    view! {
        <Layout>
            <div class="page-header">
                <h1 class="page-title">"Settings"</h1>
            </div>

            <div class="settings-grid">
                <Card title="Account" class="settings-card">
                    {move || user.get().map(|u| view! {
                        <div class="account-info">
                            <div class="info-row">
                                <span class="info-label">"Username"</span>
                                <span class="info-value">{u.username}</span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">"Role"</span>
                                <span class="info-value">{format!("{:?}", u.role)}</span>
                            </div>
                        </div>
                    })}
                </Card>

                <Card title="Appearance" class="settings-card">
                    <div class="theme-toggle">
                        <span class="theme-label">"Theme"</span>
                        <button
                            class="btn btn-secondary"
                            on:click=move |_| app_state.toggle_theme()
                        >
                            {move || if theme.get() == crate::state::Theme::Dark {
                                "Light Mode"
                            } else {
                                "Dark Mode"
                            }}
                        </button>
                    </div>
                </Card>

                <Card title="Sessions" class="settings-card">
                    <Show when=move || !loading_sessions.get() fallback=|| view! {
                        <div class="loading">"Loading..."</div>
                    }>
                        <For
                            each=move || sessions.get()
                            key=|session| session.id.clone()
                            children=move |session| {
                                let session_id = session.id.clone();
                                let user_agent = session.user_agent.clone().unwrap_or_else(|| "Unknown".to_string());

                                view! {
                                    <div class="session-item">
                                        <div class="session-info">
                                            <div class="session-details">
                                                {user_agent}
                                            </div>
                                        </div>
                                        <button
                                            class="btn btn-danger"
                                            on:click=move |_| revoke_id.set(Some(session_id.clone()))
                                        >
                                            "Revoke"
                                        </button>
                                    </div>
                                }
                            }
                        />

                        <Show when=move || sessions.get().is_empty()>
                            <p class="no-sessions">"No sessions"</p>
                        </Show>
                    </Show>
                </Card>
            </div>
        </Layout>
    }
}

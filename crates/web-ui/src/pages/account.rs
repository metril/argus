//! Account page: who you are, CA certificate, your sessions

use leptos::prelude::*;

use crate::api::auth::SessionInfo;
use crate::api::ApiClient;
use crate::components::{Card, Layout};
use crate::state::{use_app_state, use_auth_state};
use crate::utils::api_base_url;

/// Account page component
#[component]
pub fn AccountPage() -> impl IntoView {
    let app_state = use_app_state();
    let auth_state = use_auth_state();

    let sessions = RwSignal::new(Vec::<SessionInfo>::new());
    let loading_sessions = RwSignal::new(true);

    let user = auth_state.user;

    // Public URL of the root CA certificate (same origin as the API).
    let ca_url = format!("{}/api/v1/ca.crt", api_base_url());

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
                        sessions.set(response.items);
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
                <h1 class="page-title">"Account"</h1>
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

                <Card title="CA Certificate" class="settings-card">
                    <p class="form-help">
                        "Install this root certificate on each device, then point that device's "
                        "HTTP and HTTPS proxy at this server on port 8080. Without it, MITM'd "
                        "HTTPS pages will fail to load."
                    </p>
                    <div class="modal-actions">
                        <a class="btn btn-primary" href=ca_url.clone() download="argus-ca.crt">
                            "Download CA Certificate"
                        </a>
                    </div>
                    <p class="form-help">
                        "Or fetch it directly from any device at: "
                        <code>{ca_url.clone()}</code>
                    </p>
                    <p class="form-help">
                        "macOS: open the downloaded file, add it to the System keychain in "
                        "Keychain Access, then double-click it, expand \"Trust\", and set "
                        "\"When using this certificate\" to \"Always Trust\". See "
                        "docs/CA-INSTALLATION.md for Windows, Linux, iOS, Android and browsers."
                    </p>
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

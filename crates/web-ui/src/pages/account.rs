//! Account page: who you are, CA certificate, your sessions

use leptos::prelude::*;

use crate::api::auth::SessionInfo;
use crate::api::ApiClient;
use crate::components::{Card, ConfirmButton, Layout};
use crate::state::{use_app_state, use_auth_state};
use crate::utils::{api_base_url, get_origin, ua_label};

/// Account page component
#[component]
pub fn AccountPage() -> impl IntoView {
    let app_state = use_app_state();
    let auth_state = use_auth_state();

    let sessions = RwSignal::new(Vec::<SessionInfo>::new());
    let loading_sessions = RwSignal::new(true);

    let user = auth_state.user;

    // Explicit proxy port from the live config (None until loaded, or when unreadable).
    let proxy_port = RwSignal::new(Option::<u16>::None);
    wasm_bindgen_futures::spawn_local(async move {
        if let Ok(c) = ApiClient::new().get_proxy_config().await {
            proxy_port.set(Some(c.port));
        }
    });

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
                        "HTTP and HTTPS proxy at this server"
                        {move || match proxy_port.get() {
                            Some(p) => format!(" on port {p}"),
                            None => " (see the Proxy page for the port)".to_string(),
                        }}
                        ". Without it, MITM'd HTTPS pages will fail to load."
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

                <ExtensionCard />

                <Card title="Sessions" class="settings-card">
                    <Show when=move || !loading_sessions.get() fallback=|| view! {
                        <div class="loading">"Loading..."</div>
                    }>
                        <For
                            each=move || sessions.get()
                            key=|session| session.id.clone()
                            children=move |session| {
                                let session_id = session.id.clone();
                                let full_ua = session.user_agent.clone().unwrap_or_default();
                                let user_agent = session.user_agent.as_deref().map(ua_label).unwrap_or_else(|| "Unknown".to_string());
                                let current = session.current;

                                view! {
                                    <div class="session-item">
                                        <div class="session-info">
                                            <div class="session-details">
                                                <span class="ua" title=full_ua>{user_agent}</span>
                                                {current.then(|| view! { " " <span class="badge">"this session"</span> })}
                                            </div>
                                        </div>
                                        <ConfirmButton
                                            label="Revoke"
                                            on_confirm=Callback::new(move |()| revoke_id.set(Some(session_id.clone())))
                                        />
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

/// Fetch an extension build (cookie session, with a refresh on `401`) and hand it to the
/// browser as a file. A 404 means no release asset is published for this version.
async fn download_extension(browser: &'static str) -> Result<(), String> {
    use wasm_bindgen::JsCast;
    let path = format!("/downloads/extension/{browser}");
    let (bytes, name) = ApiClient::new()
        .get_bytes(&path)
        .await
        .map_err(|e| match e {
            crate::api::ApiError::NotFound(_) => {
                format!("No {browser} extension is published for this version of Argus yet.")
            }
            crate::api::ApiError::Network(m) | crate::api::ApiError::Server(m) => {
                format!("Could not download the extension: {m}")
            }
            e => e.to_string(),
        })?;
    let name = name.unwrap_or_else(|| format!("argus-extension-{browser}.zip"));
    let err = |e: wasm_bindgen::JsValue| format!("{e:?}");
    let arr = js_sys::Uint8Array::from(bytes.as_slice());
    let parts = js_sys::Array::new();
    parts.push(&arr);
    let blob = web_sys::Blob::new_with_u8_array_sequence(&parts).map_err(err)?;
    let obj = web_sys::Url::create_object_url_with_blob(&blob).map_err(err)?;
    let a: web_sys::HtmlAnchorElement = web_sys::window()
        .and_then(|w| w.document())
        .ok_or("no document")?
        .create_element("a")
        .map_err(err)?
        .dyn_into()
        .map_err(|_| "anchor")?;
    a.set_href(&obj);
    a.set_download(&name);
    a.click();
    // Not revoked at once: some browsers start the save after the click returns.
    gloo_timers::callback::Timeout::new(30_000, move || {
        let _ = web_sys::Url::revoke_object_url(&obj);
    })
    .forget();
    Ok(())
}

/// Browser extension downloads and install steps.
#[component]
fn ExtensionCard() -> impl IntoView {
    let msg = RwSignal::new(Option::<String>::None);
    let busy = RwSignal::new(false);
    let origin = get_origin();
    let user = use_auth_state().user;
    // Creating a token needs `tokens:self`, and the token itself needs `logs:read`.
    let can_token = Signal::derive(move || {
        user.get()
            .map(|u| {
                ["logs:read", "tokens:self"]
                    .iter()
                    .all(|n| u.scopes.iter().any(|s| s.as_str() == *n))
            })
            .unwrap_or(false)
    });
    let get = move |browser: &'static str| {
        busy.set(true);
        msg.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = download_extension(browser).await {
                msg.set(Some(e));
            }
            busy.set(false);
        });
    };
    view! {
        <Card title="Browser extension" class="settings-card">
            <p class="form-help">
                "Shows what each page blocked, from the browser toolbar."
            </p>
            <div class="modal-actions">
                <button class="btn btn-primary" disabled=move || busy.get() on:click=move |_| get("chrome")>
                    "Download for Chrome"
                </button>
                <button class="btn btn-primary" disabled=move || busy.get() on:click=move |_| get("firefox")>
                    "Download for Firefox"
                </button>
            </div>
            {move || msg.get().map(|m| view! { <p class="form-help" role="alert" style="color:var(--danger, #c0392b)">{m}</p> })}
            <p class="form-help">
                <strong>"Chrome: "</strong>
                "unzip the download, open chrome://extensions, turn on Developer mode, choose "
                "\"Load unpacked\" and pick the unzipped folder."
            </p>
            <p class="form-help">
                <strong>"Firefox: "</strong>
                "a signed .xpi installs directly when opened. If you got a .zip, open "
                "about:debugging, choose \"This Firefox\" and \"Load Temporary Add-on\"."
            </p>
            <p class="form-help">
                <strong>"Both: "</strong>
                {move || if can_token.get() {
                    "create an API token with the logs:read scope, then enter it and this Argus URL in the extension: "
                } else {
                    "ask an admin to issue an API token with logs:read, then enter it and this Argus URL in the extension: "
                }}
                <code>{origin}</code>
            </p>
        </Card>
    }
}

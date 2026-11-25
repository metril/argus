//! Browser extension page: download, install steps, the Argus address and your signed-in
//! browsers. Also the dashboard banner that points here until an extension has connected.

use leptos::prelude::*;

use crate::api::tokens::ApiTokenInfo;
use crate::api::ApiClient;
use crate::components::{Card, ConfirmButton, Icon, Layout};
use crate::state::{use_app_state, use_auth_state};
use crate::utils::{copy_text, fmt_ago, get_origin};

/// Name prefix of tokens minted by the extension's sign-in.
pub const EXTENSION_TOKEN_PREFIX: &str = "Extension · ";

const BANNER_KEY: &str = "argus.extensionBannerDismissed";

fn is_extension_token(t: &ApiTokenInfo) -> bool {
    !t.revoked && t.name.starts_with(EXTENSION_TOKEN_PREFIX)
}

/// This user's live extension tokens.
fn extension_tokens(all: Vec<ApiTokenInfo>) -> Vec<ApiTokenInfo> {
    all.into_iter().filter(is_extension_token).collect()
}

/// Whether any extension has used its token yet.
fn extension_connected(all: &[ApiTokenInfo]) -> bool {
    all.iter()
        .any(|t| is_extension_token(t) && t.last_used_at.is_some())
}

/// The browser part of an extension token name ("Chrome" for "Extension · Chrome").
fn browser_of(name: &str) -> &str {
    name.strip_prefix(EXTENSION_TOKEN_PREFIX).unwrap_or(name)
}

/// The extension needs these two scopes; roles without them can't sign in.
fn can_use_extension(user: &Option<api_types::UserInfo>) -> bool {
    user.as_ref().is_some_and(|u| {
        [
            api_types::Scope::LogsRead,
            api_types::Scope::UserscriptsBridge,
        ]
        .iter()
        .all(|s| u.scopes.contains(s))
    })
}

/// Every token of this user, following the paging cursor.
async fn all_tokens() -> Result<Vec<ApiTokenInfo>, crate::api::ApiError> {
    let client = ApiClient::new();
    let (mut out, mut cursor) = (Vec::new(), None::<String>);
    loop {
        let page = client.list_tokens(cursor.as_deref(), false).await?;
        out.extend(page.items);
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => return Ok(out),
        }
    }
}

/// Default extension listener ports to try in order, skipping ports Argus already uses.
fn ext_port_candidates(used: &[u16]) -> Vec<u16> {
    (3130u16..3140).filter(|p| !used.contains(p)).collect()
}

/// Status line of the extension listener.
fn listener_line(port: Option<Option<u16>>) -> String {
    match port {
        None => "Checking…".into(),
        Some(None) => "Off".into(),
        Some(Some(p)) => format!("On, port {p}"),
    }
}

/// Turn the extension listener on at the first free default port, applied live.
async fn enable_listener() -> Result<u16, String> {
    let client = ApiClient::new();
    let cfg = client.get_proxy_config().await.map_err(|e| e.to_string())?;
    let used = [Some(cfg.port), cfg.transparent_port, Some(cfg.webui_port)]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let mut last = String::from("No free port.");
    for port in ext_port_candidates(&used) {
        let req = api_types::UpdateProxyConfigRequest {
            ext_port: Some(port),
            ..Default::default()
        };
        match client.update_proxy_config_full(&req).await {
            Ok(r) if r.config.ext_port == Some(port) => return Ok(port),
            Ok(_) => last = "Argus didn't apply it.".into(),
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
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

#[component]
pub fn ExtensionPage() -> impl IntoView {
    let app_state = use_app_state();
    let user = use_auth_state().user;
    let msg = RwSignal::new(Option::<String>::None);
    let busy = RwSignal::new(false);
    let signed_in = RwSignal::new(Vec::<ApiTokenInfo>::new());
    let reload = RwSignal::new(0u32);
    let origin = get_origin();
    // `None`: not loaded yet; `Some(None)`: no extension listener.
    let listener = RwSignal::new(Option::<Option<u16>>::None);
    let listener_busy = RwSignal::new(false);
    let listener_err = RwSignal::new(Option::<String>::None);
    let can_enable = move || {
        user.get()
            .is_some_and(|u| u.scopes.contains(&api_types::Scope::ConfigWrite))
    };
    Effect::new(move |_| {
        wasm_bindgen_futures::spawn_local(async move {
            if let Ok(c) = ApiClient::new().get_proxy_config().await {
                listener.set(Some(c.ext_port));
            }
        });
    });
    let turn_on = move |_| {
        listener_busy.set(true);
        listener_err.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            match enable_listener().await {
                Ok(p) => listener.set(Some(Some(p))),
                Err(e) => listener_err.set(Some(format!("Couldn't turn it on: {e}"))),
            }
            listener_busy.set(false);
        });
    };

    Effect::new(move |_| {
        reload.track();
        wasm_bindgen_futures::spawn_local(async move {
            if let Ok(all) = all_tokens().await {
                signed_in.set(extension_tokens(all));
            }
        });
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
    let revoke = {
        let app_state = app_state.clone();
        move |id: String| {
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().revoke_token(&id).await {
                    Ok(_) => {
                        app_state.success("Signed out");
                        reload.update(|n| *n += 1);
                    }
                    Err(e) => app_state.error(format!("Failed to sign out: {e}")),
                }
            });
        }
    };
    let copy = {
        let (app_state, origin) = (app_state.clone(), origin.clone());
        move |_| {
            if copy_text(&origin) {
                app_state.success("Address copied");
            }
        }
    };

    view! {
        <Layout>
            <div class="page-header">
                <h1 class="page-title">"Browser extension"</h1>
            </div>
            <Show when=move || !can_use_extension(&user.get())>
                <p class="form-help" role="alert">"Your role can't use the extension. Ask an admin."</p>
            </Show>
            <div class="settings-grid">
                <Card title="Install" sub="Takes a minute" class="settings-card">
                    <ol class="extsteps">
                        <li>
                            <b>"Download"</b>
                            <div class="modal-actions">
                                <button class="btn btn-primary" disabled=move || busy.get() on:click=move |_| get("chrome")>
                                    <Icon name="download" />"Chrome"
                                </button>
                                <button class="btn btn-primary" disabled=move || busy.get() on:click=move |_| get("firefox")>
                                    <Icon name="download" />"Firefox"
                                </button>
                            </div>
                            {move || msg.get().map(|m| view! { <p class="form-help" role="alert" style="color:var(--danger, #c0392b)">{m}</p> })}
                        </li>
                        <li>
                            <b>"Add it"</b>
                            <p class="form-help">
                                <strong>"Chrome: "</strong>
                                "unzip it. Open chrome://extensions and turn on Developer mode. Choose Load unpacked, then the folder."
                            </p>
                            <p class="form-help">
                                <strong>"Firefox: "</strong>
                                "open the .xpi to install it. A .zip loads from about:debugging, under This Firefox."
                            </p>
                        </li>
                        <li>
                            <b>"Open it"</b>
                            <p class="form-help">"Click the Argus icon in the toolbar."</p>
                        </li>
                        <li>
                            <b>"Turn on the extension listener"</b>
                            <p class="form-help" role="status">{move || listener_line(listener.get())}</p>
                            <Show when=move || listener.get() == Some(None)>
                                <Show
                                    when=can_enable
                                    fallback=|| view! { <p class="form-help">"Ask an admin to turn on the extension listener."</p> }
                                >
                                    <button class="btn btn-primary" disabled=move || listener_busy.get() on:click=turn_on>"Turn on"</button>
                                </Show>
                            </Show>
                            {move || listener_err.get().map(|m| view! { <p class="form-help" role="alert" style="color:var(--danger, #c0392b)">{m}</p> })}
                        </li>
                        <li>
                            <b>"Sign in"</b>
                            <p class="form-help">"Use your Argus username and password. Nothing else to set up."</p>
                        </li>
                    </ol>
                </Card>

                <Card title="Argus address" sub="Chrome fills this in. Firefox asks." class="settings-card">
                    <div class="newtoken" style="border-color:var(--line);background:var(--surface-2)">
                        <code>{origin.clone()}</code>
                        <button class="btn sm" type="button" on:click=copy><Icon name="copy" />"Copy"</button>
                    </div>
                </Card>

                <Card title="Signed-in browsers" class="settings-card">
                    <Show
                        when=move || !signed_in.with(|v| v.is_empty())
                        fallback=|| view! { <p class="form-help">"None yet."</p> }
                    >
                        <For
                            each=move || signed_in.get()
                            key=|t| t.id.clone()
                            children={
                                let revoke = revoke.clone();
                                move |t| {
                                    let id = t.id.clone();
                                    let revoke = revoke.clone();
                                    view! {
                                        <div class="session-item">
                                            <div class="session-info">
                                                <div class="session-details">
                                                    <span class="ua">{browser_of(&t.name).to_string()}</span>
                                                    " "
                                                    <span class="dim">
                                                        {t.last_used_at.as_deref().map(|l| format!("used {}", fmt_ago(l))).unwrap_or_else(|| "not used yet".into())}
                                                    </span>
                                                </div>
                                            </div>
                                            <ConfirmButton
                                                label="Sign out"
                                                on_confirm=Callback::new(move |()| revoke(id.clone()))
                                            />
                                        </div>
                                    }
                                }
                            }
                        />
                    </Show>
                </Card>
            </div>
        </Layout>
    }
}

/// Dashboard banner: shown until an extension has signed in and connected, or it is dismissed.
#[component]
pub fn ExtensionBanner() -> impl IntoView {
    use gloo_storage::Storage;
    let user = use_auth_state().user;
    let dismissed =
        RwSignal::new(gloo_storage::LocalStorage::get::<bool>(BANNER_KEY).unwrap_or(false));
    let connected = RwSignal::new(true); // assume yes until the token list says otherwise
    wasm_bindgen_futures::spawn_local(async move {
        if let Ok(all) = all_tokens().await {
            connected.set(extension_connected(&all));
        }
    });
    let show = move || !dismissed.get() && !connected.get() && can_use_extension(&user.get());
    view! {
        <Show when=show>
            <div class="extbanner" role="status">
                <Icon name="download" />
                <b>"Set up the browser extension"</b>
                <a class="btn sm primary" href="/extension">"Set up"</a>
                <button class="btn sm ghost" type="button" aria-label="Dismiss" on:click=move |_| {
                    let _ = gloo_storage::LocalStorage::set(BANNER_KEY, true);
                    dismissed.set(true);
                }>"Dismiss"</button>
            </div>
        </Show>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(name: &str, used: bool, revoked: bool) -> ApiTokenInfo {
        ApiTokenInfo {
            id: name.into(),
            name: name.into(),
            scopes: vec![],
            profiles: None,
            created_by: String::new(),
            created_by_name: String::new(),
            created_at: String::new(),
            expires_at: None,
            last_used_at: used.then(|| "2026-01-01T00:00:00Z".to_string()),
            revoked,
        }
    }

    #[test]
    fn listener_ports_skip_used_ones_and_lines_read_plainly() {
        assert_eq!(ext_port_candidates(&[]).first(), Some(&3130));
        assert_eq!(ext_port_candidates(&[3130, 3131]).first(), Some(&3132));
        assert!(!ext_port_candidates(&[3135]).contains(&3135));
        assert_eq!(listener_line(None), "Checking…");
        assert_eq!(listener_line(Some(None)), "Off");
        assert_eq!(listener_line(Some(Some(3130))), "On, port 3130");
    }

    #[test]
    fn only_live_extension_tokens_count_and_one_use_means_connected() {
        let all = vec![
            tok("Extension · Chrome", false, false),
            tok("Extension · Firefox", true, true),
            tok("ci", true, false),
        ];
        assert_eq!(extension_tokens(all.clone()).len(), 1);
        assert!(!extension_connected(&all));
        let mut all = all;
        all.push(tok("Extension · Edge", true, false));
        assert!(extension_connected(&all));
        assert_eq!(browser_of("Extension · Edge"), "Edge");
    }
}

//! Devices page: addresses and tokens that select a profile. A device token is shown once, in a
//! dialog with a copy button and the proxy URL to configure. Uses only the public
//! `/api/v1/devices` API; every user-supplied name is rendered as text.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

use crate::api::profiles::{
    parse_addresses, proxy_url, CreateDeviceRequest, DeviceDto, ProfileDto, UpdateDeviceRequest,
};
use crate::api::ApiClient;
use crate::components::{Card, Layout, Modal};
use crate::state::use_app_state;

/// Copy `text` with the async clipboard API (best effort; the token is also selectable).
fn copy_to_clipboard(text: &str) {
    use js_sys::{Function, Reflect};
    use wasm_bindgen::JsValue;
    let Some(w) = web_sys::window() else { return };
    let get = |o: &JsValue, k: &str| Reflect::get(o, &JsValue::from_str(k)).ok();
    let Some(nav) = get(w.as_ref(), "navigator") else {
        return;
    };
    let Some(clip) = get(&nav, "clipboard") else {
        return;
    };
    if let Some(f) = get(&clip, "writeText").and_then(|f| f.dyn_into::<Function>().ok()) {
        let _ = f.call1(&clip, &JsValue::from_str(text));
    }
}

fn token_state(d: &DeviceDto) -> String {
    match (&d.has_token, &d.token_hint) {
        (true, Some(h)) => format!("active (ends in {h})"),
        (true, None) => "active".to_string(),
        _ => "none".to_string(),
    }
}

/// Devices page
#[component]
pub fn DevicesPage() -> impl IntoView {
    let app = StoredValue::new(use_app_state());
    let devices = RwSignal::new(Vec::<DeviceDto>::new());
    let profiles = RwSignal::new(Vec::<ProfileDto>::new());
    let reload = RwSignal::new(0u32);
    let busy = RwSignal::new(false);
    let proxy_port = RwSignal::new(Option::<u16>::None);

    // Create / edit dialog
    let show_edit = RwSignal::new(false);
    let edit_id = RwSignal::new(Option::<String>::None);
    let name = RwSignal::new(String::new());
    let profile_id = RwSignal::new("0".to_string());
    let addresses = RwSignal::new(String::new());

    // One-time token dialog: (device name, raw token)
    let show_token = RwSignal::new(false);
    let token = RwSignal::new(Option::<(String, String)>::None);

    Effect::new(move || {
        reload.track();
        wasm_bindgen_futures::spawn_local(async move {
            let client = ApiClient::new();
            match client.list_devices().await {
                Ok(d) => devices.set(d),
                Err(e) => app
                    .get_value()
                    .error(format!("Failed to load devices: {e}")),
            }
            if let Ok(p) = client.list_profiles().await {
                profiles.set(p);
            }
            if let Ok(c) = client.get_proxy_config().await {
                proxy_port.set(Some(c.port));
            }
        });
    });

    let profile_name = move |id: &str| {
        profiles
            .get()
            .into_iter()
            .find(|p| p.id == id)
            .map(|p| p.name)
            .unwrap_or_else(|| format!("#{id}"))
    };

    let open_create = move |_| {
        edit_id.set(None);
        name.set(String::new());
        profile_id.set(
            profiles
                .get_untracked()
                .first()
                .map(|p| p.id.clone())
                .unwrap_or_else(|| "0".into()),
        );
        addresses.set(String::new());
        show_edit.set(true);
    };
    let open_edit = move |d: DeviceDto| {
        edit_id.set(Some(d.id.clone()));
        name.set(d.name.clone());
        profile_id.set(d.profile_id.clone());
        addresses.set(d.ips.join("\n"));
        show_edit.set(true);
    };

    let save = move |_| {
        let (n, p, ips) = (
            name.get_untracked(),
            profile_id.get_untracked(),
            parse_addresses(&addresses.get_untracked()),
        );
        if n.trim().is_empty() {
            app.get_value().error("Give the device a name");
            return;
        }
        let id = edit_id.get_untracked();
        busy.set(true);
        wasm_bindgen_futures::spawn_local(async move {
            let client = ApiClient::new();
            let res = match &id {
                Some(id) => client
                    .update_device(
                        id,
                        &UpdateDeviceRequest {
                            name: Some(n),
                            profile_id: Some(p),
                            ips: Some(ips),
                        },
                    )
                    .await
                    .map(|_| "Device saved"),
                None => client
                    .create_device(&CreateDeviceRequest {
                        name: n,
                        profile_id: p,
                        ips,
                    })
                    .await
                    .map(|_| "Device created"),
            };
            busy.set(false);
            match res {
                Ok(msg) => {
                    app.get_value().success(msg);
                    show_edit.set(false);
                    reload.update(|n| *n += 1);
                }
                Err(e) => app.get_value().error(format!("Failed to save device: {e}")),
            }
        });
    };

    let delete = move |d: DeviceDto| {
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().delete_device(&d.id).await {
                Ok(_) => {
                    app.get_value().success("Device deleted");
                    reload.update(|n| *n += 1);
                }
                Err(e) => app.get_value().error(format!("Failed to delete: {e}")),
            }
        });
    };

    let issue = move |d: DeviceDto| {
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().issue_device_token(&d.id).await {
                Ok(t) => {
                    token.set(Some((d.name.clone(), t.token)));
                    show_token.set(true);
                    reload.update(|n| *n += 1);
                }
                Err(e) => app.get_value().error(format!("Failed to issue token: {e}")),
            }
        });
    };

    let revoke = move |d: DeviceDto| {
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().revoke_device_token(&d.id).await {
                Ok(_) => {
                    app.get_value().success("Token revoked");
                    reload.update(|n| *n += 1);
                }
                Err(e) => app.get_value().error(format!("Failed to revoke: {e}")),
            }
        });
    };

    let host = || {
        web_sys::window()
            .and_then(|w| w.location().hostname().ok())
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "<proxy-host>".to_string())
    };
    let full_url = move || {
        token.get().map(|(_, t)| match proxy_port.get() {
            Some(port) => proxy_url(&t, &host(), port),
            None => format!("http://device:{t}@{}:<port>", host()),
        })
    };

    view! {
        <Layout>
            <div class="page-header">
                <h1 class="page-title">"Devices"</h1>
                <button class="btn btn-primary" on:click=open_create>"New device"</button>
            </div>
            <p class="modal-help">
                "A device selects a profile by its address (or a CIDR prefix such as 192.168.1.0/24) \
                 or by a token used as the proxy password. Without a match, the default profile applies."
            </p>
            <Card title="Devices" class="settings-card">
                <Show
                    when=move || !devices.get().is_empty()
                    fallback=|| view! { <p class="no-sessions">"No devices yet"</p> }
                >
                    <table class="table">
                        <thead>
                            <tr>
                                <th>"Name"</th>
                                <th>"Profile"</th>
                                <th>"Addresses"</th>
                                <th>"Token"</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            <For
                                each=move || devices.get()
                                key=|d| format!("{}/{}/{}/{}/{:?}", d.id, d.name, d.profile_id, d.ips.join(","), d.token_hint)
                                children=move |d| {
                                    let (de, di, dr, dd) = (d.clone(), d.clone(), d.clone(), d.clone());
                                    let has_token = d.has_token;
                                    let pid = d.profile_id.clone();
                                    view! {
                                        <tr>
                                            <td>{d.name.clone()}</td>
                                            <td>{move || profile_name(&pid)}</td>
                                            <td>{if d.ips.is_empty() { "-".to_string() } else { d.ips.join(", ") }}</td>
                                            <td>{token_state(&d)}</td>
                                            <td>
                                                <button class="btn btn-secondary"
                                                    on:click=move |_| open_edit(de.clone())>"Edit"</button>
                                                <button class="btn btn-secondary"
                                                    on:click=move |_| issue(di.clone())>
                                                    {if has_token { "Reissue token" } else { "Issue token" }}
                                                </button>
                                                {has_token.then(|| view! {
                                                    <button class="btn btn-secondary"
                                                        on:click=move |_| revoke(dr.clone())>"Revoke token"</button>
                                                })}
                                                <button class="btn btn-danger"
                                                    on:click=move |_| delete(dd.clone())>"Delete"</button>
                                            </td>
                                        </tr>
                                    }
                                }
                            />
                        </tbody>
                    </table>
                </Show>
            </Card>

            <Modal title="Device" open=show_edit>
                <div class="form-group">
                    <label>"Name"</label>
                    <input class="form-input" type="text" maxlength="64"
                        prop:value=move || name.get()
                        on:input=move |ev| name.set(event_target_value(&ev)) />
                </div>
                <div class="form-group">
                    <label>"Profile"</label>
                    <select class="form-input"
                        prop:value=move || profile_id.get()
                        on:change=move |ev| profile_id.set(event_target_value(&ev))>
                        {move || profiles.get().into_iter().map(|p| {
                            let id = p.id.clone();
                            view! {
                                <option value=p.id.clone() selected=move || profile_id.get() == id>
                                    {p.name.clone()}
                                </option>
                            }
                        }).collect_view()}
                    </select>
                </div>
                <div class="form-group">
                    <label>"Addresses"</label>
                    <textarea class="form-input" rows="4" spellcheck="false"
                        placeholder="192.168.1.20&#10;192.168.2.0/24"
                        prop:value=move || addresses.get()
                        on:input=move |ev| addresses.set(event_target_value(&ev))></textarea>
                    <p class="form-help">
                        "One address or CIDR prefix per line. Leave empty for a token-only device."
                    </p>
                </div>
                <div class="modal-actions">
                    <button class="btn btn-secondary" on:click=move |_| show_edit.set(false)>"Cancel"</button>
                    <button class="btn btn-primary" disabled=move || busy.get() on:click=save>"Save"</button>
                </div>
            </Modal>

            <Modal title="Device token" open=show_token
                on_close=Callback::new(move |_| token.set(None))>
                <div class="us-danger">
                    "Copy this token now. It will not be shown again; if you lose it, issue a new one."
                </div>
                <p>"Device: "<strong>{move || token.get().map(|(n, _)| n).unwrap_or_default()}</strong></p>
                <div class="form-group">
                    <label>"Token"</label>
                    <input class="form-input" type="text" readonly
                        prop:value=move || token.get().map(|(_, t)| t).unwrap_or_default() />
                    <button class="btn btn-secondary"
                        on:click=move |_| if let Some((_, t)) = token.get_untracked() { copy_to_clipboard(&t) }>
                        "Copy token"
                    </button>
                </div>
                <div class="form-group">
                    <label>"Proxy URL for this device"</label>
                    <input class="form-input" type="text" readonly
                        prop:value=move || full_url().unwrap_or_default() />
                    <button class="btn btn-secondary"
                        on:click=move |_| if let Some(u) = full_url() { copy_to_clipboard(&u) }>
                        "Copy URL"
                    </button>
                    <p class="form-help">
                        "Form: http://device:<token>@<proxy-host>:<port>. The user name is \"device\"; \
                         the token is the password."
                    </p>
                </div>
                <div class="modal-actions">
                    <button class="btn btn-primary" on:click=move |_| {
                        show_token.set(false);
                        token.set(None);
                    }>"I have copied it"</button>
                </div>
            </Modal>
        </Layout>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(has: bool, hint: Option<&str>) -> DeviceDto {
        DeviceDto {
            id: "1".into(),
            name: "<b>x</b>".into(),
            profile_id: "0".into(),
            ips: vec![],
            has_token: has,
            token_hint: hint.map(str::to_string),
            last_seen: None,
            created_at: String::new(),
        }
    }

    #[test]
    fn token_state_shows_hint_only() {
        assert_eq!(token_state(&dev(false, None)), "none");
        assert_eq!(
            token_state(&dev(true, Some("ab12"))),
            "active (ends in ab12)"
        );
    }
}

//! Devices page: addresses and tokens that select a profile. A device token is shown once, in a
//! dialog with a copy button and the proxy URL to configure. Uses only the public
//! `/api/v1/devices` API; every user-supplied name is rendered as text.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

use super::vlist::*;
use crate::api::profiles::{
    parse_addresses, proxy_url, CreateDeviceRequest, DeviceDto, ProfileDto, UpdateDeviceRequest,
};
use crate::api::ApiClient;
use crate::components::{ConfirmButton, Drawer, Icon, Layout};
use crate::state::use_app_state;
use gloo_timers::callback::Timeout;
use std::rc::Rc;

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
    let counts = RwSignal::new(Option::<api_types::DeviceCounts>::None);
    let q = RwSignal::new(query_get("dq").unwrap_or_default()); // debounced
    let prof = RwSignal::new(query_get("dp").unwrap_or_default());
    let sort = RwSignal::new(query_get("ds").unwrap_or_else(|| "name".into()));
    let anchor0 = query_get("da");
    let debounce = StoredValue::new_local(None::<Timeout>);
    let anchor_t = StoredValue::new_local(None::<Timeout>);
    let dead = RwSignal::new(Vec::<char>::new());
    let row_h = Signal::derive(move || if is_narrow() { 120.0 } else { 56.0 });
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

    let fetch: Fetcher<DeviceDto> = Rc::new(move |cursor, from| {
        let (qv, p, so) = (
            q.get_untracked(),
            prof.get_untracked(),
            sort.get_untracked(),
        );
        Box::pin(async move {
            match ApiClient::new()
                .list_devices_paged(&qv, &p, &so, cursor.as_deref(), from.as_deref(), 40)
                .await
            {
                Ok(r) => {
                    dead.set(dead_letters(&r.counts.letters));
                    counts.set(Some(r.counts));
                    Ok((r.items, r.next_cursor, r.total))
                }
                Err(e) => {
                    app.get_value()
                        .error(format!("Failed to load devices: {e}"));
                    Err(e)
                }
            }
        })
    });
    let feed = Feed::new(fetch);
    let first = StoredValue::new_local(true);
    Effect::new(move |_| {
        reload.track();
        q.track();
        prof.track();
        sort.track();
        let from = if first.get_value() {
            first.set_value(false);
            if sort.get_untracked() == "name" {
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
        let so = sort.get();
        query_set(&[
            ("dq", Some(q.get())),
            ("dp", Some(prof.get())),
            ("ds", (so != "name").then_some(so)),
            ("da", None),
        ]);
    });
    let on_anchor = Callback::new(move |i: usize| {
        if sort.get_untracked() != "name" {
            return;
        }
        let label = feed
            .items
            .with_untracked(|v: &Vec<DeviceDto>| v.get(i).map(|r| r.name.clone()));
        anchor_t.set_value(Some(Timeout::new(250, move || query_set(&[("da", label)]))));
    });
    Effect::new(move |_| {
        reload.track();
        wasm_bindgen_futures::spawn_local(async move {
            let client = ApiClient::new();
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
                    if id.is_some() {
                        feed.refresh_loaded();
                    } else {
                        reload.update(|n| *n += 1);
                    }
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
                    feed.items
                        .update(|v: &mut Vec<DeviceDto>| v.retain(|x| x.id != d.id));
                    feed.total.update(|t| *t = t.saturating_sub(1));
                    counts.update(|c| {
                        if let Some(c) = c {
                            c.all = c.all.saturating_sub(1);
                        }
                    });
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
                    feed.refresh_loaded();
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
                    feed.refresh_loaded();
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

    Effect::new(move |_| {
        if !show_token.get() {
            token.set(None);
        }
    });

    view! {
        <Layout>
            <div class="page-header">
                <h1 class="page-title">"Devices"</h1>
                <button class="btn primary" on:click=open_create>"New device"</button>
            </div>
            <p class="hint">
                "A device selects a profile by its address (or a CIDR prefix such as 192.168.1.0/24) \
                 or by a token used as the proxy password. Without a match, the default profile applies."
            </p>
            <div class="card">
                <div class="card-h">
                    <h3>"Devices"</h3>
                    <span class="sub">{move || format!("{} devices", counts.get().map(|c| c.all).unwrap_or(0))}</span>
                </div>
                <div class="card-b sitebar">
                    <div class="toolbar">
                        <div class="search grow">
                            <Icon name="search" />
                            <label class="sr" for="devQ">"Search devices"</label>
                            <input id="devQ" class="input mono" placeholder="Search by name or address" autocomplete="off"
                                value=q.get_untracked()
                                on:input=move |ev| {
                                    let v = event_target_value(&ev);
                                    debounce.set_value(Some(Timeout::new(150, move || q.set(v))));
                                } />
                        </div>
                        <select class="select" aria-label="Filter by profile" prop:value=move || prof.get()
                            on:change=move |ev| prof.set(event_target_value(&ev))>
                            <option value="">{move || format!("All profiles ({})", counts.get().map(|c| c.all).unwrap_or(0))}</option>
                            {move || profiles.get().into_iter().map(|p| {
                                let n = counts.get().and_then(|c| c.by_profile.get(&p.id).copied()).unwrap_or(0);
                                view! { <option value=p.id.clone()>{format!("{} ({n})", p.name)}</option> }
                            }).collect_view()}
                        </select>
                        <select class="select" aria-label="Sort" prop:value=move || sort.get()
                            on:change=move |ev| sort.set(event_target_value(&ev))>
                            <option value="name">"Name"</option>
                            <option value="last_seen">"Last seen"</option>
                        </select>
                    </div>
                </div>
                <Show
                    when=move || !feed.items.with(|v| v.is_empty())
                    fallback=move || view! {
                        <div class="empty">
                            <b>{move || if feed.loading.get() { "Loading..." } else { "No devices match" }}</b>
                        </div>
                    }
                >
                    <div class="vwrap">
                        <VList
                            items=feed.items
                            row_h=row_h
                            key=|d: &DeviceDto| format!("{}/{}/{}/{}/{:?}/{:?}", d.id, d.name, d.profile_id, d.ips.join(","), d.token_hint, d.last_seen)
                            render=Callback::new(move |d: DeviceDto| {
                                let (de, di, dr, dd) = (d.clone(), d.clone(), d.clone(), d.clone());
                                let has_token = d.has_token;
                                let pid = d.profile_id.clone();
                                view! {
                                    <div class="devrow">
                                        <div class="h">
                                            <b>{d.name.clone()}</b>
                                            <small>{move || profile_name(&pid)}" \u{b7} "{if d.ips.is_empty() { "-".to_string() } else { d.ips.join(", ") }}</small>
                                        </div>
                                        <span class="dim">{token_state(&d)}</span>
                                        <span class="dim">{d.last_seen.clone().unwrap_or_else(|| "never".to_string())}</span>
                                        <div class="row-gap" style="justify-content:flex-end">
                                            <button class="btn sm" on:click=move |_| open_edit(de.clone())>"Edit"</button>
                                            <button class="btn sm" on:click=move |_| issue(di.clone())>
                                                {if has_token { "Reissue token" } else { "Issue token" }}
                                            </button>
                                            {has_token.then(|| view! {
                                                <ConfirmButton label="Revoke token" confirm_label="Revoke?"
                                                    on_confirm=Callback::new(move |()| revoke(dr.clone())) />
                                            })}
                                            <ConfirmButton label="Delete" confirm_label="Delete?"
                                                on_confirm=Callback::new(move |()| delete(dd.clone())) />
                                        </div>
                                    </div>
                                }.into_any()
                            })
                            on_end=Callback::new(move |()| feed.more())
                            on_anchor=on_anchor
                            reset=feed.tok
                            label="Devices"
                        />
                        <nav class="azrail" aria-label="Jump to letter" hidden=move || !(sort.get() == "name" && feed.total.get() > 12)>
                            {LETTERS.iter().map(|&l| view! {
                                <button type="button" disabled=move || dead.get().contains(&l)
                                    on:click=move |_| feed.reload(
                                        Some(l.to_string()), true,
                                        Some(Callback::new(move |n: usize| {
                                            if n == 0 {
                                                dead.update(|d| d.push(l));
                                                app.get_value().info(format!("No devices starting with {}", l.to_ascii_uppercase()));
                                            }
                                        })),
                                    )>{l.to_ascii_uppercase().to_string()}</button>
                            }).collect_view()}
                        </nav>
                    </div>
                </Show>
                <div class="vfoot" aria-live="polite">
                    <span>{move || {
                        let n = feed.total.get();
                        if !q.get().is_empty() || !prof.get().is_empty() { format!("{n} matches") } else { format!("{n} devices") }
                    }}</span>
                    <span>{move || {
                        let n = feed.items.with(|v| v.len());
                        if feed.next.get().is_some() { format!("showing 1-{n} \u{b7} scroll for more") } else { "end of list".to_string() }
                    }}</span>
                </div>
            </div>

            <Drawer title="Device" open=show_edit>
                <div class="field">
                    <label>"Name"</label>
                    <input class="input" type="text" maxlength="64"
                        prop:value=move || name.get()
                        on:input=move |ev| name.set(event_target_value(&ev)) />
                </div>
                <div class="field">
                    <label>"Profile"</label>
                    <select class="input"
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
                <div class="field">
                    <label>"Addresses"</label>
                    <textarea class="input" rows="4" spellcheck="false"
                        placeholder="192.168.1.20&#10;192.168.2.0/24"
                        prop:value=move || addresses.get()
                        on:input=move |ev| addresses.set(event_target_value(&ev))></textarea>
                    <p class="hint">
                        "One address or CIDR prefix per line. Leave empty for a token-only device."
                    </p>
                </div>
                <div class="row-gap">
                    <button class="btn" on:click=move |_| show_edit.set(false)>"Cancel"</button>
                    <button class="btn primary" disabled=move || busy.get() on:click=save>"Save"</button>
                </div>
            </Drawer>

            <Drawer title="Device token" open=show_token>
                <div class="us-danger">
                    "Copy this token now. It will not be shown again; if you lose it, issue a new one."
                </div>
                <p>"Device: "<strong>{move || token.get().map(|(n, _)| n).unwrap_or_default()}</strong></p>
                <div class="field">
                    <label>"Token"</label>
                    <input class="input" type="text" readonly
                        prop:value=move || token.get().map(|(_, t)| t).unwrap_or_default() />
                    <button class="btn"
                        on:click=move |_| if let Some((_, t)) = token.get_untracked() { copy_to_clipboard(&t) }>
                        "Copy token"
                    </button>
                </div>
                <div class="field">
                    <label>"Proxy URL for this device"</label>
                    <input class="input" type="text" readonly
                        prop:value=move || full_url().unwrap_or_default() />
                    <button class="btn"
                        on:click=move |_| if let Some(u) = full_url() { copy_to_clipboard(&u) }>
                        "Copy URL"
                    </button>
                    <p class="hint">
                        "Form: http://device:<token>@<proxy-host>:<port>. The user name is \"device\"; \
                         the token is the password."
                    </p>
                </div>
                <div class="row-gap">
                    <button class="btn primary" on:click=move |_| {
                        show_token.set(false);
                        token.set(None);
                    }>"I have copied it"</button>
                </div>
            </Drawer>
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

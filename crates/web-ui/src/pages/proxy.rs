//! Proxy configuration page

use leptos::prelude::*;
use web_sys::HtmlInputElement;

use crate::api::proxy::UpdateProxyConfigRequest;
use crate::api::ApiClient;
use crate::components::{Card, Layout};
use crate::state::use_app_state;

/// Proxy configuration page
#[component]
pub fn ProxyPage() -> impl IntoView {
    let app_state = use_app_state();

    // Form state
    let port = RwSignal::new(String::new());
    let host = RwSignal::new(String::new());
    let connection_timeout = RwSignal::new(String::new());
    let request_timeout = RwSignal::new(String::new());
    let max_connections = RwSignal::new(String::new());
    let enable_mitm = RwSignal::new(false);
    let enable_http2 = RwSignal::new(false);
    let enable_websockets = RwSignal::new(false);
    let enable_adblock = RwSignal::new(false);

    let loading = RwSignal::new(true);
    let saving = RwSignal::new(false);
    let do_save = RwSignal::new(false);

    // Stats
    let connections_total = RwSignal::new(0u64);
    let connections_active = RwSignal::new(0u64);
    let requests_total = RwSignal::new(0u64);
    let bytes_received = RwSignal::new(0u64);
    let bytes_sent = RwSignal::new(0u64);

    // Load config
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let client = ApiClient::new();

                match client.get_proxy_config().await {
                    Ok(response) => {
                        // Response is flat, access fields directly
                        port.set(response.port.to_string());
                        host.set(response.host);
                        connection_timeout.set(response.connection_timeout_secs.to_string());
                        request_timeout.set(response.request_timeout_secs.to_string());
                        max_connections.set(response.max_connections.to_string());
                        enable_mitm.set(response.enable_mitm);
                        enable_http2.set(response.enable_http2);
                        enable_websockets.set(response.enable_websockets);
                        enable_adblock.set(response.enable_adblock);
                    }
                    Err(e) => {
                        app_state.error(format!("Failed to load config: {}", e));
                    }
                }

                if let Ok(response) = client.get_proxy_stats().await {
                    connections_total.set(response.connections.total);
                    connections_active.set(response.connections.active);
                    requests_total.set(response.requests.total);
                    bytes_received.set(response.requests.bytes_received);
                    bytes_sent.set(response.requests.bytes_sent);
                }

                loading.set(false);
            });
        });
    }

    // Save config effect
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            if do_save.get() {
                saving.set(true);
                let app_state = app_state.clone();

                let config = UpdateProxyConfigRequest {
                    port: Some(port.get().parse().unwrap_or(8080)),
                    host: Some(host.get()),
                    connection_timeout_secs: Some(connection_timeout.get().parse().unwrap_or(30)),
                    request_timeout_secs: Some(request_timeout.get().parse().unwrap_or(60)),
                    max_connections: Some(max_connections.get().parse().unwrap_or(1000)),
                    enable_mitm: Some(enable_mitm.get()),
                    enable_http2: Some(enable_http2.get()),
                    enable_websockets: Some(enable_websockets.get()),
                    enable_adblock: Some(enable_adblock.get()),
                    ..Default::default()
                };

                wasm_bindgen_futures::spawn_local(async move {
                    let client = ApiClient::new();

                    match client.update_proxy_config(&config).await {
                        Ok(_) => {
                            app_state.success("Configuration saved");
                        }
                        Err(e) => {
                            app_state.error(format!("Failed to save: {}", e));
                        }
                    }

                    saving.set(false);
                    do_save.set(false);
                });
            }
        });
    }

    let on_save = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        do_save.set(true);
    };

    view! {
        <Layout>
            <div class="page-header">
                <h1 class="page-title">"Proxy Configuration"</h1>
            </div>

            <div class="proxy-grid">
                <Card title="Configuration" class="proxy-config-card">
                    <Show when=move || !loading.get() fallback=|| view! {
                        <div class="loading">"Loading..."</div>
                    }>
                        <form class="proxy-form" on:submit=on_save>
                            <div class="form-row">
                                <div class="form-field">
                                    <label class="form-label">"Host"</label>
                                    <input
                                        type="text"
                                        class="form-input"
                                        placeholder="127.0.0.1"
                                        prop:value=move || host.get()
                                        on:input=move |ev| {
                                            let target = event_target::<HtmlInputElement>(&ev);
                                            host.set(target.value());
                                        }
                                    />
                                </div>
                                <div class="form-field">
                                    <label class="form-label">"Port"</label>
                                    <input
                                        type="number"
                                        class="form-input"
                                        placeholder="8080"
                                        prop:value=move || port.get()
                                        on:input=move |ev| {
                                            let target = event_target::<HtmlInputElement>(&ev);
                                            port.set(target.value());
                                        }
                                    />
                                </div>
                            </div>

                            <div class="form-toggles">
                                <label class="form-checkbox">
                                    <input
                                        type="checkbox"
                                        class="checkbox-input"
                                        prop:checked=move || enable_mitm.get()
                                        on:change=move |_| enable_mitm.update(|v| *v = !*v)
                                    />
                                    <span class="checkbox-label">"Enable MITM"</span>
                                </label>
                                <label class="form-checkbox">
                                    <input
                                        type="checkbox"
                                        class="checkbox-input"
                                        prop:checked=move || enable_http2.get()
                                        on:change=move |_| enable_http2.update(|v| *v = !*v)
                                    />
                                    <span class="checkbox-label">"Enable HTTP/2"</span>
                                </label>
                                <label class="form-checkbox">
                                    <input
                                        type="checkbox"
                                        class="checkbox-input"
                                        prop:checked=move || enable_websockets.get()
                                        on:change=move |_| enable_websockets.update(|v| *v = !*v)
                                    />
                                    <span class="checkbox-label">"Enable WebSockets"</span>
                                </label>
                                <label class="form-checkbox">
                                    <input
                                        type="checkbox"
                                        class="checkbox-input"
                                        prop:checked=move || enable_adblock.get()
                                        on:change=move |_| enable_adblock.update(|v| *v = !*v)
                                    />
                                    <span class="checkbox-label">"Enable Adblock"</span>
                                </label>
                            </div>

                            <div class="form-actions">
                                <button
                                    type="submit"
                                    class="btn btn-primary"
                                    disabled=move || saving.get()
                                >
                                    {move || if saving.get() { "Saving..." } else { "Save" }}
                                </button>
                            </div>
                        </form>
                    </Show>
                </Card>

                <Card title="Statistics" class="proxy-stats-card">
                    <div class="stats-list">
                        <div class="stat-row">
                            <span class="stat-label">"Total Connections"</span>
                            <span class="stat-value">{connections_total}</span>
                        </div>
                        <div class="stat-row">
                            <span class="stat-label">"Active"</span>
                            <span class="stat-value">{connections_active}</span>
                        </div>
                        <div class="stat-row">
                            <span class="stat-label">"Requests"</span>
                            <span class="stat-value">{requests_total}</span>
                        </div>
                    </div>
                </Card>
            </div>
        </Layout>
    }
}

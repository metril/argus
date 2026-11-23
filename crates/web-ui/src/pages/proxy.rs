//! Proxy page: explicit and transparent listener cards, passthrough hosts, nftables redirect.

use leptos::prelude::*;

use crate::api::proxy::{ProxyConfigResponse, UpdateProxyConfigRequest};
use crate::api::ApiClient;
use crate::components::{Icon, Layout, Pill, Switch};
use crate::state::use_app_state;
use crate::utils::{copy_text, format_number};
use api_types::{ListenerFlagsUpdate, ListenerFlagsView};

#[derive(Clone, Copy, PartialEq)]
enum Which {
    Explicit,
    Transparent,
}

const FLAGS: [(&str, &str, &str, &str); 4] = [
    (
        "mitm",
        "MITM",
        "Decrypt HTTPS so cosmetic and path rules apply",
        "Needs the CA installed on every client",
    ),
    (
        "http2",
        "HTTP/2",
        "Negotiate h2 with clients via ALPN",
        "Negotiate h2 with clients via ALPN",
    ),
    (
        "ws",
        "WebSockets",
        "Proxy Upgrade requests instead of refusing them",
        "Proxy Upgrade requests instead of refusing them",
    ),
    (
        "adblock",
        "Adblock",
        "Apply network and cosmetic filters",
        "Without MITM only host-level rules apply",
    ),
];

fn flag(v: &ListenerFlagsView, k: &str) -> bool {
    match k {
        "mitm" => v.enable_mitm,
        "http2" => v.enable_http2,
        "ws" => v.enable_websockets,
        _ => v.enable_adblock,
    }
}

fn flag_update(k: &str, on: bool) -> ListenerFlagsUpdate {
    let mut u = ListenerFlagsUpdate::default();
    match k {
        "mitm" => u.enable_mitm = Some(on),
        "http2" => u.enable_http2 = Some(on),
        "ws" => u.enable_websockets = Some(on),
        _ => u.enable_adblock = Some(on),
    }
    u
}

fn nft_snippet(port: u16) -> String {
    format!(
        "define LAN  = \"eth1\"   # client-facing interface\ndefine PORT = {port}\n\n\
table inet argus {{\n  chain nat_prerouting {{\n    type nat hook prerouting priority dstnat; policy accept;\n\
    iifname != $LAN return\n    # never redirect traffic addressed to the gateway itself (loop guard)\n\
    fib daddr type local return\n    meta nfproto ipv4 tcp dport {{ 80, 443 }} redirect to :$PORT\n\
    meta nfproto ipv6 tcp dport {{ 80, 443 }} redirect to :$PORT\n  }}\n}}\n"
    )
}

#[component]
pub fn ProxyPage() -> impl IntoView {
    let app = use_app_state();
    let cfg = RwSignal::new(Option::<ProxyConfigResponse>::None);
    let active = RwSignal::new(0u64);
    let total = RwSignal::new(0u64);
    let rate = RwSignal::new(0.0f64);
    let t_counters = RwSignal::new(api_types::ListenerCounters::default());
    let e_counters = RwSignal::new(api_types::ListenerCounters::default());
    let t_enabled = RwSignal::new(false);
    let t_addr = RwSignal::new(Option::<String>::None);
    let loaded = RwSignal::new(false);

    let load = {
        let app = app.clone();
        move || {
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().get_proxy_config().await {
                    Ok(c) => {
                        cfg.set(Some(c));
                        loaded.set(true);
                    }
                    Err(e) => app.error(format!("Failed to load config: {e}")),
                }
            });
        }
    };
    load();

    let alive = StoredValue::new(true);
    on_cleanup(move || alive.set_value(false));
    wasm_bindgen_futures::spawn_local(async move {
        while alive.get_value() {
            if let Ok(s) = ApiClient::new().get_proxy_stats().await {
                active.set(s.connections.active);
                total.set(s.requests.total);
                t_enabled.set(s.transparent.enabled);
                t_addr.set(s.transparent.address);
                rate.set(s.explicit.requests_per_sec);
                e_counters.set(s.explicit);
                t_counters.set(s.transparent.counters);
            }
            gloo_timers::future::TimeoutFuture::new(5000).await;
        }
    });

    let save = {
        let app = app.clone();
        move |req: UpdateProxyConfigRequest, ok: String| {
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().update_proxy_config_full(&req).await {
                    Ok(r) => {
                        cfg.set(Some(r.config));
                        app.success(ok);
                    }
                    Err(e) => app.error(format!("Failed to save: {e}")),
                }
            });
        }
    };

    let flags_card = {
        let save = save.clone();
        move |which: Which| {
            let save = save.clone();
            FLAGS
                .iter()
                .map(|(k, label, d_exp, d_tr)| {
                    let k = *k;
                    let save = save.clone();
                    let checked = Signal::derive(move || {
                        cfg.read()
                            .as_ref()
                            .map(|c| match which {
                                Which::Explicit => flag(&c.explicit, k),
                                Which::Transparent => flag(&c.transparent, k),
                            })
                            .unwrap_or(false)
                    });
                    let name = if which == Which::Explicit { "explicit" } else { "transparent" };
                    view! {
                        <div class="srow">
                            <div class="txt">
                                <b>{*label}</b>
                                <small>{if which == Which::Explicit { *d_exp } else { *d_tr }}</small>
                            </div>
                            <Switch
                                checked=checked
                                label=format!("{label}, {name}")
                                disabled=Signal::derive(move || cfg.read().is_none())
                                on_change=Callback::new(move |on: bool| {
                                    let mut req = UpdateProxyConfigRequest::default();
                                    match which {
                                        Which::Explicit => req.explicit = Some(flag_update(k, on)),
                                        Which::Transparent => req.transparent = Some(flag_update(k, on)),
                                    }
                                    save(req, format!("{name} {label} {}", if on { "on" } else { "off" }));
                                })
                            />
                        </div>
                    }
                })
                .collect_view()
        }
    };
    let flags_e = flags_card.clone();
    let flags_t = flags_card;

    let snippet = Memo::new(move |_| {
        nft_snippet(
            cfg.read()
                .as_ref()
                .and_then(|c| c.transparent_port)
                .unwrap_or(3129),
        )
    });
    let copied = RwSignal::new(false);
    let app_copy = app.clone();

    view! {
        <Layout>
            <div class="grid2">
                <article class="card" aria-labelledby="pxE">
                    <div class="card-h">
                        <h3 id="pxE">"Explicit"</h3>
                        <span class="tag">{move || cfg.read().as_ref().map(|c| format!(":{}", c.port)).unwrap_or_default()}</span>
                        <div class="r">
                            {move || if !loaded.get() { view! { <span class="spin"></span> }.into_any() }
                                else if cfg.read().as_ref().and_then(|c| c.bind.as_ref()).map(|b| b.proxy_down).unwrap_or(false) { view! { <Pill kind="error" text="down" /> }.into_any() }
                                else { view! { <Pill kind="allowed" text="listening" /> }.into_any() }}
                        </div>
                    </div>
                    <div class="card-b">
                        <div class="listen">
                            <span class="addr">{move || cfg.read().as_ref().map(|c| c.bind.as_ref().and_then(|b| b.proxy.clone()).unwrap_or_else(|| format!("{}:{}", c.host, c.port))).unwrap_or_default()}</span>
                            <span class="dim">"clients set this as their HTTP(S) proxy"</span>
                        </div>
                        <div class="minis">
                            <div><b>{move || format_number(e_counters.get().active_connections)}</b><span>"open conns"</span></div>
                            <div><b>{move || format!("{:.0}/s", rate.get())}</b><span>"requests"</span></div>
                            <div><b>{move || format_number(e_counters.get().clients)}</b><span>"clients"</span></div>
                        </div>
                        <div>{flags_e(Which::Explicit)}</div>
                    </div>
                </article>
                <article class="card" aria-labelledby="pxT">
                    <div class="card-h">
                        <h3 id="pxT">"Transparent"</h3>
                        <span class="tag">{move || cfg.read().as_ref().and_then(|c| c.transparent_port).map(|p| format!(":{p}")).unwrap_or_else(|| "off".into())}</span>
                        <div class="r">
                            {move || if cfg.read().as_ref().and_then(|c| c.bind.as_ref()).map(|b| b.transparent_down).unwrap_or(false) { view! { <Pill kind="error" text="down" /> }.into_any() }
                                else if t_enabled.get() { view! { <Pill kind="allowed" text="listening" /> }.into_any() } else { view! { <Pill kind="neutral" text="off" /> }.into_any() }}
                        </div>
                    </div>
                    <div class="card-b">
                        <div class="listen">
                            <span class="addr">{move || t_addr.get().unwrap_or_else(|| "not listening".into())}</span>
                            <span class="dim">"receives traffic redirected by the firewall"</span>
                        </div>
                        <div class="minis">
                            <div><b>{move || format_number(t_counters.get().active_connections)}</b><span>"open conns"</span></div>
                            <div><b>{move || format!("{:.0}/s", t_counters.get().requests_per_sec)}</b><span>"requests"</span></div>
                            <div><b>{move || format_number(t_counters.get().clients)}</b><span>"clients"</span></div>
                        </div>
                        <Show when=move || !t_enabled.get()>
                            <span class="hint">"Turn the transparent listener on in "<a href="/settings" style="color:var(--accent)">"Settings"</a>"."</span>
                        </Show>
                        <div>{flags_t(Which::Transparent)}</div>
                    </div>
                </article>
            </div>

            <div class="card">
                <div class="card-h">
                    <h3>"Bypass"</h3>
                    <span class="sub">"Banking, health and pinned apps are tunnelled, not decrypted."</span>
                    <div class="r"><a class="btn sm" href="/bypass">"Manage bypass"</a></div>
                </div>
            </div>

            <div class="card">
                <div class="card-h">
                    <h3>"Redirect rule"</h3>
                    <span class="sub">"nftables, run on the gateway. Sends LAN port 80/443 to the transparent listener."</span>
                </div>
                <div class="card-b">
                    <div class="codebox">
                        <button
                            class="btn sm copy"
                            type="button"
                            on:click=move |_| {
                                if copy_text(&snippet.get_untracked()) {
                                    copied.set(true);
                                    app_copy.success("Copied the nftables rule");
                                    gloo_timers::callback::Timeout::new(2000, move || copied.set(false)).forget();
                                } else {
                                    app_copy.error("Copy failed; select the text instead");
                                }
                            }
                        >
                            <Icon name="copy" />{move || if copied.get() { "Copied" } else { "Copy" }}
                        </button>
                        <pre>{move || snippet.get()}</pre>
                    </div>
                </div>
            </div>
        </Layout>
    }
}

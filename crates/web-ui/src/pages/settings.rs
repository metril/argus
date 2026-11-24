//! Admin settings: every runtime setting, with default/modified/unsaved state, per-field reset,
//! a sticky save bar, per-field results from the PUT response and the web UI move flow.

use std::net::IpAddr;

use leptos::prelude::*;

use crate::api::proxy::{ProxyConfigResponse, UpdateProxyConfigRequest};
use crate::api::{ApiClient, ApiError};
use crate::components::{Icon, Layout, RequireAdmin, Segmented, Switch, TagInput};
use crate::state::use_app_state;

#[derive(Clone, PartialEq)]
enum Val {
    B(bool),
    S(String),
    T(Vec<String>),
}

impl Val {
    fn s(&self) -> String {
        match self {
            Val::S(s) => s.clone(),
            Val::B(b) => b.to_string(),
            Val::T(t) => t.join(", "),
        }
    }
    fn b(&self) -> bool {
        matches!(self, Val::B(true))
    }
    fn t(&self) -> Vec<String> {
        match self {
            Val::T(t) => t.clone(),
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Text,
    Port,
    Num {
        unit: &'static str,
        min: u64,
        max: u64,
    },
    Switch,
    Cidr,
    Ip,
    Seg(&'static [(&'static str, &'static str)]),
}

#[derive(Clone, Copy)]
struct Def {
    key: &'static str,
    label: &'static str,
    desc: &'static str,
    kind: Kind,
    dep: Option<&'static str>,
}

#[derive(Clone, Copy)]
struct F {
    def: Def,
    cur: RwSignal<Val>,
    saved: RwSignal<Val>,
    default: RwSignal<Val>,
    msg: RwSignal<Option<(bool, String)>>,
}

const HOURS: &[(&str, &str)] = &[("6", "6 h"), ("12", "12 h"), ("24", "24 h"), ("168", "7 d")];

struct Section {
    id: &'static str,
    title: &'static str,
    sub: &'static str,
    fields: &'static [Def],
}

const SECTIONS: &[Section] = &[
    Section {
        id: "listeners",
        title: "Listeners",
        sub: "Ports rebind live. Open connections finish on the old socket.",
        fields: &[
            Def {
                key: "explicit_host",
                label: "Explicit proxy host",
                desc: "Address to bind. 0.0.0.0 listens on all IPv4 interfaces, :: on all.",
                kind: Kind::Text,
                dep: None,
            },
            Def {
                key: "explicit_port",
                label: "Explicit proxy port",
                desc: "Clients set host:port as their HTTP(S) proxy.",
                kind: Kind::Port,
                dep: None,
            },
            Def {
                key: "transparent_on",
                label: "Transparent listener",
                desc: "Accepts traffic redirected by the firewall.",
                kind: Kind::Switch,
                dep: None,
            },
            Def {
                key: "transparent_port",
                label: "Transparent port",
                desc: "Must match the nftables redirect target.",
                kind: Kind::Port,
                dep: Some("transparent_on"),
            },
            Def {
                key: "webui_host",
                label: "Web UI host",
                desc: "Where this console is served.",
                kind: Kind::Text,
                dep: None,
            },
            Def {
                key: "webui_port",
                label: "Web UI port",
                desc: "Changing it moves this page. You confirm first.",
                kind: Kind::Port,
                dep: None,
            },
        ],
    },
    Section {
        id: "dns",
        title: "Upstream DNS",
        sub: "Resolvers the proxy uses for upstream connections.",
        fields: &[
            Def {
                key: "dns_servers",
                label: "Servers",
                desc: "Tried in order. IPv4, IPv6, or ip:port. Empty uses the system resolver.",
                kind: Kind::Ip,
                dep: None,
            },
            Def {
                key: "dns_cache",
                label: "Cache size",
                desc: "0 turns the cache off.",
                kind: Kind::Num {
                    unit: "entries",
                    min: 0,
                    max: 10_000_000,
                },
                dep: None,
            },
            Def {
                key: "dns_min_ttl",
                label: "Minimum TTL",
                desc: "Short upstream TTLs are raised to this.",
                kind: Kind::Num {
                    unit: "s",
                    min: 0,
                    max: 86400,
                },
                dep: None,
            },
            Def {
                key: "dns_max_ttl",
                label: "Maximum TTL",
                desc: "Long upstream TTLs are capped at this.",
                kind: Kind::Num {
                    unit: "s",
                    min: 1,
                    max: 604800,
                },
                dep: None,
            },
            Def {
                key: "dns_neg_ttl",
                label: "Failed lookup TTL",
                desc: "How long failed lookups are cached.",
                kind: Kind::Num {
                    unit: "s",
                    min: 0,
                    max: 86400,
                },
                dep: None,
            },
        ],
    },
    Section {
        id: "timeouts",
        title: "Timeouts and limits",
        sub: "Apply to new connections.",
        fields: &[
            Def {
                key: "conn_timeout",
                label: "Connection timeout",
                desc: "TCP and TLS handshake with the upstream.",
                kind: Kind::Num {
                    unit: "s",
                    min: 1,
                    max: 300,
                },
                dep: None,
            },
            Def {
                key: "req_timeout",
                label: "Request timeout",
                desc: "Whole request, headers to last byte.",
                kind: Kind::Num {
                    unit: "s",
                    min: 1,
                    max: 3600,
                },
                dep: None,
            },
            Def {
                key: "max_conns",
                label: "Max connections",
                desc: "Across both listeners. 0 means automatic.",
                kind: Kind::Num {
                    unit: "connections",
                    min: 0,
                    max: 1_000_000,
                },
                dep: None,
            },
        ],
    },
    Section {
        id: "access",
        title: "Network access",
        sub: "Who may use the proxy, and where it may connect.",
        fields: &[
            Def {
                key: "allow_clients",
                label: "Allowed clients",
                desc: "Source ranges. Others are refused.",
                kind: Kind::Cidr,
                dep: None,
            },
            Def {
                key: "allow_dest",
                label: "Allowed destinations",
                desc: "Destination ranges the proxy may reach. Empty means no restriction.",
                kind: Kind::Cidr,
                dep: None,
            },
            Def {
                key: "block_private",
                label: "Block private destinations",
                desc: "Refuse RFC 1918, loopback and link-local targets (SSRF guard).",
                kind: Kind::Switch,
                dep: None,
            },
        ],
    },
    Section {
        id: "updates",
        title: "Filter list updates",
        sub: "Background fetch of all enabled lists.",
        fields: &[
            Def {
                key: "auto_update",
                label: "Auto-update",
                desc: "Lists recompile in the background.",
                kind: Kind::Switch,
                dep: None,
            },
            Def {
                key: "update_every",
                label: "Interval",
                desc: "Measured from the last successful fetch.",
                kind: Kind::Seg(HOURS),
                dep: Some("auto_update"),
            },
        ],
    },
];

fn defaults(key: &str) -> Val {
    match key {
        "explicit_host" => Val::S("::".into()),
        "explicit_port" => Val::S("8080".into()),
        "transparent_on" => Val::B(true),
        "transparent_port" => Val::S("3129".into()),
        "webui_host" => Val::S("0.0.0.0".into()),
        "webui_port" => Val::S("3000".into()),
        "conn_timeout" => Val::S("30".into()),
        "req_timeout" => Val::S("60".into()),
        "max_conns" => Val::S("0".into()),
        "allow_clients" => Val::T(
            [
                "127.0.0.0/8",
                "::1/128",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "100.64.0.0/10",
                "169.254.0.0/16",
                "fc00::/7",
                "fe80::/10",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        ),
        "allow_dest" => Val::T(Vec::new()),
        "block_private" => Val::B(false),
        "auto_update" => Val::B(true),
        "dns_servers" => Val::T(Vec::new()),
        "dns_cache" | "dns_min_ttl" | "dns_max_ttl" | "dns_neg_ttl" => Val::S("0".into()),
        _ => Val::S("24".into()),
    }
}

fn from_config(c: &ProxyConfigResponse) -> Vec<(&'static str, Val)> {
    vec![
        ("explicit_host", Val::S(c.host.clone())),
        ("explicit_port", Val::S(c.port.to_string())),
        ("transparent_on", Val::B(c.transparent_port.is_some())),
        (
            "transparent_port",
            Val::S(c.transparent_port.unwrap_or(3129).to_string()),
        ),
        ("webui_host", Val::S(c.webui_host.clone())),
        ("webui_port", Val::S(c.webui_port.to_string())),
        (
            "conn_timeout",
            Val::S(c.connection_timeout_secs.to_string()),
        ),
        ("req_timeout", Val::S(c.request_timeout_secs.to_string())),
        ("max_conns", Val::S(c.max_connections.to_string())),
        ("allow_clients", Val::T(c.allowed_clients.clone())),
        ("allow_dest", Val::T(c.allowed_destinations.clone())),
        ("block_private", Val::B(c.block_private_destinations)),
        ("auto_update", Val::B(c.auto_update)),
        ("update_every", Val::S(c.update_interval_hours.to_string())),
        ("dns_servers", Val::T(c.dns.servers.clone())),
        ("dns_cache", Val::S(c.dns.cache_size.to_string())),
        ("dns_min_ttl", Val::S(c.dns.min_ttl_secs.to_string())),
        ("dns_max_ttl", Val::S(c.dns.max_ttl_secs.to_string())),
        ("dns_neg_ttl", Val::S(c.dns.negative_ttl_secs.to_string())),
    ]
}

/// Backend field names a settings key maps to (as listed in `applied` / `restart_required`).
fn backend_names(key: &str) -> &'static [&'static str] {
    match key {
        "explicit_host" => &["host"],
        "explicit_port" => &["port"],
        "transparent_on" | "transparent_port" => &["transparent_port"],
        "webui_host" => &["webui_host"],
        "webui_port" => &["webui_port"],
        "conn_timeout" => &["connection_timeout_secs"],
        "req_timeout" => &["request_timeout_secs"],
        "max_conns" => &["max_connections"],
        "allow_clients" => &["allowed_clients"],
        "allow_dest" => &["allowed_destinations"],
        "block_private" => &["block_private_destinations"],
        "auto_update" => &["auto_update"],
        "dns_servers" | "dns_cache" | "dns_min_ttl" | "dns_max_ttl" | "dns_neg_ttl" => &["dns"],
        _ => &["update_interval_hours"],
    }
}

fn host_ok(s: &str) -> bool {
    s == "localhost" || s.parse::<IpAddr>().is_ok()
}

fn dns_ok(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok() || s.parse::<std::net::SocketAddr>().is_ok()
}

fn cidr_ok(s: &str) -> bool {
    match s.split_once('/') {
        Some((ip, bits)) => match (ip.parse::<IpAddr>(), bits.parse::<u8>()) {
            (Ok(IpAddr::V4(_)), Ok(b)) => b <= 32,
            (Ok(IpAddr::V6(_)), Ok(b)) => b <= 128,
            _ => false,
        },
        None => s.parse::<IpAddr>().is_ok(),
    }
}

fn is_on(all: &[F], key: &str) -> bool {
    all.iter()
        .find(|f| f.def.key == key)
        .map(|f| f.cur.read().b())
        .unwrap_or(true)
}

/// Validation message for a field, given the current values of all fields.
fn error_of(f: &F, all: &[F]) -> Option<String> {
    if let Some(dep) = f.def.dep {
        if !is_on(all, dep) {
            return None;
        }
    }
    let v = f.cur.read();
    let get = |k: &str| {
        all.iter()
            .find(|x| x.def.key == k)
            .map(|x| x.cur.read().s())
            .unwrap_or_default()
    };
    match f.def.kind {
        Kind::Port | Kind::Num { .. } => {
            let s = v.s();
            let Ok(n) = s.trim().parse::<u64>() else {
                return Some("Enter a whole number.".into());
            };
            if let Kind::Num { min, max, .. } = f.def.kind {
                if n < min || n > max {
                    return Some(format!("Use {min} to {max}."));
                }
                if f.def.key == "dns_max_ttl"
                    && n < get("dns_min_ttl").trim().parse::<u64>().unwrap_or(0)
                {
                    return Some("Must be at least the minimum TTL.".into());
                }
            } else {
                if !(1..=65535).contains(&n) {
                    return Some("Use a port from 1 to 65535.".into());
                }
                let others = [
                    ("explicit_port", "explicit proxy"),
                    ("transparent_port", "transparent listener"),
                    ("webui_port", "web UI"),
                ];
                for (k, name) in others {
                    if k == f.def.key || (k == "transparent_port" && !is_on(all, "transparent_on"))
                    {
                        continue;
                    }
                    if get(k).trim().parse::<u64>() == Ok(n) {
                        return Some(format!("Port {n} is already used by the {name}."));
                    }
                }
            }
            None
        }
        Kind::Text if !host_ok(v.s().trim()) => {
            Some("Enter an IP address such as 0.0.0.0 or ::.".into())
        }
        Kind::Cidr if f.def.key == "allow_clients" && v.t().is_empty() => {
            Some("Add at least one range, or every client is refused.".into())
        }
        _ => None,
    }
}

#[derive(Clone, PartialEq)]
enum Bar {
    Edit,
    Confirm,
    Redirect(u32, String),
}

fn build_request(all: &[F]) -> UpdateProxyConfigRequest {
    let dirty = |k: &str| {
        all.iter()
            .any(|f| f.def.key == k && f.cur.get_untracked() != f.saved.get_untracked())
    };
    let val = |k: &str| {
        all.iter()
            .find(|f| f.def.key == k)
            .map(|f| f.cur.get_untracked())
            .unwrap_or(Val::S(String::new()))
    };
    let num = |k: &str| val(k).s().trim().parse::<u64>().unwrap_or(0);
    let mut r = UpdateProxyConfigRequest::default();
    if dirty("explicit_host") {
        r.host = Some(val("explicit_host").s().trim().to_string());
    }
    if dirty("explicit_port") {
        r.port = Some(num("explicit_port") as u16);
    }
    if dirty("transparent_on") || dirty("transparent_port") {
        r.transparent_port = Some(if val("transparent_on").b() {
            num("transparent_port") as u16
        } else {
            0
        });
    }
    if dirty("webui_host") {
        r.webui_host = Some(val("webui_host").s().trim().to_string());
    }
    if dirty("webui_port") {
        r.webui_port = Some(num("webui_port") as u16);
    }
    if dirty("conn_timeout") {
        r.connection_timeout_secs = Some(num("conn_timeout"));
    }
    if dirty("req_timeout") {
        r.request_timeout_secs = Some(num("req_timeout"));
    }
    if dirty("max_conns") {
        r.max_connections = Some(num("max_conns") as u32);
    }
    if dirty("allow_clients") {
        r.allowed_clients = Some(val("allow_clients").t());
    }
    if dirty("allow_dest") {
        r.allowed_destinations = Some(val("allow_dest").t());
    }
    if dirty("block_private") {
        r.block_private_destinations = Some(val("block_private").b());
    }
    if dirty("auto_update") {
        r.auto_update = Some(val("auto_update").b());
    }
    if dirty("update_every") {
        r.update_interval_hours = Some(num("update_every"));
    }
    if [
        "dns_servers",
        "dns_cache",
        "dns_min_ttl",
        "dns_max_ttl",
        "dns_neg_ttl",
    ]
    .iter()
    .any(|k| dirty(k))
    {
        let mut d = api_types::DnsUpdate::default();
        if dirty("dns_servers") {
            d.servers = Some(val("dns_servers").t());
        }
        if dirty("dns_cache") {
            d.cache_size = Some(num("dns_cache"));
        }
        if dirty("dns_min_ttl") {
            d.min_ttl_secs = Some(num("dns_min_ttl"));
        }
        if dirty("dns_max_ttl") {
            d.max_ttl_secs = Some(num("dns_max_ttl"));
        }
        if dirty("dns_neg_ttl") {
            d.negative_ttl_secs = Some(num("dns_neg_ttl"));
        }
        r.dns = Some(d);
    }
    r
}

#[component]
pub fn SettingsPage() -> impl IntoView {
    view! { <Layout class="settings-screen"><RequireAdmin><SettingsInner /></RequireAdmin></Layout> }
}

#[component]
fn SettingsInner() -> impl IntoView {
    let app = use_app_state();
    let all: Vec<F> = SECTIONS
        .iter()
        .flat_map(|s| s.fields.iter())
        .map(|d| F {
            def: *d,
            cur: RwSignal::new(defaults(d.key)),
            saved: RwSignal::new(defaults(d.key)),
            default: RwSignal::new(defaults(d.key)),
            msg: RwSignal::new(None),
        })
        .collect();
    let loaded = RwSignal::new(false);
    let bar = RwSignal::new(Bar::Edit);
    let busy = RwSignal::new(false);
    let cancel_redirect = StoredValue::new(false);

    let apply_values = {
        let all = all.clone();
        move |c: &ProxyConfigResponse, only_clean: bool| {
            if let Some(b) = &c.bind {
                if let (Some(a), Some(f)) = (
                    &b.webui_moved_to,
                    all.iter().find(|f| f.def.key == "webui_port"),
                ) {
                    f.msg.set(Some((
                        true,
                        format!("Web UI is on {a} because the configured port is in use. Change the port here."),
                    )));
                }
                for (down, keys) in [
                    (b.proxy_down, ["explicit_host", "explicit_port"]),
                    (b.transparent_down, ["transparent_on", "transparent_port"]),
                    (b.webui_down, ["webui_host", "webui_port"]),
                ] {
                    if down {
                        for k in keys {
                            if let Some(f) = all.iter().find(|f| f.def.key == k) {
                                f.msg.set(Some((
                                    true,
                                    "Listener is down. Save again to retry.".into(),
                                )));
                            }
                        }
                    }
                }
            }
            for (k, v) in from_config(c) {
                if let Some(f) = all.iter().find(|f| f.def.key == k) {
                    let was_dirty = f.cur.get_untracked() != f.saved.get_untracked();
                    f.saved.set(v.clone());
                    if !only_clean || !was_dirty {
                        f.cur.set(v);
                    }
                }
            }
        }
    };
    {
        let app = app.clone();
        let apply_values = apply_values.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().get_proxy_config().await {
                Ok(c) => {
                    apply_values(&c, false);
                    loaded.set(true);
                }
                Err(e) => app.error(format!("Failed to load settings: {e}")),
            }
        });
    }

    {
        let all = all.clone();
        wasm_bindgen_futures::spawn_local(async move {
            if let Ok(d) = ApiClient::new()
                .get::<ProxyConfigResponse>("/config/defaults")
                .await
            {
                for (k, v) in from_config(&d) {
                    if let Some(f) = all.iter().find(|f| f.def.key == k) {
                        f.default.set(v);
                    }
                }
            }
        });
    }

    let dirty_fields = {
        let all = all.clone();
        move || {
            all.iter()
                .filter(|f| f.cur.get() != f.saved.get())
                .copied()
                .collect::<Vec<F>>()
        }
    };
    let error_count = {
        let all = all.clone();
        move || all.iter().filter(|f| error_of(f, &all).is_some()).count()
    };

    let apply = {
        let all = all.clone();
        let app = app.clone();
        let apply_values = apply_values.clone();
        move || {
            let req = build_request(&all);
            let dirty: Vec<F> = all
                .iter()
                .filter(|f| f.cur.get_untracked() != f.saved.get_untracked())
                .copied()
                .collect();
            let moved = dirty
                .iter()
                .any(|f| matches!(f.def.key, "webui_host" | "webui_port"));
            let new_port = all
                .iter()
                .find(|f| f.def.key == "webui_port")
                .map(|f| f.cur.get_untracked().s())
                .unwrap_or_default();
            busy.set(true);
            let (all, app, apply_values) = (all.clone(), app.clone(), apply_values.clone());
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().update_proxy_config_full(&req).await {
                    Ok(r) => {
                        apply_values(&r.config, false);
                        let mut live = 0;
                        for f in &dirty {
                            let names = backend_names(f.def.key);
                            let msg = if names
                                .iter()
                                .any(|n| r.restart_required.iter().any(|x| x == n))
                            {
                                "Saved. Applies after a restart."
                            } else {
                                live += 1;
                                "Applied live"
                            };
                            f.msg.set(Some((false, msg.to_string())));
                        }
                        app.success(format!(
                            "{} setting{} saved",
                            dirty.len(),
                            if dirty.len() == 1 { "" } else { "s" }
                        ));
                        let _ = live;
                        let all2 = all.clone();
                        gloo_timers::callback::Timeout::new(5000, move || {
                            for f in &all2 {
                                if matches!(f.msg.get_untracked(), Some((false, _))) {
                                    f.msg.set(None);
                                }
                            }
                        })
                        .forget();
                        if moved {
                            let loc = web_sys::window().map(|w| w.location());
                            let proto = loc
                                .as_ref()
                                .and_then(|l| l.protocol().ok())
                                .unwrap_or_else(|| "http:".into());
                            let host = loc
                                .as_ref()
                                .and_then(|l| l.hostname().ok())
                                .unwrap_or_default();
                            let port = r.config.webui_port.to_string();
                            let port = if port.is_empty() { new_port } else { port };
                            let url = format!("{proto}//{host}:{port}/settings");
                            cancel_redirect.set_value(false);
                            bar.set(Bar::Redirect(5, url.clone()));
                            for left in (0..5).rev() {
                                gloo_timers::future::TimeoutFuture::new(1000).await;
                                if cancel_redirect.get_value() {
                                    return;
                                }
                                if left == 0 {
                                    if let Some(w) = web_sys::window() {
                                        let _ = w.location().set_href(&url);
                                    }
                                } else {
                                    bar.set(Bar::Redirect(left, url.clone()));
                                }
                            }
                        } else {
                            bar.set(Bar::Edit);
                        }
                    }
                    Err(e) => {
                        let (txt, bind) = match &e {
                            ApiError::Conflict(m) => (m.clone(), true),
                            other => (other.to_string(), false),
                        };
                        for f in &dirty {
                            let listener = matches!(
                                f.def.key,
                                "explicit_host"
                                    | "explicit_port"
                                    | "transparent_port"
                                    | "transparent_on"
                                    | "webui_host"
                                    | "webui_port"
                            );
                            if bind && listener {
                                let old = f.saved.get_untracked().s();
                                f.cur.set(f.saved.get_untracked());
                                f.msg.set(Some((true, format!("{txt}. Kept {old}."))));
                            } else if !bind {
                                f.msg.set(Some((true, txt.clone())));
                            }
                        }
                        app.error(if bind {
                            "A listener could not bind. See the highlighted field.".to_string()
                        } else {
                            format!("Failed to save: {txt}")
                        });
                        bar.set(Bar::Edit);
                    }
                }
                busy.set(false);
            });
        }
    };

    let on_save = {
        let all = all.clone();
        let apply = apply.clone();
        move |_: web_sys::MouseEvent| {
            if all.iter().any(|f| error_of(f, &all).is_some()) {
                return;
            }
            let moving = all.iter().any(|f| {
                matches!(f.def.key, "webui_host" | "webui_port")
                    && f.cur.get_untracked() != f.saved.get_untracked()
            });
            if moving {
                bar.set(Bar::Confirm);
            } else {
                apply();
            }
        }
    };
    let on_discard = {
        let all = all.clone();
        move |_: web_sys::MouseEvent| {
            for f in &all {
                f.cur.set(f.saved.get_untracked());
                f.msg.set(None);
            }
            app.info("Changes discarded");
        }
    };

    let jump = |id: &'static str| {
        if let Some(el) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id(&format!("set-{id}")))
        {
            el.scroll_into_view();
        }
    };

    let rows_for = {
        let all = all.clone();
        move |s: &'static Section| {
            let fields: Vec<F> = all
                .iter()
                .filter(|f| s.fields.iter().any(|d| d.key == f.def.key))
                .copied()
                .collect();
            fields
                .into_iter()
                .map(|f| row(f, all.clone()))
                .collect_view()
        }
    };

    let dirty_n = dirty_fields.clone();
    view! {
        <div class="set-intro">
            <p class="muted">"Every setting lives here. Changes apply live when you save, with no restart and no config file to edit."</p>
            <nav class="chips" aria-label="Settings sections">
                {SECTIONS.iter().map(|s| { let id = s.id; view! {
                    <a class="chip link" href=format!("#set-{id}") on:click=move |ev| { ev.prevent_default(); jump(id); }>{s.title}</a>
                } }).collect_view()}
                <a class="chip link" href="#set-https" on:click=move |ev| { ev.prevent_default(); jump("https"); }>"HTTPS"</a>
            </nav>
        </div>
        <Show when=move || loaded.get() fallback=|| view! { <div class="empty"><span class="spin"></span></div> }>
            <div class="set-cards">
                {SECTIONS.iter().map(|s| view! {
                    <div class="card" id=format!("set-{}", s.id)>
                        <div class="card-h"><h3>{s.title}</h3><span class="sub">{s.sub}</span></div>
                        <div>{rows_for(s)}</div>
                    </div>
                }).collect_view()}
                <super::settings_https::HttpsCard />
            </div>
        </Show>
        <Show when=move || !dirty_n().is_empty() || matches!(bar.get(), Bar::Redirect(..))>
            <div
                class=move || match bar.get() { Bar::Confirm => "savebar warn", Bar::Redirect(..) => "savebar go", _ => "savebar" }
                role="region"
                aria-label="Unsaved settings"
            >
                {
                    let dirty_fields = dirty_fields.clone();
                    let error_count = error_count.clone();
                    let (on_save, on_discard, apply) = (on_save.clone(), on_discard.clone(), apply.clone());
                    move || match bar.get() {
                        Bar::Redirect(n, url) => {
                            let u2 = url.clone();
                            view! {
                                <div class="sb-msg" aria-live="polite">
                                    <span class="countdown">{format!("{n}s")}</span>
                                    <span>"Web UI applied. Redirecting to "<b class="mono">{url.clone()}</b>"."</span>
                                </div>
                                <div class="sb-act">
                                    <button class="btn" type="button" on:click=move |_| { cancel_redirect.set_value(true); bar.set(Bar::Edit); }>"Stay on this page"</button>
                                    <button class="btn primary" type="button" on:click=move |_| { cancel_redirect.set_value(true); if let Some(w) = web_sys::window() { let _ = w.location().set_href(&u2); } }>"Go now"</button>
                                </div>
                            }.into_any()
                        }
                        Bar::Confirm => {
                            let apply = apply.clone();
                            view! {
                                <div class="sb-msg" aria-live="polite"><span>"The web UI will move. This page reconnects at the new address; other open sessions must reload."</span></div>
                                <div class="sb-act">
                                    <button class="btn" type="button" on:click=move |_| bar.set(Bar::Edit)>"Back"</button>
                                    <button class="btn primary" type="button" disabled=move || busy.get() on:click=move |_| apply()>"Move web UI and save"</button>
                                </div>
                            }.into_any()
                        }
                        Bar::Edit => {
                            let d = dirty_fields();
                            let errs = error_count();
                            let names: Vec<&str> = d.iter().map(|f| f.def.label).take(3).collect();
                            let more = d.len().saturating_sub(3);
                            let (on_save, on_discard) = (on_save.clone(), on_discard.clone());
                            view! {
                                <div class="sb-msg" aria-live="polite">
                                    <span class="sb-count">{d.len()}</span>
                                    <span>
                                        <b>{if d.len() == 1 { "Unsaved change" } else { "Unsaved changes" }}</b>
                                        <span class="dim">{format!(" · {}{}", names.join(", "), if more > 0 { format!(" and {more} more") } else { String::new() })}</span>
                                    </span>
                                    {(errs > 0).then(|| view! { <span class="err">{format!(" · fix {errs} error{} to save", if errs == 1 { "" } else { "s" })}</span> })}
                                </div>
                                <div class="sb-act">
                                    <button class="btn ghost" type="button" on:click=on_discard>"Discard"</button>
                                    <button class="btn primary" type="button" disabled={move || errs > 0 || busy.get()} on:click=on_save>"Save and apply"</button>
                                </div>
                            }.into_any()
                        }
                    }
                }
            </div>
        </Show>
    }
}

fn row(f: F, all: Vec<F>) -> impl IntoView {
    let id = format!("set-f-{}", f.def.key);
    let label_id = format!("{id}-l");
    let msg_id = format!("{id}-m");
    let d = f.def;
    let all_e = all.clone();
    let all_o = all.clone();
    let dirty = move || f.cur.get() != f.saved.get();
    let modified = move || f.cur.get() != f.default.get();
    let off = Signal::derive(move || d.dep.map(|k| !is_on(&all_o, k)).unwrap_or(false));
    let err = Signal::derive(move || error_of(&f, &all_e));
    let is_label = matches!(d.kind, Kind::Text | Kind::Port | Kind::Num { .. });
    let default_txt = move || {
        let v = f.default.get();
        match d.kind {
            Kind::Switch => {
                if v.b() {
                    "on".to_string()
                } else {
                    "off".to_string()
                }
            }
            _ => v.s(),
        }
    };

    let control = match d.kind {
        Kind::Switch => view! {
            <Switch
                checked=Signal::derive(move || f.cur.get().b())
                label=d.label
                text=Signal::derive(move || if f.cur.get().b() { "On".to_string() } else { "Off".to_string() })
                on_change=Callback::new(move |v| { f.cur.set(Val::B(v)); f.msg.set(None); })
            />
        }.into_any(),
        Kind::Seg(opts) => view! {
            <Segmented
                label=d.label
                options=opts.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
                value=Signal::derive(move || f.cur.get().s())
                disabled=off
                on_change=Callback::new(move |v: String| { f.cur.set(Val::S(v)); f.msg.set(None); })
            />
        }.into_any(),
        Kind::Cidr | Kind::Ip => {
            let is_ip = d.kind == Kind::Ip;
            let tags = RwSignal::new(f.cur.get_untracked().t());
            Effect::new(move |_| { let t = f.cur.get().t(); if tags.get_untracked() != t { tags.set(t); } });
            let terr = RwSignal::new(Option::<String>::None);
            view! {
                <TagInput
                    tags=tags
                    label=d.label
                    placeholder=if is_ip { "1.1.1.1, then Enter" } else { "192.168.1.0/24, then Enter" }
                    validate=Callback::new(move |v: String| if is_ip {
                        if dns_ok(&v) { None } else { Some(format!("\"{v}\" is not an IP address. Use 1.1.1.1 or 1.1.1.1:53.")) }
                    } else if cidr_ok(&v) { None } else { Some(format!("\"{v}\" is not a CIDR range. Use a form like 192.168.1.0/24.")) })
                    on_change=Callback::new(move |t: Vec<String>| { f.cur.set(Val::T(t)); f.msg.set(None); })
                    error=terr
                />
                {move || terr.get().map(|e| view! { <span class="fmsg bad" role="alert">{e}</span> })}
            }.into_any()
        }
        Kind::Text | Kind::Port | Kind::Num { .. } => {
            let unit = if let Kind::Num { unit, .. } = d.kind { Some(unit) } else { None };
            let cls = match d.kind { Kind::Text => "input mono mid", _ => "input mono short num" };
            let input = view! {
                <input
                    class=cls
                    id=id.clone()
                    inputmode=if d.kind == Kind::Text { "text" } else { "numeric" }
                    autocomplete="off"
                    aria-describedby=msg_id.clone()
                    aria-invalid=move || if err.get().is_some() { "true" } else { "false" }
                    disabled=move || off.get()
                    prop:value=move || f.cur.get().s()
                    on:input=move |ev| { f.cur.set(Val::S(event_target_value(&ev))); f.msg.set(None); }
                />
            };
            match unit {
                Some(u) => view! { <div class="unit">{input}<span>{u}</span></div> }.into_any(),
                None => input.into_any(),
            }
        }
    };

    view! {
        <div class=move || format!("frow {} {}", if dirty() { "dirty" } else { "" }, if off.get() { "off" } else { "" })>
            <div class="fl">
                {if is_label {
                    view! { <label for=id.clone() id=label_id.clone()>{d.label}</label> }.into_any()
                } else {
                    view! { <span class="lname" id=label_id.clone()>{d.label}</span> }.into_any()
                }}
                <small>{d.desc}</small>
                <span class="fstate">
                    {move || if modified() { view! { <span class="st st-mod">"modified"</span> }.into_any() } else { view! { <span class="st st-def">"default"</span> }.into_any() }}
                    {move || dirty().then(|| view! { <span class="st st-dirty">"unsaved"</span> })}
                </span>
            </div>
            <div class="fc">
                {control}
                <span id=msg_id class=move || match (err.get(), f.msg.get()) {
                    (Some(_), _) | (_, Some((true, _))) => "fmsg bad",
                    (None, Some((false, _))) => "fmsg ok",
                    _ => "fmsg",
                } aria-live="polite">
                    {move || match (err.get(), f.msg.get()) {
                        (Some(e), _) => e,
                        (None, Some((_, m))) => m,
                        _ => String::new(),
                    }}
                </span>
            </div>
            <button
                class="btn sm ghost freset"
                type="button"
                hidden=move || !modified()
                title=move || format!("Reset to {}", default_txt())
                aria-label=move || format!("Reset {} to default {}", d.label, default_txt())
                on:click=move |_| { f.cur.set(f.default.get()); f.msg.set(Some((false, "Default restored. Save to apply.".into()))); }
            >
                <Icon name="reset" />"Reset"
            </button>
        </div>
    }
}

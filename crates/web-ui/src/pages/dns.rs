//! DNS page: the upstream resolvers Argus uses for its own connections, their modes and cache,
//! live health and RTT, and a "Test upstreams" probe. Not a DNS server.

use leptos::prelude::*;

use crate::api::proxy::UpdateProxyConfigRequest;
use crate::api::ApiClient;
use crate::components::{Card, Layout, Pill, Segmented, Switch};
use crate::state::use_app_state;
use api_types::{DnsDto, DnsStatsResponse, DnsTestResponse, DnsUpdate};

/// Which list a textarea holds; decides what each line may be.
#[derive(Clone, Copy, PartialEq)]
enum ListKind {
    /// Upstreams with optional `[/domain/]` rules.
    Upstreams,
    /// Upstreams without rules.
    Flat,
    /// Plain IP resolvers.
    Plain,
}

/// Errors of one textarea, as `(line number, message)`.
fn list_errors(kind: ListKind, text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, l) in text.lines().enumerate() {
        let r = match kind {
            ListKind::Upstreams => dns_syntax::parse_line(l).err(),
            ListKind::Flat => dns_syntax::parse_flat(&[l]).err().map(|e| e[0].1.clone()),
            ListKind::Plain => dns_syntax::parse_plain(&[l]).err().map(|e| e[0].1.clone()),
        };
        if let Some(e) = r {
            out.push((i + 1, e));
        }
    }
    out
}

/// The lines of a textarea, trimmed, without blanks.
fn lines_of(s: &str) -> Vec<String> {
    s.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

fn subnet_ok(s: &str) -> bool {
    let Some((ip, len)) = s.trim().split_once('/') else {
        return false;
    };
    let (Ok(ip), Ok(len)) = (ip.parse::<std::net::IpAddr>(), len.parse::<u8>()) else {
        return false;
    };
    len >= 1 && len <= if ip.is_ipv4() { 32 } else { 128 }
}

fn num_ok(s: &str, min: u64, max: u64) -> bool {
    s.trim()
        .parse::<u64>()
        .is_ok_and(|n| (min..=max).contains(&n))
}

fn ms(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1} ms")).unwrap_or_else(|| "-".into())
}

/// A textarea with per-line validation messages below it.
#[component]
fn ListBox(
    #[prop(into)] label: String,
    #[prop(into)] help: String,
    #[prop(into)] placeholder: String,
    kind: ListKind,
    value: RwSignal<String>,
    #[prop(optional)] rows: Option<u32>,
) -> impl IntoView {
    let errs = Memo::new(move |_| list_errors(kind, &value.get()));
    let id = format!("dns-{}", label.to_lowercase().replace(' ', "-"));
    view! {
        <div class="field">
            <label for=id.clone()>{label}</label>
            <textarea
                id=id
                class="input"
                rows=rows.unwrap_or(5)
                spellcheck="false"
                placeholder=placeholder
                aria-invalid=move || if errs.with(|e| e.is_empty()) { "false" } else { "true" }
                prop:value=move || value.get()
                on:input=move |ev| value.set(event_target_value(&ev))
            ></textarea>
            <span class="form-help">{help}</span>
            <For
                each=move || errs.get()
                key=|(n, e)| format!("{n}:{e}")
                children=|(n, e)| view! { <span class="err" role="alert">{format!("Line {n}: {e}")}</span> }
            />
        </div>
    }
}

#[derive(Clone, Copy)]
struct Form {
    servers: RwSignal<String>,
    source: RwSignal<String>,
    mode: RwSignal<String>,
    bootstrap: RwSignal<String>,
    fallback: RwSignal<String>,
    private_rdns: RwSignal<bool>,
    private_resolvers: RwSignal<String>,
    cache_size: RwSignal<String>,
    min_ttl: RwSignal<String>,
    max_ttl: RwSignal<String>,
    neg_ttl: RwSignal<String>,
    optimistic: RwSignal<bool>,
    dnssec: RwSignal<bool>,
    ipv6: RwSignal<bool>,
    ecs: RwSignal<String>,
    ecs_subnet: RwSignal<String>,
    timeout: RwSignal<String>,
}

impl Form {
    fn new() -> Self {
        let s = || RwSignal::new(String::new());
        Self {
            servers: s(),
            source: s(),
            mode: RwSignal::new("load_balance".into()),
            bootstrap: s(),
            fallback: s(),
            private_rdns: RwSignal::new(true),
            private_resolvers: s(),
            cache_size: s(),
            min_ttl: s(),
            max_ttl: s(),
            neg_ttl: s(),
            optimistic: RwSignal::new(false),
            dnssec: RwSignal::new(false),
            ipv6: RwSignal::new(true),
            ecs: RwSignal::new("off".into()),
            ecs_subnet: s(),
            timeout: s(),
        }
    }

    fn load(&self, d: &DnsDto) {
        self.servers.set(d.servers.join("\n"));
        self.source.set(d.upstreams_source.clone());
        self.mode.set(d.mode.clone());
        self.bootstrap.set(d.bootstrap.join("\n"));
        self.fallback.set(d.fallback.join("\n"));
        self.private_rdns.set(d.private_rdns);
        self.private_resolvers.set(d.private_resolvers.join("\n"));
        self.cache_size.set(d.cache_size.to_string());
        self.min_ttl.set(d.min_ttl_secs.to_string());
        self.max_ttl.set(d.max_ttl_secs.to_string());
        self.neg_ttl.set(d.negative_ttl_secs.to_string());
        self.optimistic.set(d.optimistic_cache);
        self.dnssec.set(d.dnssec);
        self.ipv6.set(d.ipv6);
        self.ecs.set(d.ecs.clone());
        self.ecs_subnet.set(d.ecs_subnet.clone());
        self.timeout.set(d.timeout_ms.to_string());
    }

    /// First problem that stops a save, if any.
    fn problem(&self) -> Option<String> {
        for (what, kind, text) in [
            ("Upstreams", ListKind::Upstreams, self.servers.get()),
            ("Bootstrap", ListKind::Plain, self.bootstrap.get()),
            ("Fallback", ListKind::Flat, self.fallback.get()),
            ("Private resolvers", ListKind::Plain, self.private_resolvers.get()),
        ] {
            if let Some((n, e)) = list_errors(kind, &text).first() {
                return Some(format!("{what}, line {n}: {e}"));
            }
        }
        if !num_ok(&self.cache_size.get(), 1, 10_000_000) {
            return Some("Cache size must be 1 to 10000000.".into());
        }
        let (min, max) = (self.min_ttl.get(), self.max_ttl.get());
        if !num_ok(&min, 0, 604_800) || !num_ok(&max, 0, 604_800) {
            return Some("TTLs must be whole seconds, at most 7 days.".into());
        }
        if min.trim().parse::<u64>().unwrap_or(0) > max.trim().parse::<u64>().unwrap_or(0) {
            return Some("Minimum TTL must not exceed the maximum.".into());
        }
        if !num_ok(&self.neg_ttl.get(), 0, 86_400) {
            return Some("Failed lookup TTL must be 0 to 86400 seconds.".into());
        }
        if !num_ok(&self.timeout.get(), 100, 60_000) {
            return Some("Timeout must be 100 to 60000 ms.".into());
        }
        if self.ecs.get() == "custom" && !subnet_ok(&self.ecs_subnet.get()) {
            return Some("Custom ECS needs a subnet like 203.0.113.0/24.".into());
        }
        None
    }

    fn update(&self) -> DnsUpdate {
        let n = |s: RwSignal<String>| s.get().trim().parse::<u64>().ok();
        DnsUpdate {
            servers: Some(lines_of(&self.servers.get())),
            upstreams_source: Some(self.source.get().trim().to_string()),
            mode: Some(self.mode.get()),
            bootstrap: Some(lines_of(&self.bootstrap.get())),
            fallback: Some(lines_of(&self.fallback.get())),
            private_rdns: Some(self.private_rdns.get()),
            private_resolvers: Some(lines_of(&self.private_resolvers.get())),
            cache_size: n(self.cache_size),
            min_ttl_secs: n(self.min_ttl),
            max_ttl_secs: n(self.max_ttl),
            negative_ttl_secs: n(self.neg_ttl),
            optimistic_cache: Some(self.optimistic.get()),
            dnssec: Some(self.dnssec.get()),
            ipv6: Some(self.ipv6.get()),
            ecs: Some(self.ecs.get()),
            ecs_subnet: Some(self.ecs_subnet.get().trim().to_string()),
            timeout_ms: n(self.timeout),
        }
    }
}

fn field(label: &'static str, value: RwSignal<String>, ph: &'static str) -> impl IntoView {
    view! { <crate::components::Input label=label placeholder=ph value=value /> }
}

fn toggle(label: &'static str, help: &'static str, sig: RwSignal<bool>) -> impl IntoView {
    view! {
        <div class="field">
            <Switch
                checked=sig
                on_change=Callback::new(move |v| sig.set(v))
                label=label
                text=Signal::derive(move || label.to_string())
            />
            <span class="form-help">{help}</span>
        </div>
    }
}

#[component]
pub fn DnsPage() -> impl IntoView {
    let app = use_app_state();
    let form = Form::new();
    let busy = RwSignal::new(false);
    let testing = RwSignal::new(false);
    let stats = RwSignal::new(DnsStatsResponse::default());
    let tested = RwSignal::new(Option::<DnsTestResponse>::None);
    let test_err = RwSignal::new(Option::<String>::None);

    {
        let app = app.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().get_proxy_config().await {
                Ok(c) => {
                    form.load(&c.dns);
                }
                Err(e) => app.error(format!("Failed to load DNS settings: {e}")),
            }
        });
    }

    let alive = StoredValue::new(true);
    on_cleanup(move || alive.set_value(false));
    wasm_bindgen_futures::spawn_local(async move {
        while alive.get_value() {
            if let Ok(s) = ApiClient::new()
                .get::<DnsStatsResponse>("/config/dns/stats")
                .await
            {
                stats.set(s);
            }
            gloo_timers::future::TimeoutFuture::new(5_000).await;
        }
    });

    let problem = Memo::new(move |_| form.problem());

    let save = {
        let app = app.clone();
        move |_| {
            if problem.get().is_some() {
                return;
            }
            busy.set(true);
            let (app, req) = (app.clone(), form.update());
            wasm_bindgen_futures::spawn_local(async move {
                let r = UpdateProxyConfigRequest {
                    dns: Some(req),
                    ..Default::default()
                };
                match ApiClient::new().update_proxy_config_full(&r).await {
                    Ok(res) => {
                        form.load(&res.config.dns);
                        app.success(if res.applied.iter().any(|a| a == "dns") {
                            "DNS settings applied"
                        } else {
                            "DNS settings saved"
                        });
                    }
                    Err(e) => app.error(format!("Failed to save DNS settings: {e}")),
                }
                busy.set(false);
            });
        }
    };

    let test = move |_| {
        if problem.get().is_some() {
            return;
        }
        testing.set(true);
        test_err.set(None);
        let req = form.update();
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new()
                .post::<DnsTestResponse, _>("/config/dns/test", &req)
                .await
            {
                Ok(r) => tested.set(Some(r)),
                Err(e) => {
                    tested.set(None);
                    test_err.set(Some(e.to_string()));
                }
            }
            testing.set(false);
        });
    };

    let mode_opts = vec![
        ("load_balance".to_string(), "Load balance".to_string()),
        ("parallel".to_string(), "Parallel".to_string()),
        ("fastest_ip".to_string(), "Fastest address".to_string()),
    ];
    let ecs_opts = vec![
        ("off".to_string(), "Off".to_string()),
        ("auto".to_string(), "Auto".to_string()),
        ("custom".to_string(), "Custom".to_string()),
    ];

    view! {
        <Layout>
            <div class="page-header">
                <h1 class="page-title">"DNS"</h1>
            </div>
            <p class="form-help">
                "How Argus resolves names for its own connections to websites. It is not a DNS server and does not filter by DNS; blocking happens on the requests themselves."
            </p>
            <div class="settings-grid">
                <Card title="Upstream servers" sub="One per line, AdGuard syntax. Empty uses the system resolver." class="settings-card">
                    <ListBox
                        label="Upstreams"
                        help="1.1.1.1, tcp://, tls://, https://, h3://, quic://, sdns:// stamps. [/example.com/]10.0.0.1 sends one domain elsewhere; [/lan/]# uses the defaults for it."
                        placeholder="tls://dns.google\nhttps://cloudflare-dns.com/dns-query\n[/corp.example/]10.0.0.1"
                        kind=ListKind::Upstreams
                        value=form.servers
                        rows=7
                    />
                    {field("Upstreams file or URL (optional)", form.source, "/etc/argus/upstreams.txt or https://...")}
                    <div class="field">
                        <label>"Mode"</label>
                        <Segmented
                            options=mode_opts
                            value=form.mode
                            on_change=Callback::new(move |v| form.mode.set(v))
                            label="Upstream mode"
                        />
                        <span class="form-help">
                            {move || match form.mode.get().as_str() {
                                "parallel" => "Every upstream is asked at once; the first answer wins.",
                                "fastest_ip" => "Every upstream is asked; Argus then races connections to the returned addresses and uses the fastest.",
                                _ => "One upstream per query, chosen at random weighted by how fast it has been. Others are tried if it fails.",
                            }}
                        </span>
                    </div>
                    {field("Timeout per upstream (ms)", form.timeout, "5000")}
                </Card>

                <Card title="Bootstrap, fallback and private" sub="Plain IPs and where to go when things fail." class="settings-card">
                    <ListBox
                        label="Bootstrap DNS"
                        help="Plain IP resolvers used only to find the addresses of encrypted upstreams (tls://dns.google). Empty uses the system resolver for that."
                        placeholder="1.1.1.1\n9.9.9.9"
                        kind=ListKind::Plain
                        value=form.bootstrap
                        rows=3
                    />
                    <ListBox
                        label="Fallback DNS"
                        help="Used only when every upstream above fails. Empty: the lookup fails, and the system resolver is not used."
                        placeholder="9.9.9.9"
                        kind=ListKind::Flat
                        value=form.fallback
                        rows=3
                    />
                    {toggle("Private reverse resolvers", "Send reverse (PTR) lookups and LAN names (.lan, .local, private reverse zones) to the resolvers below.", form.private_rdns)}
                    <ListBox
                        label="Private resolvers"
                        help="Plain IPs, e.g. your router. Empty uses the system resolver for those names."
                        placeholder="192.168.1.1"
                        kind=ListKind::Plain
                        value=form.private_resolvers
                        rows=3
                    />
                </Card>

                <Card title="Cache" sub="Answers are kept for their TTL, within these limits." class="settings-card">
                    {field("Cache size (names)", form.cache_size, "4096")}
                    {field("Minimum TTL (s)", form.min_ttl, "10")}
                    {field("Maximum TTL (s)", form.max_ttl, "300")}
                    {field("Failed lookup TTL (s)", form.neg_ttl, "10")}
                    {toggle("Optimistic caching", "Answer from an expired cache entry at once and refresh it in the background.", form.optimistic)}
                </Card>

                <Card title="Options" class="settings-card">
                    {toggle("DNSSEC validation", "Refuse answers that fail validation. Names in unsigned zones still resolve.", form.dnssec)}
                    {toggle("IPv6 (AAAA)", "Off: only IPv4 addresses are used.", form.ipv6)}
                    <div class="field">
                        <label>"EDNS client subnet"</label>
                        <Segmented
                            options=ecs_opts
                            value=form.ecs
                            on_change=Callback::new(move |v| form.ecs.set(v))
                            label="EDNS client subnet"
                        />
                        <span class="form-help">"Auto sends this machine's public /24 (or /56), when it has one. Custom sends the subnet below."</span>
                    </div>
                    <Show when=move || form.ecs.get() == "custom">
                        {field("Custom subnet", form.ecs_subnet, "203.0.113.0/24")}
                    </Show>
                </Card>
            </div>

            <div class="modal-actions">
                <button class="btn btn-primary" disabled=move || busy.get() || problem.get().is_some() on:click=save>"Save and apply"</button>
                <button class="btn" disabled=move || testing.get() || problem.get().is_some() on:click=test>
                    {move || if testing.get() { "Testing..." } else { "Test upstreams" }}
                </button>
                {move || problem.get().map(|p| view! { <span class="err" role="alert">{p}</span> })}
            </div>
            {move || test_err.get().map(|m| view! { <p class="err" role="alert">{m}</p> })}
            {move || tested.get().map(|t| view! {
                <Card title="Test results" sub=format!("Looked up {} through each upstream.", t.name) class="settings-card">
                    <div class="tbl-wrap">
                        <table class="tbl">
                            <thead><tr><th>"Upstream"</th><th>"Role"</th><th>"Result"</th><th>"Latency"</th><th>"Answer"</th></tr></thead>
                            <tbody>
                                {t.results.into_iter().map(|r| view! {
                                    <tr>
                                        <td class="mono">{r.upstream}</td>
                                        <td>{r.role}</td>
                                        <td>{if r.ok { view! { <Pill kind="ok" text="ok" /> }.into_any() } else { view! { <Pill kind="error" text="failed" /> }.into_any() }}</td>
                                        <td>{ms(r.latency_ms)}</td>
                                        <td class="mono">{match r.error { Some(e) => e, None => r.answers.join(", ") }}</td>
                                    </tr>
                                }).collect_view()}
                            </tbody>
                        </table>
                    </div>
                </Card>
            })}

            <Card title="Upstream health" sub="Updates every few seconds." class="settings-card">
                <Show
                    when=move || !stats.with(|s| s.upstreams.is_empty())
                    fallback=|| view! { <p class="form-help">"No upstreams configured: the system resolver is in use."</p> }
                >
                    <div class="tbl-wrap">
                        <table class="tbl">
                            <thead><tr><th>"Upstream"</th><th>"Role"</th><th>"State"</th><th>"RTT"</th><th>"Queries"</th><th>"Failures"</th><th>"Last error"</th></tr></thead>
                            <tbody>
                                <For
                                    each=move || stats.get().upstreams
                                    key=|u| format!("{}|{}", u.role, u.upstream)
                                    children=|u| view! {
                                        <tr>
                                            <td class="mono">{u.upstream.clone()}</td>
                                            <td>{u.role.clone()}</td>
                                            <td>{if u.healthy { view! { <Pill kind="ok" text="healthy" /> }.into_any() } else { view! { <Pill kind="error" text="failing" /> }.into_any() }}</td>
                                            <td>{ms(u.rtt_ms)}</td>
                                            <td>{u.queries}</td>
                                            <td>{u.failures}</td>
                                            <td class="dim">{u.last_error.clone().unwrap_or_default()}</td>
                                        </tr>
                                    }
                                />
                            </tbody>
                        </table>
                    </div>
                </Show>
                <p class="form-help">
                    {move || {
                        let s = stats.get();
                        format!("Cache: {} names, {} hits, {} lookups sent upstream.", s.cached_names, s.cache_hits, s.cache_misses)
                    }}
                </p>
            </Card>
        </Layout>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_validation_follows_the_list_kind() {
        let ups = "# note\n1.1.1.1\ntls://dns.google\n[/lan/]#\nnope\n[/a.com/]";
        let e = list_errors(ListKind::Upstreams, ups);
        assert_eq!(e.iter().map(|x| x.0).collect::<Vec<_>>(), [5]);
        assert!(list_errors(ListKind::Flat, "[/a.com/]1.1.1.1")[0].1.contains("rules"));
        assert!(list_errors(ListKind::Flat, "tls://dns.google").is_empty());
        assert!(list_errors(ListKind::Plain, "1.1.1.1\n8.8.8.8:53").is_empty());
        assert_eq!(list_errors(ListKind::Plain, "tls://dns.google").len(), 1);
        assert!(list_errors(ListKind::Upstreams, "").is_empty());
    }

    #[test]
    fn numbers_and_subnets() {
        assert!(subnet_ok("203.0.113.0/24"));
        assert!(subnet_ok("2001:db8::/56"));
        assert!(!subnet_ok("203.0.113.0"));
        assert!(!subnet_ok("203.0.113.0/33"));
        assert!(!subnet_ok("203.0.113.0/0"));
        assert!(num_ok("100", 1, 200) && !num_ok("0", 1, 200) && !num_ok("x", 1, 200));
        assert_eq!(lines_of(" a \n\n b\n"), ["a", "b"]);
    }
}

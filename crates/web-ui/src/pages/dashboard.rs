//! Dashboard: tiles, block-rate sparkline, top blocked hosts, system status.

use leptos::prelude::*;

use crate::api::ApiClient;
use crate::components::{Layout, Pill, Segmented, Tile};
use crate::utils::format_number;

fn fmt_uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else {
        format!("{h}h {m}m")
    }
}

/// SVG sparkline (percent values 0..100) with a baseline, a gridline and a last-point marker.
fn sparkline(points: &[f64]) -> impl IntoView {
    const W: f64 = 720.0;
    const H: f64 = 168.0;
    const PAD: f64 = 24.0;
    let max = points.iter().cloned().fold(10.0_f64, f64::max).ceil();
    let n = points.len().max(2) as f64;
    let x = |i: usize| PAD + (W - 2.0 * PAD) * (i as f64) / (n - 1.0);
    let y = |v: f64| H - PAD - (H - 2.0 * PAD) * (v / max);
    let line: String = points
        .iter()
        .enumerate()
        .map(|(i, v)| {
            format!(
                "{}{:.1},{:.1}",
                if i == 0 { "M" } else { " L" },
                x(i),
                y(*v)
            )
        })
        .collect();
    let area = if points.is_empty() {
        String::new()
    } else {
        format!(
            "{line} L{:.1},{:.1} L{:.1},{:.1} Z",
            x(points.len() - 1),
            H - PAD,
            x(0),
            H - PAD
        )
    };
    let last = points.last().copied();
    let label = last
        .map(|v| format!("Block rate over the sampled period, currently {v:.1} percent"))
        .unwrap_or_else(|| "Block rate: waiting for samples".to_string());
    view! {
        <svg class="spark" viewBox="0 0 720 168" role="img" aria-label=label>
            <line x1=PAD y1=H - PAD x2=W - PAD y2=H - PAD stroke="var(--line-strong)" />
            <line x1=PAD y1=y(max / 2.0) x2=W - PAD y2=y(max / 2.0) stroke="var(--line)" stroke-dasharray="3 4" />
            <text x="2" y=y(max) + 4.0>{format!("{max:.0}%")}</text>
            <text x="2" y=y(max / 2.0) + 4.0>{format!("{:.0}%", max / 2.0)}</text>
            <text x="2" y=H - PAD + 4.0>"0%"</text>
            <path d=area fill="var(--accent-soft)" stroke="none" />
            <path d=line fill="none" stroke="var(--accent)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />
            {last.map(|v| view! {
                <circle cx=x(points.len() - 1) cy=y(v) r="3.5" fill="var(--accent)" />
            })}
        </svg>
    }
}

#[component]
pub fn DashboardPage() -> impl IntoView {
    let total = RwSignal::new(0u64);
    let blocked = RwSignal::new(0u64);
    let ready = RwSignal::new(false);
    let active = RwSignal::new(0u64);
    let errors = RwSignal::new(0u64);
    let uptime = RwSignal::new(String::from("-"));
    let tops = RwSignal::new(Vec::<(String, u64)>::new());
    let series = RwSignal::new(Vec::<f64>::new());
    let range = RwSignal::new("24h".to_string());
    let clients = RwSignal::new(0u64);
    {
        let alive = StoredValue::new(true);
        on_cleanup(move || alive.set_value(false));
        Effect::new(move |_| {
            let r = range.get();
            wasm_bindgen_futures::spawn_local(async move {
                let c = ApiClient::new();
                if let Ok(t) = c
                    .get::<api_types::TimeseriesResponse>(&format!("/stats/timeseries?range={r}"))
                    .await
                {
                    series.set(
                        t.points
                            .iter()
                            .map(|p| {
                                if p.requests == 0 {
                                    0.0
                                } else {
                                    p.blocked as f64 * 100.0 / p.requests as f64
                                }
                            })
                            .collect(),
                    );
                }
            });
        });
        wasm_bindgen_futures::spawn_local(async move {
            while alive.get_value() {
                gloo_timers::future::TimeoutFuture::new(30_000).await;
                let r = range.get_untracked();
                if let Ok(t) = ApiClient::new()
                    .get::<api_types::TimeseriesResponse>(&format!("/stats/timeseries?range={r}"))
                    .await
                {
                    series.set(
                        t.points
                            .iter()
                            .map(|p| {
                                if p.requests == 0 {
                                    0.0
                                } else {
                                    p.blocked as f64 * 100.0 / p.requests as f64
                                }
                            })
                            .collect(),
                    );
                }
            }
        });
    }
    let explicit = RwSignal::new(String::from("-"));
    let transparent = RwSignal::new(Option::<String>::None);
    let engine = RwSignal::new(Option::<(bool, bool)>::None); // (enabled, building)
    let scripts = RwSignal::new(String::from("-"));
    let version = RwSignal::new(String::new());

    let alive = StoredValue::new(true);
    on_cleanup(move || alive.set_value(false));
    wasm_bindgen_futures::spawn_local(async move {
        let client = ApiClient::new();
        if let Ok(c) = client.get_proxy_config().await {
            let addr = c.bind.as_ref().and_then(|b| b.proxy.clone());
            explicit.set(addr.unwrap_or_else(|| format!("{}:{}", c.host, c.port)));
        }
        if let Ok(s) = client.get_userscript_stats().await {
            scripts.set(format_number(s.total_scripts as u64));
        }
        while alive.get_value() {
            if let Ok(p) = client.get_proxy_stats().await {
                active.set(p.connections.active);
                clients.set(p.explicit.clients + p.transparent.counters.clients);
                errors.set(p.requests.errors);
                transparent.set(if p.transparent.enabled {
                    Some(p.transparent.address.unwrap_or_default())
                } else {
                    None
                });
            }
            if let Ok(s) = client
                .get::<api_types::SystemStatusResponse>("/system/status")
                .await
            {
                uptime.set(fmt_uptime(s.uptime_secs));
                version.set(s.version);
                engine.set(Some((s.engine.enabled, s.engine.building)));
            }
            if let Ok(f) = client.get_filter_stats().await {
                total.set(f.total_requests);
                blocked.set(f.blocked_requests);
                tops.set(
                    f.top_blocked_domains
                        .iter()
                        .take(8)
                        .map(|d| (d.domain.clone(), d.count))
                        .collect(),
                );
                ready.set(true);
            }
            gloo_timers::future::TimeoutFuture::new(15_000).await;
        }
    });

    let user = crate::state::use_auth_state().user;
    let logs_ok = Signal::derive(move || {
        user.get()
            .map(|u| u.scopes.iter().any(|s| s.as_str() == "logs:read"))
            .unwrap_or(false)
    });
    let rate = Signal::derive(move || {
        let t = total.get();
        if t == 0 {
            "0.0%".to_string()
        } else {
            format!("{:.1}%", blocked.get() as f64 * 100.0 / t as f64)
        }
    });
    let top_max = Memo::new(move |_| tops.read().iter().map(|t| t.1).max().unwrap_or(1).max(1));

    view! {
        <Layout>
            <div class="tiles">
                <Tile label="Requests" value=Signal::derive(move || format_number(total.get())) detail="since engine start" />
                <Tile label="Blocked" value=Signal::derive(move || format_number(blocked.get())) color="color:var(--block)" detail="matched a rule" />
                <Tile label="Block rate" value=rate detail="of all requests" />
                <Tile label="Connections" value=Signal::derive(move || format_number(active.get())) detail="open now" />
                <Tile label="Clients" value=Signal::derive(move || format_number(clients.get())) detail="seen recently" />
                <Tile label="Userscripts" value=scripts detail="installed" />
                <Tile label="Upstream errors" value=Signal::derive(move || format_number(errors.get())) detail="failed requests" />
            </div>

            <div class="card">
                <div class="card-h">
                    <h3>"Block rate"</h3>
                    <span class="sub">"share of requests blocked, per time bucket"</span>
                    <div class="r">
                        <Segmented
                            label="Range"
                            options=vec![("6h".into(), "6h".into()), ("24h".into(), "24h".into()), ("7d".into(), "7d".into())]
                            value=range
                            on_change=Callback::new(move |v| range.set(v))
                        />
                    </div>
                </div>
                <div class="spark-wrap">
                    {move || {
                        let s = series.get();
                        if s.len() < 2 {
                            view! { <div class="empty"><b>"Collecting samples"</b>"History starts at the last restart and fills in as requests flow."</div> }.into_any()
                        } else {
                            sparkline(&s).into_any()
                        }
                    }}
                </div>
            </div>

            <div class="grid2">
                <div class="card">
                    <div class="card-h">
                        <h3>"Top blocked hosts"</h3>
                        <span class="sub">"since engine start"</span>
                        <div class="r">
                            <Show when=move || logs_ok.get()>
                                <a class="btn ghost sm" href="/logs?action=blocked">"Open in logs"</a>
                            </Show>
                        </div>
                    </div>
                    <div class="card-b">
                        <Show when=move || !tops.read().is_empty() fallback=|| view! { <div class="empty"><b>"Nothing blocked yet"</b></div> }>
                            <ul class="toplist">
                                <For each=move || tops.get() key=|t| t.0.clone() children=move |(host, n)| {
                                    let pct = move || n * 100 / top_max.get();
                                    view! {
                                        <li>
                                            <div style="min-width:0">
                                                <div class="h mono">{host}</div>
                                                <div class="bar"><i style=move || format!("width:{}%", pct())></i></div>
                                            </div>
                                            <span class="num mono" style="text-align:right">{format_number(n)}</span>
                                        </li>
                                    }
                                } />
                            </ul>
                        </Show>
                    </div>
                </div>
                <div class="card">
                    <div class="card-h"><h3>"System status"</h3></div>
                    <div class="card-b">
                        <dl class="statusgrid">
                            <dt>"Explicit"</dt>
                            <dd><Pill kind="allowed" text="listening" /><span class="mono">{move || explicit.get()}</span></dd>
                            <dt>"Transparent"</dt>
                            <dd>{move || match transparent.get() {
                                Some(a) => view! { <Pill kind="allowed" text="listening" /><span class="mono">{a}</span> }.into_any(),
                                None => view! { <Pill kind="neutral" text="off" /> }.into_any(),
                            }}</dd>
                            <dt>"Engine"</dt>
                            <dd>{move || match engine.get() {
                                Some((_, true)) => view! { <Pill kind="error" text="building" /> }.into_any(),
                                Some((true, false)) => view! { <Pill kind="allowed" text="ready" /> }.into_any(),
                                Some((false, false)) => view! { <Pill kind="neutral" text="disabled" /> }.into_any(),
                                None => view! { <span class="dim">"-"</span> }.into_any(),
                            }}</dd>
                            <dt>"Version"</dt><dd class="mono">{move || version.get()}</dd>
                            <dt>"Uptime"</dt><dd class="num">{move || uptime.get()}</dd>
                        </dl>
                    </div>
                </div>
            </div>
        </Layout>
    }
}

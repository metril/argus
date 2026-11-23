//! Live request log: SSE stream, bounded buffer, windowed rendering, filters, pause, detail drawer.

use leptos::prelude::*;
use leptos_router::hooks::use_query_map;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::api::logs::{LogAction, LogMode, RequestLogEntry};
use crate::api::{client::API_PREFIX, ApiClient, ApiError};
use crate::components::{CertPanel, ChipSelect, Drawer, Icon, Layout, Pill, Segmented};
use crate::state::{use_app_state, use_auth_state};
use crate::utils::{
    api_base_url, copy_text, fmt_datetime, fmt_time, split_url, url_host, url_hostport,
};

/// Entries kept in memory.
const BUFFER_MAX: usize = 2000;
/// Rows rendered at once.
const RENDER_MAX: usize = 150;

#[derive(Clone)]
struct Row {
    id: u64,
    e: RequestLogEntry,
}

fn action_key(a: LogAction) -> &'static str {
    match a {
        LogAction::Allowed => "allowed",
        LogAction::Blocked => "blocked",
        LogAction::Passthrough => "passthrough",
        LogAction::Error => "error",
    }
}

fn parse_action(s: &str) -> Option<LogAction> {
    match s {
        "allowed" => Some(LogAction::Allowed),
        "blocked" => Some(LogAction::Blocked),
        "passthrough" => Some(LogAction::Passthrough),
        "error" => Some(LogAction::Error),
        _ => None,
    }
}

fn error_kind_label(k: api_types::LogErrorKind) -> &'static str {
    use api_types::LogErrorKind::*;
    match k {
        ClientRejectedCert => {
            "The client rejected Argus's certificate (likely certificate pinning)"
        }
        UpstreamTimeout => "The upstream server timed out",
        UpstreamReset => "The upstream server reset the connection",
        UpstreamTls => "TLS to the upstream server failed",
        Other => "Other error",
    }
}

fn action_text(a: LogAction) -> &'static str {
    match a {
        LogAction::Passthrough => "bypassed",
        other => action_key(other),
    }
}

/// Human text for the matched rule. Tunnels carry the bypass source in `rule`.
fn rule_label(action: LogAction, rule: Option<&str>) -> String {
    match (action, rule) {
        (_, None) | (_, Some("")) => "-".into(),
        (LogAction::Passthrough, Some("ev")) => "bypass: EV certificate".into(),
        (LogAction::Passthrough, Some("failsafe")) => "bypass: fail-safe (lists not loaded)".into(),
        (LogAction::Passthrough, Some(src)) => format!("bypass: {src}"),
        (_, Some(r)) => r.to_string(),
    }
}

fn mode_key(m: LogMode) -> &'static str {
    match m {
        LogMode::Explicit => "explicit",
        LogMode::Transparent => "transparent",
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Stream {
    Live,
    Reconnecting,
}

type MsgHandlers = Vec<Closure<dyn FnMut(web_sys::MessageEvent)>>;
type ErrHandler = Option<Closure<dyn FnMut(web_sys::Event)>>;

#[derive(Clone)]
struct StreamCtx {
    buffer: RwSignal<Vec<Row>>,
    pending: RwSignal<Vec<Row>>,
    paused: RwSignal<bool>,
    stream: RwSignal<Stream>,
    next_id: StoredValue<u64>,
    es_store: StoredValue<Option<web_sys::EventSource>, LocalStorage>,
    handlers: StoredValue<MsgHandlers, LocalStorage>,
    err_handler: StoredValue<ErrHandler, LocalStorage>,
    notice: RwSignal<Option<String>>,
    alive: StoredValue<bool>,
    /// Set once the stream has opened; a later open is a reconnect.
    ever_open: StoredValue<bool>,
    app: crate::state::AppState,
    auth_user: RwSignal<Option<api_types::UserInfo>>,
}

/// Identity of a log entry (the server gives none): the same request seen via the stream and
/// via a re-seed must produce the same key.
fn entry_key(e: &RequestLogEntry) -> String {
    format!(
        "{}|{}|{}|{}|{:?}",
        e.ts,
        e.method,
        e.url,
        action_key(e.action),
        e.status
    )
}

/// After a reconnect, fetch what the gap missed (`since` the newest entry held) and merge it,
/// skipping entries already held, keeping newest-first order.
fn reseed(ctx: &StreamCtx) {
    let StreamCtx {
        buffer,
        pending,
        paused,
        next_id,
        app,
        ..
    } = ctx.clone();
    let newest = |rows: &[Row]| {
        rows.iter()
            .map(|r| r.e.ts.clone())
            .max_by(|a, b| js_sys::Date::parse(a).total_cmp(&js_sys::Date::parse(b)))
    };
    let since = [
        buffer.with_untracked(|b| newest(b)),
        pending.with_untracked(|b| newest(b)),
    ]
    .into_iter()
    .flatten()
    .max_by(|a, b| js_sys::Date::parse(a).total_cmp(&js_sys::Date::parse(b)));
    wasm_bindgen_futures::spawn_local(async move {
        let c = ApiClient::new();
        let r = match &since {
            Some(s) => c.get_request_log_since(s, 1000).await,
            None => c.get_request_log(300).await,
        };
        match r {
            Ok(r) => {
                let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
                buffer.with_untracked(|b| seen.extend(b.iter().map(|r| entry_key(&r.e))));
                pending.with_untracked(|b| seen.extend(b.iter().map(|r| entry_key(&r.e))));
                let fresh: Vec<Row> = r
                    .entries
                    .into_iter()
                    .filter(|e| seen.insert(entry_key(e)))
                    .map(|e| {
                        let id = next_id.get_value();
                        next_id.set_value(id + 1);
                        Row { id, e }
                    })
                    .collect();
                if fresh.is_empty() {
                    return;
                }
                let target = if paused.get_untracked() {
                    pending
                } else {
                    buffer
                };
                target.update(|b| {
                    b.extend(fresh);
                    b.sort_by_cached_key(|r| {
                        // Newest first; ties keep their order (the sort is stable).
                        std::cmp::Reverse((js_sys::Date::parse(&r.e.ts) * 1000.0) as i64)
                    });
                    b.truncate(BUFFER_MAX);
                });
            }
            Err(e) => app.error(format!("Failed to recover missed requests: {e}")),
        }
    });
}

/// Open the SSE stream. When the browser closes it for good (expired cookie, refused stream),
/// refresh the session and reconnect with exponential backoff (1s up to 30s). A dead session
/// ends on the login page.
fn open_stream(ctx: StreamCtx, attempt: u32) {
    let StreamCtx {
        buffer,
        pending,
        paused,
        stream,
        next_id,
        es_store,
        handlers,
        err_handler,
        notice,
        alive,
        ..
    } = ctx;
    let url = format!("{}{}/logs/stream", api_base_url(), API_PREFIX);
    let init = web_sys::EventSourceInit::new();
    init.set_with_credentials(true);
    let Ok(es) = web_sys::EventSource::new_with_event_source_init_dict(&url, &init) else {
        return;
    };
    let opened = StoredValue::new(false);
    let on_request =
        Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |ev: web_sys::MessageEvent| {
            let Some(data) = ev.data().as_string() else {
                return;
            };
            let Ok(entry) = serde_json::from_str::<RequestLogEntry>(&data) else {
                return;
            };
            stream.set(Stream::Live);
            let id = next_id.get_value();
            next_id.set_value(id + 1);
            let row = Row { id, e: entry };
            if paused.get_untracked() {
                pending.update(|p| {
                    p.insert(0, row);
                    p.truncate(BUFFER_MAX);
                });
            } else {
                buffer.update(|b| {
                    b.insert(0, row);
                    b.truncate(BUFFER_MAX);
                });
            }
        });
    let app2 = ctx.app.clone();
    let on_lagged =
        Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |ev: web_sys::MessageEvent| {
            let n = ev
                .data()
                .as_string()
                .and_then(|d| serde_json::from_str::<serde_json::Value>(&d).ok())
                .and_then(|v| v["skipped"].as_u64())
                .unwrap_or(0);
            app2.warning(format!(
                "The stream fell behind; {n} requests were skipped."
            ));
        });
    let ctx_open = ctx.clone();
    let on_open =
        Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |_ev: web_sys::MessageEvent| {
            opened.set_value(true);
            if ctx_open.ever_open.get_value() {
                reseed(&ctx_open);
            }
            ctx_open.ever_open.set_value(true);
            notice.set(None);
            stream.set(Stream::Live);
        });
    let es2 = es.clone();
    let ctx2 = ctx.clone();
    let on_err = Closure::<dyn FnMut(web_sys::Event)>::new(move |_ev: web_sys::Event| {
        stream.set(Stream::Reconnecting);
        // CONNECTING (0) means the browser is retrying by itself; CLOSED (2) is final.
        if es2.ready_state() != web_sys::EventSource::CLOSED || !alive.get_value() {
            return;
        }
        es2.set_onerror(None);
        let was_open = opened.get_value();
        let delay = (1000u32 << attempt.min(5)).min(30_000);
        let ctx3 = ctx2.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let client = ApiClient::new();
            // `me()` refreshes the access token on 401; a dead refresh token surfaces as Unauthorized.
            match client.me().await {
                Err(ApiError::Unauthorized) => {
                    ctx3.auth_user.set(None);
                    return;
                }
                Err(ApiError::RateLimited) => {
                    ctx3.notice.set(Some(format!(
                        "Too many requests. Retrying in {}s.",
                        delay / 1000
                    )));
                }
                _ if !was_open => {
                    ctx3.notice.set(Some(format!(
                        "The server refused the stream (too many open log streams, or no access). Retrying in {}s.",
                        delay / 1000
                    )));
                }
                _ => {
                    ctx3.notice.set(Some(format!(
                        "Stream lost. Reconnecting in {}s.",
                        delay / 1000
                    )));
                }
            }
            gloo_timers::future::TimeoutFuture::new(delay).await;
            if ctx3.alive.get_value() {
                // A stream that opened and then dropped restarts the backoff.
                open_stream(ctx3, if was_open { 0 } else { attempt + 1 });
            }
        });
    });
    let _ = es.add_event_listener_with_callback("request", on_request.as_ref().unchecked_ref());
    let _ = es.add_event_listener_with_callback("lagged", on_lagged.as_ref().unchecked_ref());
    let _ = es.add_event_listener_with_callback("open", on_open.as_ref().unchecked_ref());
    es.set_onerror(Some(on_err.as_ref().unchecked_ref()));
    es_store.update_value(|old| {
        if let Some(o) = old.take() {
            o.set_onerror(None);
            o.close();
        }
        *old = Some(es);
    });
    handlers.set_value(vec![on_request, on_lagged, on_open]);
    err_handler.set_value(Some(on_err));
}

/// "Bypass this site" with a mode picker; for failed tunnels, a pinned-certificate hint.
fn bypass_section(
    action: LogAction,
    error_kind: Option<api_types::LogErrorKind>,
    host: String,
    mode: RwSignal<String>,
    add: Callback<String>,
) -> impl IntoView {
    if action == LogAction::Passthrough {
        return view! {
            <div class="hint">"This connection is bypassed. Manage the rules on the "<a href="/bypass" style="color:var(--accent)">"Bypass page"</a>"."</div>
        }
        .into_any();
    }
    let pinned = action == LogAction::Error
        && error_kind == Some(api_types::LogErrorKind::ClientRejectedCert);
    let h2 = host.clone();
    view! {
        {pinned.then(|| view! {
            <div class="suggest" role="note">
                <span>"This app pins its certificate, so it rejects Argus. Bypass it? "<b class="mono">{h2.clone()}</b>"."</span>
            </div>
        })}
        <div class="field">
            <span class="lbl">"Bypass this site"</span>
            <Segmented
                label="Bypass mode"
                options=vec![("no_decrypt".to_string(), "Don't decrypt".to_string()), ("full".to_string(), "Bypass entirely".to_string())]
                value=mode
                on_change=Callback::new(move |v| mode.set(v))
            />
            <div><button class="btn sm" type="button" on:click=move |_| add.run(host.clone())>"Bypass "{h2.clone()}</button></div>
        </div>
    }
    .into_any()
}

#[component]
pub fn LogsPage() -> impl IntoView {
    let app = use_app_state();
    let query = use_query_map();

    let buffer = RwSignal::new(Vec::<Row>::new()); // newest first
    let pending = RwSignal::new(Vec::<Row>::new()); // arrived while paused, newest first
    let paused = RwSignal::new(false);
    let stream = RwSignal::new(Stream::Reconnecting);
    let next_id = StoredValue::new(0u64);

    // Filters
    let initial: Vec<LogAction> = match query.get_untracked().get("action") {
        Some(a) => parse_action(&a).into_iter().collect(),
        None => vec![
            LogAction::Allowed,
            LogAction::Blocked,
            LogAction::Passthrough,
            LogAction::Error,
        ],
    };
    let actions = RwSignal::new(if initial.is_empty() {
        vec![LogAction::Blocked]
    } else {
        initial
    });
    let q = RwSignal::new(String::new());
    let mode = RwSignal::new(String::new());
    let client = RwSignal::new(String::new());
    let selected = RwSignal::new(Option::<Row>::None);
    let drawer_open = RwSignal::new(false);

    let alloc = move |e: RequestLogEntry| -> Row {
        let id = next_id.get_value();
        next_id.set_value(id + 1);
        Row { id, e }
    };

    // Seed with history, then connect the stream.
    {
        let app = app.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().get_request_log(300).await {
                Ok(r) => {
                    // API returns newest first.
                    let rows: Vec<Row> = r.entries.into_iter().map(alloc).collect();
                    buffer.update(|b| {
                        let live = std::mem::take(b);
                        *b = live;
                        b.extend(rows);
                        b.truncate(BUFFER_MAX);
                    });
                }
                Err(e) => app.error(format!("Failed to load request history: {e}")),
            }
        });
    }

    let es_store = StoredValue::new_local(None::<web_sys::EventSource>);
    let handlers = StoredValue::new_local(Vec::<Closure<dyn FnMut(web_sys::MessageEvent)>>::new());
    let err_handler = StoredValue::new_local(None::<Closure<dyn FnMut(web_sys::Event)>>);
    let notice = RwSignal::new(Option::<String>::None);
    let alive = StoredValue::new(true);
    let ctx = StreamCtx {
        buffer,
        pending,
        paused,
        stream,
        next_id,
        es_store,
        handlers,
        err_handler,
        notice,
        alive,
        ever_open: StoredValue::new(false),
        app: app.clone(),
        auth_user: use_auth_state().user,
    };
    open_stream(ctx, 0);
    on_cleanup(move || {
        alive.set_value(false);
        es_store.update_value(|es| {
            if let Some(es) = es.take() {
                es.set_onerror(None);
                es.close();
            }
        });
    });

    let set_paused = move |p: bool| {
        if !p {
            let queued = pending.get_untracked();
            if !queued.is_empty() {
                buffer.update(|b| {
                    let old = std::mem::take(b);
                    *b = queued;
                    b.extend(old);
                    b.truncate(BUFFER_MAX);
                });
                pending.set(Vec::new());
            }
        }
        paused.set(p);
    };

    // Distinct clients seen so far.
    let clients = Memo::new(move |_| {
        let mut v: Vec<String> = buffer
            .read()
            .iter()
            .filter_map(|r| r.e.client.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    });

    let matches = move |r: &Row| {
        let a = actions.read();
        if !a.contains(&r.e.action) {
            return false;
        }
        let m = mode.read();
        if !m.is_empty() && mode_key(r.e.mode) != m.as_str() {
            return false;
        }
        let c = client.read();
        if !c.is_empty() && r.e.client.as_deref() != Some(c.as_str()) {
            return false;
        }
        let needle = q.read().to_lowercase();
        needle.is_empty()
            || r.e.url.to_lowercase().contains(&needle)
            || r.e
                .rule
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .contains(&needle)
    };
    let shown = Memo::new(move |_| buffer.read().iter().filter(|r| matches(r)).count());
    let visible = move || {
        buffer
            .read()
            .iter()
            .filter(|r| matches(r))
            .take(RENDER_MAX)
            .cloned()
            .collect::<Vec<Row>>()
    };

    let allow_block = {
        let app = app.clone();
        move |allow: bool| {
            let Some(row) = selected.get_untracked() else {
                return;
            };
            let host = url_host(&row.e.url);
            let rule = if allow {
                format!("@@||{host}^")
            } else {
                format!("||{host}^")
            };
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().append_custom_rule(&rule).await {
                    Ok(()) => app.success(format!("Added {rule} to custom rules")),
                    Err(e) => app.error(format!("Could not update rules: {e}")),
                }
            });
        }
    };
    let allow_block2 = allow_block.clone();

    let bypass_mode = RwSignal::new("no_decrypt".to_string());
    let bypass_site = {
        let app = app.clone();
        Callback::new(move |host: String| {
            let m = crate::api::bypass::parse_mode(&bypass_mode.get_untracked());
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().create_bypass_entry(&host, m).await {
                    Ok(_) => app.success(format!("{host} added to Bypass")),
                    Err(e) => app.error(format!("Could not add to Bypass: {e}")),
                }
            });
        })
    };

    let drawer_title = Signal::derive(move || "Request".to_string());

    view! {
        <Layout class="logs-screen">
            <div class="logbar" role="search">
                <div class="search">
                    <Icon name="search" />
                    <label class="sr" for="logQ">"Search host, path or rule"</label>
                    <input
                        class="input mono"
                        id="logQ"
                        placeholder="host, path or rule  e.g. doubleclick"
                        autocomplete="off"
                        prop:value=move || q.get()
                        on:input=move |ev| q.set(event_target_value(&ev))
                    />
                </div>
                <select
                    class="select"
                    aria-label="Client"
                    prop:value=move || client.get()
                    on:change=move |ev| client.set(event_target_value(&ev))
                >
                    <option value="">"All clients"</option>
                    <For each=move || clients.get() key=|c| c.clone() children=move |c| {
                        let v = c.clone();
                        view! { <option value=v>{c}</option> }
                    } />
                </select>
                <button
                    class="btn"
                    type="button"
                    aria-pressed=move || paused.get().to_string()
                    on:click=move |_| set_paused(!paused.get_untracked())
                >
                    {move || if paused.get() { view! { <Icon name="play" /><span>"Resume"</span> }.into_any() }
                        else { view! { <Icon name="pause" /><span>"Pause"</span> }.into_any() }}
                </button>
            </div>
            <div class="logbar">
                <div class="chips" role="group" aria-label="Action">
                    {[
                        (LogAction::Allowed, "Allowed", "var(--allow)"),
                        (LogAction::Blocked, "Blocked", "var(--block)"),
                        (LogAction::Passthrough, "Bypassed", "var(--pass)"),
                        (LogAction::Error, "Error", "var(--error)"),
                    ].into_iter().map(|(a, label, color)| view! {
                        <ChipSelect
                            pressed=Signal::derive(move || actions.read().contains(&a))
                            on_toggle=Callback::new(move |on: bool| actions.update(|v| {
                                v.retain(|x| *x != a);
                                if on { v.push(a); }
                            }))
                            dot=color
                        >{label}</ChipSelect>
                    }).collect_view()}
                </div>
                <Segmented
                    label="Mode"
                    options=vec![
                        ("".to_string(), "Any mode".to_string()),
                        ("explicit".to_string(), "Explicit".to_string()),
                        ("transparent".to_string(), "Transparent".to_string()),
                    ]
                    value=mode
                    on_change=Callback::new(move |v| mode.set(v))
                />
                <span class="streamstate" style="margin-left:auto" role="status" aria-live="polite">
                    <i class=move || if paused.get() || stream.get() == Stream::Reconnecting { "live-dot off" } else { "live-dot" }></i>
                    <span>{move || if paused.get() { "Paused" } else if stream.get() == Stream::Live { "Live" } else { "Reconnecting" }}</span>
                    " · " <span>{move || shown.get()}</span> " shown"
                </span>
            </div>
            <Show when=move || notice.get().is_some()>
                <div class="fmsg bad" role="status">{move || notice.get().unwrap_or_default()}</div>
            </Show>
            <div class="logtable">
                <div class="lr lhead" aria-hidden="true">
                    <span>"Action"</span><span>"Time"</span><span>"Client"</span><span>"Method"</span>
                    <span>"Host + path"</span><span>"Matched rule"</span><span>"Mode"</span>
                </div>
                <Show when=move || paused.get() && !pending.read().is_empty()>
                    <div class="newbanner">
                        <button class="btn sm" type="button" on:click=move |_| set_paused(false)>
                            {move || format!("{} new requests, resume", pending.read().len())}
                        </button>
                    </div>
                </Show>
                <ul class="lbody" aria-label="Requests, newest first">
                    <For
                        each=visible
                        key=|r| r.id
                        children=move |r| {
                            let (host, path) = split_url(&r.e.url);
                            let row = r.clone();
                            let e = r.e;
                            view! {
                                <li>
                                    <button
                                        class="lr"
                                        type="button"
                                        on:click=move |_| { selected.set(Some(row.clone())); drawer_open.set(true); }
                                    >
                                        <Pill kind=action_key(e.action) text=action_text(e.action) />
                                        <span class="t">{fmt_time(&e.ts)}</span>
                                        <span class="c">{e.client.clone().unwrap_or_else(|| "-".into())}</span>
                                        <span class="m">{e.method.clone()}</span>
                                        <span class="u" title=e.url.clone()>{host}<span class="p">{path}</span></span>
                                        <span class=if e.rule.is_some() { "rule" } else { "rule none" }>
                                            {rule_label(e.action, e.rule.as_deref())}
                                        </span>
                                        <span class=if e.mode == LogMode::Transparent { "tag tp mode" } else { "tag mode" }>
                                            {mode_key(e.mode)}
                                        </span>
                                    </button>
                                </li>
                            }
                        }
                    />
                    <Show when=move || shown.get() == 0>
                        <li class="empty"><b>"No requests yet"</b>"Requests appear here as clients use the proxy."</li>
                    </Show>
                </ul>
            </div>
            <Drawer
                open=drawer_open
                title=drawer_title
                footer=std::sync::Arc::new({
                    let allow_block = allow_block.clone();
                    let allow_block2 = allow_block2.clone();
                    move || {
                        let a = allow_block.clone();
                        let b = allow_block2.clone();
                        view! {
                            <button class="btn" type="button" on:click=move |_| b(true)>"Allow host"</button>
                            <button class="btn danger" type="button" on:click=move |_| a(false)>"Block host"</button>
                        }.into_any()
                    }
                })
            >
                {move || selected.get().map(|r| {
                    let e = r.e;
                    let url = e.url.clone();
                    let host = url_host(&e.url);
                    view! {
                        <div class="row-gap">
                            <Pill kind=action_key(e.action) text=action_text(e.action) />
                            <span class=if e.mode == LogMode::Transparent { "tag tp" } else { "tag" }>{mode_key(e.mode)}</span>
                        </div>
                        <dl class="kv">
                            <dt>"Time"</dt><dd class="num">{fmt_datetime(&e.ts)}</dd>
                            <dt>"URL"</dt><dd class="mono">{e.url.clone()}</dd>
                            <dt>"Method"</dt><dd class="mono">{e.method.clone()}</dd>
                            <dt>"Client"</dt><dd>{e.client.clone().unwrap_or_else(|| "-".into())}</dd>
                            <dt>"Type"</dt><dd class="mono">{e.request_type.clone()}</dd>
                            <dt>"Page"</dt><dd class="mono">{e.source_host.clone().unwrap_or_else(|| "-".into())}</dd>
                            <dt>"Rule"</dt><dd class="mono">{rule_label(e.action, e.rule.as_deref())}</dd>
                            <dt>"List"</dt><dd>{e.list_id.clone().unwrap_or_else(|| "-".into())}</dd>
                            {e.error_kind.map(|k| view! { <dt>"Error"</dt><dd>{error_kind_label(k)}</dd> })}
                            <dt>"Status"</dt><dd class="num">{e.status.map(|s| s.to_string()).unwrap_or_else(|| "-".into())}</dd>
                        </dl>
                        <div>
                            <button class="btn sm" type="button" on:click=move |_| { copy_text(&url); }>
                                <Icon name="copy" />"Copy URL"
                            </button>
                        </div>
                        {e.cert_fp.clone().map(|fp| view! { <CertPanel fp=fp host=url_hostport(&e.url) /> })}
                        {bypass_section(e.action, e.error_kind, host, bypass_mode, bypass_site)}
                    }
                })}
            </Drawer>
        </Layout>
    }
}

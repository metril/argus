//! `/userscripts/:id`: one script's overview, permissions, updates, storage, source, removal.

use std::rc::Rc;

use gloo_timers::callback::Timeout;
use leptos::prelude::*;
use leptos_router::hooks::{use_location, use_navigate};
use wasm_bindgen::{closure::Closure, JsCast};

use super::model::*;
use super::plan::{diff_rows, PlanDrawer, Review, UrlRow};
use crate::api::userscripts::Userscript;
use crate::api::{ApiClient, ApiError};
use crate::components::{ConfirmButton, Icon, Layout, ProfileSelector, Switch};
use crate::pages::vlist::*;
use crate::state::use_app_state;
use crate::utils::format_number;

type Sc = RwSignal<Option<Userscript>>;

/// The id in `/userscripts/<encoded id>`.
fn id_from_path(path: &str) -> String {
    let raw = path.strip_prefix("/userscripts/").unwrap_or("");
    let raw = raw.split(['?', '#']).next().unwrap_or("");
    js_sys::decode_uri_component(raw)
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_else(|| raw.to_string())
}

const SECTIONS: [(&str, &str); 5] = [
    ("overview", "Overview"),
    ("permissions", "Permissions"),
    ("updates", "Updates"),
    ("storage", "Storage"),
    ("source", "Source"),
];

/// Calls `on_hit(section id)` whenever a section crosses the reading line near the top.
/// An observer and the closure that must stay alive with it.
type Watch = (
    web_sys::IntersectionObserver,
    Closure<dyn FnMut(js_sys::Array, web_sys::IntersectionObserver)>,
);

fn watch_sections(on_hit: impl Fn(String) + 'static) -> Option<Watch> {
    let doc = web_sys::window()?.document()?;
    let cb = Closure::<dyn FnMut(js_sys::Array, web_sys::IntersectionObserver)>::new(
        move |entries: js_sys::Array, _o: web_sys::IntersectionObserver| {
            for e in entries.iter() {
                if let Ok(e) = e.dyn_into::<web_sys::IntersectionObserverEntry>() {
                    if e.is_intersecting() {
                        on_hit(e.target().id());
                    }
                }
            }
        },
    );
    let opts = web_sys::IntersectionObserverInit::new();
    opts.set_root_margin("-15% 0px -70% 0px");
    let obs =
        web_sys::IntersectionObserver::new_with_options(cb.as_ref().unchecked_ref(), &opts).ok()?;
    for (id, _) in SECTIONS {
        if let Some(el) = doc.get_element_by_id(id) {
            obs.observe(&el);
        }
    }
    Some((obs, cb))
}

fn state_line(st: &UpdateState) -> Option<AnyView> {
    state_pill(st).map(|(c, t)| view! { <span class=format!("pill {c}")>{t}</span> }.into_any())
}

#[component]
fn Section(id: &'static str, title: &'static str, children: Children) -> impl IntoView {
    view! {
        <section class="card us-sec" id=id>
            <div class="card-h"><h3>{title}</h3></div>
            <div class="card-b">{children()}</div>
        </section>
    }
}

#[component]
fn OverviewSec(sc: Sc) -> impl IntoView {
    view! {
        <Section id="overview" title="Overview">
            {move || sc.get().map(|s| {
                let (sites, every) = site_list(&s.match_patterns);
                view! {
                    <p class="full-desc">{s.description.clone().unwrap_or_else(|| "No description.".into())}</p>
                    <dl class="kv">
                        <dt>"Author"</dt><dd>{s.author.clone().unwrap_or_else(|| "Unknown".into())}</dd>
                        {s.homepage.clone().map(|h| view! {
                            <dt>"Homepage"</dt>
                            <dd><a href=h.clone() target="_blank" rel="noopener noreferrer">{h.clone()}</a></dd>
                        })}
                        <dt>"Namespace"</dt><dd>{s.namespace.clone().unwrap_or_else(|| "None".into())}</dd>
                        <dt>"Run at"</dt><dd class="mono">{s.run_at.as_deref().map(run_at_label).unwrap_or_else(|| "document-idle".into())}</dd>
                        <dt>"Frames"</dt><dd>{if s.noframes { "Top frame only" } else { "Top frame and iframes" }}</dd>
                        <dt>"Runs on"</dt><dd>{if every { "Every site".to_string() } else { format!("{} site{}", sites.len(), if sites.len() == 1 { "" } else { "s" }) }}</dd>
                        <dt>"Executions"</dt><dd>{format_number(s.execution_count)}" in total"</dd>
                        <dt>"Last run"</dt>
                        <dd>{match s.last_executed.clone() {
                            Some(t) => view! { <span title=fmt_abs(&t)>{rel_time(&t)}</span> }.into_any(),
                            None => view! { "Never" }.into_any(),
                        }}</dd>
                        {s.error.then(|| view! {
                            <dt>"Last error"</dt>
                            <dd class="bad">{s.unsupported.first().cloned().unwrap_or_else(|| "The last run failed".into())}</dd>
                        })}
                    </dl>
                    {(!s.warnings.is_empty()).then(|| view! {
                        <ul class="plainlist">{s.warnings.iter().map(|w| view! { <li class="muted">{w.clone()}</li> }).collect_view()}</ul>
                    })}
                    <p class="hint">"Menu commands: open a matching site and use the Argus button to run this script's commands."</p>
                }
            })}
        </Section>
    }
}

#[component]
fn PermsSec(sc: Sc) -> impl IntoView {
    view! {
        <Section id="permissions" title="Permissions">
            {move || sc.get().map(|s| {
                let has_xhr = s.grants.iter().any(|g| grant_key(g) == "xmlhttprequest");
                let none = s.grants.iter().all(|g| grant_key(g) == "none") && s.connect.is_empty() && !has_xhr;
                let approved = s.connect_all_approved;
                view! {
                    {none.then(|| view! { <p>"Uses no special permissions"</p> })}
                    {(!s.grants.is_empty() && !none).then(|| view! {
                        <div class="sec">
                            <h4 class="sec-title">"Can access"</h4>
                            <dl class="kv wide">
                                {s.grants.iter().map(|g| view! {
                                    <dt class="mono">{grant_display(g)}</dt>
                                    <dd>{grant_meaning(g)}
                                        {is_sensitive_grant(g).then(|| view! { " " <span class="pill p-error">"Sensitive"</span> })}</dd>
                                }).collect_view()}
                            </dl>
                        </div>
                    })}
                    {(has_xhr || !s.connect.is_empty()).then(|| {
                        let any = s.connect.iter().any(|c| c == "*") || s.connect.is_empty();
                        view! {
                            <div class="sec">
                                <h4 class="sec-title">"Can contact"</h4>
                                <div class="pats">
                                    {if any {
                                        view! { <span class="pat hot">{if s.connect.is_empty() { "Any site (approval required)" } else { "Any site" }}</span> }.into_any()
                                    } else {
                                        ().into_any()
                                    }}
                                    {s.connect.iter().filter(|c| *c != "*").map(|c| view! { <span class="pat">{c.clone()}</span> }).collect_view()}
                                </div>
                                {any.then(|| view! {
                                    <span class="muted">{if approved { "You approved contacting any site." } else { "Not approved: requests to other sites are blocked." }}</span>
                                })}
                            </div>
                        }
                    })}
                    {(!s.match_patterns.is_empty()).then(|| view! {
                        <div class="sec">
                            <h4 class="sec-title">"Runs on"</h4>
                            <div class="pats">
                                {s.match_patterns.iter().map(|p| view! { <span class=if site_name(p).is_none() { "pat hot" } else { "pat" }>{p.clone()}</span> }).collect_view()}
                            </div>
                        </div>
                    })}
                }
            })}
        </Section>
    }
}

#[component]
fn UpdatesSec(
    sc: Sc,
    busy: RwSignal<bool>,
    msg: RwSignal<Option<(bool, String)>>,
    check: Callback<()>,
    review: RwSignal<Option<Review>>,
    show_review: RwSignal<bool>,
) -> impl IntoView {
    view! {
        <Section id="updates" title="Updates">
            {move || sc.get().map(|s| {
                let pending = s.pending_update.clone();
                let no_src = s.update_url.is_none();
                view! {
                    <dl class="kv">
                        <dt>"Installed"</dt><dd class="mono">{s.version.clone().unwrap_or_else(|| "unknown".into())}</dd>
                        <dt>"Update source"</dt>
                        <dd>{match s.update_url.clone() {
                            Some(u) => view! { <UrlRow url=u /> }.into_any(),
                            None => view! { <span>"None"</span> }.into_any(),
                        }}</dd>
                        <dt>"Last checked"</dt>
                        <dd>{match s.last_update_check.clone() {
                            Some(t) => view! { <span title=fmt_abs(&t)>{rel_time(&t)}</span> }.into_any(),
                            None => view! { "Never" }.into_any(),
                        }}</dd>
                        <dt>"Result"</dt>
                        <dd role="status">{move || match msg.get() {
                            Some((true, t)) => view! { <span>{t}</span> }.into_any(),
                            Some((false, t)) => view! { <span class="bad">{t}</span> }.into_any(),
                            None => match sc.with(|s| s.as_ref().and_then(|s| s.pending_update.as_ref().map(|p| p.new_version.clone()))) {
                                Some(v) => view! { <span>{format!("Update {} is waiting for your approval", v.unwrap_or_else(|| "?".into()))}</span> }.into_any(),
                                None => view! { <span class="muted">"No pending update"</span> }.into_any(),
                            },
                        }}</dd>
                        {(s.require_count + s.resource_count > 0).then(|| view! {
                            <dt>"External files"</dt>
                            <dd>{format!("{} @require, {} @resource, stored with the script", s.require_count, s.resource_count)}</dd>
                        })}
                    </dl>
                    {s.update_url.is_none().then(|| view! { <div class="hint box">{NO_SOURCE_HINT}</div> })}
                    {pending.map(|p| view! {
                        <div class="sec"><h4 class="sec-title">"Pending changes"</h4>{diff_rows(p.diff)}</div>
                    })}
                    <div class="row-gap">
                        <button type="button" class="btn" disabled=move || busy.get() || no_src
                            title=if no_src { NO_SOURCE_HINT } else { "" }
                            on:click=move |_| check.run(())>
                            {move || if busy.get() { view! { <span class="spin"></span>"Checking\u{2026}" }.into_any() } else { view! { <Icon name="refresh" />"Check now" }.into_any() }}
                        </button>
                        {s.pending_update.is_some().then(|| {
                            let s3 = s.clone();
                            view! {
                                <button type="button" class="btn primary" on:click=move |_| {
                                    if let Some(r) = Review::from_update(&s3) {
                                        review.set(Some(r));
                                        show_review.set(true);
                                    }
                                }>"Review update"</button>
                            }
                        })}
                    </div>
                }
            })}
        </Section>
    }
}

#[component]
fn StorageSec(id: Memo<String>, sc: Sc) -> impl IntoView {
    let used = RwSignal::new(Option::<(u64, u64)>::None);
    let q = RwSignal::new(String::new());
    let t = StoredValue::new_local(None::<Timeout>);
    let act_err = RwSignal::new(Option::<String>::None);
    let fetch: Fetcher<api_types::StorageValueDto> = Rc::new(move |cursor, _| {
        let (id, q) = (id.get_untracked(), q.get_untracked());
        Box::pin(async move {
            let s = ApiClient::new()
                .get_userscript_storage(&id, &q, cursor.as_deref())
                .await?;
            used.set(Some((s.used_bytes, s.quota_bytes)));
            Ok((s.values, s.next_cursor, s.total))
        })
    });
    let feed = Feed::new(fetch);
    Effect::new(move |_| {
        id.track();
        used.set(None);
        feed.reload(None, false, None);
    });
    let refresh_script = move || {
        let id = id.get_untracked();
        wasm_bindgen_futures::spawn_local(async move {
            if let Ok(s) = ApiClient::new().get_userscript(&id).await {
                sc.set(Some(s));
            }
        });
    };
    let delete = move |name: String| {
        let id = id.get_untracked();
        act_err.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().delete_userscript_value(&id, &name).await {
                Ok(_) => {
                    feed.items.update(|v| v.retain(|x| x.name != name));
                    feed.total.update(|n| *n = n.saturating_sub(1));
                    feed.reload(None, false, None);
                    refresh_script();
                }
                Err(e) => act_err.set(Some(format!("Couldn't delete {name}: {e}"))),
            }
        });
    };
    let clear = move |()| {
        let id = id.get_untracked();
        act_err.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().clear_userscript_storage(&id).await {
                Ok(_) => {
                    feed.reload(None, false, None);
                    refresh_script();
                }
                Err(e) => act_err.set(Some(format!("Couldn't clear the stored values: {e}"))),
            }
        });
    };
    view! {
        <Section id="storage" title="Storage">
            <div class="toolbar">
                <div class="search grow">
                    <Icon name="search" />
                    <label class="sr" for="usStQ">"Search stored values"</label>
                    <input id="usStQ" class="input" placeholder="Search keys" autocomplete="off"
                        prop:value=move || q.get()
                        on:input=move |ev| {
                            q.set(event_target_value(&ev));
                            t.set_value(Some(Timeout::new(250, move || feed.reload(None, false, None))));
                        } />
                </div>
                <span class="dim">{move || {
                    let n = feed.total.get();
                    let u = used.get().map(|(u, quota)| format!(" \u{b7} {} of {}", fmt_bytes(u), fmt_bytes(quota))).unwrap_or_default();
                    format!("{n} key{}{u}", if n == 1 { "" } else { "s" })
                }}</span>
                <ConfirmButton label="Clear all" confirm_label="Clear all?" on_confirm=Callback::new(clear)
                    disabled=Signal::derive(move || feed.total.get() == 0) />
            </div>
            {move || act_err.get().map(|e| view! { <div class="err" role="alert">{e}</div> })}
            <Show when=move || feed.items.with(|v| v.is_empty()) fallback=|| ()>
                <p class="muted">{move || if feed.loading.get() {
                    "Loading\u{2026}".to_string()
                } else if feed.error.get().is_some() {
                    String::new()
                } else if q.with(|q| q.is_empty()) {
                    "This script hasn't stored anything yet.".to_string()
                } else {
                    "No stored keys match.".to_string()
                }}</p>
            </Show>
            <Show when=move || feed.items.with(|v| !v.is_empty()) || feed.error.get().is_some()>
            <Scroller feed=feed>
                <table class="tbl stack">
                    <thead><tr><th>"Key"</th><th class="r">"Size"</th><th>"Value"</th><th></th></tr></thead>
                    <tbody>
                        <For each=move || feed.items.get() key=|v| format!("{}/{}/{}", v.name, v.size_bytes, v.preview)
                            children=move |v| {
                                let name = v.name.clone();
                                view! { <tr>
                                    <td class="k">{v.name.clone()}</td>
                                    <td class="sz r">{fmt_bytes(v.size_bytes as u64)}</td>
                                    <td class="v" title=v.preview.clone()>{v.preview.clone()}</td>
                                    <td class="a"><ConfirmButton label="Delete" confirm_label="Delete?"
                                        on_confirm=Callback::new(move |()| delete(name.clone())) /></td>
                                </tr> }
                            } />
                    </tbody>
                </table>
            </Scroller>
            </Show>
        </Section>
    }
}

const BIG: usize = 200 * 1024;
const FIRST_LINES: usize = 2000;
const WRAP_KEY: &str = "us.src.wrap";

#[component]
fn SourceSec(id: Memo<String>, want: RwSignal<bool>) -> impl IntoView {
    let app = StoredValue::new(use_app_state());
    let src = RwSignal::new(Option::<String>::None);
    let loading = RwSignal::new(false);
    let err = RwSignal::new(Option::<String>::None);
    let all = RwSignal::new(false);
    let wrap = RwSignal::new({
        use gloo_storage::Storage;
        gloo_storage::LocalStorage::get::<bool>(WRAP_KEY).unwrap_or_else(|_| is_narrow())
    });
    let load = move || {
        if loading.get_untracked() {
            return;
        }
        loading.set(true);
        err.set(None);
        let id = id.get_untracked();
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().get_userscript_source(&id).await {
                Ok(r) => src.set(Some(r.source)),
                Err(e) => err.set(Some(e.to_string())),
            }
            loading.set(false);
        });
    };
    Effect::new(move |_| {
        if want.get() && src.with_untracked(|s| s.is_none()) {
            load();
        }
    });
    let set_wrap = move |w: bool| {
        use gloo_storage::Storage;
        let _ = gloo_storage::LocalStorage::set(WRAP_KEY, w);
        wrap.set(w);
    };
    let copy = move |_| {
        if let Some(text) = src.get_untracked() {
            if let Some(w) = web_sys::window() {
                let p = w.navigator().clipboard().write_text(&text);
                wasm_bindgen_futures::spawn_local(async move {
                    match wasm_bindgen_futures::JsFuture::from(p).await {
                        Ok(_) => app.get_value().success("Source copied"),
                        Err(_) => app
                            .get_value()
                            .error("Couldn't copy: the browser blocked clipboard access"),
                    }
                });
            }
        }
    };
    let download = move |_| {
        if let Some(text) = src.get_untracked() {
            if let Err(e) = download_as("userscript.user.js", &text, "text/javascript") {
                err.set(Some(format!("Download failed: {e}")));
            }
        }
    };
    view! {
        <Section id="source" title="Source">
            {move || match (src.get(), loading.get(), err.get()) {
                (Some(text), _, _) => {
                    let lines = text.lines().count();
                    let big = text.len() > BIG;
                    let size = fmt_bytes(text.len() as u64);
                    view! {
                        <div class="codebox">
                            <div class="code-h">
                                <span class="dim">{format!("{size} \u{b7} {lines} lines")}</span>
                                <div class="seg" role="radiogroup" aria-label="Line wrapping">
                                    <button type="button" role="radio" aria-checked=move || wrap.get().to_string() on:click=move |_| set_wrap(true)>"Wrap"</button>
                                    <button type="button" role="radio" aria-checked=move || (!wrap.get()).to_string() on:click=move |_| set_wrap(false)>"Scroll"</button>
                                </div>
                                <span class="grow"></span>
                                <button type="button" class="btn sm ghost" on:click=copy><Icon name="copy" />"Copy"</button>
                                <button type="button" class="btn sm ghost" on:click=download><Icon name="download" />"Download"</button>
                            </div>
                            <pre class=move || if wrap.get() { "src wrap" } else { "src" } tabindex="0" aria-label="Script source">
                                {move || {
                                    let limit = if big && !all.get() { FIRST_LINES } else { usize::MAX };
                                    text.lines().take(limit).map(|l| view! { <span class="l">{l.to_string()}</span> }).collect_view()
                                }}
                            </pre>
                            {move || (big && !all.get()).then(|| view! {
                                <div class="code-h">
                                    <span class="dim">{format!("Showing the first {FIRST_LINES} of {lines} lines")}</span>
                                    <button type="button" class="btn sm" on:click=move |_| all.set(true)>"Load all"</button>
                                </div>
                            })}
                        </div>
                    }.into_any()
                }
                (None, true, _) => view! { <div class="row-gap"><span class="spin"></span>"Loading source\u{2026}"</div> }.into_any(),
                (None, false, Some(e)) => view! {
                    <div class="err row-gap" role="alert">
                        <span>{format!("Couldn't load the source: {e}")}</span>
                        <button type="button" class="btn sm" on:click=move |_| load()>"Retry"</button>
                    </div>
                }.into_any(),
                (None, false, None) => view! {
                    <div><button type="button" class="btn" on:click=move |_| want.set(true)><Icon name="code" />"Show source"</button></div>
                }.into_any(),
            }}
        </Section>
    }
}

#[component]
fn DangerSec(id: Memo<String>) -> impl IntoView {
    let app = StoredValue::new(use_app_state());
    let navigate = use_navigate();
    let busy = RwSignal::new(false);
    let err = RwSignal::new(Option::<String>::None);
    let go = move |()| {
        let id = id.get_untracked();
        let navigate = navigate.clone();
        busy.set(true);
        err.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().uninstall_userscript(&id).await {
                Ok(_) => {
                    approval_remove(&id);
                    app.get_value().success("Userscript uninstalled");
                    navigate("/userscripts", Default::default());
                }
                Err(e) => {
                    err.set(Some(format!("Couldn't uninstall: {e}")));
                    busy.set(false);
                }
            }
        });
    };
    view! {
        <section class="card danger us-sec" id="danger">
            <div class="card-h"><h3>"Danger zone"</h3></div>
            <div class="card-b">
                <div class="row-gap spread">
                    <span><b>"Uninstall script."</b>" Removes the code and its stored values."</span>
                    <ConfirmButton label="Uninstall" confirm_label="Uninstall?" large=true
                        disabled=Signal::derive(move || busy.get()) on_confirm=Callback::new(go) />
                </div>
                {move || err.get().map(|e| view! { <div class="err" role="alert">{e}</div> })}
            </div>
        </section>
    }
}

/// The per-script page.
#[component]
pub fn UserscriptDetailPage() -> impl IntoView {
    let location = use_location();
    // Leaving the page (uninstall, Back) must not turn the id into "" and refetch while the
    // page is being torn down: keep the previous id then.
    let id = Memo::new(move |prev: Option<&String>| {
        let p = location.pathname.get();
        if p.strip_prefix("/userscripts/")
            .is_some_and(|r| !r.is_empty())
        {
            id_from_path(&p)
        } else {
            prev.cloned().unwrap_or_default()
        }
    });
    let sc: Sc = RwSignal::new(None);
    let loading = RwSignal::new(true);
    let missing = RwSignal::new(false);
    let load_err = RwSignal::new(Option::<String>::None);
    let rev = RwSignal::new(0u32);
    let approval = RwSignal::new(approval_load());
    let review = RwSignal::new(Option::<Review>::None);
    let show_review = RwSignal::new(false);
    let want_src = RwSignal::new(false);
    let active = RwSignal::new("overview".to_string());
    let toggle_err = RwSignal::new(Option::<String>::None);
    let toggling = RwSignal::new(false);
    let check_busy = RwSignal::new(false);
    let check_msg = RwSignal::new(Option::<(bool, String)>::None);
    let obs = StoredValue::new_local(None::<Watch>);

    Effect::new(move |_| {
        rev.track();
        let id = id.get();
        loading.set(true);
        missing.set(false);
        load_err.set(None);
        approval.set(approval_load());
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().get_userscript(&id).await {
                Ok(s) => sc.set(Some(s)),
                Err(ApiError::NotFound(_)) => {
                    sc.set(None);
                    missing.set(true);
                }
                Err(e) => {
                    sc.set(None);
                    load_err.set(Some(e.to_string()));
                }
            }
            loading.set(false);
        });
    });
    // Section highlight, lazy source, and the #hash jump once the sections exist.
    Effect::new(move |_| {
        let ready = sc.with(|s| s.is_some());
        if !ready || obs.with_value(|o| o.is_some()) {
            return;
        }
        Timeout::new(60, move || {
            let hit = move |id: String| {
                if id == "source" {
                    want_src.set(true);
                }
                active.set(id);
            };
            obs.set_value(watch_sections(hit));
            if let Some(w) = web_sys::window() {
                let hash = w.location().hash().unwrap_or_default();
                let hash = hash.trim_start_matches('#');
                if !hash.is_empty() {
                    if let Some(el) = w.document().and_then(|d| d.get_element_by_id(hash)) {
                        el.scroll_into_view();
                    }
                }
            }
        })
        .forget();
    });
    on_cleanup(move || {
        obs.try_with_value(|o| {
            if let Some((o, _)) = o {
                o.disconnect();
            }
        });
    });

    let toggle = move |v: bool| {
        let id = id.get_untracked();
        toggling.set(true);
        toggle_err.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().set_userscript_enabled(&id, v).await {
                Ok(s) => {
                    if v {
                        approval_remove(&id);
                        approval.set(approval_load());
                    }
                    sc.set(Some(s));
                }
                Err(e) => toggle_err.set(Some(format!(
                    "Couldn't {} the script: {e}",
                    if v { "enable" } else { "disable" }
                ))),
            }
            toggling.set(false);
        });
    };
    let jump = move |sec: &'static str| {
        if let Some(el) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id(sec))
        {
            el.scroll_into_view();
        }
        active.set(sec.to_string());
    };
    let do_check = move |()| {
        let id = id.get_untracked();
        check_busy.set(true);
        check_msg.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().check_userscript_update(&id).await {
                Ok(r) => {
                    let t = match r.status.as_str() {
                        "up_to_date" => "Up to date".to_string(),
                        "updated" => {
                            format!("Updated to {}", r.new_version.clone().unwrap_or_default())
                        }
                        "pending_approval" => format!(
                            "Update {} is waiting for your approval",
                            r.new_version.clone().unwrap_or_default()
                        ),
                        s => format!("Update check: {s}"),
                    };
                    sc.set(Some(r.script));
                    check_msg.set(Some((true, t)));
                }
                Err(e) => check_msg.set(Some((false, format!("Update check failed: {e}")))),
            }
            check_busy.set(false);
        });
    };

    let toc = move || {
        SECTIONS.iter().map(|&(sid, label)| view! {
            <a class="tab" href=format!("#{sid}")
                aria-current=move || if active.get() == sid { Some("true") } else { None }
                on:click=move |ev: web_sys::MouseEvent| { ev.prevent_default(); jump(sid); }>{label}</a>
        }).collect_view()
    };

    view! {
        <Layout>
            <ProfileSelector reload=rev />
            <a class="back" href="/userscripts"><Icon name="chev-l" />"Userscripts"</a>
            <Show when=move || missing.get()>
                <div class="not-found">
                    <h1>"404"</h1>
                    <p class="muted">"This userscript isn't installed (or was uninstalled)."</p>
                    <a href="/userscripts" class="btn primary">"Back to userscripts"</a>
                </div>
            </Show>
            {move || load_err.get().map(|e| view! {
                <div class="err row-gap" role="alert">
                    <span>{format!("Failed to load the script: {e}")}</span>
                    <button type="button" class="btn sm" on:click=move |_| rev.update(|n| *n += 1)>"Retry"</button>
                </div>
            })}
            <Show when=move || loading.get() && sc.with(|s| s.is_none())>
                <div class="skel-wrap" aria-busy="true" aria-label="Loading script">
                    <div class="skel" style="height:28px;width:40%"></div>
                    <div class="skel" style="height:14px;width:60%"></div>
                    <div class="skel" style="height:160px"></div>
                    <div class="skel" style="height:160px"></div>
                </div>
            </Show>
            <Show when=move || sc.with(|s| s.is_some())>
                <header class="us-page-h">
                    <div class="ttl">
                        <h1 class="page-title">{move || sc.with(|s| s.as_ref().map(|s| s.name.clone()).unwrap_or_default())}</h1>
                        {move || sc.with(|s| s.as_ref().and_then(|s| s.version.clone())).map(|v| view! { <span class="ver">{v}</span> })}
                        {move || sc.with(|s| s.as_ref().map(|s| update_status(s, &approval.get()))).and_then(|st| state_line(&st))}
                    </div>
                    <div class="acts">
                        <Switch
                            checked=Signal::derive(move || sc.with(|s| s.as_ref().is_some_and(|s| s.enabled)))
                            label="Enabled"
                            text=Signal::derive(move || if sc.with(|s| s.as_ref().is_some_and(|s| s.enabled)) { "Enabled".to_string() } else { "Disabled".to_string() })
                            disabled=Signal::derive(move || toggling.get())
                            on_change=Callback::new(toggle) />
                        <button type="button" class="btn"
                            disabled=move || check_busy.get() || sc.with(|s| s.as_ref().is_some_and(|s| s.update_url.is_none()))
                            title=move || if sc.with(|s| s.as_ref().is_some_and(|s| s.update_url.is_none())) { NO_SOURCE_HINT } else { "" }
                            on:click=move |_| do_check(())>
                            {move || if check_busy.get() { view! { <span class="spin"></span>"Checking\u{2026}" }.into_any() } else { view! { <Icon name="refresh" />"Check for update" }.into_any() }}
                        </button>
                    </div>
                    <div class="meta">
                        {move || sc.with(|s| s.as_ref().map(|s| {
                            let ns = s.namespace.as_deref().map(url_host).filter(|h| !h.is_empty());
                            view! {
                                {s.author.clone().map(|a| view! { <span>{format!("by {a}")}</span> })}
                                {ns.map(|n| view! { <span>{n}</span> })}
                                <span title=fmt_abs(&s.updated_at)>{format!("updated {}", fmt_date(&s.updated_at))}</span>
                                {s.update_url.as_deref().map(|u| view! { <span>{format!("from {}", url_host(u))}</span> })}
                            }
                        }))}
                    </div>
                    {move || check_msg.get().map(|(ok, t)| view! { <div class=if ok { "hint fullrow" } else { "err fullrow" } role="status">{t}</div> })}
                    {move || toggle_err.get().map(|e| view! { <div class="err fullrow" role="alert">{e}</div> })}
                    {move || {
                        let s = sc.get()?;
                        (update_status(&s, &approval.get()) == UpdateState::NeedsApproval).then(|| {
                            let s2 = s.clone();
                            view! {
                                <div class="hint box row-gap fullrow">
                                    <span>"Imported from a file and still off. Review its permissions to approve it."</span>
                                    <button type="button" class="btn sm primary" on:click=move |_| {
                                        review.set(Some(Review::from_approval(&s2)));
                                        show_review.set(true);
                                    }>"Review"</button>
                                </div>
                            }
                        })
                    }}
                </header>
                <div class="us-page">
                    <div class="us-secs">
                        <OverviewSec sc=sc />
                        <PermsSec sc=sc />
                        <UpdatesSec sc=sc busy=check_busy msg=check_msg check=Callback::new(do_check) review=review show_review=show_review />
                        <StorageSec id=id sc=sc />
                        <SourceSec id=id want=want_src />
                        <DangerSec id=id />
                    </div>
                    <nav class="us-toc" aria-label="On this page">{toc}</nav>
                </div>
            </Show>
            <PlanDrawer review=review open=show_review on_done=Callback::new(move |()| rev.update(|n| *n += 1)) />
        </Layout>
    }
}

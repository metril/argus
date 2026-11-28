//! API tokens list: status filter, table, details drawer, revoke and regenerate. Creating and
//! editing live in `token_edit`, the permission model and wording in `token_form`.

use api_types::{ApiTokenInfo, ProfileDto, Scope};
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use super::token_form::{
    access_summary, build_regenerate, counts, empty_text, expiring_banner, expiry_cell,
    expiry_line, grace_until, long_date, parse_rfc3339, plain_error, purpose_title, resolve_expiry,
    summary_sentence, token_status, Filter, Status, EXPIRY_OPTIONS, GRACE_OPTIONS,
};
use super::token_view::{
    end_of_day_iso, long_datetime, now_secs, today, ymd_of_secs, GrantedList, Reveal, RevealPanel,
    StatusPill,
};
use crate::api::ApiClient;
use crate::components::{ConfirmButton, Drawer, Icon, Layout, Menu, MenuItem, Pill, Segmented};
use crate::state::use_app_state;
use crate::utils::fmt_ago;

/// Scopes of a token row as plain language, the full text on hover (used by the admin list).
pub fn scope_tags(scopes: &[Scope]) -> impl IntoView {
    let (short, full) = access_summary(scopes, 0);
    view! { <span title=full>{short}</span> }
}

/// Instant of an RFC 3339 string as a local long date, e.g. "Fri, 12 Mar 2027".
fn date_of(ts: &str) -> Option<String> {
    parse_rfc3339(ts).map(|t| long_date(ymd_of_secs(t)))
}

fn last_used(t: &ApiTokenInfo) -> (String, Option<String>) {
    match t.last_used_at.as_deref() {
        Some(ts) => (
            fmt_ago(ts),
            t.last_used_addr.clone().filter(|a| !a.is_empty()),
        ),
        None => ("Never used".into(), None),
    }
}

fn filter_options() -> Vec<(String, String)> {
    Filter::ALL
        .iter()
        .map(|f| (f.key().to_string(), f.label().to_string()))
        .collect()
}

#[component]
pub fn TokensPage() -> impl IntoView {
    let app_state = use_app_state();
    let navigate = use_navigate();

    let tokens = RwSignal::new(Vec::<ApiTokenInfo>::new());
    let loaded = RwSignal::new(false);
    let load_error = RwSignal::new(Option::<String>::None);
    let profiles = RwSignal::new(Vec::<ProfileDto>::new());
    let now = RwSignal::new(now_secs());
    let filter = RwSignal::new(Filter::Active);
    let drawer_open = RwSignal::new(false);
    let drawer_id = RwSignal::new(String::new());
    let regen = RwSignal::new(Option::<String>::None);
    let reveal = RwSignal::new(Option::<Reveal>::None);

    let reload = {
        Callback::new(move |_: ()| {
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().list_all_tokens().await {
                    Ok(all) => {
                        now.set(now_secs());
                        tokens.set(all);
                        load_error.set(None);
                    }
                    Err(e) => {
                        // Shown inline below; no toast on top of it.
                        load_error.set(Some(e.to_string()));
                    }
                }
                loaded.set(true);
            });
        })
    };
    reload.run(());
    wasm_bindgen_futures::spawn_local(async move {
        if let Ok(p) = ApiClient::new().list_profiles().await {
            profiles.set(p);
        }
    });

    let revoke = {
        let app_state = app_state.clone();

        Callback::new(move |id: String| {
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().revoke_token(&id).await {
                    Ok(_) => {
                        app_state.success("Token revoked");
                        reload.run(());
                    }
                    Err(e) => app_state.error(format!("Failed to revoke: {e}")),
                }
            });
        })
    };

    let go = Callback::new(move |to: String| navigate(&to, Default::default()));
    let open_regen = move |id: String| {
        drawer_open.set(false);
        regen.set(Some(id));
        if let Some(m) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id("main"))
        {
            m.set_scroll_top(0);
        }
    };

    let c = Memo::new(move |_| tokens.with(|t| counts(t, now.get())));
    let shown = Signal::derive(move || {
        let (f, n) = (filter.get(), now.get());
        tokens.with(|all| {
            all.iter()
                .filter(|t| f.matches(token_status(t, n)))
                .cloned()
                .collect::<Vec<_>>()
        })
    });
    let banner = Memo::new(move |_| tokens.with(|t| expiring_banner(t, now.get())));
    let drawer_token = Signal::derive(move || {
        let id = drawer_id.get();
        tokens.with(|all| all.iter().find(|t| t.id == id).cloned())
    });

    let profile_label = move |t: &ApiTokenInfo| match &t.profiles {
        None => "All profiles".to_string(),
        Some(ids) => {
            let all = profiles.get();
            ids.iter()
                .map(|id| {
                    all.iter()
                        .find(|p| p.id == *id)
                        .map_or(id.clone(), |p| p.name.clone())
                })
                .collect::<Vec<_>>()
                .join(", ")
        }
    };

    let row_view = {
        move |t: ApiTokenInfo| {
            let n = now.get_untracked();
            let status = token_status(&t, n);
            let (short, full) = access_summary(&t.scopes, t.unknown_scopes.len());
            let (ago, addr) = last_used(&t);
            let exp_date = t.expires_at.as_deref().and_then(date_of);
            let cell = expiry_cell(&t, n);
            let (id, id2, id3, id4, id5) = (
                t.id.clone(),
                t.id.clone(),
                t.id.clone(),
                t.id.clone(),
                t.id.clone(),
            );
            let name = t.name.clone();
            let go1 = go;
            let go2 = go;
            let live = status != Status::Revoked;
            let can_edit = live && status != Status::Expired;
            view! {
                <tr class="clk" on:click=move |_| { drawer_id.set(id.clone()); drawer_open.set(true); }>
                    <td class="n">
                        <button type="button" class="lnk nm" on:click=move |ev| {
                            ev.stop_propagation();
                            drawer_id.set(id2.clone());
                            drawer_open.set(true);
                        }>{name.clone()}</button>
                        {matches!(status, Status::Revoked | Status::Expired).then(|| view! { " "<StatusPill status=status /> })}
                        <div class="row tk-sub">
                            <span class="pfx">{t.secret_hint.clone()}</span>
                            <span class="tk-tag acc">{purpose_title(t.purpose)}</span>
                        </div>
                    </td>
                    <td class="muted ac"><div class="clamp" title=full>{short}</div></td>
                    <td class="num lu">{ago}{addr.map(|a| view! { <div class="dim">"from "{a}</div> })}</td>
                    <td class="num r ex">
                        {if status == Status::Expiring {
                            view! { <Pill kind="warn" text=cell /> }.into_any()
                        } else {
                            view! { {cell} }.into_any()
                        }}
                        {live.then(|| exp_date.map(|d| view! { <div class="dim">{d}</div> })).flatten()}
                    </td>
                    <td class="act" on:click=|ev| ev.stop_propagation()>
                        <div class="aw">
                            <span class="rv">
                                {live.then(|| {
                                    let id = t.id.clone();
                                    view! { <ConfirmButton label="Revoke" confirm_label="Revoke?" cancel=true
                                        on_confirm=Callback::new(move |_| revoke.run(id.clone())) /> }
                                })}
                            </span>
                            <Menu label=format!("More actions for {name}") icon="dots">
                                {can_edit.then(|| {
                                    let (go, id) = (go1, id3.clone());
                                    view! { <MenuItem on_select=Callback::new(move |_| go.run(format!("/tokens/{id}/edit")))>"Edit"</MenuItem> }
                                })}
                                {live.then(|| {
                                    let id = id4.clone();
                                    view! { <MenuItem on_select=Callback::new(move |_| open_regen(id.clone()))>"Regenerate"</MenuItem> }
                                })}
                                {
                                    let (go, id) = (go2, id5.clone());
                                    view! { <MenuItem on_select=Callback::new(move |_| go.run(format!("/tokens/new?from={id}")))>"Duplicate"</MenuItem> }
                                }
                            </Menu>
                        </div>
                    </td>
                </tr>
            }
        }
    };

    let go_new = move |_| go.run("/tokens/new".to_string());

    view! {
        <Layout class="tkp">
            {move || reveal.get().map(|r| view! {
                <RevealPanel reveal=r on_done=Callback::new(move |_| { reveal.set(None); reload.run(()); }) />
            })}
            <Show when=move || reveal.get().is_none()>
                <div class="ph">
                    <div class="t">
                        <h1>"API tokens"</h1>
                        <p class="muted">"Tokens let scripts and the browser extension talk to Argus."</p>
                    </div>
                </div>
                {move || banner.get().map(|b| {
                    let id = b.id.clone();
                    view! {
                        <div class="banner warn" role="status">
                            <Icon name="alert" />
                            <span class="bt"><b>{b.headline.clone()}</b>" · "{b.name.clone()}</span>
                            {move || regen.get().is_none().then(|| {
                                let id = id.clone();
                                view! { <span class="ba"><button type="button" class="btn" on:click=move |_| open_regen(id.clone())>"Regenerate"</button></span> }
                            })}
                        </div>
                    }
                })}
                {move || regen.get().map(|id| view! {
                    <RegenerateCard
                        token=Signal::derive(move || tokens.with(|all| all.iter().find(|t| t.id == id).cloned()))
                        on_cancel=Callback::new(move |_| regen.set(None))
                        on_done=Callback::new(move |r: Reveal| { regen.set(None); reveal.set(Some(r)); })
                    />
                })}
                <div class="toolbar">
                    <Segmented
                        class="flt"
                        label="Show tokens"
                        options=filter_options()
                        value=Signal::derive(move || filter.get().key().to_string())
                        counts=Signal::derive(move || Filter::ALL.iter().map(|f| c.get().of(*f)).collect::<Vec<_>>())
                        on_change=Callback::new(move |k: String| filter.set(Filter::from_key(&k)))
                    />
                    <span class="tbr">
                        <button type="button" class="btn primary" on:click=go_new>"New token"</button>
                    </span>
                </div>
                {move || load_error.get().map(|e| view! {
                    <div class="banner err" role="alert"><Icon name="alert" /><span class="bt">{format!("Failed to load tokens: {e}")}</span></div>
                })}
                <div class="tk-list">
                    <div class="tk-tw">
                        <table class="tk-t tk">
                            <thead><tr>
                                <th class="cn">"Name"</th><th>"Access"</th><th class="clu">"Last used"</th><th class="r cex">"Expires"</th><th class="acth">"Actions"</th>
                            </tr></thead>
                            <tbody>
                                <For each=move || shown.get() key=|t| format!("{}{}{}{}", t.id, t.revoked, t.last_used_at.clone().unwrap_or_default(), t.updated_at.clone().unwrap_or_default()) children=row_view />
                                {move || (loaded.get() && shown.with(|v| v.is_empty())).then(|| view! {
                                    <tr class="em"><td colspan="5" class="muted tk-empty">
                                        {empty_text(filter.get(), tokens.with(|t| !t.is_empty()))}
                                    </td></tr>
                                })}
                                {move || (!loaded.get()).then(|| view! { <tr class="em"><td colspan="5" class="muted tk-empty">"Loading…"</td></tr> })}
                            </tbody>
                        </table>
                    </div>
                </div>
            </Show>
            <Drawer
                open=drawer_open
                class="tk-drawer"
                title=Signal::derive(move || drawer_token.get().map(|t| t.name).unwrap_or_default())
                badge=std::sync::Arc::new(move || view! {
                    {move || drawer_token.get().map(|t| view! { <StatusPill status=token_status(&t, now.get()) /> })}
                }.into_any())
                footer=std::sync::Arc::new(move || drawer_token.get().map(|t| {
                    let status = token_status(&t, now.get());
                    let live = status != Status::Revoked;
                    let (go_a, go_b) = (go, go);
                    let (id1, id2, id3, id4) = (t.id.clone(), t.id.clone(), t.id.clone(), t.id.clone());
                    view! {
                        {live.then(|| view! {
                            <span class="tk-fl"><ConfirmButton large=true label="Revoke" confirm_label="Revoke?" cancel=true
                                on_confirm=Callback::new(move |_| { drawer_open.set(false); revoke.run(id1.clone()); }) /></span>
                        })}
                        <button type="button" class="btn" on:click=move |_| go_a.run(format!("/tokens/new?from={id2}"))>"Duplicate"</button>
                        {live.then(|| view! { <button type="button" class="btn" on:click=move |_| open_regen(id3.clone())>"Regenerate"</button> })}
                        {(live && status != Status::Expired).then(|| view! {
                            <button type="button" class="btn primary" on:click=move |_| go_b.run(format!("/tokens/{id4}/edit"))>"Edit"</button>
                        })}
                    }
                }).into_any())
            >
                {move || drawer_token.get().map(|t| {
                    let n = now.get();
                    let status = token_status(&t, n);
                    let (ago, addr) = last_used(&t);
                    let expires = match (t.expires_at.as_deref().and_then(date_of), status) {
                        (Some(d), Status::Revoked) => format!("Was {d}"),
                        (Some(d), _) => format!("{} · {d}", expiry_cell(&t, n)),
                        (None, _) => "Never".to_string(),
                    };
                    let grace = grace_until(&t, n).map(|u| {
                        let iso = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(u as f64 * 1000.0))
                            .to_iso_string()
                            .as_string()
                            .unwrap_or_default();
                        format!("The previous secret still works until {}.", long_datetime(&iso))
                    });
                    view! {
                        <dl class="tk-kv">
                            <dt>"Token"</dt><dd class="mono">{t.secret_hint.clone()}</dd>
                            <dt>"Purpose"</dt><dd>{purpose_title(t.purpose)}</dd>
                            <dt>"Created"</dt><dd>{long_datetime(&t.created_at)}</dd>
                            <dt>"Expires"</dt><dd>{expires}</dd>
                            <dt>"Last used"</dt><dd>{ago}{addr.map(|a| format!(" from {a}"))}</dd>
                            <dt>"Profiles"</dt><dd>{profile_label(&t)}</dd>
                        </dl>
                        {grace.map(|g| view! { <div class="banner info"><Icon name="info" /><span class="bt">{g}</span></div> })}
                        <div class="sec-t">"Permissions"</div>
                        <p>{summary_sentence(&t.scopes)}</p>
                        <GrantedList scopes=t.scopes.clone() unknown=t.unknown_scopes.clone() />
                    }
                })}
            </Drawer>
        </Layout>
    }
}

/// Inline card above the list: choose how long the old secret keeps working and, for an
/// expired token, the new expiry.
#[component]
fn RegenerateCard(
    token: Signal<Option<ApiTokenInfo>>,
    on_cancel: Callback<()>,
    on_done: Callback<Reveal>,
) -> impl IntoView {
    let grace = RwSignal::new("86400".to_string());
    // The server can say "expired" before the page's clock does (the token ran out while the
    // card was open): from then on the card asks for a new expiry too.
    let force_expired = RwSignal::new(false);
    let expired = move || {
        force_expired.get()
            || token
                .get()
                .is_some_and(|t| token_status(&t, now_secs()) == Status::Expired)
    };
    let choice = RwSignal::new("90".to_string());
    let custom = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);
    let go = move |_| {
        let Some(t) = token.get_untracked() else {
            return;
        };
        let (c, u) = (choice.get_untracked(), custom.get_untracked());
        let was_expired = expired();
        let new_expiry = was_expired.then_some((c.as_str(), u.as_str()));
        let req =
            match build_regenerate(&grace.get_untracked(), new_expiry, today(), &end_of_day_iso) {
                Ok(r) => r,
                Err(m) => {
                    error.set(Some(m.into()));
                    return;
                }
            };
        busy.set(true);
        error.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            let r = ApiClient::new().regenerate_token(&t.id, &req).await;
            busy.set(false);
            match r {
                Ok(c) => on_done.run(Reveal {
                    name: t.name.clone(),
                    secret: c.secret,
                    purpose: t.purpose,
                    regenerated: true,
                    // An expired secret is dead: never promise it keeps working.
                    prev_valid_until: if was_expired {
                        None
                    } else {
                        c.token.prev_valid_until
                    },
                }),
                Err(e) => {
                    // The inline banner is the only message; no toast on top of it.
                    if e.code() == Some("token_expired") {
                        force_expired.set(true);
                        error.set(Some("It expired while you were here. Pick a new expiry and regenerate again.".into()));
                    } else {
                        error.set(Some(plain_error(e.code(), &e.text())));
                    }
                }
            }
        });
    };
    view! {
        <div class="card tk-card tk-regen">
            <b>{move || format!("Regenerate {}?", token.get().map(|t| t.name).unwrap_or_default())}</b>
            <p class="muted">"A new secret replaces the old one. Update every place that uses this token."</p>
            <div class="two">
                <Show when=move || !expired()>
                <div class="field">
                    <label for="tk-grace">"Old secret keeps working for"</label>
                    <select class="select" id="tk-grace" prop:value=move || grace.get()
                        on:change=move |ev| grace.set(event_target_value(&ev))>
                        {GRACE_OPTIONS.iter().map(|(v, l)| view! { <option value=*v selected=move || grace.get() == *v>{*l}</option> }).collect_view()}
                    </select>
                </div>
                </Show>
                <Show when=expired>
                    <div class="field">
                        <label for="tk-rexp">"New expiry"</label>
                        <select class="select" id="tk-rexp" prop:value=move || choice.get()
                            on:change=move |ev| choice.set(event_target_value(&ev))>
                            {EXPIRY_OPTIONS.iter().map(|(v, l)| view! { <option value=*v selected=move || choice.get() == *v>{*l}</option> }).collect_view()}
                        </select>
                        <Show when=move || choice.get() == "custom">
                            <input class="input" type="date" aria-label="New expiry date"
                                prop:value=move || custom.get()
                                on:input=move |ev| custom.set(event_target_value(&ev)) />
                        </Show>
                        <span class="hint">{move || expiry_line(&resolve_expiry(&choice.get(), &custom.get(), today()), today())}</span>
                    </div>
                </Show>
            </div>
            {move || error.get().map(|m| view! { <div class="banner err" role="alert"><Icon name="alert" /><span class="bt">{m}</span></div> })}
            <div class="card-footer">
                <button type="button" class="btn ghost" on:click=move |_| on_cancel.run(())>"Cancel"</button>
                <button type="button" class="btn" disabled=move || busy.get() on:click=go>"Regenerate"</button>
            </div>
        </div>
    }
}

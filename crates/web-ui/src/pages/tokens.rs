//! API tokens page: create (templates, access table, expiry), show the secret once, list, revoke.

use std::rc::Rc;

use api_types::scopes::Resource;
use leptos::prelude::*;

use super::token_form::{
    add_days, expiry_line, fmt_ymd, resolve_expiry, rows, set_level, summarize, template_of,
    Expiry, Template, Ymd, EXPIRY_OPTIONS,
};
use super::vlist::{Feed, Fetcher, Scroller};
use crate::api::tokens::{ApiTokenInfo, Scope};
use crate::api::ApiClient;
use crate::components::{Card, ConfirmButton, Icon, Layout, Segmented};
use crate::state::{use_app_state, use_auth_state};
use crate::utils::{copy_text, fmt_ago, fmt_datetime};

/// Local calendar date today.
fn today() -> Ymd {
    let d = js_sys::Date::new_0();
    (d.get_full_year() as i32, d.get_month() + 1, d.get_date())
}

/// RFC 3339 instant for the end of local day `d`.
fn end_of_day_iso(d: Ymd) -> String {
    js_sys::Date::new_with_year_month_day_hr_min_sec(
        d.0 as u32,
        d.1 as i32 - 1,
        d.2 as i32,
        23,
        59,
        59,
    )
    .to_iso_string()
    .as_string()
    .unwrap_or_default()
}

/// Scopes of a token row: a short summary with the full list on hover.
pub fn scope_tags(scopes: &[Scope]) -> impl IntoView {
    let (short, full) = summarize(scopes);
    view! { <span title=full>{short}</span> }
}

/// One row of the access table: the resource and a control for the levels the user holds.
fn access_row(
    r: &'static Resource,
    held: Vec<Scope>,
    selected: RwSignal<Vec<Scope>>,
) -> impl IntoView {
    let avail = r.available(&held);
    let mut options = vec![("0".to_string(), "No access".to_string())];
    options.extend(
        r.levels
            .iter()
            .take(avail)
            .enumerate()
            .map(|(i, l)| ((i + 1).to_string(), l.label.to_string())),
    );
    let tip = r
        .levels
        .iter()
        .take(avail)
        .flat_map(|l| {
            l.scopes
                .iter()
                .map(|s| format!("{}: {}", s.as_str(), s.description()))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let value = Signal::derive(move || r.level_of(&selected.read()).min(avail).to_string());
    view! {
        <div class="accrow">
            <span class="accname" title=tip>{r.label}</span>
            <Segmented
                label=r.label
                options=options
                value=value
                on_change=Callback::new(move |v: String| {
                    let n = v.parse().unwrap_or(0);
                    selected.update(|sel| set_level(sel, r, n));
                })
            />
        </div>
    }
}

#[component]
pub fn TokensPage() -> impl IntoView {
    let app_state = use_app_state();
    let user = use_auth_state().user;

    let name = RwSignal::new(String::new());
    let expiry = RwSignal::new("90".to_string());
    let custom_date = RwSignal::new(String::new());
    let selected = RwSignal::new(Vec::<Scope>::new());
    let new_secret = RwSignal::new(Option::<String>::None);
    let reload = RwSignal::new(0u32);

    let held = Memo::new(move |_| user.get().map(|u| u.scopes).unwrap_or_default());
    let template = Signal::derive(move || {
        held.with(|h| selected.with(|s| template_of(s, h)))
            .key()
            .to_string()
    });
    let resolved = Memo::new(move |_| resolve_expiry(&expiry.get(), &custom_date.get(), today()));

    let fetch: Fetcher<ApiTokenInfo> = {
        let app_state = app_state.clone();
        Rc::new(move |cursor, _| {
            let app_state = app_state.clone();
            Box::pin(async move {
                match ApiClient::new().list_tokens(cursor.as_deref()).await {
                    Ok(p) => Ok((p.items, p.next_cursor, p.total)),
                    Err(e) => {
                        app_state.error(format!("Failed to load tokens: {e}"));
                        Err(e)
                    }
                }
            })
        })
    };
    let tokens = Feed::new(fetch);
    Effect::new(move |_| {
        reload.track();
        tokens.reload(None, false, None);
    });

    let create = {
        let app_state = app_state.clone();
        move |_| {
            let scopes = selected.get_untracked();
            let token_name = name.get_untracked();
            if token_name.trim().is_empty() || scopes.is_empty() {
                app_state.error("Name the token and choose some access");
                return;
            }
            let (days, at) = match resolved.get_untracked() {
                Expiry::Days(n) => (Some(n), None),
                Expiry::On(d) => (None, Some(end_of_day_iso(d))),
                Expiry::Never => (None, None),
                Expiry::Invalid => {
                    app_state.error("Pick an expiry date after today");
                    return;
                }
            };
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new()
                    .create_token(&token_name, scopes, days, at)
                    .await
                {
                    Ok(created) => {
                        new_secret.set(Some(created.secret));
                        name.set(String::new());
                        selected.set(Vec::new());
                        reload.update(|n| *n += 1);
                    }
                    Err(e) => app_state.error(format!("Failed to create token: {e}")),
                }
            });
        }
    };

    let revoke = {
        let app_state = app_state.clone();
        move |id: String| {
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().revoke_token(&id).await {
                    Ok(_) => {
                        app_state.success("Token revoked");
                        reload.update(|n| *n += 1);
                    }
                    Err(e) => app_state.error(format!("Failed to revoke: {e}")),
                }
            });
        }
    };

    let app_copy = app_state.clone();
    let scope_count = move || selected.read().len();
    let template_options: Vec<(String, String)> = Template::ALL
        .iter()
        .map(|t| (t.key().to_string(), t.label().to_string()))
        .collect();
    let expiry_options = EXPIRY_OPTIONS;

    view! {
        <Layout>
            <Show when=move || new_secret.get().is_some()>
                <div class="newtoken" role="status">
                    <code>{move || new_secret.get().unwrap_or_default()}</code>
                    <button class="btn sm" type="button" on:click={
                        let app = app_copy.clone();
                        move |_| {
                            if copy_text(&new_secret.get_untracked().unwrap_or_default()) {
                                app.success("Token copied");
                            }
                        }
                    }><Icon name="copy" />"Copy"</button>
                    <button class="btn sm ghost" type="button" on:click=move |_| new_secret.set(None)>"I have copied it"</button>
                    <span class="hint" style="flex-basis:100%">"Copy it now. You can't view this token again."</span>
                </div>
            </Show>

            <Card title="New token" sub="For scripts and integrations. Shown once.">
                <div class="grid2" style="gap:var(--s3)">
                    <div class="field">
                        <label for="tkName">"Name"</label>
                        <input
                            class="input"
                            id="tkName"
                            prop:value=move || name.get()
                            on:input=move |ev| name.set(event_target_value(&ev))
                        />
                    </div>
                    <div class="field">
                        <label for="tkExp">"Expires"</label>
                        <div class="exprow">
                            <select
                                class="input"
                                id="tkExp"
                                prop:value=move || expiry.get()
                                on:change=move |ev| expiry.set(event_target_value(&ev))
                            >
                                {expiry_options.iter().map(|(v, l)| view! { <option value=*v>{*l}</option> }).collect_view()}
                            </select>
                            <Show when=move || expiry.get() == "custom">
                                <input
                                    class="input"
                                    type="date"
                                    aria-label="Expiry date"
                                    min=fmt_ymd(add_days(today(), 1))
                                    prop:value=move || custom_date.get()
                                    on:input=move |ev| custom_date.set(event_target_value(&ev))
                                />
                            </Show>
                        </div>
                        <span class=move || if resolved.get() == Expiry::Never { "hint warn" } else { "hint" }>
                            {move || expiry_line(&resolved.get(), today())}
                            {move || (resolved.get() == Expiry::Never).then_some(". Revoke it when you're done.")}
                        </span>
                    </div>
                </div>
                <div class="field">
                    <span class="lbl">"Template"</span>
                    <Segmented
                        label="Template"
                        options=template_options
                        value=template
                        on_change=Callback::new(move |k: String| {
                            let held = held.get_untracked();
                            if let Some(s) = Template::from_key(&k).scopes(&held) {
                                selected.set(s);
                            }
                        })
                    />
                </div>
                <div class="field">
                    <span class="lbl">"Access "<span class="dim">{move || format!("({} selected)", scope_count())}</span></span>
                    <div class="accgrid">
                        {move || {
                            let h = held.get();
                            rows(&h, false).into_iter().map(|r| access_row(r, h.clone(), selected)).collect_view()
                        }}
                    </div>
                    {move || {
                        let h = held.get();
                        let admin = rows(&h, true);
                        (!admin.is_empty()).then(|| view! {
                            <details class="accadmin">
                                <summary>"Admin access"</summary>
                                <span class="hint">"Reaches other users' data."</span>
                                <div class="accgrid">
                                    {admin.into_iter().map(|r| access_row(r, h.clone(), selected)).collect_view()}
                                </div>
                            </details>
                        })
                    }}
                </div>
                <div class="toolbar">
                    <button class="btn primary" type="button" on:click=create>"Create token"</button>
                </div>
            </Card>

            <div class="card">
                <div class="card-h"><h3>"Your tokens"</h3></div>
                <Scroller feed=tokens class="tbl-wrap">
                    <table class="tbl">
                        <thead><tr><th>"Name"</th><th>"Access"</th><th>"Last used"</th><th>"Expires"</th><th></th></tr></thead>
                        <tbody>
                            <For
                                each=move || tokens.items.get()
                                key=|t| format!("{}{}", t.id, t.revoked)
                                children={
                                    let revoke = revoke.clone();
                                    move |t| {
                                        let id = t.id.clone();
                                        let revoke = revoke.clone();
                                        view! {
                                            <tr>
                                                <td>{t.name.clone()}</td>
                                                <td style="white-space:normal">{scope_tags(&t.scopes)}</td>
                                                <td class="num">{t.last_used_at.as_deref().map(fmt_ago).unwrap_or_else(|| "never".into())}</td>
                                                <td class="num">{t.expires_at.as_deref().map(fmt_datetime).unwrap_or_else(|| "never".into())}</td>
                                                <td class="r">
                                                    {if t.revoked {
                                                        view! { <span class="dim">"revoked"</span> }.into_any()
                                                    } else {
                                                        view! { <ConfirmButton label="Revoke" confirm_label="Confirm revoke" on_confirm=Callback::new(move |_| revoke(id.clone())) /> }.into_any()
                                                    }}
                                                </td>
                                            </tr>
                                        }
                                    }
                                }
                            />
                        </tbody>
                    </table>
                    <Show when=move || tokens.items.with(|v| v.is_empty()) && !tokens.loading.get()>
                        <div class="empty"><b>"No tokens yet"</b>"Create one above."</div>
                    </Show>
                </Scroller>
            </div>
        </Layout>
    }
}

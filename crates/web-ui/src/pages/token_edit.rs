//! New, duplicate and edit token: one form container with Purpose, Details and Review steps.

use api_types::scopes::{PermGroup, PermKind, PermRow};
use api_types::{ProfileDto, TokenPurpose};
use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_params_map};

use super::token_form::{
    add_days, build_create, build_update, can_list, cannot_sentence, duplicate_selection,
    expires_today_text, expiry_choice_for, expiry_kept, expiry_label, expiry_summary, fmt_ymd,
    hidden_row_count, level_label, level_options, long_date, permissions_note, plain_error,
    profile_change, purpose_desc, purpose_expiry, purpose_scopes, purpose_title, resolve_expiry,
    row_flags, row_locked, row_scopes, set_level, stale_profiles, status_of, summary_sentence,
    update_is_empty, validate, visible_groups, Baseline, Check, Expiry, Field, FormValues,
    ProfileChange, Status, CARD_PURPOSES, EXPIRY_OPTIONS,
};
use super::token_view::{
    end_of_day_iso, now_secs, today, ymd_of_secs, GrantedList, Reveal, RevealPanel,
};
use super::vlist::query_get;
use crate::api::tokens::{ApiTokenInfo, Scope};
use crate::api::ApiClient;
use crate::components::{ChipSelect, Icon, Pill, Segmented, Switch};
use crate::state::{use_app_state, use_auth_state};

/// Everything the form starts from.
#[derive(Clone)]
struct Init {
    edit_id: Option<String>,
    step: u8,
    purpose: TokenPurpose,
    name: String,
    expiry: (String, String),
    profiles: Option<Vec<String>>,
    selected: Vec<Scope>,
    unknown: Vec<String>,
    status: Status,
    /// The token as it was loaded (edit only): the PATCH and the Review diff compare against it.
    base: Option<Baseline>,
    /// Permissions of the original a duplicate could not copy.
    dropped: usize,
}

impl Init {
    fn blank() -> Self {
        Self {
            edit_id: None,
            step: 1,
            purpose: TokenPurpose::Custom,
            name: String::new(),
            expiry: ("30".into(), String::new()),
            profiles: None,
            selected: Vec::new(),
            unknown: Vec::new(),
            status: Status::Active,
            base: None,
            dropped: 0,
        }
    }

    fn of_token(t: &ApiTokenInfo, edit: bool, held: &[Scope]) -> Self {
        let now = now_secs();
        let exp = t
            .expires_at
            .as_deref()
            .and_then(super::token_form::parse_rfc3339)
            .map(ymd_of_secs);
        let expiry = expiry_choice_for(exp, today());
        let (selected, dropped) = if edit {
            (t.scopes.clone(), 0)
        } else {
            duplicate_selection(&t.scopes, held)
        };
        Self {
            edit_id: edit.then(|| t.id.clone()),
            step: 2,
            purpose: t.purpose,
            name: if edit {
                t.name.clone()
            } else {
                format!("Copy of {}", t.name)
            },
            expiry: if edit {
                expiry.clone()
            } else {
                ("90".into(), String::new())
            },
            profiles: t.profiles.clone(),
            selected,
            unknown: if edit {
                t.unknown_scopes.clone()
            } else {
                Vec::new()
            },
            status: status_of(t.revoked, t.expires_at.as_deref(), now),
            base: edit.then(|| Baseline {
                name: t.name.clone(),
                expiry,
                expiry_text: exp.map_or("No expiration".to_string(), long_date),
                expires_secs: t
                    .expires_at
                    .as_deref()
                    .and_then(super::token_form::parse_rfc3339),
                profiles: t.profiles.clone(),
                scopes: t.scopes.clone(),
            }),
            dropped,
        }
    }
}

/// `/tokens/new` (optionally `?from=<id>` to start from an existing token).
#[component]
pub fn TokenNewPage() -> impl IntoView {
    let from = query_get("from");
    view! { <TokenForm edit=false id=from /> }
}

/// `/tokens/:id/edit`.
#[component]
pub fn TokenEditPage() -> impl IntoView {
    let params = use_params_map();
    let id = params.read_untracked().get("id");
    view! { <TokenForm edit=true id=id /> }
}

#[component]
fn TokenForm(edit: bool, id: Option<String>) -> impl IntoView {
    let held: Vec<Scope> = use_auth_state()
        .user
        .get_untracked()
        .map(|u| u.scopes)
        .unwrap_or_default();
    // None while loading, Some(None) when the token is not found.
    let init = RwSignal::new(if id.is_none() && !edit {
        Some(Some(Init::blank()))
    } else {
        None
    });
    if let Some(id) = id.clone() {
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().list_all_tokens().await {
                Ok(all) => init.set(Some(
                    all.iter()
                        .find(|t| t.id == id)
                        .map(|t| Init::of_token(t, edit, &held)),
                )),
                Err(_) => init.set(Some(None)),
            }
        });
    }
    view! {
        <crate::components::Layout class="tkp tk-form">
            {move || match init.get() {
                None => view! { <p class="muted">"Loading…"</p> }.into_any(),
                Some(None) => view! {
                    <a class="lnk tk-back" href="/tokens"><Icon name="chev-l" />"API tokens"</a>
                    <div class="empty"><b>"Token not found"</b>"It may have been deleted."</div>
                }.into_any(),
                Some(Some(i)) => view! { <Wizard init=i /> }.into_any(),
            }}
        </crate::components::Layout>
    }
}

fn row_tags(row: &'static PermRow, selected: RwSignal<Vec<Scope>>) -> impl IntoView {
    row_scopes(row)
        .into_iter()
        .map(|s| {
            view! {
                <code class="tg" class:on=move || selected.read().contains(&s)>{s.as_str()}</code>
            }
        })
        .collect_view()
}

fn perm_row(
    group: &'static PermGroup,
    row: &'static PermRow,
    held: Vec<Scope>,
    initial: &[Scope],
    selected: RwSignal<Vec<Scope>>,
) -> impl IntoView {
    let level = Memo::new(move |_| selected.with(|s| row.level_of(s)));
    let (always, edit_only) = row_flags(group, row);
    // The token holds more of this row than the editor can grant: show the truth, locked.
    let locked = row_locked(row, initial, &held);
    let true_level = level_label(row, row.level_of(initial));
    let control = if locked {
        view! {
            <span class="tk-locked" title="Your account can't grant this level">
                <Icon name="lock" />
                <b>{true_level}</b>
            </span>
        }
        .into_any()
    } else {
        match row.kind {
            PermKind::Switch { .. } => view! {
                <Switch
                    label=row.label
                    checked=Signal::derive(move || level.get() > 0)
                    on_change=Callback::new(move |on: bool| {
                        selected.update(|s| set_level(s, row, usize::from(on)))
                    })
                />
            }
            .into_any(),
            PermKind::Levels(_) => {
                let avail = row.available(&held);
                view! {
                    <Segmented
                        class="perm"
                        label=row.label
                        options=level_options(row, &held)
                        value=Signal::derive(move || level.get().min(avail).to_string())
                        on_change=Callback::new(move |v: String| {
                            let n = v.parse().unwrap_or(0);
                            selected.update(|s| set_level(s, row, n))
                        })
                    />
                }
                .into_any()
            }
        }
    };
    view! {
        <tr class:locked=locked>
            <td>
                <b>{row.label}</b>
                {always.then(|| view! { " "<Pill kind="blocked" text="Sensitive" /> })}
                {edit_only.then(|| view! { " "<Pill kind="blocked" text="Edit is sensitive" /> })}
                {row.description.map(|d| view! { <div class="hint">{d}</div> })}
                {locked.then(|| view! { <div class="hint">{format!("This token has {true_level}, which your account can't grant, so it stays as it is.")}</div> })}
                <div class="cap">{row_tags(row, selected)}</div>
            </td>
            <td class="ctl"><div class="cc">{control}</div></td>
        </tr>
    }
}

#[component]
fn Wizard(init: Init) -> impl IntoView {
    let app_state = use_app_state();
    let navigate = use_navigate();
    let user = use_auth_state().user;
    let held: Vec<Scope> = user.get_untracked().map(|u| u.scopes).unwrap_or_default();
    let edit = init.edit_id.clone();
    let is_edit = edit.is_some();
    let unknown = init.unknown.clone();
    let dropped = init.dropped;
    let base = StoredValue::new(init.base.clone());
    // Selection the form opened with: decides which rows are locked.
    let initial_scopes = StoredValue::new(init.selected.clone());

    let step = RwSignal::new(init.step);
    let purpose = RwSignal::new(init.purpose);
    let name = RwSignal::new(init.name.clone());
    let choice = RwSignal::new(init.expiry.0.clone());
    let custom = RwSignal::new(init.expiry.1.clone());
    let mode_all = RwSignal::new(init.profiles.is_none());
    let chosen = RwSignal::new(init.profiles.clone().unwrap_or_default());
    let selected = RwSignal::new(init.selected.clone());
    let error = RwSignal::new(Option::<(Field, String)>::None);
    let server_error = RwSignal::new(Option::<String>::None);
    let busy = RwSignal::new(false);
    let reveal = RwSignal::new(Option::<Reveal>::None);
    let profiles = RwSignal::new(Vec::<ProfileDto>::new());
    let profiles_loaded = RwSignal::new(false);
    let dead = matches!(init.status, Status::Expired | Status::Revoked) && is_edit;
    let status = init.status;
    let held_sv = StoredValue::new(held.clone());

    wasm_bindgen_futures::spawn_local(async move {
        if let Ok(p) = ApiClient::new().list_profiles().await {
            profiles.set(p);
        }
        profiles_loaded.set(true);
    });

    let resolved = Memo::new(move |_| resolve_expiry(&choice.get(), &custom.get(), today()));
    let no_profiles = Memo::new(move |_| !mode_all.get() && chosen.read().is_empty());
    let kept = move || {
        base.get_value().is_some_and(|b| {
            expiry_kept(&b.expiry, &choice.get_untracked(), &custom.get_untracked())
        })
    };
    // Profile ids still chosen that no longer exist (shown as removable "deleted profile" chips).
    let stale_ids = move || {
        if !profiles_loaded.get() || mode_all.get() {
            return Vec::new();
        }
        let known: Vec<String> = profiles.with(|p| p.iter().map(|x| x.id.clone()).collect());
        chosen.with(|c| stale_profiles(c, &known))
    };
    // They only block when they would be sent: always on create, on edit once the choice changed.
    let stale_blocks = move || {
        !stale_ids().is_empty()
            && base.get_value().is_none_or(|b| {
                profile_change(&b.profiles, false, &chosen.get_untracked()) != ProfileChange::Keep
            })
    };
    let snapshot = move || FormValues {
        name: name.get_untracked(),
        choice: choice.get_untracked(),
        custom: custom.get_untracked(),
        all_profiles: mode_all.get_untracked(),
        chosen: chosen.get_untracked(),
        selected: selected.get_untracked(),
        purpose: purpose.get_untracked(),
    };
    let check = move || {
        validate(&Check {
            name: &name.get_untracked(),
            expiry: &resolved.get_untracked(),
            expiry_kept: kept(),
            profiles_empty: no_profiles.get_untracked(),
            stale_profiles: stale_blocks(),
            scopes: &selected.get_untracked(),
        })
    };
    // A problem shown after a failed attempt clears as soon as the form is fixed.
    Effect::new(move |_| {
        name.track();
        resolved.track();
        no_profiles.track();
        selected.track();
        profiles.track();
        profiles_loaded.track();
        chosen.track();
        if error.get_untracked().is_some() && check().is_none() {
            error.set(None);
        }
    });
    // Edit only: nothing differs from the saved token, so there is nothing to save.
    let no_change = Memo::new(move |_| {
        name.track();
        choice.track();
        custom.track();
        mode_all.track();
        chosen.track();
        selected.track();
        base.get_value().is_some_and(|b| {
            update_is_empty(&build_update(
                &b,
                &snapshot(),
                &held_sv.get_value(),
                today(),
                &end_of_day_iso,
            ))
        })
    });

    // Moving to another step puts focus on its heading, so keyboard and screen-reader users
    // land at the top of the new content instead of on a removed button.
    Effect::new(move |prev: Option<u8>| {
        let now = step.get();
        if prev.is_some_and(|p| p != now) {
            gloo_timers::callback::Timeout::new(0, || {
                if let Some(h) = web_sys::window()
                    .and_then(|w| w.document())
                    .and_then(|d| d.get_element_by_id("tk-step-h"))
                {
                    use wasm_bindgen::JsCast;
                    let _ = h.dyn_into::<web_sys::HtmlElement>().map(|h| h.focus());
                }
            })
            .forget();
        }
        now
    });

    let go = {
        let navigate = navigate.clone();
        move |to: &str| navigate(to, Default::default())
    };
    let cancel = {
        let go = go.clone();
        Callback::new(move |_: ()| go("/tokens"))
    };

    let pick = move |p: TokenPurpose| {
        selected.set(purpose_scopes(p, &held_for_pick(&user)));
        purpose.set(p);
        choice.set(purpose_expiry(p).to_string());
        custom.set(String::new());
        step.set(2);
    };

    let to_review = move |_| {
        if let Some((f, m)) = check() {
            error.set(Some((f, m.to_string())));
            return;
        }
        error.set(None);
        step.set(3);
        scroll_top();
    };

    let submit = Callback::new({
        let app_state = app_state.clone();
        let go = go.clone();
        let edit = edit.clone();
        move |_: leptos::ev::MouseEvent| {
            if busy.get_untracked() {
                return;
            }
            if let Some((f, m)) = check() {
                error.set(Some((f, m.to_string())));
                step.set(2);
                return;
            }
            server_error.set(None);
            busy.set(true);
            let values = snapshot();
            let held = held_sv.get_value();
            let baseline = base.get_value();
            let app_state = app_state.clone();
            let go = go.clone();
            let edit = edit.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let client = ApiClient::new();
                let token_name = values.name.trim().to_string();
                let result = match (edit, baseline) {
                    (Some(id), Some(b)) => {
                        let req = build_update(&b, &values, &held, today(), &end_of_day_iso);
                        client.update_token(&id, &req).await.map(|_| None)
                    }
                    _ => client
                        .create_token(&build_create(&values, today(), &end_of_day_iso))
                        .await
                        .map(Some),
                };
                busy.set(false);
                match result {
                    Ok(Some(c)) => reveal.set(Some(Reveal {
                        name: token_name,
                        secret: c.secret,
                        purpose: values.purpose,
                        regenerated: false,
                        prev_valid_until: None,
                    })),
                    Ok(None) => {
                        app_state.success(format!("Saved {token_name}"));
                        go("/tokens");
                    }
                    Err(e) => server_error.set(Some(plain_error(e.code(), &e.text()))),
                }
            });
        }
    });

    let head = {
        let go = go.clone();
        move |title: &'static str| {
            let go = go.clone();
            view! {
                <div>
                    <button type="button" class="lnk tk-back" on:click=move |_| go("/tokens")>
                        <Icon name="chev-l" />"API tokens"
                    </button>
                </div>
                <div class="ph"><div class="t"><h1>{title}</h1></div></div>
            }
        }
    };
    let names: &'static [&'static str] = if is_edit {
        &["Details", "Review"]
    } else {
        &["Purpose", "Details", "Review"]
    };
    let steps = move || {
        let cur = step.get() as usize - usize::from(is_edit);
        view! {
            <ol class="tk-steps" role="list" aria-label="Steps">
                {names.iter().enumerate().map(|(i, n)| {
                    let state = if cur == i + 1 { "on" } else if cur > i + 1 { "done" } else { "" };
                    view! {
                        <li class=format!("tk-step {state}") aria-current=(cur == i + 1).then_some("step")>
                            <b aria-hidden="true">{if cur > i + 1 { "\u{2713}".to_string() } else { (i + 1).to_string() }}</b>{*n}
                            {(cur > i + 1).then(|| view! { <span class="sr-only">" (done)"</span> })}
                        </li>
                    }
                }).collect_view()}
            </ol>
        }
    };
    let step_heading = move |idx: usize| {
        let n = names.len();
        let at = idx - usize::from(is_edit);
        view! {
            <h2 class="sr-only" id="tk-step-h" tabindex="-1">{format!("Step {at} of {n}: {}", names[at - 1])}</h2>
        }
    };

    let unknown_sv = StoredValue::new(unknown.clone());
    let groups = move || {
        let held_rows = held_sv.get_value();
        let initial = initial_scopes.get_value();
        visible_groups(&held_rows)
            .into_iter()
            .map(|g| {
                let group = g.group;
                let held = held_rows.clone();
                let initial = initial.clone();
                view! {
                    <tr class="g"><td colspan="2">
                        {group.label}
                        {group.sensitive.then(|| view! { " "<Pill kind="blocked" text="Sensitive" /> })}
                        {group.hint.map(|h| view! { <span class="ghint">{h}</span> })}
                    </td></tr>
                    {g.rows.into_iter().map(|r| perm_row(group, r, held.clone(), &initial, selected)).collect_view()}
                }
            })
            .collect_view()
    };

    let err_for = move |f: Field| {
        move || {
            error
                .get()
                .filter(|(ef, _)| *ef == f)
                .map(|(_, m)| view! { <span class="err" role="alert">{m}</span> })
        }
    };
    let toggle = move |id: String| {
        chosen.update(|c| {
            if let Some(i) = c.iter().position(|x| *x == id) {
                c.remove(i);
            } else {
                c.push(id);
            }
        })
    };
    let profile_chips = move || {
        profiles
            .get()
            .into_iter()
            .map(|p| {
                let id = p.id.clone();
                let id2 = p.id.clone();
                view! {
                    <ChipSelect
                        pressed=Signal::derive(move || chosen.read().contains(&id))
                        on_toggle=Callback::new(move |_| toggle(id2.clone()))
                    >{p.name.clone()}</ChipSelect>
                }
            })
            .collect_view()
    };
    let stale_chips = move || {
        stale_ids()
            .into_iter()
            .map(|id| {
                let short: String = id.chars().take(8).collect();
                let id2 = id.clone();
                view! {
                    <button type="button" class="chip stale" title=format!("This profile no longer exists (id {short}). Remove it from the token.")
                        aria-label="Remove deleted profile"
                        on:click=move |_| toggle(id2.clone())>
                        <Icon name="alert" />"Deleted profile"<Icon name="x" />
                    </button>
                }
            })
            .collect_view()
    };
    let names_of = move |ids: &[String]| {
        let all = profiles.get();
        ids.iter()
            .map(|id| {
                all.iter()
                    .find(|p| p.id == *id)
                    .map_or_else(|| "deleted profile".to_string(), |p| p.name.clone())
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let profile_names = move || {
        if mode_all.get() {
            "All profiles".to_string()
        } else {
            names_of(&chosen.get())
        }
    };
    // Edit only: the saved token ends later today and the expiry has not been changed.
    let today_note = move || {
        let b = base.get_value()?;
        let at = b.expires_secs?;
        if !kept() {
            return None;
        }
        let now = now_secs();
        expires_today_text(at - now, ymd_of_secs(at) == today())
    };
    let expiry_text = move || expiry_summary(&choice.get(), &custom.get(), kept(), today());
    // Review: what the saved token had, shown beside each changed top-line value.
    let was =
        move |text: Option<String>| text.map(|t| view! { <span class="tk-was">"was "{t}</span> });
    let name_was = move || {
        was(base
            .get_value()
            .filter(|b| b.name != name.get().trim())
            .map(|b| b.name))
    };
    let expiry_was = move || {
        let (c, u) = (choice.get(), custom.get());
        was(base
            .get_value()
            .filter(|b| !expiry_kept(&b.expiry, &c, &u))
            .map(|b| b.expiry_text))
    };
    let profiles_was = move || {
        let (all, ch) = (mode_all.get(), chosen.get());
        was(base.get_value().and_then(|b| {
            (profile_change(&b.profiles, all, &ch) != ProfileChange::Keep).then(|| {
                match &b.profiles {
                    None => "All profiles".to_string(),
                    Some(ids) => names_of(ids),
                }
            })
        }))
    };

    let done = {
        let go = go.clone();
        Callback::new(move |_| go("/tokens"))
    };
    let before = StoredValue::new(base.get_value().map(|b| b.scopes));

    view! {
        {move || reveal.get().map(|r| view! { <RevealPanel reveal=r on_done=done /> })}
        <Show when=move || reveal.get().is_none()>
            {head(if is_edit { "Edit token" } else { "New token" })}
            {steps}
            {dead.then(|| view! {
                <div class="banner err" role="alert">
                    <Icon name="alert" />
                    <span class="bt">{if status == Status::Revoked {
                        "This token was revoked and can't be changed."
                    } else {
                        "This token has expired. Regenerate it with a new expiry to use it again."
                    }}</span>
                </div>
            })}
            // ---- step 1: purpose ----
            <Show when=move || step.get() == 1>
                {step_heading(1)}
                <p class="muted">"What will this token be used for? You can adjust everything on the next step."</p>
                <div class="tk-pcards">
                    {CARD_PURPOSES.map(|p| view! {
                        <button type="button" class="tk-pc" on:click=move |_| pick(p)>
                            <b>{purpose_title(p)}</b>
                            <span>{purpose_desc(p)}</span>
                            <span class="tk-tag acc">"Expires in "{expiry_label(purpose_expiry(p))}</span>
                        </button>
                    }).into_iter().collect_view()}
                </div>
                <div class="row">
                    <button type="button" class="lnk" on:click=move |_| pick(TokenPurpose::ReadOnly)>"Read-only"</button>
                    <span class="dim">"\u{b7}"</span>
                    <button type="button" class="lnk" on:click=move |_| pick(TokenPurpose::Custom)>"Start from scratch"</button>
                </div>
            </Show>
            // ---- step 2: details ----
            <Show when=move || step.get() == 2>
                {step_heading(2)}
                <div class="tk-wrap">
                    <div class="card tk-card">
                        <div class="two">
                            <div class="field">
                                <label for="tk-name">"Name"</label>
                                <input
                                    class="input"
                                    id="tk-name"
                                    autocomplete="off"
                                    placeholder="Firefox on laptop"
                                    aria-invalid=move || error.get().is_some_and(|(f, _)| f == Field::Name).to_string()
                                    prop:value=move || name.get()
                                    on:input=move |ev| name.set(event_target_value(&ev))
                                />
                                {move || match err_for(Field::Name)() {
                                    Some(e) => e.into_any(),
                                    None => view! { <span class="hint">"Where it's used, e.g. a device or a script"</span> }.into_any(),
                                }}
                            </div>
                            <div class="field">
                                <label for="tk-exp">"Expires"</label>
                                <select
                                    class="select"
                                    id="tk-exp"
                                    prop:value=move || choice.get()
                                    on:change=move |ev| choice.set(event_target_value(&ev))
                                >
                                    {EXPIRY_OPTIONS.iter().map(|(v, l)| view! { <option value=*v selected=move || choice.get() == *v>{*l}</option> }).collect_view()}
                                </select>
                                <Show when=move || choice.get() == "custom">
                                    <input
                                        class="input"
                                        type="date"
                                        aria-label="Expiry date"
                                        min=fmt_ymd(add_days(today(), 1))
                                        prop:value=move || custom.get()
                                        on:input=move |ev| custom.set(event_target_value(&ev))
                                    />
                                </Show>
                                {move || match (err_for(Field::Expiry)(), resolved.get()) {
                                    (Some(e), _) => e.into_any(),
                                    (None, Expiry::Never) => view! {
                                        <div class="banner warn">
                                            <Icon name="alert" />
                                            <span class="bt">"Tokens that never expire stay valid if leaked."</span>
                                        </div>
                                    }.into_any(),
                                    _ if today_note().is_some() => view! { <span class="hint warn">{today_note()}</span> }.into_any(),
                                    (None, Expiry::Invalid) if kept() => view! { <span class="hint">{expiry_text()}</span> }.into_any(),
                                    (None, Expiry::Invalid) => view! { <span class="hint">"Pick a date after today"</span> }.into_any(),
                                    (None, e) => view! { <span class="hint">{super::token_form::expiry_line(&e, today())}</span> }.into_any(),
                                }}
                            </div>
                        </div>
                        <div class="field">
                            <span class="lbl">"Profiles"</span>
                            <Segmented
                                label="Profiles"
                                options=vec![("all".to_string(), "All profiles".to_string()), ("choose".to_string(), "Choose".to_string())]
                                value=Signal::derive(move || if mode_all.get() { "all".to_string() } else { "choose".to_string() })
                                on_change=Callback::new(move |v: String| mode_all.set(v == "all"))
                            />
                            <Show when=move || !mode_all.get()>
                                <div class="chips">
                                    {profile_chips}
                                    {stale_chips}
                                    {move || (profiles_loaded.get() && profiles.with(|p| p.is_empty()) && stale_ids().is_empty()).then(|| view! { <span class="hint">"There are no profiles yet."</span> })}
                                </div>
                            </Show>
                            {err_for(Field::Profiles)}
                        </div>
                        <div class="sec-t">"Permissions"</div>
                        {permissions_note(hidden_row_count(&held_sv.get_value()), dropped).map(|n| view! {
                            <div class="banner info"><Icon name="alert" /><span class="bt">{n}</span></div>
                        })}
                        {err_for(Field::Access)}
                        <div class="tk-tw">
                            <table class="pt">
                                <thead><tr><th>"Permission"</th><th>"Access"</th></tr></thead>
                                <tbody>{groups}</tbody>
                            </table>
                        </div>
                    </div>
                    <aside class="card tk-card tk-sum" aria-live="polite">
                        <b>"This token can:"</b>
                        {move || {
                            let can = selected.with(|s| can_list(s));
                            if can.is_empty() {
                                view! { <p class="muted">"Nothing yet. Pick a level for at least one area."</p> }.into_any()
                            } else {
                                view! { <ul>{can.into_iter().map(|c| view! { <li>{c}</li> }).collect_view()}</ul> }.into_any()
                            }
                        }}
                        <b>"It cannot:"</b>
                        <p class="muted">{move || selected.with(|s| cannot_sentence(s))}</p>
                    </aside>
                </div>
                {foot(cancel, step, if is_edit { None } else { Some(1) }, view! {
                    <button type="button" class="btn primary" disabled=dead on:click=to_review>"Review"</button>
                }.into_any())}
            </Show>
            // ---- step 3: review ----
            <Show when=move || step.get() == 3>
                {step_heading(3)}
                <div class="card tk-card">
                    <div class="row tk-meta">
                        <b>{move || name.get().trim().to_string()}</b>
                        {name_was}
                        <span class="tk-tag" class:acc=move || today_note().is_none() class:warn=move || today_note().is_some()>
                            {move || today_note().unwrap_or_else(expiry_text)}
                        </span>
                        {expiry_was}
                        <span class="tk-tag">{profile_names}</span>
                        {profiles_was}
                    </div>
                    <p>{move || selected.with(|s| summary_sentence(s))}</p>
                    {
                        move || match before.get_value() {
                            Some(b) => view! { <GrantedList scopes=selected.get() unknown=unknown_sv.get_value() before=b /> }.into_any(),
                            None => view! { <GrantedList scopes=selected.get() unknown=unknown_sv.get_value() /> }.into_any(),
                        }
                    }
                    {move || (resolved.get() == Expiry::Never).then(|| view! {
                        <div class="banner warn">
                            <Icon name="alert" />
                            <span class="bt">"Tokens that never expire stay valid if leaked."</span>
                        </div>
                    })}
                    {move || (mode_all.get() && base.get_value().is_some_and(|b| b.profiles.is_some())).then(|| view! {
                        <div class="banner warn">
                            <Icon name="alert" />
                            <span class="bt">"Now applies to all profiles."</span>
                        </div>
                    })}
                    {move || server_error.get().map(|m| view! {
                        <div class="banner err" role="alert"><Icon name="alert" /><span class="bt">{m}</span></div>
                    })}
                    <div class="card-footer">
                        <button type="button" class="btn ghost" on:click=move |_| cancel.run(())>"Cancel"</button>
                        <span class="sp"></span>
                        {move || no_change.get().then(|| view! { <span class="dim tk-nc">"No changes"</span> })}
                        <button type="button" class="btn" on:click=move |_| { step.set(2); scroll_top(); }>"Back"</button>
                        <button type="button" class="btn primary" disabled=move || busy.get() || dead || no_change.get() on:click=move |ev| submit.run(ev)>
                            {if is_edit { "Save changes" } else { "Create token" }}
                        </button>
                    </div>
                </div>
            </Show>
        </Show>
    }
}

fn held_for_pick(user: &RwSignal<Option<crate::api::auth::UserInfo>>) -> Vec<Scope> {
    user.get_untracked().map(|u| u.scopes).unwrap_or_default()
}

fn scroll_top() {
    if let Some(m) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.get_element_by_id("main"))
    {
        m.set_scroll_top(0);
    }
}

/// Sticky action bar under the form: Cancel at the left, Back and the primary action at the right.
fn foot(
    cancel: Callback<()>,
    step: RwSignal<u8>,
    back_to: Option<u8>,
    primary: AnyView,
) -> impl IntoView {
    view! {
        <div class="tk-foot">
            <button type="button" class="btn ghost" on:click=move |_| cancel.run(())>"Cancel"</button>
            <span class="sp"></span>
            {back_to.map(|b| view! {
                <button type="button" class="btn" on:click=move |_| { step.set(b); scroll_top(); }>"Back"</button>
            })}
            {primary}
        </div>
    }
}

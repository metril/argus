//! Pieces shared by the token pages: clock helpers, the dense permission list, status pill and
//! the reveal panel.

use api_types::{Scope, TokenPurpose};
use leptos::prelude::*;

use super::token_form::{grace_sentence, granted_vs, howto, Status, Ymd};
use crate::components::Icon;
use crate::utils::{copy_text, fmt_datetime};

/// Seconds since the epoch.
pub fn now_secs() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

/// Local calendar date today.
pub fn today() -> Ymd {
    ymd_local(js_sys::Date::new_0())
}

/// Local calendar date of an instant given in epoch seconds.
pub fn ymd_of_secs(secs: i64) -> Ymd {
    ymd_local(js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(
        secs as f64 * 1000.0,
    )))
}

fn ymd_local(d: js_sys::Date) -> Ymd {
    (d.get_full_year() as i32, d.get_month() + 1, d.get_date())
}

/// RFC 3339 instant for the end of local day `d`.
pub fn end_of_day_iso(d: Ymd) -> String {
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

/// "Sat, 28 Nov 2026, 04:48" (local time) for an RFC 3339 instant.
pub fn long_datetime(ts: &str) -> String {
    let Some(secs) = super::token_form::parse_rfc3339(ts) else {
        return fmt_datetime(ts);
    };
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(secs as f64 * 1000.0));
    format!(
        "{}, {:02}:{:02}",
        super::token_form::long_date(ymd_of_secs(secs)),
        d.get_hours(),
        d.get_minutes()
    )
}

/// The address the browser reached Argus at (for the how-to snippet).
pub fn origin() -> String {
    web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_default()
}

/// Status word as a pill.
#[component]
pub fn StatusPill(status: Status) -> impl IntoView {
    let kind = match status {
        Status::Active => "allowed",
        Status::Expiring => "warn",
        Status::Expired | Status::Revoked => "blocked",
    };
    view! { <crate::components::Pill kind=kind text=status.label() /> }
}

/// One dense list of granted permissions: area, level, scope names, Sensitive pill. Scope names
/// this version does not know are listed as they are.
#[component]
pub fn GrantedList(
    scopes: Vec<Scope>,
    #[prop(optional)] unknown: Vec<String>,
    /// The token's scopes before an edit: changed rows are marked "was X to Y".
    #[prop(optional)]
    before: Option<Vec<Scope>>,
) -> impl IntoView {
    let groups = granted_vs(&scopes, before.as_deref());
    let empty = groups.is_empty() && unknown.is_empty();
    view! {
        {empty.then(|| view! { <p class="muted">"No permissions granted."</p> })}
        {groups.into_iter().map(|g| view! {
            <div class="tk-gl">
                <div class="tk-gh">{g.label}</div>
                {g.rows.into_iter().map(|r| view! {
                    <div class="tk-pl" class:chg={r.was.is_some()}>
                        <span class="pa">{r.area}</span>
                        <span class="pv2">{r.level}</span>
                        <span class="ptags">
                            {r.was.clone().map(|w| view! { <span class="tk-was">{w}</span> })}
                            {r.scopes.into_iter().map(|s| view! { <code class="tg">{s}</code> }).collect_view()}
                        </span>
                        <span class="pe">{r.sensitive.then(|| view! { <crate::components::Pill kind="blocked" text="Sensitive" /> })}</span>
                    </div>
                }).collect_view()}
            </div>
        }).collect_view()}
        {(!unknown.is_empty()).then(|| view! {
            <div class="tk-gl">
                <div class="tk-gh">"Not recognised by this version"</div>
                {unknown.into_iter().map(|u| view! {
                    <div class="tk-pl">
                        <span class="pa"><code class="tg">{u}</code></span>
                        <span class="pv2">"Unknown"</span>
                        <span class="ptags"></span>
                        <span class="pe"></span>
                    </div>
                }).collect_view()}
            </div>
        })}
    }
}

/// What the reveal panel shows. The secret lives only in this value and on screen.
#[derive(Clone)]
pub struct Reveal {
    pub name: String,
    pub secret: String,
    pub purpose: TokenPurpose,
    pub regenerated: bool,
    /// From the returned token: until when the previous secret still works.
    pub prev_valid_until: Option<String>,
}

/// The one-time secret after create or regenerate: copyable, with usage help and a Done button
/// that asks first when the secret was not copied.
#[component]
pub fn RevealPanel(reveal: Reveal, on_done: Callback<()>) -> impl IntoView {
    let copied = RwSignal::new(false);
    let leaving = RwSignal::new(false);
    let announce = RwSignal::new(String::new());
    let secret = reveal.secret.clone();
    let snippet = howto(reveal.purpose, &origin());
    let note = reveal
        .regenerated
        .then(|| {
            let until = reveal.prev_valid_until.as_deref()?;
            let written = long_datetime(until);
            grace_sentence(until, now_secs(), &written)
        })
        .flatten();
    let do_copy = move |_| {
        if copy_text(&secret) {
            copied.set(true);
            leaving.set(false);
            announce.set("Token copied to the clipboard".into());
        } else {
            announce.set("Could not copy. Select the token and copy it by hand.".into());
        }
    };
    let done = move |_| {
        if copied.get_untracked() || leaving.get_untracked() {
            on_done.run(());
        } else {
            leaving.set(true);
        }
    };
    let shown = reveal.secret.clone();
    view! {
        <div class="ph">
            <div class="t">
                <h1>{if reveal.regenerated { "Token regenerated" } else { "Token created" }}</h1>
                <p class="muted">{reveal.name.clone()}</p>
            </div>
        </div>
        <div class="card tk-card tk-reveal">
            <div class="banner warn" role="status">
                <Icon name="alert" />
                <span class="bt"><b>"Copy your token now."</b>" This is the only time it's shown. If you lose it, regenerate it."</span>
            </div>
            <div class="attach">
                <div class="secret" id="tk-secret"><span>{shown}</span></div>
                <button type="button" class="btn tk-copy" class:ok=move || copied.get() on:click=do_copy>
                    {move || if copied.get() { view! { <Icon name="check" />"Copied" }.into_any() } else { view! { <Icon name="copy" />"Copy" }.into_any() }}
                </button>
            </div>
            <span class="sr-only" role="status" aria-live="polite">{move || announce.get()}</span>
            {note.map(|n| view! { <p class="muted">{n}</p> })}
            <div class="sec-t">"How to use it"</div>
            <pre class="tk-pv">{snippet}</pre>
            <div class="card-footer">
                <span class="dim">{move || (leaving.get() && !copied.get()).then_some("Not copied.")}</span>
                <button type="button" class="btn primary tk-done" on:click=done>
                    {move || if leaving.get() && !copied.get() { "Leave anyway?" } else { "Done" }}
                </button>
                <Show when=move || leaving.get() && !copied.get()>
                    <button type="button" class="btn ghost" on:mousedown=move |ev| ev.prevent_default()
                        on:click=move |_| leaving.set(false)>"Stay"</button>
                </Show>
            </div>
        </div>
    }
}

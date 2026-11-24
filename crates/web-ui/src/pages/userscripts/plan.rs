//! Review drawer: install plan, pending update, or imported-script approval.

use std::sync::Arc;

use leptos::prelude::*;

use super::model::*;
use crate::api::userscripts::{UpdateDiffDto, Userscript, UserscriptPlanResponse};
use crate::api::ApiClient;
use crate::components::{Drawer, Icon};
use crate::state::use_app_state;

#[derive(Clone, Debug, PartialEq)]
pub enum ReviewKind {
    /// A planned install (plan id).
    Install(String),
    /// A script's pending update (script id).
    Update(String),
    /// An imported script waiting to be enabled (script id).
    Approve(String),
}

/// One external file (`@require` / `@resource`).
#[derive(Clone)]
pub struct ReqRow {
    pub label: Option<String>,
    pub url: String,
    pub size: u64,
    pub sri: bool,
}

/// A warning: plain title, raw technical detail, and whether it is in the error colour.
#[derive(Clone)]
pub struct Warn {
    pub title: String,
    pub detail: String,
    pub error: bool,
}

/// Everything the review drawer shows, whichever flow it came from.
#[derive(Clone)]
pub struct Review {
    pub kind: ReviewKind,
    pub name: String,
    pub version: Option<String>,
    pub new_version: Option<String>,
    pub author: Option<String>,
    pub source: Option<String>,
    pub description: Option<String>,
    pub grants: Vec<String>,
    pub connect: Vec<String>,
    pub matches: Vec<String>,
    pub broad_match: bool,
    pub reqs: Vec<ReqRow>,
    /// Number of external files when their details are unknown (an installed script).
    pub req_count: usize,
    pub warns: Vec<Warn>,
    /// Serious warnings (from the server's `high_warnings`), shown in a danger callout.
    pub high: Vec<String>,
    pub notes: Vec<String>,
    pub diff: Option<UpdateDiffDto>,
    pub needs_reapproval: bool,
    /// The script declares `@connect *`: the review asks whether to allow it.
    pub wants_any: bool,
}

fn warn_from(raw: &str, unsupported: bool) -> Warn {
    let l = raw.to_ascii_lowercase();
    let (title, error) = if l.contains("bad regex") || l.contains("pattern") {
        // "@exclude /re/: bad regex: ..." -> "Ignored @exclude pattern: /re/"
        let directive = raw.split_whitespace().next().unwrap_or("");
        let pat = raw
            .strip_prefix(directive)
            .unwrap_or(raw)
            .split(": bad regex")
            .next()
            .unwrap_or("")
            .trim();
        let short: String = pat.chars().take(48).collect();
        let dots = if pat.chars().count() > 48 {
            "\u{2026}"
        } else {
            ""
        };
        if directive.starts_with('@') {
            (format!("Ignored {directive} pattern: {short}{dots}"), true)
        } else {
            ("A pattern was ignored".to_string(), true)
        }
    } else if unsupported {
        ("Part of the script is not supported".to_string(), true)
    } else {
        let t: String = raw.chars().take(90).collect();
        (t, false)
    };
    Warn {
        title,
        detail: raw.to_string(),
        error,
    }
}

impl Review {
    pub fn from_plan(p: UserscriptPlanResponse, source_url: Option<&str>) -> Self {
        let mut reqs: Vec<ReqRow> = p
            .requires
            .iter()
            .map(|r| ReqRow {
                label: None,
                url: r.url.clone(),
                size: r.size_bytes as u64,
                sri: r.sri_verified,
            })
            .collect();
        reqs.extend(p.resources.iter().map(|r| ReqRow {
            label: Some(format!("@resource {}", r.name)),
            url: r.url.clone(),
            size: r.size_bytes as u64,
            sri: r.sri_verified,
        }));
        let mut warns: Vec<Warn> = p.unsupported.iter().map(|u| warn_from(u, true)).collect();
        warns.extend(p.warnings.iter().map(|w| warn_from(w, false)));
        // A high warning is shown once, in the callout, not again in the list.
        warns.retain(|w| {
            let pat = w
                .detail
                .split_once(' ')
                .map(|(_, r)| r.split(": bad regex").next().unwrap_or("").trim())
                .unwrap_or("");
            !p.high_warnings
                .iter()
                .any(|h| *h == w.detail || (!pat.is_empty() && h.contains(pat)))
        });
        let unhashed = reqs.iter().filter(|r| !r.sri).count();
        if unhashed > 0 {
            warns.push(Warn {
                title: format!(
                    "No integrity hash for {unhashed} external file{}",
                    if unhashed == 1 { "" } else { "s" }
                ),
                detail: "The files are fetched once at install time; nothing proves they match what the author published.".into(),
                error: true,
            });
        }
        let mut notes = Vec::new();
        if p.already_installed {
            notes.push(format!(
                "Already installed{}. Installing replaces it with this version.{}",
                p.installed_version
                    .as_ref()
                    .map(|v| format!(" (version {v})"))
                    .unwrap_or_default(),
                if p.update.as_ref().is_some_and(|u| !u.is_newer) {
                    " This is not a newer version."
                } else {
                    ""
                }
            ));
        }
        let mut connect = p.connect.clone();
        if p.connect_all && !connect.iter().any(|c| c == "*") {
            connect.push("*".into());
        }
        Review {
            kind: ReviewKind::Install(p.plan_id.clone()),
            name: p.name.clone(),
            version: p.version.clone(),
            new_version: None,
            author: None,
            source: source_url.map(url_host).filter(|h| !h.is_empty()),
            description: p.description.clone(),
            grants: p.grants.clone(),
            connect,
            matches: p.matches.clone(),
            broad_match: p.broad_match,
            reqs,
            req_count: 0,
            warns,
            high: p.high_warnings.clone(),
            notes,
            needs_reapproval: p.update.as_ref().is_some_and(|u| u.needs_reapproval),
            diff: p.update.map(|u| u.diff),
            wants_any: p.connect_all,
        }
    }

    /// A pending update of an installed script.
    pub fn from_update(s: &Userscript) -> Option<Self> {
        let p = s.pending_update.clone()?;
        let mut r = Self::from_script(s, ReviewKind::Update(s.id.clone()));
        // Judge the risk of the version being approved: the current script with the diff applied.
        let apply = |cur: &mut Vec<String>, add: &[String], del: &[String], strip: bool| {
            let clean = |x: &String| {
                if strip {
                    x.strip_prefix("@match ")
                        .or_else(|| x.strip_prefix("@include "))
                        .unwrap_or(x)
                        .to_string()
                } else {
                    x.clone()
                }
            };
            let del: Vec<String> = del.iter().map(clean).collect();
            cur.retain(|c| !del.contains(c));
            for a in add.iter().map(clean) {
                if !cur.contains(&a) {
                    cur.push(a);
                }
            }
        };
        apply(
            &mut r.matches,
            &p.diff.added_matches,
            &p.diff.removed_matches,
            true,
        );
        apply(
            &mut r.connect,
            &p.diff.added_connect,
            &p.diff.removed_connect,
            false,
        );
        apply(
            &mut r.grants,
            &p.diff.added_grants,
            &p.diff.removed_grants,
            false,
        );
        r.new_version = p.new_version.clone();
        r.wants_any = p.diff.added_connect.iter().any(|c| c == "*");
        r.needs_reapproval = p.needs_reapproval;
        r.notes.push(format!("Found {}", fmt_abs(&p.found_at)));
        r.diff = Some(p.diff);
        Some(r)
    }

    /// An imported script that is still disabled.
    pub fn from_approval(s: &Userscript) -> Self {
        let mut r = Self::from_script(s, ReviewKind::Approve(s.id.clone()));
        r.notes
            .push("Imported from a file. It stays off until you approve it here.".to_string());
        r
    }

    fn from_script(s: &Userscript, kind: ReviewKind) -> Self {
        let mut warns: Vec<Warn> = s.unsupported.iter().map(|u| warn_from(u, true)).collect();
        warns.extend(s.warnings.iter().map(|w| warn_from(w, false)));
        let (_, every) = site_list(&s.match_patterns);
        Review {
            kind,
            name: s.name.clone(),
            version: s.version.clone(),
            new_version: None,
            author: s.author.clone(),
            source: s.update_url.as_deref().map(url_host),
            description: s.description.clone(),
            grants: s.grants.clone(),
            connect: s.connect.clone(),
            matches: s.match_patterns.clone(),
            broad_match: every,
            reqs: Vec::new(),
            req_count: s.require_count + s.resource_count,
            warns,
            high: Vec::new(),
            notes: Vec::new(),
            diff: None,
            needs_reapproval: false,
            wants_any: s.connect.iter().any(|c| c == "*"),
        }
    }

    fn unhashed(&self) -> bool {
        self.reqs.iter().any(|r| !r.sri)
    }

    fn n_ext(&self) -> usize {
        self.reqs.len().max(self.req_count)
    }

    pub fn perms(&self) -> Vec<(&'static str, String, bool)> {
        perm_items(&self.grants, &self.connect, self.n_ext(), self.unhashed())
    }

    /// `(level, verdict)`; level is `low`, `med` or `high`.
    pub fn risk(&self) -> (&'static str, String) {
        let items = self.perms();
        let (_, every) = site_list(&self.matches);
        let every = every || self.broad_match;
        let any_site = items
            .iter()
            .any(|i| i.1.starts_with("Can contact any site"));
        let hot = items.iter().any(|i| i.2);
        let level = if any_site || (every && hot) {
            "high"
        } else if hot || every {
            "med"
        } else {
            "low"
        };
        let mut parts: Vec<String> = Vec::new();
        if every {
            parts.push("Runs on every site".into());
        }
        for (_, t, h) in &items {
            if *h {
                let t = if parts.is_empty() {
                    t.clone()
                } else {
                    lower_first(t)
                };
                parts.push(t);
            }
        }
        let verdict = if parts.is_empty() {
            "Limited to the sites it names, with no sensitive permissions".to_string()
        } else {
            parts.join(" and ")
        };
        (level, verdict)
    }
}

fn lower_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Added items in the hot colour, removed ones plain.
pub fn diff_rows(d: UpdateDiffDto) -> impl IntoView {
    fn site(i: String) -> String {
        i.strip_prefix("@match ")
            .or_else(|| i.strip_prefix("@include "))
            .map(str::to_string)
            .unwrap_or(i)
    }
    fn conn(i: String) -> String {
        if i == "*" {
            "Any site".to_string()
        } else {
            i
        }
    }
    let row = |label: &'static str, items: Vec<String>, hot: bool, f: fn(String) -> String| {
        (!items.is_empty()).then(|| {
            view! {
                <div class="sec">
                    <h4 class="sec-title">{label}</h4>
                    <div class="pats">
                        {items.into_iter().map(|i| view! { <span class=if hot { "pat hot" } else { "pat" }>{f(i)}</span> }).collect_view()}
                    </div>
                </div>
            }
        })
    };
    view! {
        {row("Added sites", d.added_matches, true, site)}
        {row("Added connections", d.added_connect, true, conn)}
        {row("Added permissions", d.added_grants, true, |g| grant_display(&g))}
        {row("Removed sites", d.removed_matches, false, site)}
        {row("Removed connections", d.removed_connect, false, conn)}
        {row("Removed permissions", d.removed_grants, false, |g| grant_display(&g))}
        {row("Other widening", d.widened, true, |w| w)}
    }
}

/// An external URL with the host in bold, its size and hash state.
#[component]
pub fn UrlRow(
    #[prop(into)] url: String,
    #[prop(optional)] size: Option<u64>,
    #[prop(optional)] sri: Option<bool>,
    #[prop(into, optional)] label: String,
) -> impl IntoView {
    let (host, rest) = split_url(&url);
    view! {
        <div class="urlrow">
            <code>
                {(!label.is_empty()).then(|| view! { <span class="dim">{format!("{label} ")}</span> })}
                <b>{host}</b>{rest}
            </code>
            <span class="row-gap">
                {size.map(|s| view! { <span class="dim">{fmt_bytes(s)}</span> })}
                {sri.map(|ok| if ok {
                    view! { <span class="pill p-allow">"hash ok"</span> }
                } else {
                    view! { <span class="pill p-error">"no hash"</span> }
                })}
            </span>
        </div>
    }
}

/// One warning: a plain sentence, raw detail collapsed.
#[component]
pub fn WarnItem(w: Warn) -> impl IntoView {
    let same = w.detail == w.title;
    view! {
        <div class=if w.error { "warnitem err" } else { "warnitem" }>
            <div class="wt"><Icon name="alert" /><span>{w.title.clone()}</span></div>
            {(!same).then(|| view! {
                <details><summary>"Technical detail"</summary><pre class="wrap">{w.detail.clone()}</pre></details>
            })}
        </div>
    }
}

/// The risk box: verdict plus the plain-language permission list.
#[component]
pub fn RiskSummary(review: Review) -> impl IntoView {
    let (level, verdict) = review.risk();
    let items = review.perms();
    let icon = if level == "low" { "check" } else { "alert" };
    view! {
        <div class=format!("risk {level}") role="group" aria-label="Risk summary">
            <div class="rv"><Icon name=icon /><b>{verdict}</b></div>
            <ul>
                {items.into_iter().map(|(i, t, hot)| view! {
                    <li class=if hot { "hot" } else { "" }><Icon name=i />{t}</li>
                }).collect_view()}
            </ul>
        </div>
    }
}

/// The review drawer. `on_done` runs after a successful confirm/approve/discard.
#[component]
pub fn PlanDrawer(
    review: RwSignal<Option<Review>>,
    open: RwSignal<bool>,
    on_done: Callback<()>,
) -> impl IntoView {
    let app = StoredValue::new(use_app_state());
    let busy = RwSignal::new(false);
    let err = RwSignal::new(Option::<String>::None);
    let all_pats = RwSignal::new(false);
    // Permission question for `@connect *`; always starts off.
    let allow = RwSignal::new(false);
    Effect::new(move |_| {
        if open.get() {
            allow.set(false);
            err.set(None);
            all_pats.set(false);
        }
    });
    let title = Signal::derive(move || match review.get().map(|r| r.kind) {
        Some(ReviewKind::Update(_)) => "Review update".to_string(),
        Some(ReviewKind::Approve(_)) => "Approve imported script".to_string(),
        _ => "Review install".to_string(),
    });
    let high = move || review.with(|r| r.as_ref().is_some_and(|r| r.risk().0 == "high"));
    let confirm_label = move || {
        let k = review.with(|r| r.as_ref().map(|r| r.kind.clone()));
        let base = match k {
            Some(ReviewKind::Update(_)) => "Approve update",
            Some(ReviewKind::Approve(_)) => "Approve",
            _ => "Install",
        };
        if high() {
            match base {
                "Install" => "Install anyway".to_string(),
                b => format!("{b} anyway"),
            }
        } else {
            base.to_string()
        }
    };
    let run = move |discard: bool| {
        let Some(r) = review.get_untracked() else {
            return;
        };
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        err.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            let c = ApiClient::new();
            let res: Result<&str, crate::api::ApiError> = match (&r.kind, discard) {
                (ReviewKind::Install(pid), _) => c
                    .confirm_userscript_plan(pid, r.wants_any && allow.get_untracked())
                    .await
                    .map(|_| "Userscript installed"),
                (ReviewKind::Update(id), false) => c
                    .approve_userscript_update(id, r.wants_any && allow.get_untracked())
                    .await
                    .map(|_| "Update applied"),
                (ReviewKind::Update(id), true) => c
                    .discard_userscript_update(id)
                    .await
                    .map(|_| "Update discarded"),
                (ReviewKind::Approve(id), _) => c
                    .approve_userscript(id, r.wants_any && allow.get_untracked())
                    .await
                    .map(|_| "Script approved and enabled"),
            };
            match res {
                Ok(msg) => {
                    app.get_value().success(msg);
                    open.set(false);
                    on_done.run(());
                }
                Err(e) => err.set(Some(e.to_string())),
            }
            busy.set(false);
        });
    };
    let footer: ChildrenFn = Arc::new(move || {
        view! {
            {move || review.get().filter(|r| !r.high.is_empty()).map(|r| view! {
                <div class="callout" role="alert">
                    <Icon name="alert" />
                    <ul>{r.high.iter().map(|h| view! { <li>{h.clone()}</li> }).collect_view()}</ul>
                </div>
            })}
            {move || review.get().filter(|r| r.wants_any).map(|r| {
                let verb = match r.kind {
                    ReviewKind::Install(_) => "installed",
                    ReviewKind::Update(_) => "updated",
                    ReviewKind::Approve(_) => "approved",
                };
                view! {
                    <label class="ask">
                        <input type="checkbox" prop:checked=move || allow.get()
                            on:change=move |ev| allow.set(event_target_checked(&ev)) />
                        <span>
                            <b>"Allow contacting any site"</b>
                            <span class="muted">{format!(" This script declares @connect *. Off: it is {verb}, but its requests to other sites are blocked.")}</span>
                        </span>
                    </label>
                }
            })}
            <button type="button" class="btn ghost" on:click=move |_| open.set(false)>"Cancel"</button>
            {move || matches!(review.get().map(|r| r.kind), Some(ReviewKind::Update(_))).then(|| view! {
                <button type="button" class="btn danger" aria-disabled=move || busy.get().to_string() on:click=move |_| run(true)>"Discard update"</button>
            })}
            <button type="button" class=move || if high() { "btn primary hi" } else { "btn primary" }
                aria-disabled=move || busy.get().to_string() on:click=move |_| run(false)>
                {move || busy.get().then(|| view! { <span class="spin"></span> })}
                {confirm_label}
            </button>
        }
        .into_any()
    });
    view! {
        <Drawer title=title open=open class="wide" footer=footer>
            {move || review.get().map(|r| {
                let pats: Vec<String> = r.matches.clone();
                let n_pats = pats.len();
                let grants = r.grants.clone();
                let reqs = r.reqs.clone();
                let warns = r.warns.clone();
                let rr = r.clone();
                view! {
                    <div class="plan-h">
                        <h3>{r.name.clone()}
                            {r.version.clone().map(|v| view! { <span class="ver">{v}</span> })}
                            {r.new_version.clone().map(|v| view! { <span class="ver">{format!("\u{2192} {v}")}</span> })}
                        </h3>
                        <div class="meta">
                            {r.author.clone().map(|a| view! { <span>{format!("by {a}")}</span> })}
                            {r.source.clone().map(|h| view! { <span>{format!("from {h}")}</span> })}
                        </div>
                        {r.description.clone().map(|d| view! { <p class="muted">{d}</p> })}
                    </div>
                    {r.notes.iter().map(|n| view! { <div class="hint box">{n.clone()}</div> }).collect_view()}
                    <RiskSummary review=rr />
                    {r.diff.clone().map(|d| view! {
                        <div class="sec">
                            <h4 class="sec-title">"What changed"</h4>
                            {r.needs_reapproval.then(|| view! {
                                <div class="warnitem err"><div class="wt"><Icon name="alert" />
                                    <span>"This version widens what the script may match, reach or run."</span></div></div>
                            })}
                            {diff_rows(d)}
                        </div>
                    })}
                    <div class="sec">
                        <h4 class="sec-title">"Runs on"</h4>
                        <div class="pats">
                            {move || {
                                let all = all_pats.get();
                                pats.iter().take(if all { usize::MAX } else { 12 }).map(|p| {
                                    let hot = site_name(p).is_none();
                                    view! { <span class=if hot { "pat hot" } else { "pat" }>{p.clone()}</span> }
                                }).collect_view()
                            }}
                        </div>
                        {(n_pats > 12).then(|| view! {
                            <button type="button" class="linkish" on:click=move |_| all_pats.update(|a| *a = !*a)>
                                {move || if all_pats.get() { "Show fewer".to_string() } else { format!("Show all {n_pats}") }}
                            </button>
                        })}
                        {(n_pats == 0).then(|| view! { <span class="muted">"No sites listed"</span> })}
                    </div>
                    {(!grants.is_empty()).then(|| view! {
                        <div class="sec">
                            <h4 class="sec-title">"Permissions"</h4>
                            <dl class="kv wide">
                                {grants.iter().map(|g| view! {
                                    <dt class="mono">{grant_display(g)}</dt>
                                    <dd>{grant_meaning(g)}
                                        {is_sensitive_grant(g).then(|| view! { " " <span class="pill p-error">"Sensitive"</span> })}</dd>
                                }).collect_view()}
                            </dl>
                        </div>
                    })}
                    {(!r.connect.is_empty()).then(|| view! {
                        <div class="sec">
                            <h4 class="sec-title">"Can contact"</h4>
                            <div class="pats">
                                {r.connect.iter().map(|c| {
                                    let any = c == "*";
                                    view! { <span class=if any { "pat hot" } else { "pat" }>{if any { "Any site".to_string() } else { c.clone() }}</span> }
                                }).collect_view()}
                            </div>
                        </div>
                    })}
                    {(!reqs.is_empty()).then(|| view! {
                        <div class="sec">
                            <h4 class="sec-title">"External code"</h4>
                            {reqs.iter().map(|q| view! {
                                <UrlRow url=q.url.clone() size=q.size sri=q.sri label=q.label.clone().unwrap_or_default() />
                            }).collect_view()}
                        </div>
                    })}
                    {(reqs.is_empty() && r.req_count > 0).then(|| view! {
                        <div class="sec">
                            <h4 class="sec-title">"External code"</h4>
                            <span class="muted">{format!("{} external file{} stored with the script", r.req_count, if r.req_count == 1 { "" } else { "s" })}</span>
                        </div>
                    })}
                    {(!warns.is_empty()).then(|| view! {
                        <div class="sec">
                            <h4 class="sec-title">"Warnings"</h4>
                            {warns.into_iter().map(|w| view! { <WarnItem w=w /> }).collect_view()}
                        </div>
                    })}
                }
            })}
            {move || err.get().map(|e| view! { <div class="err" role="alert">{format!("Failed: {e}")}</div> })}
        </Drawer>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(
        grants: &[&str],
        connect: &[&str],
        matches: &[&str],
        pend: Option<serde_json::Value>,
    ) -> Userscript {
        serde_json::from_value(serde_json::json!({
            "id": "ns:n", "name": "n", "enabled": true, "execution_count": 0,
            "match_patterns": matches, "pending_update": pend,
            "grants": grants, "connect": connect, "connect_all_approved": false,
            "unsupported": [], "warnings": [], "noframes": false, "storage_bytes": 0,
            "require_count": 0, "resource_count": 0, "updated_at": "", "error": false
        }))
        .unwrap()
    }

    fn pending(add_m: &[&str], add_c: &[&str], add_g: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "new_version": "2.0", "needs_reapproval": true, "found_at": "2026-01-01T00:00:00Z",
            "diff": {"added_matches": add_m, "added_connect": add_c, "added_grants": add_g,
                     "removed_matches": [], "removed_connect": [], "removed_grants": [], "widened": []}
        })
    }

    #[test]
    fn risk_levels() {
        let low =
            Review::from_approval(&script(&["gm_getvalue"], &[], &["https://a.test/*"], None));
        assert_eq!(low.risk().0, "low");
        let med = Review::from_approval(&script(
            &["gm_setclipboard"],
            &[],
            &["https://a.test/*"],
            None,
        ));
        assert_eq!(med.risk().0, "med");
        let every = Review::from_approval(&script(&[], &[], &["*://*/*"], None));
        assert_eq!(every.risk().0, "med");
        let high = Review::from_approval(&script(
            &["gm_xmlhttprequest"],
            &["*"],
            &["https://a.test/*"],
            None,
        ));
        assert_eq!(high.risk().0, "high");
        assert!(high.wants_any);
        // xhr with no @connect: same wording as the catalogue, still high.
        let none = Review::from_approval(&script(
            &["GM_xmlhttpRequest"],
            &[],
            &["https://a.test/*"],
            None,
        ));
        assert_eq!(none.risk().0, "high");
        assert!(!none.wants_any);
    }

    #[test]
    fn update_review_judges_the_new_version() {
        let s = script(
            &["gm_getvalue"],
            &[],
            &["https://a.test/*"],
            Some(pending(
                &["@match https://*.b.test/*"],
                &["*"],
                &["gm_xmlhttprequest"],
            )),
        );
        let r = Review::from_update(&s).unwrap();
        assert_eq!(r.risk().0, "high");
        assert!(r.wants_any);
        assert!(r.matches.contains(&"https://*.b.test/*".to_string()));
        assert!(r.grants.contains(&"gm_xmlhttprequest".to_string()));
        assert_eq!(r.new_version.as_deref(), Some("2.0"));
        assert!(Review::from_update(&script(&[], &[], &[], None)).is_none());
    }
}

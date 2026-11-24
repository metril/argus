//! Browse tab: the signed catalogue as a divided list of entries.

use leptos::prelude::*;

use super::installed::script_href;
use super::model::*;
use super::plan::Review;
use super::Ctx;
use crate::api::userscripts::{UserscriptCatalogueEntryDto, UserscriptCatalogueResponse};
use crate::api::ApiClient;
use crate::components::Icon;

const HINT_KEY: &str = "us.hint.dismissed";

/// Where the entry runs and what it may do, in plain words.
#[component]
fn PermSummary(entry: UserscriptCatalogueEntryDto) -> impl IntoView {
    let (hosts, every) = site_list(&entry.sites);
    let expanded = RwSignal::new(false);
    let n = hosts.len();
    let shown = hosts.clone();
    let items = perm_summary(&entry);
    // At most two lines: capabilities, then stored settings and external code.
    let group = |icon: &str| {
        let sel: Vec<&(&str, String, bool)> = items.iter().filter(|i| i.0 == icon).collect();
        (!sel.is_empty()).then(|| {
            (
                sel.iter()
                    .map(|i| i.1.clone())
                    .collect::<Vec<_>>()
                    .join(" \u{b7} "),
                sel.iter().any(|i| i.2),
            )
        })
    };
    let caps = group("bolt");
    let code = group("code");
    view! {
        <ul class="perm">
            <li class=if every { "hot" } else { "" }>
                <Icon name="globe" />
                <span>
                    {if every {
                        "Runs on every site".to_string()
                    } else if n == 0 {
                        "Site list not given".to_string()
                    } else {
                        format!("Runs on {}", shown.iter().take(2).cloned().collect::<Vec<_>>().join(", "))
                    }}
                    {move || (n > 2 && !every).then(|| {
                        if expanded.get() {
                            view! {
                                {format!(", {}", hosts.iter().skip(2).cloned().collect::<Vec<_>>().join(", "))}
                                " "<button type="button" class="linkish" on:click=move |_| expanded.set(false)>"less"</button>
                            }.into_any()
                        } else {
                            view! {
                                " "<button type="button" class="linkish" on:click=move |_| expanded.set(true)>{format!("+{} more", n - 2)}</button>
                            }.into_any()
                        }
                    })}
                </span>
            </li>
            {caps.map(|(t, hot)| view! { <li class=if hot { "hot" } else { "" }><Icon name="bolt" /><span>{t}</span></li> })}
            {code.map(|(t, hot)| view! { <li class=if hot { "hot" } else { "" }><Icon name="code" /><span>{t}</span></li> })}
        </ul>
    }
}

#[component]
fn CatalogueItem(entry: UserscriptCatalogueEntryDto, ctx: Ctx) -> impl IntoView {
    let installing = RwSignal::new(false);
    let err = RwSignal::new(Option::<String>::None);
    let url = entry.install_url.clone();
    let key = url_key(&url);
    let installed = Signal::derive(move || {
        ctx.all.with(|all| {
            all.iter()
                .find(|s| s.update_url.as_deref().map(url_key).as_deref() == Some(key.as_str()))
                .cloned()
        })
    });
    let plan = {
        let url = url.clone();
        move || {
            installing.set(true);
            err.set(None);
            let url = url.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new()
                    .plan_userscript(None, Some(url.clone()))
                    .await
                {
                    Ok(p) => {
                        ctx.review.set(Some(Review::from_plan(p, Some(&url))));
                        ctx.show_review.set(true);
                    }
                    Err(e) => err.set(Some(format!("Couldn't prepare the install: {e}"))),
                }
                installing.set(false);
            });
        }
    };
    let plan2 = plan.clone();
    let licence = if entry.licence.is_empty() {
        "licence unknown".to_string()
    } else {
        entry.licence.clone()
    };
    view! {
        <article class="cat">
            <h3>{entry.name.clone()}</h3>
            <div class="by">
                <span class="tag">{entry.category.clone()}</span>
                <span>{licence}</span>
                {(!entry.homepage.is_empty()).then(|| view! {
                    <a href=entry.homepage.clone() target="_blank" rel="noopener noreferrer">"Homepage"</a>
                })}
            </div>
            <div class="desc" title=entry.description.clone()>{entry.description.clone()}</div>
            <PermSummary entry=entry.clone() />
            <div class="act">
                {move || match installed.get() {
                    Some(s) => {
                        let upd = s.pending_update.clone().is_some();
                        let href = script_href(&s.id);
                        view! {
                            <div class="row-gap">
                                <span class="pill p-allow">"Installed"</span>
                                {if upd {
                                    let s2 = s.clone();
                                    view! {
                                        <button type="button" class="btn sm primary" on:click=move |_| {
                                            if let Some(r) = Review::from_update(&s2) {
                                                ctx.review.set(Some(r));
                                                ctx.show_review.set(true);
                                            }
                                        }>"Update"</button>
                                    }.into_any()
                                } else {
                                    view! { <a class="btn sm ghost" href=href>"Open"</a> }.into_any()
                                }}
                            </div>
                        }.into_any()
                    }
                    None => {
                        let plan = plan.clone();
                        view! {
                            <button type="button" class="btn sm primary instbtn"
                                aria-busy=move || installing.get().to_string()
                                disabled=move || installing.get()
                                aria-label=format!("Install {}", entry.name)
                                on:click=move |_| plan()>
                                {move || if installing.get() {
                                    view! { <span class="spin"></span>"Preparing\u{2026}" }.into_any()
                                } else {
                                    view! { "Install" }.into_any()
                                }}
                            </button>
                        }.into_any()
                    }
                }}
            </div>
            {move || err.get().map(|e| {
                let plan = plan2.clone();
                view! {
                    <div class="err row-gap fullrow" role="alert">
                        <span>{e}</span>
                        <button type="button" class="btn sm" on:click=move |_| plan()>"Retry"</button>
                    </div>
                }
            })}
        </article>
    }
}

/// The Browse tab body.
#[component]
pub fn BrowsePanel(ctx: Ctx) -> impl IntoView {
    let cat = RwSignal::new(Option::<UserscriptCatalogueResponse>::None);
    let load_err = RwSignal::new(Option::<String>::None);
    let loading = RwSignal::new(false);
    let q = RwSignal::new(String::new());
    let chosen = RwSignal::new(String::new());
    let hint_gone = RwSignal::new({
        use gloo_storage::Storage;
        gloo_storage::LocalStorage::get::<bool>(HINT_KEY).unwrap_or(false)
    });
    let load = move || {
        loading.set(true);
        load_err.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().get_userscript_catalogue().await {
                Ok(c) => {
                    ctx.cat_n.set(Some(c.entries.len()));
                    cat.set(Some(c));
                }
                Err(e) => load_err.set(Some(e.to_string())),
            }
            loading.set(false);
        });
    };
    // Loaded the first time the tab opens.
    Effect::new(move |_| {
        if ctx.tab.get() == "browse"
            && cat.with_untracked(|c| c.is_none())
            && !loading.get_untracked()
        {
            load();
        }
    });
    let entries = move || cat.with(|c| c.as_ref().map(|c| c.entries.clone()).unwrap_or_default());
    let categories = Signal::derive(move || {
        let mut v: Vec<String> = entries().iter().map(|e| e.category.clone()).collect();
        v.sort();
        v.dedup();
        v
    });
    let filtered = Signal::derive(move || {
        let q = q.get().to_lowercase();
        let c = chosen.get();
        entries()
            .into_iter()
            .filter(|e| {
                (c.is_empty() || e.category == c)
                    && (q.is_empty()
                        || e.name.to_lowercase().contains(&q)
                        || e.description.to_lowercase().contains(&q)
                        || e.sites.iter().any(|s| s.to_lowercase().contains(&q)))
            })
            .collect::<Vec<_>>()
    });
    let sub = move || {
        cat.with(|c| match c {
            Some(c) if c.source == "signed" => format!(
                "Signed catalogue \u{b7} updated {} \u{b7} {} scripts",
                c.fetched_at
                    .as_deref()
                    .map(fmt_date)
                    .unwrap_or_else(|| "unknown".into()),
                c.entries.len()
            ),
            Some(_) => "Catalogue not available yet".to_string(),
            None => "Signed catalogue".to_string(),
        })
    };
    view! {
        <div class="card">
            <div class="card-h"><span class="sub">{sub}</span></div>
            <div class="card-b">
                <div class="toolbar">
                    <div class="search grow">
                        <Icon name="search" />
                        <label class="sr" for="usCatQ">"Search the catalogue"</label>
                        <input id="usCatQ" class="input" placeholder="Search by name, description or site" autocomplete="off"
                            prop:value=move || q.get()
                            on:input=move |ev| q.set(event_target_value(&ev)) />
                    </div>
                </div>
                <div class="chips scroll" role="group" aria-label="Category">
                    <button type="button" class="chip" aria-pressed=move || chosen.get().is_empty().to_string()
                        on:click=move |_| chosen.set(String::new())>"All"</button>
                    {move || categories.get().into_iter().map(|c| {
                        let (c1, c2) = (c.clone(), c.clone());
                        view! {
                            <button type="button" class="chip" aria-pressed=move || (chosen.get() == c1).to_string()
                                on:click=move |_| chosen.set(c2.clone())>{c.clone()}</button>
                        }
                    }).collect_view()}
                </div>
                <Show when=move || !hint_gone.get()>
                    <div class="hint box row-gap">
                        <span>"Curated, not audited. You'll review each script's permissions before it installs."</span>
                        <button type="button" class="btn sm ghost" aria-label="Dismiss this note" on:click=move |_| {
                            use gloo_storage::Storage;
                            let _ = gloo_storage::LocalStorage::set(HINT_KEY, true);
                            hint_gone.set(true);
                        }>"Dismiss"</button>
                    </div>
                </Show>
            </div>
            {move || load_err.get().map(|e| view! {
                <div class="err row-gap pad" role="alert">
                    <span>{format!("Failed to load the catalogue: {e}")}</span>
                    <button type="button" class="btn sm" on:click=move |_| load()>"Retry"</button>
                </div>
            })}
            {move || loading.get().then(|| view! {
                <div class="empty"><span class="row-gap" style="justify-content:center"><span class="spin"></span>"Loading the catalogue\u{2026}"</span></div>
            })}
            <div class="catlist">
                <For each=move || filtered.get() key=|e| e.id.clone()
                    children=move |e| view! { <CatalogueItem entry=e ctx=ctx /> } />
            </div>
            {move || (!loading.get() && load_err.get().is_none() && cat.with(|c| c.is_some()) && filtered.with(|f| f.is_empty())).then(|| view! {
                <div class="empty">
                    <b>"No catalogue entries match"</b>
                    <button type="button" class="btn sm ghost" on:click=move |_| { q.set(String::new()); chosen.set(String::new()); }>"Clear filters"</button>
                </div>
            })}
        </div>
    }
}

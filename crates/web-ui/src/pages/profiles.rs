//! Profiles page: named sets of enabled filter lists plus overlay rules. Create, edit and delete
//! (a profile with devices cannot be deleted). Uses only the public `/api/v1/profiles` API;
//! every user-supplied name is rendered as text.

use std::rc::Rc;

use gloo_timers::callback::Timeout;
use leptos::prelude::*;

use super::vlist::{Feed, Fetcher, Scroller};
use crate::api::filters::FilterList;
use crate::api::profiles::{CreateProfileRequest, ProfileDto, UpdateProfileRequest};
use crate::api::{ApiClient, ApiError};
use crate::components::{Card, ChipSelect, Drawer, Layout};
use crate::state::use_app_state;

/// The built-in default profile (its lists and rules are the global ones).
fn is_default(p: &ProfileDto) -> bool {
    p.id == "0"
}

/// Message shown when deleting a profile fails.
pub fn delete_failure(e: &ApiError) -> String {
    match e {
        ApiError::Conflict(_) => "This profile still has devices assigned to it. Reassign or \
             delete those devices on the Devices page, then delete the profile."
            .to_string(),
        other => other.to_string(),
    }
}

/// Profiles page
#[component]
pub fn ProfilesPage() -> impl IntoView {
    let app = StoredValue::new(use_app_state());
    let pq_raw = RwSignal::new(String::new());
    let pq = RwSignal::new(String::new()); // debounced
    let pq_t = StoredValue::new_local(None::<Timeout>);
    let lq = RwSignal::new(String::new()); // filter-list picker search (debounced)
    let lq_t = StoredValue::new_local(None::<Timeout>);
    let reload = RwSignal::new(0u32);
    let busy = RwSignal::new(false);

    // Create / edit dialog
    let show_edit = RwSignal::new(false);
    let edit_id = RwSignal::new(Option::<String>::None);
    let name = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());
    let enabled = RwSignal::new(Vec::<String>::new());
    let rules = RwSignal::new(String::new());

    // Delete dialog
    let show_delete = RwSignal::new(false);
    let delete_target = RwSignal::new(Option::<ProfileDto>::None);
    let delete_error = RwSignal::new(Option::<String>::None);

    let pfetch: Fetcher<ProfileDto> = Rc::new(move |cursor, _| {
        let q = pq.get_untracked();
        Box::pin(async move {
            match ApiClient::new()
                .list_profiles_page(&q, cursor.as_deref())
                .await
            {
                Ok(p) => Ok((p.items, p.next_cursor, p.total)),
                Err(e) => {
                    app.get_value()
                        .error(format!("Failed to load profiles: {e}"));
                    Err(e)
                }
            }
        })
    });
    let profiles = Feed::new(pfetch);
    Effect::new(move || {
        reload.track();
        pq.track();
        profiles.reload(None, false, None);
    });

    // The filter-list picker: searchable, paged by name.
    let lfetch: Fetcher<FilterList> = Rc::new(move |cursor, _| {
        let q = lq.get_untracked();
        Box::pin(async move {
            ApiClient::new()
                .list_filter_lists_paged(&q, "", "name", cursor.as_deref(), None, 40)
                .await
                .map(|p| (p.items, p.next_cursor, p.total))
        })
    });
    let lists = Feed::new(lfetch);
    Effect::new(move || {
        lq.track();
        lists.reload(None, false, None);
    });

    let open_create = move |_| {
        edit_id.set(None);
        name.set(String::new());
        description.set(String::new());
        enabled.set(Vec::new());
        rules.set(String::new());
        show_edit.set(true);
    };
    let open_edit = move |p: ProfileDto| {
        edit_id.set(Some(p.id.clone()));
        name.set(p.name.clone());
        description.set(p.description.clone());
        enabled.set(p.lists.clone());
        rules.set(p.rules.clone());
        show_edit.set(true);
    };
    let open_delete = move |p: ProfileDto| {
        delete_error.set(None);
        delete_target.set(Some(p));
        show_delete.set(true);
    };

    let save = move |_| {
        let (n, d, l, r) = (
            name.get_untracked(),
            description.get_untracked(),
            enabled.get_untracked(),
            rules.get_untracked(),
        );
        if n.trim().is_empty() {
            app.get_value().error("Give the profile a name");
            return;
        }
        let id = edit_id.get_untracked();
        busy.set(true);
        wasm_bindgen_futures::spawn_local(async move {
            let client = ApiClient::new();
            let res = match &id {
                Some(id) => client
                    .update_profile(
                        id,
                        &UpdateProfileRequest {
                            name: Some(n),
                            description: Some(d),
                            lists: Some(l),
                            rules: Some(r),
                        },
                    )
                    .await
                    .map(|_| "Profile saved"),
                None => client
                    .create_profile(&CreateProfileRequest {
                        name: n,
                        description: d,
                        lists: l,
                        rules: r,
                    })
                    .await
                    .map(|_| "Profile created"),
            };
            busy.set(false);
            match res {
                Ok(msg) => {
                    app.get_value().success(msg);
                    show_edit.set(false);
                    reload.update(|n| *n += 1);
                }
                Err(e) => app
                    .get_value()
                    .error(format!("Failed to save profile: {e}")),
            }
        });
    };

    let confirm_delete = move |_| {
        let Some(p) = delete_target.get_untracked() else {
            return;
        };
        busy.set(true);
        wasm_bindgen_futures::spawn_local(async move {
            let res = ApiClient::new().delete_profile(&p.id).await;
            busy.set(false);
            match res {
                Ok(_) => {
                    app.get_value().success("Profile deleted");
                    show_delete.set(false);
                    reload.update(|n| *n += 1);
                }
                Err(e) => delete_error.set(Some(delete_failure(&e))),
            }
        });
    };

    view! {
        <Layout>
            <div class="page-header">
                <h1 class="page-title">"Profiles"</h1>
                <button class="btn primary" on:click=open_create>"New profile"</button>
            </div>
            <p class="hint">
                "A profile is a set of enabled filter lists plus its own rules. Devices pick a \
                 profile by address or token (see Devices). The default profile uses the global \
                 lists and custom rules and cannot be renamed or deleted."
            </p>
            <Card title="Profiles" class="settings-card">
                <div class="search">
                    <label class="sr" for="profQ">"Search profiles"</label>
                    <input class="input" id="profQ" placeholder="Search profiles"
                        prop:value=move || pq_raw.get()
                        on:input=move |ev| {
                            let v = event_target_value(&ev);
                            pq_raw.set(v.clone());
                            pq_t.set_value(Some(Timeout::new(250, move || pq.set(v))));
                        } />
                </div>
                <Scroller feed=profiles class="tbl-wrap"><table class="tbl">
                    <thead>
                        <tr>
                            <th>"Name"</th>
                            <th>"Description"</th>
                            <th>"Lists"</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        <For
                            each=move || profiles.items.get()
                            key=|p| format!("{}/{}/{}", p.id, p.name, p.updated_at)
                            children=move |p| {
                                let builtin = is_default(&p);
                                let (pe, pd) = (p.clone(), p.clone());
                                view! {
                                    <tr>
                                        <td>
                                            {p.name.clone()}
                                            {builtin.then(|| view! {
                                                <span class="us-badge">"built-in"</span>
                                            })}
                                        </td>
                                        <td>
                                            {p.description.clone()}
                                            {p.last_error.clone().map(|e| view! {
                                                <p class="form-error">"Last build failed: "{e}</p>
                                            })}
                                        </td>
                                        <td>{if builtin {
                                            "global lists".to_string()
                                        } else {
                                            format!("{} enabled", p.lists.len())
                                        }}</td>
                                        <td>
                                            <button
                                                class="btn sm"
                                                disabled=builtin
                                                on:click=move |_| open_edit(pe.clone())
                                            >"Edit"</button>
                                            <button
                                                class="btn danger sm"
                                                disabled=builtin
                                                on:click=move |_| open_delete(pd.clone())
                                            >"Delete"</button>
                                        </td>
                                    </tr>
                                }
                            }
                        />
                    </tbody>
                </table></Scroller>
            </Card>

            <Drawer title="Profile" open=show_edit>
                <div class="field">
                    <label>"Name"</label>
                    <input class="input" type="text" maxlength="64"
                        prop:value=move || name.get()
                        on:input=move |ev| name.set(event_target_value(&ev)) />
                    <p class="hint">
                        "Letters, digits, spaces, '_', '-' and '.' (up to 64 characters)."
                    </p>
                </div>
                <div class="field">
                    <label>"Description"</label>
                    <input class="input" type="text" maxlength="500"
                        prop:value=move || description.get()
                        on:input=move |ev| description.set(event_target_value(&ev)) />
                </div>
                <div class="field">
                    <label>"Enabled filter lists"</label>
                    <input class="input" placeholder="Search filter lists" aria-label="Search filter lists"
                        on:input=move |ev| {
                            let v = event_target_value(&ev);
                            lq_t.set_value(Some(Timeout::new(250, move || lq.set(v))));
                        } />
                    <p class="hint">{move || format!("{} enabled", enabled.with(|e| e.len()))}</p>
                    <Show
                        when=move || !lists.items.with(|v| v.is_empty())
                        fallback=move || view! { <p class="hint">{if lists.loading.get() { "Loading..." } else { "No filter lists match." }}</p> }
                    >
                        <Scroller feed=lists class="chips">
                        <For
                            each=move || lists.items.get()
                            key=|l| l.id.clone()
                            children=move |l| {
                                let id = l.id.clone();
                                let id2 = l.id.clone();
                                view! {
                                    <ChipSelect
                                        pressed=Signal::derive(move || enabled.get().contains(&id))
                                        on_toggle=Callback::new(move |on: bool| {
                                            let id = id2.clone();
                                            enabled.update(|v| {
                                                v.retain(|x| *x != id);
                                                if on { v.push(id); }
                                            });
                                        })
                                    >
                                        {l.name.clone()}
                                    </ChipSelect>
                                }
                            }
                        />
                        </Scroller>
                    </Show>
                </div>
                <div class="field">
                    <label>"Custom rules (adblock syntax)"</label>
                    <textarea class="input" rows="8" spellcheck="false"
                        prop:value=move || rules.get()
                        on:input=move |ev| rules.set(event_target_value(&ev))></textarea>
                    <p class="hint">
                        "Applied on top of this profile's lists, like the global custom rules."
                    </p>
                </div>
                <div class="row-gap">
                    <button class="btn" on:click=move |_| show_edit.set(false)>"Cancel"</button>
                    <button class="btn primary" disabled=move || busy.get() on:click=save>"Save"</button>
                </div>
            </Drawer>

            <Drawer title="Delete profile" open=show_delete>
                <p>
                    "Delete profile "
                    <strong>{move || delete_target.get().map(|p| p.name).unwrap_or_default()}</strong>
                    "?"
                </p>
                {move || delete_error.get().map(|m| view! { <div class="us-warn">{m}</div> })}
                <div class="row-gap">
                    <button class="btn" on:click=move |_| show_delete.set(false)>"Cancel"</button>
                    <button class="btn danger sm" disabled=move || busy.get() on:click=confirm_delete>"Delete"</button>
                </div>
            </Drawer>
        </Layout>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflict_is_explained() {
        let msg = delete_failure(&ApiError::Conflict("profile in use".into()));
        assert!(msg.contains("devices"));
        assert_eq!(
            delete_failure(&ApiError::NotFound("x".into())),
            ApiError::NotFound("x".into()).to_string()
        );
    }
}

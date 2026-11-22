//! Profile selector for the profile-scoped pages (script policy, userscripts). Picking a profile
//! makes the API client add `?profile=<id>` to those pages' calls and bumps `reload`.

use leptos::prelude::*;

use crate::api::client::{current_profile, set_current_profile};
use crate::api::profiles::ProfileDto;
use crate::api::ApiClient;

/// `<select>` of profiles. `reload` is incremented after the selection changes so the page
/// reloads its data. The selection resets to the default profile when the page is left.
#[component]
pub fn ProfileSelector(reload: RwSignal<u32>) -> impl IntoView {
    let profiles = RwSignal::new(Vec::<ProfileDto>::new());
    let selected = RwSignal::new(current_profile());

    wasm_bindgen_futures::spawn_local(async move {
        if let Ok(list) = ApiClient::new().list_profiles().await {
            profiles.set(list);
        }
    });
    on_cleanup(|| set_current_profile("0"));

    view! {
        <label class="profile-selector">
            <span class="form-help">"Profile "</span>
            <select
                class="form-input"
                prop:value=move || selected.get()
                on:change=move |ev| {
                    let id = event_target_value(&ev);
                    set_current_profile(&id);
                    selected.set(id);
                    reload.update(|n| *n += 1);
                }
            >
                <For
                    each=move || profiles.get()
                    key=|p| format!("{}/{}", p.id, p.name)
                    children=move |p| {
                        let id = p.id.clone();
                        let sel = id.clone();
                        view! {
                            <option value=id selected=move || selected.get() == sel>
                                {p.name.clone()}
                            </option>
                        }
                    }
                />
            </select>
        </label>
    }
}

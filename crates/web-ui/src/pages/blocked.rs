//! Recently blocked requests page

use leptos::prelude::*;
use web_sys::HtmlInputElement;

use crate::api::filters::BlockedEntry;
use crate::api::ApiClient;
use crate::components::{Card, Layout};
use crate::state::use_app_state;

/// Recent-blocked page: newest first, filterable by host, client label and list id.
#[component]
pub fn BlockedPage() -> impl IntoView {
    let app_state = use_app_state();
    let entries = RwSignal::new(Vec::<BlockedEntry>::new());
    let total = RwSignal::new(0usize);
    let host = RwSignal::new(String::new());
    let client = RwSignal::new(String::new());
    let list_id = RwSignal::new(String::new());
    let refresh = RwSignal::new(0u32);

    Effect::new(move || {
        let _ = refresh.get();
        let (h, c, l) = (
            host.get_untracked(),
            client.get_untracked(),
            list_id.get_untracked(),
        );
        let app_state = app_state.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().get_recent_blocked(200, &c, &h, &l).await {
                Ok(r) => {
                    total.set(r.total);
                    entries.set(r.entries);
                }
                Err(e) => app_state.error(format!("Failed to load recent blocks: {}", e)),
            }
        });
    });

    let input = |label: &'static str, sig: RwSignal<String>| {
        view! {
            <div class="form-field">
                <label class="form-label">{label}</label>
                <input
                    type="text"
                    class="form-input"
                    prop:value=move || sig.get()
                    on:input=move |ev| sig.set(event_target::<HtmlInputElement>(&ev).value())
                />
            </div>
        }
    };

    let numbered = move || {
        let v: Vec<(usize, BlockedEntry)> = entries.get().into_iter().enumerate().collect();
        v
    };

    view! {
        <Layout>
            <div class="page-header">
                <h1 class="page-title">"Recently Blocked"</h1>
                <button class="btn btn-primary" on:click=move |_| refresh.update(|n| *n += 1)>
                    "Refresh"
                </button>
            </div>
            <Card>
                {input("Host", host)}
                {input("Client", client)}
                {input("List id", list_id)}
                <p class="form-help">
                    {move || format!("{} matching event(s) in the engine's recent-blocked ring; showing up to 200.", total.get())}
                </p>
                <div style="overflow-x: auto">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>"Time"</th><th>"URL"</th><th>"Type"</th>
                                <th>"Rule"</th><th>"List"</th><th>"Client"</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For
                                each=numbered
                                key=|(i, _)| *i
                                children=|(_, e)| view! {
                                    <tr>
                                        <td>{e.time.clone()}</td>
                                        <td>{e.url.clone()}</td>
                                        <td>{e.resource_type.clone()}</td>
                                        <td>{e.rule.clone().unwrap_or_default()}</td>
                                        <td>{e.list_id.clone().unwrap_or_default()}</td>
                                        <td>{e.client.clone().unwrap_or_default()}</td>
                                    </tr>
                                }
                            />
                        </tbody>
                    </table>
                </div>
                <Show when=move || entries.get().is_empty()>
                    <div class="empty-state"><p>"Nothing blocked yet"</p></div>
                </Show>
            </Card>
        </Layout>
    }
}

//! Filter lists management page

use leptos::prelude::*;
use web_sys::HtmlInputElement;

use crate::api::filters::FilterList;
use crate::api::ApiClient;
use crate::components::{Card, Layout, Modal};
use crate::state::use_app_state;

/// Filters page component
#[component]
pub fn FiltersPage() -> impl IntoView {
    let app_state = use_app_state();

    let filters = RwSignal::new(Vec::<FilterList>::new());
    let loading = RwSignal::new(true);

    // Modal state
    let show_modal = RwSignal::new(false);
    let add_name = RwSignal::new(String::new());
    let add_url = RwSignal::new(String::new());

    // Stats
    let total_rules = RwSignal::new(0usize);
    let requests_blocked = RwSignal::new(0u64);

    // Action signals
    let do_add = RwSignal::new(false);
    let delete_id = RwSignal::new(Option::<String>::None);

    // Load filters
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let client = ApiClient::new();

                match client.list_filter_lists(1, 100).await {
                    Ok(response) => {
                        filters.set(response.data);
                    }
                    Err(e) => {
                        app_state.error(format!("Failed to load filters: {}", e));
                    }
                }

                if let Ok(response) = client.get_filter_stats().await {
                    total_rules.set(response.stats.total_rules);
                    requests_blocked.set(response.stats.requests_blocked);
                }

                loading.set(false);
            });
        });
    }

    // Add filter effect
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            if do_add.get() {
                let name = add_name.get();
                let url = add_url.get();
                let app_state = app_state.clone();

                wasm_bindgen_futures::spawn_local(async move {
                    let client = ApiClient::new();

                    match client.add_filter_list(&name, &url, true).await {
                        Ok(filter) => {
                            filters.update(|f| f.push(filter));
                            app_state.success("Filter list added");
                            show_modal.set(false);
                            add_name.set(String::new());
                            add_url.set(String::new());
                        }
                        Err(e) => {
                            app_state.error(format!("Failed to add filter: {}", e));
                        }
                    }
                    do_add.set(false);
                });
            }
        });
    }

    // Delete filter effect
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            if let Some(id) = delete_id.get() {
                let app_state = app_state.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let client = ApiClient::new();

                    match client.delete_filter_list(&id).await {
                        Ok(_) => {
                            filters.update(|f| f.retain(|filter| filter.id != id));
                            app_state.success("Filter list deleted");
                        }
                        Err(e) => {
                            app_state.error(format!("Failed to delete filter: {}", e));
                        }
                    }
                    delete_id.set(None);
                });
            }
        });
    }

    view! {
        <Layout>
            <div class="page-header">
                <h1 class="page-title">"Filter Lists"</h1>
                <button class="btn btn-primary" on:click=move |_| show_modal.set(true)>
                    "+ Add Filter List"
                </button>
            </div>

            <div class="filters-stats">
                <div class="stat-badge">
                    <span class="stat-value">{total_rules}</span>
                    <span class="stat-label">"Total Rules"</span>
                </div>
                <div class="stat-badge">
                    <span class="stat-value">{requests_blocked}</span>
                    <span class="stat-label">"Requests Blocked"</span>
                </div>
            </div>

            <Card class="filters-card">
                <Show when=move || !loading.get() fallback=|| view! {
                    <div class="loading">"Loading..."</div>
                }>
                    <For
                        each=move || filters.get()
                        key=|filter| filter.id.clone()
                        children=move |filter| {
                            let id_for_delete = filter.id.clone();
                            view! {
                                <div class={format!(
                                    "filter-item {}",
                                    if filter.enabled { "" } else { "disabled" }
                                )}>
                                    <div class="filter-info">
                                        <h3 class="filter-name">{filter.name.clone()}</h3>
                                        <p class="filter-url">{filter.url.clone().unwrap_or_default()}</p>
                                        <div class="filter-meta">
                                            <span class="filter-rules">{filter.rule_count}" rules"</span>
                                        </div>
                                    </div>
                                    <div class="filter-actions">
                                        <button
                                            class="btn btn-danger"
                                            on:click=move |_| delete_id.set(Some(id_for_delete.clone()))
                                        >
                                            "Delete"
                                        </button>
                                    </div>
                                </div>
                            }
                        }
                    />

                    <Show when=move || filters.get().is_empty()>
                        <div class="empty-state">
                            <p>"No filter lists configured"</p>
                        </div>
                    </Show>
                </Show>
            </Card>

            <Modal
                title="Add Filter List"
                open=show_modal
                on_close=Callback::new(move |_| show_modal.set(false))
            >
                <div class="form-field">
                    <label class="form-label">"Name"</label>
                    <input
                        type="text"
                        class="form-input"
                        placeholder="e.g., EasyList"
                        prop:value=move || add_name.get()
                        on:input=move |ev| {
                            let target = event_target::<HtmlInputElement>(&ev);
                            add_name.set(target.value());
                        }
                    />
                </div>
                <div class="form-field">
                    <label class="form-label">"URL"</label>
                    <input
                        type="text"
                        class="form-input"
                        placeholder="https://example.com/filters.txt"
                        prop:value=move || add_url.get()
                        on:input=move |ev| {
                            let target = event_target::<HtmlInputElement>(&ev);
                            add_url.set(target.value());
                        }
                    />
                </div>
                <div class="modal-actions">
                    <button class="btn btn-secondary" on:click=move |_| show_modal.set(false)>
                        "Cancel"
                    </button>
                    <button class="btn btn-primary" on:click=move |_| do_add.set(true)>
                        "Add"
                    </button>
                </div>
            </Modal>
        </Layout>
    }
}

//! Filter lists management page

use leptos::prelude::*;
use uuid::Uuid;
use web_sys::{HtmlInputElement, HtmlTextAreaElement};

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
    let total_requests = RwSignal::new(0u64);
    let requests_blocked = RwSignal::new(0u64);

    // Custom rules editor
    let custom_rules = RwSignal::new(String::new());
    // ETag of the rules as last read; sent as If-Match so concurrent edits are not overwritten.
    let rules_etag = RwSignal::new(Option::<String>::None);
    let saving_rules = RwSignal::new(false);
    let do_save_rules = RwSignal::new(false);

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
                        filters.set(response.items);
                    }
                    Err(e) => {
                        app_state.error(format!("Failed to load filters: {}", e));
                    }
                }

                if let Ok(stats) = client.get_filter_stats().await {
                    total_requests.set(stats.total_requests);
                    requests_blocked.set(stats.blocked_requests);
                }

                if let Ok((resp, etag)) = client.get_custom_rules().await {
                    custom_rules.set(resp.rules);
                    rules_etag.set(etag);
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
                    let filter_id = Uuid::new_v4().to_string();

                    match client.add_filter_list(&filter_id, &name, &url, true).await {
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

    // Save custom rules effect
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            if do_save_rules.get() {
                saving_rules.set(true);
                let app_state = app_state.clone();
                let rules = custom_rules.get();
                let etag = rules_etag.get_untracked().unwrap_or_default();
                wasm_bindgen_futures::spawn_local(async move {
                    let client = ApiClient::new();
                    match client.update_custom_rules(&rules, &etag).await {
                        Ok((_, new_etag)) => {
                            rules_etag.set(new_etag);
                            app_state.success("Custom rules saved")
                        }
                        Err(e) => app_state.error(format!("Failed to save rules: {}", e)),
                    }
                    saving_rules.set(false);
                    do_save_rules.set(false);
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
                    <span class="stat-value">{total_requests}</span>
                    <span class="stat-label">"Requests Checked"</span>
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
                                        <p class="filter-url">{filter.url.clone()}</p>
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

            <Card title="Custom Rules" class="filters-card">
                <p class="form-help">
                    "One rule per line in Adblock Plus / uBlock syntax. Use "
                    <code>"||ads.example^"</code>" to block, "<code>"@@||good.example^"</code>
                    " to allow (exceptions win over blocklists), or "<code>"example.com##.banner"</code>
                    " to hide elements. Changes apply after saving."
                </p>
                <textarea
                    class="form-input"
                    rows="8"
                    style="font-family: monospace; width: 100%;"
                    placeholder="||ads.example^&#10;@@||good.example^&#10;example.com##.sponsored"
                    prop:value=move || custom_rules.get()
                    on:input=move |ev| {
                        let target = event_target::<HtmlTextAreaElement>(&ev);
                        custom_rules.set(target.value());
                    }
                ></textarea>
                <div class="modal-actions">
                    <button
                        class="btn btn-primary"
                        disabled=move || saving_rules.get()
                        on:click=move |_| do_save_rules.set(true)
                    >
                        {move || if saving_rules.get() { "Saving..." } else { "Save Rules" }}
                    </button>
                </div>
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

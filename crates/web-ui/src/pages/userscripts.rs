//! Userscripts management page

use leptos::prelude::*;

use crate::api::userscripts::Userscript;
use crate::api::ApiClient;
use crate::components::{Card, Layout, Modal};
use crate::state::use_app_state;

/// Userscripts page component
#[component]
pub fn UserscriptsPage() -> impl IntoView {
    let app_state = use_app_state();

    let scripts = RwSignal::new(Vec::<Userscript>::new());
    let loading = RwSignal::new(true);

    // Install modal state
    let show_install_modal = RwSignal::new(false);
    let install_source = RwSignal::new(String::new());

    // View source modal state
    let show_source_modal = RwSignal::new(false);
    let source_content = RwSignal::new(String::new());

    // Stats
    let total_executions = RwSignal::new(0u64);

    // Action signals
    let do_install = RwSignal::new(false);
    let view_source_id = RwSignal::new(Option::<String>::None);
    let delete_id = RwSignal::new(Option::<String>::None);

    // Load scripts
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            let app_state = app_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let client = ApiClient::new();

                match client.list_userscripts(1, 100, None).await {
                    Ok(response) => {
                        scripts.set(response.data);
                    }
                    Err(e) => {
                        app_state.error(format!("Failed to load userscripts: {}", e));
                    }
                }

                if let Ok(stats) = client.get_userscript_stats().await {
                    total_executions.set(stats.total_executions);
                }

                loading.set(false);
            });
        });
    }

    // Install script effect
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            if do_install.get() {
                let source = install_source.get();
                let app_state = app_state.clone();

                wasm_bindgen_futures::spawn_local(async move {
                    let client = ApiClient::new();

                    match client.install_userscript(&source).await {
                        Ok(script) => {
                            scripts.update(|s| s.push(script));
                            app_state.success("Userscript installed");
                            show_install_modal.set(false);
                            install_source.set(String::new());
                        }
                        Err(e) => {
                            app_state.error(format!("Failed to install: {}", e));
                        }
                    }
                    do_install.set(false);
                });
            }
        });
    }

    // View source effect
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            if let Some(id) = view_source_id.get() {
                let app_state = app_state.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let client = ApiClient::new();

                    match client.get_userscript_source(&id).await {
                        Ok(response) => {
                            source_content.set(response.source);
                            show_source_modal.set(true);
                        }
                        Err(e) => {
                            app_state.error(format!("Failed to get source: {}", e));
                        }
                    }
                    view_source_id.set(None);
                });
            }
        });
    }

    // Delete script effect
    {
        let app_state = app_state.clone();
        Effect::new(move || {
            if let Some(id) = delete_id.get() {
                let app_state = app_state.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let client = ApiClient::new();

                    match client.uninstall_userscript(&id).await {
                        Ok(_) => {
                            scripts.update(|s| s.retain(|script| script.id != id));
                            app_state.success("Userscript uninstalled");
                        }
                        Err(e) => {
                            app_state.error(format!("Failed to uninstall: {}", e));
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
                <h1 class="page-title">"Userscripts"</h1>
                <button class="btn btn-primary" on:click=move |_| show_install_modal.set(true)>
                    "+ Install Userscript"
                </button>
            </div>

            <div class="userscripts-stats">
                <div class="stat-badge">
                    <span class="stat-value">{move || scripts.get().len()}</span>
                    <span class="stat-label">"Installed"</span>
                </div>
                <div class="stat-badge">
                    <span class="stat-value">{total_executions}</span>
                    <span class="stat-label">"Total Executions"</span>
                </div>
            </div>

            <Card class="userscripts-card">
                <Show when=move || !loading.get() fallback=|| view! {
                    <div class="loading">"Loading..."</div>
                }>
                    <For
                        each=move || scripts.get()
                        key=|script| script.id.clone()
                        children=move |script| {
                            let id_source = script.id.clone();
                            let id_delete = script.id.clone();
                            let name = script.name.clone();
                            let version = script.version.clone();
                            let description = script.description.clone();
                            let exec_count = script.execution_count;
                            let enabled = script.enabled;

                            view! {
                                <div class={format!(
                                    "userscript-item {}",
                                    if enabled { "" } else { "disabled" }
                                )}>
                                    <div class="userscript-info">
                                        <h3 class="userscript-name">
                                            {name}
                                            {version.map(|v| view! {
                                                <span class="userscript-version">{v}</span>
                                            })}
                                        </h3>
                                        {description.map(|d| view! {
                                            <p class="userscript-description">{d}</p>
                                        })}
                                        <div class="userscript-meta">
                                            <span class="userscript-executions">
                                                {exec_count}" executions"
                                            </span>
                                        </div>
                                    </div>
                                    <div class="userscript-actions">
                                        <button
                                            class="btn btn-ghost"
                                            on:click=move |_| view_source_id.set(Some(id_source.clone()))
                                        >
                                            "Source"
                                        </button>
                                        <button
                                            class="btn btn-danger"
                                            on:click=move |_| delete_id.set(Some(id_delete.clone()))
                                        >
                                            "Uninstall"
                                        </button>
                                    </div>
                                </div>
                            }
                        }
                    />

                    <Show when=move || scripts.get().is_empty()>
                        <div class="empty-state">
                            <p>"No userscripts installed"</p>
                        </div>
                    </Show>
                </Show>
            </Card>

            <Modal
                title="Install Userscript"
                open=show_install_modal
                on_close=Callback::new(move |_| show_install_modal.set(false))
            >
                <p class="modal-help">
                    "Paste the userscript source code below."
                </p>
                <textarea
                    class="source-input"
                    placeholder="// ==UserScript==
// @name        My Script
// @match       https://example.com/*
// ==/UserScript==

// Your code here..."
                    prop:value=move || install_source.get()
                    on:input=move |ev| {
                        install_source.set(event_target_value(&ev));
                    }
                ></textarea>
                <div class="modal-actions">
                    <button class="btn btn-secondary" on:click=move |_| show_install_modal.set(false)>
                        "Cancel"
                    </button>
                    <button class="btn btn-primary" on:click=move |_| do_install.set(true)>
                        "Install"
                    </button>
                </div>
            </Modal>

            <Modal
                title="Userscript Source"
                open=show_source_modal
                on_close=Callback::new(move |_| show_source_modal.set(false))
                class="source-modal"
            >
                <pre class="source-code">{source_content}</pre>
            </Modal>
        </Layout>
    }
}

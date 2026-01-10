//! Dashboard page

use leptos::prelude::*;

use crate::api::ApiClient;
use crate::components::{Card, Layout};
use crate::utils::format_number;

/// Dashboard page component
#[component]
pub fn DashboardPage() -> impl IntoView {
    // Stats signals
    let requests_blocked = RwSignal::new("--".to_string());
    let active_connections = RwSignal::new("--".to_string());
    let filter_rules = RwSignal::new("--".to_string());
    let userscripts_installed = RwSignal::new("--".to_string());
    let uptime = RwSignal::new("--".to_string());

    // Fetch stats
    Effect::new(move || {
        wasm_bindgen_futures::spawn_local(async move {
            let client = ApiClient::new();

            // Fetch proxy stats
            if let Ok(response) = client.get_proxy_stats().await {
                let stats = response.stats;
                active_connections.set(format_number(stats.connections_active));
                uptime.set(format_uptime(stats.uptime_seconds));
            }

            // Fetch filter stats
            if let Ok(response) = client.get_filter_stats().await {
                let stats = response.stats;
                requests_blocked.set(format_number(stats.requests_blocked));
                filter_rules.set(format_number(stats.total_rules as u64));
            }

            // Fetch userscript stats
            if let Ok(stats) = client.get_userscript_stats().await {
                userscripts_installed.set(format_number(stats.total_scripts as u64));
            }
        });
    });

    view! {
        <Layout>
            <div class="page-header">
                <h1 class="page-title">"Dashboard"</h1>
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-card-header">
                        <span class="stat-icon">"B"</span>
                        <span class="stat-title">"Requests Blocked"</span>
                    </div>
                    <div class="stat-value">{requests_blocked}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-card-header">
                        <span class="stat-icon">"C"</span>
                        <span class="stat-title">"Active Connections"</span>
                    </div>
                    <div class="stat-value">{active_connections}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-card-header">
                        <span class="stat-icon">"F"</span>
                        <span class="stat-title">"Filter Rules"</span>
                    </div>
                    <div class="stat-value">{filter_rules}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-card-header">
                        <span class="stat-icon">"U"</span>
                        <span class="stat-title">"Userscripts"</span>
                    </div>
                    <div class="stat-value">{userscripts_installed}</div>
                </div>
            </div>

            <div class="dashboard-row">
                <Card title="System Status" class="dashboard-card">
                    <div class="status-item">
                        <span class="status-label">"Uptime"</span>
                        <span class="status-value">{uptime}</span>
                    </div>
                    <div class="status-item">
                        <span class="status-label">"Proxy Status"</span>
                        <span class="status-value status-online">"Online"</span>
                    </div>
                </Card>

                <Card title="Quick Actions" class="dashboard-card">
                    <div class="quick-actions">
                        <a href="/filters" class="quick-action">
                            <span class="quick-action-icon">"+"</span>
                            <span class="quick-action-label">"Add Filter List"</span>
                        </a>
                        <a href="/userscripts" class="quick-action">
                            <span class="quick-action-icon">"+"</span>
                            <span class="quick-action-label">"Install Userscript"</span>
                        </a>
                        <a href="/proxy" class="quick-action">
                            <span class="quick-action-icon">"S"</span>
                            <span class="quick-action-label">"Proxy Settings"</span>
                        </a>
                    </div>
                </Card>
            </div>
        </Layout>
    }
}

/// Format uptime seconds to human-readable string
fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;

    if days > 0 {
        format!("{}d {}h {}m", days, hours, minutes)
    } else if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    }
}

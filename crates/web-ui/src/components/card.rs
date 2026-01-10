//! Card component

use leptos::prelude::*;

/// Card component
#[component]
pub fn Card(
    #[prop(into, optional)] title: String,
    #[prop(into, optional)] class: String,
    children: Children,
) -> impl IntoView {
    view! {
        <div class={format!("card {}", class)}>
            {(!title.is_empty()).then(|| view! {
                <div class="card-header">
                    <h3 class="card-title">{title.clone()}</h3>
                </div>
            })}
            <div class="card-body">
                {children()}
            </div>
        </div>
    }
}

/// Stat card for dashboard
#[component]
pub fn StatCard(
    #[prop(into)] title: String,
    #[prop(into)] value: String,
    #[prop(into, optional)] icon: String,
) -> impl IntoView {
    view! {
        <div class="stat-card">
            <div class="stat-card-header">
                {(!icon.is_empty()).then(|| view! {
                    <span class="stat-icon">{icon.clone()}</span>
                })}
                <span class="stat-title">{title}</span>
            </div>
            <div class="stat-value">{value}</div>
        </div>
    }
}

//! Card and stat tile.

use leptos::prelude::*;

/// Card with an optional titled header.
#[component]
pub fn Card(
    #[prop(into, optional)] title: String,
    #[prop(into, optional)] sub: String,
    #[prop(into, optional)] class: String,
    children: Children,
) -> impl IntoView {
    view! {
        <div class=format!("card {class}")>
            {(!title.is_empty()).then(|| view! {
                <div class="card-h">
                    <h3>{title.clone()}</h3>
                    {(!sub.is_empty()).then(|| view! { <span class="sub">{sub.clone()}</span> })}
                </div>
            })}
            <div class="card-b">{children()}</div>
        </div>
    }
}

/// Dashboard tile: label, big mono value, small detail line.
#[component]
pub fn Tile(
    #[prop(into)] label: String,
    #[prop(into)] value: Signal<String>,
    #[prop(into, optional)] detail: Signal<String>,
    #[prop(into, optional)] color: String,
) -> impl IntoView {
    view! {
        <div class="tile">
            <span class="k">{label}</span>
            <span class="v" style=color>{move || value.get()}</span>
            <span class="d">{move || detail.get()}</span>
        </div>
    }
}

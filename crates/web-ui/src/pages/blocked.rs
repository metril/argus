//! `/blocked` now lives in the Logs page with the blocked filter preset.

use leptos::prelude::*;
use leptos_router::components::Redirect;

#[component]
pub fn BlockedPage() -> impl IntoView {
    view! { <Redirect path="/logs?action=blocked" /> }
}

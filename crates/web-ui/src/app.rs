//! Main application component

use leptos::prelude::*;

use crate::router::AppRouter;
use crate::state::app::provide_app_state;
use crate::state::auth::provide_auth_state;

/// Main application component
#[component]
pub fn App() -> impl IntoView {
    // Provide global state contexts
    provide_app_state();
    provide_auth_state();

    view! {
        <AppRouter />
    }
}

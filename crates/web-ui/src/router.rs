//! Client-side routing

use leptos::prelude::*;
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;

use crate::pages::*;

/// Main router component
#[component]
pub fn AppRouter() -> impl IntoView {
    view! {
        <Router>
            <Routes fallback=|| view! { <NotFoundPage /> }>
                // Auth routes
                <Route path=path!("/login") view=LoginPage />
                <Route path=path!("/register") view=RegisterPage />

                // Protected routes
                <Route path=path!("/") view=DashboardPage />
                <Route path=path!("/proxy") view=ProxyPage />
                <Route path=path!("/filters") view=FiltersPage />
                <Route path=path!("/blocked") view=BlockedPage />
                <Route path=path!("/userscripts") view=UserscriptsPage />
                <Route path=path!("/policy") view=PolicyPage />
                <Route path=path!("/tokens") view=TokensPage />
                <Route path=path!("/settings") view=SettingsPage />
            </Routes>
        </Router>
    }
}

/// 404 Not Found page
#[component]
fn NotFoundPage() -> impl IntoView {
    view! {
        <div class="not-found">
            <h1>"404"</h1>
            <p>"Page not found"</p>
            <a href="/" class="btn btn-primary">"Go to Dashboard"</a>
        </div>
    }
}

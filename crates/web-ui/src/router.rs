//! Client-side routing

use leptos::prelude::*;
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;

use crate::components::Protected;
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
                <Route path=path!("/") view=|| view! { <Protected><DashboardPage /></Protected> } />
                <Route path=path!("/proxy") view=|| view! { <Protected><ProxyPage /></Protected> } />
                <Route path=path!("/bypass") view=|| view! { <Protected><BypassPage /></Protected> } />
                <Route path=path!("/filters") view=|| view! { <Protected><FiltersPage /></Protected> } />
                <Route path=path!("/logs") view=|| view! { <Protected><LogsPage /></Protected> } />
                <Route path=path!("/blocked") view=|| view! { <Protected><BlockedPage /></Protected> } />
                <Route path=path!("/account") view=|| view! { <Protected><AccountPage /></Protected> } />
                <Route path=path!("/users") view=|| view! { <Protected><UsersPage /></Protected> } />
                <Route path=path!("/sessions") view=|| view! { <Protected><SessionsPage /></Protected> } />
                <Route path=path!("/audit") view=|| view! { <Protected><AuditPage /></Protected> } />
                <Route path=path!("/userscripts") view=|| view! { <Protected><UserscriptsPage /></Protected> } />
                <Route path=path!("/userscripts/:id") view=|| view! { <Protected><UserscriptDetailPage /></Protected> } />
                <Route path=path!("/policy") view=|| view! { <Protected><PolicyPage /></Protected> } />
                <Route path=path!("/profiles") view=|| view! { <Protected><ProfilesPage /></Protected> } />
                <Route path=path!("/devices") view=|| view! { <Protected><DevicesPage /></Protected> } />
                <Route path=path!("/tokens") view=|| view! { <Protected><TokensPage /></Protected> } />
                <Route path=path!("/settings") view=|| view! { <Protected><SettingsPage /></Protected> } />
            </Routes>
        </Router>
    }
}

/// 404 Not Found page
#[component]
fn NotFoundPage() -> impl IntoView {
    view! {
        <div class="auth-wrap">
            <div class="not-found">
                <h1>"404"</h1>
                <p class="muted">"Page not found"</p>
                <a href="/" class="btn primary">"Go to Dashboard"</a>
            </div>
        </div>
    }
}

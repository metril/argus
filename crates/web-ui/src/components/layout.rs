//! App shell: sidebar, top bar, work area, toasts, command palette.

use leptos::prelude::*;
use leptos_router::components::Redirect;

use super::{CommandPalette, Navbar, Sidebar, ToastContainer};
use crate::state::{use_app_state, use_auth_state};

/// Wraps every authenticated route. Checks the session once and builds the page only when
/// logged in, so a logged-out visit makes no API calls beyond the session check itself
/// (pages fetch in their own bodies, which only run inside this gate).
#[component]
pub fn Protected(children: Children) -> impl IntoView {
    let auth_state = use_auth_state();
    let (user, checked, error) = (auth_state.user, auth_state.checked, auth_state.error);
    let check = {
        let auth_state = auth_state.clone();
        move || {
            let auth_state = auth_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                auth_state.check_session().await;
            });
        }
    };
    if user.get_untracked().is_none() {
        check();
    }
    // Back to the page we were on after signing in.
    let login_path = {
        let loc = web_sys::window().map(|w| w.location());
        let here = loc
            .and_then(|l| Some(format!("{}{}", l.pathname().ok()?, l.search().ok()?)))
            .unwrap_or_default();
        if here.is_empty() || here == "/" {
            "/login".to_string()
        } else {
            format!(
                "/login?next={}",
                String::from(js_sys::encode_uri_component(&here))
            )
        }
    };
    let slot = StoredValue::new_local(Some(children));
    let authed = Memo::new(move |_| user.with(|u| u.is_some()));
    view! {
        {move || authed.get().then(|| slot.try_update_value(Option::take).flatten().map(|c| c()))}
        <Show when=move || checked.get() && user.get().is_none() && error.get().is_none()>
            <Redirect path=login_path.clone() />
        </Show>
        <Show when=move || checked.get() && user.get().is_none() && error.get().is_some()>
            <div class="auth-wrap">
                <div class="reg-card">
                    <h2>"Can't reach the server"</h2>
                    <span class="err" role="alert">{move || error.get().unwrap_or_default()}</span>
                    <button class="btn primary" type="button" on:click={
                        let check = check.clone();
                        move |_| check()
                    }>"Retry"</button>
                </div>
            </div>
        </Show>
    }
}

/// Main layout wrapper for authenticated pages. `class` is added to the page container
/// (e.g. `logs-screen`).
#[component]
pub fn Layout(#[prop(into, optional)] class: String, children: Children) -> impl IntoView {
    let app_state = use_app_state();
    let (collapsed, nav_open) = (app_state.collapsed, app_state.nav_open);
    // HTTPS configured but not served: say so on every page (Layout only renders when logged in).
    let tls_error = RwSignal::new(Option::<String>::None);
    wasm_bindgen_futures::spawn_local(async move {
        if let Ok(s) = crate::api::ApiClient::new()
            .get::<api_types::SystemStatusResponse>("/system/status")
            .await
        {
            tls_error.set(s.tls_error);
        }
    });
    // A navigation closes the off-canvas menu.
    nav_open.set(false);

    let children_view = children();

    view! {
        <div class=move || format!(
            "app {} {}",
            if collapsed.get() { "collapsed" } else { "" },
            if nav_open.get() { "navopen" } else { "" }
        )>
            <Sidebar />
            <Navbar />
            <main class="main" id="main" tabindex="-1">
                {move || tls_error.get().map(|e| view! {
                    <div class="card" role="alert" style="margin:var(--s3);border-color:var(--block)">
                        <div class="card-b"><b>"HTTPS is not active. "</b>{e}" "<a href="/settings#set-https" style="color:var(--accent)">"Open HTTPS settings"</a></div>
                    </div>
                })}
                <div class=format!("screen {class}")>
                    {children_view}
                </div>
            </main>
            <Show when=move || nav_open.get()>
                <div class="navscrim" on:click=move |_| nav_open.set(false)></div>
            </Show>
            <ToastContainer />
            <CommandPalette />
        </div>
    }
}

/// Centered card for login/register.
#[component]
pub fn AuthLayout(children: Children) -> impl IntoView {
    let children_view = children();
    view! {
        <div class="auth-wrap">
            <div class="reg-card">
                <div class="brand">
                    <span class="brand-mark"><super::icon::Icon name="adblock" /></span>
                    <span><b>"argus"</b></span>
                </div>
                {children_view}
            </div>
            <ToastContainer />
        </div>
    }
}

/// Renders its children only for Admin users; everyone else gets an explanation.
#[component]
pub fn RequireAdmin(children: ChildrenFn) -> impl IntoView {
    let user = use_auth_state().user;
    view! {
        <Show
            when=move || user.get().map(|u| u.role.is_admin()).unwrap_or(false)
            fallback=move || view! {
                <div class="card"><div class="empty">
                    <b>"Admins only"</b>
                    "Your role does not include access to this page."
                </div></div>
            }
        >
            {children()}
        </Show>
    }
}

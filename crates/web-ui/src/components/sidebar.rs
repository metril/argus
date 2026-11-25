//! Sidebar navigation: grouped, collapsible, off-canvas under 760px.

use leptos::prelude::*;
use leptos_router::hooks::use_location;

use super::icon::Icon;
use crate::state::{use_app_state, use_auth_state};

pub struct NavItem {
    pub path: &'static str,
    pub label: &'static str,
    pub icon: &'static str,
    pub sub: &'static str,
    /// Scope the user needs to see this entry.
    pub scope: Option<&'static str>,
}

pub const OVERVIEW: &[NavItem] = &[
    NavItem {
        path: "/",
        label: "Dashboard",
        icon: "dash",
        sub: "Traffic at a glance",
        scope: None,
    },
    NavItem {
        path: "/logs",
        label: "Logs",
        icon: "logs",
        sub: "Live request stream",
        scope: Some("logs:read"),
    },
];
pub const PROTECTION: &[NavItem] = &[
    NavItem {
        path: "/proxy",
        label: "Proxy",
        icon: "proxy",
        sub: "Listeners and redirect",
        scope: None,
    },
    NavItem {
        path: "/bypass",
        label: "Bypass",
        icon: "bypass",
        sub: "Sites Argus leaves alone",
        scope: None,
    },
    NavItem {
        path: "/filters",
        label: "Filters",
        icon: "filter",
        sub: "Lists and custom rules",
        scope: None,
    },
    NavItem {
        path: "/policy",
        label: "Policy",
        icon: "policy",
        sub: "Script policy per site",
        scope: None,
    },
    NavItem {
        path: "/userscripts",
        label: "Userscripts",
        icon: "code",
        sub: "Installed scripts",
        scope: None,
    },
    NavItem {
        path: "/profiles",
        label: "Profiles",
        icon: "user",
        sub: "Filtering profiles",
        scope: None,
    },
    NavItem {
        path: "/devices",
        label: "Devices",
        icon: "device",
        sub: "Known clients",
        scope: None,
    },
];
pub const ACCOUNT: &[NavItem] = &[
    NavItem {
        path: "/account",
        label: "Account",
        icon: "user",
        sub: "Your account, CA and sessions",
        scope: None,
    },
    NavItem {
        path: "/extension",
        label: "Browser extension",
        icon: "download",
        sub: "Install and sign in",
        scope: None,
    },
    NavItem {
        path: "/tokens",
        label: "API tokens",
        icon: "key",
        sub: "Scripts and integrations",
        scope: None,
    },
];
pub const ADMIN: &[NavItem] = &[
    NavItem {
        path: "/settings",
        label: "Settings",
        icon: "gear",
        sub: "Every runtime setting",
        scope: None,
    },
    NavItem {
        path: "/users",
        label: "Users",
        icon: "users",
        sub: "Accounts and roles",
        scope: None,
    },
    NavItem {
        path: "/sessions",
        label: "Sessions & tokens",
        icon: "session",
        sub: "All users",
        scope: None,
    },
    NavItem {
        path: "/audit",
        label: "Audit log",
        icon: "audit",
        sub: "Who changed what",
        scope: None,
    },
];

/// Whether `path` is the nav entry `item` or below it (`/users` is not `/userscripts`).
fn nav_matches(item: &str, path: &str) -> bool {
    item == path || (item != "/" && path.strip_prefix(item).is_some_and(|r| r.starts_with('/')))
}

/// Title and subtitle for a path (used by the top bar).
pub fn page_meta(path: &str) -> (&'static str, &'static str) {
    OVERVIEW
        .iter()
        .chain(PROTECTION)
        .chain(ACCOUNT)
        .chain(ADMIN)
        .find(|i| nav_matches(i.path, path))
        .map(|i| (i.label, i.sub))
        .unwrap_or(("Argus", ""))
}

fn group(
    label: &'static str,
    items: &'static [NavItem],
    admin_badge: bool,
    pathname: Signal<String>,
    scopes: Signal<Vec<String>>,
) -> impl IntoView {
    view! {
        <div class="nav-group">
            <span>{label}</span>
            {admin_badge.then(|| view! { <b class="badge admin">"admin"</b> })}
        </div>
        {items.iter().map(|item| {
            let path = item.path;
            let need = item.scope;
            let allowed = move || need.map(|n| scopes.get().iter().any(|s| s == n)).unwrap_or(true);
            let current = move || {
                nav_matches(path, &pathname.get())
            };
            view! {
                <Show when=allowed>
                <a
                    href=path
                    title=item.label
                    aria-current=move || if current() { Some("page") } else { None }
                >
                    <Icon name=item.icon />
                    <span class="nav-label">{item.label}</span>
                </a>
                </Show>
            }
        }).collect_view()}
    }
}

#[component]
pub fn Sidebar() -> impl IntoView {
    let app_state = use_app_state();
    let user = use_auth_state().user;
    let location = use_location();
    let pathname: Signal<String> = Signal::derive(move || location.pathname.get());
    let scopes: Signal<Vec<String>> = Signal::derive(move || {
        user.get()
            .map(|u| u.scopes.iter().map(|s| s.as_str().to_string()).collect())
            .unwrap_or_default()
    });
    let is_admin = move || user.get().map(|u| u.role.is_admin()).unwrap_or(false);
    let collapsed = app_state.collapsed;
    let logout = {
        let auth = use_auth_state();
        move |_| {
            let auth = auth.clone();
            wasm_bindgen_futures::spawn_local(async move { auth.logout().await });
        }
    };

    view! {
        <aside class="side" id="side" aria-label="Main navigation">
            <div class="brand">
                <span class="brand-mark"><Icon name="adblock" /></span>
                <span class="brand-text"><b>"Argus"</b></span>
            </div>
            <nav class="nav" id="nav">
                {group("Overview", OVERVIEW, false, pathname, scopes)}
                {group("Protection", PROTECTION, false, pathname, scopes)}
                {group("Account", ACCOUNT, false, pathname, scopes)}
                <Show when=is_admin>{group("Admin", ADMIN, true, pathname, scopes)}</Show>
            </nav>
            <div class="side-foot">
                <button type="button" on:click=logout title="Sign out">
                    <Icon name="out" /><span>"Sign out"</span>
                </button>
                <button
                    type="button"
                    class="collapse-btn"
                    aria-expanded=move || (!collapsed.get()).to_string()
                    title="Collapse sidebar"
                    on:click=move |_| app_state.toggle_collapsed()
                >
                    <span class="collapse-ic"><Icon name="collapse" /></span><span>"Collapse"</span>
                </button>
            </div>
        </aside>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nav_entry_does_not_match_a_longer_sibling() {
        assert!(nav_matches("/users", "/users"));
        assert!(nav_matches("/users", "/users/1"));
        assert!(!nav_matches("/users", "/userscripts"));
        assert!(nav_matches("/", "/"));
        assert!(!nav_matches("/", "/logs"));
        assert_eq!(page_meta("/userscripts").0, "Userscripts");
    }
}

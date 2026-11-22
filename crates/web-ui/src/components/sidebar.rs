//! Sidebar navigation component

use leptos::prelude::*;
use leptos_router::hooks::use_location;

use crate::state::use_app_state;

/// Navigation item
struct NavItem {
    path: &'static str,
    label: &'static str,
    icon: &'static str,
}

const NAV_ITEMS: &[NavItem] = &[
    NavItem {
        path: "/",
        label: "Dashboard",
        icon: "D",
    },
    NavItem {
        path: "/proxy",
        label: "Proxy",
        icon: "P",
    },
    NavItem {
        path: "/filters",
        label: "Filters",
        icon: "F",
    },
    NavItem {
        path: "/blocked",
        label: "Blocked",
        icon: "B",
    },
    NavItem {
        path: "/userscripts",
        label: "Userscripts",
        icon: "U",
    },
    NavItem {
        path: "/tokens",
        label: "API Tokens",
        icon: "T",
    },
    NavItem {
        path: "/settings",
        label: "Settings",
        icon: "S",
    },
];

/// Sidebar component
#[component]
pub fn Sidebar() -> impl IntoView {
    let app_state = use_app_state();
    let sidebar_open = app_state.sidebar_open;
    let location = use_location();

    view! {
        <aside class=move || format!(
            "sidebar {}",
            if sidebar_open.get() { "open" } else { "closed" }
        )>
            <nav class="sidebar-nav">
                {NAV_ITEMS.iter().map(|item| {
                    let path = item.path;
                    let is_active = move || {
                        let pathname = location.pathname.get();
                        if path == "/" {
                            pathname == "/"
                        } else {
                            pathname.starts_with(path)
                        }
                    };

                    view! {
                        <a
                            href=path
                            class=move || format!(
                                "sidebar-link {}",
                                if is_active() { "active" } else { "" }
                            )
                        >
                            <span class="sidebar-icon">{item.icon}</span>
                            <span class="sidebar-label">{item.label}</span>
                        </a>
                    }
                }).collect_view()}
            </nav>
        </aside>
    }
}

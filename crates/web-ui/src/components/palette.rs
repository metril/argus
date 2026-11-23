//! Command palette (Ctrl/Cmd+K).

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use super::drawer::{trap_tab, use_focus_return};
use super::icon::Icon;
use super::sidebar::{ACCOUNT, ADMIN, OVERVIEW, PROTECTION};
use crate::state::{use_app_state, use_auth_state};

#[derive(Clone)]
enum Action {
    Go(&'static str),
    Theme,
    Logout,
}

#[derive(Clone)]
struct Cmd {
    title: String,
    group: &'static str,
    action: Action,
}

#[component]
pub fn CommandPalette() -> impl IntoView {
    let app_state = use_app_state();
    let auth = use_auth_state();
    let open = app_state.palette_open;
    let navigate = use_navigate();
    let query = RwSignal::new(String::new());
    let sel = RwSignal::new(0usize);
    let input: NodeRef<leptos::html::Input> = NodeRef::new();
    let box_ref: NodeRef<leptos::html::Div> = NodeRef::new();
    use_focus_return(open.into());

    window_event_listener(leptos::ev::keydown, move |ev| {
        if (ev.ctrl_key() || ev.meta_key()) && ev.key().eq_ignore_ascii_case("k") {
            ev.prevent_default();
            open.update(|v| *v = !*v);
        }
    });

    let user = auth.user;
    let cmds = move || {
        let has = |sc: &str| {
            user.get()
                .map(|u| u.scopes.iter().any(|x| x.as_str() == sc))
                .unwrap_or(false)
        };
        let logs_ok = has("logs:read");
        let is_admin = user.get().map(|u| u.role.is_admin()).unwrap_or(false);
        let mut v: Vec<Cmd> = Vec::new();
        let sets: [(&[super::sidebar::NavItem], &'static str, bool); 4] = [
            (OVERVIEW, "Navigate", true),
            (PROTECTION, "Navigate", true),
            (ACCOUNT, "Navigate", true),
            (ADMIN, "Admin", is_admin),
        ];
        for (items, g, ok) in sets {
            if ok {
                for i in items.iter().filter(|i| i.scope.is_none() || logs_ok) {
                    v.push(Cmd {
                        title: format!("Go to {}", i.label),
                        group: g,
                        action: Action::Go(i.path),
                    });
                }
            }
        }
        if logs_ok {
            v.push(Cmd {
                title: "Show blocked requests only".into(),
                group: "Logs",
                action: Action::Go("/logs?action=blocked"),
            });
        }
        v.push(Cmd {
            title: "Switch theme".into(),
            group: "Appearance",
            action: Action::Theme,
        });
        v.push(Cmd {
            title: "Sign out".into(),
            group: "Account",
            action: Action::Logout,
        });
        let q = query.get().to_lowercase();
        v.retain(|c| {
            q.is_empty()
                || c.title.to_lowercase().contains(&q)
                || c.group.to_lowercase().contains(&q)
        });
        v
    };

    let run = {
        let app_state = app_state.clone();
        let navigate = navigate.clone();
        move |c: Cmd| {
            open.set(false);
            match c.action {
                Action::Go(p) => navigate(p, Default::default()),
                Action::Theme => app_state.toggle_theme(),
                Action::Logout => {
                    let auth = auth.clone();
                    wasm_bindgen_futures::spawn_local(async move { auth.logout().await });
                }
            }
        }
    };

    Effect::new(move |_| {
        if open.get() {
            query.set(String::new());
            sel.set(0);
            if let Some(i) = input.get() {
                let _ = i.focus();
            }
        }
    });

    view! {
        <Show when=move || open.get()>
            <div class="palette-scrim" on:click=move |_| open.set(false)>
                <div
                    class="palette"
                    role="dialog"
                    aria-modal="true"
                    aria-label="Command palette"
                    node_ref=box_ref
                    on:click=move |ev| ev.stop_propagation()
                    on:keydown={
                        let run = run.clone();
                        move |ev: web_sys::KeyboardEvent| {
                            match ev.key().as_str() {
                                "Escape" => { ev.prevent_default(); open.set(false); }
                                "ArrowDown" => { ev.prevent_default(); let n = cmds().len(); if n > 0 { sel.update(|s| *s = (*s + 1) % n); } }
                                "ArrowUp" => { ev.prevent_default(); let n = cmds().len(); if n > 0 { sel.update(|s| *s = (*s + n - 1) % n); } }
                                "Enter" => { ev.prevent_default(); if let Some(c) = cmds().get(sel.get_untracked()).cloned() { run(c); } }
                                _ => {
                                    if let Some(b) = box_ref.get() {
                                        let el: web_sys::Element = b.into();
                                        trap_tab(&ev, &el);
                                    }
                                }
                            }
                        }
                    }
                >
                    <div class="pin">
                        <Icon name="search" />
                        <input
                            node_ref=input
                            role="combobox"
                            aria-expanded="true"
                            aria-controls="pal-list"
                            aria-label="Type a command"
                            placeholder="Type a command or page name"
                            prop:value=move || query.get()
                            on:input=move |ev| { query.set(event_target_value(&ev)); sel.set(0); }
                        />
                    </div>
                    <ul id="pal-list" role="listbox">
                        {
                            let run = run.clone();
                            move || {
                                let list = cmds();
                                if list.is_empty() {
                                    return view! { <li class="dim">"No matches"</li> }.into_any();
                                }
                                list.into_iter().enumerate().map(|(i, c)| {
                                    let run = run.clone();
                                    let c2 = c.clone();
                                    view! {
                                        <li
                                            role="option"
                                            aria-selected=move || (sel.get() == i).to_string()
                                            on:mousemove=move |_| sel.set(i)
                                            on:click=move |_| run(c2.clone())
                                        >
                                            {c.title.clone()}
                                            <span class="grp">{c.group}</span>
                                        </li>
                                    }
                                }).collect_view().into_any()
                            }
                        }
                    </ul>
                    <div class="pfoot"><span>"Up/Down to move"</span><span>"Enter to run"</span><span>"Esc to close"</span></div>
                </div>
            </div>
        </Show>
    }
}

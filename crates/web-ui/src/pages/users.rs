//! Admin: users table with create/edit drawer.

use leptos::prelude::*;

use crate::api::users::{UserInfo, UserRole};
use crate::api::ApiClient;
use crate::components::{
    ChipSelect, ConfirmButton, Drawer, Icon, Layout, RequireAdmin, Segmented, Switch,
};
use crate::state::{use_app_state, use_auth_state};
use crate::utils::fmt_ago;

fn role_key(r: UserRole) -> &'static str {
    match r {
        UserRole::Admin => "admin",
        UserRole::User => "user",
        UserRole::Viewer => "viewer",
    }
}

fn parse_role(s: &str) -> UserRole {
    match s {
        "admin" => UserRole::Admin,
        "user" => UserRole::User,
        _ => UserRole::Viewer,
    }
}

const ROLES: [UserRole; 3] = [UserRole::Admin, UserRole::User, UserRole::Viewer];

#[component]
pub fn UsersPage() -> impl IntoView {
    view! { <Layout><RequireAdmin><UsersInner /></RequireAdmin></Layout> }
}

#[component]
fn UsersInner() -> impl IntoView {
    let app = use_app_state();
    let me = use_auth_state().user;
    let users = RwSignal::new(Vec::<UserInfo>::new());
    let profiles = RwSignal::new(Vec::<(String, String)>::new());
    let f_profile = RwSignal::new(String::new());
    let reload = RwSignal::new(0u32);
    let search = RwSignal::new(String::new());
    let roles = RwSignal::new(ROLES.to_vec());

    // Drawer state
    let open = RwSignal::new(false);
    let editing = RwSignal::new(Option::<UserInfo>::None);
    let f_name = RwSignal::new(String::new());
    let f_pass = RwSignal::new(String::new());
    let f_role = RwSignal::new("user".to_string());
    let f_enabled = RwSignal::new(true);
    let f_err = RwSignal::new(Option::<String>::None);

    {
        let app = app.clone();
        Effect::new(move |_| {
            reload.get();
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let c = ApiClient::new();
                match c.list_users().await {
                    Ok(p) => users.set(p.items),
                    Err(e) => app.error(format!("Failed to load users: {e}")),
                }
                match c.list_profiles().await {
                    Ok(p) => profiles.set(p.into_iter().map(|p| (p.id, p.name)).collect()),
                    Err(e) => app.error(format!("Failed to load profiles: {e}")),
                }
            });
        });
    }

    let visible = move || {
        let q = search.get().to_lowercase();
        let r = roles.get();
        users
            .get()
            .into_iter()
            .filter(|u| {
                r.contains(&u.role) && (q.is_empty() || u.username.to_lowercase().contains(&q))
            })
            .collect::<Vec<_>>()
    };

    let open_new = move |_| {
        editing.set(None);
        f_name.set(String::new());
        f_pass.set(String::new());
        f_role.set("user".into());
        f_enabled.set(true);
        f_err.set(None);
        open.set(true);
    };

    let toggle_enabled = {
        let app = app.clone();
        move |id: String, on: bool| {
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new()
                    .update_user(&id, None, Some(on), None)
                    .await
                {
                    Ok(u) => {
                        app.success(format!(
                            "{} {}",
                            u.username,
                            if on { "enabled" } else { "disabled" }
                        ));
                        reload.update(|n| *n += 1);
                    }
                    Err(e) => app.error(e.to_string()),
                }
            });
        }
    };
    let delete = {
        let app = app.clone();
        move |id: String| {
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().delete_user(&id).await {
                    Ok(_) => {
                        app.success("User deleted");
                        reload.update(|n| *n += 1);
                    }
                    Err(e) => app.error(e.to_string()),
                }
            });
        }
    };

    let save = {
        let app = app.clone();
        move |_| {
            let role = parse_role(&f_role.get_untracked());
            let app = app.clone();
            match editing.get_untracked() {
                Some(u) => {
                    let enabled = f_enabled.get_untracked();
                    let profile = f_profile.get_untracked();
                    wasm_bindgen_futures::spawn_local(async move {
                        match ApiClient::new()
                            .update_user(&u.id, Some(role), Some(enabled), Some(profile))
                            .await
                        {
                            Ok(_) => {
                                app.success("User updated");
                                open.set(false);
                                reload.update(|n| *n += 1);
                            }
                            Err(e) => f_err.set(Some(e.to_string())),
                        }
                    });
                }
                None => {
                    let (name, pass) = (f_name.get_untracked(), f_pass.get_untracked());
                    if name.trim().len() < 3 {
                        f_err.set(Some("Username must be 3 to 50 characters.".into()));
                        return;
                    }
                    if pass.len() < 8 {
                        f_err.set(Some("Password must be at least 8 characters.".into()));
                        return;
                    }
                    wasm_bindgen_futures::spawn_local(async move {
                        match ApiClient::new().create_user(name.trim(), &pass, role).await {
                            Ok(_) => {
                                app.success("User created");
                                open.set(false);
                                reload.update(|n| *n += 1);
                            }
                            Err(e) => f_err.set(Some(e.to_string())),
                        }
                    });
                }
            }
        }
    };

    let title = Signal::derive(move || {
        if editing.read().is_some() {
            "Edit user".to_string()
        } else {
            "New user".to_string()
        }
    });
    let role_opts = vec![
        ("admin".to_string(), "Admin".to_string()),
        ("user".to_string(), "User".to_string()),
        ("viewer".to_string(), "Viewer".to_string()),
    ];

    view! {
        <div class="toolbar">
            <div class="search grow">
                <Icon name="search" />
                <label class="sr" for="userQ">"Search users"</label>
                <input class="input" id="userQ" placeholder="Search users" prop:value=move || search.get() on:input=move |ev| search.set(event_target_value(&ev)) />
            </div>
            <div class="chips" role="group" aria-label="Role filter">
                {ROLES.into_iter().map(|r| view! {
                    <ChipSelect
                        pressed=Signal::derive(move || roles.read().contains(&r))
                        on_toggle=Callback::new(move |on: bool| roles.update(|v| { v.retain(|x| *x != r); if on { v.push(r); } }))
                    >{match r { UserRole::Admin => "Admin", UserRole::User => "User", UserRole::Viewer => "Viewer" }}</ChipSelect>
                }).collect_view()}
            </div>
            <button class="btn primary" type="button" on:click=open_new><Icon name="plus" />"New user"</button>
        </div>
        <div class="card">
            <div class="tbl-wrap">
                <table class="tbl">
                    <thead><tr><th>"User"</th><th>"Role"</th><th>"Enabled"</th><th>"Profile"</th><th class="r">"Sessions"</th><th>"Last seen"</th><th></th></tr></thead>
                    <tbody>
                        <For
                            each=visible
                            key=|u| format!("{}{}{}{}", u.id, role_key(u.role), u.enabled, u.last_login.clone().unwrap_or_default())
                            children={
                                let toggle_enabled = toggle_enabled.clone();
                                let delete = delete.clone();
                                move |u| {
                                    let is_me = me.get_untracked().map(|m| m.id == u.id).unwrap_or(false);
                                    let id = u.id.clone();
                                    let (id_t, id_d) = (id.clone(), id.clone());
                                    let toggle_enabled = toggle_enabled.clone();
                                    let delete = delete.clone();
                                    let u2 = u.clone();
                                    let prof_name = u.default_profile.clone().map(|id| profiles.get_untracked().into_iter().find(|p| p.0 == id).map(|p| p.1).unwrap_or(id));
                                    view! {
                                        <tr>
                                            <td>{u.username.clone()}{is_me.then(|| view! { " " <span class="badge">"you"</span> })}</td>
                                            <td><span class=if u.role == UserRole::Admin { "badge admin" } else { "badge" }>{role_key(u.role)}</span></td>
                                            <td>
                                                <Switch
                                                    checked=u.enabled
                                                    label=format!("Enabled, {}", u.username)
                                                    disabled=is_me
                                                    on_change=Callback::new(move |on: bool| toggle_enabled(id_t.clone(), on))
                                                />
                                            </td>
                                            <td>{prof_name.unwrap_or_else(|| "-".into())}</td>
                                            <td class="r num">{u.session_count}</td>
                                            <td class="num">{u.last_login.as_deref().map(fmt_ago).unwrap_or_else(|| "never".into())}</td>
                                            <td class="r">
                                                <button class="btn sm ghost" type="button" on:click=move |_| {
                                                    editing.set(Some(u2.clone()));
                                                    f_name.set(u2.username.clone());
                                                    f_role.set(role_key(u2.role).into());
                                                    f_enabled.set(u2.enabled);
                                                    f_profile.set(u2.default_profile.clone().unwrap_or_default());
                                                    f_err.set(None);
                                                    open.set(true);
                                                }>"Edit"</button>
                                                {(!is_me).then(|| view! {
                                                    <ConfirmButton label="Delete" on_confirm=Callback::new(move |_| delete(id_d.clone())) />
                                                })}
                                            </td>
                                        </tr>
                                    }
                                }
                            }
                        />
                    </tbody>
                </table>
                <Show when=move || visible().is_empty()>
                    <div class="empty"><b>"No users match"</b>"Clear a filter to see more."</div>
                </Show>
            </div>
        </div>
        <Drawer
            open=open
            title=title
            footer=std::sync::Arc::new({
                let save = save.clone();
                move || {
                    let save = save.clone();
                    view! {
                        <button class="btn ghost" type="button" on:click=move |_| open.set(false)>"Cancel"</button>
                        <button class="btn primary" type="button" on:click=save>"Save"</button>
                    }.into_any()
                }
            })
        >
            <div class="field">
                <label for="uName">"Username"</label>
                <input class="input" id="uName" disabled=move || editing.read().is_some() prop:value=move || f_name.get() on:input=move |ev| f_name.set(event_target_value(&ev)) />
            </div>
            <Show when=move || editing.read().is_none()>
                <div class="field">
                    <label for="uPass">"Password"</label>
                    <input class="input" id="uPass" type="password" autocomplete="new-password" prop:value=move || f_pass.get() on:input=move |ev| f_pass.set(event_target_value(&ev)) />
                    <span class="hint">"At least 8 characters."</span>
                </div>
            </Show>
            <div class="field">
                <span class="lbl">"Role"</span>
                <Segmented label="Role" options=role_opts.clone() value=f_role on_change=Callback::new(move |v| f_role.set(v)) />
            </div>
            <Show when=move || editing.read().is_some()>
                <div class="field">
                    <label for="uProf">"Default profile"</label>
                    <select class="select" id="uProf" prop:value=move || f_profile.get() on:change=move |ev| f_profile.set(event_target_value(&ev))>
                        <option value="">"None"</option>
                        <For each=move || profiles.get() key=|p| p.0.clone() children=|p| { let v = p.0.clone(); view! { <option value=v>{p.1}</option> } } />
                    </select>
                    <span class="hint">"The profile this account starts on in the UI."</span>
                </div>
                <div class="srow">
                    <div class="txt"><b>"Enabled"</b><small>"Disabling signs the user out and disables their tokens."</small></div>
                    <Switch checked=f_enabled label="Enabled" on_change=Callback::new(move |v| f_enabled.set(v)) />
                </div>
            </Show>
            {move || f_err.get().map(|e| view! { <span class="err" role="alert">{e}</span> })}
        </Drawer>
    }
}

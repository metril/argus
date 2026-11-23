//! Bridge between the navbar profile selector and profile-scoped pages (script policy,
//! userscripts). The selector itself lives in the navbar; this component bumps the page's
//! `reload` signal whenever the selection changes.

use leptos::prelude::*;

use crate::state::use_app_state;

/// Renders nothing. `reload` is incremented after the navbar selection changes so the page
/// reloads its data.
#[component]
pub fn ProfileSelector(reload: RwSignal<u32>) -> impl IntoView {
    let global = use_app_state().profile_reload;
    Effect::new(move |first: Option<()>| {
        global.track();
        if first.is_some() {
            reload.update(|n| *n += 1);
        }
    });
}

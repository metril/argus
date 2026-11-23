//! Modal dialog component

use leptos::prelude::*;

/// Modal component
#[component]
pub fn Modal(
    #[prop(into)] title: String,
    open: RwSignal<bool>,
    #[prop(optional)] on_close: Option<Callback<()>>,
    #[prop(into, optional)] class: String,
    children: Children,
) -> impl IntoView {
    let class_value = format!("modal {}", class);

    // Store children view immediately since Children is FnOnce
    let children_view = children();

    view! {
        <div
            class="modal-overlay"
            style=move || if open.get() { "display: flex" } else { "display: none" }
            on:click=move |_| {
                open.set(false);
                if let Some(cb) = on_close {
                    cb.run(());
                }
            }
        >
            <div
                class=class_value
                role="dialog"
                aria-modal="true"
                on:keydown=move |ev: web_sys::KeyboardEvent| if ev.key() == "Escape" { open.set(false); }
                on:click=move |ev: web_sys::MouseEvent| ev.stop_propagation()
            >
                <div class="modal-header">
                    <h2 class="modal-title">{title.clone()}</h2>
                    <button
                        type="button"
                        class="modal-close"
                        on:click=move |_| {
                            open.set(false);
                            if let Some(cb) = on_close {
                                cb.run(());
                            }
                        }
                    >
                        "x"
                    </button>
                </div>
                <div class="modal-body">
                    {children_view}
                </div>
            </div>
        </div>
    }
}

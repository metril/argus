//! Outcome pills and mode tags.

use leptos::prelude::*;

/// Pill for a request outcome. Always pairs the colour dot with the word.
#[component]
pub fn Pill(
    /// `allowed`, `blocked`, `passthrough`, `error`, or anything else for neutral.
    #[prop(into)]
    kind: String,
    #[prop(into, optional)] text: Option<String>,
) -> impl IntoView {
    let class = match kind.as_str() {
        "allowed" | "ok" | "allow" => "p-allow",
        "blocked" | "failed" | "block" => "p-block",
        "passthrough" | "pass" => "p-pass",
        "error" | "warn" => "p-error",
        _ => "p-neutral",
    };
    let label = text.unwrap_or(kind);
    view! { <span class=format!("pill {class}")>{label}</span> }
}

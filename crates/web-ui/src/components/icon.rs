//! Inline SVG icons (16x16, stroke = currentColor), drawn from the design mockup.

use leptos::prelude::*;

fn paths(name: &str) -> &'static str {
    match name {
        "dash" => {
            r#"<rect x="2" y="2" width="5" height="5" rx="1"/><rect x="9" y="2" width="5" height="3" rx="1"/><rect x="9" y="7" width="5" height="7" rx="1"/><rect x="2" y="9" width="5" height="5" rx="1"/>"#
        }
        "logs" => r#"<path d="M1.5 8h3l2-5 3 10 2-5h3"/>"#,
        "proxy" => r#"<path d="M2 5h9M8 2l3 3-3 3M14 11H5M8 8l-3 3 3 3"/>"#,
        "filter" => r#"<path d="M2 3h12l-4.5 5.5V13l-3 1.5V8.5z"/>"#,
        "policy" => {
            r#"<path d="M8 1.5 13.5 4v4c0 3.2-2.4 5.6-5.5 6.5C4.9 13.6 2.5 11.2 2.5 8V4z"/><path d="m5.5 8 1.8 1.8L10.5 6.5"/>"#
        }
        "key" => {
            r#"<circle cx="5" cy="11" r="3"/><path d="m7.2 8.8 6.3-6.3M11 5l2 2M12.5 3.5l1 1"/>"#
        }
        "users" => {
            r#"<circle cx="6" cy="5.5" r="2.5"/><path d="M1.5 14c.4-2.6 2.2-4 4.5-4s4.1 1.4 4.5 4"/><path d="M10.5 3.2a2.4 2.4 0 0 1 0 4.6M12 10.3c1.4.5 2.3 1.8 2.5 3.7"/>"#
        }
        "session" => {
            r#"<rect x="1.5" y="2.5" width="13" height="9" rx="1"/><path d="M5.5 14h5M8 11.5V14"/>"#
        }
        "audit" => {
            r#"<path d="M3.5 1.5h6l3 3v10h-9z"/><path d="M9.5 1.5v3h3M5.5 8h5M5.5 10.5h5M5.5 13h3"/>"#
        }
        "dots" => {
            r#"<circle cx="3.5" cy="8" r="1"/><circle cx="8" cy="8" r="1"/><circle cx="12.5" cy="8" r="1"/>"#
        }
        "plus" => r#"<path d="M8 3v10M3 8h10"/>"#,
        "search" => r#"<circle cx="7" cy="7" r="4.5"/><path d="m10.5 10.5 3.5 3.5"/>"#,
        "x" => r#"<path d="M4 4l8 8M12 4l-8 8"/>"#,
        "menu" => r#"<path d="M2 4h12M2 8h12M2 12h12"/>"#,
        "collapse" => {
            r#"<rect x="1.5" y="2.5" width="13" height="11" rx="1"/><path d="M5.5 2.5v11M10.5 6 8.5 8l2 2"/>"#
        }
        "pause" => r#"<path d="M5.5 3v10M10.5 3v10"/>"#,
        "play" => r#"<path d="M4.5 2.5v11l9-5.5z"/>"#,
        "copy" => {
            r#"<rect x="5" y="5" width="9" height="9" rx="1"/><path d="M11 5V2.5H2.5V11H5"/>"#
        }
        "sun" => {
            r#"<circle cx="8" cy="8" r="3"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3 3l1.4 1.4M11.6 11.6 13 13M3 13l1.4-1.4M11.6 4.4 13 3"/>"#
        }
        "check" => r#"<path d="m3 8.5 3 3 7-7"/>"#,
        "lock" => {
            r#"<rect x="3.5" y="7" width="9" height="6.5" rx="1.2"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/>"#
        }
        "adblock" => {
            r#"<path d="M1.5 8s2.5-4.5 6.5-4.5S14.5 8 14.5 8 12 12.5 8 12.5 1.5 8 1.5 8z"/><circle cx="8" cy="8" r="2"/>"#
        }
        "gear" => {
            r#"<circle cx="8" cy="8" r="2.2"/><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M3.4 12.6l1.4-1.4M11.2 4.8l1.4-1.4"/>"#
        }
        "reset" => r#"<path d="M3 3v3.5h3.5"/><path d="M3.4 6.3A5 5 0 1 1 3 9.5"/>"#,
        "first" => {
            r#"<circle cx="6.5" cy="5" r="2.5"/><path d="M2 14c.4-2.6 2.2-4 4.5-4 1 0 1.9.3 2.6.8M12.5 9.5v5M10 12h5"/>"#
        }
        "code" => r#"<path d="M5.5 4 2 8l3.5 4M10.5 4 14 8l-3.5 4M9 3 7 13"/>"#,
        "device" => r#"<rect x="3" y="2" width="10" height="12" rx="1.5"/><path d="M7 11.5h2"/>"#,
        "user" => {
            r#"<circle cx="8" cy="5.5" r="2.7"/><path d="M2.5 14c.5-2.8 2.7-4.3 5.5-4.3s5 1.5 5.5 4.3"/>"#
        }
        "moon" => r#"<path d="M13 9.5A5.5 5.5 0 0 1 6.5 3 5.5 5.5 0 1 0 13 9.5z"/>"#,
        "out" => r#"<path d="M6 2.5H3v11h3M10 5l3 3-3 3M13 8H6"/>"#,
        "trash" => {
            r#"<path d="M2.5 4h11M6 4V2.5h4V4M4 4l.6 9.5h6.8L12 4M6.8 6.5v4.5M9.2 6.5v4.5"/>"#
        }
        "bypass" => {
            r#"<rect x="3" y="7" width="10" height="7" rx="1.2"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2M8 10v1.5"/>"#
        }
        "globe" => {
            r#"<circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2c2.2 2.4 2.2 9.6 0 12M8 2c-2.2 2.4-2.2 9.6 0 12"/>"#
        }
        "bolt" => r#"<path d="M9 1.5 3.5 9H8l-1 5.5L12.5 7H8z"/>"#,
        "chev-r" => r#"<path d="m6 3 5 5-5 5"/>"#,
        "chev-l" => r#"<path d="m10 3-5 5 5 5"/>"#,
        "alert" => r#"<path d="M8 2 1.5 13.5h13z"/><path d="M8 6.5v3M8 11.5v.5"/>"#,
        "download" => r#"<path d="M8 2v8M4.5 6.5 8 10l3.5-3.5M2.5 13.5h11"/>"#,
        "upload" => r#"<path d="M8 10V2M4.5 5.5 8 2l3.5 3.5M2.5 13.5h11"/>"#,
        "refresh" => {
            r#"<path d="M13 3v3.5H9.5M3 13V9.5h3.5M12.5 6.5A5 5 0 0 0 3.7 5M3.5 9.5a5 5 0 0 0 8.8 1.5"/>"#
        }
        _ => "",
    }
}

/// A named icon. Size and colour come from the `svg.i` CSS rule.
#[component]
pub fn Icon(#[prop(into)] name: String) -> impl IntoView {
    view! { <svg class="i" viewBox="0 0 16 16" aria-hidden="true" inner_html=paths(&name)></svg> }
}

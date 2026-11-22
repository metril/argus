//! A resource library is validated when loaded: broken resources are dropped, reported and never
//! served (this also covers libraries cached by older versions).

use base64::Engine as _;
use filter_engine::{build_set, ListFormat, ListInput, SharedEngine};

fn res(name: &str, js: &str, deps: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "kind": {"mime": "application/javascript"},
        "content": base64::engine::general_purpose::STANDARD.encode(js),
        "dependencies": deps,
    })
}

#[test]
fn broken_resources_are_dropped_reported_and_not_served() {
    let json = serde_json::json!([
        res("good.js", "function good() { window.ok = 1; }", &[]),
        res("cut.js", "function cut(a, b = {", &[]),
        res("needs-cut.js", "function needsCut() {}", &["cut.js"]),
    ])
    .to_string();
    let e = SharedEngine::new();
    assert_eq!(e.set_resources_from_json(&json).unwrap(), 1);
    let r = e.resource_report();
    assert_eq!(r.loaded, 1);
    let mut dropped: Vec<&str> = r.dropped.iter().map(|d| d.name.as_str()).collect();
    dropped.sort();
    assert_eq!(dropped, ["cut.js", "needs-cut.js"]);
    assert!(r.dropped.iter().all(|d| !d.reason.is_empty()));

    build_set(&[ListInput {
        id: "l".into(),
        content: "site.test##+js(cut)\nsite.test##+js(good)\n".into(),
        format: ListFormat::Abp,
        allowlist: false,
        trusted: false,
        includes: Default::default(),
    }])
    .install_into(&e);
    let js = e.cosmetic_for("https://site.test/").injected_script;
    assert!(js.contains("good("), "{js}");
    assert!(
        !js.contains("cut"),
        "a dropped resource must not be served: {js}"
    );
}

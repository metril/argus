//! How the engine treats ports in `||host/path` rules (documents the behaviour the proxy relies
//! on: it must hand the engine the default-port spelling of a URL).

use filter_engine::{build_set, ListFormat, ListInput, SharedEngine};

fn engine(rule: &str) -> SharedEngine {
    let e = SharedEngine::new();
    build_set(&[ListInput {
        id: "l".into(),
        content: format!("{rule}\n"),
        format: ListFormat::Abp,
        allowlist: false,
        trusted: false,
        includes: Default::default(),
    }])
    .install_into(&e);
    e
}

fn hit(e: &SharedEngine, url: &str) -> bool {
    e.check(url, "https://page.test/", "script").blocked
}

#[test]
fn path_anchored_rule_needs_the_default_port_spelling() {
    let e = engine("||example.com/ads.js");
    assert!(hit(&e, "https://example.com/ads.js"));
    // The engine matches the URL text: the proxy must drop default ports before asking.
    assert!(!hit(&e, "https://example.com:443/ads.js"));
    assert!(!hit(&e, "http://example.com:80/ads.js"));
    // A non-default port is part of the URL: like uBO, this does not match.
    assert!(!hit(&e, "https://example.com:8443/ads.js"));
}

#[test]
fn host_anchored_caret_rule_matches_any_port() {
    let e = engine("||example.com^");
    for u in [
        "https://example.com/x.js",
        "https://example.com:443/x.js",
        "https://example.com:8443/x.js",
    ] {
        assert!(hit(&e, u), "{u}");
    }
}

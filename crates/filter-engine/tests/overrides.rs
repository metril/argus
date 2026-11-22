//! Domain-set hits are overridden by the engine's exceptions, `$important` and `$badfilter`
//! rules exactly as if every rule lived in the engine.

use filter_engine::{build_set, ListFormat, ListInput, SharedEngine};

fn engine(lists: &[&str]) -> SharedEngine {
    let inputs: Vec<ListInput> = lists
        .iter()
        .enumerate()
        .map(|(i, c)| ListInput {
            id: format!("l{i}"),
            content: c.to_string(),
            format: ListFormat::Auto,
            allowlist: false,
            trusted: false,
            includes: Default::default(),
        })
        .collect();
    let e = SharedEngine::new();
    let built = build_set(&inputs);
    assert!(
        !built.domains.is_empty(),
        "pure domain rules must reach the set"
    );
    built.install_into(&e);
    e
}

fn blocked(e: &SharedEngine, host: &str) -> (bool, bool) {
    let r = e.check(
        &format!("https://{host}/x.js"),
        "https://site.test/",
        "script",
    );
    (r.blocked, r.important)
}

#[test]
fn exception_for_a_subdomain_unblocks_it_but_not_its_siblings() {
    let e = engine(&["||example.com^\n@@||sub.example.com^\n"]);
    assert!(blocked(&e, "example.com").0);
    assert!(blocked(&e, "other.example.com").0);
    assert!(!blocked(&e, "sub.example.com").0);
    assert!(!blocked(&e, "a.sub.example.com").0);
}

#[test]
fn important_in_the_engine_beats_the_exception() {
    let e = engine(&["||example.com^\n||sub.example.com^$important\n@@||sub.example.com^\n"]);
    assert_eq!(blocked(&e, "sub.example.com"), (true, true));
    assert!(blocked(&e, "other.example.com").0);
}

#[test]
fn badfilter_removes_a_domain_set_entry() {
    let e = engine(&["||ads.example.com^\n||keep.example.com^\n||ads.example.com^$badfilter\n"]);
    assert!(!blocked(&e, "ads.example.com").0);
    assert!(!blocked(&e, "x.ads.example.com").0);
    assert!(blocked(&e, "keep.example.com").0);
}

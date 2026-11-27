//! Generic `##+js(...)` rules and the `:style(remove: true)` / `:remove()` forms: scriptlet
//! injections and remove actions, never CSS selectors.

use ext_rules::*;

fn rule(raw: &str, trusted: bool) -> ExtRule {
    let mut r = ExtRule::new(ExtKind::Other, raw);
    r.trusted = trusted;
    r.list = "L".into();
    r
}

fn plan_injections(rules: &[&str], trusted: bool, url: &str) -> Vec<Injection> {
    let i = ExtIndex::build(&rules.iter().map(|r| rule(r, trusted)).collect::<Vec<_>>());
    let h: Vec<(&str, &str)> = vec![("content-type", "text/html")];
    let req = RequestInfo {
        source_url: None,
        ..RequestInfo::new(url, "GET", ResourceType::Document)
    };
    i.response_plan(
        &req,
        &ResponseInfo {
            status: 200,
            headers: &h,
        },
    )
    .injections
    .into_iter()
    .cloned()
    .collect()
}

#[test]
fn generic_ubo_scriptlet_is_a_scriptlet_injection_not_a_selector() {
    let inj = plan_injections(&["##+js(no-topics)"], false, "https://any.example/");
    assert_eq!(
        inj,
        [Injection::Scriptlet {
            name: "no-topics".into(),
            args: vec![],
            trusted: false
        }]
    );
}

#[test]
fn scriptlet_arguments_unescape_and_keep_inner_empties() {
    let inj = plan_injections(
        &["##+js(set-constant.js, a.b, 'x\\,y', , true)"],
        false,
        "https://any.example/",
    );
    assert_eq!(
        inj,
        [Injection::Scriptlet {
            name: "set-constant".into(),
            args: vec!["a.b".into(), "x,y".into(), "".into(), "true".into()],
            trusted: false
        }]
    );
}

#[test]
fn domain_scoped_and_excepted() {
    let rules = ["a.example##+js(no-topics)", "b.example#@#+js(no-topics)"];
    assert_eq!(plan_injections(&rules, false, "https://a.example/").len(), 1);
    assert!(plan_injections(&rules, false, "https://c.example/").is_empty());
    let rules = ["##+js(no-topics)", "b.example#@#+js(no-topics)"];
    assert!(plan_injections(&rules, false, "https://b.example/").is_empty());
    assert_eq!(plan_injections(&rules, false, "https://a.example/").len(), 1);
}

#[test]
fn only_trusted_scriptlets_need_a_trusted_list() {
    // Plain scriptlets are as safe as the engine's own `+js()` rules: any list.
    assert_eq!(
        plan_injections(
            &["x.example#%#//scriptlet('prevent-element-src-loading', 'script', 'ad')"],
            false,
            "https://x.example/"
        )
        .len(),
        1
    );
    // Trust is decided where the name is resolved (by the resource, so aliases cannot dodge
    // it); the injection only carries the list's trust.
    for r in [
        "x.example##+js(trusted-set-cookie, a, b)",
        "x.example##+js(rpnt, a, b)",
        "x.example##+js(replace-node-text, a, b)",
    ] {
        for trusted in [false, true] {
            let inj = plan_injections(&[r], trusted, "https://x.example/");
            assert!(
                matches!(&inj[..], [Injection::Scriptlet { trusted: t, .. }] if *t == trusted),
                "{r} {trusted}: {inj:?}"
            );
        }
    }
}

fn procedural(inj: &[Injection]) -> Vec<(String, Option<String>)> {
    inj.iter()
        .filter_map(|i| match i {
            Injection::ProceduralCss { selector, style } => Some((selector.clone(), style.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn remove_forms_are_remove_actions() {
    for raw in [
        "##.promo:style(remove: true)",
        "##.promo:remove()",
        "#$?#.promo { remove: true }",
    ] {
        let inj = plan_injections(&[raw], false, "https://any.example/");
        assert_eq!(
            procedural(&inj),
            [(".promo".to_string(), Some("remove: true".to_string()))],
            "{raw}"
        );
    }
    // A real style stays a style, and neither leaves the action text in the selector.
    let inj = plan_injections(
        &["##.promo:style(margin: 0 !important)"],
        false,
        "https://any.example/",
    );
    assert_eq!(
        procedural(&inj),
        [(".promo".to_string(), Some("margin: 0 !important".to_string()))]
    );
    // Procedural operators in front of the action keep working.
    let inj = plan_injections(
        &["##div:has-text(Ad):remove()"],
        false,
        "https://any.example/",
    );
    assert_eq!(procedural(&inj)[0].0, "div:has-text(Ad)");
}

#[test]
fn unsafe_styles_are_still_refused_in_the_action_form() {
    let inj = plan_injections(
        &["##.x:style(background: url(https://t.example/p.gif))"],
        false,
        "https://any.example/",
    );
    assert!(inj.is_empty());
}

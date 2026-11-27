//! AdGuard scriptlet coverage, generic scriptlet / action routing and `remove: true` forms.

use filter_engine::{
    compile_lists, convert, ConvertOptions, Converted, ExtKind, ListFormat, SharedEngine,
};

fn one(rule: &str) -> Converted {
    convert(
        &format!("{rule}\n"),
        &ConvertOptions {
            format: ListFormat::Adguard,
            ..Default::default()
        },
    )
}

fn lines(c: &Converted) -> Vec<&str> {
    c.rules.lines().collect()
}

#[test]
fn adguard_names_ubo_knows_are_translated_not_handed_off() {
    for ubo in [
        "evaldata-prune",
        "href-sanitizer",
        "json-prune-fetch-response",
        "json-prune-xhr-response",
        "prevent-bab",
        "prevent-canvas",
        "prevent-innerHTML",
        "prevent-navigation",
        "trusted-set-attr",
        "trusted-set-constant",
        "trusted-set-cookie-reload",
        "trusted-replace-node-text",
        "trusted-prune-inbound-object",
        "trusted-suppress-native-method",
    ] {
        let c = one(&format!("a.example#%#//scriptlet('{ubo}', 'x')"));
        assert_eq!(lines(&c), [format!("a.example##+js({ubo}, x)")], "{ubo}");
    }
    // uBO's own spelling through AdGuard's compatibility prefix, with or without `.js`.
    let c = one("a.example#%#//scriptlet('ubo-aopr.js', 'foo')");
    assert_eq!(lines(&c), ["a.example##+js(aopr, foo)"]);
    let c = one("a.example#%#//scriptlet('ubo-set-constant', 'a', 'true')");
    assert_eq!(lines(&c), ["a.example##+js(set-constant, a, true)"]);
}

#[test]
fn adguard_only_scriptlets_stay_with_the_page_runtime() {
    for name in [
        "prevent-element-src-loading",
        "google-ima3",
        "prevent-adfly",
        "prevent-fab-3.2.0",
        "prevent-popads-net",
        "set-popads-dummy",
        "no-protected-audience",
        "metrika-yandex-tag",
        "hide-in-shadow-dom",
        "remove-in-shadow-dom",
        "trusted-create-element",
        "trusted-dispatch-event",
        "debug-on-property-read",
        "dir-string",
    ] {
        let c = one(&format!("a.example#%#//scriptlet('{name}', 'x')"));
        assert!(c.rules.is_empty(), "{name}");
        assert_eq!(c.ext[0].kind, ExtKind::Scriptlet, "{name}");
    }
}

#[test]
fn remove_declarations_become_the_remove_action() {
    for (rule, want) in [
        (
            "example.com#$#.sel { remove: true }",
            "example.com##.sel:remove()",
        ),
        (
            "example.com#$#.sel { remove:true; }",
            "example.com##.sel:remove()",
        ),
        ("#$#.sel { remove: true }", "##.sel:remove()"),
        (
            "example.com#@$#.sel { remove: true }",
            "example.com#@#.sel:remove()",
        ),
        (
            "example.com##.sel:style(remove: true)",
            "example.com##.sel:remove()",
        ),
        ("##.sel:style(remove:true)", "##.sel:remove()"),
        // Other declarations are untouched.
        (
            "example.com#$#.sel { margin: 0 }",
            "example.com##.sel:style(margin: 0)",
        ),
    ] {
        assert_eq!(lines(&one(rule)), [want], "{rule}");
    }
}

#[test]
fn generic_scriptlets_and_actions_are_handed_off_not_filed_as_css() {
    // adblock-rust refuses generic scriptlets and actions; they must come back as extended
    // rules carrying the uBO call or the action, never as a selector.
    let c = one("#%#//scriptlet('no-topics')");
    let out = compile_lists(&[&c.rules]);
    let ext = &out.per_list[0].ext_rules;
    assert_eq!(ext.len(), 1, "{ext:?}");
    assert_eq!(ext[0].raw, "##+js(no-topics)");
    let c = one("#$#.sel { remove: true }");
    let out = compile_lists(&[&c.rules]);
    assert_eq!(out.per_list[0].ext_rules[0].raw, "##.sel:remove()");
}

#[test]
fn scriptlet_script_resolves_from_the_resource_library() {
    let engine = SharedEngine::new();
    assert!(engine
        .scriptlet_script("aopr", &["a.b".into()], false)
        .is_none());
    let json = serde_json::json!([{
        "name": "abort-on-property-read.js", "aliases": ["aopr.js"],
        "kind": {"mime": "application/javascript"},
        "content": "ZnVuY3Rpb24gYWJvcnRPblByb3BlcnR5UmVhZCgpIHt9",
    }]);
    engine.set_resources_from_json(&json.to_string()).unwrap();
    for name in ["aopr", "abort-on-property-read", "aopr.js"] {
        let js = engine
            .scriptlet_script(name, &["a.b".into(), "x,y".into()], false)
            .unwrap_or_else(|| panic!("{name}"));
        assert!(js.contains("abortOnPropertyRead"), "{js}");
    }
    assert!(engine.scriptlet_script("nope", &[], false).is_none());
}

#[test]
fn trust_is_the_resources_not_the_spelling() {
    // A resource that requires trust, reachable by several aliases: none of them may run it for
    // an untrusted rule, and all of them may for a trusted one.
    let engine = SharedEngine::new();
    let json = serde_json::json!([{
        "name": "trusted-replace-node-text.js",
        "aliases": ["trusted-rpnt.js", "replace-node-text.js", "rpnt.js"],
        "kind": {"mime": "application/javascript"},
        "content": "ZnVuY3Rpb24gdHJ1c3RlZFJlcGxhY2VOb2RlVGV4dCgpIHt9",
        "permission": 1,
    }]);
    engine.set_resources_from_json(&json.to_string()).unwrap();
    for name in [
        "trusted-replace-node-text",
        "trusted-replace-node-text.js",
        "trusted-rpnt",
        "replace-node-text",
        "rpnt",
        "rpnt.js",
    ] {
        assert!(
            engine
                .scriptlet_script(name, &["a".into()], false)
                .is_none(),
            "{name} must not run for an untrusted rule"
        );
        assert!(
            engine
                .scriptlet_script(name, &["a".into()], true)
                .is_some_and(|j| j.contains("trustedReplaceNodeText")),
            "{name} trusted"
        );
    }
}

//! Real rules, spelled as lists write them (no `.js`), through convert -> compile -> engine with
//! the bundled uBO resource library: the scriptlet code must end up in the injected bundle.

use filter_engine::{
    compile_lists, convert, merge_resources_json, ConvertOptions, ListFormat, SharedEngine,
    BUNDLED_REDIRECTS_JSON, BUNDLED_RESOURCES_JSON,
};

#[test]
fn raw_list_rules_resolve_end_to_end_with_the_bundled_library() {
    let json = merge_resources_json(BUNDLED_RESOURCES_JSON, BUNDLED_REDIRECTS_JSON).unwrap();
    let cases = [
        (
            "a.example##+js(set-constant, foo.bar, true)",
            ListFormat::Ubo,
            "function setConstant",
        ),
        (
            "a.example##+js(aopr, foo.bar)",
            ListFormat::Ubo,
            "function abortOnPropertyRead",
        ),
        (
            "a.example#%#//scriptlet('abort-on-property-read', 'foo.bar')",
            ListFormat::Adguard,
            "function abortOnPropertyRead",
        ),
        (
            "a.example#%#//scriptlet('prevent-setTimeout', 'ads', '500')",
            ListFormat::Adguard,
            "function preventSetTimeout",
        ),
        (
            "a.example#%#//scriptlet('remove-cookie', 'x')",
            ListFormat::Adguard,
            "function removeCookie",
        ),
        (
            "a.example#%#//scriptlet('ubo-aopr.js', 'foo.bar')",
            ListFormat::Adguard,
            "function abortOnPropertyRead",
        ),
        (
            "a.example#%#//scriptlet('json-prune-fetch-response', 'a')",
            ListFormat::Adguard,
            "function jsonPruneFetchResponse",
        ),
    ];
    for (rule, format, marker) in cases {
        let c = convert(
            &format!("{rule}\n"),
            &ConvertOptions {
                format,
                ..Default::default()
            },
        );
        let engine = SharedEngine::new();
        engine.set_resources_from_json(&json).unwrap();
        engine.install(compile_lists(&[&c.rules]).blob);
        let js = engine.cosmetic_for("https://a.example/").injected_script;
        assert!(js.contains(marker), "{rule} -> {:?}: {js}", c.rules);
    }
    // Generic forms take the extended route and resolve from the same library.
    let engine = SharedEngine::new();
    engine.set_resources_from_json(&json).unwrap();
    for (name, marker) in [
        ("set-constant", "function setConstant"),
        ("no-setTimeout-if", "function preventSetTimeout"),
    ] {
        let js = engine
            .scriptlet_script(name, &["a".into(), "b".into()], false)
            .unwrap_or_else(|| panic!("{name}"));
        assert!(js.contains(marker), "{name}");
    }
}

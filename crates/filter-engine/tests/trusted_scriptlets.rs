//! Scriptlets registered with `requiresTrust` only inject for rules of a trusted list.

use filter_engine::{build_set, convert_ubo_sources, ListFormat, ListInput, SharedEngine};

const SRC: &str = r#"
import { registerScriptlet } from './base.js';
export function plain(a = {}) { return `${a}}`; }
registerScriptlet(plain, { name: 'plain.js' });
export function trustedOnly(a = {}) { return `${a}}`; }
registerScriptlet(trustedOnly, { name: 'trusted-only.js', requiresTrust: true });
"#;

fn script(trusted: bool, rule: &str) -> String {
    let e = SharedEngine::new();
    let json = serde_json::to_string(&convert_ubo_sources(&[SRC]).resources).unwrap();
    assert_eq!(e.set_resources_from_json(&json).unwrap(), 2);
    let built = build_set(&[ListInput {
        id: "l".into(),
        content: format!("{rule}\n"),
        format: ListFormat::Abp,
        allowlist: false,
        trusted,
        includes: Default::default(),
    }]);
    built.install_into(&e);
    e.cosmetic_for("https://site.test/").injected_script
}

#[test]
fn requires_trust_scriptlet_needs_a_trusted_list() {
    let rule = "site.test##+js(trusted-only, x)";
    assert_eq!(script(false, rule), "", "untrusted list must not inject it");
    assert!(script(true, rule).contains("trustedOnly("));
}

#[test]
fn ordinary_scriptlets_work_from_any_list() {
    let rule = "site.test##+js(plain, x)";
    assert!(script(false, rule).contains("plain("));
    assert!(script(true, rule).contains("plain("));
}

/// The bundled uBO resources: trusted scriptlets compile into the engine and the injected bundle
/// for a trusted list only.
#[cfg(feature = "bundled-ubo-resources")]
mod bundled {
    use super::*;

    fn bundled_script(trusted: bool, rule: &str) -> String {
        let e = SharedEngine::new();
        assert!(
            e.set_resources_from_json(filter_engine::BUNDLED_RESOURCES_JSON)
                .unwrap()
                > 50
        );
        build_set(&[ListInput {
            id: "ubo".into(),
            content: format!("{rule}\n"),
            format: ListFormat::Ubo,
            allowlist: false,
            trusted,
            includes: Default::default(),
        }])
        .install_into(&e);
        e.cosmetic_for("https://site.test/").injected_script
    }

    #[test]
    fn bundled_trusted_scriptlets_inject_only_for_trusted_lists() {
        for rule in [
            "site.test##+js(trusted-replace-fetch-response, /\"a\"/, \"b\", , /x/)",
            "site.test##+js(rpnt, script, /a/, b)",
            "site.test##+js(trusted-replace-node-text, script, /a/, b)",
        ] {
            assert_eq!(bundled_script(false, rule), "", "untrusted: {rule}");
            assert!(!bundled_script(true, rule).is_empty(), "trusted: {rule}");
        }
    }
}

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

// ---- bundled uBO redirect resources ---------------------------------------------------------------

#[cfg(feature = "bundled-ubo-resources")]
mod redirects {
    use base64::Engine as _;
    use filter_engine::{
        build_set_checked, known_redirect_names, merge_resources_json, ListFormat, ListInput,
        SharedEngine, ADGUARD_REDIRECT_ALIASES, BUNDLED_REDIRECTS_JSON, BUNDLED_RESOURCES_JSON,
    };

    fn bundled() -> Vec<adblock::resources::Resource> {
        serde_json::from_str(BUNDLED_REDIRECTS_JSON).unwrap()
    }

    fn engine_with(rules: &[&str]) -> SharedEngine {
        let e = SharedEngine::new();
        let json = merge_resources_json(BUNDLED_RESOURCES_JSON, BUNDLED_REDIRECTS_JSON).unwrap();
        e.set_resources_from_json(&json).unwrap();
        let text = rules.join("\n") + "\n";
        build_set_checked(
            &[ListInput {
                id: "l".into(),
                content: text,
                format: ListFormat::Abp,
                allowlist: false,
                trusted: false,
                includes: Default::default(),
            }],
            None,
        )
        .install_into(&e);
        e
    }

    #[test]
    fn every_ubo_name_alias_and_adguard_name_resolves() {
        let all = bundled();
        assert!(all.len() >= 49, "{}", all.len());
        let e = SharedEngine::new();
        let json = merge_resources_json(BUNDLED_RESOURCES_JSON, BUNDLED_REDIRECTS_JSON).unwrap();
        e.set_resources_from_json(&json).unwrap();
        assert!(e.resource_report().dropped.is_empty());
        let known = known_redirect_names(&e.resources());
        for r in &all {
            assert!(known.contains(&r.name), "{}", r.name);
            for a in &r.aliases {
                assert!(known.contains(a), "{a}");
            }
        }
        for (ag, _) in ADGUARD_REDIRECT_ALIASES {
            assert!(known.contains(*ag), "AdGuard name {ag}");
        }
        for n in [
            "googlesyndication_adsbygoogle.js",
            "google-ima.js",
            "googletagservices_gpt.js",
            "googletagmanager_gtm.js",
            "google-analytics_analytics.js",
            "google-analytics_ga.js",
            "amazon_apstag.js",
            "fingerprint2.js",
            "fingerprint3.js",
            "google-ima-dai.js",
            "google-ima3-dai",
            "nobab2.js",
            "nofab.js",
            "popads.js",
            "prebid-ads.js",
            "adthrive_abd.js",
            "ampproject_v0.js",
            "noop-vast2.xml",
            "noop-vast3.xml",
            "noop-vast4.xml",
            "noop-vmap1.xml",
            "noopmp3-0.1s",
            "noopmp4-1s",
            "1x1.gif",
            "2x2.png",
            "3x2.png",
            "32x32.png",
            "noop.html",
            "noop.txt",
            "noop.css",
            "noop.js",
            "noop-0.1s.mp3",
            "empty",
            "click2load.html",
            "googlesyndication-adsbygoogle",
            "noopjs",
            "nooptext",
            "noopvast-2.0",
        ] {
            assert!(known.contains(n), "{n}");
        }
    }

    #[test]
    fn adsbygoogle_redirect_serves_the_neutered_script() {
        let e = engine_with(&[
            "||pagead2.googlesyndication.com/pagead/js/adsbygoogle.js$script,redirect=googlesyndication_adsbygoogle.js",
        ]);
        let r = e.check(
            "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js",
            "https://site.test/",
            "script",
        );
        assert!(r.blocked);
        let res = r.redirect_resource().expect("redirect resource");
        assert_eq!(res.mime, "application/javascript");
        let body = String::from_utf8(res.body).unwrap();
        assert!(body.contains("adsbygoogle"), "{body}");
    }

    #[test]
    fn adguard_name_and_redirect_rule_work() {
        let e = engine_with(&[
            "||ads.test/a.js$script,redirect=googlesyndication-adsbygoogle",
            "||b.test^$script",
            "||b.test^$redirect-rule=noopjs",
        ]);
        let r = e.check("https://ads.test/a.js", "https://site.test/", "script");
        assert!(r.redirect_resource().is_some());
        let r = e.check("https://b.test/x.js", "https://site.test/", "script");
        assert_eq!(
            r.redirect_resource().unwrap().mime,
            "application/javascript"
        );
        // redirect-rule alone never blocks.
        let r = e.check("https://b.test/x.png", "https://site.test/", "image");
        assert!(!r.blocked);
    }

    #[test]
    fn binary_resources_decode_to_real_files() {
        let e = engine_with(&[
            "||a.test/p.gif$redirect=1x1.gif",
            "||a.test/q.png$redirect=32x32-transparent.png",
            "||a.test/s.mp3$redirect=noopmp3-0.1s",
            "||a.test/v.mp4$redirect=noopmp4-1s",
        ]);
        let get = |u: &str| {
            e.check(u, "https://site.test/", "image")
                .redirect_resource()
                .unwrap_or_else(|| panic!("{u}"))
        };
        let gif = get("https://a.test/p.gif");
        assert_eq!(
            (gif.mime.as_str(), &gif.body[..4]),
            ("image/gif", &b"GIF8"[..])
        );
        let png = get("https://a.test/q.png");
        assert_eq!(&png.body[1..4], b"PNG");
        let mp3 = get("https://a.test/s.mp3");
        assert_eq!(mp3.mime, "audio/mp3");
        assert!(!mp3.body.is_empty());
        let mp4 = get("https://a.test/v.mp4");
        assert_eq!(
            (mp4.mime.as_str(), &mp4.body[4..8]),
            ("video/mp4", &b"ftyp"[..])
        );
        // The resource file itself is base64 in the JSON and decodes.
        for r in bundled() {
            base64::engine::general_purpose::STANDARD
                .decode(&r.content)
                .unwrap_or_else(|_| panic!("{}", r.name));
        }
    }

    #[test]
    fn a_redirect_never_resolves_to_a_scriptlet_alias() {
        let e = engine_with(&["||a.test/x.js$script,redirect=nobab.js"]);
        let r = e.check("https://a.test/x.js", "https://site.test/", "script");
        assert!(r.blocked && r.redirect_resource().is_none(), "{r:?}");
        let known = known_redirect_names(&e.resources());
        assert!(!known.contains("nobab.js") && !known.contains("prevent-bab.js"));
        assert!(known.contains("nobab2.js"));
    }

    #[test]
    fn trusted_dai_redirect_is_served() {
        let e = engine_with(&["||a.test/dai.js$script,redirect=google-ima3-dai"]);
        let r = e.check("https://a.test/dai.js", "https://site.test/", "script");
        assert!(r.redirect_resource().is_some(), "{r:?}");
    }

    #[test]
    fn redirect_to_a_missing_resource_is_counted() {
        let e = SharedEngine::new();
        let json = merge_resources_json(BUNDLED_RESOURCES_JSON, BUNDLED_REDIRECTS_JSON).unwrap();
        e.set_resources_from_json(&json).unwrap();
        let known = known_redirect_names(&e.resources());
        let built = build_set_checked(
            &[ListInput {
                id: "l".into(),
                content: "||a.test^$script,redirect=no-such-resource.js\n||b.test^$redirect-rule=nope:10\n||c.test^$script,redirect=noop.js:5\n@@||d.test^$redirect=none\n".into(),
                format: ListFormat::Abp,
                allowlist: false,
                trusted: false,
                includes: Default::default(),
            }],
            Some(&known),
        );
        assert_eq!(built.reports[0].redirect_missing, 2);
        assert_eq!(
            built.reports[0].redirect_missing_names,
            ["no-such-resource.js", "nope"]
        );
    }
}

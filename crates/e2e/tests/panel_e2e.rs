//! The in-page panel's server side: the reserved confirmation host, the read-only state endpoint
//! and the authority rules (a page must not be able to change anything).

use std::sync::Arc;

use e2e::{e2e_test, MockResponse, TestClient, TestEnv};
use proxy_core::panel::{encode_proposal, PanelOp, Ttl};
use script_policy::panel::{hash_pin, PanelAuth, PanelSettings};
use script_policy::store::PolicyStore;
use script_policy::{Preset, Scope, DEFAULT_PROFILE as P};
use serde_json::{json, Value};

const PANEL_HOST: &str = "adblock.invalid";
const PIN: &str = "471100";
const PAGE: &str = "<!doctype html><html><head><title>t</title></head><body>hi</body></html>";

fn setup(env: &TestEnv, auth: PanelAuth) -> Arc<PolicyStore> {
    let (store, control) = env.proxy.script_control();
    store
        .set_panel_settings(
            P,
            &PanelSettings {
                enabled: true,
                auth,
                pin_hash: Some(hash_pin(PIN).unwrap()),
                ..Default::default()
            },
        )
        .unwrap();
    control.refresh();
    store
}

fn panel_origin(env: &TestEnv) -> String {
    env.origin
        .https_url(PANEL_HOST, "/")
        .trim_end_matches('/')
        .to_string()
}

fn proposal() -> String {
    encode_proposal(&[PanelOp::Preset {
        page: "app.test".into(),
        preset: "untrusted".into(),
    }])
}

async fn confirm(env: &TestEnv, c: &TestClient, p: &str) -> (u16, String) {
    let r = c
        .request(
            reqwest::Method::GET,
            &env.origin.https_url(PANEL_HOST, &format!("/confirm?p={p}")),
        )
        .header("sec-fetch-dest", "document")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-site", "cross-site")
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

fn field(html: &str, name: &str) -> String {
    let k = format!("name=\"{name}\" value=\"");
    let i = html.find(&k).unwrap_or_else(|| panic!("{name} in {html}")) + k.len();
    html[i..i + html[i..].find('"').unwrap()].to_string()
}

#[allow(clippy::too_many_arguments)]
async fn apply(
    env: &TestEnv,
    c: &TestClient,
    p: &str,
    n: &str,
    pin: &str,
    site: &str,
    origin: Option<&str>,
    user: bool,
) -> u16 {
    let mut rb = c
        .request(
            reqwest::Method::POST,
            &env.origin.https_url(PANEL_HOST, "/apply"),
        )
        .header("content-type", "application/x-www-form-urlencoded")
        .header("sec-fetch-dest", "document")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-site", site)
        .body(format!("p={p}&n={n}&pin={pin}"));
    if user {
        rb = rb.header("sec-fetch-user", "?1");
    }
    if let Some(o) = origin {
        rb = rb.header("origin", o);
    }
    rb.send().await.unwrap().status().as_u16()
}

fn preset_of(store: &PolicyStore) -> Option<Preset> {
    store
        .rules(P)
        .unwrap()
        .site_rule_for_scope(&Scope::parse("app.test").unwrap())
        .map(|r| r.preset)
}

e2e_test!(
    reserved_host_is_answered_locally_never_forwarded_or_filtered,
    rules = ["||adblock.invalid^"],
    |env| {
        setup(&env, PanelAuth::Pin);
        let c = env.client();
        for path in ["/", "/confirm?p=x", "/anything"] {
            let r = c
                .request(
                    reqwest::Method::GET,
                    &env.origin.https_url(PANEL_HOST, path),
                )
                .header("sec-fetch-dest", "document")
                .send()
                .await
                .unwrap();
            assert_ne!(
                r.headers().get("x-adblock").map(|v| v.to_str().unwrap()),
                Some("blocked"),
                "filter rules never apply to it"
            );
            assert!(r.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'"));
            assert_eq!(r.headers()["x-frame-options"], "DENY");
        }
        assert!(
            env.origin.requests().is_empty(),
            "nothing reached the origin: {:?}",
            env.origin.requests().len()
        );
        // Plain HTTP too.
        let r = c
            .request(reqwest::Method::GET, &env.origin.http_url(PANEL_HOST, "/"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert!(env.origin.requests().is_empty());
        // ... but never the confirmation form or /apply: a PIN must not cross the LAN in clear.
        let q = proposal();
        let r = c
            .request(
                reqwest::Method::GET,
                &env.origin.http_url(PANEL_HOST, &format!("/confirm?p={q}")),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        let body = r.text().await.unwrap();
        assert!(
            !body.contains("<form") && !body.contains("name=\"pin\""),
            "{body}"
        );
        let r = c
            .request(
                reqwest::Method::POST,
                &env.origin.http_url(PANEL_HOST, "/apply"),
            )
            .header("content-type", "application/x-www-form-urlencoded")
            .body("p=x&n=y&pin=z")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
    }
);

e2e_test!(confirm_and_apply_with_the_pin, rules = [], |env| {
    let store = setup(&env, PanelAuth::Pin);
    let c = env.client();
    let p = proposal();
    let (st, html) = confirm(&env, &c, &p).await;
    assert_eq!(st, 200);
    assert!(
        html.contains("Pages of app.test use the untrusted preset"),
        "{html}"
    );
    let n = field(&html, "n");
    let o = panel_origin(&env);
    assert_eq!(
        apply(&env, &c, &p, &n, "0000", "same-origin", Some(&o), true).await,
        403,
        "wrong pin"
    );
    assert!(preset_of(&store).is_none());
    assert_eq!(
        apply(&env, &c, &p, &n, PIN, "same-origin", Some(&o), true).await,
        200
    );
    assert_eq!(preset_of(&store), Some(Preset::Untrusted));
});

e2e_test!(an_apply_nonce_is_single_use, rules = [], |env| {
    let store = setup(&env, PanelAuth::None);
    let c = env.client();
    let p = proposal();
    let n = field(&confirm(&env, &c, &p).await.1, "n");
    let o = panel_origin(&env);
    assert_eq!(
        apply(&env, &c, &p, &n, "", "same-origin", Some(&o), true).await,
        200
    );
    assert_eq!(preset_of(&store), Some(Preset::Untrusted));
    let id = store
        .rules(P)
        .unwrap()
        .site_rule_for_scope(&Scope::parse("app.test").unwrap())
        .map(|r| r.id.clone())
        .unwrap();
    store.delete_site_rule(P, &id).unwrap();
    assert_eq!(
        apply(&env, &c, &p, &n, "", "same-origin", Some(&o), true).await,
        403,
        "a replayed confirmation must be refused"
    );
    assert!(preset_of(&store).is_none(), "replay must not re-apply");
});

e2e_test!(a_page_cannot_apply_or_forge_a_change, rules = [], |env| {
    let store = setup(&env, PanelAuth::None);
    let c = env.client();
    let p = proposal();
    let (_, html) = confirm(&env, &c, &p).await;
    let n = field(&html, "n");
    let o = panel_origin(&env);
    // Everything a hostile page can send (cross-site fetch or form post), even with the right
    // nonce and PIN: no.
    assert_eq!(
        apply(
            &env,
            &c,
            &p,
            &n,
            PIN,
            "cross-site",
            Some("https://app.test"),
            false
        )
        .await,
        403
    );
    assert_eq!(
        apply(&env, &c, &p, &n, PIN, "cross-site", Some(&o), true).await,
        403,
        "site header"
    );
    assert_eq!(
        apply(
            &env,
            &c,
            &p,
            &n,
            PIN,
            "same-origin",
            Some("https://app.test"),
            true
        )
        .await,
        403,
        "origin header"
    );
    assert_eq!(
        apply(&env, &c, &p, &n, PIN, "same-origin", None, true).await,
        403,
        "no origin"
    );
    assert_eq!(
        apply(&env, &c, &p, &n, PIN, "same-origin", Some(&o), false).await,
        403,
        "no user activation"
    );
    // Forged nonce, swapped proposal, missing nonce.
    let other = encode_proposal(&[PanelOp::RevokeTemps]);
    assert_eq!(
        apply(&env, &c, &other, &n, PIN, "same-origin", Some(&o), true).await,
        403,
        "nonce is bound to the proposal"
    );
    assert_eq!(
        apply(
            &env,
            &c,
            &p,
            "ffffffffff.AAAA",
            PIN,
            "same-origin",
            Some(&o),
            true
        )
        .await,
        403
    );
    assert_eq!(
        apply(&env, &c, &p, "", PIN, "same-origin", Some(&o), true).await,
        403
    );
    assert!(preset_of(&store).is_none(), "nothing changed");
    // Not a top-level navigation: refused to render at all.
    for dest in ["iframe", "empty", "script"] {
        let r = c
            .request(
                reqwest::Method::GET,
                &env.origin.https_url(PANEL_HOST, &format!("/confirm?p={p}")),
            )
            .header("sec-fetch-dest", dest)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "{dest}");
    }
    // And the legitimate click still works.
    assert_eq!(
        apply(&env, &c, &p, &n, "", "same-origin", Some(&o), true).await,
        200
    );
    assert_eq!(preset_of(&store), Some(Preset::Untrusted));
});

e2e_test!(
    wrong_pins_lock_out_and_session_mode_never_applies,
    rules = [],
    |env| {
        let store = setup(&env, PanelAuth::Pin);
        let c = env.client();
        let p = proposal();
        let n = field(&confirm(&env, &c, &p).await.1, "n");
        let o = panel_origin(&env);
        for _ in 0..5 {
            assert_eq!(
                apply(&env, &c, &p, &n, "1", "same-origin", Some(&o), true).await,
                403
            );
        }
        assert_eq!(
            apply(&env, &c, &p, &n, PIN, "same-origin", Some(&o), true).await,
            429,
            "locked even for the right pin"
        );
        assert!(preset_of(&store).is_none());
        // Session mode: the confirmation page has no form and /apply refuses.
        let (_, control) = env.proxy.script_control();
        store
            .set_panel_settings(
                P,
                &PanelSettings {
                    enabled: true,
                    auth: PanelAuth::Session,
                    ..Default::default()
                },
            )
            .unwrap();
        control.refresh();
        let (_, html) = confirm(&env, &c, &p).await;
        assert!(!html.contains("<form"), "{html}");
    }
);

e2e_test!(proposal_ops_are_validated_server_side, rules = [], |env| {
    let store = setup(&env, PanelAuth::None);
    let c = env.client();
    let o = panel_origin(&env);
    let bad = encode_proposal(&[
        PanelOp::Preset {
            page: "*".into(),
            preset: "trusted".into(),
        },
        PanelOp::Source {
            page: "app.test".into(),
            source: "cdn.test".into(),
            caps: vec!["inline-script".into()],
            allow: true,
            ttl: Ttl::Hour1,
        },
        PanelOp::Adblock {
            site: "a.test\n||x^".into(),
            enabled: false,
        },
    ]);
    let n = field(&confirm(&env, &c, &bad).await.1, "n");
    let r = c
        .request(
            reqwest::Method::POST,
            &env.origin.https_url(PANEL_HOST, "/apply"),
        )
        .header("content-type", "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .header("origin", &o)
        .header("sec-fetch-user", "?1")
        .header("sec-fetch-dest", "document")
        .body(format!("p={bad}&n={n}"))
        .send()
        .await
        .unwrap();
    let body = r.text().await.unwrap();
    assert_eq!(body.matches("<b>failed:</b>").count(), 3, "{body}");
    assert!(store.rules(P).unwrap().site_rules.is_empty());
});

fn token_in(html: &str) -> String {
    let i = html.find("\"t\":\"").expect("token in config") + 5;
    html[i..i + html[i..].find('"').unwrap()].to_string()
}

async fn state(
    env: &TestEnv,
    c: &TestClient,
    host: &str,
    token: &str,
    url: &str,
    extra: &[(&str, &str)],
) -> (u16, Value) {
    let mut rb = c
        .request(
            reqwest::Method::POST,
            &env.origin.https_url(host, "/__adblock__/panel/state"),
        )
        .header("content-type", "application/json")
        .header("x-adblock-token", token)
        .body(json!({ "url": url }).to_string());
    if !extra.iter().any(|(k, _)| *k == "sec-fetch-site") {
        rb = rb.header("sec-fetch-site", "same-origin");
    }
    for (k, v) in extra {
        rb = rb.header(*k, *v);
    }
    let r = rb.send().await.unwrap();
    let st = r.status().as_u16();
    (st, r.json().await.unwrap_or(Value::Null))
}

e2e_test!(
    panel_is_injected_only_when_on_and_state_is_token_bound,
    rules = ["app.test##.ad"],
    |env| {
        let (store, control) = env.proxy.script_control();
        env.origin.route("/p", MockResponse::html(PAGE));
        let c = env.client();
        let get = |host: &'static str| {
            let (env, c) = (&env, &c);
            async move {
                c.request(reqwest::Method::GET, &env.origin.https_url(host, "/p"))
                    .header("sec-fetch-dest", "document")
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap()
            }
        };
        let off = get("app.test").await;
        assert!(!off.contains("\"pn\""), "off by default: {off}");
        setup(&env, PanelAuth::Pin);
        let on = get("app.test").await;
        assert!(on.contains("\"k\":[1,0,1,0,\"KeyA\"]"), "{on}");
        assert!(on.contains("/__adblock__/panel."), "{on}");
        // The panel script itself is fetched lazily: immutable and static.
        let path = on[on.find("/__adblock__/panel.").unwrap()..]
            .split('"')
            .next()
            .unwrap()
            .to_string();
        let js = c
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("app.test", &path),
            )
            .header("sec-fetch-site", "same-origin")
            .send()
            .await
            .unwrap();
        assert_eq!(js.status(), 200);
        assert!(js.headers()["cache-control"]
            .to_str()
            .unwrap()
            .contains("immutable"));
        assert!(js.text().await.unwrap().contains("attachShadow"));
        assert!(env.origin.requests_for(&path).is_empty());

        // State: token and host binding, JSON only, same-origin only.
        let token = token_in(&on);
        let url = env.origin.https_url("app.test", "/p");
        let (st, v) = state(&env, &c, "app.test", &token, &url, &[]).await;
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["site"], "app.test");
        assert_eq!(v["preset"], "default");
        assert_eq!(v["auth"], "pin");
        assert!(v.get("pin_hash").is_none() && !v.to_string().contains("pin_hash"));
        assert_eq!(state(&env, &c, "app.test", "bad", &url, &[]).await.0, 403);
        assert_eq!(
            state(
                &env,
                &c,
                "other.test",
                &token,
                &env.origin.https_url("other.test", "/"),
                &[]
            )
            .await
            .0,
            403,
            "token is bound to its host"
        );
        assert_eq!(
            state(
                &env,
                &c,
                "app.test",
                &token,
                &env.origin.https_url("other.test", "/"),
                &[]
            )
            .await
            .0,
            403,
            "cannot ask about another host"
        );
        assert_eq!(
            state(
                &env,
                &c,
                "app.test",
                &token,
                &url,
                &[("sec-fetch-site", "cross-site")]
            )
            .await
            .0,
            403
        );
        // Per-profile switch.
        store
            .set_panel_settings(
                P,
                &PanelSettings {
                    enabled: false,
                    ..Default::default()
                },
            )
            .unwrap();
        control.refresh();
        assert!(!get("app.test").await.contains("\"pn\""));
    }
);

//! Per-device profiles through the real proxy: devices are told apart by token (explicit mode)
//! or by source address (`127.0.0.N`, both modes), and every profile edit, device reassignment,
//! rename and delete reaches open connections and stored data correctly.

use base64::Engine as _;
use e2e::{e2e_test, ClientOpts, EntryMode, HttpVersion, MockResponse, TestClient, TestEnv};
use serde_json::{json, Value};

const PAGE: &str = "<!doctype html><html><head><title>t</title></head><body>hi</body></html>";

/// Request `https://host/path` as a navigation; the status (403 when blocked).
async fn status(env: &TestEnv, c: &TestClient, host: &str, path: &str) -> u16 {
    env.origin.route(path, MockResponse::html(PAGE));
    c.request(reqwest::Method::GET, &env.origin.https_url(host, path))
        .header("sec-fetch-dest", "document")
        .header("accept", "text/html")
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {host}{path}: {e:?}"))
        .status()
        .as_u16()
}

fn as_ip(env: &TestEnv, ip: &str) -> TestClient {
    env.client_as(&ClientOpts::source(ip))
}

fn script(name: &str) -> String {
    format!(
        "// ==UserScript==\n// @name {name}\n// @namespace e2e\n// @version 1.0\n// @match *://app.test/*\n// @run-at document-start\n// @grant GM_getValue\n// @grant GM_setValue\n// ==/UserScript==\nwindow.__{name} = 1;\n"
    )
}

// ---- the API and the proxy share one set of stores -------------------------------------------

e2e_test!(
    api_created_profile_and_device_drive_proxy_blocking,
    rules = [],
    explicit_only,
    |env| {
        let api = env.proxy.api().await;
        let p = api
            .create("/profiles", json!({"name": "kids", "rules": "||ads.test^"}))
            .await;
        let d = api
            .create(
                "/devices",
                json!({"name": "tablet", "profile_id": p["id"], "ips": []}),
            )
            .await;
        let did = d["id"].as_str().unwrap();
        assert!(d["last_seen"].is_null());
        let tok = api
            .create(&format!("/devices/{did}/token"), json!({}))
            .await["token"]
            .as_str()
            .unwrap()
            .to_string();
        env.proxy.profiles().sync().await;

        let kid = env.client_as(&ClientOpts::token(&tok));
        assert_eq!(status(&env, &kid, "ads.test", "/a").await, 403);
        assert_eq!(status(&env, &kid, "ok.test", "/a").await, 200);
        assert_eq!(status(&env, &env.client(), "ads.test", "/a").await, 200);

        // Build status and activity are reported by the proxy.
        let prof: Value = api
            .get(&format!("/profiles/{}", p["id"].as_str().unwrap()))
            .await
            .json();
        assert!(prof["last_built"].is_string(), "{prof}");
        assert!(prof["last_error"].is_null(), "{prof}");
        let dev: Value = api.get(&format!("/devices/{did}")).await.json();
        assert!(dev["last_seen"].is_string(), "{dev}");
    }
);

e2e_test!(
    failed_profile_build_is_reported_with_its_error,
    rules = [],
    |env| {
        let api = env.proxy.api().await;
        let h = env.proxy.profiles();
        let id = h.profile("broken", "");
        let mut rec = h.store.get(id).unwrap().unwrap();
        rec.lists = vec!["no-such-list".into()];
        h.store.put(rec).unwrap();
        h.sync().await;
        let prof: Value = api.get(&format!("/profiles/{id}")).await.json();
        assert!(
            prof["last_error"]
                .as_str()
                .unwrap_or("")
                .contains("no-such-list"),
            "{prof}"
        );
    }
);

// ---- two devices, two behaviours ---------------------------------------------------------------

e2e_test!(
    devices_are_told_apart_by_source_address,
    rules = [],
    |env| {
        let h = env.proxy.profiles();
        let (a, b) = (
            h.profile("alpha", "||ads.test^"),
            h.profile("beta", "||trk.test^"),
        );
        h.device("da", a, &["127.0.0.11"]);
        h.device("db", b, &["127.0.0.12"]);
        h.sync().await;
        let (ca, cb) = (as_ip(&env, "127.0.0.11"), as_ip(&env, "127.0.0.12"));
        assert_eq!(status(&env, &ca, "ads.test", "/x").await, 403);
        assert_eq!(status(&env, &ca, "trk.test", "/x").await, 200);
        assert_eq!(status(&env, &cb, "ads.test", "/x").await, 200);
        assert_eq!(status(&env, &cb, "trk.test", "/x").await, 403);
        // An unknown address is the default profile.
        let other = as_ip(&env, "127.0.0.13");
        assert_eq!(status(&env, &other, "ads.test", "/x").await, 200);
        assert_eq!(status(&env, &other, "trk.test", "/x").await, 200);
    }
);

e2e_test!(
    devices_are_told_apart_by_token,
    rules = [],
    explicit_only,
    |env| {
        let h = env.proxy.profiles();
        let (a, b) = (
            h.profile("alpha", "||ads.test^"),
            h.profile("beta", "||trk.test^"),
        );
        let (ta, tb) = (
            h.token(h.device("da", a, &[])),
            h.token(h.device("db", b, &[])),
        );
        h.sync().await;
        let (ca, cb) = (
            env.client_as(&ClientOpts::token(&ta)),
            env.client_as(&ClientOpts::token(&tb)),
        );
        assert_eq!(status(&env, &ca, "ads.test", "/x").await, 403);
        assert_eq!(status(&env, &ca, "trk.test", "/x").await, 200);
        assert_eq!(status(&env, &cb, "ads.test", "/x").await, 200);
        assert_eq!(status(&env, &cb, "trk.test", "/x").await, 403);
        // A token beats the source address.
        let by_both = env.client_as(&ClientOpts {
            token: Some(ta.clone()),
            source: Some("127.0.0.14".parse().unwrap()),
        });
        assert_eq!(status(&env, &by_both, "ads.test", "/x").await, 403);
    }
);

// ---- GM storage ------------------------------------------------------------------------------

fn srcs(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find("/__adblock__/us/") {
        let tail = &rest[i..];
        let end = tail.find('"').expect("quote");
        out.push(tail[..end].to_string());
        rest = &tail[end..];
    }
    out
}

/// The GM token of the first script injected into `app.test/gm`.
async fn gm_token(env: &TestEnv, c: &TestClient) -> String {
    env.origin.route("/gm", MockResponse::html(PAGE));
    let html = c
        .request(
            reqwest::Method::GET,
            &env.origin.https_url("app.test", "/gm"),
        )
        .header("sec-fetch-dest", "document")
        .header("accept", "text/html")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let src = srcs(&html)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("no bundle: {html}"));
    let js = c
        .request(
            reqwest::Method::GET,
            &env.origin.https_url("app.test", &src),
        )
        .header("sec-fetch-site", "same-origin")
        .header("sec-fetch-dest", "script")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let i = js.find("\"token\":\"").expect("token") + 9;
    js[i..i + js[i..].find('"').unwrap()].to_string()
}

async fn gm(env: &TestEnv, c: &TestClient, tok: &str, route: &str, body: Value) -> Value {
    let origin = env.origin.https_url("app.test", "/");
    let r = c
        .request(
            reqwest::Method::POST,
            &env.origin
                .https_url("app.test", &format!("/__adblock__/gm/v1/{route}")),
        )
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .header("origin", origin.trim_end_matches('/'))
        .header("x-gm-token", tok)
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{route}");
    r.json().await.unwrap()
}

e2e_test!(
    gm_values_are_separate_per_device_profile,
    rules = [],
    |env| {
        let h = env.proxy.profiles();
        let (a, b) = (h.profile("alpha", ""), h.profile("beta", ""));
        h.device("da", a, &["127.0.0.21"]);
        h.device("db", b, &["127.0.0.22"]);
        h.sync().await;
        for p in [a, b] {
            env.proxy.install_userscript_in(
                &h.namespace(p),
                &script("gmtest"),
                Default::default(),
                false,
            );
        }
        let (ca, cb) = (as_ip(&env, "127.0.0.21"), as_ip(&env, "127.0.0.22"));
        let (ta, tb) = (gm_token(&env, &ca).await, gm_token(&env, &cb).await);
        gm(
            &env,
            &ca,
            &ta,
            "values/set",
            json!({"values": {"k": "from-a"}}),
        )
        .await;
        let got_b = gm(&env, &cb, &tb, "values/get", json!({"names": ["k"]})).await;
        assert!(
            got_b["result"]["k"].is_null() && got_b["ok"] == true,
            "{got_b}"
        );
        gm(
            &env,
            &cb,
            &tb,
            "values/set",
            json!({"values": {"k": "from-b"}}),
        )
        .await;
        let got_a = gm(&env, &ca, &ta, "values/get", json!({"names": ["k"]})).await;
        assert_eq!(got_a["result"]["k"], "from-a", "{got_a}");
        let got_b = gm(&env, &cb, &tb, "values/get", json!({"names": ["k"]})).await;
        assert_eq!(got_b["result"]["k"], "from-b", "{got_b}");
        // Stored under each profile's own namespace.
        assert_eq!(h.manager.get_all_in(&h.namespace(a)).len(), 1);
        assert_eq!(h.manager.get_all_in(&h.namespace(b)).len(), 1);
    }
);

// ---- edits reach open connections --------------------------------------------------------------

e2e_test!(
    rule_edit_applies_on_open_keepalive_and_h2_connections,
    rules = [],
    |env| {
        let h = env.proxy.profiles();
        for (i, v) in [HttpVersion::Http1, HttpVersion::Http2]
            .into_iter()
            .enumerate()
        {
            let ip = format!("127.0.0.{}", 31 + i);
            let p = h.profile(&format!("live{i}"), "");
            h.device(&format!("d{i}"), p, &[&ip]);
            h.sync().await;
            let c = env.client_as_with(v, &ClientOpts::source(&ip));
            assert_eq!(
                status(&env, &c, "page.test", "/blockme").await,
                200,
                "{v:?}"
            );
            let mut rec = h.store.get(p).unwrap().unwrap();
            rec.rules = "/blockme$document".into();
            h.store.put(rec).unwrap();
            h.sync().await;
            // Same client, so the same pooled connection (one h2 connection, or the h1 one).
            assert_eq!(
                status(&env, &c, "page.test", "/blockme").await,
                403,
                "{v:?}"
            );
            let mut rec = h.store.get(p).unwrap().unwrap();
            rec.rules = String::new();
            h.store.put(rec).unwrap();
            h.sync().await;
            assert_eq!(
                status(&env, &c, "page.test", "/blockme").await,
                200,
                "{v:?}"
            );
        }
    }
);

e2e_test!(
    reassigning_a_device_applies_on_the_next_request_of_an_open_connection,
    rules = [],
    |env| {
        let h = env.proxy.profiles();
        let strict = h.profile("strict", "/blockme$document");
        let lax = h.profile("lax", "");
        let d = h.device("d", strict, &["127.0.0.41"]);
        h.sync().await;
        let c = as_ip(&env, "127.0.0.41");
        assert_eq!(status(&env, &c, "page.test", "/blockme").await, 403);
        let mut rec = h.store.device(d).unwrap().unwrap();
        rec.profile_id = lax;
        h.store.put_device(rec).unwrap();
        h.sync().await;
        assert_eq!(status(&env, &c, "page.test", "/blockme").await, 200);
        let mut rec = h.store.device(d).unwrap().unwrap();
        rec.profile_id = strict;
        h.store.put_device(rec).unwrap();
        h.sync().await;
        assert_eq!(status(&env, &c, "page.test", "/blockme").await, 403);
    }
);

// ---- tokens in explicit mode -----------------------------------------------------------------------

#[tokio::test]
async fn required_token_gives_407_without_one() {
    let env = TestEnv::start_tweaked(EntryMode::Explicit, &[], &|c| {
        c.proxy.require_device_token = true;
    })
    .await;
    let h = env.proxy.profiles();
    let p = h.profile("p", "/blockme$document");
    let tok = h.token(h.device("d", p, &[]));
    h.sync().await;

    // Plain HTTP through the proxy: a 407 response. HTTPS: the CONNECT is refused.
    let anon = env.client();
    let r = anon
        .request(
            reqwest::Method::GET,
            &env.origin.http_url("page.test", "/x"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 407);
    assert!(anon
        .request(
            reqwest::Method::GET,
            &env.origin.https_url("page.test", "/x")
        )
        .send()
        .await
        .is_err());
    let wrong = env.client_as(&ClientOpts::token("abd_nope"));
    assert_eq!(
        wrong
            .request(
                reqwest::Method::GET,
                &env.origin.http_url("page.test", "/x")
            )
            .send()
            .await
            .unwrap()
            .status(),
        407
    );
    assert!(
        env.origin.requests().is_empty(),
        "nothing reached the origin"
    );

    let ok = env.client_as(&ClientOpts::token(&tok));
    assert_eq!(status(&env, &ok, "page.test", "/blockme").await, 403);
    assert_eq!(status(&env, &ok, "page.test", "/fine").await, 200);
}

#[tokio::test]
async fn proxy_authorization_inside_the_tunnel_does_not_switch_profile() {
    let env = TestEnv::start(EntryMode::Explicit, &[]).await;
    let h = env.proxy.profiles();
    let p = h.profile("p", "/blockme$document");
    let tok = h.token(h.device("d", p, &[]));
    h.sync().await;
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("u:{tok}"))
    );
    env.origin.route("/blockme", MockResponse::html(PAGE));
    let anon = env.client();
    // Default profile on the tunnel: the header inside it is ignored (and not forwarded).
    for _ in 0..2 {
        let r = anon
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("page.test", "/blockme"),
            )
            .header("proxy-authorization", &auth)
            .header("sec-fetch-dest", "document")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }
    assert!(env.origin.requests().iter().all(|r| r
        .headers
        .iter()
        .all(|(k, _)| !k.eq_ignore_ascii_case("proxy-authorization"))));
    // Control: the same token on the CONNECT does select the profile.
    let dev = env.client_as(&ClientOpts::token(&tok));
    assert_eq!(status(&env, &dev, "page.test", "/blockme").await, 403);
}

// ---- delete and rename ----------------------------------------------------------------------------

e2e_test!(
    deleted_profile_falls_back_to_default_and_its_data_is_gone,
    rules = [],
    |env| {
        use script_policy::{Preset, Scope};
        let h = env.proxy.profiles();
        let p = h.profile("doomed", "/blockme$document");
        let d = h.device("d", p, &["127.0.0.51"]);
        h.sync().await;
        let ns = h.namespace(p);
        env.proxy
            .install_userscript_in(&ns, &script("gone"), Default::default(), false);
        h.policy
            .create_site_rule(
                &ns,
                Scope::parse("example.com").unwrap(),
                Preset::Trusted,
                None,
            )
            .unwrap();
        let c = as_ip(&env, "127.0.0.51");
        assert_eq!(status(&env, &c, "page.test", "/blockme").await, 403);

        assert!(h.store.delete(p).is_err(), "in use");
        h.store.delete_device(d).unwrap();
        assert!(h.store.delete(p).unwrap());
        h.sync().await;
        // The old device address now resolves to the default profile.
        assert_eq!(status(&env, &c, "page.test", "/blockme").await, 200);
        assert!(h.manager.get_all_in(&ns).is_empty());
        assert!(h.policy.rules(&ns).unwrap().site_rules.is_empty());

        // The id (so the namespace) is never handed out again.
        let again = h.profile("doomed", "");
        assert_ne!(again, p);
        h.sync().await;
        assert!(h.manager.get_all_in(&h.namespace(again)).is_empty());
    }
);

e2e_test!(rename_keeps_userscripts_and_policy, rules = [], |env| {
    use script_policy::{Preset, Scope};
    let h = env.proxy.profiles();
    let p = h.profile("before", "/blockme$document");
    h.device("d", p, &["127.0.0.61"]);
    h.sync().await;
    let ns = h.namespace(p);
    env.proxy
        .install_userscript_in(&ns, &script("kept"), Default::default(), false);
    h.policy
        .create_site_rule(
            &ns,
            Scope::parse("example.com").unwrap(),
            Preset::Trusted,
            None,
        )
        .unwrap();
    let c = as_ip(&env, "127.0.0.61");
    assert_eq!(status(&env, &c, "page.test", "/blockme").await, 403);

    let mut rec = h.store.get(p).unwrap().unwrap();
    rec.name = "after".into();
    h.store.put(rec).unwrap();
    h.sync().await;
    assert_eq!(h.manager.get_all_in(&ns).len(), 1, "userscripts survive");
    assert_eq!(
        h.policy.rules(&ns).unwrap().site_rules.len(),
        1,
        "policy survives"
    );
    let live = env
        .proxy
        .ctx
        .profiles()
        .table()
        .slot(p)
        .unwrap()
        .load_full();
    assert_eq!(&*live.name, ns.as_str(), "namespace is not the label");
    assert_eq!(&*live.display_name, "after");
    assert_eq!(status(&env, &c, "page.test", "/blockme").await, 403);
    // The injected bundle still comes from the same namespace.
    let t = gm_token(&env, &c).await;
    assert!(t.starts_with("v1."));
});

//! Cookie provenance through the real proxy: a page sets cookies, a rule strips one and changes
//! another, the extension listener binds the browser to a session, and `GET
//! /ext/cookies/provenance` reports names, attributes and effects, never a value.

use api_types::ExtIdent;
use e2e::{e2e_test, MockResponse, TestClient, TestEnv};
use serde_json::Value;
use std::sync::atomic::Ordering;

const V1: &str = "VALUE-sess-9f2c71d0aa";
const V2: &str = "VALUE-gid-5be1c07722";
const V3: &str = "VALUE-ga-0d4e8f31c6";
const V4: &str = "VALUE-host-77aa10be99";
const V5: &str = "VALUE-trk-c3d29e8810";
const V6: &str = "VALUE-keep-1177aa0000";
// A request cookie with no `=`: its whole text is a value and must never be reported as a name.
const V7: &str = "NAMELESS-VALUE-3a91c0de55";
const SECRETS: [&str; 7] = [V1, V2, V3, V4, V5, V6, V7];

const RULES: [&str; 4] = [
    "||cookies.test^$cookie=/^NAMELESS/",
    "||cookies.test^$cookie=_gid",
    "||cookies.test^$cookie=_ga;maxAge=600;sameSite=strict",
    "||cookies.test^$cookie=trk",
];

async fn ext_client(env: &TestEnv, sid: &str) -> TestClient {
    let addr = env.proxy.ext_addr().await;
    TestClient::via_ext(&env.proxy, addr, sid, "")
}

async fn read(api: &e2e::TestApi, sid: &str, q: &str) -> (Value, String) {
    let r = api
        .get(&format!("/ext/cookies/provenance{q}"))
        .add_header("x-argus-session", sid)
        .await;
    assert_eq!(r.status_code(), 200, "{}", r.text());
    let text = r.text();
    (serde_json::from_str(&text).unwrap(), text)
}

fn names(v: &Value) -> Vec<(String, String)> {
    v["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap().to_string(),
                r["effect"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

e2e_test!(
    cookie_provenance_reports_effects_for_an_extension_session_and_never_values,
    rules = RULES,
    explicit_only,
    |env| {
        let api = env.proxy.api().await;
        let handle = env.proxy.ctx.cookie_provenance_handle();
        let hub = env.proxy.ctx.internal().gm.ext().clone();
        let (id, sid, _rx) = hub.open(ExtIdent {
            token_id: api.token_id.clone(),
            user: "u".into(),
            profiles: None,
        });
        let bound = ext_client(&env, &sid).await;
        let plain = env.client();
        let page = "https://cookies.test/page";
        env.origin.route(
            "/page",
            MockResponse::html("<html><body>x</body></html>")
                .header(
                    "set-cookie",
                    &format!("sess={V1}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600"),
                )
                .header("set-cookie", &format!("_gid={V2}; Path=/; Max-Age=86400"))
                .header(
                    "set-cookie",
                    &format!("_ga={V3}; Path=/; Max-Age=31536000; SameSite=None; Secure"),
                )
                .header("set-cookie", &format!("__Host-x=\"{V4}\"; Secure; Path=/")),
        );
        env.origin.route(
            "/api",
            MockResponse::ok("{}").header("set-cookie", &format!("xhr={V6}; Path=/api")),
        );
        env.origin.route(
            "/go",
            MockResponse::new(302, "")
                .header("location", "/page")
                .header("set-cookie", &format!("hop={V6}")),
        );
        env.origin.route(
            "/nm",
            MockResponse::new(304, "").header("set-cookie", &format!("nm={V6}")),
        );
        let get = |c: &TestClient, path: &str, dest: &str| {
            let rb = c
                .request(
                    reqwest::Method::GET,
                    &env.origin.https_url("cookies.test", path),
                )
                .header("sec-fetch-dest", dest)
                .header("referer", page);
            async move { rb.send().await.expect("response") }
        };

        // Off by default: nothing is recorded, and the API says so.
        assert!(!handle.load(Ordering::Relaxed));
        get(&bound, "/page", "document").await;
        let (v, _) = read(&api, &sid, "").await;
        assert_eq!(v["enabled"], false);
        assert!(filter_engine::cookie_log()
            .since(id, 0, 10, None)
            .0
            .is_empty());

        // On: a browser that is not the extension's records nothing.
        env.proxy.ctx.set_cookie_provenance(true);
        let before = filter_engine::cookie_log().len();
        let r = get(&plain, "/page", "document").await;
        assert_eq!(r.status(), 200);
        assert_eq!(filter_engine::cookie_log().len(), before);

        // The bound browser: a document, a fetch, a redirect and a 304.
        let r = get(&bound, "/page", "document").await;
        assert_eq!(r.status(), 200);
        // The browser still gets what the rules left: `_gid` is gone, `_ga` is capped.
        let set: Vec<String> = r
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(set.len(), 3, "{set:?}");
        assert!(set.iter().any(|s| s.starts_with("_ga=")
            && s.contains("Max-Age=600")
            && s.contains("SameSite=Strict")));
        get(&bound, "/api", "empty").await;
        assert_eq!(get(&bound, "/go", "document").await.status(), 302);
        assert_eq!(get(&bound, "/nm", "empty").await.status(), 304);
        // A request that carried cookies a rule removes.
        let r = bound
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("cookies.test", "/api"),
            )
            .header("sec-fetch-dest", "empty")
            .header("referer", page)
            .header("cookie", format!("trk={V5}; keep={V6}; {V7}"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let sent = env.origin.requests_for("/api");
        let cookie = sent
            .last()
            .unwrap()
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .map(|(_, v)| v.clone());
        assert_eq!(cookie.as_deref(), Some(&*format!("keep={V6}")));

        let (v, text) = read(&api, &sid, "").await;
        for s in SECRETS {
            assert!(
                !text.contains(s),
                "a cookie value reached the API: {s}\n{text}"
            );
        }
        assert_eq!(v["enabled"], true);
        let got = names(&v);
        let want = |n: &str, e: &str| (n.to_string(), e.to_string());
        for w in [
            want("sess", "set"),
            want("_gid", "stripped"),
            want("_ga", "changed"),
            want("__Host-x", "set"),
            want("xhr", "set"),
            want("hop", "set"),
            want("nm", "set"),
            want("trk", "blocked_send"),
            want("", "blocked_send"),
        ] {
            assert!(got.contains(&w), "{w:?} in {got:?}");
        }
        // Nothing from the browser that is not bound.
        assert_eq!(got.iter().filter(|(n, _)| n == "sess").count(), 1);
        let rec = |name: &str| {
            v["records"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["name"] == name)
                .unwrap()
                .clone()
        };
        let sess = rec("sess");
        assert_eq!(sess["host"], "cookies.test");
        assert_eq!(sess["path"], "/page");
        assert_eq!(sess["page_host"], "cookies.test");
        assert_eq!(sess["attrs"]["max_age"], 3600);
        assert_eq!(sess["attrs"]["same_site"], "lax");
        assert_eq!(sess["attrs"]["secure"], true);
        assert_eq!(sess["attrs"]["http_only"], true);
        let gid = rec("_gid");
        assert_eq!(gid["rule"], "||cookies.test^$cookie=_gid");
        // The attributes are the ones the server sent, not what the rule left.
        assert_eq!(gid["attrs"]["max_age"], 86400);
        let ga = rec("_ga");
        assert_eq!(
            ga["rule"],
            "||cookies.test^$cookie=_ga;maxAge=600;sameSite=strict"
        );
        assert_eq!(ga["attrs"]["max_age"], 31536000);
        assert_eq!(ga["attrs"]["same_site"], "none");
        let ch: Vec<(&str, &str, &str)> = ga["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                (
                    c["attr"].as_str().unwrap(),
                    c["from"].as_str().unwrap(),
                    c["to"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            ch,
            [
                ("max_age", "31536000", "600"),
                ("same_site", "none", "strict")
            ]
        );
        assert_eq!(rec("__Host-x")["prefix"], "__Host-");
        assert_eq!(rec("__Host-x")["prefix_valid"], true);
        assert_eq!(rec("xhr")["path"], "/api");
        let trk = rec("trk");
        assert_eq!(trk["rule"], "||cookies.test^$cookie=trk");
        assert_eq!(trk["host"], "cookies.test");

        // Polling after the last record returns nothing new; the host filter narrows.
        let next = v["next_since"].as_u64().unwrap();
        let (again, _) = read(&api, &sid, &format!("?since={next}")).await;
        assert!(again["records"].as_array().unwrap().is_empty());
        let (other, _) = read(&api, &sid, "?host=elsewhere.org").await;
        assert!(other["records"].as_array().unwrap().is_empty());

        // Another session never sees these records.
        let (_id2, sid2, _rx2) = hub.open(ExtIdent {
            token_id: api.token_id.clone(),
            user: "u".into(),
            profiles: None,
        });
        let (theirs, _) = read(&api, &sid2, "").await;
        assert!(theirs["records"].as_array().unwrap().is_empty());

        // Switching the setting off clears every ring at once.
        env.proxy.ctx.set_cookie_provenance(false);
        let (off, _) = read(&api, &sid, "").await;
        assert_eq!(off["enabled"], false);
        assert!(filter_engine::cookie_log()
            .since(id, 0, 10, None)
            .0
            .is_empty());

        // The session ending drops what it held.
        env.proxy.ctx.set_cookie_provenance(true);
        get(&bound, "/page", "document").await;
        assert!(!filter_engine::cookie_log()
            .since(id, 0, 10, None)
            .0
            .is_empty());
        hub.close(id);
        assert!(filter_engine::cookie_log()
            .since(id, 0, 10, None)
            .0
            .is_empty());
    }
);

const CHALLENGE_BODY: &str = "<html><body>Just a moment... CHALLENGE-BODY</body></html>";

e2e_test!(
    a_challenge_pages_set_cookie_is_recorded_while_the_body_passes_through,
    rules = RULES,
    explicit_only,
    |env| {
        let api = env.proxy.api().await;
        let hub = env.proxy.ctx.internal().gm.ext().clone();
        let (id, sid, _rx) = hub.open(ExtIdent {
            token_id: api.token_id.clone(),
            user: "u".into(),
            profiles: None,
        });
        let bound = ext_client(&env, &sid).await;
        env.proxy.ctx.set_cookie_provenance(true);
        env.origin.route(
            "/chl",
            MockResponse::new(403, CHALLENGE_BODY)
                .header("content-type", "text/html; charset=UTF-8")
                .header("cf-mitigated", "challenge")
                .header(
                    "set-cookie",
                    &format!("cf_clearance={V1}; Path=/; Secure; HttpOnly; SameSite=None"),
                )
                .header("set-cookie", &format!("_gid={V2}; Path=/; Max-Age=86400")),
        );
        let r = bound
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("cookies.test", "/chl"),
            )
            .header("sec-fetch-dest", "document")
            .send()
            .await
            .expect("response");
        assert_eq!(r.status().as_u16(), 403);
        let set: Vec<String> = r
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        // The header-level `$cookie` rule still applies on a challenge response.
        assert_eq!(set.len(), 1, "{set:?}");
        assert!(set[0].starts_with("cf_clearance="));
        // The body is untouched.
        assert_eq!(r.text().await.unwrap(), CHALLENGE_BODY);
        let (v, text) = read(&api, &sid, "").await;
        for s in SECRETS {
            assert!(!text.contains(s), "{s}\n{text}");
        }
        let got = names(&v);
        assert!(
            got.contains(&("cf_clearance".to_string(), "set".to_string())),
            "{got:?}"
        );
        assert!(
            got.contains(&("_gid".to_string(), "stripped".to_string())),
            "{got:?}"
        );
        hub.close(id);
    }
);

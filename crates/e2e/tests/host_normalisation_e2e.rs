//! A blocked host cannot be reached by changing its spelling: the proxy lower-cases hosts, strips
//! a trailing dot and punycodes IDNs once at entry, before the filter check and the destination
//! policy (domain-set and engine rules alike).

use e2e::{e2e_test, tls_via_proxy, MockResponse, TestEnv};
use filter_engine::{build_set, ListFormat, ListInput};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn install(env: &TestEnv) {
    // `set-ad.test` lands in the domain set, `||eng-ad.test^$script` stays in the engine.
    let built = build_set(&[
        ListInput {
            id: "hosts".into(),
            content: "0.0.0.0 set-ad.test\n".into(),
            format: ListFormat::Hosts,
            ..Default::default()
        },
        ListInput {
            id: "abp".into(),
            content: "||eng-ad.test^\n||xn--bcher-kva.example^\n".into(),
            format: ListFormat::Abp,
            ..Default::default()
        },
    ]);
    assert_eq!(built.domains.len(), 3);
    built.install_into(&env.proxy.engine);
    env.origin.route("/a.png", MockResponse::ok("origin-body"));
}

/// Send `request` on a fresh plain connection to the proxy; the full response text.
async fn raw(env: &TestEnv, request: &str) -> String {
    let mut tcp = TcpStream::connect(env.proxy.addr).await.unwrap();
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ =
        tokio::time::timeout(std::time::Duration::from_secs(5), tcp.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).to_ascii_lowercase()
}

e2e_test!(
    mixed_case_absolute_form_is_blocked,
    rules = Vec::<&str>::new(),
    explicit_only,
    |env| {
        install(&env);
        for host in ["SET-AD.test", "Set-Ad.TEST", "ENG-ad.TEST", "x.ENG-AD.test"] {
            let r = raw(
                &env,
                &format!("GET http://{host}:{}/a.png HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
                    env.origin.http_port()),
            )
            .await;
            assert!(r.contains("x-adblock: blocked"), "{host}: {r}");
        }
        // Upper-case scheme and host, no port.
        let r = raw(
            &env,
            "GET HTTPS://ExAmPle.TEST/ HTTP/1.1\r\nHost: ExAmPle.TEST\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            !r.contains("x-adblock: blocked"),
            "unlisted host must pass: {r}"
        );
        let r = raw(
            &env,
            "GET HTTPS://SeT-aD.TesT/a.png HTTP/1.1\r\nHost: SeT-aD.TesT\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(r.contains("x-adblock: blocked"), "{r}");
        assert!(
            env.origin.requests_for("/a.png").is_empty(),
            "nothing reached the origin"
        );
    }
);

e2e_test!(
    trailing_dot_and_unicode_hosts_are_blocked,
    rules = Vec::<&str>::new(),
    explicit_only,
    |env| {
        install(&env);
        let c = env.client();
        for host in [
            "set-ad.test.",
            "eng-ad.test.",
            "bücher.example",
            "BÜCHER.example.",
        ] {
            let resp = c.get(&env.origin.https_url(host, "/a.png")).await;
            assert_eq!(resp.headers()["x-adblock"], "blocked", "{host}");
        }
        assert!(env.origin.requests_for("/a.png").is_empty());
        // The unlisted neighbour is untouched.
        let ok = c.get(&env.origin.https_url("fine.test.", "/a.png")).await;
        assert_eq!(ok.text().await.unwrap(), "origin-body");
    }
);

e2e_test!(
    mixed_case_connect_and_sni_are_blocked,
    rules = Vec::<&str>::new(),
    |env| {
        install(&env);
        for host in ["SET-AD.test", "Eng-Ad.Test"] {
            let mut tls =
                tls_via_proxy(&env.proxy, host, env.origin.https_port(), &[b"http/1.1"]).await;
            tls.write_all(
                format!("GET /a.png HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
            let mut out = Vec::new();
            let _ = tls.read_to_end(&mut out).await;
            let r = String::from_utf8_lossy(&out).to_ascii_lowercase();
            assert!(r.contains("x-adblock: blocked"), "{host}: {r}");
        }
        assert!(env.origin.requests_for("/a.png").is_empty());
    }
);

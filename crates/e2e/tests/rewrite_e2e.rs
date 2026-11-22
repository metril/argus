//! Page rewriting end to end: injection, CSP, content codings, charsets, document sniffing,
//! header correctness, the `/__adblock__/` endpoints and streaming behaviour. Every scenario runs
//! in both entry modes; transport-sensitive ones also over HTTP/1.1 and HTTP/2.

use e2e::{
    decode, e2e_test, encode_stacked, Coding, HttpVersion, MockResponse, StreamSpec, TestEnv,
};
use futures_util::StreamExt;
use std::sync::atomic::Ordering;
use std::time::Duration;

const AD: [&str; 1] = ["rw.test##.ad"];
const PAGE: &str =
    "<!DOCTYPE html><html><head><title>t</title></head><body><div class=\"ad\">x</div><p>hello</p></body></html>";

async fn get_doc(
    env: &TestEnv,
    version: HttpVersion,
    path: &str,
    extra: &[(&str, &str)],
) -> reqwest::Response {
    let mut rb = env
        .client_with(version)
        .request(reqwest::Method::GET, &env.origin.https_url("rw.test", path))
        .header("sec-fetch-dest", "document")
        .header("sec-fetch-mode", "navigate")
        .header("accept", "text/html");
    for (k, v) in extra {
        rb = rb.header(*k, *v);
    }
    rb.send().await.expect("request")
}

async fn body_text(r: reqwest::Response) -> String {
    String::from_utf8(r.bytes().await.unwrap().to_vec()).unwrap()
}

const VERSIONS: [HttpVersion; 2] = [HttpVersion::Http1, HttpVersion::Http2];

/// Value of `attr="..."` on the first tag after `anchor`.
fn attr_after(html: &str, anchor: &str, attr: &str) -> String {
    let i = html
        .find(anchor)
        .unwrap_or_else(|| panic!("no {anchor} in {html}"));
    let rest = &html[i..];
    let key = format!("{attr}=\"");
    let j = rest
        .find(&key)
        .unwrap_or_else(|| panic!("no {attr} after {anchor}"));
    let v = &rest[j + key.len()..];
    v[..v.find('"').unwrap()].to_string()
}

fn csp_values(r: &reqwest::Response) -> Vec<String> {
    r.headers()
        .get_all("content-security-policy")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

// ---- injection basics ---------------------------------------------------------------------

e2e_test!(
    injects_after_head_and_keeps_doctype_first,
    rules = AD,
    |env| {
        env.origin.route("/p", MockResponse::html(PAGE));
        for v in VERSIONS {
            let r = get_doc(&env, v, "/p", &[]).await;
            assert_eq!(r.status(), 200);
            assert!(r.headers().get("content-length").is_none());
            let html = body_text(r).await;
            assert!(
                html.starts_with("<!DOCTYPE html><html><head><style id=\"__adblock_cosmetic\""),
                "{html}"
            );
            assert!(html.contains(".ad{display:none!important}"));
            assert!(html.contains("/__adblock__/boot."));
            assert!(html.ends_with("<p>hello</p></body></html>"));
            assert_eq!(html.matches("__adblock_cosmetic").count(), 1);
        }
    }
);

e2e_test!(no_head_no_doctype_and_fragments, rules = AD, |env| {
    env.origin.route(
        "/nohead",
        MockResponse::html("<html><body><p>a</p></body></html>"),
    );
    env.origin
        .route("/frag", MockResponse::html("<p>just a fragment</p>"));
    env.origin.route(
        "/doctype-only",
        MockResponse::html("<!DOCTYPE html><div class=ad>x</div>"),
    );
    env.origin.route(
        "/tricky",
        MockResponse::html(
            "<!DOCTYPE html><!-- </head> <body> --><html><head><script>var s='</head><body>';</script><!--</head>--><title>x</title></head><body>b</body></html>",
        ),
    );
    env.origin.route(
        "/cdata",
        MockResponse::html("<!DOCTYPE html><svg><![CDATA[</head><body>]]></svg><p>z</p>"),
    );
    for (path, expect_prefix) in [
        ("/nohead", "<html><style"),
        ("/frag", "<style"),
        ("/doctype-only", "<!DOCTYPE html><style"),
        (
            "/tricky",
            "<!DOCTYPE html><!-- </head> <body> --><html><head><style",
        ),
    ] {
        let html = body_text(get_doc(&env, HttpVersion::Auto, path, &[]).await).await;
        assert!(html.starts_with(expect_prefix), "{path}: {html}");
        assert_eq!(html.matches("__adblock_cosmetic").count(), 1, "{path}");
    }
    // The script string / comment copies of </head> stay intact and ours is the first script.
    let t = body_text(get_doc(&env, HttpVersion::Auto, "/tricky", &[]).await).await;
    assert!(t.contains("var s='</head><body>';"));
    assert!(t.find("/__adblock__/boot.").unwrap() < t.find("var s=").unwrap());
    let c = body_text(get_doc(&env, HttpVersion::Auto, "/cdata", &[]).await).await;
    assert!(c.contains("<![CDATA[</head><body>]]>"));
    assert_eq!(c.matches("__adblock_cosmetic").count(), 1);
});

e2e_test!(not_html_is_left_alone, rules = AD, |env| {
    let json = "{\"a\":\"<head></head>\"}";
    env.origin.route(
        "/json",
        MockResponse::ok(json).header("content-type", "text/html"),
    );
    env.origin.route(
        "/xml",
        MockResponse::ok("<?xml version=\"1.0\"?><rss><head/></rss>")
            .header("content-type", "text/html"),
    );
    env.origin.route(
        "/js",
        MockResponse::ok("var a = '<head>';").header("content-type", "text/html"),
    );
    env.origin.route(
        "/svg",
        MockResponse::ok("<svg><head/></svg>").header("content-type", "text/html"),
    );
    env.origin.route(
        "/empty",
        MockResponse::ok("").header("content-type", "text/html"),
    );
    env.origin.route(
        "/dl",
        MockResponse::html(PAGE).header("content-disposition", "attachment; filename=\"a.html\""),
    );
    env.origin.route(
        "/css",
        MockResponse::ok("<head>").header("content-type", "text/css"),
    );
    for (path, want) in [
        ("/json", json),
        ("/xml", "<?xml version=\"1.0\"?><rss><head/></rss>"),
        ("/js", "var a = '<head>';"),
        ("/svg", "<svg><head/></svg>"),
        ("/empty", ""),
        ("/dl", PAGE),
        ("/css", "<head>"),
    ] {
        let r = get_doc(&env, HttpVersion::Auto, path, &[]).await;
        assert!(
            r.headers().get("content-length").is_some()
                || path == "/empty"
                || r.version() == reqwest::Version::HTTP_2,
            "{path}: length kept"
        );
        assert_eq!(body_text(r).await, want, "{path}");
    }
});

e2e_test!(only_documents_and_frames_are_rewritten, rules = AD, |env| {
    env.origin.route("/p", MockResponse::html(PAGE));
    let client = env.client();
    let url = env.origin.https_url("rw.test", "/p");
    for (dest, rewritten) in [
        ("document", true),
        ("iframe", true),
        ("frame", true),
        ("empty", false),
        ("script", false),
        ("image", false),
    ] {
        let r = client
            .request(reqwest::Method::GET, &url)
            .header("sec-fetch-dest", dest)
            .send()
            .await
            .unwrap();
        let html = body_text(r).await;
        assert_eq!(html.contains("__adblock_cosmetic"), rewritten, "{dest}");
    }
});

e2e_test!(head_204_304_206_untouched, rules = AD, |env| {
    env.origin.route("/p", MockResponse::html(PAGE));
    env.origin.route(
        "/s204",
        MockResponse::new(204, "").header("content-type", "text/html"),
    );
    env.origin.route(
        "/s206",
        MockResponse::new(206, "<html><head>partial")
            .header("content-type", "text/html")
            .header("content-range", "bytes 0-18/1000"),
    );
    env.origin.route(
        "/s304",
        MockResponse::new(304, "")
            .header("content-type", "text/html")
            .header("etag", "\"abc\""),
    );
    let client = env.client();
    let url = env.origin.https_url("rw.test", "/p");
    let head = client
        .request(reqwest::Method::HEAD, &url)
        .header("sec-fetch-dest", "document")
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 200);
    assert_eq!(head.headers()["content-length"], PAGE.len().to_string());
    assert!(head.bytes().await.unwrap().is_empty());
    for (path, status, body) in [
        ("/s204", 204, ""),
        ("/s206", 206, "<html><head>partial"),
        ("/s304", 304, ""),
    ] {
        let r = get_doc(&env, HttpVersion::Auto, path, &[]).await;
        assert_eq!(r.status(), status, "{path}");
        assert_eq!(body_text(r).await, body, "{path}");
    }
    // Range is not forwarded for documents, so the origin never answers one with a fragment.
    let _ = get_doc(
        &env,
        HttpVersion::Auto,
        "/p",
        &[("range", "bytes=0-10"), ("if-range", "x")],
    )
    .await;
    let seen = env.origin.requests_for("/p");
    let last = seen.last().unwrap();
    assert!(!last
        .headers
        .iter()
        .any(|(k, _)| k == "range" || k == "if-range"));
});

e2e_test!(header_correctness_on_rewrite, rules = AD, |env| {
    env.origin.route(
        "/p",
        MockResponse::html(PAGE)
            .header("etag", "\"v1\"")
            .header("content-md5", "abc")
            .header("digest", "sha-256=abc")
            .header("repr-digest", "sha-256=:abc:")
            .header("accept-ranges", "bytes")
            .header("vary", "Cookie")
            .header("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT"),
    );
    for v in VERSIONS {
        let r = get_doc(&env, v, "/p", &[]).await;
        let h = r.headers().clone();
        assert!(h.get("content-length").is_none());
        assert_eq!(h["etag"], "W/\"v1\"");
        for gone in ["content-md5", "digest", "repr-digest", "accept-ranges"] {
            assert!(h.get(gone).is_none(), "{gone} must be dropped");
        }
        let vary = h["vary"].to_str().unwrap();
        assert!(
            vary.contains("Cookie") && vary.contains("Sec-Fetch-Dest"),
            "{vary}"
        );
        assert_eq!(h["last-modified"], "Wed, 21 Oct 2015 07:28:00 GMT");
        let _ = r.bytes().await;
    }
});

// ---- content codings ----------------------------------------------------------------------

e2e_test!(
    codings_are_decoded_rewritten_and_reencoded,
    rules = AD,
    |env| {
        for (name, codings) in [
            ("zstd", vec![Coding::Zstd]),
            ("br", vec![Coding::Br]),
            ("gzip", vec![Coding::Gzip]),
            ("deflate", vec![Coding::Deflate]),
            ("stack", vec![Coding::Gzip, Coding::Br]),
        ] {
            let enc = encode_stacked(&codings, PAGE.as_bytes()).await;
            let ce = codings
                .iter()
                .map(|c| c.token())
                .collect::<Vec<_>>()
                .join(", ");
            env.origin.route(
                &format!("/{name}"),
                MockResponse::ok(enc)
                    .header("content-type", "text/html; charset=utf-8")
                    .header("content-encoding", &ce),
            );
        }
        for v in VERSIONS {
            for name in ["zstd", "br", "gzip", "deflate", "stack"] {
                for (accept, want) in [
                    ("gzip, deflate, br, zstd", Some(Coding::Zstd)),
                    ("gzip, br", Some(Coding::Br)),
                    ("gzip", Some(Coding::Gzip)),
                    ("identity", None),
                ] {
                    let r =
                        get_doc(&env, v, &format!("/{name}"), &[("accept-encoding", accept)]).await;
                    assert_eq!(r.status(), 200);
                    let ce = r
                        .headers()
                        .get("content-encoding")
                        .map(|v| v.to_str().unwrap().to_string());
                    assert_eq!(ce.as_deref(), want.map(|c| c.token()), "{name} / {accept}");
                    assert!(r.headers().get("content-length").is_none());
                    assert!(r.headers()["vary"]
                        .to_str()
                        .unwrap()
                        .contains("Accept-Encoding"));
                    let raw = r.bytes().await.unwrap();
                    let plain = match want {
                        Some(c) => decode(&[c], &raw).await,
                        None => raw.to_vec(),
                    };
                    let html = String::from_utf8(plain).unwrap();
                    assert!(
                        html.contains("__adblock_cosmetic"),
                        "{name}/{accept}: {html}"
                    );
                    assert!(html.contains("<p>hello</p>"));
                }
            }
        }
    }
);

e2e_test!(
    identity_origin_stays_identity_and_unknown_coding_passes_through,
    rules = AD,
    |env| {
        env.origin.route("/id", MockResponse::html(PAGE));
        let r = get_doc(
            &env,
            HttpVersion::Auto,
            "/id",
            &[("accept-encoding", "zstd, br, gzip")],
        )
        .await;
        assert!(r.headers().get("content-encoding").is_none());
        assert!(body_text(r).await.contains("__adblock_cosmetic"));

        let blob = b"\x01\x02not really compressed <html><head>".to_vec();
        env.origin.route(
            "/odd",
            MockResponse::ok(blob.clone())
                .header("content-type", "text/html")
                .header("content-encoding", "compress"),
        );
        env.origin.route(
            "/odd2",
            MockResponse::ok(blob.clone())
                .header("content-type", "text/html")
                .header("content-encoding", "gzip, dcb"),
        );
        for p in ["/odd", "/odd2"] {
            let r = get_doc(
                &env,
                HttpVersion::Http1,
                p,
                &[("accept-encoding", "gzip, compress")],
            )
            .await;
            assert!(r.headers().get("content-encoding").is_some());
            assert_eq!(r.headers()["content-length"], blob.len().to_string());
            assert_eq!(r.bytes().await.unwrap().to_vec(), blob);
        }
        // The client's Accept-Encoding reaches the origin unchanged.
        let seen = env.origin.requests_for("/odd");
        let ae = seen[0]
            .headers
            .iter()
            .find(|(k, _)| k == "accept-encoding")
            .unwrap();
        assert_eq!(ae.1, "gzip, compress");
    }
);

e2e_test!(
    corrupt_body_is_passed_through_not_dropped,
    rules = AD,
    |env| {
        let garbage = b"definitely not gzip".to_vec();
        env.origin.route(
            "/bad",
            MockResponse::ok(garbage.clone())
                .header("content-type", "text/html")
                .header("content-encoding", "gzip"),
        );
        let r = get_doc(
            &env,
            HttpVersion::Http1,
            "/bad",
            &[("accept-encoding", "gzip")],
        )
        .await;
        assert_eq!(r.bytes().await.unwrap().to_vec(), garbage);
    }
);

// ---- charsets -----------------------------------------------------------------------------

fn sjis(s: &str) -> Vec<u8> {
    encoding_rs::SHIFT_JIS.encode(s).0.into_owned()
}

e2e_test!(
    shift_jis_gbk_and_latin1_text_stays_byte_exact,
    rules = AD,
    |env| {
        let jp = "<html><head><meta charset=\"shift_jis\"><title>\u{65e5}\u{672c}\u{8a9e}</title></head><body><p>\u{3053}\u{3093}\u{306b}\u{3061}\u{306f}\u{8868}\u{793a}</p><div class=ad>\u{5e83}\u{544a}</div></body></html>";
        let jp_bytes = sjis(jp);
        env.origin.route(
            "/sjis",
            MockResponse::ok(jp_bytes.clone()).header("content-type", "text/html"),
        );
        let gbk_page =
            "<html><head></head><body><p>\u{4e2d}\u{6587}\u{5e7f}\u{544a}</p></body></html>";
        let gbk_bytes = encoding_rs::GBK.encode(gbk_page).0.into_owned();
        env.origin.route(
            "/gbk",
            MockResponse::ok(gbk_bytes.clone()).header("content-type", "text/html; charset=gbk"),
        );
        let l1 = encoding_rs::WINDOWS_1252
            .encode("<html><head></head><body>caf\u{e9} \u{201c}x\u{201d}</body></html>")
            .0
            .into_owned();
        env.origin.route(
            "/l1",
            MockResponse::ok(l1.clone()).header("content-type", "text/html; charset=windows-1252"),
        );
        for v in VERSIONS {
            for (path, orig) in [("/sjis", &jp_bytes), ("/gbk", &gbk_bytes), ("/l1", &l1)] {
                let r = get_doc(&env, v, path, &[]).await;
                let ct = r.headers()["content-type"].to_str().unwrap().to_string();
                assert!(
                    !ct.contains("utf-8"),
                    "{path}: charset header untouched: {ct}"
                );
                let out = r.bytes().await.unwrap().to_vec();
                let marker = b"<style id=\"__adblock_cosmetic\"";
                let at = out
                    .windows(marker.len())
                    .position(|w| w == marker)
                    .expect("injected");
                let end = out.windows(8).position(|w| w == b"</style>").unwrap();
                // Removing the injected span restores the original bytes exactly.
                let boot = out
                    .windows(9)
                    .rposition(|w| w == b"</script>")
                    .map(|p| p + 9)
                    .unwrap_or(end + 8);
                let mut restored = out[..at].to_vec();
                restored.extend_from_slice(&out[boot.max(end + 8)..]);
                assert_eq!(&restored, orig, "{path}");
            }
        }
    }
);

e2e_test!(
    utf16_is_transcoded_with_consistent_declarations,
    rules = AD,
    |env| {
        let text = "<html><head><meta charset=\"utf-16\"></head><body><p>\u{65e5}\u{672c}\u{8a9e} caf\u{e9}</p></body></html>";
        let mut le = vec![0xff, 0xfe];
        for u in text.encode_utf16() {
            le.extend_from_slice(&u.to_le_bytes());
        }
        let mut be = vec![0xfe, 0xff];
        for u in text.encode_utf16() {
            be.extend_from_slice(&u.to_be_bytes());
        }
        env.origin.route(
            "/le",
            MockResponse::ok(le).header("content-type", "text/html; charset=utf-16le"),
        );
        env.origin.route(
            "/be",
            MockResponse::ok(be).header("content-type", "text/html"),
        );
        for p in ["/le", "/be"] {
            let r = get_doc(&env, HttpVersion::Auto, p, &[]).await;
            let ct = r.headers()["content-type"].to_str().unwrap().to_string();
            assert!(ct.contains("charset=utf-8"), "{p}: {ct}");
            let html = body_text(r).await;
            assert!(
                html.contains("<p>\u{65e5}\u{672c}\u{8a9e} caf\u{e9}</p>"),
                "{p}: {html}"
            );
            assert!(html.contains("__adblock_cosmetic"));
            assert!(
                html.contains("<meta charset=\"utf-8\">"),
                "meta fixed up: {html}"
            );
            assert!(!html.starts_with('\u{feff}'));
        }
    }
);

// ---- CSP ----------------------------------------------------------------------------------

e2e_test!(strict_nonce_csp_gets_our_nonce, rules = AD, |env| {
    env.origin.route(
        "/p",
        MockResponse::html(PAGE).header(
            "content-security-policy",
            "default-src 'none'; script-src 'nonce-page' 'strict-dynamic'; style-src 'nonce-page'; connect-src 'none'",
        ),
    );
    for v in VERSIONS {
        let r = get_doc(&env, v, "/p", &[]).await;
        let csp = csp_values(&r);
        assert_eq!(csp.len(), 1);
        let html = body_text(r).await;
        let nonce = attr_after(&html, "<style id=\"__adblock_cosmetic\"", "nonce");
        assert_eq!(
            nonce,
            attr_after(&html, "<script src=\"/__adblock__/boot.", "nonce")
        );
        let want = format!("'nonce-{nonce}'");
        let c = &csp[0];
        assert!(
            c.contains(&format!("script-src 'nonce-page' 'strict-dynamic' {want}")),
            "{c}"
        );
        assert!(c.contains(&format!("style-src 'nonce-page' {want}")), "{c}");
        // A `'none'` source list is replaced by our source, never extended (that would make the
        // browser ignore the `'none'`).
        assert!(c.contains("connect-src https://rw.test"), "{c}");
        assert!(!c.contains("'none' https://"), "{c}");
        assert!(
            c.contains("default-src 'none';"),
            "default-src untouched: {c}"
        );
        // 128-bit+ nonce
        assert!(nonce.len() >= 22);
    }
});

e2e_test!(nonces_are_fresh_per_response, rules = AD, |env| {
    env.origin.route(
        "/p",
        MockResponse::html(PAGE).header("content-security-policy", "script-src 'nonce-page'"),
    );
    let mut seen = std::collections::HashSet::new();
    for _ in 0..5 {
        let html = body_text(get_doc(&env, HttpVersion::Auto, "/p", &[]).await).await;
        assert!(seen.insert(attr_after(
            &html,
            "<style id=\"__adblock_cosmetic\"",
            "nonce"
        )));
    }
});

e2e_test!(unsafe_inline_policy_gets_no_nonce, rules = AD, |env| {
    let own = "script-src 'self' 'unsafe-inline'";
    env.origin.route(
        "/self",
        MockResponse::html(PAGE).header("content-security-policy", own),
    );
    env.origin.route(
        "/cdn",
        MockResponse::html(PAGE).header(
            "content-security-policy",
            "script-src https://cdn.test 'unsafe-inline'",
        ),
    );
    // 'self' + 'unsafe-inline': the header is not touched at all.
    let r = get_doc(&env, HttpVersion::Auto, "/self", &[]).await;
    assert_eq!(csp_values(&r), vec![own.to_string()]);
    assert!(body_text(r).await.contains("/__adblock__/boot."));
    // 'unsafe-inline' without 'self': a narrow host-source, never a nonce.
    let r = get_doc(&env, HttpVersion::Auto, "/cdn", &[]).await;
    let c = csp_values(&r).remove(0);
    assert!(!c.contains("nonce-"), "{c}");
    assert!(
        c.starts_with("script-src https://cdn.test 'unsafe-inline' https://rw.test:"),
        "{c}"
    );
    assert!(c.ends_with("/__adblock__/"), "{c}");
});

e2e_test!(multiple_and_report_only_policies, rules = AD, |env| {
    env.origin.route(
        "/p",
        MockResponse::html(PAGE)
            .header("content-security-policy", "script-src 'self'")
            .header("content-security-policy", "script-src 'nonce-a'")
            .header("content-security-policy-report-only", "script-src 'none'"),
    );
    let r = get_doc(&env, HttpVersion::Auto, "/p", &[]).await;
    let ro = r.headers()["content-security-policy-report-only"]
        .to_str()
        .unwrap()
        .to_string();
    // Report-Only policies get the same narrow additions (so our tags cause no reports); the
    // original `script-src 'none'` is left as written.
    assert!(
        ro.starts_with("script-src 'none'; script-src-elem 'nonce-"),
        "{ro}"
    );
    assert!(!ro.contains("'none' 'nonce"), "{ro}");
    let c = csp_values(&r);
    assert_eq!(c.len(), 2);
    assert_eq!(c[0], "script-src 'self'");
    assert!(c[1].starts_with("script-src 'nonce-a' 'nonce-"), "{}", c[1]);
});

e2e_test!(sandbox_without_scripts_gets_css_only, rules = AD, |env| {
    env.origin.route(
        "/p",
        MockResponse::html(PAGE).header("content-security-policy", "sandbox allow-forms"),
    );
    let r = get_doc(&env, HttpVersion::Auto, "/p", &[]).await;
    assert_eq!(csp_values(&r), vec!["sandbox allow-forms".to_string()]);
    let html = body_text(r).await;
    assert!(html.contains(".ad{display:none!important}"));
    assert!(!html.contains("<script"), "{html}");
});

e2e_test!(meta_csp_gets_only_the_beacon_allowance, rules = AD, |env| {
    let page = "<!DOCTYPE html><html><head><meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'none'; connect-src https://api.test\"><title>x</title></head><body></body></html>";
    env.origin.route("/p", MockResponse::html(page));
    let html = body_text(get_doc(&env, HttpVersion::Auto, "/p", &[]).await).await;
    // Our tags come before the meta, so its script-src is left exactly as the page wrote it.
    assert!(
        html.contains("script-src 'none'; connect-src https://api.test https://rw.test:"),
        "{html}"
    );
    assert!(html.find("/__adblock__/boot.").unwrap() < html.find("http-equiv").unwrap());
});

e2e_test!(trusted_types_name_added, rules = AD, |env| {
    env.origin.route(
        "/p",
        MockResponse::html(PAGE).header(
            "content-security-policy",
            "require-trusted-types-for 'script'; trusted-types app; script-src 'nonce-page'",
        ),
    );
    let r = get_doc(&env, HttpVersion::Auto, "/p", &[]).await;
    let c = csp_values(&r).remove(0);
    assert!(c.contains("trusted-types app adblock-proxy"), "{c}");
});

// ---- /__adblock__/ ------------------------------------------------------------------------

e2e_test!(
    internal_endpoints_are_local_and_hardened,
    rules = ["rw.test##.ad", "||rw.test/__adblock__/^"],
    |env| {
        env.origin.route("/p", MockResponse::html(PAGE));
        env.origin
            .route("/__adblock__/boot.js", MockResponse::ok("evil()"));
        let html = body_text(get_doc(&env, HttpVersion::Auto, "/p", &[]).await).await;
        let boot = attr_after(&html, "<script src=\"/__adblock__/boot.", "src");
        let client = env.client();
        let base = |p: &str| env.origin.https_url("rw.test", p);

        let r = client.get(&base(&boot)).await;
        assert_eq!(
            r.status(),
            200,
            "internal path must never match filter rules"
        );
        let h = r.headers().clone();
        assert_eq!(h["cache-control"], "public, max-age=31536000, immutable");
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert_eq!(h["cross-origin-resource-policy"], "cross-origin");
        assert!(h["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/javascript"));
        let js = body_text(r).await;
        assert!(js.contains("__abBoot") && !js.contains("evil"));

        // A stale or invented hash is not served; nothing is reflected.
        for p in [
            "/__adblock__/boot.js",
            "/__adblock__/boot.deadbeef.js",
            "/__adblock__/s/%3Cscript%3Ealert(1)%3C/script%3E.js",
            "/__adblock__/nope",
            "/__adblock__/",
        ] {
            let r = client.get(&base(p)).await;
            assert_eq!(r.status(), 404, "{p}");
            assert_eq!(r.headers()["x-content-type-options"], "nosniff");
            assert!(r.bytes().await.unwrap().is_empty(), "{p}");
        }
        // Wrong methods.
        let r = client
            .request(reqwest::Method::POST, &base(&boot))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 405);
        let r = client
            .request(reqwest::Method::GET, &base("/__adblock__/cc"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 405);
        let r = client
            .request(reqwest::Method::OPTIONS, &base("/__adblock__/cc"))
            .send()
            .await
            .unwrap();
        assert!(r.headers().get("access-control-allow-origin").is_none());
        assert!(env.origin.requests_for("/__adblock__/boot.js").is_empty());
        assert!(env
            .origin
            .requests()
            .iter()
            .all(|r| !r.path().starts_with("/__adblock__")));
    }
);

e2e_test!(
    beacon_requires_token_json_and_same_origin,
    rules = ["rw.test##.ad", "rw.test###promo", "##.banner"],
    |env| {
        env.origin.route("/p", MockResponse::html(PAGE));
        let html = body_text(get_doc(&env, HttpVersion::Auto, "/p", &[]).await).await;
        let cfg = {
            let i = html.find("id=\"__ab_cfg\">").expect("cfg") + "id=\"__ab_cfg\">".len();
            let j = html[i..].find("</script>").unwrap();
            serde_json::from_str::<serde_json::Value>(&html[i..i + j]).unwrap()
        };
        let token = cfg["t"].as_str().unwrap().to_string();
        assert_eq!(cfg["o"], true);
        let client = env.client();
        let url = env.origin.https_url("rw.test", "/__adblock__/cc");
        let body = r#"{"url":"https://rw.test/","classes":["banner"],"ids":[]}"#;
        let send = |ct: Option<&str>, tok: Option<&str>, site: Option<&str>, b: String| {
            let mut rb = client.request(reqwest::Method::POST, &url).body(b);
            if let Some(ct) = ct {
                rb = rb.header("content-type", ct);
            }
            if let Some(t) = tok {
                rb = rb.header("x-adblock-token", t);
            }
            if let Some(s) = site {
                rb = rb.header("sec-fetch-site", s);
            }
            rb.send()
        };
        // Forgeable shapes are refused.
        assert_eq!(
            send(None, Some(&token), None, body.into())
                .await
                .unwrap()
                .status(),
            415
        );
        assert_eq!(
            send(Some("text/plain"), Some(&token), None, body.into())
                .await
                .unwrap()
                .status(),
            415
        );
        assert_eq!(
            send(Some("application/json"), None, None, body.into())
                .await
                .unwrap()
                .status(),
            403
        );
        assert_eq!(
            send(Some("application/json"), Some("0.AAAA"), None, body.into())
                .await
                .unwrap()
                .status(),
            403
        );
        assert_eq!(
            send(
                Some("application/json"),
                Some(&token),
                Some("cross-site"),
                body.into()
            )
            .await
            .unwrap()
            .status(),
            403
        );
        assert_eq!(
            send(
                Some("application/json"),
                Some(&token),
                None,
                "x".repeat(70 * 1024)
            )
            .await
            .unwrap()
            .status(),
            413
        );
        assert_eq!(
            send(Some("application/json"), Some(&token), None, "{".into())
                .await
                .unwrap()
                .status(),
            400
        );
        // A token minted for another host is useless here.
        env.origin.route("/q", MockResponse::html(PAGE));
        let other = client
            .request(
                reqwest::Method::GET,
                &env.origin.https_url("other.test", "/q"),
            )
            .header("sec-fetch-dest", "document")
            .send()
            .await
            .unwrap();
        let _ = other.bytes().await;
        let r = send(
            Some("application/json"),
            Some(&token),
            Some("same-origin"),
            body.into(),
        )
        .await
        .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["cache-control"], "no-store");
        assert_eq!(r.headers()["cross-origin-resource-policy"], "same-origin");
        assert!(r.headers().get("access-control-allow-origin").is_none());
        let j: serde_json::Value = serde_json::from_str(&body_text(r).await).unwrap();
        assert!(j["selectors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == ".banner"));
        // The same token against another host fails.
        let wrong_host = env.origin.https_url("other.test", "/__adblock__/cc");
        let r = client
            .request(reqwest::Method::POST, &wrong_host)
            .header("content-type", "application/json")
            .header("x-adblock-token", &token)
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        assert!(env
            .origin
            .requests()
            .iter()
            .all(|r| !r.path().starts_with("/__adblock__")));
    }
);

// A page's token only buys lookups for its own host: asking about another site's cosmetic rules
// (which would reveal the user's lists) is refused.
e2e_test!(
    beacon_refuses_urls_of_other_hosts,
    rules = ["rw.test##.ad", "##.banner", "victim.test##.secret-rule"],
    |env| {
        env.origin.route("/p", MockResponse::html(PAGE));
        let html = body_text(get_doc(&env, HttpVersion::Auto, "/p", &[]).await).await;
        let i = html.find("id=\"__ab_cfg\">").expect("cfg") + "id=\"__ab_cfg\">".len();
        let j = html[i..].find("</script>").unwrap();
        let cfg: serde_json::Value = serde_json::from_str(&html[i..i + j]).unwrap();
        let token = cfg["t"].as_str().unwrap().to_string();
        let client = env.client();
        let url = env.origin.https_url("rw.test", "/__adblock__/cc");
        let ask = |page_url: &str, class: &str| {
            let body = serde_json::json!({"url": page_url, "classes": [class], "ids": []});
            client
                .request(reqwest::Method::POST, &url)
                .header("content-type", "application/json")
                .header("x-adblock-token", &token)
                .body(body.to_string())
                .send()
        };
        for foreign in [
            "https://victim.test/",
            "https://victim.test:8443/x",
            "https://rw.test.evil.test/",
            "https://evil.test/?https://rw.test/",
            "https://rw.test@victim.test/",
            "not a url",
            "",
        ] {
            let r = ask(foreign, "secret-rule").await.unwrap();
            assert_eq!(r.status(), 403, "{foreign}");
            assert!(body_text(r).await.is_empty(), "{foreign}");
        }
        // Its own host, spelled differently, still works.
        for own in [
            "https://rw.test/",
            "https://RW.test./a?b=1",
            "http://rw.test:8080/",
        ] {
            let r = ask(own, "banner").await.unwrap();
            assert_eq!(r.status(), 200, "{own}");
        }
    }
);

// The HTML rewriter has a fixed memory budget. A tag it must inspect that outgrows it (a
// multi-megabyte attribute on an element a rule selects) cannot be rewritten, and the part of the
// document already sent cannot be taken back: the response is aborted (the browser sees a failed
// load), never ended as a complete-looking 200 with a truncated body.
e2e_test!(
    rewriter_memory_limit_aborts_the_response,
    rules = ["rw.test##^div.ad"],
    |env| {
        let huge = "a".repeat(4 * 1024 * 1024);
        let page = format!(
            "<!DOCTYPE html><html><head></head><body><p>before</p><div class=\"ad\" data-x=\"{huge}\">x</div><p>after</p></body></html>"
        );
        env.origin.route("/big", MockResponse::html(page.clone()));
        env.origin.route("/p", MockResponse::html(PAGE));
        for v in VERSIONS {
            let outcome = match get_doc(&env, v, "/big", &[]).await {
                r if r.status() == 200 => r.bytes().await.map(|b| b.len()),
                r => panic!("unexpected status {}", r.status()),
            };
            assert!(
                outcome.is_err(),
                "{v:?}: truncated body delivered as success: {outcome:?}"
            );
            // The proxy carries on serving.
            let ok = body_text(get_doc(&env, v, "/p", &[]).await).await;
            assert!(ok.contains("<p>hello</p>"), "{v:?}");
        }
    }
);

// More stacked codings than the proxy decodes (two) is hostile or broken: the body is forwarded
// exactly as received, with its original headers.
e2e_test!(
    too_many_stacked_codings_pass_through_untouched,
    rules = AD,
    |env| {
        let codings = [Coding::Deflate, Coding::Zstd, Coding::Gzip];
        let enc = encode_stacked(&codings, PAGE.as_bytes()).await;
        env.origin.route(
            "/stack3",
            MockResponse::ok(enc.clone())
                .header("content-type", "text/html; charset=utf-8")
                .header("content-encoding", "deflate, zstd, gzip"),
        );
        for v in VERSIONS {
            let r = get_doc(&env, v, "/stack3", &[("accept-encoding", "gzip, br, zstd")]).await;
            assert_eq!(r.status(), 200);
            assert_eq!(r.headers()["content-encoding"], "deflate, zstd, gzip");
            let raw = r.bytes().await.unwrap();
            assert_eq!(raw.to_vec(), enc);
            assert!(!String::from_utf8_lossy(&raw).contains("__adblock"));
        }
    }
);

e2e_test!(
    internal_endpoints_refused_when_blocking_is_off,
    rules = AD,
    |env| {
        env.origin.route("/p", MockResponse::html(PAGE));
        let html = body_text(get_doc(&env, HttpVersion::Auto, "/p", &[]).await).await;
        let boot = attr_after(&html, "<script src=\"/__adblock__/boot.", "src");
        env.proxy.ctx.set_adblock_enabled(false);
        let r = env
            .client()
            .get(&env.origin.https_url("rw.test", &boot))
            .await;
        assert_eq!(r.status(), 404);
        // And pages are no longer rewritten.
        let html = body_text(get_doc(&env, HttpVersion::Auto, "/p", &[]).await).await;
        assert_eq!(html, PAGE);
        assert!(env
            .origin
            .requests()
            .iter()
            .all(|r| !r.path().starts_with("/__adblock__")));
    }
);

// ---- streaming ----------------------------------------------------------------------------

fn big_stream(total: usize) -> StreamSpec {
    let line: String =
        "<p class=\"row\">some ordinary paragraph text for the stream</p>\n".repeat(1000);
    StreamSpec::new(
        "<!DOCTYPE html><html><head><title>big</title></head><body>\n",
        line,
        total,
    )
}

e2e_test!(
    fifty_megabyte_stream_uses_bounded_buffers,
    rules = AD,
    |env| {
        const TOTAL: usize = 50 * 1024 * 1024;
        env.origin.route(
            "/big",
            MockResponse::streaming(200, big_stream(TOTAL))
                .header("content-type", "text/html; charset=utf-8"),
        );
        proxy_core::rewrite::pipeline::reset_peak_buffered();
        let r = get_doc(&env, HttpVersion::Http1, "/big", &[]).await;
        assert_eq!(r.status(), 200);
        let mut stream = r.bytes_stream();
        let mut total = 0usize;
        let mut first: Option<Vec<u8>> = None;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.unwrap();
            if first.is_none() {
                first = Some(chunk.to_vec());
            }
            total += chunk.len();
        }
        assert!(total >= TOTAL, "whole body delivered ({total})");
        assert!(String::from_utf8_lossy(&first.unwrap()).contains("__adblock_cosmetic"));
        let peak = proxy_core::rewrite::pipeline::peak_buffered_bytes();
        assert!(peak > 0 && peak < 256 * 1024, "peak buffered {peak} bytes");
    }
);

// An origin that drips the start of a document slowly (longer than the sniffing wait) must not be
// able to make the proxy give up and skip injection: for a document navigation answered as
// text/html, the first bytes decide, however they are paced.
e2e_test!(
    slow_drip_start_cannot_disable_injection,
    rules = AD,
    |env| {
        let doc = "<!DOCTYPE html><html><head><title>t</title></head><body><p>hi</p></body></html>";
        // Splits inside the first token: "<", "<!", "<!DOCT", "<h"-style prefixes.
        let doc2 = "<html><head></head><body><p>hi</p></body></html>";
        let cases = [
            (doc, 1usize),
            (doc, 2),
            (doc, 6),
            (doc2, 1),
            (doc2, 3),
            (doc, 12),
        ];
        for (i, (d, at)) in cases.iter().enumerate() {
            let spec = StreamSpec::new(d[..*at].to_string(), d[*at..].to_string(), d.len())
                .paused(Duration::from_millis(400));
            env.origin.route(
                &format!("/drip{i}"),
                MockResponse::streaming(200, spec).header("content-type", "text/html"),
            );
        }
        let reqs = cases.iter().enumerate().map(|(i, _)| {
            get_doc(
                &env,
                HttpVersion::Http1,
                Box::leak(format!("/drip{i}").into_boxed_str()),
                &[],
            )
        });
        for (i, r) in futures_util::future::join_all(reqs)
            .await
            .into_iter()
            .enumerate()
        {
            let html = body_text(r).await;
            assert!(
                html.contains("__adblock_cosmetic"),
                "case {i} {:?}: {html}",
                cases[i].1
            );
            assert!(html.contains("<p>hi</p></body></html>"), "case {i}: {html}");
        }
    }
);

e2e_test!(
    client_disconnect_stops_the_upstream_read,
    rules = AD,
    |env| {
        let spec = big_stream(usize::MAX).paused(Duration::from_millis(1));
        let sent = spec.sent.clone();
        env.origin.route(
            "/endless",
            MockResponse::streaming(200, spec).header("content-type", "text/html; charset=utf-8"),
        );
        for v in VERSIONS {
            let before = sent.load(Ordering::Relaxed);
            let r = get_doc(&env, v, "/endless", &[("accept-encoding", "zstd")]).await;
            let mut stream = r.bytes_stream();
            let mut got = 0usize;
            while got < 256 * 1024 {
                got += stream.next().await.expect("data").unwrap().len();
            }
            drop(stream);
            tokio::time::sleep(Duration::from_millis(500)).await;
            let a = sent.load(Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(500)).await;
            let b = sent.load(Ordering::Relaxed);
            assert_eq!(a, b, "{v:?}: upstream still being read after disconnect");
            assert!(
                a - before < 64 * 1024 * 1024,
                "{v:?}: read {} bytes",
                a - before
            );
        }
    }
);

e2e_test!(slow_stream_is_flushed_not_held_back, rules = AD, |env| {
    // A page that dribbles: the head must reach the client long before the body ends.
    let spec = big_stream(10 * 1024 * 1024).paused(Duration::from_millis(200));
    env.origin.route(
        "/slow",
        MockResponse::streaming(200, spec).header("content-type", "text/html; charset=utf-8"),
    );
    let r = get_doc(&env, HttpVersion::Http1, "/slow", &[]).await;
    let mut s = r.bytes_stream();
    let first = tokio::time::timeout(Duration::from_secs(5), s.next())
        .await
        .expect("first bytes arrive promptly")
        .unwrap()
        .unwrap();
    assert!(!first.is_empty());
});

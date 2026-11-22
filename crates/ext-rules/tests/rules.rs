//! Rule-table tests: parse -> match -> action for each handed-off kind, precedence, trust, stats.

use ext_rules::*;

fn rule(raw: &str, trusted: bool) -> ExtRule {
    let mut r = ExtRule::new(ExtKind::Other, raw);
    r.trusted = trusted;
    r.list = "L".into();
    r
}

fn idx(rules: &[&str]) -> ExtIndex {
    ExtIndex::build(&rules.iter().map(|r| rule(r, true)).collect::<Vec<_>>())
}

fn req<'a>(
    url: &'a str,
    method: &'a str,
    rt: ResourceType,
    src: Option<&'a str>,
) -> RequestInfo<'a> {
    RequestInfo {
        source_url: src,
        ..RequestInfo::new(url, method, rt)
    }
}

fn get<'a>(url: &'a str, rt: ResourceType) -> RequestInfo<'a> {
    req(url, "GET", rt, Some("https://page.example/"))
}

fn resp<'a>(ct: &'a str, extra: &'a [(&'a str, &'a str)]) -> (Vec<(&'a str, &'a str)>, u16) {
    let mut h = vec![("Content-Type", ct)];
    h.extend_from_slice(extra);
    (h, 200)
}

fn plan<'a>(
    i: &'a ExtIndex,
    r: &RequestInfo<'_>,
    ct: &str,
    extra: &[(&str, &str)],
) -> ResponsePlan<'a> {
    let (h, status) = resp(ct, extra);
    i.response_plan(
        r,
        &ResponseInfo {
            status,
            headers: &h,
        },
    )
}

// ---- request side ------------------------------------------------------------------------------

#[test]
fn denyallow() {
    // AdGuard KB "$denyallow": the rule applies except to the listed hosts (and their subdomains).
    let i = idx(&["/ads/*$denyallow=good.example,script"]);
    assert!(i
        .request_decision(&get("https://bad.example/ads/x.js", ResourceType::Script))
        .block
        .is_some());
    assert!(i
        .request_decision(&get("https://good.example/ads/x.js", ResourceType::Script))
        .block
        .is_none());
    assert!(i
        .request_decision(&get(
            "https://cdn.good.example/ads/x.js",
            ResourceType::Script
        ))
        .block
        .is_none());
    assert!(i
        .request_decision(&get("https://bad.example/ads/x.png", ResourceType::Image))
        .block
        .is_none());
    // exception for a denyallow rule
    let i = idx(&[
        "/ads/*$denyallow=good.example",
        "@@||bad.example^$denyallow=good.example",
    ]);
    assert!(i
        .request_decision(&get("https://bad.example/ads/x", ResourceType::Script))
        .block
        .is_none());
    assert!(i
        .request_decision(&get("https://other.example/ads/x", ResourceType::Script))
        .block
        .is_some());
}

#[test]
fn method() {
    let i = idx(&[
        "||api.example^$method=post|put",
        "||beacon.example^$method=~get",
    ]);
    let post = |u| req(u, "POST", ResourceType::Xhr, Some("https://page.example/"));
    assert!(i
        .request_decision(&post("https://api.example/x"))
        .block
        .is_some());
    assert!(i
        .request_decision(&get("https://api.example/x", ResourceType::Xhr))
        .block
        .is_none());
    assert!(i
        .request_decision(&post("https://beacon.example/x"))
        .block
        .is_some());
    assert!(i
        .request_decision(&get("https://beacon.example/x", ResourceType::Xhr))
        .block
        .is_none());
    assert!(i
        .request_decision(&req(
            "https://api.example/x",
            "put",
            ResourceType::Xhr,
            None
        ))
        .block
        .is_some());
}

#[test]
fn to_with_pattern() {
    let i = idx(&["/track$to=a.example|b.example,xhr", "@@/track$to=b.example"]);
    assert!(i
        .request_decision(&get("https://a.example/track", ResourceType::Xhr))
        .block
        .is_some());
    assert!(i
        .request_decision(&get("https://sub.a.example/track?x", ResourceType::Xhr))
        .block
        .is_some());
    assert!(i
        .request_decision(&get("https://b.example/track", ResourceType::Xhr))
        .block
        .is_none());
    assert!(i
        .request_decision(&get("https://c.example/track", ResourceType::Xhr))
        .block
        .is_none());
    assert!(i
        .request_decision(&get("https://a.example/track", ResourceType::Image))
        .block
        .is_none());
}

#[test]
fn popup_is_inert_without_signal() {
    let i = idx(&["||pop.example^$popup"]);
    let mut r = req("https://pop.example/", "GET", ResourceType::Document, None);
    assert!(i.request_decision(&r).block.is_none());
    r.opened_as_popup = true;
    assert!(i.request_decision(&r).block.is_some());
    r.resource_type = ResourceType::Script;
    assert!(i.request_decision(&r).block.is_none());
}

#[test]
fn urltransform() {
    let i = idx(&["||site.example/*$urltransform=/&utm_\\w+=[^&]*//"]);
    let d = i.request_decision(&get(
        "https://site.example/p?a=1&utm_src=x&b=2",
        ResourceType::Document,
    ));
    assert_eq!(
        d.rewrite_url.as_ref().map(|x| x.0.as_str()),
        Some("https://site.example/p?a=1&b=2")
    );
    assert!(i
        .request_decision(&get("https://site.example/p?a=1", ResourceType::Document))
        .rewrite_url
        .is_none());
    // a transform that would leave the origin is ignored
    let i = idx(&["||site.example/*$urltransform=/^\\/p/\\/\\/evil.example\\/p/"]);
    assert!(i
        .request_decision(&get("https://site.example/p", ResourceType::Document))
        .rewrite_url
        .is_none());
    // exception
    let i = idx(&[
        "||site.example/*$urltransform=/p/q/",
        "@@||site.example/*$urltransform",
    ]);
    assert!(i
        .request_decision(&get("https://site.example/p", ResourceType::Document))
        .rewrite_url
        .is_none());
}

#[test]
fn request_cookie_and_removeheader() {
    let i = idx(&[
        "||site.example^$cookie=track",
        "||site.example^$removeheader=request:x-client-data",
        "||site.example^$cookie=sess;maxAge=10",
    ]);
    let hdrs = [("Cookie", "a=1; track=2"), ("X-Client-Data", "z")];
    let r = RequestInfo {
        headers: &hdrs,
        ..get("https://site.example/", ResourceType::Document)
    };
    let d = i.request_decision(&r);
    assert!(d
        .header_edits
        .contains(&HeaderEdit::SetAll("cookie".into(), vec!["a=1".into()])));
    assert!(d
        .header_edits
        .contains(&HeaderEdit::Remove("x-client-data".into())));
    assert!(i.needs_request_headers());
    // everything removed -> header dropped
    let i = idx(&["||site.example^$cookie"]);
    let hdrs = [("cookie", "a=1")];
    let r = RequestInfo {
        headers: &hdrs,
        ..get("https://site.example/", ResourceType::Document)
    };
    assert_eq!(
        i.request_decision(&r).header_edits,
        vec![HeaderEdit::Remove("cookie".into())]
    );
    // exception
    let i = idx(&["||site.example^$cookie", "@@||site.example^$cookie"]);
    assert!(i.request_decision(&r).is_noop());
}

#[test]
fn source_domain_and_party() {
    let i = idx(&["||t.example^$method=post,domain=a.example|~x.a.example,third-party"]);
    let p = |src| req("https://t.example/x", "POST", ResourceType::Xhr, Some(src));
    assert!(i.request_decision(&p("https://a.example/")).block.is_some());
    assert!(i
        .request_decision(&p("https://sub.a.example/"))
        .block
        .is_some());
    assert!(i
        .request_decision(&p("https://x.a.example/"))
        .block
        .is_none());
    assert!(i
        .request_decision(&p("https://other.example/"))
        .block
        .is_none());
    let i = idx(&["||t.example^$method=post,~third-party"]);
    assert!(i
        .request_decision(&req(
            "https://t.example/x",
            "POST",
            ResourceType::Xhr,
            Some("https://www.t.example/")
        ))
        .block
        .is_some());
    assert!(i
        .request_decision(&p("https://other.example/"))
        .block
        .is_none());
}

#[test]
fn important_and_badfilter() {
    let i = idx(&[
        "||t.example^$method=post,important",
        "@@||t.example^$method=post",
    ]);
    let post = req("https://t.example/", "POST", ResourceType::Xhr, None);
    assert!(
        i.request_decision(&post).block.is_some(),
        "important beats a plain exception"
    );
    let i = idx(&[
        "||t.example^$method=post,important",
        "@@||t.example^$method=post,important",
    ]);
    assert!(i.request_decision(&post).block.is_none());
    let i = idx(&[
        "||t.example^$method=post",
        "||t.example^$method=post,badfilter",
    ]);
    assert!(i.is_empty());
    assert_eq!(i.stats().per_kind["other"].badfiltered, 1);
    // option order does not matter for badfilter pairing
    let i = idx(&[
        "||t.example^$method=post,xhr",
        "||t.example^$xhr,method=post,badfilter",
    ]);
    assert!(i.is_empty());
}

// ---- response side -----------------------------------------------------------------------------

#[test]
fn replace() {
    let i = idx(&[
        "||site.example^$replace=/adsbygoogle/noads/i",
        "||site.example^$replace=/foo/bar/,domain=other.example",
    ]);
    let r = get("https://site.example/a.html", ResourceType::Document);
    let p = plan(&i, &r, "text/html", &[]);
    assert_eq!(&*p.apply_body(b"<AdsByGoogle>"), b"<noads>");
    assert!(p.needs_body() && p.body_limit() > 0);
    // not textual
    assert!(plan(&i, &r, "image/png", &[]).body.is_empty());
    // oversized by Content-Length
    assert!(plan(&i, &r, "text/html", &[("Content-Length", "99999999")])
        .body
        .is_empty());
    // encoded body flagged
    assert!(plan(&i, &r, "text/html", &[("Content-Encoding", "gzip")]).requires_decoded_body);
    // exceptions: empty disables all, value disables one
    let i = idx(&[
        "||s.example^$replace=/a/b/",
        "||s.example^$replace=/c/d/",
        "@@||s.example^$replace=/a/b/",
    ]);
    let r = get("https://s.example/", ResourceType::Document);
    assert_eq!(&*plan(&i, &r, "text/html", &[]).apply_body(b"ac"), b"ad");
    let i = idx(&["||s.example^$replace=/a/b/", "@@||s.example^$replace"]);
    assert!(plan(&i, &r, "text/html", &[]).body.is_empty());
    // $content exception (AdGuard) also lifts replace
    let i = idx(&["||s.example^$replace=/a/b/", "@@||s.example^$content"]);
    assert!(plan(&i, &r, "text/html", &[]).body.is_empty());
}

#[test]
fn jsonprune_xmlprune_hls() {
    let i = idx(&[
        "||api.example^$jsonprune=\\$..adPlacements",
        "||api.example^$jsonprune=\\$.meta.trk",
        "||vast.example^$xmlprune=//Ad[@sequence='1']",
        "||cdn.example/*.m3u8$hls=/ads\\.example/",
    ]);
    let r = get("https://api.example/v1", ResourceType::Xhr);
    let p = plan(&i, &r, "application/json; charset=utf-8", &[]);
    assert_eq!(p.body.len(), 1, "both jsonprune rules share one parse");
    assert_eq!(
        &*p.apply_body(br#"{"a":{"adPlacements":[1]},"meta":{"trk":1,"k":2}}"#),
        br#"{"a":{},"meta":{"k":2}}"#
    );
    assert!(plan(&i, &r, "text/html", &[]).body.is_empty());
    let r = get("https://vast.example/x", ResourceType::Xhr);
    let p = plan(&i, &r, "text/xml", &[]);
    assert_eq!(
        &*p.apply_body(b"<V><Ad sequence=\"1\"/><Ad sequence=\"2\"/></V>"),
        b"<V><Ad sequence=\"2\"/></V>"
    );
    let r = get("https://cdn.example/live.m3u8", ResourceType::Media);
    let p = plan(&i, &r, "application/vnd.apple.mpegurl", &[]);
    let out = p.apply_body(b"#EXTM3U\n#EXTINF:5,\nhttps://ads.example/a.ts\n#EXTINF:5,\ns.ts\n");
    assert_eq!(&*out, b"#EXTM3U\n#EXTINF:5,\ns.ts\n");
}

#[test]
fn removeheader_permissions_header() {
    let i = idx(&[
        "||site.example^$removeheader=refresh",
        "||site.example^$permissions=geolocation=()\\, camera=()",
        "||site.example^$header=x-ad:~ok,script",
        "||site.example^$header=via:/google/i",
    ]);
    let r = get("https://site.example/", ResourceType::Document);
    let p = plan(&i, &r, "text/html", &[("Refresh", "5;url=/x")]);
    assert!(p
        .header_edits
        .contains(&HeaderEdit::Remove("refresh".into())));
    assert!(p.header_edits.contains(&HeaderEdit::Append(
        "permissions-policy".into(),
        "geolocation=(), camera=()".into()
    )));
    assert!(p.block.is_none());
    // permissions only on documents
    let p = plan(
        &i,
        &get("https://site.example/a.js", ResourceType::Script),
        "text/javascript",
        &[],
    );
    assert!(!p
        .header_edits
        .iter()
        .any(|e| e.name() == "permissions-policy"));
    // $header
    let s = get("https://site.example/a.js", ResourceType::Script);
    assert!(plan(&i, &s, "text/javascript", &[("X-Ad", "yes")])
        .block
        .is_some());
    assert!(plan(&i, &s, "text/javascript", &[("X-Ad", "ok")])
        .block
        .is_none());
    assert!(plan(&i, &r, "text/html", &[("Via", "1.1 Google")])
        .block
        .is_some());
}

#[test]
fn set_cookie_rules() {
    let i = idx(&[
        "||site.example^$cookie=/^_ga/",
        "||site.example^$cookie=sid;maxAge=60;sameSite=strict",
    ]);
    let r = get("https://site.example/", ResourceType::Document);
    let p = plan(
        &i,
        &r,
        "text/html",
        &[
            ("Set-Cookie", "_ga=1; Path=/"),
            (
                "Set-Cookie",
                "sid=2; Path=/; Expires=Wed, 21 Oct 2099 07:28:00 GMT",
            ),
            ("Set-Cookie", "other=3"),
        ],
    );
    assert_eq!(
        p.header_edits,
        vec![HeaderEdit::SetAll(
            "set-cookie".into(),
            vec![
                "sid=2; Path=/; Max-Age=60; SameSite=Strict".into(),
                "other=3".into()
            ]
        )]
    );
}

#[test]
fn html_filters_and_injections() {
    let i = idx(&[
        "page.example##^script:has-text(adblock)",
        "page.example$$script[tag-content=\"detect\"][max-length=\"300\"]",
        "page.example#%#window.__x = 1;",
        "page.example#%#//scriptlet('weird-one', 'a')",
        "page.example#$?#div:has(> a) { display: none }",
        "other.example##^script",
    ]);
    let r = req(
        "https://www.page.example/",
        "GET",
        ResourceType::Document,
        None,
    );
    let p = plan(&i, &r, "text/html; charset=utf-8", &[]);
    assert_eq!(p.html_removals.len(), 2);
    assert_eq!(p.html_removals[1].max_len, 300);
    assert!(
        p.html_removals[0].text_matches("if (adblock) {}")
            && !p.html_removals[0].text_matches("hello")
    );
    assert_eq!(p.injections.len(), 3);
    assert!(p.needs_html_rewrite());
    assert_eq!(
        p.injections[0].script_body().as_deref(),
        Some("window.__x = 1;")
    );
    assert!(p.injections[1]
        .script_body()
        .unwrap()
        .contains("\"weird-one\""));
    assert!(matches!(
        p.injections[2],
        Injection::ProceduralCss { style: Some(_), .. }
    ));
    // non-HTML responses and other hosts get nothing
    assert!(plan(&i, &r, "application/json", &[]).is_noop());
    let o = req("https://nope.example/", "GET", ResourceType::Document, None);
    assert!(plan(&i, &o, "text/html", &[]).html_removals.is_empty());
    // exceptions
    let i = idx(&[
        "##^script:has-text(adblock)",
        "page.example#@#^script:has-text(adblock)",
        "page.example#%#a()",
        "page.example#@%#",
        "x.example#%#b()",
        "@@||x.example^$jsinject",
    ]);
    let p = plan(&i, &r, "text/html", &[]);
    assert!(p.html_removals.is_empty() && p.injections.is_empty());
    let x = req("https://x.example/", "GET", ResourceType::Document, None);
    assert!(plan(&i, &x, "text/html", &[]).injections.is_empty());
    assert_eq!(plan(&i, &x, "text/html", &[]).html_removals.len(), 1);
    // uBO ##^responseheader()
    let i = idx(&["site.example##^responseheader(refresh)"]);
    let p = plan(
        &i,
        &req("https://site.example/", "GET", ResourceType::Document, None),
        "text/html",
        &[],
    );
    assert_eq!(p.header_edits, vec![HeaderEdit::Remove("refresh".into())]);
}

#[test]
fn document_exception_lifts_everything() {
    let i = idx(&[
        "||s.example^$replace=/a/b/",
        "s.example##^script",
        "s.example#%#x()",
        "@@||s.example^$document",
    ]);
    let r = req("https://s.example/", "GET", ResourceType::Document, None);
    assert!(plan(&i, &r, "text/html", &[]).is_noop());
}

// ---- trust, stats, errors ----------------------------------------------------------------------

#[test]
fn untrusted_code_rules_are_dropped_and_counted() {
    let raws = [
        "||s.example^$replace=/a/b/",
        "||s.example/*$urltransform=/a/b/",
        "s.example#%#x()",
        "s.example#%#//scriptlet('n')",
        "s.example#$#log hi",
        "s.example##^script",
        "||s.example^$jsonprune=\\$.x",
        "@@||s.example^$replace",
    ];
    let mut rules: Vec<ExtRule> = raws.iter().map(|r| rule(r, false)).collect();
    for r in &mut rules[..4] {
        r.list = "ads".into();
    }
    rules[4].list = "snippets".into();
    let i = ExtIndex::build(&rules);
    let st = i.stats();
    assert_eq!(st.dropped_untrusted_by_list["ads"], 4);
    assert_eq!(st.dropped_untrusted_by_list["snippets"], 1);
    assert_eq!(i.len(), 3, "html filter, jsonprune and the exception stay");
    // trusting a list by id
    let mut o = BuildOptions::default();
    o.trusted_lists.insert("ads".into());
    let i = ExtIndex::build_with(&rules, &o);
    assert_eq!(i.len(), 7);
    assert_eq!(i.stats().dropped_untrusted_by_list.len(), 1);
}

#[test]
fn stats_and_errors() {
    let rules = vec![
        ExtRule::new(ExtKind::Replace, "||a^$replace=/x/y/"),
        ExtRule::new(ExtKind::Replace, "||a^$replace=/(?=x)/y/"),
        ExtRule::new(ExtKind::Replace, "||a^$replace"),
        ExtRule::new(ExtKind::Method, "||a^$method=get,redirect=x"),
        ExtRule::new(ExtKind::RemoveHeader, "||a^$removeheader=content-length"),
    ];
    let mut r2 = rules.clone();
    r2[0].trusted = true;
    let i = ExtIndex::build(&r2);
    let s = i.stats();
    assert_eq!(s.total, 5);
    let rep = &s.per_kind["replace"];
    assert_eq!(
        (rep.parsed, rep.active, rep.unsupported, rep.parse_errors),
        (1, 1, 1, 1)
    );
    assert_eq!(s.per_kind["method"].unsupported, 1);
    assert_eq!(s.per_kind["removeheader"].parse_errors, 1);
    assert_eq!(s.issues.len(), 4);
    assert!(s.issues[0].reason.contains("look-around"));
    let mut o = BuildOptions::default();
    o.max_issues = 1;
    let i = ExtIndex::build_with(&r2, &o);
    assert_eq!((i.stats().issues.len(), i.stats().issues_truncated), (1, 3));
}

#[test]
fn quick_exit_flags() {
    let i = ExtIndex::build(&[]);
    assert!(
        i.is_empty() && !i.has_request_rules() && !i.has_response_rules() && i.kinds_present() == 0
    );
    assert!(i
        .request_decision(&get("https://a.example/", ResourceType::Script))
        .is_noop());
    let i = idx(&["||a.example^$method=post"]);
    assert!(i.has_request_rules() && !i.has_response_rules());
    assert_eq!(i.kinds_present(), target::BLOCK);
    let i = idx(&["a.example##^script"]);
    assert!(!i.has_request_rules() && i.has_html_rules() && i.has_response_rules());
}

#[test]
fn index_is_send_sync() {
    fn ok<T: Send + Sync>() {}
    ok::<ExtIndex>();
}

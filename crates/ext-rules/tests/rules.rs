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
    assert!(p.header_edits.contains(&HeaderEdit::SetAll(
        "permissions-policy".into(),
        vec!["geolocation=(), camera=()".into()]
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
        "s.example#%#y()",
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
        ExtRule::new(ExtKind::Method, "||a^$method=get,app=x.exe"),
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
    let o = BuildOptions {
        max_issues: 1,
        ..Default::default()
    };
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

// ---- $permissions must never loosen the site's own policy -------------------------------------

/// Header lines the browser would see after the plan's edits.
fn pp_after(site: &[&str], edits: &[HeaderEdit]) -> Vec<String> {
    let mut lines: Vec<String> = site.iter().map(|s| s.to_string()).collect();
    for e in edits.iter().filter(|e| e.name() == "permissions-policy") {
        match e {
            HeaderEdit::Append(_, v) => lines.push(v.clone()),
            HeaderEdit::SetAll(_, v) => lines = v.clone(),
            HeaderEdit::Remove(_) => lines.clear(),
        }
    }
    lines
}

fn pp_plan(trusted: bool, raw: &str, site: &[&str]) -> Vec<String> {
    let i = ExtIndex::build(&[rule(raw, trusted)]);
    let extra: Vec<(&str, &str)> = site.iter().map(|v| ("Permissions-Policy", *v)).collect();
    let p = plan(
        &i,
        &get("https://site.example/", ResourceType::Document),
        "text/html",
        &extra,
    );
    pp_after(site, &p.header_edits)
}

#[test]
fn untrusted_permissions_cannot_loosen_the_site_policy() {
    // A widening member from an untrusted list is dropped outright.
    let i = ExtIndex::build(&[rule("||site.example^$permissions=camera=*", false)]);
    assert_eq!(i.len(), 0);
    assert_eq!(i.stats().dropped_untrusted_by_list["L"], 1);
    let out = pp_plan(
        false,
        "||site.example^$permissions=camera=*",
        &["camera=()"],
    );
    assert_eq!(out, vec!["camera=()"]);
    // Restrictive members tighten, in ONE header, and keep the site's other members.
    let out = pp_plan(
        false,
        "||site.example^$permissions=camera=()",
        &["camera=self, geolocation=(self)"],
    );
    assert_eq!(out.len(), 1);
    assert!(
        out[0].contains("camera=()") && out[0].contains("geolocation=(self)"),
        "{out:?}"
    );
    // Several site header lines collapse into the one merged header.
    let out = pp_plan(
        false,
        "||site.example^$permissions=camera=()",
        &["camera=*", "microphone=self"],
    );
    assert_eq!(out.len(), 1, "{out:?}");
    assert!(
        out[0].contains("camera=()") && out[0].contains("microphone=self"),
        "{out:?}"
    );
    // No site header: the restriction is added.
    assert_eq!(
        pp_plan(false, "||site.example^$permissions=camera=()", &[]),
        vec!["camera=()"]
    );
}

#[test]
fn permissions_values_are_validated() {
    for bad in [
        "||site.example^$permissions=camera",
        "||site.example^$permissions=Camera=(",
        "||site.example^$permissions=camera=(foo)",
        "||site.example^$permissions=cam era=()",
    ] {
        assert!(
            matches!(parse_rule(&rule(bad, true)), Err(RuleError::Invalid(_))),
            "{bad}"
        );
    }
}

#[test]
fn trusted_permissions_may_set_any_member() {
    let out = pp_plan(
        true,
        "||site.example^$permissions=camera=*",
        &["camera=()", "fullscreen=self"],
    );
    assert_eq!(out.len(), 1);
    assert!(
        out[0].contains("camera=*") && out[0].contains("fullscreen=self"),
        "{out:?}"
    );
}

// ---- style injection must not be able to load URLs --------------------------------------------

const UNSAFE_STYLES: &[&str] = &[
    "background: url(http://evil.test/x)",
    "background:URL( 'http://evil.test/x' )",
    "background-image: image-set(\"http://evil.test/x\" 1x)",
    "background: -webkit-image-set(url(x) 1x)",
    "content: src(\"x\")",
    "color: red; @import 'http://evil.test/x.css'",
    "width: expression(alert(1))",
    "background: u\\72l(http://evil.test/x)",
    "color: red /* x */",
    "color: red } body { background: red",
    "color: red; @font-face { src: x }",
    "-moz-binding: foo",
    "background: image(\"x\")",
    "background: attr(data-u type(<url>))",
];

#[test]
fn unsafe_style_declarations_are_rejected_from_any_list() {
    for st in UNSAFE_STYLES {
        for trusted in [false, true] {
            let raw = format!("a.example#$?#body {{ {st} }}");
            assert!(parse_rule(&rule(&raw, trusted)).is_err(), "{raw}");
        }
    }
    let ok = parse_rule(&rule(
        "a.example#$#body { display: none !important; color: red }",
        false,
    ));
    assert!(ok.is_ok());
}

// ---- $cookie from untrusted lists may only remove or tighten ----------------------------------

fn cookie_edit(trusted: bool, raw: &str, set_cookie: &str) -> Option<Vec<String>> {
    let i = ExtIndex::build(&[rule(raw, trusted)]);
    let p = plan(
        &i,
        &get("https://site.example/", ResourceType::Document),
        "text/html",
        &[("Set-Cookie", set_cookie)],
    );
    p.header_edits.iter().find_map(|e| match e {
        HeaderEdit::SetAll(n, v) if n == "set-cookie" => Some(v.clone()),
        _ => None,
    })
}

#[test]
fn untrusted_cookie_rules_cannot_weaken_a_cookie() {
    let weak = "c=1; Path=/; Secure; HttpOnly; Max-Age=60; SameSite=Strict";
    // Loosening SameSite or extending the lifetime changes nothing.
    assert_eq!(
        cookie_edit(false, "||site.example^$cookie=c;sameSite=none", weak),
        None
    );
    assert_eq!(
        cookie_edit(false, "||site.example^$cookie=c;sameSite=lax", weak),
        None
    );
    assert_eq!(
        cookie_edit(false, "||site.example^$cookie=c;maxAge=999999", weak),
        None
    );
    // A cookie without an explicit lifetime is not given one (it might outlive the session).
    assert_eq!(
        cookie_edit(
            false,
            "||site.example^$cookie=c;maxAge=999999",
            "c=1; Secure"
        ),
        None
    );
    // Tightening applies and keeps Secure / HttpOnly.
    let out = cookie_edit(
        false,
        "||site.example^$cookie=c;maxAge=30;sameSite=strict",
        "c=1; Path=/; Secure; HttpOnly; Max-Age=60; SameSite=Lax",
    )
    .unwrap();
    assert_eq!(out.len(), 1);
    let line = &out[0];
    for want in ["Secure", "HttpOnly", "Max-Age=30", "SameSite=Strict"] {
        assert!(line.contains(want), "{line}");
    }
    // An unset SameSite is Lax by default: Strict is a tightening, None is not.
    assert!(cookie_edit(
        false,
        "||site.example^$cookie=c;sameSite=strict",
        "c=1; Secure"
    )
    .is_some());
    assert_eq!(
        cookie_edit(
            false,
            "||site.example^$cookie=c;sameSite=none",
            "c=1; Secure"
        ),
        None
    );
    // Removal is always fine.
    assert_eq!(
        cookie_edit(false, "||site.example^$cookie=c", weak),
        Some(vec![])
    );
    // Trusted lists keep the full behaviour.
    let out = cookie_edit(true, "||site.example^$cookie=c;sameSite=none", weak).unwrap();
    assert!(
        out[0].contains("SameSite=None") && out[0].contains("Secure"),
        "{out:?}"
    );
}

// ---- page-scoped cosmetic exceptions ------------------------------------------------------------

#[test]
fn page_scoped_exceptions_report_what_they_switch_off() {
    use ext_rules::target::{JS, PCSS, SCRIPTLET, SNIPPET, SPECIFICHIDE};
    let r = get("https://site.example/page", ResourceType::Document);
    let disabled = |rule: &str| plan(&idx(&[rule]), &r, "text/html", &[]).disabled;
    let d = disabled("@@||site.example^$elemhide");
    assert!(
        d & PCSS != 0 && d & SPECIFICHIDE != 0 && d & JS == 0,
        "{d:#b}"
    );
    let d = disabled("@@||site.example^$specifichide");
    assert!(d & SPECIFICHIDE != 0 && d & PCSS == 0, "{d:#b}");
    let d = disabled("@@||site.example^$jsinject");
    assert!(d & (JS | SCRIPTLET | SNIPPET) == (JS | SCRIPTLET | SNIPPET) && d & PCSS == 0);
    assert_eq!(
        disabled("@@||site.example^$document") & (PCSS | JS),
        PCSS | JS
    );
    // another site, and a rule scoped to a cosmetic selector, switch nothing off
    assert_eq!(disabled("@@||other.example^$elemhide"), 0);
    assert_eq!(disabled("site.example#@#.ad"), 0);
}

#[test]
fn removeparam_forms_and_exceptions() {
    let url = "https://s.example/p?a=1&utm_x=2&keep=3&utm_y=4#h";
    let clean = |rules: &[&str], rt| {
        idx(rules)
            .request_decision(&get(url, rt))
            .cleaned_url
            .map(|x| x.0)
    };
    for rt in [ResourceType::Document, ResourceType::Image] {
        assert_eq!(
            clean(&["||s.example^$removeparam=/^utm_/"], rt).as_deref(),
            Some("https://s.example/p?a=1&keep=3#h")
        );
        assert_eq!(
            clean(&["||s.example^$removeparam=~keep"], rt).as_deref(),
            Some("https://s.example/p?keep=3#h")
        );
        assert_eq!(
            clean(&["||s.example^$removeparam"], rt).as_deref(),
            Some("https://s.example/p#h")
        );
    }
    // exceptions: by value, bare, and `$important` beats a plain exception
    let r = "||s.example^$removeparam=/^utm_/";
    assert_eq!(
        clean(
            &[r, "@@||s.example^$removeparam=/^utm_/"],
            ResourceType::Document
        ),
        None
    );
    assert_eq!(
        clean(&[r, "@@||s.example^$removeparam"], ResourceType::Document),
        None
    );
    assert!(clean(
        &[r, "@@||s.example^$removeparam=other"],
        ResourceType::Document
    )
    .is_some());
    // no query / nothing matched: no decision at all
    let i = idx(&[r]);
    assert!(i
        .request_decision(&get("https://s.example/p", ResourceType::Document))
        .is_noop());
    // the cleaned URL is a fixpoint (no redirect loop)
    let d = i.request_decision(&get(url, ResourceType::Document));
    let c = d.cleaned_url.unwrap().0;
    assert!(i
        .request_decision(&get(&c, ResourceType::Document))
        .is_noop());
    // $urltransform sees the cleaned URL; cleaned_url stays removeparam-only
    let i = idx(&[r, "||s.example^$urltransform=/keep=3/keep=4/"]);
    let d = i.request_decision(&get(url, ResourceType::Document));
    assert_eq!(d.cleaned_url.unwrap().0, "https://s.example/p?a=1&keep=3#h");
    assert_eq!(d.rewrite_url.unwrap().0, "https://s.example/p?a=1&keep=4#h");
}

#[test]
fn removeparam_exemption_reports_exceptions() {
    let i = idx(&[
        "@@||s.example^$removeparam=utm",
        "@@||t.example^$removeparam",
    ]);
    let e = i
        .removeparam_exemption(&get("https://s.example/p?utm=1", ResourceType::Document))
        .unwrap();
    assert_eq!(e, (false, vec!["utm".to_string()]));
    assert!(
        i.removeparam_exemption(&get("https://t.example/p?utm=1", ResourceType::Image))
            .unwrap()
            .0
    );
    assert!(i
        .removeparam_exemption(&get("https://u.example/p", ResourceType::Image))
        .is_none());
}

#[test]
fn page_exempt_by_document_elemhide_jsinject() {
    for r in [
        "@@||d.example^$document",
        "@@||d.example^$elemhide",
        "@@||d.example^$jsinject",
    ] {
        let i = idx(&[r]);
        let q = RequestInfo::new("https://d.example/", "GET", ResourceType::Document);
        assert!(i.page_exempt(&q), "{r}");
        let q = RequestInfo::new("https://o.example/", "GET", ResourceType::Document);
        assert!(!i.page_exempt(&q), "{r}");
    }
    assert!(
        !idx(&["@@||d.example^$script"]).page_exempt(&RequestInfo::new(
            "https://d.example/",
            "GET",
            ResourceType::Document
        ))
    );
}

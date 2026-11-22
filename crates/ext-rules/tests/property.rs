//! Index-equals-brute-force properties, ABP pattern semantics against a regex reference, and
//! no-panic fuzzing. Deterministic seeds.

use ext_rules::*;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use regex::Regex;

const HOSTS: &[&str] = &[
    "a.example",
    "b.example",
    "sub.a.example",
    "x.sub.a.example",
    "ads.net",
    "cdn.ads.net",
    "t.co",
    "example.org",
    "page.example",
    "a.example.org",
    "notexample.org",
];
const PATHS: &[&str] = &[
    "/",
    "/ads/x.js",
    "/track?id=1",
    "/a/b/c.gif",
    "/banner.png",
    "/adserver/v1/img",
    "/x?u=a.example",
    "/banner12.png",
    "/ads/",
    "/Track/UP.js",
];

fn pick<'a, T: ?Sized>(r: &mut StdRng, v: &[&'a T]) -> &'a T {
    v[r.gen_range(0..v.len())]
}

fn gen_net_rule(r: &mut StdRng) -> String {
    let host = pick(r, HOSTS);
    let pat = match r.gen_range(0..11) {
        0 => format!("||{host}^"),
        1 => format!("||{host}/ads/"),
        2 => format!("||{host}"),
        3 => "/adserver/".to_string(),
        4 => "*/ads/*".to_string(),
        5 => "/track|".to_string(),
        6 => "/banner\\d*\\.png/".to_string(),
        7 => format!("|https://{host}/"),
        8 => "ads^".to_string(),
        9 => format!("||{host}^*/x"),
        _ => "".to_string(),
    };
    let mut opts: Vec<String> = Vec::new();
    match r.gen_range(0..9) {
        0 => opts.push(format!(
            "method={}",
            pick(r, &["post", "get|put", "~get", "post|~put"])
        )),
        1 => opts.push(format!(
            "denyallow={}",
            pick(r, &["a.example", "ads.net|t.co", "sub.a.example"])
        )),
        2 => opts.push(format!(
            "to={}",
            pick(
                r,
                &[
                    "a.example|b.example",
                    "~a.example",
                    "ads.net",
                    "example.org"
                ]
            )
        )),
        3 => opts.push("removeheader=request:x-a".into()),
        4 => opts.push(format!("cookie={}", pick(r, &["", "a", "/^_g/"]))),
        5 => opts.push("removeheader=refresh".into()),
        6 => opts.push("header=x-ad".into()),
        7 => opts.push("permissions=geolocation=()".into()),
        _ => opts.push(format!("replace=/a/{}/", r.gen_range(0..9))),
    }
    if r.gen_bool(0.3) {
        opts.push(format!(
            "domain={}",
            pick(
                r,
                &[
                    "a.example",
                    "~sub.a.example",
                    "a.example|~x.sub.a.example",
                    "page.example|t.co",
                    "ads.*"
                ]
            )
        ));
    }
    if r.gen_bool(0.3) {
        opts.push(
            pick(
                r,
                &[
                    "script",
                    "image",
                    "xhr",
                    "~script",
                    "document",
                    "third-party",
                    "~third-party",
                    "match-case",
                ],
            )
            .to_string(),
        );
    }
    if r.gen_bool(0.1) {
        opts.push("important".into());
    }
    let ex = if r.gen_bool(0.15) { "@@" } else { "" };
    format!("{ex}{pat}${}", opts.join(","))
}

fn gen_dom_rule(r: &mut StdRng) -> String {
    let doms = match r.gen_range(0..6) {
        0 => String::new(),
        1 => pick(r, HOSTS).to_string(),
        2 => format!("{},{}", pick(r, HOSTS), pick(r, HOSTS)),
        3 => format!("{},~{}", pick(r, HOSTS), pick(r, HOSTS)),
        4 => "a.*".to_string(),
        _ => format!("~{}", pick(r, HOSTS)),
    };
    let body = pick(
        r,
        &[
            "##^script:has-text(x)",
            "##^script",
            "#@#^script",
            "#%#foo()",
            "#@%#",
            "#?#div:has(p)",
            "$$script[tag-content=\"a\"]",
        ],
    );
    format!("{doms}{body}")
}

fn types() -> [ResourceType; 5] {
    [
        ResourceType::Script,
        ResourceType::Image,
        ResourceType::Xhr,
        ResourceType::Document,
        ResourceType::Subdocument,
    ]
}

#[test]
fn index_equals_linear_scan() {
    let mut r = StdRng::seed_from_u64(0xADB10C);
    let mut rules = Vec::new();
    for _ in 0..500 {
        let mut e = ExtRule::new(ExtKind::Other, &gen_net_rule(&mut r));
        e.trusted = true;
        rules.push(e);
    }
    for _ in 0..60 {
        let mut e = ExtRule::new(ExtKind::Other, &gen_dom_rule(&mut r));
        e.trusted = true;
        rules.push(e);
    }
    let idx = ExtIndex::build(&rules);
    assert!(
        idx.len() > 300,
        "most generated rules must parse (got {})",
        idx.len()
    );
    let (mut hits_req, mut hits_resp, mut hits_dom) = (0, 0, 0);
    for _ in 0..1500 {
        let host = pick(&mut r, HOSTS);
        let path = pick(&mut r, PATHS);
        let url = format!("https://{host}{path}");
        let src = if r.gen_bool(0.7) {
            Some(format!("https://{}/", pick(&mut r, HOSTS)))
        } else {
            None
        };
        let method = pick(&mut r, &["GET", "POST", "put"]);
        let info = RequestInfo {
            source_url: src.as_deref(),
            third_party: Some(r.gen_bool(0.5)),
            opened_as_popup: r.gen_bool(0.1),
            ..RequestInfo::new(&url, method, types()[r.gen_range(0..5)])
        };
        for resp in [false, true] {
            let a = idx.debug_net_matches(&info, resp, true);
            let b = idx.debug_net_matches(&info, resp, false);
            assert_eq!(a, b, "{url} src={src:?} {method} resp={resp}");
            if resp {
                hits_resp += a.len()
            } else {
                hits_req += a.len()
            }
        }
        let h = pick(&mut r, HOSTS);
        let a = idx.debug_dom_matches(h, true);
        assert_eq!(a, idx.debug_dom_matches(h, false), "{h}");
        hits_dom += a.len();
    }
    assert!(
        hits_req > 200 && hits_resp > 200 && hits_dom > 200,
        "{hits_req} {hits_resp} {hits_dom}"
    );
}

/// Reference ABP pattern -> regex translation (documented semantics).
fn abp_to_regex(p: &str) -> Regex {
    let (anchor_host, anchor_url, rest) = if let Some(r) = p.strip_prefix("||") {
        (true, false, r)
    } else if let Some(r) = p.strip_prefix('|') {
        (false, true, r)
    } else {
        (false, false, p)
    };
    let (end, rest) = match rest.strip_suffix('|') {
        Some(r) => (true, r),
        None => (false, rest),
    };
    let mut re = String::from("(?i)");
    if anchor_host {
        re.push_str(r"^[a-z][a-z0-9+.\-]*://(?:[^/?#]*\.)?");
    } else if anchor_url {
        re.push('^');
    }
    for c in rest.chars() {
        match c {
            '*' => re.push_str(".*"),
            '^' => re.push_str(r"(?:[^a-z0-9_.%\-]|$)"),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
    }
    if end {
        re.push('$');
    }
    Regex::new(&re).unwrap()
}

#[test]
fn abp_patterns_match_reference() {
    let mut r = StdRng::seed_from_u64(7);
    let frags = [
        "a", "b", "ab", "/", "^", "*", ".", "?", "=", "-", "_", "1", "||", "|", "x.a", "example",
    ];
    let chars = [
        "a", "b", "ab", "/", ".", "?", "=", "-", "_", "1", "&", "%", "X",
    ];
    let hosts = ["a.example", "b.a.example", "ab.com", "x.a.b"];
    let mut positives = 0;
    for _ in 0..2500 {
        let mut pat = String::new();
        for _ in 0..r.gen_range(1..6) {
            pat.push_str(frags[r.gen_range(0..frags.len())]);
        }
        let body = pat.trim_start_matches('|').trim_end_matches('|');
        if body.is_empty()
            || body.trim_matches('*').is_empty()
            || (pat.starts_with('/') && pat.ends_with('/') && pat.len() > 2)
        {
            continue;
        }
        // `||` must be followed by something host-like for the reference to be meaningful
        let url = {
            let mut s = format!("https://{}/", hosts[r.gen_range(0..hosts.len())]);
            for _ in 0..r.gen_range(0..7) {
                s.push_str(chars[r.gen_range(0..chars.len())]);
            }
            s
        };
        let rule = format!("{pat}$method=post");
        let e = ExtRule::new(ExtKind::Method, &rule);
        let idx = ExtIndex::build(&[e]);
        let info = RequestInfo {
            source_url: Some("https://p.example/"),
            ..RequestInfo::new(&url, "POST", ResourceType::Xhr)
        };
        let got = idx.request_decision(&info).block.is_some();
        let want = abp_to_regex(&pat).is_match(&url);
        if idx.is_empty() {
            continue;
        }
        assert_eq!(got, want, "pattern {pat:?} url {url:?}");
        positives += got as usize;
    }
    assert!(
        positives > 150,
        "reference test must exercise matches ({positives})"
    );
}

fn random_rule_text(r: &mut StdRng) -> String {
    const F: &[&str] = &[
        "||",
        "@@",
        "$",
        "~",
        ",",
        "=",
        "/",
        "\\",
        "^",
        "*",
        "|",
        "replace",
        "jsonprune",
        "xmlprune",
        "hls",
        "cookie",
        "removeheader",
        "permissions",
        "urltransform",
        "method",
        "header",
        "denyallow",
        "domain",
        "to",
        "popup",
        "important",
        "badfilter",
        "##",
        "#@#",
        "#%#",
        "#$#",
        "#?#",
        "#@%#",
        "$$",
        "$@$",
        "script",
        ":has-text(",
        "(",
        ")",
        "[",
        "]",
        "\"",
        "'",
        "a.com",
        ".",
        "xhr",
        "third-party",
        "match-case",
        "//scriptlet(",
        "tag-content",
        "max-length",
        "request:",
        ";",
        "maxAge=1",
        "sameSite=lax",
        "{",
        "}",
        " ",
        "\u{0}",
        "é",
        "~a.com",
        "|",
        "$.a..b",
        "[?(@.a==1)]",
        "(?=a)",
    ];
    let n = r.gen_range(1..14);
    let mut s = String::new();
    for _ in 0..n {
        if r.gen_bool(0.1) {
            s.push(char::from_u32(r.gen_range(1..0x2fff)).unwrap_or('?'));
        } else {
            s.push_str(F[r.gen_range(0..F.len())]);
        }
    }
    s
}

#[test]
fn arbitrary_rule_text_never_panics() {
    let mut r = StdRng::seed_from_u64(99);
    let url = "https://a.com/x?y=1";
    let hdrs = [
        ("Content-Type", "text/html"),
        ("Set-Cookie", "a=1"),
        ("X-Ad", "1"),
    ];
    let mut parsed = 0;
    for _ in 0..20000 {
        let raw = random_rule_text(&mut r);
        let mut e = ExtRule::new(ExtKind::Other, &raw);
        e.trusted = true;
        if parse_rule(&e).is_ok() {
            parsed += 1;
        }
        let idx = ExtIndex::build(&[e]);
        for rt in [ResourceType::Document, ResourceType::Xhr] {
            let req = RequestInfo {
                source_url: Some("https://b.com/"),
                headers: &hdrs,
                opened_as_popup: true,
                ..RequestInfo::new(url, "POST", rt)
            };
            let _ = idx.request_decision(&req);
            let p = idx.response_plan(
                &req,
                &ResponseInfo {
                    status: 200,
                    headers: &hdrs,
                },
            );
            let _ = p.apply_body(b"<html>{\"a\":1}</html>");
        }
    }
    assert!(
        parsed > 100,
        "fuzzer must reach the parsed paths ({parsed})"
    );
}

#[test]
fn arbitrary_bodies_never_panic() {
    let mut r = StdRng::seed_from_u64(5);
    let replace = ReplaceSpec::parse("/a(b*)/[$1]/gi").unwrap();
    let json = JsonPrune::parse("$..[\"a\",\"b\"] $.x[?(@.k=='v' || @.n>1)] a.[].c").unwrap();
    let xml = XmlPrune::parse("//a[@b='c']").unwrap();
    let hls = HlsPrune::parse("/ad/").unwrap();
    let frags: &[&[u8]] = &[
        b"{",
        b"}",
        b"[",
        b"]",
        b"\"a\"",
        b":",
        b",",
        b"1",
        b"-1.5e3",
        b"null",
        b"true",
        b"\"x\\\"\"",
        b"\\u00e9",
        b"<a b='c'>",
        b"</a>",
        b"<!--",
        b"-->",
        b"<![CDATA[",
        b"]]>",
        b"<?x?>",
        b"#EXTM3U\n",
        b"#EXTINF:5,\n",
        b"ad.ts\n",
        b"\xff",
        b"\x00",
        b" ",
        b"\n",
        b"<",
        b">",
        b"/",
        b"\"k\":\"v\"",
    ];
    for _ in 0..15000 {
        let mut b: Vec<u8> = Vec::new();
        for _ in 0..r.gen_range(0..30) {
            if r.gen_bool(0.1) {
                b.push(r.gen());
            } else {
                b.extend_from_slice(frags[r.gen_range(0..frags.len())]);
            }
        }
        let _ = apply_replace(&b, &replace);
        let _ = apply_jsonprune(&b, &[&json]);
        let _ = apply_xmlprune(&b, &[&xml]);
        let _ = apply_hls(&b, &[&hls]);
        let _ = apply_set_cookie(
            &String::from_utf8_lossy(&b),
            &[&CookieSpec::parse("a;maxAge=1").unwrap()],
        );
    }
}

use super::*;

const SECRET: &str = "S3CR3T-VALUE-d41d8cd98f00b204";

fn cx() -> Context<'static> {
    Context {
        host: "Shop.Example.com",
        path: "/cart",
        page_host: "www.example.com",
    }
}

fn on() -> AtomicBool {
    AtomicBool::new(true)
}

fn src(rule: &str) -> Source<'_> {
    Source {
        rule,
        list_id: Some("l"),
    }
}

fn put(log: &CookieLog, on: &AtomicBool, sid: u64, line: &str) {
    log.open(sid);
    log.record_response(on, sid, &cx(), [(line.as_bytes(), true)].into_iter(), &[]);
}

fn all(log: &CookieLog, sid: u64) -> Vec<CookieRecord> {
    log.since(sid, 0, 10_000, None).0
}

// -- parsing -------------------------------------------------------------------------------------

#[test]
fn parses_name_and_attributes_in_any_case_and_order() {
    let p = parse_set_cookie(
        b"id=abc; SECURE; httponly; PATH=/a/b; domain=.Example.COM; SameSite=STRICT; MAX-AGE=60; Partitioned",
    )
    .unwrap();
    assert_eq!(p.name, "id");
    let a = p.attrs;
    assert_eq!(a.domain.as_deref(), Some("example.com"));
    assert_eq!(a.path.as_deref(), Some("/a/b"));
    assert!(a.secure && a.http_only && a.partitioned);
    assert_eq!(a.same_site, Some(SameSite::Strict));
    assert_eq!(a.max_age, Some(60));
}

#[test]
fn the_value_is_never_part_of_a_parsed_cookie() {
    let p = parse_set_cookie(format!("sid={SECRET}; Path=/").as_bytes()).unwrap();
    assert!(!format!("{p:?}").contains(SECRET));
}

#[test]
fn quotes_and_equals_signs_in_values() {
    // The first `;` ends the pair and the first `=` ends the name; quotes are not special.
    let p = parse_set_cookie(format!("a=\"{SECRET}=x;y=z\"; Secure; Path=/p").as_bytes()).unwrap();
    assert_eq!(p.name, "a");
    assert!(p.attrs.secure);
    assert_eq!(p.attrs.path.as_deref(), Some("/p"));
    let p = parse_set_cookie(b"tok=a=b=c; HttpOnly").unwrap();
    assert_eq!(p.name, "tok");
    assert!(p.attrs.http_only);
    assert!(!format!("{p:?}").contains("b=c"));
}

#[test]
fn duplicate_attributes_take_the_last_one() {
    let p = parse_set_cookie(
        b"a=1; Max-Age=10; Max-Age=20; SameSite=Lax; SameSite=None; Path=/x; Path=/y",
    )
    .unwrap();
    assert_eq!(p.attrs.max_age, Some(20));
    assert_eq!(p.attrs.same_site, Some(SameSite::None));
    assert_eq!(p.attrs.path.as_deref(), Some("/y"));
}

#[test]
fn empty_and_odd_names() {
    assert_eq!(parse_set_cookie(b"=v; Path=/").unwrap().name, "");
    assert_eq!(parse_set_cookie(b"justvalue; Secure").unwrap().name, "");
    assert!(parse_set_cookie(b"").is_none());
    assert!(parse_set_cookie(b"=").is_none());
    assert!(parse_set_cookie(b"  ; Secure").is_none());
    assert_eq!(
        parse_set_cookie(b"  spaced name  = v").unwrap().name,
        "spaced name"
    );
}

#[test]
fn bad_attribute_values_are_ignored() {
    let a = parse_set_cookie(
        b"a=1; Max-Age=abc; Expires=nonsense; Path=relative; SameSite=weird; Domain=",
    )
    .unwrap()
    .attrs;
    assert_eq!(a, Attrs::default());
    assert_eq!(
        parse_set_cookie(b"a=1; Max-Age=-5").unwrap().attrs.max_age,
        Some(-5)
    );
    assert_eq!(
        parse_set_cookie(b"a=1; Max-Age=99999999999999999999999")
            .unwrap()
            .attrs
            .max_age,
        Some(i64::MAX)
    );
}

#[test]
fn expires_dates_in_the_forms_servers_send() {
    let want = Utc
        .with_ymd_and_hms(2099, 10, 21, 7, 28, 0)
        .unwrap()
        .timestamp();
    for d in [
        "Wed, 21 Oct 2099 07:28:00 GMT",
        "Wednesday, 21-Oct-2099 07:28:00 GMT",
        "Wed Oct 21 07:28:00 2099",
        "21 oct 2099 7:28:0",
    ] {
        assert_eq!(parse_cookie_date(d), Some(want), "{d}");
    }
    assert_eq!(parse_cookie_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
    // Two-digit years: 70-99 are 19xx, 0-69 are 20xx.
    assert_eq!(
        parse_cookie_date("Thu, 21-Oct-99 07:28:00 GMT"),
        Some(940490880)
    );
    assert_eq!(
        parse_cookie_date("Thu, 21-Oct-30 07:28:00 GMT"),
        Some(1918798080)
    );
    assert_eq!(parse_cookie_date("Wed, 32 Oct 2099 07:28:00 GMT"), None);
    assert_eq!(parse_cookie_date("Wed, 21 Oct 2099 25:28:00 GMT"), None);
    assert_eq!(parse_cookie_date(""), None);
}

#[test]
fn very_long_headers_are_bounded() {
    let big = format!(
        "n={}; Secure; Path=/{}",
        "v".repeat(100_000),
        "p".repeat(100_000)
    );
    let p = parse_set_cookie(big.as_bytes()).unwrap();
    // Cut at the parse cap, so the attributes after the value are not reached.
    assert_eq!(p.name, "n");
    let long_name = format!("{}=1", "n".repeat(10_000));
    assert_eq!(
        parse_set_cookie(long_name.as_bytes()).unwrap().name.len(),
        NAME_CAP
    );
    let long_path = format!("a=1; Path=/{}", "p".repeat(5000));
    assert_eq!(
        parse_set_cookie(long_path.as_bytes())
            .unwrap()
            .attrs
            .path
            .unwrap()
            .len(),
        PATH_CAP
    );
}

#[test]
fn non_utf8_bytes_do_not_break_parsing() {
    let mut raw = b"na".to_vec();
    raw.extend_from_slice(&[0xff, 0xfe]);
    raw.extend_from_slice(b"me=\xff\xfe; Secure");
    let p = parse_set_cookie(&raw).unwrap();
    assert!(p.name.starts_with("na") && p.name.ends_with("me"));
    assert!(p.attrs.secure);
    // Multi-byte names are cut on a character boundary.
    let name = "é".repeat(300);
    let p = parse_set_cookie(format!("{name}=1").as_bytes()).unwrap();
    assert!(p.name.len() <= NAME_CAP && p.name.chars().all(|c| c == 'é'));
}

#[test]
fn prefix_facts_follow_the_attributes() {
    let host = parse_set_cookie(b"__Host-a=1; Secure; Path=/").unwrap();
    assert_eq!(
        prefix_facts(&host.name, &host.attrs),
        Some(("__Host-", true))
    );
    let bad = parse_set_cookie(b"__Host-a=1; Secure; Path=/; Domain=x.com").unwrap();
    assert_eq!(
        prefix_facts(&bad.name, &bad.attrs),
        Some(("__Host-", false))
    );
    let sec = parse_set_cookie(b"__secure-a=1").unwrap();
    assert_eq!(
        prefix_facts(&sec.name, &sec.attrs),
        Some(("__Secure-", false))
    );
    assert_eq!(prefix_facts("plain", &Attrs::default()), None);
}

// -- recording -----------------------------------------------------------------------------------

#[test]
fn nothing_is_recorded_while_the_setting_is_off() {
    let log = CookieLog::default();
    let off = AtomicBool::new(false);
    log.record_response(&off, 1, &cx(), [(b"a=1".as_slice(), true)].into_iter(), &[]);
    log.record_blocked_send(&off, 1, &cx(), &[("a", "$cookie", None)]);
    assert!(log.is_empty());
    assert!(log.sessions.is_empty(), "not even a session is created");
    log.open(1);
    log.record_response(&off, 1, &cx(), [(b"a=1".as_slice(), true)].into_iter(), &[]);
    log.record_blocked_send(&off, 1, &cx(), &[("a", "$cookie", None)]);
    assert!(log.is_empty());
}

#[test]
fn a_value_appears_nowhere_in_the_ring_or_its_readout() {
    let log = CookieLog::default();
    log.open(1);
    log.open(2);
    log.open(3);
    let on = on();
    let lines = [
        format!("sess={SECRET}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600"),
        format!("other=\"{SECRET}\"; Domain=example.com"),
        format!("=\"{SECRET}\""),
        SECRET.to_string(),
        format!("tracker={SECRET}; Max-Age=999999999"),
    ];
    let touch = Touch {
        index: 4,
        stripped: false,
        max_age: Some((60, src("$cookie=tracker;maxAge=60"))),
        same_site: Some((SameSite::Strict, src("$cookie=tracker;sameSite=strict"))),
        rule: "$cookie=tracker;maxAge=60",
        list_id: Some("l1"),
    };
    log.record_response(
        &on,
        1,
        &cx(),
        lines.iter().map(|l| (l.as_bytes(), true)),
        &[touch],
    );
    let rows = all(&log, 1);
    assert_eq!(rows.len(), 5);
    let shown = format!("{log:?} {rows:?}");
    assert!(!shown.contains(SECRET), "{shown}");
    assert!(!shown.contains("S3CR3T"), "{shown}");
}

#[test]
fn effects_are_set_changed_stripped_and_blocked_send() {
    let log = CookieLog::default();
    log.open(1);
    log.open(2);
    log.open(3);
    let on = on();
    let lines = [
        "keep=1; Path=/",
        "gone=1; Path=/",
        "cap=1; Max-Age=86400; Expires=Wed, 21 Oct 2099 07:28:00 GMT; SameSite=None",
        "same=1; Max-Age=60",
    ];
    let touches = [
        Touch {
            index: 1,
            stripped: true,
            max_age: None,
            same_site: None,
            rule: "$cookie=gone",
            list_id: Some("l"),
        },
        Touch {
            index: 2,
            stripped: false,
            max_age: Some((3600, src("$cookie=cap;maxAge=3600"))),
            same_site: Some((SameSite::Lax, src("$cookie=cap;sameSite=lax"))),
            rule: "$cookie=cap;maxAge=3600;sameSite=lax",
            list_id: Some("l"),
        },
        // A rule that sets what the server already sent changes nothing.
        Touch {
            index: 3,
            stripped: false,
            max_age: Some((60, src("$cookie=same;maxAge=60"))),
            same_site: None,
            rule: "$cookie=same;maxAge=60",
            list_id: Some("l"),
        },
    ];
    log.record_response(
        &on,
        1,
        &cx(),
        lines.iter().map(|l| (l.as_bytes(), true)),
        &touches,
    );
    log.record_blocked_send(&on, 1, &cx(), &[("tr", "$cookie=tr", Some("l2"))]);
    let r = all(&log, 1);
    let effects: Vec<_> = r.iter().map(|x| x.effect).collect();
    assert_eq!(
        effects,
        [
            Effect::Set,
            Effect::Stripped,
            Effect::Changed,
            Effect::Set,
            Effect::BlockedSend
        ]
    );
    assert_eq!(r[1].rule.as_deref(), Some("$cookie=gone"));
    assert_eq!(r[1].list_id.as_deref(), Some("l"));
    let ch = &r[2].changes;
    assert_eq!(
        ch.iter()
            .map(|c| (
                c.attr,
                c.from.as_deref(),
                c.to.as_deref(),
                c.rule.as_deref()
            ))
            .collect::<Vec<_>>(),
        [
            (
                "max_age",
                Some("86400"),
                Some("3600"),
                Some("$cookie=cap;maxAge=3600")
            ),
            (
                "expires",
                Some("4096250880"),
                None,
                Some("$cookie=cap;maxAge=3600")
            ),
            (
                "same_site",
                Some("none"),
                Some("lax"),
                Some("$cookie=cap;sameSite=lax")
            ),
        ]
    );
    assert!(ch.iter().all(|c| c.list_id.as_deref() == Some("l")));
    assert!(r[3].rule.is_none() && r[3].changes.is_empty());
    assert_eq!(
        (r[4].name.as_str(), r[4].host.as_str()),
        ("tr", "shop.example.com")
    );
    assert_eq!(r[4].rule.as_deref(), Some("$cookie=tr"));
}

#[test]
fn touches_index_only_the_visible_lines() {
    // A line with bytes a HeaderValue refuses to show is not counted by the rules.
    let log = CookieLog::default();
    log.open(1);
    log.open(2);
    log.open(3);
    let on = on();
    let hidden = b"h\xffx=1".as_slice();
    let lines = [
        (hidden, false),
        (b"a=1".as_slice(), true),
        (b"b=1".as_slice(), true),
    ];
    let t = Touch {
        index: 1,
        stripped: true,
        max_age: None,
        same_site: None,
        rule: "r",
        list_id: None,
    };
    log.record_response(&on, 1, &cx(), lines.into_iter(), &[t]);
    let r = all(&log, 1);
    assert_eq!(
        r.iter()
            .map(|x| (x.name.as_str(), x.effect))
            .collect::<Vec<_>>()
            .len(),
        3
    );
    assert_eq!(r[0].effect, Effect::Set);
    assert_eq!(r[1].effect, Effect::Set);
    assert_eq!((r[2].name.as_str(), r[2].effect), ("b", Effect::Stripped));
}

#[test]
fn context_is_kept_without_query_and_third_party_is_derived() {
    let log = CookieLog::default();
    log.open(1);
    log.open(2);
    log.open(3);
    let on = on();
    log.record_response(
        &on,
        1,
        &Context {
            host: "cdn.tracker.net",
            path: "/p",
            page_host: "www.example.com",
        },
        [(b"a=1".as_slice(), true)].into_iter(),
        &[],
    );
    put(&log, &on, 1, "b=1");
    log.record_response(
        &on,
        1,
        &Context {
            host: "x.test",
            path: "/",
            page_host: "",
        },
        [(b"c=1".as_slice(), true)].into_iter(),
        &[],
    );
    let r = all(&log, 1);
    assert_eq!(r[0].third_party, Some(true));
    assert_eq!(r[1].third_party, Some(false));
    assert_eq!(r[2].third_party, None);
    assert_eq!(
        (
            r[1].host.as_str(),
            r[1].path.as_str(),
            r[1].page_host.as_str()
        ),
        ("shop.example.com", "/cart", "www.example.com")
    );
}

// -- storage -------------------------------------------------------------------------------------

#[test]
fn the_ring_is_bounded_and_keeps_the_newest() {
    let log = CookieLog::default();
    log.open(1);
    log.open(2);
    log.open(3);
    let on = on();
    for i in 0..RING_CAPACITY + 50 {
        put(&log, &on, 1, &format!("c{i}=1"));
    }
    let r = all(&log, 1);
    assert_eq!(r.len(), RING_CAPACITY);
    assert_eq!(r[0].name, "c50");
    assert_eq!(r.last().unwrap().name, format!("c{}", RING_CAPACITY + 49));
}

#[test]
fn the_ring_is_bounded_in_bytes_too() {
    let log = CookieLog::default();
    log.open(1);
    log.open(2);
    log.open(3);
    let on = on();
    let name = "n".repeat(NAME_CAP);
    for i in 0..RING_CAPACITY {
        put(
            &log,
            &on,
            1,
            &format!(
                "{name}{i}=1; Domain={}.example.com; Path=/{}",
                "d".repeat(200),
                "p".repeat(400)
            ),
        );
    }
    let r = log.sessions.get(&1).unwrap().ring.lock().unwrap().bytes;
    assert!(r <= RING_BYTES, "{r}");
    assert!(all(&log, 1).len() < RING_CAPACITY);
}

#[test]
fn clearing_and_forgetting_drop_everything() {
    let log = CookieLog::default();
    let on = on();
    put(&log, &on, 1, "a=1");
    put(&log, &on, 2, "b=1");
    log.forget(1);
    assert!(all(&log, 1).is_empty());
    assert!(!log.sessions.contains_key(&1));
    assert_eq!(all(&log, 2).len(), 1);
    log.clear();
    assert!(log.is_empty());
    assert!(all(&log, 2).is_empty());
    assert_eq!(
        format!("{log:?}"),
        "{2: Ring { last: 0, bytes: 0, entries: [] }}"
    );
    // Clearing leaves the session open: it records again.
    put(&log, &on, 2, "c=1");
    assert_eq!(all(&log, 2).len(), 1);
}

#[test]
fn a_response_in_flight_cannot_refill_after_switch_off() {
    let log = CookieLog::default();
    log.open(1);
    log.open(2);
    log.open(3);
    let flag = on();
    put(&log, &flag, 1, "a=1");
    flag.store(false, Ordering::Relaxed);
    log.clear();
    // The recorder passed its first check before the flag flipped; the lock re-check refuses.
    let obs = vec![Observed {
        name: "late".into(),
        attrs: Attrs::default(),
        effect: Effect::Set,
        changes: vec![],
        rule: None,
        list_id: None,
    }];
    log.push(&flag, 1, &cx(), obs);
    assert!(log.is_empty());
}

#[test]
fn sessions_never_see_each_other_and_their_number_is_bounded() {
    let log = CookieLog::default();
    let on = on();
    put(&log, &on, 1, "a=1");
    put(&log, &on, 2, "b=1");
    assert_eq!(all(&log, 1)[0].name, "a");
    assert_eq!(all(&log, 2)[0].name, "b");
    assert!(all(&log, 3).is_empty());
    for s in 10..10 + MAX_SESSIONS as u64 + 5 {
        put(&log, &on, s, "x=1");
        let holding = log
            .sessions
            .iter()
            .filter(|s| !s.ring.lock().unwrap().entries.is_empty())
            .count();
        assert!(holding <= MAX_SESSIONS, "{holding}");
    }
    // Every session is still open, only the oldest rings were emptied, never the newest.
    assert_eq!(log.sessions.len(), 2 + MAX_SESSIONS + 5);
    assert_eq!(all(&log, 10 + MAX_SESSIONS as u64 + 4).len(), 1);
}

// -- reading -------------------------------------------------------------------------------------

#[test]
fn since_and_limit_page_without_gaps_or_repeats() {
    let log = CookieLog::default();
    log.open(1);
    log.open(2);
    log.open(3);
    let on = on();
    for i in 0..25 {
        put(&log, &on, 1, &format!("c{i}=1"));
    }
    let mut seen = Vec::new();
    let mut since = 0;
    loop {
        let (rows, next, _) = log.since(1, since, 10, None);
        if rows.is_empty() {
            assert_eq!(next, since);
            break;
        }
        assert!(rows.len() <= 10);
        seen.extend(rows.into_iter().map(|r| r.name));
        since = next;
    }
    assert_eq!(seen, (0..25).map(|i| format!("c{i}")).collect::<Vec<_>>());
}

#[test]
fn the_host_filter_matches_the_site_and_its_subdomains_and_still_advances() {
    let log = CookieLog::default();
    log.open(1);
    log.open(2);
    log.open(3);
    let on = on();
    for (host, name) in [
        ("example.com", "apex"),
        ("www.example.com", "www"),
        ("a.b.example.com", "deep"),
        ("notexample.com", "lookalike"),
        ("example.com.evil.net", "suffix"),
        ("other.org", "other"),
    ] {
        log.record_response(
            &on,
            1,
            &Context {
                host,
                path: "/",
                page_host: "",
            },
            [(format!("{name}=1").as_bytes(), true)].into_iter(),
            &[],
        );
    }
    let (rows, next, _) = log.since(1, 0, 100, Some("shop.Example.com"));
    assert_eq!(
        rows.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
        ["apex", "www", "deep"]
    );
    // The cursor moved past the records the filter skipped.
    assert_eq!(next, log.since(1, 0, 100, None).1);
    assert!(log.since(1, next, 100, Some("example.com")).0.is_empty());
    assert_eq!(log.since(1, 0, 100, Some("")).0.len(), 6);
}

#[test]
fn a_cursor_from_before_a_restart_reads_from_the_start() {
    let log = CookieLog::default();
    log.open(1);
    log.open(2);
    log.open(3);
    let on = on();
    put(&log, &on, 1, "a=1");
    let (rows, _, _) = log.since(1, 9_999_999, 10, None);
    assert_eq!(rows.len(), 1);
}

#[test]
fn concurrent_inserts_never_cause_gaps_or_duplicates_for_a_polling_reader() {
    use std::sync::Arc;
    let log = Arc::new(CookieLog::default());
    log.open(1);
    let flag = Arc::new(on());
    let writers: Vec<_> = (0..4)
        .map(|w| {
            let (log, flag) = (log.clone(), flag.clone());
            std::thread::spawn(move || {
                for i in 0..500 {
                    log.record_response(
                        &flag,
                        1,
                        &Context {
                            host: "a.test",
                            path: "/",
                            page_host: "",
                        },
                        [(format!("w{w}c{i}=1").into_bytes().as_slice().to_vec(), true)]
                            .iter()
                            .map(|(b, v)| (b.as_slice(), *v)),
                        &[],
                    );
                }
            })
        })
        .collect();
    let mut seen: Vec<u64> = Vec::new();
    let mut since = 0;
    while seen.len() < 2000 {
        let (rows, next, _) = log.since(1, since, 37, None);
        seen.extend(rows.iter().map(|r| r.seq));
        since = next;
        if writers.iter().all(|w| w.is_finished()) && rows.is_empty() {
            break;
        }
    }
    for w in writers {
        w.join().unwrap();
    }
    let (rows, _, _) = log.since(1, since, 10_000, None);
    seen.extend(rows.iter().map(|r| r.seq));
    assert_eq!(seen.len(), 2000);
    assert!(
        seen.windows(2).all(|w| w[0] < w[1]),
        "ordered, no duplicates"
    );
    let mut names: Vec<String> = log
        .since(1, 0, 10_000, None)
        .0
        .into_iter()
        .map(|r| r.name)
        .collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 2000);
}

/// Cost per response with three `Set-Cookie` lines, setting off and on. Run with
/// `cargo test --release -p filter-engine overhead -- --ignored --nocapture`.
#[test]
#[ignore]
fn overhead() {
    let log = CookieLog::default();
    log.open(1);
    log.open(2);
    log.open(3);
    let lines: [&[u8]; 3] = [
        b"sid=0123456789abcdef0123456789abcdef; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600",
        b"_ga=GA1.2.1873245501.1790000000; Domain=.example.com; Path=/; Expires=Wed, 21 Oct 2099 07:28:00 GMT",
        b"__Host-t=abc; Secure; Path=/; SameSite=None",
    ];
    const N: u32 = 200_000;
    for (label, flag) in [
        ("off", AtomicBool::new(false)),
        ("on", AtomicBool::new(true)),
    ] {
        let t = std::time::Instant::now();
        for _ in 0..N {
            log.record_response(&flag, 1, &cx(), lines.iter().map(|l| (*l, true)), &[]);
        }
        println!(
            "setting {label}: {} ns per response",
            t.elapsed().as_nanos() / u128::from(N)
        );
    }
}

// -- closed sessions, accounting, value guards ----------------------------------------------------

#[test]
fn a_closed_or_unknown_session_never_gets_a_ring_back() {
    let log = CookieLog::default();
    let on = on();
    put(&log, &on, 1, "a=1");
    log.forget(1);
    // A response in flight and a keep-alive connection still bound to the old id.
    log.record_response(
        &on,
        1,
        &cx(),
        [(b"late=1".as_slice(), true)].into_iter(),
        &[],
    );
    log.record_blocked_send(&on, 1, &cx(), &[("late", "$cookie", None)]);
    log.record_response(
        &on,
        99,
        &cx(),
        [(b"never=1".as_slice(), true)].into_iter(),
        &[],
    );
    assert!(log.sessions.is_empty(), "{log:?}");
    assert!(log.is_empty());
    assert!(all(&log, 1).is_empty());
    // An in-flight recorder that already holds the ring pushes into an orphan nobody can read.
    log.open(2);
    let held = log.sessions.get(&2).unwrap().clone();
    log.forget(2);
    held.ring.lock().unwrap().entries.clear();
    assert!(all(&log, 2).is_empty());
}

#[test]
fn bytes_count_every_string_a_record_keeps() {
    let log = CookieLog::default();
    let on = on();
    assert!(
        std::mem::size_of::<Stored>() < 400,
        "{}",
        std::mem::size_of::<Stored>()
    );
    let long = "h".repeat(HOST_CAP);
    let cx = Context {
        host: &long,
        path: &"/p".repeat(PATH_CAP),
        page_host: &long,
    };
    let line = format!(
        "{}=v; Domain={}; Path=/{}; Max-Age=999; SameSite=none; Expires=Wed, 21 Oct 2099 07:28:00 GMT",
        "n".repeat(NAME_CAP),
        "d".repeat(ATTR_CAP),
        "q".repeat(PATH_CAP)
    );
    let rule = "r".repeat(RULE_CAP);
    let list = "l".repeat(LIST_CAP);
    let t = Touch {
        index: 0,
        stripped: false,
        rule: &rule,
        list_id: Some(&list),
        max_age: Some((
            60,
            Source {
                rule: &rule,
                list_id: Some(&list),
            },
        )),
        same_site: Some((
            SameSite::Strict,
            Source {
                rule: &rule,
                list_id: Some(&list),
            },
        )),
    };
    log.open(1);
    for _ in 0..RING_CAPACITY {
        log.record_response(&on, 1, &cx, [(line.as_bytes(), true)].into_iter(), &[t]);
    }
    let r = log.sessions.get(&1).unwrap().ring.lock().unwrap().bytes;
    let ring = log.sessions.get(&1).unwrap();
    let ring = ring.ring.lock().unwrap();
    let sum: usize = ring.entries.iter().map(Stored::size).sum();
    assert_eq!(r, sum, "the counter is exactly the sum of the records");
    assert!(r <= RING_BYTES, "{r}");
    // Every string's length is inside the counted size (nothing is uncounted).
    for e in &ring.entries {
        let text = e.name.len()
            + e.host.len()
            + e.path.len()
            + e.page_host.len()
            + e.rule.as_ref().map_or(0, String::len)
            + e.list_id.as_ref().map_or(0, String::len)
            + e.attrs.domain.as_ref().map_or(0, String::len)
            + e.attrs.path.as_ref().map_or(0, String::len)
            + e.changes
                .iter()
                .map(|c| {
                    c.rule.as_ref().map_or(0, String::len)
                        + c.list_id.as_ref().map_or(0, String::len)
                        + c.from.as_ref().map_or(0, String::len)
                        + c.to.as_ref().map_or(0, String::len)
                })
                .sum::<usize>();
        assert!(
            e.size() >= text + std::mem::size_of::<Stored>(),
            "{} {text}",
            e.size()
        );
    }
    // Worst-case records are about 4 KB, so the byte bound is what holds, not the record bound.
    assert!(ring.entries.len() < RING_CAPACITY);
}

#[test]
fn nameless_cookies_on_both_sides_leave_no_value_in_any_form() {
    let log = CookieLog::default();
    let on = on();
    log.open(1);
    // Response: `value` with no `=` has the empty name. Request: the proxy reports `""`.
    let lines = [
        SECRET.to_string(),
        format!("={SECRET}"),
        format!("\"{SECRET}\"; Secure"),
    ];
    log.record_response(
        &on,
        1,
        &cx(),
        lines.iter().map(|l| (l.as_bytes(), true)),
        &[],
    );
    log.record_blocked_send(&on, 1, &cx(), &[("", "$cookie", None)]);
    let rows = all(&log, 1);
    assert_eq!(rows.len(), 4);
    let shown = format!(
        "{log:?} {rows:?} {:?}",
        log.since(1, 0, 10, Some("example.com"))
    );
    assert!(!shown.contains("S3CR3T"), "{shown}");
    assert!(rows.iter().filter(|r| r.name.is_empty()).count() >= 3);
}

/// Compile-time guard: these types are destructured without `..`, so a new field (one that could
/// hold a value) stops the build here until it is reviewed and added.
#[test]
fn record_types_have_no_field_that_could_hold_a_value() {
    let Parsed { name: _, attrs } = parse_set_cookie(b"a=v").unwrap();
    let Attrs {
        domain: _,
        path: _,
        secure: _,
        http_only: _,
        same_site: _,
        max_age: _,
        expires: _,
        partitioned: _,
    } = attrs;
    let Change {
        attr: _,
        from: _,
        to: _,
        rule: _,
        list_id: _,
    } = Change {
        attr: "max_age",
        from: None,
        to: None,
        rule: None,
        list_id: None,
    };
    let CookieRecord {
        seq: _,
        ts: _,
        effect: _,
        name: _,
        host: _,
        path: _,
        page_host: _,
        third_party: _,
        attrs: _,
        changes: _,
        prefix: _,
        rule: _,
        list_id: _,
    } = CookieRecord {
        seq: 0,
        ts: DateTime::default(),
        effect: Effect::Set,
        name: String::new(),
        host: String::new(),
        path: String::new(),
        page_host: String::new(),
        third_party: None,
        attrs: Attrs::default(),
        changes: vec![],
        prefix: None,
        rule: None,
        list_id: None,
    };
    let Stored {
        seq: _,
        ts_ms: _,
        effect: _,
        name: _,
        host: _,
        path: _,
        page_host: _,
        attrs: _,
        changes: _,
        rule: _,
        list_id: _,
    } = Stored {
        seq: 0,
        ts_ms: 0,
        effect: Effect::Set,
        name: String::new(),
        host: String::new(),
        path: String::new(),
        page_host: String::new(),
        attrs: Attrs::default(),
        changes: vec![],
        rule: None,
        list_id: None,
    };
}

#[test]
fn a_changed_record_names_the_rule_of_each_attribute() {
    let log = CookieLog::default();
    let on = on();
    log.open(1);
    let t = Touch {
        index: 0,
        stripped: false,
        rule: "$cookie=c;maxAge=60",
        list_id: Some("l1"),
        max_age: Some((
            60,
            Source {
                rule: "$cookie=c;maxAge=60",
                list_id: Some("l1"),
            },
        )),
        same_site: Some((
            SameSite::Strict,
            Source {
                rule: "$cookie=c;sameSite=strict",
                list_id: None,
            },
        )),
    };
    log.record_response(
        &on,
        1,
        &cx(),
        [(b"c=1; Max-Age=999; SameSite=Lax".as_slice(), true)].into_iter(),
        &[t],
    );
    let r = &all(&log, 1)[0];
    assert_eq!(r.rule.as_deref(), Some("$cookie=c;maxAge=60"));
    let by: Vec<_> = r
        .changes
        .iter()
        .map(|c| (c.attr, c.rule.as_deref().unwrap(), c.list_id.as_deref()))
        .collect();
    assert_eq!(
        by,
        [
            ("max_age", "$cookie=c;maxAge=60", Some("l1")),
            ("same_site", "$cookie=c;sameSite=strict", None)
        ]
    );
}

mod common;
use common::*;
use script_policy::Capability as C;
use script_policy::*;

fn header(
    r: &RuleSet,
    scheme: &str,
    host: &str,
    port: Option<u16>,
    px: Option<&ProxyInject>,
) -> String {
    let c = compile(r);
    c.decide(scheme, host, port)
        .csp_header(px)
        .unwrap_or_else(|| "<none>".into())
}

#[test]
fn preset_golden_table() {
    let mut r = rs();
    site_rule(&mut r, "t", "trusted.com", Preset::Trusted);
    site_rule(&mut r, "u", "untrusted.com", Preset::Untrusted);
    site_rule(&mut r, "d", "default.com", Preset::Default);
    let h = |host: &str, px| header(&r, "https", host, None, px);

    // Trusted: nothing to add.
    assert_eq!(h("www.trusted.com", None), "<none>");
    assert_eq!(h("www.trusted.com", Some(&PX)), "<none>");

    // Default: first-party scripts only; third-party scripts, workers and plugins blocked.
    assert_eq!(
        h("www.default.com", None),
        "script-src 'self' *.default.com default.com 'unsafe-inline' 'unsafe-eval'; \
         worker-src 'self' *.default.com default.com blob:; \
         object-src 'self' *.default.com default.com"
    );
    // Unlisted site uses the global default (= Default).
    assert_eq!(h("shop.other.org", None), h("shop.other.org", Some(&PX)));
    assert!(h("shop.other.org", None).starts_with("script-src 'self' *.other.org other.org "));

    // Untrusted without proxy resources.
    assert_eq!(
        h("www.untrusted.com", None),
        "script-src 'none'; script-src-attr 'none'; worker-src 'none'; object-src 'none'; \
         frame-src 'self' *.untrusted.com untrusted.com; connect-src 'none'"
    );
    // Untrusted with the proxy's nonce and path: exactly the nonce, and the path (no 'self').
    assert_eq!(
        h("www.untrusted.com", Some(&PX)),
        "script-src https://www.untrusted.com/__adblock__/ 'nonce-N0nce'; script-src-attr 'none'; \
         worker-src 'none'; object-src 'none'; \
         frame-src 'self' *.untrusted.com untrusted.com; \
         connect-src https://www.untrusted.com/__adblock__/"
    );
}

#[test]
fn nonce_only_when_inline_is_blocked_and_path_only_without_self() {
    let mut r = rs();
    // Inline blocked, first-party scripts allowed, third-party blocked.
    site_rule(&mut r, "a", "a.com", custom(&[C::Eval], &[C::Script], &[]));
    let c = compile(&r);
    let p = c.decide("https", "a.com", None);
    // 'self' covers the proxy path: no path source; nonce present because inline is blocked.
    assert_eq!(
        p.csp(Some(&PX))
            .iter()
            .find(|d| d.name == "script-src")
            .unwrap()
            .render(),
        "script-src 'self' *.a.com a.com 'nonce-N0nce' 'unsafe-eval'"
    );
}

#[test]
fn inline_eval_wasm_flags() {
    let mut r = rs();
    // Sources unrestricted, so script-src exists only for the flags.
    let all_set: Vec<C> = CapSet::SOURCE_KEYED.iter().collect();
    let all: &[C] = &all_set;
    site_rule(
        &mut r,
        "1",
        "noinline.com",
        custom(&[C::InlineStyle, C::Eval], all, all),
    );
    site_rule(
        &mut r,
        "2",
        "noeval.com",
        custom(&[C::InlineStyle, C::InlineScript], all, all),
    );
    site_rule(
        &mut r,
        "3",
        "wasmonly.com",
        custom(&[C::InlineStyle, C::InlineScript, C::Wasm], all, all),
    );
    site_rule(
        &mut r,
        "4",
        "evalnowasm.com",
        custom(&[C::InlineStyle, C::InlineScript, C::Eval], all, all),
    );
    site_rule(
        &mut r,
        "5",
        "allflags.com",
        custom(
            &[C::InlineStyle, C::InlineScript, C::Eval, C::Wasm],
            all,
            all,
        ),
    );
    let h = |host: &str| header(&r, "https", host, None, None);
    assert_eq!(
        h("noinline.com"),
        "script-src * data: blob: 'unsafe-eval'; script-src-attr 'none'"
    );
    assert_eq!(h("noeval.com"), "script-src * data: blob: 'unsafe-inline'");
    assert_eq!(
        h("wasmonly.com"),
        "script-src * data: blob: 'unsafe-inline' 'wasm-unsafe-eval'"
    );
    // Eval allowed implies wasm (not separable), so only 'unsafe-eval'.
    assert_eq!(h("evalnowasm.com"), "<none>");
    // Everything allowed and sources unrestricted: no script-src at all.
    assert_eq!(h("allflags.com"), "<none>");
    let c = compile(&r);
    let out = c
        .decide("https", "evalnowasm.com", None)
        .csp_with_notes(None);
    assert!(out
        .notes
        .iter()
        .any(|n| n.contains("wasm denied but eval allowed")));
}

#[test]
fn third_party_allow_rules_become_host_sources() {
    let mut r = rs();
    src_rule(
        &mut r,
        "1",
        "example.com",
        "host:cdn.example.net",
        &[C::Script],
        Effect::Allow,
    );
    src_rule(
        &mut r,
        "2",
        "example.com",
        "static-site.org",
        &[C::Script, C::Font],
        Effect::Allow,
    );
    src_rule(
        &mut r,
        "3",
        "example.com",
        "https://secure.example.org",
        &[C::Script],
        Effect::Allow,
    );
    // Global rule: applies to every page.
    src_rule(
        &mut r,
        "4",
        "*",
        "host:cdnjs.cloudflare.com",
        &[C::Script],
        Effect::Allow,
    );
    let c = compile(&r);
    let p = c.decide("https", "www.example.com", None);
    assert_eq!(
        p.csp(None)[0].render(),
        "script-src 'self' *.example.com *.static-site.org cdn.example.net cdnjs.cloudflare.com \
         example.com https://secure.example.org static-site.org 'unsafe-inline' 'unsafe-eval'"
    );
    // Fonts are unrestricted by default, so the font allow rule adds nothing.
    assert!(!p.csp(None).iter().any(|d| d.name == "font-src"));
    // Other pages only get the global rule.
    let q = c.decide("https", "other.org", None);
    assert!(q.csp(None)[0].render().contains("cdnjs.cloudflare.com"));
    assert!(!q.csp(None)[0].render().contains("host:cdn.example.net"));
}

#[test]
fn passive_directives_carry_data_and_blob_only_when_something_is_allowed() {
    let mut r = rs();
    let page = &[C::InlineScript, C::Eval, C::Wasm, C::InlineStyle];
    site_rule(
        &mut r,
        "1",
        "p.com",
        custom(
            page,
            &[
                C::Script,
                C::Image,
                C::Font,
                C::Media,
                C::Connect,
                C::Style,
                C::FormAction,
                C::Frame,
                C::Object,
                C::Worker,
            ],
            &[C::Script],
        ),
    );
    let c = compile(&r);
    let d = c.csp_header_for("https", "p.com");
    assert_eq!(
        d,
        "worker-src 'self' *.p.com p.com blob:; style-src 'self' *.p.com p.com 'unsafe-inline'; \
         img-src 'self' *.p.com p.com data: blob:; font-src 'self' *.p.com p.com data:; \
         media-src 'self' *.p.com p.com blob: data:; object-src 'self' *.p.com p.com; \
         frame-src 'self' *.p.com p.com; connect-src 'self' *.p.com p.com data: blob:; \
         form-action 'self' *.p.com p.com"
    );
}

trait HeaderFor {
    fn csp_header_for(&self, scheme: &str, host: &str) -> String;
}
impl HeaderFor for CompiledPolicy {
    fn csp_header_for(&self, scheme: &str, host: &str) -> String {
        self.decide(scheme, host, None)
            .csp_header(None)
            .unwrap_or_default()
    }
}

#[test]
fn non_default_port_and_http_page_in_path_source() {
    let mut r = rs();
    site_rule(&mut r, "u", "localhost", Preset::Untrusted);
    let c = compile(&r);
    let p = c.decide("http", "localhost", Some(3000));
    let d = p.csp(Some(&PX));
    assert_eq!(
        d[0].render(),
        "script-src http://localhost:3000/__adblock__/ 'nonce-N0nce'"
    );
    // Default port is omitted.
    let p = c.decide("http", "localhost", Some(80));
    assert_eq!(
        p.csp(Some(&PX))[0].render(),
        "script-src http://localhost/__adblock__/ 'nonce-N0nce'"
    );
    // Frame first-party on a single-label host: 'self' + the host, no wildcard.
    assert!(p
        .csp(None)
        .iter()
        .any(|d| d.render() == "frame-src 'self' localhost"));
}

#[test]
fn permissions_policy_for_untrusted() {
    let mut r = rs();
    site_rule(&mut r, "u", "bad.com", Preset::Untrusted);
    let c = compile(&r);
    assert_eq!(
        c.decide("https", "bad.com", None)
            .permissions_policy()
            .as_deref(),
        Some("camera=(), microphone=(), geolocation=(), payment=(), usb=(), display-capture=()")
    );
    assert_eq!(
        c.decide("https", "good.com", None).permissions_policy(),
        None
    );
}

#[test]
fn disabled_policy_adds_nothing() {
    let mut r = RuleSet::default();
    site_rule(&mut r, "u", "bad.com", Preset::Untrusted);
    let c = compile(&r);
    let p = c.decide("https", "bad.com", None);
    assert!(!p.is_active());
    assert!(p.csp(None).is_empty());
    assert!(p.html_actions().is_empty());
    assert!(p.allows_host(C::Script, "evil.net"));
    assert!(p.network_hints().is_empty());
}

#[test]
fn carve_outs_are_reported_not_emitted() {
    let mut r = rs();
    src_rule(
        &mut r,
        "1",
        "example.com",
        "host:ads.example.com",
        &[C::Script],
        Effect::Deny,
    );
    let c = compile(&r);
    let o = c
        .decide("https", "www.example.com", None)
        .csp_with_notes(None);
    // First-party stays allowed in CSP; the deny is only a note (network hints enforce it).
    assert!(o.directives[0]
        .sources
        .contains(&"*.example.com".to_string()));
    assert!(o.notes.iter().any(|n| n.contains("carve-out")));
    // ...but the exact matrix evaluation denies it.
    let p = c.decide("https", "www.example.com", None);
    assert!(!p.allows_host(C::Script, "ads.example.com"));
    assert!(p.allows_host(C::Script, "cdn.example.com"));
}

#[test]
fn deny_over_covering_allow_drops_the_source() {
    let mut r = rs();
    // Deny all script sources on the page, allow one CDN (more specific source scope wins).
    src_rule(&mut r, "1", "example.com", "*", &[C::Script], Effect::Deny);
    src_rule(
        &mut r,
        "2",
        "example.com",
        "host:cdn.example.net",
        &[C::Script],
        Effect::Allow,
    );
    let c = compile(&r);
    let p = c.decide("https", "example.com", None);
    assert_eq!(
        p.csp(None)[0].render(),
        "script-src cdn.example.net 'unsafe-inline' 'unsafe-eval'"
    );
    assert!(!p.allows_host(C::Script, "example.com"));
}

// ---- rendered headers are always well-formed -------------------------------------------------

const KNOWN: &[&str] = &[
    "script-src",
    "script-src-attr",
    "worker-src",
    "object-src",
    "frame-src",
    "connect-src",
    "style-src",
    "img-src",
    "font-src",
    "media-src",
    "default-src",
    "base-uri",
    "form-action",
    "prefetch-src",
    "manifest-src",
];

fn source_ok(s: &str) -> bool {
    if matches!(
        s,
        "'none'"
            | "'self'"
            | "'unsafe-inline'"
            | "'unsafe-eval'"
            | "'strict-dynamic'"
            | "*"
            | "blob:"
            | "data:"
            | "https:"
            | "http:"
    ) {
        return true;
    }
    if let Some(n) = s.strip_prefix("'nonce-").and_then(|x| x.strip_suffix('\'')) {
        return !n.is_empty()
            && n.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b));
    }
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (host, port) = if let Some(i) = hostport.find("]:") {
        (&hostport[..=i], Some(&hostport[i + 2..]))
    } else if hostport.starts_with('[') {
        (hostport, None)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        }
    };
    let host = host.strip_prefix("*.").unwrap_or(host);
    let host_ok = !host.is_empty()
        && (host.starts_with('[')
            && host.ends_with(']')
            && host[1..host.len() - 1]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
            || host
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
                && !host.starts_with('.'));
    let port_ok =
        port.is_none_or(|p| p == "*" || (!p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())));
    let path_ok = path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/-._~%!$&()*+=:@".contains(&b));
    host_ok && port_ok && path_ok
}

/// Parse a header the way a CSP parser does and check every directive and source expression.
fn assert_well_formed(h: &str) {
    for d in h.split(';') {
        let d = d.trim();
        assert!(!d.is_empty(), "empty directive in {h:?}");
        let mut it = d.split(' ');
        let name = it.next().unwrap();
        assert!(
            KNOWN.contains(&name),
            "unexpected directive {name:?} in {h:?}"
        );
        let srcs: Vec<&str> = it.collect();
        assert!(!srcs.is_empty(), "directive without sources in {h:?}");
        for s in &srcs {
            assert!(source_ok(s), "malformed source {s:?} in {h:?}");
        }
        if srcs.contains(&"'none'") {
            assert_eq!(srcs.len(), 1, "'none' must stand alone in {h:?}");
        }
    }
}

use proptest::prelude::*;

fn hostile() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z0-9.-]{1,12}",
        "[a-z0-9.;,'\"*: /\\\\%-]{1,16}",
        "(xn--)?[a-z0-9\u{e4}\u{4e2d}\u{1f600}.-]{1,10}",
        Just("a;script-src *".to_string()),
        Just("evil.com;sandbox".to_string()),
        Just("a,b.com".to_string()),
        Just("münchen.example".to_string()),
        Just("[::1]".to_string()),
        Just("exa mple.com".to_string()),
        Just("a'b.com".to_string()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(600))]
    #[test]
    fn rendered_csp_is_always_well_formed(
        page in hostile(),
        src in hostile(),
        port in proptest::option::of(any::<u16>()),
        preset in 0u8..3,
        allow in any::<bool>(),
        px in any::<bool>(),
    ) {
        let mut r = rs();
        let preset = match preset { 0 => Preset::Default, 1 => Preset::Untrusted, _ => Preset::Trusted };
        // Rules are built from user-typed scopes: whatever parses must render safely.
        if let Ok(p) = Scope::parse(&page) {
            r.site_rules.insert("s".into(), SiteRule { id: "s".into(), scope: p, preset: preset.clone(), note: None });
            if let Ok(sc) = Scope::parse(&src) {
                r.source_rules.insert("r".into(), SourceRule {
                    id: "r".into(), page: Scope::parse(&page).unwrap(), source: sc,
                    caps: CapSet::of(&[C::Script, C::Connect, C::Frame]),
                    effect: if allow { Effect::Allow } else { Effect::Deny }, note: None });
            }
        }
        r.site_rules.insert("g".into(), SiteRule { id: "g".into(), scope: Scope::Global, preset, note: None });
        let c = compile(&r);
        for scheme in ["https", "http"] {
            // The page host reaches us from the proxy; it is normalised first (IDN to punycode).
            let host = match script_policy::normalize_host(&page) { Ok(h) => h, Err(_) => continue };
            let p = c.decide(scheme, &host, port);
            let inject = ProxyInject { nonce: Some("N0nce"), path: Some("/__adblock__/") };
            if let Some(h) = p.csp_header(if px { Some(&inject) } else { None }) {
                assert_well_formed(&h);
            }
        }
    }
}

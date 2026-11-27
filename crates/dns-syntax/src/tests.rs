use super::*;
use base64::Engine;

fn lp(s: &[u8]) -> Vec<u8> {
    let mut v = vec![s.len() as u8];
    v.extend_from_slice(s);
    v
}

/// A variable-length set.
fn vlp(items: &[&[u8]]) -> Vec<u8> {
    if items.is_empty() {
        return vec![0];
    }
    let mut v = Vec::new();
    for (i, it) in items.iter().enumerate() {
        let last = i + 1 == items.len();
        v.push(it.len() as u8 | if last { 0 } else { 0x80 });
        v.extend_from_slice(it);
    }
    v
}

fn stamp(proto: u8, parts: &[Vec<u8>]) -> String {
    let mut b = vec![proto];
    b.extend_from_slice(&[0u8; 8]);
    for p in parts {
        b.extend_from_slice(p);
    }
    format!(
        "sdns://{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    )
}

#[test]
fn plain_and_scheme_forms() {
    let s = parse_upstream("1.1.1.1").unwrap();
    assert_eq!((s.transport, s.host.as_str(), s.port), (Transport::Udp, "1.1.1.1", 53));
    let s = parse_upstream("9.9.9.9:5353").unwrap();
    assert_eq!(s.port, 5353);
    let s = parse_upstream("[2606:4700::1111]:5353").unwrap();
    assert_eq!((s.host.as_str(), s.port), ("2606:4700::1111", 5353));
    let s = parse_upstream("2606:4700::1111").unwrap();
    assert_eq!((s.host.as_str(), s.port), ("2606:4700::1111", 53));
    assert_eq!(parse_upstream("tcp://8.8.8.8").unwrap().transport, Transport::Tcp);
    assert_eq!(parse_upstream("udp://8.8.8.8:53").unwrap().transport, Transport::Udp);
    let s = parse_upstream("tls://dns.google").unwrap();
    assert_eq!((s.transport, s.host.as_str(), s.port), (Transport::Tls, "dns.google", 853));
    let s = parse_upstream("https://dns.google/dns-query").unwrap();
    assert_eq!((s.transport, s.port, s.path.as_str()), (Transport::Https, 443, "/dns-query"));
    let s = parse_upstream("https://dns.google:8443").unwrap();
    assert_eq!((s.port, s.path.as_str()), (8443, "/dns-query"));
    let s = parse_upstream("h3://dns.google/dns-query").unwrap();
    assert_eq!(s.transport, Transport::H3);
    let s = parse_upstream("quic://dns.adguard-dns.com").unwrap();
    assert_eq!((s.transport, s.port), (Transport::Quic, 853));
}

#[test]
fn bootstrap_pin_suffix() {
    let s = parse_upstream("tls://dns.google#8.8.8.8,2001:4860:4860::8888").unwrap();
    assert_eq!(s.host, "dns.google");
    assert_eq!(s.ips.len(), 2);
    assert!(!s.needs_bootstrap());
    assert!(parse_upstream("tls://dns.google").unwrap().needs_bootstrap());
    assert!(parse_upstream("tls://dns.google#nope").is_err());
    assert!(parse_upstream("1.1.1.1#8.8.8.8").is_err());
}

#[test]
fn rejects_bad_input() {
    for bad in [
        "dns.google",
        "300.1.1.1",
        "ftp://1.1.1.1",
        "1.1.1.1:0",
        "1.1.1.1:99999",
        "tls://",
        "[::1",
        "tcp://1.1.1.1/path",
        "sdns://@@@",
        "tls://bad host",
    ] {
        assert!(parse_upstream(bad).is_err(), "{bad} should not parse");
    }
}

#[test]
fn comments_blank_and_multiple_per_line() {
    assert_eq!(parse_line("").unwrap(), None);
    assert_eq!(parse_line("   ").unwrap(), None);
    assert_eq!(parse_line("# 1.1.1.1").unwrap(), None);
    match parse_line("1.1.1.1 8.8.8.8").unwrap().unwrap() {
        Line::Default(v) => assert_eq!(v.len(), 2),
        _ => panic!(),
    }
}

#[test]
fn domain_rules() {
    let Line::Rule(r) = parse_line("[/example.com/lan/]10.0.0.1 tls://dns.google")
        .unwrap()
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(r.domains.len(), 2);
    assert_eq!(r.upstreams.len(), 2);
    for tail in ["[/lan/]#", "[/lan/]"] {
        let Line::Rule(r) = parse_line(tail).unwrap().unwrap() else {
            panic!()
        };
        assert!(r.upstreams.is_empty(), "{tail}: `#` means the default upstreams");
    }
    let Line::Rule(r) = parse_line("[//]192.168.1.1").unwrap().unwrap() else {
        panic!()
    };
    assert_eq!(r.domains, [DomainPattern::Unqualified]);
    assert!(parse_line("[/example.com]1.1.1.1").is_err());
    assert!(parse_line("[/bad_dom!/]1.1.1.1").is_err());
    assert!(parse_line("[/a.com//b.com/]1.1.1.1").is_err());
    assert!(parse_line("[/a.com/]nonsense").is_err());
}

#[test]
fn rule_lookup_prefers_the_most_specific_domain() {
    let u = parse_upstreams(&[
        "9.9.9.9",
        "[/example.com/]10.0.0.1",
        "[/internal.example.com/]10.0.0.2",
        "[/*.wild.test/]10.0.0.3",
        "[/lan/]#",
        "[//]10.0.0.4",
    ])
    .unwrap();
    let up = |n: &str| u.rule_for(n).map(|r| r.upstreams.first().map(|s| s.host.clone()));
    assert_eq!(up("a.example.com"), Some(Some("10.0.0.1".into())));
    assert_eq!(up("example.com"), Some(Some("10.0.0.1".into())));
    assert_eq!(up("x.internal.example.com"), Some(Some("10.0.0.2".into())));
    assert_eq!(up("example.org"), None);
    assert_eq!(up("notexample.com"), None, "suffix match is on label boundaries");
    assert_eq!(up("a.wild.test"), Some(Some("10.0.0.3".into())));
    assert_eq!(up("wild.test"), None, "`*.` excludes the apex");
    assert_eq!(up("printer.lan"), Some(None), "`#` rule: default upstreams");
    assert_eq!(up("nas"), Some(Some("10.0.0.4".into())));
    assert_eq!(up("A.Example.COM."), Some(Some("10.0.0.1".into())));
}

#[test]
fn line_errors_carry_numbers() {
    let e = parse_upstreams(&["1.1.1.1", "bogus", "# ok", "tls://"]).unwrap_err();
    assert_eq!(e.iter().map(|x| x.0).collect::<Vec<_>>(), [2, 4]);
}

#[test]
fn flat_and_plain_lists() {
    assert!(parse_flat(&["tls://dns.google", "1.1.1.1"]).is_ok());
    assert!(parse_flat(&["[/a.com/]1.1.1.1"]).is_err());
    assert_eq!(parse_plain(&["1.1.1.1", "8.8.8.8:53"]).unwrap().len(), 2);
    assert!(parse_plain(&["tls://dns.google"]).is_err());
    assert!(parse_plain(&["tcp://1.1.1.1"]).is_ok());
}

#[test]
fn stamps_plain_doh_dot_doq() {
    let s = parse_upstream(&stamp(0x00, &[lp(b"8.8.4.4:5353")])).unwrap();
    assert_eq!((s.transport, s.host.as_str(), s.port), (Transport::Udp, "8.8.4.4", 5353));

    let doh = stamp(
        0x02,
        &[
            lp(b"1.0.0.1"),
            vlp(&[b"hash1", b"hash2"]),
            lp(b"cloudflare-dns.com"),
            lp(b"/dns-query"),
        ],
    );
    let s = parse_upstream(&doh).unwrap();
    assert_eq!((s.transport, s.host.as_str(), s.port, s.path.as_str()), (Transport::Https, "cloudflare-dns.com", 443, "/dns-query"));
    assert_eq!(s.ips, ["1.0.0.1".parse::<IpAddr>().unwrap()]);
    assert!(!s.needs_bootstrap());

    let dot = stamp(0x03, &[lp(b""), vlp(&[]), lp(b"dns.example:8853")]);
    let s = parse_upstream(&dot).unwrap();
    assert_eq!((s.transport, s.host.as_str(), s.port), (Transport::Tls, "dns.example", 8853));
    assert!(s.needs_bootstrap());

    let doq = stamp(0x04, &[lp(b""), vlp(&[]), lp(b"q.example"), vlp(&[b"9.9.9.9", b"149.112.112.112"])]);
    let s = parse_upstream(&doq).unwrap();
    assert_eq!(s.transport, Transport::Quic);
    assert_eq!(s.ips.len(), 2);
}

#[test]
fn stamp_dnscrypt() {
    let pk = [7u8; 32];
    let st = stamp(
        0x01,
        &[lp(b"[2001:db8::1]:5443"), lp(&pk), lp(b"2.dnscrypt-cert.example.com")],
    );
    let s = parse_upstream(&st).unwrap();
    assert_eq!(s.transport, Transport::DnsCrypt);
    assert_eq!(s.port, 5443);
    let d = s.dnscrypt.unwrap();
    assert_eq!(d.provider_pk, pk);
    assert_eq!(d.provider_name, "2.dnscrypt-cert.example.com");
    // Wrong key length.
    assert!(parse_upstream(&stamp(0x01, &[lp(b"1.2.3.4"), lp(&[1u8; 31]), lp(b"n")])).is_err());
}

#[test]
fn stamp_errors() {
    assert!(parse_upstream(&stamp(0x05, &[lp(b"x")])).unwrap_err().contains("Oblivious"));
    assert!(parse_upstream(&stamp(0x81, &[lp(b"x")])).is_err());
    assert!(parse_upstream(&stamp(0x7f, &[])).is_err());
    assert!(parse_upstream(&stamp(0x02, &[lp(b"1.1.1.1")])).unwrap_err().contains("truncated"));
}

#[test]
fn real_world_stamp() {
    // Cloudflare's published DoH stamp.
    let s = parse_upstream("sdns://AgcAAAAAAAAABzEuMC4wLjEAEmNsb3VkZmxhcmUtZG5zLmNvbQovZG5zLXF1ZXJ5").unwrap();
    assert_eq!((s.transport, s.host.as_str()), (Transport::Https, "cloudflare-dns.com"));
    assert_eq!(s.path, "/dns-query");
}

#[test]
fn private_names() {
    for n in ["printer.lan", "nas.local", "x.home.arpa", "router", "a.b.internal", "1.0.0.10.in-addr.arpa", "10.in-addr.arpa", "5.1.168.192.in-addr.arpa", "1.0.16.172.in-addr.arpa", "1.0.0.127.in-addr.arpa", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"] {
        assert!(is_private_name(n), "{n}");
    }
    for n in ["example.com", "8.8.8.8.in-addr.arpa", "1.0.32.172.in-addr.arpa", "localhost.example.com", "2.0.0.192.in-addr.arpa"] {
        assert!(!is_private_name(n), "{n}");
    }
    assert_eq!(
        private_reverse_zone("192.168.1.5".parse().unwrap()),
        "5.1.168.192.in-addr.arpa"
    );
    assert!(private_reverse_zone("fd00::1".parse().unwrap()).ends_with(".ip6.arpa"));
    assert!(is_private_name(&private_reverse_zone("fd00::1".parse().unwrap())));
    assert!(!is_private_name(&private_reverse_zone("2606:4700::1111".parse().unwrap())));
}

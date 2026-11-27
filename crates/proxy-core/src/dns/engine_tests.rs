//! Engine, upstream and cache behaviour against in-process stub servers. Every test starts its
//! own servers on ephemeral ports and shares no state, so they run in parallel.

use super::stub::{self, Behavior, Stub};
use super::*;
use common::config::{DnsEcs, DnsMode};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::RecordType;
use std::net::SocketAddr;
use std::sync::Mutex;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn settings(servers: &[&str]) -> DnsSettings {
    DnsSettings {
        servers: servers.iter().map(|s| s.to_string()).collect(),
        timeout_ms: 600,
        min_ttl_secs: 1,
        max_ttl_secs: 60,
        negative_ttl_secs: 1,
        ..Default::default()
    }
}

fn build(s: &DnsSettings, tls: Option<rustls::ClientConfig>, race: RaceOpts) -> Arc<Engine> {
    Arc::new(
        Engine::new(EngineSpec {
            settings: s,
            extra_lines: &[],
            tls,
            system: system_resolver(),
            race,
        })
        .unwrap(),
    )
}

fn engine(s: &DnsSettings) -> Arc<Engine> {
    build(s, None, RaceOpts::default())
}

fn addr(s: &Stub) -> String {
    s.addr.to_string()
}

async fn first(e: &Engine, name: &str) -> IpAddr {
    e.lookup_name(name).await.unwrap().0[0]
}

// ---- transports ----

#[tokio::test]
async fn udp_upstream_resolves_and_reports_stats() {
    let s = stub::start(Behavior::answering("192.0.2.10")).await;
    let e = engine(&settings(&[&addr(&s)]));
    let (ips, ttl) = e.lookup_name("Host.Example.").await.unwrap();
    assert_eq!(ips, [ip("192.0.2.10")]);
    assert_eq!(ttl, Duration::from_secs(60));
    assert_eq!(s.names()[0], "host.example");
    let st = EngineResolver(e).stats();
    assert_eq!(st.len(), 1);
    assert_eq!(st[0].transport, "udp");
    assert!(st[0].queries >= 1 && st[0].failures == 0 && st[0].healthy);
    assert!(st[0].rtt_ms.is_some() && st[0].last_ok_secs_ago.is_some());
}

#[tokio::test]
async fn tcp_upstream_resolves() {
    let s = stub::start(Behavior::answering("192.0.2.11")).await;
    let e = engine(&settings(&[&format!("tcp://{}", addr(&s))]));
    assert_eq!(first(&e, "a.example").await, ip("192.0.2.11"));
}

#[tokio::test]
async fn truncated_udp_answers_are_retried_over_tcp() {
    let s = stub::start(Behavior {
        truncate_udp: true,
        ..Behavior::answering("192.0.2.12")
    })
    .await;
    let e = engine(&settings(&[&addr(&s)]));
    assert_eq!(first(&e, "big.example").await, ip("192.0.2.12"));
}

#[tokio::test]
async fn dot_upstream_with_pinned_address() {
    let t = stub::tls(&[]);
    let s = stub::start_dot(Behavior::answering("192.0.2.20"), &t).await;
    let st = settings(&[&format!("tls://dns.test:{}#127.0.0.1", s.addr.port())]);
    let e = build(&st, Some(t.client), RaceOpts::default());
    assert_eq!(first(&e, "dot.example").await, ip("192.0.2.20"));
    assert_eq!(EngineResolver(e).stats()[0].transport, "tls");
}

#[tokio::test]
async fn doh_upstream_with_pinned_address() {
    let t = stub::tls(&[b"h2"]);
    let s = stub::start_doh(Behavior::answering("192.0.2.30"), &t).await;
    let st = settings(&[&format!(
        "https://dns.test:{}/dns-query#127.0.0.1",
        s.addr.port()
    )]);
    let e = build(&st, Some(t.client), RaceOpts::default());
    assert_eq!(first(&e, "doh.example").await, ip("192.0.2.30"));
    // The connection is reused for the next names.
    assert_eq!(first(&e, "doh2.example").await, ip("192.0.2.30"));
    assert_eq!(EngineResolver(e).stats()[0].transport, "https");
}

#[tokio::test]
async fn untrusted_tls_certificates_are_refused() {
    let t = stub::tls(&[]);
    let other = stub::tls(&[]);
    let s = stub::start_dot(Behavior::answering("192.0.2.20"), &t).await;
    let st = settings(&[&format!("tls://dns.test:{}#127.0.0.1", s.addr.port())]);
    let e = build(&st, Some(other.client), RaceOpts::default());
    assert!(e.lookup_name("x.example").await.is_err());
}

#[tokio::test]
async fn quic_and_h3_upstreams_report_unreachable_servers() {
    // Nothing listens on these ports: the failure is reported, not hung on.
    let free = stub::start(Behavior::default()).await.addr.port();
    for scheme in ["quic", "h3"] {
        let st = DnsSettings {
            timeout_ms: 400,
            ..settings(&[&format!("{scheme}://dns.test:{free}#127.0.0.1")])
        };
        let e = engine(&st);
        let t = std::time::Instant::now();
        assert!(e.lookup_name("x.example").await.is_err(), "{scheme}");
        assert!(t.elapsed() < Duration::from_secs(5), "{scheme}");
        let s = EngineResolver(e).stats();
        assert_eq!(s[0].transport, scheme);
        assert!(s[0].failures > 0 && s[0].last_error.is_some());
    }
}

#[tokio::test]
async fn doq_upstream_with_pinned_address() {
    let t = stub::tls(&[b"doq"]);
    let s = stub::start_doq(Behavior::answering("192.0.2.60"), &t).await;
    let st = settings(&[&format!("quic://dns.test:{}#127.0.0.1", s.addr.port())]);
    let e = build(&st, Some(t.client), RaceOpts::default());
    assert_eq!(first(&e, "doq.example").await, ip("192.0.2.60"));
    assert_eq!(first(&e, "doq2.example").await, ip("192.0.2.60"));
    assert_eq!(EngineResolver(e).stats()[0].transport, "quic");
}

#[tokio::test]
async fn h3_upstream_with_pinned_address() {
    let t = stub::tls(&[b"h3"]);
    let s = stub::start_h3(Behavior::answering("192.0.2.70"), &t).await;
    let st = settings(&[&format!(
        "h3://dns.test:{}/dns-query#127.0.0.1",
        s.addr.port()
    )]);
    let e = build(&st, Some(t.client), RaceOpts::default());
    assert_eq!(first(&e, "h3.example").await, ip("192.0.2.70"));
    assert_eq!(first(&e, "h32.example").await, ip("192.0.2.70"));
    assert_eq!(EngineResolver(e).stats()[0].transport, "h3");
}

/// Real public resolvers (needs the network): `cargo test -p proxy-core --lib -- --ignored
/// real_dnscrypt`. AdGuard's DNSCrypt servers, from the dnscrypt public-resolvers list.
#[tokio::test]
#[ignore]
async fn real_dnscrypt_public_resolver_interop() {
    for stamp in [
        "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
        "sdns://AQMAAAAAAAAAETk0LjE0MC4xNS4xNTo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
    ] {
        let e = engine(&DnsSettings {
            timeout_ms: 5000,
            ..settings(&[stamp])
        });
        let (ips, _) = e.lookup_name("example.com").await.unwrap();
        assert!(!ips.is_empty());
        eprintln!("{stamp}: {ips:?}");
    }
}

fn stamp_dnscrypt(addr: SocketAddr, pk: [u8; 32], provider: &str) -> String {
    use base64::Engine;
    let lp = |b: &[u8]| {
        let mut v = vec![b.len() as u8];
        v.extend_from_slice(b);
        v
    };
    let mut b = vec![0x01];
    b.extend_from_slice(&[0u8; 8]);
    b.extend(lp(addr.to_string().as_bytes()));
    b.extend(lp(&pk));
    b.extend(lp(provider.as_bytes()));
    format!(
        "sdns://{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    )
}

#[tokio::test]
async fn dnscrypt_upstream_from_a_stamp_both_suites() {
    use std::net::Ipv4Addr;
    for es in [1u16, 2] {
        let srv = dnscrypt::testserver::start(es, Ipv4Addr::new(192, 0, 2, 40)).await;
        let stamp = stamp_dnscrypt(srv.addr, srv.provider_pk, &srv.provider_name);
        let e = engine(&settings(&[&stamp]));
        assert_eq!(
            first(&e, "crypt.example").await,
            ip("192.0.2.40"),
            "es {es}"
        );
        assert_eq!(EngineResolver(e).stats()[0].transport, "dnscrypt");
    }
}

#[tokio::test]
async fn dnscrypt_rejects_a_certificate_signed_by_another_key() {
    use std::net::Ipv4Addr;
    let srv = dnscrypt::testserver::start(1, Ipv4Addr::new(192, 0, 2, 40)).await;
    let stamp = stamp_dnscrypt(srv.addr, [9u8; 32], &srv.provider_name);
    let e = engine(&settings(&[&stamp]));
    let err = e.lookup_name("crypt.example").await.unwrap_err();
    assert!(
        err.message.to_lowercase().contains("certificate"),
        "{err:?}"
    );
}

// ---- routing ----

#[tokio::test]
async fn per_domain_rules_pick_the_upstream() {
    let (def, corp, sub) = (
        stub::start(Behavior::answering("192.0.2.1")).await,
        stub::start(Behavior::answering("192.0.2.2")).await,
        stub::start(Behavior::answering("192.0.2.3")).await,
    );
    let st = settings(&[
        &addr(&def),
        &format!("[/corp.test/]{}", addr(&corp)),
        &format!("[/*.sub.test/]{}", addr(&sub)),
        "[/lan/]#",
    ]);
    let e = engine(&st);
    assert_eq!(first(&e, "x.corp.test").await, ip("192.0.2.2"));
    assert_eq!(first(&e, "corp.test").await, ip("192.0.2.2"));
    assert_eq!(first(&e, "other.test").await, ip("192.0.2.1"));
    assert_eq!(first(&e, "h.sub.test").await, ip("192.0.2.3"));
    assert_eq!(
        first(&e, "sub.test").await,
        ip("192.0.2.1"),
        "`*.` excludes the apex"
    );
    // `#` sends the name to the default upstreams (and not the private resolvers).
    assert_eq!(first(&e, "printer.lan").await, ip("192.0.2.1"));
    assert!(!corp.names().contains(&"other.test".to_string()));
    assert!(!def.names().contains(&"x.corp.test".to_string()));
}

#[tokio::test]
async fn rule_upstreams_can_be_several_and_failover() {
    let dead = stub::start(Behavior {
        drop: true,
        ..Default::default()
    })
    .await;
    let good = stub::start(Behavior::answering("192.0.2.5")).await;
    let st = DnsSettings {
        timeout_ms: 700,
        ..settings(&[&format!("[/r.test/]{} {}", addr(&dead), addr(&good))])
    };
    let e = engine(&st);
    for i in 0..4 {
        assert_eq!(first(&e, &format!("h{i}.r.test")).await, ip("192.0.2.5"));
    }
}

#[tokio::test]
async fn private_names_and_ptr_go_to_the_private_resolvers() {
    let (def, private) = (
        stub::start(Behavior::answering("192.0.2.1")).await,
        stub::start(Behavior {
            ptr: [(
                "5.1.168.192.in-addr.arpa".to_string(),
                "nas.lan".to_string(),
            )]
            .into(),
            ..Behavior::answering("10.0.0.5")
        })
        .await,
    );
    let st = DnsSettings {
        private_resolvers: vec![addr(&private)],
        ..settings(&[&addr(&def)])
    };
    let e = engine(&st);
    assert_eq!(first(&e, "nas.lan").await, ip("10.0.0.5"));
    assert_eq!(first(&e, "example.com").await, ip("192.0.2.1"));
    assert!(!def.names().contains(&"nas.lan".to_string()));
    assert_eq!(e.lookup_ptr(ip("192.168.1.5")).await.unwrap(), ["nas.lan"]);
    assert!(def.names().iter().all(|n| !n.ends_with("arpa")));

    // Off: LAN names go to the normal upstreams.
    let off = engine(&DnsSettings {
        private_rdns: false,
        ..st
    });
    assert_eq!(first(&off, "nas.lan").await, ip("192.0.2.1"));
}

#[tokio::test]
async fn public_ptr_goes_to_the_upstreams() {
    let def = stub::start(Behavior {
        ptr: [("8.8.8.8.in-addr.arpa".to_string(), "dns.google".to_string())].into(),
        ..Default::default()
    })
    .await;
    let e = engine(&settings(&[&addr(&def)]));
    assert_eq!(e.lookup_ptr(ip("8.8.8.8")).await.unwrap(), ["dns.google"]);
    assert!(e.lookup_ptr(ip("1.1.1.1")).await.is_err());
}

#[tokio::test]
async fn empty_upstream_list_uses_the_system_resolver() {
    let e = engine(&settings(&[]));
    assert!(e.is_empty());
    let a = e.lookup_name("localhost").await.unwrap().0;
    assert!(a.iter().any(|i| i.is_loopback()), "{a:?}");
}

// ---- modes ----

#[tokio::test]
async fn load_balance_prefers_the_faster_upstream() {
    let fast = stub::start(Behavior::answering("192.0.2.1")).await;
    let slow = stub::start(Behavior {
        delay: Duration::from_millis(120),
        ..Behavior::answering("192.0.2.2")
    })
    .await;
    let st = DnsSettings {
        timeout_ms: 1500,
        ..settings(&[&addr(&slow), &addr(&fast)])
    };
    let e = engine(&st);
    // Measure both first, so neither is "unmeasured" (and the stats below exist whatever the
    // random picks were). After that a lookup picks the slow one first with probability
    // (1/120) / (1/120 + 1/1) < 1%; 40 lookups send it 16 or more of ~80 queries with
    // probability far below 1e-9.
    let probed = e.probe("warm.example").await;
    assert!(probed.iter().all(|p| p.ok), "{probed:?}");
    for i in 0..40 {
        e.lookup_name(&format!("n{i}.example")).await.unwrap();
    }
    assert!(
        fast.count() > slow.count() * 4,
        "fast {} slow {}",
        fast.count(),
        slow.count()
    );
    let stats = EngineResolver(e).stats();
    let (f, s) = (
        stats.iter().find(|x| x.upstream == addr(&fast)).unwrap(),
        stats.iter().find(|x| x.upstream == addr(&slow)).unwrap(),
    );
    assert!(s.rtt_ms.unwrap() > f.rtt_ms.unwrap(), "{s:?} {f:?}");
}

#[tokio::test]
async fn load_balance_fails_over_and_marks_the_dead_one_unhealthy() {
    let dead = stub::start(Behavior {
        drop: true,
        ..Default::default()
    })
    .await;
    let good = stub::start(Behavior::answering("192.0.2.9")).await;
    let st = DnsSettings {
        timeout_ms: 1000,
        ..settings(&[&addr(&dead), &addr(&good)])
    };
    let e = engine(&st);
    // Probe both, so the dead one has certainly been tried (which upstream a lookup tries
    // first is random).
    let probed = e.probe("warm.example").await;
    assert_eq!(probed.iter().filter(|p| !p.ok).count(), 1, "{probed:?}");
    for i in 0..12 {
        assert_eq!(first(&e, &format!("f{i}.example")).await, ip("192.0.2.9"));
    }
    // The dead one is only ever tried first rarely; it was tried at least once (unmeasured
    // upstreams look average) and failed.
    let stats = EngineResolver(e).stats();
    let d = stats.iter().find(|x| x.upstream == addr(&dead)).unwrap();
    assert!(d.failures >= 1 && d.last_error.is_some(), "{d:?}");
}

#[tokio::test]
async fn a_lone_dead_upstream_turns_unhealthy_and_errors() {
    let dead = stub::start(Behavior {
        drop: true,
        ..Default::default()
    })
    .await;
    let st = DnsSettings {
        timeout_ms: 150,
        ..settings(&[&addr(&dead)])
    };
    let e = engine(&st);
    for i in 0..2 {
        let err = e.lookup_name(&format!("d{i}.example")).await.unwrap_err();
        assert_eq!(err.kind, FailKind::Timeout);
    }
    let s = EngineResolver(e).stats();
    assert!(
        !s[0].healthy && s[0].consecutive_failures >= 3,
        "{:?}",
        s[0]
    );
}

#[tokio::test]
async fn parallel_mode_returns_the_first_answer() {
    let fast = stub::start(Behavior::answering("192.0.2.1")).await;
    let slow = stub::start(Behavior {
        delay: Duration::from_millis(2500),
        ..Behavior::answering("192.0.2.2")
    })
    .await;
    let st = DnsSettings {
        mode: DnsMode::Parallel,
        timeout_ms: 5000,
        ..settings(&[&addr(&slow), &addr(&fast)])
    };
    let e = engine(&st);
    let t = std::time::Instant::now();
    assert_eq!(first(&e, "p.example").await, ip("192.0.2.1"));
    assert!(
        t.elapsed() < Duration::from_millis(450),
        "{:?}",
        t.elapsed()
    );
    // Both were asked.
    assert!(slow.count() >= 1 && fast.count() >= 1);
}

#[tokio::test]
async fn parallel_mode_prefers_an_answer_over_an_early_nxdomain() {
    let nx = stub::start(Behavior::default()).await;
    let ok = stub::start(Behavior {
        delay: Duration::from_millis(25),
        ..Behavior::answering("192.0.2.2")
    })
    .await;
    let st = DnsSettings {
        mode: DnsMode::Parallel,
        ..settings(&[&addr(&nx), &addr(&ok)])
    };
    assert_eq!(first(&engine(&st), "p2.example").await, ip("192.0.2.2"));
}

#[tokio::test]
async fn parallel_mode_survives_a_dead_upstream() {
    let dead = stub::start(Behavior {
        drop: true,
        ..Default::default()
    })
    .await;
    let ok = stub::start(Behavior::answering("192.0.2.2")).await;
    let st = DnsSettings {
        mode: DnsMode::Parallel,
        timeout_ms: 1500,
        ..settings(&[&addr(&dead), &addr(&ok)])
    };
    assert_eq!(first(&engine(&st), "p3.example").await, ip("192.0.2.2"));
}

#[tokio::test]
async fn fastest_ip_mode_races_connections_and_puts_the_winner_first() {
    // 127.0.0.2 accepts connections on the port, 127.0.0.1 does not.
    let (port, accepted, _hold) = stub::race_listener().await;
    let s = stub::start(Behavior::answering_many(&["127.0.0.1", "127.0.0.2"])).await;
    let st = DnsSettings {
        mode: DnsMode::FastestIp,
        ..settings(&[&addr(&s)])
    };
    let race = RaceOpts {
        ports: vec![port],
        allow_private: true,
        ..Default::default()
    };
    let e = build(&st, None, race);
    let (ips, _) = e.lookup_name("race.example").await.unwrap();
    assert_eq!(ips, [ip("127.0.0.2"), ip("127.0.0.1")]);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(accepted.load(Ordering::SeqCst) >= 1);

    // By default private and loopback addresses are never probed.
    let before = accepted.load(Ordering::SeqCst);
    let e = engine(&st);
    let (ips, _) = e.lookup_name("race2.example").await.unwrap();
    assert_eq!(ips, [ip("127.0.0.1"), ip("127.0.0.2")]);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), before);
}

#[tokio::test]
async fn fastest_ip_mode_merges_the_answers_of_every_upstream() {
    let a = stub::start(Behavior::answering("192.0.2.1")).await;
    let b = stub::start(Behavior::answering("192.0.2.2")).await;
    let st = DnsSettings {
        mode: DnsMode::FastestIp,
        ..settings(&[&addr(&a), &addr(&b)])
    };
    let (ips, _) = engine(&st).lookup_name("m.example").await.unwrap();
    assert_eq!(ips.len(), 2, "{ips:?}");
    assert!(ips.contains(&ip("192.0.2.1")) && ips.contains(&ip("192.0.2.2")));
}

// ---- bootstrap and fallback ----

#[tokio::test]
async fn bootstrap_resolves_the_host_of_an_encrypted_upstream() {
    let t = stub::tls(&[]);
    let dot = stub::start_dot(Behavior::answering("192.0.2.50"), &t).await;
    let bs = stub::start(Behavior {
        answers: [("dns.test".to_string(), vec![ip("127.0.0.1")])].into(),
        ..Default::default()
    })
    .await;
    let st = DnsSettings {
        bootstrap: vec![addr(&bs)],
        ..settings(&[&format!("tls://dns.test:{}", dot.addr.port())])
    };
    let e = build(&st, Some(t.client), RaceOpts::default());
    assert_eq!(first(&e, "viaboot.example").await, ip("192.0.2.50"));
    assert!(bs.names().contains(&"dns.test".to_string()));
    // The bootstrap server is asked about the upstream's host and nothing else.
    assert!(
        bs.names().iter().all(|n| n == "dns.test"),
        "{:?}",
        bs.names()
    );
    // The address is kept: a second name does not ask again.
    let n = bs.count();
    first(&e, "second.example").await;
    assert_eq!(bs.count(), n);
    let roles: Vec<_> = EngineResolver(e).stats().iter().map(|s| s.role).collect();
    assert!(roles.contains(&"bootstrap") && roles.contains(&"upstream"));
}

#[tokio::test]
async fn bootstrap_failure_is_reported() {
    let t = stub::tls(&[]);
    let dot = stub::start_dot(Behavior::answering("192.0.2.50"), &t).await;
    let bs = stub::start(Behavior {
        drop: true,
        ..Default::default()
    })
    .await;
    let st = DnsSettings {
        timeout_ms: 250,
        bootstrap: vec![addr(&bs)],
        ..settings(&[&format!("tls://dns.test:{}", dot.addr.port())])
    };
    let e = build(&st, Some(t.client), RaceOpts::default());
    let err = e.lookup_name("nobootstrap.example").await.unwrap_err();
    assert!(
        err.message.contains("cannot resolve its address"),
        "{err:?}"
    );
}

#[tokio::test]
async fn fallback_is_used_only_when_every_upstream_fails() {
    let dead = stub::start(Behavior {
        drop: true,
        ..Default::default()
    })
    .await;
    let fb = stub::start(Behavior::answering("192.0.2.77")).await;
    let st = DnsSettings {
        timeout_ms: 800,
        fallback: vec![addr(&fb)],
        ..settings(&[&addr(&dead)])
    };
    let e = engine(&st);
    assert_eq!(first(&e, "fb.example").await, ip("192.0.2.77"));
    assert!(dead.count() >= 1);

    // A healthy primary never touches the fallback.
    let ok = stub::start(Behavior::answering("192.0.2.1")).await;
    let fb2 = stub::start(Behavior::answering("192.0.2.77")).await;
    let st = DnsSettings {
        fallback: vec![addr(&fb2)],
        ..settings(&[&addr(&ok)])
    };
    assert_eq!(first(&engine(&st), "fb.example").await, ip("192.0.2.1"));
    assert_eq!(fb2.count(), 0);

    // NXDOMAIN is an answer, not a failure.
    let nx = stub::start(Behavior::default()).await;
    let fb3 = stub::start(Behavior::answering("192.0.2.77")).await;
    let st = DnsSettings {
        fallback: vec![addr(&fb3)],
        ..settings(&[&addr(&nx)])
    };
    let err = engine(&st).lookup_name("nx.example").await.unwrap_err();
    assert_eq!(err.kind, FailKind::NotFound);
    assert_eq!(fb3.count(), 0);
}

#[tokio::test]
async fn no_fallback_means_the_lookup_fails_without_touching_the_system_resolver() {
    let dead = stub::start(Behavior {
        drop: true,
        ..Default::default()
    })
    .await;
    let st = DnsSettings {
        timeout_ms: 200,
        private_rdns: false,
        ..settings(&[&addr(&dead)])
    };
    // `localhost` would resolve through the system resolver; it must not.
    let err = engine(&st).lookup_name("localhost").await.unwrap_err();
    assert!(matches!(err.kind, FailKind::Timeout | FailKind::Transient));
}

#[tokio::test]
async fn servfail_counts_as_a_failure_and_fails_over() {
    let bad = stub::start(Behavior {
        rcode: Some(ResponseCode::ServFail),
        ..Default::default()
    })
    .await;
    let st = settings(&[&addr(&bad)]);
    let e = engine(&st);
    let err = e.lookup_name("sf.example").await.unwrap_err();
    assert_eq!(err.kind, FailKind::Transient);
    let good = stub::start(Behavior::answering("192.0.2.4")).await;
    let st = settings(&[&addr(&bad), &addr(&good)]);
    assert_eq!(first(&engine(&st), "sf2.example").await, ip("192.0.2.4"));
}

// ---- options ----

#[tokio::test]
async fn ipv6_off_asks_no_aaaa_and_returns_only_ipv4() {
    let s = stub::start(Behavior::answering_many(&["192.0.2.1", "2001:db8::1"])).await;
    let on = engine(&settings(&[&addr(&s)]));
    let (ips, _) = on.lookup_name("v6.example").await.unwrap();
    assert_eq!(ips.len(), 2);
    assert!(s.count_type(RecordType::AAAA) >= 1);
    let off = stub::start(Behavior::answering_many(&["192.0.2.1", "2001:db8::1"])).await;
    let e = engine(&DnsSettings {
        ipv6: false,
        ..settings(&[&addr(&off)])
    });
    let (ips, _) = e.lookup_name("v6.example").await.unwrap();
    assert_eq!(ips, [ip("192.0.2.1")]);
    assert_eq!(off.count_type(RecordType::AAAA), 0);
}

#[tokio::test]
async fn ecs_custom_is_sent_and_off_is_not() {
    let s = stub::start(Behavior::answering("192.0.2.1")).await;
    engine(&settings(&[&addr(&s)]))
        .lookup_name("ecs.example")
        .await
        .unwrap();
    assert_eq!(*s.last_ecs.lock(), None);
    let e = engine(&DnsSettings {
        ecs: DnsEcs::Custom,
        ecs_subnet: "203.0.113.77/24".into(),
        ..settings(&[&addr(&s)])
    });
    e.lookup_name("ecs2.example").await.unwrap();
    assert_eq!(*s.last_ecs.lock(), Some((ip("203.0.113.0"), 24)));
}

#[tokio::test]
async fn dnssec_validation_failure_is_an_error_and_is_not_cached_or_fallen_back_on() {
    // The stub answers with unsigned data and cannot prove the zone is insecure, so
    // validation must refuse it.
    let s = stub::start(Behavior::answering("192.0.2.66")).await;
    let fb = stub::start(Behavior::answering("192.0.2.77")).await;
    let st = DnsSettings {
        dnssec: true,
        timeout_ms: 1500,
        fallback: vec![addr(&fb)],
        ..settings(&[&addr(&s)])
    };
    let r = CachedResolver::from_settings(&st);
    let err = r.resolve("bogus.example").await.unwrap_err();
    assert!(err.to_lowercase().contains("dnssec"), "{err}");
    let n = s.count();
    assert!(r.resolve("bogus.example").await.is_err());
    assert!(s.count() > n, "a validation failure must not be cached");
    assert_eq!(fb.count(), 0, "no fallback after a validation failure");

    // The same server resolves fine with validation off.
    let off = CachedResolver::from_settings(&settings(&[&addr(&s)]));
    assert_eq!(
        off.resolve("bogus.example").await.unwrap()[0],
        ip("192.0.2.66")
    );
}

// ---- cache ----

struct Fake {
    calls: AtomicU64,
    ip: Mutex<IpAddr>,
    ttl: Mutex<Duration>,
    fail: Mutex<bool>,
}

impl Fake {
    fn new(ip_: &str, ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicU64::new(0),
            ip: Mutex::new(ip(ip_)),
            ttl: Mutex::new(ttl),
            fail: Mutex::new(false),
        })
    }
}

impl Resolver for Fake {
    fn lookup(&self, _n: &str) -> BoxFut<BackendResult> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let r = if *self.fail.lock().unwrap() {
            Err(DnsFailure::new(FailKind::Transient, "down"))
        } else {
            Ok((vec![*self.ip.lock().unwrap()], *self.ttl.lock().unwrap()))
        };
        Box::pin(async move { r })
    }
}

fn cache(min: u64, max: u64, optimistic: bool) -> DnsCacheConfig {
    DnsCacheConfig {
        capacity: 100,
        min_ttl: Duration::from_millis(min),
        max_ttl: Duration::from_millis(max),
        negative_ttl: Duration::from_millis(min),
        optimistic,
    }
}

#[tokio::test]
async fn zero_ttl_answers_are_held_for_the_minimum_ttl() {
    let f = Fake::new("192.0.2.1", Duration::ZERO);
    let r = CachedResolver::new(f.clone(), cache(800, 5000, false));
    r.resolve("z.example").await.unwrap();
    r.resolve("z.example").await.unwrap();
    assert_eq!(f.calls.load(Ordering::SeqCst), 1, "min TTL applies");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    r.resolve("z.example").await.unwrap();
    assert_eq!(f.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn long_ttls_are_cut_to_the_maximum() {
    let f = Fake::new("192.0.2.1", Duration::from_secs(86_400));
    let r = CachedResolver::new(f.clone(), cache(50, 200, false));
    r.resolve("l.example").await.unwrap();
    tokio::time::sleep(Duration::from_millis(350)).await;
    r.resolve("l.example").await.unwrap();
    assert_eq!(f.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn optimistic_cache_serves_stale_and_refreshes_in_the_background() {
    let f = Fake::new("192.0.2.1", Duration::from_millis(100));
    let r = CachedResolver::new(f.clone(), cache(100, 100, true));
    assert_eq!(r.resolve("o.example").await.unwrap()[0], ip("192.0.2.1"));
    tokio::time::sleep(Duration::from_millis(220)).await;
    *f.ip.lock().unwrap() = ip("192.0.2.2");
    // Expired: the old answer comes back at once...
    assert_eq!(r.resolve("o.example").await.unwrap()[0], ip("192.0.2.1"));
    // ...while a refresh runs; afterwards the new answer is served.
    for _ in 0..50 {
        if f.calls.load(Ordering::SeqCst) >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(f.calls.load(Ordering::SeqCst), 2);
    assert_eq!(r.resolve("o.example").await.unwrap()[0], ip("192.0.2.2"));
}

#[tokio::test]
async fn optimistic_cache_keeps_the_stale_answer_when_the_refresh_fails() {
    let f = Fake::new("192.0.2.1", Duration::from_millis(100));
    let r = CachedResolver::new(f.clone(), cache(100, 100, true));
    r.resolve("k.example").await.unwrap();
    tokio::time::sleep(Duration::from_millis(220)).await;
    *f.fail.lock().unwrap() = true;
    assert_eq!(r.resolve("k.example").await.unwrap()[0], ip("192.0.2.1"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The upstream is down but the name still resolves from the stale entry.
    assert_eq!(r.resolve("k.example").await.unwrap()[0], ip("192.0.2.1"));
}

#[tokio::test]
async fn without_optimistic_caching_an_expired_answer_is_asked_again() {
    let f = Fake::new("192.0.2.1", Duration::from_millis(100));
    let r = CachedResolver::new(f.clone(), cache(100, 100, false));
    r.resolve("n.example").await.unwrap();
    tokio::time::sleep(Duration::from_millis(220)).await;
    *f.ip.lock().unwrap() = ip("192.0.2.2");
    assert_eq!(r.resolve("n.example").await.unwrap()[0], ip("192.0.2.2"));
}

// ---- hot swap, probing, sources ----

#[tokio::test]
async fn hot_swap_replaces_the_upstreams_and_flushes_the_cache() {
    let (a, b) = (
        stub::start(Behavior::answering("192.0.2.1")).await,
        stub::start(Behavior::answering("192.0.2.2")).await,
    );
    let r = CachedResolver::from_settings(&settings(&[&addr(&a)]));
    assert_eq!(r.resolve("s.example").await.unwrap()[0], ip("192.0.2.1"));
    assert_eq!(r.cached_names().await, 1);
    assert_eq!(r.upstream_stats()[0].upstream, addr(&a));

    r.reconfigure(&settings(&[&addr(&b)]));
    assert_eq!(r.cached_names().await, 0);
    assert_eq!(r.resolve("s.example").await.unwrap()[0], ip("192.0.2.2"));
    let st = r.upstream_stats();
    assert_eq!(st.len(), 1);
    assert_eq!(st[0].upstream, addr(&b));

    // A swap to the system resolver drops the upstream stats.
    r.reconfigure(&settings(&[]));
    assert!(r.upstream_stats().is_empty());
}

#[tokio::test]
async fn in_flight_lookups_finish_on_the_old_upstreams_during_a_swap() {
    let slow = stub::start(Behavior {
        delay: Duration::from_millis(900),
        ..Behavior::answering("192.0.2.1")
    })
    .await;
    let new = stub::start(Behavior::answering("192.0.2.2")).await;
    let r = Arc::new(CachedResolver::from_settings(&DnsSettings {
        timeout_ms: 4000,
        ..settings(&[&addr(&slow)])
    }));
    let r2 = r.clone();
    let h = tokio::spawn(async move { r2.resolve("inflight.example").await });
    tokio::time::sleep(Duration::from_millis(80)).await;
    r.reconfigure(&settings(&[&addr(&new)]));
    assert_eq!(h.await.unwrap().unwrap()[0], ip("192.0.2.1"));
    assert_eq!(
        r.resolve("after.example").await.unwrap()[0],
        ip("192.0.2.2")
    );
}

#[tokio::test]
async fn probe_reports_each_upstream_latency_or_error() {
    let ok = stub::start(Behavior::answering("192.0.2.1")).await;
    let dead = stub::start(Behavior {
        drop: true,
        ..Default::default()
    })
    .await;
    let st = DnsSettings {
        timeout_ms: 1000,
        fallback: vec![addr(&dead)],
        ..settings(&[&addr(&ok)])
    };
    let res = test_upstreams(&st, &[]).await.unwrap();
    assert_eq!(res.len(), 2);
    let g = res.iter().find(|r| r.upstream == addr(&ok)).unwrap();
    assert!(g.ok && g.latency_ms.is_some() && g.answers == [ip("192.0.2.1")]);
    assert_eq!(g.role, "upstream");
    let d = res.iter().find(|r| r.upstream == addr(&dead)).unwrap();
    assert!(!d.ok && d.error.is_some());
    assert_eq!(d.role, "fallback");
    // Nothing configured: the system resolver is what gets probed.
    let sys = test_upstreams(&settings(&[]), &[]).await.unwrap();
    assert_eq!(sys[0].role, "system");
}

fn source(s: &str) -> DnsSettings {
    DnsSettings {
        upstreams_source: s.into(),
        ..settings(&[])
    }
}

#[tokio::test]
async fn upstream_lines_load_from_a_file_in_the_data_dns_folder() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("dns")).unwrap();
    let a = stub::start(Behavior::answering("192.0.2.1")).await;
    let b = stub::start(Behavior::answering("192.0.2.2")).await;
    let f = d.path().join("dns/up.txt");
    std::fs::write(&f, format!("# mine\n[/file.test/]{}\n\n", addr(&b))).unwrap();
    let st = DnsSettings {
        upstreams_source: "up.txt".into(),
        ..settings(&[&addr(&a)])
    };
    let lines = load_upstream_lines(&st, d.path()).await.unwrap();
    let r = CachedResolver::from_settings_with(&st, &lines);
    assert_eq!(r.resolve("x.file.test").await.unwrap()[0], ip("192.0.2.2"));
    assert_eq!(r.resolve("x.other.test").await.unwrap()[0], ip("192.0.2.1"));
    // An absolute path inside the folder works too.
    let abs = source(&f.display().to_string());
    assert!(!load_upstream_lines(&abs, d.path())
        .await
        .unwrap()
        .is_empty());
    assert!(load_upstream_lines(&settings(&[]), d.path())
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn a_source_file_outside_the_dns_folder_is_refused() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("dns")).unwrap();
    std::fs::write(d.path().join("secret.txt"), "SECRET-LINE\n").unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("o.txt"), "SECRET-LINE\n").unwrap();
    for src in [
        d.path().join("secret.txt").display().to_string(),
        "../secret.txt".to_string(),
        "/etc/passwd".to_string(),
        outside.path().join("o.txt").display().to_string(),
    ] {
        let e = load_upstream_lines(&source(&src), d.path())
            .await
            .unwrap_err();
        assert!(!e.contains("SECRET") && !e.contains("root:"), "{src}: {e}");
    }
    // A symlink inside the folder pointing out is followed to its target and refused.
    std::os::unix::fs::symlink(d.path().join("secret.txt"), d.path().join("dns/link.txt")).unwrap();
    let e = load_upstream_lines(&source("link.txt"), d.path())
        .await
        .unwrap_err();
    assert!(e.contains("inside"), "{e}");
    let e = load_upstream_lines(&source("nope.txt"), d.path())
        .await
        .unwrap_err();
    assert!(e.contains("not found"), "{e}");
}

#[tokio::test]
async fn source_errors_name_the_line_and_never_its_text() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("dns")).unwrap();
    std::fs::write(d.path().join("dns/bad.txt"), "1.1.1.1\nSECRET-TOKEN-XYZ\n").unwrap();
    let e = load_upstream_lines(&source("bad.txt"), d.path())
        .await
        .unwrap_err();
    assert!(e.contains("line 2") && !e.contains("SECRET"), "{e}");
    // The same for the engine, where the lines are used.
    let bad = DnsSettings {
        servers: vec!["SECRET-TOKEN-XYZ".into()],
        ..settings(&[])
    };
    let e = Engine::new(EngineSpec {
        settings: &bad,
        extra_lines: &[],
        tls: None,
        system: system_resolver(),
        race: Default::default(),
    })
    .err()
    .unwrap();
    assert!(e.contains("line 1") && !e.contains("SECRET"), "{e}");
    assert!(!bad.validate().unwrap_err().contains("SECRET"));
}

#[tokio::test]
async fn source_urls_must_be_https_and_public() {
    let d = tempfile::tempdir().unwrap();
    for u in [
        "http://example.com/u.txt",
        "ftp://example.com/u.txt",
        "https://127.0.0.1/u.txt",
        "https://localhost/u.txt",
        "https://[::1]/u.txt",
        "https://10.0.0.5/u.txt",
        "https://169.254.169.254/latest",
        "https://[::ffff:127.0.0.1]/u.txt",
    ] {
        assert!(
            load_upstream_lines(&source(u), d.path()).await.is_err(),
            "{u}"
        );
    }
    assert!(source("http://example.com/x").validate().is_err());
    assert!(source("https://example.com/x").validate().is_ok());
}

#[tokio::test]
async fn downloads_stop_at_the_size_cap() {
    use bytes::Bytes;
    let chunks = |n: usize| {
        futures_util::stream::iter(
            (0..n).map(|_| Ok::<_, std::io::Error>(Bytes::from(vec![b'a'; 400]))),
        )
    };
    assert_eq!(read_capped(chunks(2), 1000).await.unwrap().len(), 800);
    assert!(read_capped(chunks(3), 1000).await.is_err());
    // An endless stream is cut off, not read to the end.
    let endless =
        futures_util::stream::repeat_with(|| Ok::<_, std::io::Error>(Bytes::from(vec![0u8; 4096])));
    assert!(read_capped(Box::pin(endless), 1 << 20).await.is_err());
}

#[test]
fn only_public_addresses_are_probed() {
    for ok in ["8.8.8.8", "2606:4700:4700::1111", "1.1.1.1"] {
        assert!(engine::probeable(ip(ok)), "{ok}");
    }
    for no in [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.1.1",
        "169.254.1.1",
        "0.1.2.3",
        "198.18.0.1",
        "198.19.255.255",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
        "fe80::1",
        "fd00::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "64:ff9b::7f00:1",
        "64:ff9b::808:808",
        "2002:7f00:1::1",
        "2002:808:808::1",
        "224.0.0.1",
        "0.0.0.0",
    ] {
        assert!(!engine::probeable(ip(no)), "{no}");
    }
}

#[tokio::test]
async fn no_direct_probes_when_switched_off() {
    let (port, accepted, _hold) = stub::race_listener().await;
    let s = stub::start(Behavior::answering_many(&["127.0.0.1", "127.0.0.2"])).await;
    let st = DnsSettings {
        mode: DnsMode::FastestIp,
        ..settings(&[&addr(&s)])
    };
    let race = RaceOpts {
        ports: vec![port],
        allow_private: true,
        ..Default::default()
    };
    race.enabled.store(false, Ordering::Relaxed);
    let e = build(&st, None, race.clone());
    let (ips, _) = e.lookup_name("noprobe.example").await.unwrap();
    assert_eq!(ips, [ip("127.0.0.1"), ip("127.0.0.2")], "answer order kept");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "nothing was dialled");
    // The flag is live: switching it on makes the next lookup race.
    race.enabled.store(true, Ordering::Relaxed);
    let (ips, _) = e.lookup_name("probe.example").await.unwrap();
    assert_eq!(ips[0], ip("127.0.0.2"));
}

#[tokio::test]
async fn the_resolver_switch_reaches_a_rebuilt_engine() {
    let s = stub::start(Behavior::answering_many(&["8.8.8.8", "8.8.4.4"])).await;
    let st = DnsSettings {
        mode: DnsMode::FastestIp,
        ..settings(&[&addr(&s)])
    };
    let r = CachedResolver::from_settings(&st);
    r.set_direct_probes(false);
    r.reconfigure(&st);
    // With probing off no connection to 8.8.8.8 is attempted: the answer comes back at once,
    // in the upstream's order.
    let t = std::time::Instant::now();
    let a = r.resolve("x.example").await.unwrap();
    assert_eq!(&*a, &[ip("8.8.8.8"), ip("8.8.4.4")]);
    assert!(t.elapsed() < Duration::from_millis(500));
}

#[tokio::test]
async fn sinkholed_answers_still_reach_the_policy() {
    // The resolver returns whatever the upstream says (here a sinkhole); the destination
    // policy, applied by every caller, is what refuses it.
    let s = stub::start(Behavior::answering("0.0.0.0")).await;
    let r = Arc::new(CachedResolver::from_settings(&settings(&[&addr(&s)])));
    let policy = crate::policy::DestPolicy::new(false, &[])
        .unwrap()
        .with_resolver(Arc::new(DnsHandle(r)));
    let e = policy.resolve("ads.example", 443, None).await.unwrap_err();
    assert!(
        e.to_string()
            .contains(common::net_policy::Refusal::SINKHOLE_REASON),
        "{e}"
    );
    // A sinkholed answer is never a candidate for the fastest-address race either.
    assert!(!engine::probeable(ip("0.0.0.0")) && !engine::probeable(ip("127.0.0.1")));
}

// ---- CNAME chains ----

fn chained(ttl: u32) -> Behavior {
    let mut b = Behavior {
        ttl,
        ..Behavior::default()
    };
    b.cnames
        .insert("cmp.site.test".into(), "edge.cdn.test".into());
    b.cnames
        .insert("edge.cdn.test".into(), "d2gt.tracker.test".into());
    b.answers
        .insert("d2gt.tracker.test".into(), vec![ip("192.0.2.7")]);
    b.answers.insert("plain.test".into(), vec![ip("192.0.2.8")]);
    b
}

#[tokio::test]
async fn the_last_cname_target_comes_from_the_dial_lookup() {
    let s = stub::start(chained(60)).await;
    let r = CachedResolver::from_settings(&settings(&[&addr(&s)]));
    let a = r.resolve_canon("cmp.site.test").await.unwrap();
    assert_eq!(&*a.addrs, &[ip("192.0.2.7")]);
    assert_eq!(a.canonical.as_deref(), Some("d2gt.tracker.test"));
    // A name without a CNAME has no canonical name.
    assert_eq!(r.resolve_canon("plain.test").await.unwrap().canonical, None);
    // Cached next to the addresses: the second read asks nothing.
    let before = s.count();
    let again = r.resolve_canon("cmp.site.test").await.unwrap();
    assert_eq!(again.canonical.as_deref(), Some("d2gt.tracker.test"));
    assert_eq!(s.count(), before);
    // Only the address queries of the one lookup were made for the alias (no CNAME query).
    assert!(s
        .log
        .lock()
        .iter()
        .all(|(_, t)| matches!(t, RecordType::A | RecordType::AAAA)));
}

#[tokio::test]
async fn the_cname_is_dropped_after_its_max_ttl() {
    let s = stub::start(chained(60)).await;
    let r = CachedResolver::from_settings(&settings(&[&addr(&s)]));
    r.set_cname_max_ttl(1);
    assert!(r
        .resolve_canon("cmp.site.test")
        .await
        .unwrap()
        .canonical
        .is_some());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let late = r.resolve_canon("cmp.site.test").await.unwrap();
    // The addresses are still served from the cache; the alias is no longer trusted.
    assert_eq!(&*late.addrs, &[ip("192.0.2.7")]);
    assert_eq!(late.canonical, None);
}

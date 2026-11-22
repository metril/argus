//! Profile lookup cost: 10,000 devices over 50 profiles.
//!
//! Targets: `resolve_*` < 100 ns, per-request (epoch load + slot load) < 20 ns, no allocation.
//! A counting global allocator asserts the zero-allocation claim before measuring.

use base64::Engine as _;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use filter_engine::SharedEngine;
use proxy_core::profiles::{digest_from_proxy_auth, token_digest, ProfileTable, Profiles};
use proxy_core::request_ctx::{default_profile_slot, ConnCtx, Profile, ProfileSlot};
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct Counting;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.realloc(p, l, n)
    }
}
#[global_allocator]
static A: Counting = Counting;

const DEVICES: u32 = 10_000;
const PROFILES: u64 = 50;

fn device_ip(i: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i))
}

fn token(i: u32) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[..4].copy_from_slice(&i.to_le_bytes());
    t
}

fn build() -> Profiles {
    let engine = Arc::new(SharedEngine::new());
    let default = default_profile_slot(engine.clone());
    let mut b = ProfileTable::builder(default.clone());
    for id in 1..=PROFILES {
        let slot: ProfileSlot = Arc::new(arc_swap::ArcSwap::from_pointee(Profile::new(
            id,
            0,
            engine.clone(),
        )));
        b = b.profile(id, slot);
    }
    for i in 0..DEVICES {
        let id = 1 + (i as u64 % PROFILES);
        b = b.ip(device_ip(i), id).token(token_digest(&token(i)), id);
    }
    // Subnets for the prefix path (192.168.n.0/24) and a coarser fallback.
    for n in 0..16u8 {
        b = b.prefix(format!("192.168.{n}.0/24").parse().unwrap(), 1 + n as u64);
    }
    b = b.prefix("192.0.0.0/8".parse().unwrap(), 2);
    let profiles = Profiles::new(default);
    profiles.publish(b.build());
    profiles
}

fn allocs<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let before = ALLOCS.load(Ordering::Relaxed);
    let r = f();
    (r, ALLOCS.load(Ordering::Relaxed) - before)
}

fn bench(c: &mut Criterion) {
    let profiles = build();
    let hit = device_ip(4321);
    let prefix_hit = IpAddr::V4(Ipv4Addr::new(192, 168, 7, 99));
    let miss = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
    let digest = token_digest(&token(4321));
    let header = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode([b"dev:".as_slice(), &token(4321)].concat())
    );
    let conn = ConnCtx::new(&profiles, SocketAddr::new(hit, 5555));

    // Zero-allocation proof for every lookup path.
    let (_, n) = allocs(|| {
        for _ in 0..1000 {
            black_box(profiles.resolve(black_box(hit), None));
            black_box(profiles.resolve(black_box(prefix_hit), None));
            black_box(profiles.resolve(black_box(miss), None));
            black_box(
                profiles
                    .table()
                    .resolve_digest(black_box(&digest))
                    .is_some(),
            );
            black_box(digest_from_proxy_auth(black_box(header.as_bytes())));
            black_box(conn.current(&profiles, false));
        }
    });
    assert_eq!(n, 0, "profile lookup allocated {n} times");

    let mut g = c.benchmark_group("profiles");
    g.bench_function("resolve_ip/exact_hit", |b| {
        let t = profiles.table();
        b.iter(|| black_box(Arc::as_ptr(t.resolve_ip(black_box(hit)))))
    });
    g.bench_function("resolve_ip/prefix_hit", |b| {
        let t = profiles.table();
        b.iter(|| black_box(Arc::as_ptr(t.resolve_ip(black_box(prefix_hit)))))
    });
    g.bench_function("resolve_ip/miss", |b| {
        let t = profiles.table();
        b.iter(|| black_box(Arc::as_ptr(t.resolve_ip(black_box(miss)))))
    });
    g.bench_function("resolve_digest/precomputed", |b| {
        let t = profiles.table();
        b.iter(|| black_box(t.resolve_digest(black_box(&digest)).is_some()))
    });
    g.bench_function("resolve/Profiles::resolve ip (table load + clone)", |b| {
        b.iter(|| black_box(profiles.resolve(black_box(hit), None)))
    });
    g.bench_function("token_path/base64+blake3+probe", |b| {
        b.iter(|| {
            let d = digest_from_proxy_auth(black_box(header.as_bytes())).unwrap();
            black_box(profiles.table().resolve_digest(&d).is_some())
        })
    });
    g.bench_function("per_request/epoch_load+slot_load", |b| {
        let slot = profiles.table().resolve_ip(hit).clone();
        b.iter(|| {
            black_box(profiles.epoch());
            black_box(slot.load().id)
        })
    });
    g.bench_function("per_request/ConnCtx::current", |b| {
        b.iter(|| black_box(conn.current(&profiles, false)))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

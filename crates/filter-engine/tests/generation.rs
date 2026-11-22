//! The engine and its companion data are one generation: a verdict and the companion that comes
//! with it always belong to the same build, however often the engine is swapped meanwhile.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use filter_engine::{build_engine, compile_engine, IpFilter, SharedEngine};

fn install(e: &SharedEngine, rule: &str, tag: u64) {
    let blob = compile_engine(&[format!("{rule}\n")]);
    let live = build_engine(&blob, &e.resources());
    e.install_set_with(
        Arc::new(blob),
        live,
        Some(Arc::new(tag)),
        Arc::default(),
        Arc::new(IpFilter::default()),
        Arc::default(),
    );
}

#[test]
fn verdict_and_companion_never_come_from_different_builds() {
    let e = Arc::new(SharedEngine::new());
    // Build A blocks a.test, build B blocks b.test; the companion names the build.
    install(&e, "||a.test^", 1);
    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let (e, stop) = (e.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) && n < 2000 {
                if n.is_multiple_of(2) {
                    install(&e, "||b.test^", 2);
                } else {
                    install(&e, "||a.test^", 1);
                }
                n += 1;
            }
        })
    };
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let e = e.clone();
            std::thread::spawn(move || {
                for _ in 0..5000 {
                    let (a, g) = e.check_gen("http://a.test/x", "http://s.test/", "script", "t");
                    let tag = *g.aux::<u64>().unwrap();
                    assert_eq!(a.blocked, tag == 1, "a.test verdict vs build {tag}");
                    let (b, g) = e.check_gen("http://b.test/x", "http://s.test/", "script", "t");
                    let tag = *g.aux::<u64>().unwrap();
                    assert_eq!(b.blocked, tag == 2, "b.test verdict vs build {tag}");
                }
            })
        })
        .collect();
    for r in readers {
        r.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    swapper.join().unwrap();
}

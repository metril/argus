#![cfg(feature = "store")]

use common::db::Db;
use script_policy::store::{Clock, PolicyStore, StoreError};
use script_policy::Capability as C;
use script_policy::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn clock() -> (Arc<AtomicU64>, Clock) {
    let t = Arc::new(AtomicU64::new(1_000));
    let t2 = t.clone();
    (t, Arc::new(move || t2.load(Ordering::SeqCst)))
}

fn open(dir: &std::path::Path, c: Clock) -> PolicyStore {
    PolicyStore::with_clock(Db::open(dir).unwrap(), c)
}

#[test]
fn rules_persist_across_reopen_and_generation_bumps() {
    let dir = tempfile::tempdir().unwrap();
    let (_t, c) = clock();
    let (site_id, g1);
    {
        let s = open(dir.path(), c.clone());
        assert_eq!(s.snapshot(DEFAULT_PROFILE).unwrap().generation(), 1);
        let mut st = s.rules(DEFAULT_PROFILE).unwrap().settings;
        st.enabled = true;
        st.global = Preset::Untrusted;
        s.set_settings(DEFAULT_PROFILE, st).unwrap();
        let r = s
            .create_site_rule(
                DEFAULT_PROFILE,
                Scope::parse("example.com").unwrap(),
                Preset::Trusted,
                Some("n".into()),
            )
            .unwrap();
        site_id = r.id;
        s.create_source_rule(
            DEFAULT_PROFILE,
            Scope::parse("example.com").unwrap(),
            Scope::parse("host:cdn.net").unwrap(),
            CapSet::of(&[C::Script]),
            Effect::Allow,
            None,
        )
        .unwrap();
        g1 = s.generation(DEFAULT_PROFILE).unwrap();
        assert!(g1 >= 3);
        // Profiles are independent.
        assert!(s.rules("other").unwrap().site_rules.is_empty());
        Db::sync_all();
    }
    // Same process, same dir: Db::open returns the live handle; the store reloads from redb.
    let s = open(dir.path(), c);
    let r = s.rules(DEFAULT_PROFILE).unwrap();
    assert!(r.settings.enabled);
    assert_eq!(r.site_rules[&site_id].note.as_deref(), Some("n"));
    assert_eq!(r.source_rules.len(), 1);
    let snap = s.snapshot(DEFAULT_PROFILE).unwrap();
    assert!(snap.generation() >= g1);
    assert_eq!(
        snap.decide("https", "example.com", None).profile(),
        Profile::TRUSTED
    );
    assert_eq!(
        snap.decide("https", "unknown.org", None).profile(),
        Profile::UNTRUSTED
    );
}

#[test]
fn conflicts_validation_and_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let (_t, c) = clock();
    let s = open(dir.path(), c);
    let sc = || Scope::parse("example.com").unwrap();
    s.create_site_rule(DEFAULT_PROFILE, sc(), Preset::Trusted, None)
        .unwrap();
    assert!(matches!(
        s.create_site_rule(DEFAULT_PROFILE, sc(), Preset::Untrusted, None),
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(
        s.create_site_rule(DEFAULT_PROFILE, Scope::Global, Preset::Untrusted, None),
        Err(StoreError::Rule(_))
    ));
    assert!(matches!(
        s.delete_site_rule(DEFAULT_PROFILE, "nope"),
        Err(StoreError::NotFound(_))
    ));
    assert!(matches!(
        s.create_source_rule(
            DEFAULT_PROFILE,
            sc(),
            Scope::Global,
            CapSet::of(&[C::Eval]),
            Effect::Allow,
            None
        ),
        Err(StoreError::Rule(_))
    ));
    // A failed edit changes nothing (generation included).
    let g = s.generation(DEFAULT_PROFILE).unwrap();
    let _ = s.delete_site_rule(DEFAULT_PROFILE, "nope");
    assert_eq!(s.generation(DEFAULT_PROFILE).unwrap(), g);
}

#[test]
fn temp_grants_expire_with_the_clock_and_persist_only_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let (t, c) = clock();
    let s = open(dir.path(), c.clone());
    let mut st = s.rules(DEFAULT_PROFILE).unwrap().settings;
    st.enabled = true;
    st.global = Preset::Untrusted;
    s.set_settings(DEFAULT_PROFILE, st).unwrap();
    let page = Scope::parse("example.com").unwrap();
    let kind = || GrantKind::Site {
        preset: Preset::Trusted,
    };
    let timed = s
        .grant_temp(DEFAULT_PROFILE, page.clone(), kind(), Some(60), false, true)
        .unwrap();
    let session = s
        .grant_temp(
            DEFAULT_PROFILE,
            Scope::parse("other.com").unwrap(),
            kind(),
            None,
            true,
            false,
        )
        .unwrap();
    assert!(s
        .grant_temp(DEFAULT_PROFILE, page.clone(), kind(), None, false, false)
        .is_err());
    assert!(s
        .grant_temp(DEFAULT_PROFILE, page.clone(), kind(), None, true, true)
        .is_err());
    let trusted = |s: &PolicyStore, h: &str| {
        s.snapshot(DEFAULT_PROFILE)
            .unwrap()
            .decide("https", h, None)
            .profile()
            == Profile::TRUSTED
    };
    assert!(trusted(&s, "example.com") && trusted(&s, "other.com"));
    let g = s.generation(DEFAULT_PROFILE).unwrap();
    // Expiry: the snapshot is rebuilt lazily and the generation changes (cache key).
    t.store(1_061, Ordering::SeqCst);
    assert!(!trusted(&s, "example.com"));
    assert!(trusted(&s, "other.com"));
    assert!(s.generation(DEFAULT_PROFILE).unwrap() > g);
    assert_eq!(s.rules(DEFAULT_PROFILE).unwrap().temps.len(), 1);
    // Restart: persisted+active grants come back, until-restart ones do not.
    t.store(1_010, Ordering::SeqCst);
    let s2 = open(dir.path(), c);
    let temps = s2.rules(DEFAULT_PROFILE).unwrap().temps;
    assert!(temps.contains_key(&timed.id));
    assert!(!temps.contains_key(&session.id));
    // Revoke and revoke-all.
    s2.revoke_temp(DEFAULT_PROFILE, &timed.id).unwrap();
    assert!(matches!(
        s2.revoke_temp(DEFAULT_PROFILE, &timed.id),
        Err(StoreError::NotFound(_))
    ));
    s2.grant_temp(DEFAULT_PROFILE, page, kind(), Some(5), false, false)
        .unwrap();
    assert_eq!(s2.revoke_all_temps(DEFAULT_PROFILE).unwrap(), 1);
}

#[test]
fn import_export_through_the_store_and_reports() {
    let dir = tempfile::tempdir().unwrap();
    let (_t, c) = clock();
    let s = open(dir.path(), c);
    s.create_site_rule(
        DEFAULT_PROFILE,
        Scope::parse("a.com").unwrap(),
        Preset::Trusted,
        None,
    )
    .unwrap();
    let doc = s.rules(DEFAULT_PROFILE).unwrap().export();
    s.create_site_rule(
        DEFAULT_PROFILE,
        Scope::parse("b.com").unwrap(),
        Preset::Trusted,
        None,
    )
    .unwrap();
    s.import(DEFAULT_PROFILE, doc.clone(), true).unwrap();
    assert_eq!(s.rules(DEFAULT_PROFILE).unwrap().export(), doc);
    // Reports.
    s.record_block(
        DEFAULT_PROFILE,
        "a.com",
        BlockEvent {
            cap: C::Script,
            source: Some("cdn.net".into()),
            sample: None,
            via: Via::Network,
        },
    );
    assert_eq!(
        s.report_for(DEFAULT_PROFILE, "a.com").unwrap().items.len(),
        1
    );
    assert_eq!(s.report_pages(DEFAULT_PROFILE).len(), 1);
}

#[test]
fn pin_lockout_is_per_client_and_per_profile_backs_off_exponentially_and_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let (t, c) = clock();
    let st = open(dir.path(), c.clone());
    let wait = |s: &PolicyStore, ip: &str| s.pin_wait("p", ip).unwrap();
    for _ in 0..4 {
        st.pin_failed("p", "10.0.0.1").unwrap();
    }
    assert_eq!(wait(&st, "10.0.0.1"), 0, "five free tries");
    st.pin_failed("p", "10.0.0.1").unwrap();
    let w1 = wait(&st, "10.0.0.1");
    assert!((1..=30).contains(&w1), "{w1}");
    assert_eq!(wait(&st, "10.0.0.2"), 0, "another client is not locked");
    st.pin_failed("p", "10.0.0.1").unwrap();
    let w2 = wait(&st, "10.0.0.1");
    assert!(w2 > w1 && w2 <= 60, "backoff doubles: {w1} -> {w2}");
    // Survives a reopen of the store.
    drop(st);
    let st = open(dir.path(), c.clone());
    assert!(wait(&st, "10.0.0.1") > 0, "lock survives restart");
    // Time passes: the lock lapses; a correct PIN clears the counters.
    t.fetch_add(120, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(wait(&st, "10.0.0.1"), 0);
    st.pin_failed("p", "10.0.0.1").unwrap();
    st.pin_ok("p", "10.0.0.1").unwrap();
    st.pin_failed("p", "10.0.0.1").unwrap();
    assert_eq!(wait(&st, "10.0.0.1"), 0, "counter was cleared");
    // Many clients together trip the per-profile backoff.
    for i in 0..20 {
        st.pin_failed("q", &format!("192.168.0.{i}")).unwrap();
    }
    assert!(
        st.pin_wait("q", "192.168.9.9").unwrap() > 0,
        "profile-wide lock"
    );
}

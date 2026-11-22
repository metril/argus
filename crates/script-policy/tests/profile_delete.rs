#![cfg(feature = "store")]

use common::db::Db;
use script_policy::panel::PanelSettings;
use script_policy::store::PolicyStore;
use script_policy::*;

#[test]
fn delete_profile_removes_rules_grants_panel_and_lockout_only_for_that_profile() {
    let dir = tempfile::tempdir().unwrap();
    let st = PolicyStore::new(Db::open(dir.path()).unwrap());
    let fill = |p: &str| {
        st.create_site_rule(
            p,
            Scope::parse("example.com").unwrap(),
            Preset::Trusted,
            None,
        )
        .unwrap();
        st.grant_temp(
            p,
            Scope::parse("example.com").unwrap(),
            GrantKind::Site {
                preset: Preset::Trusted,
            },
            Some(600),
            false,
            true,
        )
        .unwrap();
        st.set_panel_settings(
            p,
            &PanelSettings {
                pin_hash: Some("hash".into()),
                ..Default::default()
            },
        )
        .unwrap();
        for _ in 0..8 {
            st.pin_failed(p, "10.0.0.1").unwrap();
        }
    };
    fill("gone");
    fill("kept");
    assert!(st.pin_wait("gone", "10.0.0.1").unwrap() > 0);

    st.delete_profile("gone").unwrap();
    // A profile recreated under the same name starts empty.
    let r = st.rules("gone").unwrap();
    assert!(r.site_rules.is_empty() && r.temps.is_empty());
    assert!(st.panel_settings("gone").unwrap().pin_hash.is_none());
    assert_eq!(st.pin_wait("gone", "10.0.0.1").unwrap(), 0);
    // Other profiles are untouched; the default profile is refused.
    assert_eq!(st.rules("kept").unwrap().site_rules.len(), 1);
    assert_eq!(st.rules("kept").unwrap().temps.len(), 1);
    assert!(st.panel_settings("kept").unwrap().pin_hash.is_some());
    assert!(st.pin_wait("kept", "10.0.0.1").unwrap() > 0);
    assert!(st.delete_profile(DEFAULT_PROFILE).is_err());
}

//! The opt-in Strict blocking profile: extra annoyance/social/tracker lists on top of the default
//! set. The store remembers exactly what Strict changed, so switching back undoes only that and
//! never touches lists the user added or toggled themselves.

use std::collections::BTreeSet;

use filter_engine::{FilterList, STRICT_ARGUS_EXTRA_ID};
use serde::{Deserialize, Serialize};

use crate::{ListStore, Result};

const KEY: &str = "strict_profile";

/// Persisted Strict state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StrictState {
    pub active: bool,
    /// Lists Strict created (removed again on switching back).
    #[serde(default)]
    pub added: BTreeSet<String>,
    /// Existing lists Strict switched on (switched off again on switching back).
    #[serde(default)]
    pub enabled: BTreeSet<String>,
}

/// Outcome of applying the profile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StrictProfile {
    pub state: StrictState,
    /// Strict lists that could not be added yet (the signed `argus-extra` list while the signed
    /// catalogue has not loaded); applying again later adds them.
    pub pending: Vec<String>,
}

impl ListStore {
    /// The persisted Strict state (inactive when never switched on).
    pub fn strict_state(&self) -> Result<StrictState> {
        Ok(match self.get_meta(KEY)? {
            Some(b) => serde_json::from_slice(&b).unwrap_or_default(),
            None => StrictState::default(),
        })
    }

    fn set_strict_state(&self, s: &StrictState) -> Result<()> {
        let b = serde_json::to_vec(s).map_err(|e| crate::Error::Storage(e.to_string()))?;
        self.put_meta(KEY, &b)
    }

    /// Switch Strict on: enable the built-in Strict lists plus `signed` (every `profile: strict`
    /// entry of the signed catalogue, `None` while it is not loaded, which leaves `argus-extra`
    /// pending). Idempotent; lists already present and enabled are left alone and not recorded.
    pub fn strict_enable(&self, signed: Option<Vec<FilterList>>) -> Result<StrictProfile> {
        let _g = self.strict_lock.lock();
        let st = self.strict_state()?;
        let mut wanted = filter_engine::strict_catalogue_lists();
        let mut pending = Vec::new();
        match signed {
            Some(v) => {
                for mut l in v {
                    l.enabled = true;
                    if !wanted.iter().any(|w| w.id == l.id) {
                        wanted.push(l);
                    }
                }
            }
            None => pending.push(STRICT_ARGUS_EXTRA_ID.to_string()),
        }
        let st = self.strict_enable_tx(KEY, wanted, st)?;
        Ok(StrictProfile { state: st, pending })
    }

    /// Switch Strict off: remove the lists it added and disable the ones it enabled.
    pub fn strict_disable(&self) -> Result<StrictState> {
        let _g = self.strict_lock.lock();
        let st = self.strict_state()?;
        for id in &st.added {
            self.remove(id)?;
        }
        for id in &st.enabled {
            self.set_enabled(id, false)?;
        }
        let off = StrictState::default();
        self.set_strict_state(&off)?;
        Ok(off)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (ListStore, tempfile::TempDir) {
        let d = tempfile::tempdir().unwrap();
        (ListStore::new(d.path()).unwrap(), d)
    }

    fn cat(id: &str) -> FilterList {
        filter_engine::catalogue()
            .into_iter()
            .find(|e| e.id == id)
            .unwrap()
            .to_filter_list()
    }

    #[test]
    fn the_profile_field_is_optional_and_only_strict_counts() {
        let entry = |extra: &str| -> crate::FilterCatalogueEntry {
            serde_json::from_str(&format!(
                r#"{{"id":"a","name":"A","url":"https://e/a.txt","format":"abp","category":"ads"{extra}}}"#
            ))
            .unwrap()
        };
        assert!(!entry("").is_strict(), "missing");
        assert!(!entry(r#","profile":null"#).is_strict(), "null");
        assert!(
            !entry(r#","profile":"paranoid""#).is_strict(),
            "unknown value"
        );
        assert!(
            entry(r#","profile":"strict","new_field":1"#).is_strict(),
            "unknown field"
        );
        assert!(entry(r#","profile":"strict""#).is_strict());
    }

    #[test]
    fn a_fetch_finishing_after_disable_does_not_re_enable_or_resurrect() {
        let (s, _d) = store();
        s.strict_enable(None).unwrap();
        // A fetch took its snapshot while Strict was on.
        let snapshot = s.get("fanboy-social").unwrap().unwrap();
        s.strict_disable().unwrap();
        // The late write-back touches only fetch metadata, and a deleted list stays deleted.
        let wrote = s
            .update_list(&snapshot.id, |l| {
                l.etag = Some("e".into());
                l.rule_count = 5;
            })
            .unwrap();
        assert!(!wrote);
        assert!(s.get("fanboy-social").unwrap().is_none());

        // A list that survives (user-owned, disabled) keeps `enabled` through a fetch update.
        let mut mine = cat("fanboy-social");
        mine.enabled = false;
        s.upsert(&mine).unwrap();
        assert!(s
            .update_list("fanboy-social", |l| l.rule_count = 9)
            .unwrap());
        let got = s.get("fanboy-social").unwrap().unwrap();
        assert!(!got.enabled);
        assert_eq!(got.rule_count, 9);
    }

    #[test]
    fn concurrent_toggles_leave_consistent_state() {
        let (s, _d) = store();
        let s = std::sync::Arc::new(s);
        let hs: Vec<_> = (0..8)
            .map(|i| {
                let s = s.clone();
                std::thread::spawn(move || {
                    if i % 2 == 0 {
                        s.strict_enable(None).unwrap();
                    } else {
                        s.strict_disable().unwrap();
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        let st = s.strict_state().unwrap();
        for l in filter_engine::strict_catalogue_lists() {
            // Every Strict list in the store is recorded, so a disable can remove it.
            assert_eq!(
                s.get(&l.id).unwrap().is_some(),
                st.active && st.added.contains(&l.id)
            );
        }
        s.strict_disable().unwrap();
        for l in filter_engine::strict_catalogue_lists() {
            assert!(s.get(&l.id).unwrap().is_none());
        }
    }

    #[test]
    fn enable_records_every_added_list_with_the_lists() {
        let (s, _d) = store();
        s.strict_enable(None).unwrap();
        let st = s.strict_state().unwrap();
        for l in filter_engine::strict_catalogue_lists() {
            assert!(s.get(&l.id).unwrap().is_some());
            assert!(st.added.contains(&l.id), "{} unrecorded", l.id);
        }
    }

    #[test]
    fn strict_entries_are_never_seeded() {
        let (s, _d) = store();
        s.seed_defaults_if_empty().unwrap();
        for l in filter_engine::strict_catalogue_lists() {
            assert!(s.get(&l.id).unwrap().is_none(), "{} seeded", l.id);
        }
        assert!(!s.strict_state().unwrap().active);
    }

    #[test]
    fn strict_adds_then_reverts_only_its_own_lists() {
        let (s, _d) = store();
        s.seed_defaults_if_empty().unwrap();
        let user = FilterList::new("mine".into(), "Mine".into(), "https://e/x.txt".into());
        s.upsert(&user).unwrap();
        // A Strict list the user has but disabled: Strict switches it on, revert off again.
        s.upsert(&cat("fanboy-social")).unwrap();
        // One the user already runs enabled: untouched both ways.
        let mut keep = cat("easylist-cookie");
        keep.enabled = true;
        s.upsert(&keep).unwrap();
        let before = s.get_all().unwrap().len();

        let p = s.strict_enable(None).unwrap();
        assert_eq!(p.pending, vec!["argus-extra"], "fail-safe until loaded");
        assert!(s.get("argus-extra").unwrap().is_none());
        assert!(s.get("ublock-annoyances").unwrap().unwrap().enabled);
        assert!(s.get("fanboy-social").unwrap().unwrap().enabled);
        assert!(s.strict_state().unwrap().active);

        // Applying again once the signed list is known adds it; nothing is lost.
        let extra = FilterList::new(
            "argus-extra".into(),
            "Argus Extra Trackers".into(),
            "https://e/a.txt".into(),
        );
        let p = s.strict_enable(Some(vec![extra])).unwrap();
        assert!(p.pending.is_empty());
        assert!(s.get("argus-extra").unwrap().unwrap().enabled);

        s.strict_disable().unwrap();
        assert!(!s.strict_state().unwrap().active);
        assert!(s.get("ublock-annoyances").unwrap().is_none());
        assert!(s.get("argus-extra").unwrap().is_none());
        assert!(!s.get("fanboy-social").unwrap().unwrap().enabled);
        assert!(s.get("easylist-cookie").unwrap().unwrap().enabled);
        assert!(s.get("mine").unwrap().unwrap().enabled);
        assert_eq!(s.get_all().unwrap().len(), before);
    }
}

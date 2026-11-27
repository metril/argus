//! The `default` signed-catalogue profile: lists the catalogue offers to every install, once.
//! The ids already offered are kept in META, so a list the user removes or disables stays that
//! way and is never added again.

use std::collections::BTreeSet;

use filter_engine::FilterList;

use crate::{ListStore, Result};

const KEY: &str = "default_offered";

impl ListStore {
    /// Ids of the `default`-profile lists already offered (never offered again).
    pub fn default_offered(&self) -> Result<BTreeSet<String>> {
        Ok(match self.get_meta(KEY)? {
            Some(b) => serde_json::from_slice(&b).unwrap_or_default(),
            None => BTreeSet::new(),
        })
    }

    /// Add and enable every list of `wanted` (the verified signed catalogue's `profile: default`
    /// entries) not offered before, and record it as offered. A list the store already has is
    /// recorded but left as the user set it. Returns the ids added. Goes through the same lock as
    /// Strict; call only once the catalogue has loaded (fail-safe: never offered before that).
    pub fn default_offer(&self, wanted: Vec<FilterList>) -> Result<Vec<String>> {
        let _g = self.strict_lock.lock();
        let offered = self.default_offered()?;
        if wanted.iter().all(|l| offered.contains(&l.id)) {
            return Ok(Vec::new());
        }
        self.default_offer_tx(KEY, wanted, offered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (ListStore, tempfile::TempDir) {
        let d = tempfile::tempdir().unwrap();
        (ListStore::new(d.path()).unwrap(), d)
    }

    fn base() -> FilterList {
        let mut l = FilterList::new(
            "argus-base".into(),
            "Argus Base".into(),
            "https://e/base.txt".into(),
        );
        l.enabled = true;
        l
    }

    #[test]
    fn fresh_install_gets_the_list_enabled_once() {
        let (s, _d) = store();
        assert!(
            s.get("argus-base").unwrap().is_none(),
            "fail-safe before load"
        );
        s.seed_defaults_if_empty().unwrap();
        assert!(s.get("argus-base").unwrap().is_none(), "never seeded");
        assert_eq!(s.default_offer(vec![base()]).unwrap(), vec!["argus-base"]);
        assert!(s.get("argus-base").unwrap().unwrap().enabled);
        assert!(s.default_offered().unwrap().contains("argus-base"));
        assert!(s.default_offer(vec![base()]).unwrap().is_empty());
    }

    #[test]
    fn existing_install_gets_it_without_touching_other_lists() {
        let (s, _d) = store();
        s.seed_defaults_if_empty().unwrap();
        let mut mine = FilterList::new("mine".into(), "Mine".into(), "https://e/m.txt".into());
        mine.enabled = false;
        s.upsert(&mine).unwrap();
        let before = s.get_all().unwrap().len();
        s.default_offer(vec![base()]).unwrap();
        assert_eq!(s.get_all().unwrap().len(), before + 1);
        assert!(!s.get("mine").unwrap().unwrap().enabled);
        assert!(s.get("argus-base").unwrap().unwrap().enabled);
    }

    #[test]
    fn a_removed_or_disabled_list_is_never_re_added_or_re_enabled() {
        let (s, _d) = store();
        s.default_offer(vec![base()]).unwrap();
        s.set_enabled("argus-base", false).unwrap();
        assert!(s.default_offer(vec![base()]).unwrap().is_empty());
        assert!(!s.get("argus-base").unwrap().unwrap().enabled);
        s.remove("argus-base").unwrap();
        assert!(s.default_offer(vec![base()]).unwrap().is_empty());
        assert!(s.get("argus-base").unwrap().is_none());
    }

    #[test]
    fn a_list_the_user_already_has_is_left_as_is_and_recorded() {
        let (s, _d) = store();
        let mut mine = base();
        mine.enabled = false;
        s.upsert(&mine).unwrap();
        assert!(s.default_offer(vec![base()]).unwrap().is_empty());
        assert!(!s.get("argus-base").unwrap().unwrap().enabled);
        assert!(s.default_offered().unwrap().contains("argus-base"));
    }

    #[test]
    fn a_later_catalogue_entry_is_offered_without_repeating_old_ones() {
        let (s, _d) = store();
        s.default_offer(vec![base()]).unwrap();
        s.remove("argus-base").unwrap();
        let mut other = base();
        other.id = "argus-more".into();
        assert_eq!(
            s.default_offer(vec![base(), other]).unwrap(),
            vec!["argus-more"]
        );
        assert!(s.get("argus-base").unwrap().is_none());
    }

    #[test]
    fn the_strict_toggle_never_touches_default_lists() {
        let (s, _d) = store();
        s.default_offer(vec![base()]).unwrap();
        s.strict_enable(None).unwrap();
        assert!(s.get("argus-base").unwrap().unwrap().enabled);
        s.strict_disable().unwrap();
        assert!(s.get("argus-base").unwrap().unwrap().enabled);
        // Even if Strict had recorded it, disabling must not remove or disable it.
        let mut st = s.strict_state().unwrap();
        st.added.insert("argus-base".into());
        st.enabled.insert("argus-base".into());
        st.active = true;
        s.put_meta("strict_profile", &serde_json::to_vec(&st).unwrap())
            .unwrap();
        s.strict_disable().unwrap();
        assert!(s.get("argus-base").unwrap().unwrap().enabled);
    }
}

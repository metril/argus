//! Display names and categories of the lists that rules and blocks are attributed to. The
//! attribution itself happens at build time (the engine generation maps each compiled rule to
//! its list, see `filter_engine::origins`); nothing here scans lists.

use crate::state::AppState;

/// List id reported for the user's own rules.
pub const CUSTOM_ID: &str = "custom";
/// The id the build gives the custom rules (they are compiled as a list of their own).
const CUSTOM_BUILD_ID: &str = "\0custom";

/// Is `id` the user's own rules?
pub fn is_custom(id: &str) -> bool {
    id == CUSTOM_ID || id == CUSTOM_BUILD_ID
}

/// The id as the API shows it.
pub fn public_id(id: &str) -> &str {
    if is_custom(id) {
        CUSTOM_ID
    } else {
        id
    }
}

impl AppState {
    /// Display name of a list id (the custom rules included).
    pub fn list_name(&self, id: &str) -> Option<String> {
        if is_custom(id) {
            return Some("Custom rules".into());
        }
        if let Ok(Some(l)) = self.filter_store.get(id) {
            return Some(l.name);
        }
        if let Some(doc) = self.filter_catalogue().get() {
            if let Some(e) = doc.entries.iter().find(|e| e.id == id) {
                return Some(e.name.clone());
            }
        }
        None
    }

    /// Category index (see [`crate::daily::CATEGORIES`]) of a list id.
    pub fn list_category(&self, id: &str) -> usize {
        if is_custom(id) {
            return crate::daily::OTHER;
        }
        if let Some(doc) = self.filter_catalogue().get() {
            if let Some(e) = doc.entries.iter().find(|e| e.id == id) {
                return crate::daily::category_index(&e.category);
            }
        }
        filter_engine::catalogue()
            .iter()
            .find(|e| e.id == id)
            .map_or(crate::daily::OTHER, |e| {
                crate::daily::category_index(e.category)
            })
    }

    /// Attribute the blocks tallied since the last call to categories: by the catalogue category
    /// of the list that blocked them; blocks with no known list count as `other`.
    pub fn take_category_counts(&self) -> crate::daily::Counts {
        let (by_list, by_rule) = self.filter_stats.take_sources();
        let mut out = [0u64; 6];
        for (id, n) in by_list {
            out[self.list_category(&id)] += n;
        }
        out[crate::daily::OTHER] += by_rule.iter().map(|(_, n)| n).sum::<u64>();
        out
    }
}

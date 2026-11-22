//! Pinned snapshot of the uBlock Origin scriptlet library, embedded as the offline fallback.
//!
//! See `resources/SOURCE.txt` for the upstream commit and licence. A copy fetched at runtime (or
//! cached on disk) takes precedence over this one.

/// adblock-rust resources JSON array (scriptlets with dependencies and aliases).
pub const BUNDLED_RESOURCES_JSON: &str = include_str!("../resources/ubo-resources.json");

/// Upstream commit of the bundled snapshot.
pub const BUNDLED_RESOURCES_COMMIT: &str = "5934db2a0437a50182c4a8f3da2e0941cf806253";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_snapshot_parses_and_has_core_scriptlets() {
        let v: Vec<serde_json::Value> = serde_json::from_str(BUNDLED_RESOURCES_JSON).unwrap();
        assert!(v.len() > 80, "{} resources", v.len());
        // Names or aliases (e.g. `no-fetch-if.js` is an alias of `prevent-fetch.js`).
        let has = |n: &str| {
            v.iter().any(|r| {
                r["name"] == n
                    || r["aliases"]
                        .as_array()
                        .is_some_and(|a| a.iter().any(|x| x == n))
            })
        };
        for name in [
            "abort-on-property-read.js",
            "set-constant.js",
            "no-fetch-if.js",
            "json-prune.js",
        ] {
            assert!(has(name), "{name}");
        }
        assert!(BUNDLED_RESOURCES_JSON.len() < 400_000);
    }
}

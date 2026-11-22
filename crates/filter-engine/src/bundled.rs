//! Pinned snapshot of the uBlock Origin scriptlet library (GPL-3.0), embedded as an offline
//! fallback **only with the `bundled-ubo-resources` cargo feature** (off by default so the default
//! build carries no GPL code). Without it these constants are empty and the offline fallback is
//! the on-disk cache of the last successful fetch.
//!
//! See `resources/SOURCE.txt` and `docs/LICENSING.md`. A copy fetched at runtime (or cached on
//! disk) takes precedence over this one.

/// adblock-rust resources JSON array (scriptlets with dependencies and aliases); empty unless the
/// `bundled-ubo-resources` feature is on.
#[cfg(feature = "bundled-ubo-resources")]
pub const BUNDLED_RESOURCES_JSON: &str = include_str!("../resources/ubo-resources.json");
#[cfg(not(feature = "bundled-ubo-resources"))]
pub const BUNDLED_RESOURCES_JSON: &str = "";

/// Upstream commit of the bundled snapshot (empty when not bundled).
#[cfg(feature = "bundled-ubo-resources")]
pub const BUNDLED_RESOURCES_COMMIT: &str = "5934db2a0437a50182c4a8f3da2e0941cf806253";
#[cfg(not(feature = "bundled-ubo-resources"))]
pub const BUNDLED_RESOURCES_COMMIT: &str = "";

/// Whether the uBO snapshot is compiled in.
pub const BUNDLED_AVAILABLE: bool = cfg!(feature = "bundled-ubo-resources");

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "bundled-ubo-resources"))]
    #[test]
    fn nothing_bundled_by_default() {
        assert!(!BUNDLED_AVAILABLE);
        assert!(BUNDLED_RESOURCES_JSON.is_empty() && BUNDLED_RESOURCES_COMMIT.is_empty());
    }

    #[cfg(feature = "bundled-ubo-resources")]
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

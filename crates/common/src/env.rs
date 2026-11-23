//! Environment variable lookup with a deprecated `ADBLOCKER_*` fallback for `ARGUS_*`.

use std::collections::HashSet;
use std::ffi::OsString;
use std::sync::Mutex;

static WARNED: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// Resolve `ARGUS_<suffix>`, falling back to the legacy `ADBLOCKER_<suffix>`.
/// Returns the value and whether the legacy name supplied it.
pub fn resolve(suffix: &str, get: impl Fn(&str) -> Option<OsString>) -> (Option<OsString>, bool) {
    if let Some(v) = get(&format!("ARGUS_{suffix}")) {
        return (Some(v), false);
    }
    match get(&format!("ADBLOCKER_{suffix}")) {
        Some(v) => (Some(v), true),
        None => (None, false),
    }
}

/// Look up `ARGUS_<suffix>` in the process environment (legacy fallback, warns once per variable).
pub fn var_os(suffix: &str) -> Option<OsString> {
    let (v, legacy) = resolve(suffix, |k| std::env::var_os(k));
    if legacy {
        let mut g = WARNED.lock().unwrap_or_else(|e| e.into_inner());
        if g.get_or_insert_with(HashSet::new)
            .insert(suffix.to_string())
        {
            tracing::warn!(
                "environment variable ADBLOCKER_{suffix} is deprecated; use ARGUS_{suffix}"
            );
        }
    }
    v
}

/// Lookup without logging (for use before the tracing subscriber exists).
pub fn peek_os(suffix: &str) -> Option<OsString> {
    resolve(suffix, |k| std::env::var_os(k)).0
}

/// Like [`var_os`], as a UTF-8 string.
pub fn var(suffix: &str) -> Option<String> {
    var_os(suffix).and_then(|v| v.into_string().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let m: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), OsString::from(v)))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn new_name_wins() {
        let (v, legacy) = resolve("X", env(&[("ARGUS_X", "new"), ("ADBLOCKER_X", "old")]));
        assert_eq!(v.unwrap(), "new");
        assert!(!legacy);
    }

    #[test]
    fn legacy_name_is_accepted_and_flagged() {
        let (v, legacy) = resolve("X", env(&[("ADBLOCKER_X", "old")]));
        assert_eq!(v.unwrap(), "old");
        assert!(legacy);
    }

    #[test]
    fn unset_is_none() {
        assert_eq!(resolve("X", env(&[])), (None, false));
    }

    #[test]
    fn warns_once_per_variable() {
        use std::sync::{Arc, Mutex};
        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let b2 = buf.clone();
        let sub = tracing_subscriber::fmt()
            .with_writer(move || b2.clone())
            .with_ansi(false)
            .finish();
        // Unique suffix: the warned-set is process-global.
        std::env::set_var("ADBLOCKER_ENVTEST_ONCE", "1");
        tracing::subscriber::with_default(sub, || {
            assert!(var_os("ENVTEST_ONCE").is_some());
            assert!(var_os("ENVTEST_ONCE").is_some());
        });
        std::env::remove_var("ADBLOCKER_ENVTEST_ONCE");
        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert_eq!(out.matches("deprecated").count(), 1, "{out}");
        assert!(out.contains("ARGUS_ENVTEST_ONCE"));
    }
}

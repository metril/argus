//! Per-site "ad blocking off": a plain document exception line in the custom rules
//! (`@@||example.com^$document`), so it works with the engine's normal exception handling,
//! shows up in the custom-rules editor and needs no extra storage.
//!
//! The functions are pure text edits; callers write the result with
//! [`crate::ListStore::set_custom_rules`] and trigger a rebuild.

/// The exception line for `site`, or `None` when `site` is not a plain host name (letters,
/// digits, `-`, `.`; at most 253 characters): nothing else may ever reach the rule text.
pub fn exception_line(site: &str) -> Option<String> {
    let ok = !site.is_empty()
        && site.len() <= 253
        && !site.starts_with(['.', '-'])
        && !site.ends_with(['.', '-'])
        && site
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    ok.then(|| format!("@@||{site}^$document"))
}

/// Sites with an exception line in `rules`, in order of appearance.
pub fn list(rules: &str) -> Vec<String> {
    rules
        .lines()
        .filter_map(|l| {
            let site = l.trim().strip_prefix("@@||")?.strip_suffix("^$document")?;
            exception_line(site).map(|_| site.to_string())
        })
        .collect()
}

pub fn is_disabled(rules: &str, site: &str) -> bool {
    exception_line(site).is_some_and(|line| rules.lines().any(|l| l.trim() == line))
}

/// `rules` with the exception for `site` present (`disabled`) or removed. Other lines are kept
/// verbatim. `None` for an invalid host name.
pub fn set(rules: &str, site: &str, disabled: bool) -> Option<String> {
    let line = exception_line(site)?;
    let present = is_disabled(rules, site);
    if disabled == present {
        return Some(rules.to_string());
    }
    if disabled {
        let mut out = rules.to_string();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&line);
        out.push('\n');
        return Some(out);
    }
    let mut out: String = rules
        .lines()
        .filter(|l| l.trim() != line)
        .collect::<Vec<_>>()
        .join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_remove_list() {
        let base = "||ads.example^\n! comment\n";
        let on = set(base, "shop.test", true).unwrap();
        assert!(on.starts_with(base) && on.ends_with("@@||shop.test^$document\n"));
        assert!(is_disabled(&on, "shop.test") && !is_disabled(&on, "other.test"));
        assert_eq!(list(&on), ["shop.test"]);
        assert_eq!(set(&on, "shop.test", true).unwrap(), on, "idempotent");
        assert_eq!(set(&on, "shop.test", false).unwrap(), base);
        assert_eq!(set("", "a.test", true).unwrap(), "@@||a.test^$document\n");
        assert_eq!(set("@@||a.test^$document\n", "a.test", false).unwrap(), "");
    }

    #[test]
    fn nothing_but_host_names_reach_the_rules() {
        for bad in ["", "a b.test", "a.test\n||x^", "A.test", "a.test/", "*.test", "-a.test", "a.test^$x", "é.test"] {
            assert!(set("", bad, true).is_none(), "{bad:?}");
        }
    }
}

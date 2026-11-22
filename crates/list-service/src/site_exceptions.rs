//! Per-site "ad blocking off", kept in the custom rules so it shows up in the custom-rules
//! editor and needs no extra storage: one `@@$domain=example.com` line per site (the engine then
//! lets the page's requests through, and `SharedEngine::site_off` makes the proxy leave its
//! cosmetic filtering, scriptlets and extended rules out), plus the sentinel rule
//! `||adblock.invalid^` that `site_off` probes while any site is excepted.
//!
//! The functions are pure text edits; callers write the result with
//! [`crate::ListStore::set_custom_rules`] and trigger a rebuild.

/// The sentinel rule `SharedEngine::site_off` probes.
pub const SENTINEL: &str = "||adblock.invalid^";

/// The exception line for `site`, or `None` when `site` is not a plain host name (letters,
/// digits, `-`, `.`; at most 253 characters): nothing else may ever reach the rule text.
pub fn exception_line(site: &str) -> Option<String> {
    valid(site).then(|| format!("@@$domain={site}"))
}

fn valid(site: &str) -> bool {
    let ok = !site.is_empty()
        && site.len() <= 253
        && !site.starts_with(['.', '-'])
        && !site.ends_with(['.', '-'])
        && site
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    ok
}

/// Sites with an exception line in `rules`, in order of appearance.
pub fn list(rules: &str) -> Vec<String> {
    rules
        .lines()
        .filter_map(|l| {
            let site = l.trim().strip_prefix("@@$domain=")?;
            exception_line(site).map(|_| site.to_string())
        })
        .collect()
}

pub fn is_disabled(rules: &str, site: &str) -> bool {
    exception_line(site).is_some_and(|line| rules.lines().any(|l| l.trim() == line))
}

/// `rules` with the exception for `site` present (`disabled`) or removed. Other lines are kept
/// verbatim; the sentinel is added with the first site and removed with the last. `None` for an
/// invalid host name.
pub fn set(rules: &str, site: &str, disabled: bool) -> Option<String> {
    let line = exception_line(site)?;
    let mut lines: Vec<&str> = rules.lines().collect();
    let present = lines.iter().any(|l| l.trim() == line);
    if disabled == present {
        return Some(rules.to_string());
    }
    if disabled {
        lines.push(&line);
        if !lines.iter().any(|l| l.trim() == SENTINEL) {
            lines.push(SENTINEL);
        }
    } else {
        lines.retain(|l| l.trim() != line);
        if list(&lines.join("\n")).is_empty() {
            lines.retain(|l| l.trim() != SENTINEL);
        }
    }
    let mut out = lines.join("\n");
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
        assert_eq!(on, format!("{base}@@$domain=shop.test\n{SENTINEL}\n"));
        assert!(is_disabled(&on, "shop.test") && !is_disabled(&on, "other.test"));
        assert_eq!(list(&on), ["shop.test"]);
        assert_eq!(set(&on, "shop.test", true).unwrap(), on, "idempotent");
        let two = set(&on, "b.test", true).unwrap();
        assert_eq!(
            two.matches(SENTINEL).count(),
            1,
            "one sentinel for all sites"
        );
        assert_eq!(set(&two, "b.test", false).unwrap(), on);
        assert_eq!(
            set(&on, "shop.test", false).unwrap(),
            base,
            "sentinel goes with the last site"
        );
        assert_eq!(
            set("", "a.test", true).unwrap(),
            format!("@@$domain=a.test\n{SENTINEL}\n")
        );
    }

    #[test]
    fn nothing_but_host_names_reach_the_rules() {
        for bad in [
            "",
            "a b.test",
            "a.test\n||x^",
            "A.test",
            "a.test/",
            "*.test",
            "-a.test",
            "a.test^$x",
            "é.test",
        ] {
            assert!(set("", bad, true).is_none(), "{bad:?}");
        }
    }
}

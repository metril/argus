//! Hosts whose TLS is never intercepted (certificate-pinned apps, banking, ...).

use std::collections::HashSet;

/// Exact names and `*.suffix` entries, matched case-insensitively. A `*.example.com` entry
/// matches subdomains (`a.example.com`, `a.b.example.com`) but not `example.com` itself.
#[derive(Debug, Default, Clone)]
pub struct PassthroughList {
    exact: HashSet<String>,
    /// Stored with the leading dot (`.example.com`).
    suffixes: Vec<String>,
}

fn normalize(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl PassthroughList {
    pub fn new<S: AsRef<str>>(entries: &[S]) -> Self {
        let mut list = Self::default();
        for e in entries {
            let e = normalize(e.as_ref());
            if let Some(suffix) = e.strip_prefix("*.") {
                if !suffix.is_empty() {
                    list.suffixes.push(format!(".{suffix}"));
                }
            } else if !e.is_empty() {
                list.exact.insert(e);
            }
        }
        list
    }

    pub fn matches(&self, host: &str) -> bool {
        if self.exact.is_empty() && self.suffixes.is_empty() {
            return false;
        }
        let host = normalize(host);
        self.exact.contains(&host) || self.suffixes.iter().any(|s| host.ends_with(s.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_wildcard_entries() {
        let l = PassthroughList::new(&["Bank.Example.com", "*.pinned.test", " ", "*."]);
        assert!(l.matches("bank.example.com"));
        assert!(l.matches("BANK.example.com."));
        assert!(!l.matches("www.bank.example.com"));
        assert!(l.matches("a.pinned.test"));
        assert!(l.matches("a.b.pinned.test"));
        assert!(!l.matches("pinned.test"));
        assert!(!l.matches("notpinned.test"));
        assert!(!PassthroughList::default().matches("x.test"));
    }
}

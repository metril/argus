//! Page-location scope of cosmetic / scriptlet / HTML-filter rules: AdGuard `[$path=…]` and
//! `[$domain=…]` prefixes (the document's hostname and its path plus query).

use regex::{Regex, RegexBuilder};

use crate::parse::{unsupported_or_invalid, RuleError};
use crate::util::{compile_slash_regex, DomainSet, REGEX_SIZE_LIMIT};

/// A `$path` condition.
#[derive(Debug, Clone)]
pub(crate) enum PathCond {
    /// `[$path]` without a pattern: the site's main page only (AdGuard KB).
    Main,
    /// Plain pattern (`|` anchors, `*`, `^`) or `/regex/`, matched against path plus query.
    Re(Regex),
}

impl PathCond {
    /// `pattern` is the `$path=` value (`None` or empty for the main page).
    pub fn parse(pattern: Option<&str>) -> Result<Self, String> {
        let p = pattern.unwrap_or("").trim();
        if p.is_empty() {
            return Ok(Self::Main);
        }
        if p.len() > 1 && p.starts_with('/') && p.ends_with('/') {
            return compile_slash_regex(p, false).map(Self::Re);
        }
        let (start, p) = match p.strip_prefix('|') {
            Some(r) => (true, r),
            None => (false, p),
        };
        let (end, p) = match p.strip_suffix('|') {
            Some(r) => (true, r),
            None => (false, p),
        };
        let body: Vec<String> = p
            .split('*')
            .map(|part| {
                part.split('^')
                    .map(regex::escape)
                    .collect::<Vec<_>>()
                    .join(r"(?:[^\w.%-]|$)")
            })
            .collect();
        let re = format!(
            "{}{}{}",
            if start { "^" } else { "" },
            body.join(".*"),
            if end { "$" } else { "" }
        );
        RegexBuilder::new(&re)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map(Self::Re)
            .map_err(|e| format!("unsupported path pattern: {e}"))
    }

    pub fn matches(&self, path_and_query: &str) -> bool {
        match self {
            Self::Main => path_and_query.split('?').next() == Some("/"),
            Self::Re(r) => r.is_match(path_and_query),
        }
    }
}

/// The `[$…]` prefix conditions, ANDed with the rule's ordinary domain list.
#[derive(Debug, Clone, Default)]
pub(crate) struct Location {
    pub path: Option<PathCond>,
    pub domain: Option<DomainSet>,
}

impl Location {
    /// Parse the `[$…]` modifiers. `path` and `domain` are enforced; anything else (`app`, `url`,
    /// unknown) makes the rule unsupported, never silently ignored.
    pub fn parse(mods: &[&str]) -> Result<Self, RuleError> {
        let mut loc = Location::default();
        for m in mods {
            let m = m.trim();
            let (name, val) = match m.split_once('=') {
                Some((n, v)) => (n.trim().to_ascii_lowercase(), Some(v)),
                None => (m.to_ascii_lowercase(), None),
            };
            match name.as_str() {
                "path" => {
                    if loc.path.is_some() {
                        return Err(RuleError::Invalid("duplicate `path` modifier".into()));
                    }
                    loc.path = Some(PathCond::parse(val).map_err(unsupported_or_invalid)?);
                }
                "domain" => {
                    if loc.domain.is_some() {
                        return Err(RuleError::Invalid("duplicate `domain` modifier".into()));
                    }
                    let v = val.filter(|v| !v.trim().is_empty()).ok_or_else(|| {
                        RuleError::Invalid("`domain` modifier needs a value".into())
                    })?;
                    loc.domain = Some(DomainSet::parse(v, '|').map_err(unsupported_or_invalid)?);
                }
                other => {
                    return Err(RuleError::Unsupported(format!(
                        "unsupported cosmetic modifier `{other}`"
                    )))
                }
            }
        }
        Ok(loc)
    }

    pub fn matches(&self, host: &str, path_and_query: &str) -> bool {
        self.domain.as_ref().is_none_or(|d| d.matches(host))
            && self.path.as_ref().is_none_or(|p| p.matches(path_and_query))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pc(p: &str) -> PathCond {
        PathCond::parse(Some(p)).unwrap()
    }

    #[test]
    fn path_patterns_follow_the_adguard_kb() {
        // KB examples.
        assert!(
            pc("page.html").matches("/sub/page.html")
                && pc("page.html").matches("/another_page.html")
        );
        assert!(
            pc("/page.html").matches("/sub/page.html")
                && !pc("/page.html").matches("/another_page.html")
        );
        assert!(
            pc("|/page.html").matches("/page.html?x")
                && !pc("|/page.html").matches("/sub/page.html")
        );
        assert!(
            pc("/page.html|").matches("/sub/page.html")
                && !pc("/page.html|").matches("/page.html?x")
        );
        assert!(pc("/page*.html").matches("/page2.html"));
        assert!(pc(r"/\/(sub1|sub2)\/page\.html/").matches("/sub2/page.html"));
        assert!(pc(r"/^\/$/").matches("/") && !pc(r"/^\/$/").matches("/a"));
        assert!(PathCond::parse(None).unwrap().matches("/?q=1") && !PathCond::Main.matches("/a"));
        assert!(PathCond::parse(Some("/(?=x)/"))
            .unwrap_err()
            .contains("unsupported"));
    }

    #[test]
    fn modifiers() {
        let l = Location::parse(&["domain=a.com|~b.a.com", "path=/x"]).unwrap();
        assert!(
            l.matches("a.com", "/x") && !l.matches("b.a.com", "/x") && !l.matches("a.com", "/y")
        );
        assert!(matches!(
            Location::parse(&["app=x"]),
            Err(RuleError::Unsupported(_))
        ));
        assert!(matches!(
            Location::parse(&["path=/a", "path=/b"]),
            Err(RuleError::Invalid(_))
        ));
    }
}

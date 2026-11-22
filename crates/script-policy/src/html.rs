//! What the HTML rewriter does beyond CSP, expressed as data.

use crate::caps::Capability;
use crate::compile::{PagePolicy, Source};
use crate::scope::Scheme;
use std::borrow::Cow;

/// Element operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HtmlOp {
    /// Drop the tags, keep the children (lol_html `remove_and_keep_content`).
    UnwrapKeepContent,
    /// Drop the element and its content.
    Remove,
    /// Drop one attribute.
    RemoveAttribute(&'static str),
}

/// Extra condition, evaluated by the rewriter per element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HtmlWhen {
    Always,
    /// Apply only if the URL(s) in `attr` (whitespace separated for `ping`) are denied for
    /// `cap`: call [`PagePolicy::allows_url`] with the attribute value.
    UrlDenied {
        attr: &'static str,
        cap: Capability,
    },
}

/// One rewriter instruction: for every element matching `selector` (a lol_html selector),
/// apply `op` when `when` holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HtmlRule {
    pub selector: &'static str,
    pub op: HtmlOp,
    pub when: HtmlWhen,
}

/// Executable inline script blocks (JSON data blocks such as `ld+json` are left alone).
pub const INLINE_EXECUTABLE_SCRIPT: &str = "script:not([src]):not([type]), script:not([src])[type=\"text/javascript\" i], script:not([src])[type=\"application/javascript\" i], script:not([src])[type=\"module\" i]";

/// Rewriter instructions for one document.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HtmlActions {
    pub rules: Vec<HtmlRule>,
    /// `<noscript>` content is rendered.
    pub unwrap_noscript: bool,
    /// Blocked `<script>` elements are removed (strip mode) instead of left for the CSP to block.
    pub strip_scripts: bool,
}

impl HtmlActions {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl<'a> PagePolicy<'a> {
    /// True when the page can run neither external nor inline scripts of its own.
    fn scripts_blocked(&self) -> bool {
        !self.allows_host(Capability::Script, self.host)
            && !self.profile.page.contains(Capability::InlineScript)
    }

    /// True when some external script (or, for `cap`, any source) may be denied.
    fn may_deny(&self, cap: Capability) -> bool {
        !self.profile.first_party.contains(cap)
            || !self.profile.third_party.contains(cap)
            || self.rules_for(cap).iter().any(|(_, r)| r.deny)
    }

    /// Rewriter instructions for this document (empty when inactive).
    pub fn html_actions(&self) -> HtmlActions {
        let mut a = HtmlActions::default();
        if !self.active {
            return a;
        }
        let s = self.c.settings();
        let blocked = self.scripts_blocked();
        if blocked && self.profile.page.contains(Capability::Noscript) {
            a.unwrap_noscript = true;
            a.rules.push(HtmlRule {
                selector: "noscript",
                op: HtmlOp::UnwrapKeepContent,
                when: HtmlWhen::Always,
            });
        }
        if blocked && s.strip_meta_refresh {
            a.rules.push(HtmlRule {
                selector: "meta[http-equiv=\"refresh\" i]",
                op: HtmlOp::Remove,
                when: HtmlWhen::Always,
            });
        }
        if self.may_deny(Capability::Ping) {
            a.rules.push(HtmlRule {
                selector: "a[ping], area[ping]",
                op: HtmlOp::RemoveAttribute("ping"),
                when: HtmlWhen::UrlDenied {
                    attr: "ping",
                    cap: Capability::Ping,
                },
            });
        }
        if s.strip_blocked_scripts {
            if self.may_deny(Capability::Script) {
                a.strip_scripts = true;
                a.rules.push(HtmlRule {
                    selector: "script[src]",
                    op: HtmlOp::Remove,
                    when: HtmlWhen::UrlDenied {
                        attr: "src",
                        cap: Capability::Script,
                    },
                });
                a.rules.push(HtmlRule {
                    selector: "link[rel~=\"modulepreload\" i][href], link[rel=\"preload\" i][as=\"script\" i][href]",
                    op: HtmlOp::Remove,
                    when: HtmlWhen::UrlDenied {
                        attr: "href",
                        cap: Capability::Script,
                    },
                });
            }
            if !self.profile.page.contains(Capability::InlineScript) {
                a.strip_scripts = true;
                a.rules.push(HtmlRule {
                    selector: INLINE_EXECUTABLE_SCRIPT,
                    op: HtmlOp::Remove,
                    when: HtmlWhen::Always,
                });
            }
        }
        a
    }

    /// May the page use `cap` with the resource at `url` (absolute, protocol-relative or
    /// relative to the page)? Relative URLs are first party. Schemes other than http(s)/ws(s)
    /// (`data:`, `blob:`, `javascript:`) are not judged here: CSP governs them.
    pub fn allows_url(&self, cap: Capability, url: &str) -> bool {
        match url_source(url.trim()) {
            UrlSource::Relative => self.allows(
                cap,
                Source {
                    scheme: self.scheme,
                    host: self.host,
                },
            ),
            UrlSource::Other => true,
            UrlSource::Remote(scheme, host) => self.allows(
                cap,
                Source {
                    scheme: scheme.or(self.scheme),
                    host: &host,
                },
            ),
        }
    }
}

enum UrlSource<'a> {
    Relative,
    Other,
    Remote(Option<Scheme>, Cow<'a, str>),
}

fn url_source(u: &str) -> UrlSource<'_> {
    let (scheme, rest) = if let Some(r) = u.strip_prefix("//") {
        (None, r)
    } else if let Some((sc, r)) = u.split_once("://") {
        match Scheme::parse(sc) {
            Some(s) => (Some(s), r),
            None => return UrlSource::Other,
        }
    } else if has_scheme(u) {
        return UrlSource::Other;
    } else {
        return UrlSource::Relative;
    };
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let auth = &rest[..auth_end];
    let auth = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    let host = if auth.starts_with('[') {
        auth.find(']').map_or(auth, |i| &auth[..=i])
    } else {
        auth.split(':').next().unwrap_or(auth)
    };
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return UrlSource::Relative;
    }
    if host.is_ascii() && !host.contains('%') {
        let h = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(host.to_ascii_lowercase())
        } else {
            Cow::Borrowed(host)
        };
        UrlSource::Remote(scheme, h)
    } else {
        match crate::scope::normalize_host(host) {
            Ok(h) => UrlSource::Remote(scheme, Cow::Owned(h)),
            Err(_) => UrlSource::Other,
        }
    }
}

fn has_scheme(u: &str) -> bool {
    let b = u.as_bytes();
    let Some(i) = u.find(':') else { return false };
    i > 0
        && b[0].is_ascii_alphabetic()
        && b[..i]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
}

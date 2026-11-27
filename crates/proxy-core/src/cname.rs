//! CNAME uncloaking, after uBlock Origin on Firefox.
//!
//! uBO reads the canonical name of a request's host with `browser.dns.resolve(hn,
//! ['canonical_name'])` and judges the request again under that name, so a tracker that a site
//! hides behind its own sub-domain (`cmp.osano.com` -> `d2gt...cloudfront.net`) is still blocked.
//! Argus resolves every upstream host itself, so it reads the last CNAME target from the same
//! answer it dials with ([`crate::dns::CachedResolver::peek_canon`]): no extra lookup.
//!
//! Source references are to gorhill/uBlock `platform/firefox/vapi-background-ext.js` (`vAPI.Net`).

use arc_swap::ArcSwap;
use common::config::CnameSettings;
use std::net::IpAddr;
use std::sync::Arc;

/// The live settings, compiled for per-request use.
struct Compiled {
    s: CnameSettings,
    /// Lowercased ignore entries without `*.` / leading or trailing dots.
    ignore: Vec<String>,
    /// `*` in the list (uBO's `/^./`: every canonical name).
    ignore_all: bool,
}

/// Decides whether, and under which URL, a request is judged again by its canonical name.
pub struct Uncloak {
    cfg: ArcSwap<Compiled>,
}

impl Default for Uncloak {
    fn default() -> Self {
        Self::new(&CnameSettings::default())
    }
}

impl Uncloak {
    pub fn new(s: &CnameSettings) -> Self {
        Self {
            cfg: ArcSwap::from_pointee(compile(s)),
        }
    }

    /// Apply new settings; the next request uses them.
    pub fn set(&self, s: &CnameSettings) {
        self.cfg.store(Arc::new(compile(s)));
    }

    /// `cnameUncloakEnabled` (vapi-background-ext.js:65, checked at :206).
    pub fn enabled(&self) -> bool {
        self.cfg.load().s.enabled
    }

    /// `cnameIgnoreExceptions` (vapi-background-ext.js:68): when set, a request an exception
    /// filter matched is never uncloaked. The first-pass result `r` is returned as is when it is
    /// a cancel or a redirect or this switch is on (vapi-background-ext.js:175-190); argus never
    /// reaches this for a block.
    pub fn ignores_exceptions(&self) -> bool {
        self.cfg.load().s.ignore_exceptions
    }

    /// Should a request to `host` skip the canonical-name step before any lookup? True when the
    /// request is the page's own host or a document (`cnameIgnoreRootDocument`,
    /// vapi-background-ext.js:299-302: `hn === hostnameFromNetworkURL(documentUrl || url)`, and a
    /// root document request has no `documentUrl`), or an IP literal (`dnsShouldResolve`,
    /// :271-278).
    pub fn skip_request(&self, host: &str, source_host: &str, is_document: bool) -> bool {
        if host.is_empty() || host.starts_with('[') || host.parse::<IpAddr>().is_ok() {
            return true;
        }
        let c = self.cfg.load();
        c.s.ignore_root_document
            && (is_document || (!source_host.is_empty() && host.eq_ignore_ascii_case(source_host)))
    }

    /// The canonical name to judge `host` under, or `None` (`cnameFromRecord`,
    /// vapi-background-ext.js:289-304): not the host itself (:291), not on the host's registrable
    /// domain when `cnameIgnore1stParty` (:293-295), not on the ignore list (:296-298).
    pub fn accept(&self, host: &str, canonical: &str) -> Option<String> {
        let cn = canonical.trim_end_matches('.').to_ascii_lowercase();
        let hn = host.trim_end_matches('.').to_ascii_lowercase();
        if cn.is_empty() || cn == hn {
            return None;
        }
        let c = self.cfg.load();
        if c.s.ignore_first_party && registrable(&cn) == registrable(&hn) {
            return None;
        }
        if c.ignore_all || c.ignore.iter().any(|e| in_domain(&cn, e)) {
            return None;
        }
        Some(cn)
    }

    /// The URL to judge: `url` with its host replaced by `canonical`, cut after the first `/` of
    /// the path unless `cnameReplayFullURL` is on (`uncloakURL`, vapi-background-ext.js:306-321,
    /// :97). `None` when the host cannot be found in the URL (:308).
    pub fn replay_url(&self, url: &str, host: &str, canonical: &str) -> Option<String> {
        let start = url.find("://").map_or(0, |i| i + 3);
        let beg = start + url[start..].find(host)?;
        let end = beg + host.len();
        let mut out = String::with_capacity(url.len());
        out.push_str(&url[..beg]);
        out.push_str(canonical);
        if self.cfg.load().s.replay_full_url {
            out.push_str(&url[end..]);
        } else if let Some(p) = url[end..].find('/') {
            // Up to and including the first `/` after the host (the port stays).
            out.push_str(&url[end..=end + p]);
        }
        Some(out)
    }
}

fn compile(s: &CnameSettings) -> Compiled {
    let mut ignore = Vec::new();
    let mut ignore_all = false;
    for e in &s.ignore_list {
        let e = e.trim().to_ascii_lowercase();
        if e == "*" {
            ignore_all = true;
            continue;
        }
        let e = e.strip_prefix("*.").unwrap_or(&e).trim_matches('.');
        if !e.is_empty() {
            ignore.push(e.to_string());
        }
    }
    Compiled {
        s: s.clone(),
        ignore,
        ignore_all,
    }
}

/// `domainFromHostname`: the registrable domain, or the name itself without one.
fn registrable(h: &str) -> &str {
    psl::domain_str(h).unwrap_or(h)
}

/// `(?:^|\.)entry$` (`regexFromStrList`, vapi-background-ext.js:160-171).
fn in_domain(name: &str, entry: &str) -> bool {
    name == entry
        || name
            .strip_suffix(entry)
            .is_some_and(|rest| rest.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{BackendResult, CachedResolver, DnsCacheConfig, FailKind, Resolver};
    use filter_engine::{compile_engine, Query, SharedEngine};
    use std::future::Future;
    use std::pin::Pin;
    use std::time::Duration;

    /// Answers `cmp.site.test` -> `d2gt.tracker.test` and `plain.test` with no alias.
    struct Aliased;
    impl Resolver for Aliased {
        fn lookup(&self, name: &str) -> Pin<Box<dyn Future<Output = BackendResult> + Send>> {
            let f = self.lookup_canon(name);
            Box::pin(async move { f.await.map(|(a, t, _)| (a, t)) })
        }
        fn lookup_canon(
            &self,
            name: &str,
        ) -> Pin<Box<dyn Future<Output = crate::dns::CanonResult> + Send>> {
            let canon = match name {
                "cmp.site.test" => Some("d2gt.tracker.test".to_string()),
                "static.site.test" => Some("cdn.site.test".to_string()),
                "ok.site.test" => Some("edge.cdn.test".to_string()),
                _ => None,
            };
            let name = name.to_string();
            Box::pin(async move {
                if name.is_empty() {
                    return Err(crate::dns::DnsFailure::new(FailKind::NotFound, "x"));
                }
                Ok((
                    vec!["192.0.2.1".parse().unwrap()],
                    Duration::from_secs(60),
                    canon,
                ))
            })
        }
    }

    fn dns() -> CachedResolver {
        CachedResolver::new(Arc::new(Aliased), DnsCacheConfig::default())
    }

    fn engine(rules: &str) -> SharedEngine {
        let e = SharedEngine::new();
        e.install(compile_engine(&[rules.to_string()]));
        e
    }

    /// The decision the request path makes, over a real engine and resolver: the canonical name
    /// to block under, if any.
    async fn blocked_by(
        u: &Uncloak,
        eng: &SharedEngine,
        dns: &CachedResolver,
        url: &str,
        host: &str,
        source: &str,
        rtype: &str,
    ) -> Option<String> {
        let first = eng.check_deferred_q(&Query::new(url, source, rtype));
        if first.blocked || !u.enabled() {
            return None;
        }
        if first.exception_rule.is_some() && u.ignores_exceptions() {
            return None;
        }
        let source_host = url::Url::parse(source)
            .ok()
            .and_then(|s| s.host_str().map(str::to_string))
            .unwrap_or_default();
        if u.skip_request(host, &source_host, rtype == "document") {
            return None;
        }
        let cn = u.accept(host, dns.peek_canon(host).await.ok()?.canonical.as_deref()?)?;
        let replay = u.replay_url(url, host, &cn)?;
        eng.check_deferred_q(&Query::new(&replay, source, rtype))
            .blocked
            .then_some(cn)
    }

    const RULES: &str =
        "||tracker.test^\n||cdn.site.test^\n||edge.cdn.test^\n||ok.site.test^\n@@||ok.site.test^\n";

    #[tokio::test]
    async fn a_chained_cname_to_a_blocked_name_is_blocked() {
        let (u, e, d) = (Uncloak::default(), engine(RULES), dns());
        let got = blocked_by(
            &u,
            &e,
            &d,
            "https://cmp.site.test/consent.js?x=1",
            "cmp.site.test",
            "https://news.example/",
            "script",
        )
        .await;
        assert_eq!(got.as_deref(), Some("d2gt.tracker.test"));
        // The name itself is not blocked, and a host without an alias is left alone.
        assert!(
            !e.check_deferred_q(&Query::new(
                "https://cmp.site.test/consent.js",
                "https://news.example/",
                "script"
            ))
            .blocked
        );
        assert_eq!(
            blocked_by(
                &u,
                &e,
                &d,
                "https://plain.test/a.js",
                "plain.test",
                "https://news.example/",
                "script"
            )
            .await,
            None
        );
    }

    #[tokio::test]
    async fn a_first_party_cname_is_ignored_unless_the_setting_is_off() {
        let (e, d) = (engine(RULES), dns());
        let url = "https://static.site.test/a.js";
        let args = (url, "static.site.test", "https://news.example/", "script");
        let u = Uncloak::default();
        assert_eq!(
            blocked_by(&u, &e, &d, args.0, args.1, args.2, args.3).await,
            None
        );
        u.set(&CnameSettings {
            ignore_first_party: false,
            ..Default::default()
        });
        assert_eq!(
            blocked_by(&u, &e, &d, args.0, args.1, args.2, args.3)
                .await
                .as_deref(),
            Some("cdn.site.test")
        );
    }

    #[tokio::test]
    async fn an_exception_is_honoured_unless_the_setting_is_off() {
        let (e, d) = (engine(RULES), dns());
        let args = (
            "https://ok.site.test/a.js",
            "ok.site.test",
            "https://news.example/",
            "script",
        );
        let u = Uncloak::default();
        assert_eq!(
            blocked_by(&u, &e, &d, args.0, args.1, args.2, args.3).await,
            None
        );
        u.set(&CnameSettings {
            ignore_exceptions: false,
            ..Default::default()
        });
        assert_eq!(
            blocked_by(&u, &e, &d, args.0, args.1, args.2, args.3)
                .await
                .as_deref(),
            Some("edge.cdn.test")
        );
    }

    #[tokio::test]
    async fn the_root_document_is_ignored() {
        let (u, e, d) = (Uncloak::default(), engine(RULES), dns());
        // A document request, and a request to the page's own host.
        for (url, source, ty) in [
            (
                "https://cmp.site.test/",
                "https://cmp.site.test/",
                "document",
            ),
            (
                "https://cmp.site.test/x.js",
                "https://cmp.site.test/",
                "script",
            ),
        ] {
            assert_eq!(
                blocked_by(&u, &e, &d, url, "cmp.site.test", source, ty).await,
                None,
                "{url}"
            );
        }
        // With the switch off the alias is judged.
        u.set(&CnameSettings {
            ignore_root_document: false,
            ..Default::default()
        });
        assert!(blocked_by(
            &u,
            &e,
            &d,
            "https://cmp.site.test/x.js",
            "cmp.site.test",
            "https://cmp.site.test/",
            "script"
        )
        .await
        .is_some());
    }

    #[tokio::test]
    async fn the_master_switch_and_the_ignore_list() {
        let (e, d) = (engine(RULES), dns());
        let args = (
            "https://cmp.site.test/a.js",
            "cmp.site.test",
            "https://news.example/",
            "script",
        );
        let off = Uncloak::new(&CnameSettings {
            enabled: false,
            ..Default::default()
        });
        assert_eq!(
            blocked_by(&off, &e, &d, args.0, args.1, args.2, args.3).await,
            None
        );
        for entry in ["tracker.test", "*.tracker.test", "*"] {
            let u = Uncloak::new(&CnameSettings {
                ignore_list: vec![entry.into()],
                ..Default::default()
            });
            assert_eq!(
                blocked_by(&u, &e, &d, args.0, args.1, args.2, args.3).await,
                None,
                "{entry}"
            );
        }
        // A look-alike suffix is not on the list.
        let u = Uncloak::new(&CnameSettings {
            ignore_list: vec!["acker.test".into()],
            ..Default::default()
        });
        assert!(blocked_by(&u, &e, &d, args.0, args.1, args.2, args.3)
            .await
            .is_some());
    }

    #[test]
    fn replay_url_keeps_the_scheme_and_path_root_unless_the_full_url_is_asked_for() {
        let u = Uncloak::default();
        assert_eq!(
            u.replay_url("https://a.b.test:8443/x/y.js?q=1", "a.b.test", "c.d.test")
                .as_deref(),
            Some("https://c.d.test:8443/")
        );
        assert_eq!(
            u.replay_url("https://a.b.test", "a.b.test", "c.d.test")
                .as_deref(),
            Some("https://c.d.test")
        );
        u.set(&CnameSettings {
            replay_full_url: true,
            ..Default::default()
        });
        assert_eq!(
            u.replay_url("https://a.b.test/x/y.js?q=1", "a.b.test", "c.d.test")
                .as_deref(),
            Some("https://c.d.test/x/y.js?q=1")
        );
    }
}

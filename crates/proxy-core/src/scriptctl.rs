//! Script control (NoScript-style) on the proxy path: the compiled policy of a profile, the
//! per-document header cache, and the early request check.
//!
//! The pure model lives in the `script-policy` crate. This module owns what the proxy adds:
//! a lock-free current snapshot (rebuilt off the request path on every change and when a
//! temporary grant expires), header strings cached per `(generation, scheme, host, port)`, and
//! the per-request check for denied third-party subresources.
//!
//! With the master switch off, every entry point returns after one relaxed atomic load.

use crate::csp::INTERNAL_PREFIX;
use filter_engine::ArcSwap;
use hyper::header::HeaderMap;
use script_policy as sp;
use script_policy::panel::PanelSettings;
use script_policy::store::PolicyStore;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

/// Stands in for the per-document nonce in cached CSP text.
pub const NONCE_MARK: &str = "ABPOLICYNONCE00000000";
/// Stands in for the per-document report token in cached CSP text.
pub const DOC_MARK: &str = "ABPOLICYDOCTOKEN0000";

/// Policy-derived response parts for one document class `(generation, scheme, host, port)`.
pub struct DocEntry {
    /// The extra `Content-Security-Policy` text with [`NONCE_MARK`] and [`DOC_MARK`] in it.
    pub csp: Option<String>,
    /// The `Permissions-Policy` contribution.
    pub permissions: Option<String>,
    /// Rewriter instructions; `None` when the policy needs no HTML work.
    pub html: Option<Arc<crate::rewrite::PolicyHtml>>,
}

impl DocEntry {
    /// The CSP header for one document.
    pub fn csp_for(&self, nonce: &str, doc_token: &str) -> Option<String> {
        self.csp
            .as_ref()
            .map(|t| t.replace(NONCE_MARK, nonce).replace(DOC_MARK, doc_token))
    }
}

/// Rules carry no port, so a host source must match whatever port the host is served on (CSP
/// otherwise matches only the scheme's default port). Keywords, schemes (`data:`), `'self'` and
/// sources with a path (the proxy's own) are left alone.
fn any_port(directives: &mut [sp::CspDirective]) {
    for d in directives {
        for tok in &mut d.sources {
            let t = tok.as_str();
            let authority = t.split_once("://").map_or(t, |(_, r)| r);
            if t.starts_with('\'') || t.ends_with(':') || t == "*" || authority.contains(['/', ':'])
            {
                continue;
            }
            tok.push_str(":*");
        }
    }
}

type DocKey = (u64, bool, u16, Box<str>);

/// Can any rule of the profile deny something? A profile whose every preset is `Trusted` and
/// that has no deny rule needs no request-path checks at all.
fn is_restrictive(store: &PolicyStore, profile: &str) -> bool {
    let Ok(r) = store.rules(profile) else {
        return true;
    };
    let s = &r.settings;
    s.enabled
        && (s.global.resolve(s) != sp::Profile::TRUSTED
            || r.site_rules
                .values()
                .any(|x| x.preset.resolve(s) != sp::Profile::TRUSTED)
            || r.source_rules
                .values()
                .any(|x| x.effect == sp::Effect::Deny))
}

impl Drop for ScriptControl {
    fn drop(&mut self) {
        self.stop();
    }
}

/// One profile's script control.
pub struct ScriptControl {
    store: Arc<PolicyStore>,
    profile: String,
    compiled: ArcSwap<sp::CompiledPolicy>,
    enabled: AtomicBool,
    /// Some rule can deny something (checked off the request path); when none can, the request
    /// check returns without a lookup.
    restrictive: AtomicBool,
    panel: ArcSwap<PanelSettings>,
    docs: moka::sync::Cache<DocKey, Arc<DocEntry>>,
    wake: Arc<tokio::sync::Notify>,
    /// The store listener, removed by [`Self::stop`] and on drop.
    listener: std::sync::atomic::AtomicU64,
    /// The expiry task, aborted by [`Self::stop`] and on drop.
    expiry: parking_lot::Mutex<Option<tokio::task::AbortHandle>>,
    /// Number of `decide` calls made (tests and benches assert the disabled path makes none).
    decides: AtomicU64,
    /// Blocked requests per page host (ads and policy), for the panel.
    blocked: moka::sync::Cache<Box<str>, Arc<AtomicU64>>,
}

impl ScriptControl {
    pub fn new(store: Arc<PolicyStore>, profile: &str) -> Arc<Self> {
        let compiled = store
            .snapshot(profile)
            .unwrap_or_else(|_| Arc::new(sp::CompiledPolicy::disabled()));
        let panel = store.panel_settings(profile).unwrap_or_default();
        let this = Arc::new(ScriptControl {
            enabled: AtomicBool::new(compiled.is_enabled()),
            restrictive: AtomicBool::new(is_restrictive(&store, profile)),
            compiled: ArcSwap::from(compiled),
            panel: ArcSwap::from_pointee(panel),
            store: store.clone(),
            profile: profile.to_string(),
            docs: moka::sync::Cache::builder().max_capacity(4096).build(),
            wake: Arc::new(tokio::sync::Notify::new()),
            expiry: parking_lot::Mutex::new(None),
            listener: AtomicU64::new(0),
            decides: AtomicU64::new(0),
            blocked: moka::sync::Cache::builder()
                .max_capacity(2048)
                .time_to_idle(std::time::Duration::from_secs(1800))
                .build(),
        });
        let weak: Weak<ScriptControl> = Arc::downgrade(&this);
        let name = profile.to_string();
        let lid = store.on_change(move |p| {
            if p == name {
                if let Some(s) = weak.upgrade() {
                    s.refresh();
                }
            }
        });
        this.listener.store(lid, Ordering::Release);
        this
    }

    /// Re-read the compiled policy and panel settings from the store, and wake the expiry task.
    pub fn refresh(&self) {
        self.reload();
        self.wake.notify_one();
    }

    /// [`Self::refresh`] without waking the expiry task (which calls it itself).
    fn reload(&self) {
        if let Ok(c) = self.store.snapshot(&self.profile) {
            self.enabled.store(c.is_enabled(), Ordering::Release);
            self.restrictive.store(
                is_restrictive(&self.store, &self.profile),
                Ordering::Release,
            );
            self.compiled.store(c);
        }
        if let Ok(p) = self.store.panel_settings(&self.profile) {
            self.panel.store(Arc::new(p));
        }
    }

    /// Spawn the task that rebuilds the snapshot when the next temporary grant expires. It
    /// sleeps until `valid_until()` (no polling) and exits when the control is dropped.
    pub fn spawn_expiry(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            loop {
                let Some(this) = weak.upgrade() else { return };
                let until = this.compiled.load().valid_until();
                let now = this.store.now();
                let wait = until.map(|u| u.saturating_sub(now) + 1);
                let wake = this.wake.clone();
                drop(this);
                let notified = wake.notified();
                tokio::pin!(notified);
                match wait {
                    Some(secs) => {
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(secs),
                            &mut notified,
                        )
                        .await;
                    }
                    None => notified.await,
                }
                match weak.upgrade() {
                    Some(this) => this.reload(),
                    None => return,
                }
            }
        });
        if let Some(old) = self.expiry.lock().replace(task.abort_handle()) {
            old.abort();
        }
    }

    /// End the expiry task and unregister the store listener (the profile is gone). Safe to call more than once.
    pub fn stop(&self) {
        let lid = self.listener.swap(0, Ordering::AcqRel);
        if lid != 0 {
            self.store.remove_listener(lid);
        }
        if let Some(h) = self.expiry.lock().as_ref() {
            h.abort();
        }
    }

    /// Whether the expiry task is alive (tests).
    pub fn expiry_running(&self) -> bool {
        self.expiry
            .lock()
            .as_ref()
            .is_some_and(|h| !h.is_finished())
    }

    pub fn store(&self) -> &Arc<PolicyStore> {
        &self.store
    }
    pub fn profile_name(&self) -> &str {
        &self.profile
    }
    /// The master switch: one relaxed load.
    #[inline]
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
    pub fn compiled(&self) -> Arc<sp::CompiledPolicy> {
        self.compiled.load_full()
    }

    /// The snapshot to decide with: if a temporary grant in it has expired, rebuild it now rather
    /// than waiting for the expiry task's timer, so an expiry takes effect on the very next
    /// request. One atomic load and a clock read otherwise.
    fn fresh(&self) -> Arc<sp::CompiledPolicy> {
        let c = self.compiled.load_full();
        if c.valid_until().is_some_and(|v| self.store.now() >= v) {
            self.reload();
            return self.compiled.load_full();
        }
        c
    }
    pub fn panel(&self) -> Arc<PanelSettings> {
        self.panel.load_full()
    }
    pub fn decide_calls(&self) -> u64 {
        self.decides.load(Ordering::Relaxed)
    }

    /// Policy parts for a document at `scheme://host[:port]`; `None` when nothing applies.
    pub fn document(&self, scheme: &str, host: &str, port: u16) -> Option<Arc<DocEntry>> {
        if !self.enabled() {
            return None;
        }
        let compiled = self.fresh();
        let https = scheme == "https";
        let key: DocKey = (compiled.generation(), https, port, host.into());
        if let Some(e) = self.docs.get(&key) {
            return Some(e);
        }
        self.decides.fetch_add(1, Ordering::Relaxed);
        let default_port = if https { 443 } else { 80 };
        let page_port = (port != default_port).then_some(port);
        let page = compiled.decide(scheme, host, page_port);
        let entry = if page.is_active() {
            let inject = sp::ProxyInject {
                nonce: Some(NONCE_MARK),
                path: Some(INTERNAL_PREFIX),
            };
            let mut directives = page.csp(Some(&inject));
            any_port(&mut directives);
            let csp = (!directives.is_empty()).then(|| {
                format!(
                    "{}; report-uri {INTERNAL_PREFIX}pv?d={DOC_MARK}",
                    sp::render_header(&directives)
                )
            });
            let actions = page.html_actions();
            let html = (!actions.is_empty()).then(|| {
                Arc::new(crate::rewrite::PolicyHtml {
                    compiled: compiled.clone(),
                    scheme: scheme.to_string(),
                    host: host.to_string(),
                    port: page_port,
                    actions,
                })
            });
            Arc::new(DocEntry {
                permissions: page.permissions_policy(),
                csp,
                html,
            })
        } else {
            Arc::new(DocEntry {
                csp: None,
                permissions: None,
                html: None,
            })
        };
        self.docs.insert(key, entry.clone());
        Some(entry)
    }

    /// Early check of a subresource request: `Some(cap)` when the page's policy denies it and
    /// the page is reliably known. No allocation on the allow path.
    pub fn check_request(
        &self,
        headers: &HeaderMap,
        scheme: &str,
        host: &str,
        port: u16,
    ) -> Option<sp::Capability> {
        if !self.enabled() || !self.restrictive.load(Ordering::Relaxed) {
            return None;
        }
        let target_scheme = sp::Scheme::parse(scheme)?;
        let dest = headers
            .get("sec-fetch-dest")
            .and_then(|v| v.to_str().ok())
            .map(sp::FetchDest::from_header)?;
        let ping = headers.contains_key("ping-to");
        if dest.capability().is_none() && !ping {
            return None;
        }
        let get = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
        let default_port = target_scheme.default_port();
        let target_port = (port != default_port).then_some(port);
        let ctx = sp::PageContext::from_headers(
            get("referer"),
            get("origin"),
            get("sec-fetch-site"),
            (target_scheme, host, target_port),
        );
        let sp::PageContext::Known {
            scheme: ps,
            host: ph,
            port: pp,
        } = ctx
        else {
            return None;
        };
        let compiled = self.fresh();
        self.decides.fetch_add(1, Ordering::Relaxed);
        let page = compiled.decide(ps.as_str(), ph, pp);
        let hints = page.network_hints();
        if hints.is_empty() {
            return None;
        }
        match page.check_request(
            &hints,
            &sp::SubRequest {
                dest,
                ping,
                target: sp::Source {
                    scheme: Some(target_scheme),
                    host,
                },
            },
        ) {
            sp::HintVerdict::Block { cap } => {
                drop(compiled);
                self.record_network_block(ph, cap, host, scheme, port);
                Some(cap)
            }
            sp::HintVerdict::Allow => None,
        }
    }

    fn record_network_block(
        &self,
        page_host: &str,
        cap: sp::Capability,
        host: &str,
        scheme: &str,
        port: u16,
    ) {
        let _ = (scheme, port);
        self.store.record_block(
            &self.profile,
            page_host,
            sp::BlockEvent {
                cap,
                source: Some(host.to_string()),
                sample: None,
                via: sp::Via::Network,
            },
        );
        self.count_blocked(page_host);
    }

    /// Count a blocked request (ad or policy) against the page it belongs to.
    pub fn count_blocked(&self, page_host: &str) {
        if !self.panel().enabled {
            return;
        }
        let c = self
            .blocked
            .get_with(page_host.into(), || Arc::new(AtomicU64::new(0)));
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn blocked_on(&self, page_host: &str) -> u64 {
        self.blocked
            .get(page_host)
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use script_policy::{CapSet, Capability as C, GrantKind, Scope, DEFAULT_PROFILE as P};

    fn control() -> (tempfile::TempDir, Arc<PolicyStore>, Arc<ScriptControl>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(PolicyStore::new(common::db::Db::open(dir.path()).unwrap()));
        let mut s = store.rules(P).unwrap().settings;
        s.enabled = true;
        store.set_settings(P, s).unwrap();
        let c = ScriptControl::new(store.clone(), P);
        (dir, store, c)
    }

    fn script_from(page: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("sec-fetch-dest", HeaderValue::from_static("script"));
        h.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        h.insert(
            "referer",
            HeaderValue::from_str(&format!("https://{page}/")).unwrap(),
        );
        h
    }

    #[test]
    fn host_sources_match_any_port_but_nothing_else_changes() {
        let mut d = vec![sp::CspDirective {
            name: "script-src",
            sources: vec![
                "'self'".into(),
                "'nonce-x'".into(),
                "a.test".into(),
                "*.a.test".into(),
                "https://b.test".into(),
                "data:".into(),
                "https://p.test:8443/__adblock__/".into(),
                "c.test:444".into(),
                "*".into(),
            ],
        }];
        any_port(&mut d);
        assert_eq!(
            d[0].sources,
            [
                "'self'",
                "'nonce-x'",
                "a.test:*",
                "*.a.test:*",
                "https://b.test:*",
                "data:",
                "https://p.test:8443/__adblock__/",
                "c.test:444",
                "*"
            ]
        );
    }

    #[test]
    fn disabled_control_does_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(PolicyStore::new(common::db::Db::open(dir.path()).unwrap()));
        let c = ScriptControl::new(store, P);
        assert!(!c.enabled());
        assert!(c.document("https", "a.test", 443).is_none());
        assert!(c
            .check_request(&script_from("a.test"), "https", "cdn.test", 443)
            .is_none());
        assert_eq!(c.decide_calls(), 0);
    }

    #[test]
    fn documents_are_cached_per_generation_and_hints_judge_known_pages_only() {
        let (_d, store, c) = control();
        let e1 = c.document("https", "a.test", 443).unwrap();
        let e2 = c.document("https", "a.test", 443).unwrap();
        assert!(Arc::ptr_eq(&e1, &e2), "one decide per document class");
        assert_eq!(c.decide_calls(), 1);
        store
            .create_site_rule(
                P,
                Scope::parse("a.test").unwrap(),
                sp::Preset::Untrusted,
                None,
            )
            .unwrap();
        let e3 = c.document("https", "a.test", 443).unwrap();
        assert!(
            !Arc::ptr_eq(&e1, &e3),
            "a policy change starts a new cache generation"
        );
        assert!(c
            .check_request(&script_from("a.test"), "https", "cdn.test", 443)
            .is_some());
        let mut unknown = script_from("a.test");
        unknown.remove("referer");
        assert!(c
            .check_request(&unknown, "https", "cdn.test", 443)
            .is_none());
    }

    #[test]
    fn all_trusted_profiles_skip_the_request_check_entirely() {
        let (_d, store, c) = control();
        let h = script_from("a.test");
        assert!(c.check_request(&h, "https", "cdn.test", 443).is_some());
        let mut s = store.rules(P).unwrap().settings;
        s.global = sp::Preset::Trusted;
        store.set_settings(P, s).unwrap();
        let before = c.decide_calls();
        assert!(c.check_request(&h, "https", "cdn.test", 443).is_none());
        assert_eq!(c.decide_calls(), before, "no lookup at all");
        store
            .create_site_rule(
                P,
                Scope::parse("a.test").unwrap(),
                sp::Preset::Untrusted,
                None,
            )
            .unwrap();
        assert!(
            c.check_request(&h, "https", "cdn.test", 443).is_some(),
            "one restrictive rule is enough"
        );
    }

    #[tokio::test]
    async fn expiry_task_rebuilds_the_snapshot_without_polling() {
        let (_d, store, c) = control();
        c.spawn_expiry();
        let h = script_from("a.test");
        assert!(c.check_request(&h, "https", "cdn.test", 443).is_some());
        store
            .grant_temp(
                P,
                Scope::parse("a.test").unwrap(),
                GrantKind::Source {
                    source: Scope::parse("cdn.test").unwrap(),
                    caps: CapSet::of(&[C::Script]),
                },
                // Expiry is whole-second: 2s leaves a full second before the first check can see it
                // gone, however the clock ticks.
                Some(2),
                false,
                false,
            )
            .unwrap();
        assert!(
            c.check_request(&h, "https", "cdn.test", 443).is_none(),
            "granted"
        );
        assert!(c.compiled().valid_until().is_some());
        // No further calls: the task alone must notice the expiry.
        tokio::time::sleep(std::time::Duration::from_millis(3200)).await;
        assert!(
            c.compiled().valid_until().is_none(),
            "snapshot rebuilt after the grant expired"
        );
        assert!(
            c.check_request(&h, "https", "cdn.test", 443).is_some(),
            "blocked again"
        );
    }

    #[test]
    fn an_expired_temporary_grant_is_gone_on_the_very_next_request() {
        // No expiry task here: the request path itself must notice the expiry.
        let (_d, store, c) = control();
        let h = script_from("a.test");
        store
            .grant_temp(
                P,
                Scope::parse("a.test").unwrap(),
                GrantKind::Source {
                    source: Scope::parse("cdn.test").unwrap(),
                    caps: CapSet::of(&[C::Script]),
                },
                // Expiry is whole-second: 2s leaves a full second before the first check can see it
                // gone, however the clock ticks.
                Some(2),
                false,
                false,
            )
            .unwrap();
        assert!(
            c.check_request(&h, "https", "cdn.test", 443).is_none(),
            "granted"
        );
        std::thread::sleep(std::time::Duration::from_millis(3100));
        assert!(
            c.check_request(&h, "https", "cdn.test", 443).is_some(),
            "blocked again without waiting for a timer"
        );
        let e = c.document("https", "a.test", 443).unwrap();
        assert!(c.compiled().valid_until().is_none(), "{:?}", e.csp);
    }
}

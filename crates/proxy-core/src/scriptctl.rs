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
            if t.starts_with('\'') || t.ends_with(':') || t == "*" || authority.contains(['/', ':']) {
                continue;
            }
            tok.push_str(":*");
        }
    }
}

type DocKey = (u64, bool, u16, Box<str>);

/// One profile's script control.
pub struct ScriptControl {
    store: Arc<PolicyStore>,
    profile: String,
    compiled: ArcSwap<sp::CompiledPolicy>,
    enabled: AtomicBool,
    panel: ArcSwap<PanelSettings>,
    docs: moka::sync::Cache<DocKey, Arc<DocEntry>>,
    wake: Arc<tokio::sync::Notify>,
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
            compiled: ArcSwap::from(compiled),
            panel: ArcSwap::from_pointee(panel),
            store: store.clone(),
            profile: profile.to_string(),
            docs: moka::sync::Cache::builder().max_capacity(4096).build(),
            wake: Arc::new(tokio::sync::Notify::new()),
            decides: AtomicU64::new(0),
            blocked: moka::sync::Cache::builder()
                .max_capacity(2048)
                .time_to_idle(std::time::Duration::from_secs(1800))
                .build(),
        });
        let weak: Weak<ScriptControl> = Arc::downgrade(&this);
        let name = profile.to_string();
        store.on_change(move |p| {
            if p == name {
                if let Some(s) = weak.upgrade() {
                    s.refresh();
                }
            }
        });
        this
    }

    /// Re-read the compiled policy and panel settings from the store, and wake the expiry task.
    pub fn refresh(&self) {
        if let Ok(c) = self.store.snapshot(&self.profile) {
            self.enabled.store(c.is_enabled(), Ordering::Release);
            self.compiled.store(c);
        }
        if let Ok(p) = self.store.panel_settings(&self.profile) {
            self.panel.store(Arc::new(p));
        }
        self.wake.notify_one();
    }

    /// Spawn the task that rebuilds the snapshot when the next temporary grant expires. It
    /// sleeps until `valid_until()` (no polling) and exits when the control is dropped.
    pub fn spawn_expiry(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let Some(this) = weak.upgrade() else { return };
                let until = this.compiled.load().valid_until();
                let now = this.store.now();
                let wait = until.map(|u| u.saturating_sub(now).max(0) + 1);
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
                    Some(this) => this.refresh(),
                    None => return,
                }
            }
        });
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
        let compiled = self.compiled.load_full();
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
        if !self.enabled() {
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
        let compiled = self.compiled.load();
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

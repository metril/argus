//! Request filtering and upstream forwarding.
//!
//! [`ProxyContext`] carries the shared, `Send + Sync` handles every connection needs: the
//! [`SharedEngine`] (one `Arc<Engine>` behind an `ArcSwap`) for block/allow decisions and a single
//! pooled [`UpstreamClient`] for forwarding requests upstream over real TLS.
//!
//! Per request the pipeline is: classify (resource type + source URL) -> engine check ->
//! block / `$redirect` resource / `$removeparam` rewrite -> stream upstream -> `$csp` header and
//! cosmetic injection on the way back.

use crate::authority;
use crate::csp;
use crate::ext;
use crate::inject::{build_head, full_body, passthrough_body, PageSpec, ProxyBody};
use crate::internal::Internal;
use crate::policy::{is_refusal, DestPolicy};
use crate::profiles::Profiles;
use crate::redirect::{block_response, policy_block_response, redirect_response, rewrite_redirect};
use crate::request_ctx::{default_profile_slot, Profile, ProfileSlot, RequestCtx};
use crate::request_type::{classify, source_url, RequestType};
use crate::rewrite::codec::{choose_encoding, response_codings};
use crate::rewrite::pipeline::{transform_html, transform_text, Outcome};
use crate::rewrite::{
    classify_body, media_type, BodyKind, HeaderEdit, HtmlPlan, ResponseInfo, ResponseTransforms,
    TransformSource,
};
use crate::stealth;
use crate::upstream::{
    build_strict_upstream_client, build_strict_upstream_client_via, build_upstream_client,
    build_upstream_client_via, UpstreamClient, UpstreamOptions,
};
use crate::{Error, Result};
use bytes::Bytes;
use filter_engine::ArcSwap;
use filter_engine::SharedEngine;
use futures_util::TryStreamExt;
use http_body_util::BodyExt;
use hyper::body::{Body, Incoming};
use hyper::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, HOST};
use hyper::{Request, Response, StatusCode};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

/// Hop-by-hop headers that must not be forwarded (RFC 7230 §6.1), plus framing headers we
/// reconstruct ourselves.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Default cap on time-to-response-headers for an upstream call (includes uploading the body).
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 60_000;

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP
        .iter()
        .any(|h| name.as_str().eq_ignore_ascii_case(h))
}

/// Headers named by the `Connection` header (hop-by-hop for this hop only, RFC 9110 §7.6.1).
fn connection_listed(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .collect()
}

/// The 403 answer for a destination the policy refuses.
pub fn refused_response() -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("x-adblock", "destination-refused")
        .header("cache-control", "no-store")
        .body(full_body(Bytes::from_static(b"Destination refused")))
        .expect("static response")
}

/// `Origin`-header form of an authority: scheme, host, and the port unless it is the default.
/// The page a request came from, for logs: the Referer as the browser sent it, even when
/// Stealth Mode replaced it on the way out.
fn src_of<'a>(
    orig_referer: &'a Option<String>,
    headers: &'a hyper::HeaderMap,
    url: &'a str,
    rtype: RequestType,
) -> &'a str {
    orig_referer
        .as_deref()
        .filter(|_| rtype != RequestType::Document)
        .unwrap_or_else(|| source_url(headers, url, rtype))
}

fn origin_of(scheme: &str, url_host: &str, port: u16) -> String {
    let scheme = if scheme == "http" { "http" } else { "https" };
    let default = if scheme == "http" { 80 } else { 443 };
    if port == default {
        format!("{scheme}://{url_host}")
    } else {
        format!("{scheme}://{url_host}:{port}")
    }
}

/// Combine the base verdict with the profile's overlay engine, if any: an overlay exception or
/// block wins over the base verdict (so an overlay block beats a base allow and an overlay
/// exception beats a base block).
fn apply_overlay(
    profile: &Profile,
    base: filter_engine::MatchResult,
    q: &filter_engine::Query<'_>,
) -> filter_engine::MatchResult {
    let Some(ov) = &profile.overlay else {
        return base;
    };
    if !ov.is_enabled() {
        return base;
    }
    // Neither verdict is counted here: the caller records the final one once.
    let o = ov.check_deferred_q(q);
    if o.blocked || o.exception_rule.is_some() {
        return o;
    }
    // An exception-only overlay rule is only reported by the engine next to a block it
    // overrides, so when the base blocked, ask the overlay for its exceptions explicitly.
    if base.blocked {
        if let Some(req) = q.request() {
            let r = ov.engine().check_network_request_subset(req, false, true);
            if !r.matched {
                if let Some(rule) = r.exception {
                    return filter_engine::MatchResult::allowed_by_exception(rule);
                }
            }
        }
    }
    base
}

/// Merge overlay cosmetic resources into the base's. The overlay wins: its `site#@#selector`
/// exceptions cancel the base's hides of that selector, and its `$generichide` exception makes
/// the page generic-hide free.
///
/// Limits of the engine API, deliberately documented in `docs/PROFILES.md`: only host-scoped
/// overlay exceptions are visible here (a bare `#@#.x` is resolved inside the overlay engine
/// alone), an overlay exception cannot cancel a base *procedural* filter, and `$generichide`
/// cannot strip the non-class/id "misc" generic selectors already in the base's static list;
/// `$elemhide`, `$specifichide` and `$jsinject` are not understood by the engine at all (base or
/// overlay); the caller applies them to the merged result with [`mask_cosmetics`].
fn merge_cosmetics(base: &mut filter_engine::Cosmetics, ov: filter_engine::Cosmetics) {
    if !ov.exceptions.is_empty() {
        base.hide_selectors.retain(|s| !ov.exceptions.contains(s));
    }
    base.hide_selectors.extend(ov.hide_selectors);
    base.procedural_actions.extend(ov.procedural_actions);
    if !ov.injected_script.is_empty() {
        if !base.injected_script.is_empty() {
            base.injected_script.push('\n');
        }
        base.injected_script.push_str(&ov.injected_script);
    }
    base.generichide |= ov.generichide;
    base.exceptions.extend(ov.exceptions);
}

/// Apply the page-scoped exception bits (`ext_rules::target`) to the cosmetic engine's output:
/// `$elemhide` drops every hide and the observer; `$specifichide` keeps only the generic hides
/// (`generic`, evaluated lazily: the selectors a host without rules gets); `$jsinject` drops the
/// scriptlets. (`$content` is HTML filtering and `$replace`, not scriptlets, as in AdGuard.)
pub(crate) fn mask_cosmetics(
    cos: &mut filter_engine::Cosmetics,
    disabled: u32,
    generic: impl FnOnce() -> Vec<String>,
) {
    use ext_rules::target::{JS, PCSS, SCRIPTLET, SNIPPET, SPECIFICHIDE};
    if disabled & PCSS != 0 {
        cos.hide_selectors.clear();
        cos.procedural_actions.clear();
        cos.generichide = true;
    } else if disabled & SPECIFICHIDE != 0 {
        cos.hide_selectors = if cos.generichide {
            Vec::new()
        } else {
            let mut g = generic();
            // the page's own `#@#` exceptions still cancel generic hides
            g.retain(|s| !cos.exceptions.contains(s));
            g
        };
        cos.procedural_actions.clear();
    }
    if disabled & (JS | SCRIPTLET | SNIPPET) != 0 {
        cos.injected_script.clear();
    }
}

/// The hides a host with no rules of its own gets from both of the profile's engines (the generic
/// ones): what `$specifichide` leaves.
fn generic_hides(
    engine: &filter_engine::SharedEngine,
    overlay: Option<&filter_engine::SharedEngine>,
) -> Vec<String> {
    const NO_RULES: &str = "https://argus-generic-hide.invalid/";
    let mut c = engine.cosmetic_for(NO_RULES);
    if let Some(ov) = overlay.filter(|o| o.is_enabled()) {
        merge_cosmetics(&mut c, ov.cosmetic_for(NO_RULES));
    }
    c.hide_selectors
}

fn document_excepted(engine: &filter_engine::SharedEngine, url: &str) -> bool {
    engine.document_excepted(url).0
}

/// AdGuard's `#$?#sel { remove: true }`: the style block that means "remove the element".
fn is_remove_style(style: &str) -> bool {
    let n: String = style
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ';')
        .collect();
    n.eq_ignore_ascii_case("remove:true")
}

/// Generic hide selectors for the classes and ids a page reports, from both of the profile's
/// engines: the base's minus the overlay's exceptions, plus the overlay's own; nothing when
/// either engine excepts the page from generic hiding.
pub(crate) fn dynamic_selectors(
    profile: &Profile,
    url: &str,
    classes: &[String],
    ids: &[String],
) -> Vec<String> {
    let mut out = profile.engine.dynamic_hide_selectors(url, classes, ids);
    let Some(ov) = &profile.overlay else {
        return out;
    };
    if !ov.is_enabled() {
        return out;
    }
    let cos = ov.cosmetic_for(url);
    if cos.generichide {
        return Vec::new();
    }
    out.retain(|s| !cos.exceptions.contains(s));
    for s in ov.dynamic_hide_selectors(url, classes, ids) {
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

/// Replacement upstream clients, built but not yet installed.
pub struct PreparedUpstream {
    client: UpstreamClient,
    strict: UpstreamClient,
    opts: UpstreamOptions,
    proxy: Option<Arc<crate::upstream_proxy::ProxyEndpoint>>,
}

/// Shared per-process filtering + forwarding context, cloned (via `Arc`) into every connection.
pub struct ProxyContext {
    engine: Arc<SharedEngine>,
    /// The pooled upstream client; replaced when its timeouts change (requests in flight keep
    /// the old one).
    client: ArcSwap<UpstreamClient>,
    /// The live upstream proxy (empty: connect directly), shared by every dialer.
    proxy: Arc<crate::upstream_proxy::ProxyHandle>,
    /// The options the clients were built from, for rebuilding.
    upstream_opts: parking_lot::Mutex<Option<UpstreamOptions>>,
    /// The default profile's slot (also held by the profile table).
    default_slot: ProfileSlot,
    /// Device-to-profile table; holds only the default profile until something publishes.
    profiles: Profiles,
    /// The profile and device store and the builder that compiles it into `profiles` (set once
    /// at startup; see [`Self::set_profile_service`]).
    /// Hosts excluded from interception / filtering (see `common::bypass`).
    bypass: std::sync::OnceLock<Arc<common::bypass::BypassEngine>>,
    /// Per-host Extended Validation verdicts.
    ev: crate::ev::EvCache,
    profile_store: std::sync::OnceLock<Arc<common::profile_store::ProfileStore>>,
    profile_builder: std::sync::OnceLock<Arc<crate::profile_build::ProfileBuilder>>,
    /// Refuse explicit-proxy connections without a known device token (`407`).
    require_device_token: std::sync::atomic::AtomicBool,
    /// Upstream request timeout in milliseconds; 0 disables it.
    request_timeout_ms: Arc<AtomicU64>,
    /// Code-only upstream dial override (tests/controlled setups); shared by the HTTP client and
    /// the WebSocket dialer. Never read from config.
    resolve_all_to: Option<IpAddr>,
    /// Destination policy for every upstream dial.
    policy: Arc<DestPolicy>,
    /// The web server, for in-process handoff of requests to the web UI endpoint.
    web_server: parking_lot::RwLock<Option<Arc<dyn crate::self_route::WebUiHandoff>>>,
    /// Client for requests aimed at the proxy's own ports (see [`build_strict_upstream_client`]).
    strict_client: ArcSwap<UpstreamClient>,
    /// The `/__adblock__/` endpoints and their state.
    internal: Arc<Internal>,
    /// Optional per-response transforms (extended rules), see [`crate::rewrite`].
    transform_source: ArcSwap<Option<Arc<dyn TransformSource>>>,
    /// Leave bodies alone when the origin says `Cache-Control: no-transform` (header-only edits
    /// still apply). Many CDNs set it on everything, hence the switch.
    respect_no_transform: std::sync::atomic::AtomicBool,
    /// Neutralise service workers on filtered sites (see `AdblockSettings::guard_service_workers`).
    guard_service_workers: std::sync::atomic::AtomicBool,
    /// Hosts the guard leaves alone (exact or `*.suffix`).
    guard_exempt: ArcSwap<Vec<String>>,
    /// Live Stealth Mode settings (shared with the web API, which swaps them on save).
    stealth: Arc<ArcSwap<common::config::StealthSettings>>,
    /// Upstream certificates seen by the upstream clients (shared with the web API).
    certs: Arc<common::certstore::CertStore>,
    /// Probe handshakes to learn why an upstream certificate was rejected (when built from
    /// options).
    prober: Option<Arc<crate::upstream::CertProber>>,
    /// The live trusted root set (when built from options).
    roots: Option<Arc<crate::roots::RootsHandle>>,
}

impl ProxyContext {
    /// `adblock_enabled == false` disables the engine at startup; afterwards the on/off state is
    /// the engine's live flag (see [`Self::set_adblock_enabled`]), so UI toggles take effect.
    pub fn new(engine: Arc<SharedEngine>, adblock_enabled: bool) -> Self {
        let opts = UpstreamOptions::default();
        let client = build_upstream_client(&opts).expect("default upstream client");
        let strict = build_strict_upstream_client(&opts).expect("default upstream client");
        Self::with_clients(engine, client, strict, adblock_enabled)
    }

    fn with_clients(
        engine: Arc<SharedEngine>,
        client: UpstreamClient,
        strict: UpstreamClient,
        adblock_enabled: bool,
    ) -> Self {
        if !adblock_enabled {
            engine.set_enabled(false);
        }
        let default_slot = default_profile_slot(engine.clone());
        Self {
            engine,
            strict_client: ArcSwap::from_pointee(strict),
            policy: Arc::default(),
            web_server: parking_lot::RwLock::new(None),
            upstream_opts: parking_lot::Mutex::new(None),
            proxy: Default::default(),
            client: ArcSwap::from_pointee(client),
            profiles: Profiles::new(default_slot.clone()),
            default_slot,
            bypass: std::sync::OnceLock::new(),
            ev: Default::default(),
            profile_store: std::sync::OnceLock::new(),
            profile_builder: std::sync::OnceLock::new(),
            require_device_token: std::sync::atomic::AtomicBool::new(false),
            request_timeout_ms: Arc::new(AtomicU64::new(DEFAULT_REQUEST_TIMEOUT_MS)),
            resolve_all_to: None,
            internal: Arc::new(Internal::new()),
            transform_source: ArcSwap::from_pointee(Some(Arc::new(ext::ExtTransformSource))),
            respect_no_transform: std::sync::atomic::AtomicBool::new(true),
            guard_service_workers: std::sync::atomic::AtomicBool::new(false),
            guard_exempt: ArcSwap::from_pointee(Vec::new()),
            stealth: Arc::default(),
            certs: Default::default(),
            prober: None,
            roots: None,
        }
    }

    /// Attach (or detach) the userscripts of the default profile. Live: connections hold the
    /// profile slot, so the next request sees them.
    pub fn set_userscripts(&self, manager: Option<Arc<userscript_engine::UserscriptManager>>) {
        let slot = &self.default_slot;
        slot.store(Arc::new(
            slot.load()
                .with(|p| *p = p.clone().with_userscripts(manager)),
        ));
    }

    /// What to do about service workers on sites that get userscripts.
    pub fn set_service_worker_policy(&self, p: common::config::ServiceWorkerPolicy) {
        self.internal.gm.set_sw_policy(p);
    }

    /// Configure the in-page panel (reserved host, global switch, dashboard link) and the
    /// per-site blocking backend.
    pub fn configure_panel(
        &self,
        cfg: crate::panel::PanelConfig,
        blocking: Option<Arc<dyn crate::panel::SiteBlocking>>,
    ) {
        self.internal.panel.configure(cfg);
        self.internal.panel.set_site_blocking(blocking);
    }

    /// Attach the script control of the default profile (see [`crate::scriptctl`]). Live, like
    /// [`Self::set_userscripts`].
    pub fn set_script_control(&self, control: Option<Arc<crate::scriptctl::ScriptControl>>) {
        let slot = &self.default_slot;
        slot.store(Arc::new(slot.load().with(|p| p.script_control = control)));
    }

    /// Documents currently holding unfetched userscript bundle URLs (bounded; for tests/metrics).
    pub fn userscript_docs(&self) -> usize {
        self.internal.gm.docs.len()
    }

    /// Scriptlet names that pages reported as unsupported (no uBO equivalent), with report counts.
    pub fn unsupported_scriptlets(&self) -> Vec<(String, u64)> {
        self.internal.unsupported_scriptlets()
    }

    /// Honour `Cache-Control: no-transform` on responses (default on).
    /// Live switch for the service-worker guard.
    pub fn set_guard_service_workers(&self, on: bool) {
        self.guard_service_workers.store(on, Ordering::Relaxed);
    }

    /// Live exempt-host list of the service-worker guard.
    pub fn set_guard_service_workers_exempt(&self, hosts: Vec<String>) {
        self.guard_exempt.store(Arc::new(hosts));
    }

    /// Is the service-worker guard off for `host` / `url`: listed host, per-site blocking off, or
    /// a `@@$document` / `$elemhide` / `$jsinject` exception?
    fn sw_guard_exempt(&self, rctx: &RequestCtx, host: &str, url: &str) -> bool {
        let h = host.to_ascii_lowercase();
        if self
            .guard_exempt
            .load()
            .iter()
            .any(|e| match e.strip_prefix("*.") {
                Some(s) => {
                    h.len() > s.len() && h.ends_with(s) && h[..h.len() - s.len()].ends_with('.')
                }
                None => *e == h,
            })
        {
            return true;
        }
        let profile = rctx.profile.load();
        let probe = SharedEngine::site_probe(url);
        if profile.engine.site_off_with(&probe)
            || profile
                .overlay
                .as_ref()
                .is_some_and(|o| o.site_off_with(&probe))
        {
            return true;
        }
        let (excepted, gen_) = profile.engine.document_excepted(url);
        if excepted {
            return true;
        }
        gen_.aux::<ext_rules::ExtIndex>().is_some_and(|idx| {
            let mut info =
                ext_rules::RequestInfo::new(url, "GET", ext_rules::ResourceType::Document);
            info.source_url = None;
            idx.page_exempt(&info)
        })
    }

    /// Replace the Stealth Mode settings; the next request uses them.
    pub fn set_stealth(&self, s: common::config::StealthSettings) {
        self.stealth.store(Arc::new(s));
    }

    /// The live settings cell, for the web API to swap on save.
    pub fn stealth_handle(&self) -> Arc<ArcSwap<common::config::StealthSettings>> {
        self.stealth.clone()
    }

    pub fn set_respect_no_transform(&self, respect: bool) {
        self.respect_no_transform.store(respect, Ordering::Relaxed);
    }

    /// Install (or clear) the source of per-response transforms (the default is the extended
    /// rule index, see [`crate::ext`]).
    pub fn set_transform_source(&self, source: Option<Arc<dyn TransformSource>>) {
        self.transform_source.store(Arc::new(source));
    }

    /// Build the context and its pooled upstream client from `opts` in one step, so the HTTP
    /// client and WebSocket dialer share the same resolve override.
    pub fn with_upstream(
        engine: Arc<SharedEngine>,
        opts: &UpstreamOptions,
        adblock_enabled: bool,
    ) -> Result<Self> {
        // One root set for every client, the prober and the WebSocket dialer.
        let mut opts = opts.clone();
        let roots = opts.roots_handle()?;
        opts.roots = Some(roots.clone());
        let opts = &opts;
        let mut ctx = Self::with_clients(
            engine,
            build_upstream_client(opts)?,
            build_strict_upstream_client(opts)?,
            adblock_enabled,
        );
        ctx.roots = Some(roots);
        *ctx.upstream_opts.lock() = Some(opts.clone());
        ctx.policy = opts.policy.clone();
        ctx.proxy = opts.proxy.clone();
        ctx.resolve_all_to = opts.resolve_all_to;
        ctx.certs = opts.certs.clone();
        ctx.prober = Some(Arc::new(crate::upstream::CertProber::new(opts)?));
        Ok(ctx)
    }

    /// The live trusted root set, or a fresh compiled-in set with `extra_ca_paths` for a context
    /// built from a ready-made client.
    pub fn roots_handle(
        &self,
        extra_ca_paths: &[std::path::PathBuf],
    ) -> Result<Arc<crate::roots::RootsHandle>> {
        match &self.roots {
            Some(r) => Ok(r.clone()),
            None => crate::roots::RootsHandle::floor(extra_ca_paths),
        }
    }

    /// The live trusted root set, when built from options.
    pub fn roots(&self) -> Option<&Arc<crate::roots::RootsHandle>> {
        self.roots.as_ref()
    }

    /// The certificate prober, when built from options.
    pub fn prober(&self) -> Option<&Arc<crate::upstream::CertProber>> {
        self.prober.as_ref()
    }

    /// The upstream certificate store.
    pub fn certs(&self) -> &Arc<common::certstore::CertStore> {
        &self.certs
    }

    /// Replace the destination policy (for contexts built from a ready-made client).
    pub fn with_policy(mut self, policy: Arc<DestPolicy>) -> Self {
        self.policy = policy;
        self
    }

    /// Register the web server that requests to the web UI endpoint are handed to.
    pub fn set_web_server(&self, server: Arc<dyn crate::self_route::WebUiHandoff>) {
        *self.web_server.write() = Some(server);
    }

    /// The web server and whether `host:port` names the web UI endpoint such that `client` could
    /// reach it directly (see [`DestPolicy::is_web_ui`]).
    pub(crate) async fn web_ui_for(
        &self,
        host: &str,
        port: u16,
        client: std::net::IpAddr,
        client_local: Option<std::net::IpAddr>,
    ) -> Option<Arc<dyn crate::self_route::WebUiHandoff>> {
        let server = self.web_server.read().clone()?;
        self.policy
            .is_web_ui(host, port, self.resolve_all_to(), client, client_local)
            .await
            .then_some(server)
    }

    /// The live upstream proxy every dial goes through when one is on.
    pub fn proxy_handle(&self) -> &Arc<crate::upstream_proxy::ProxyHandle> {
        &self.proxy
    }

    /// Resolve and check the upstream proxy `cfg` (the fallible half of changing it live); the
    /// endpoint in force is reused when `cfg` is unchanged. `None`: no proxy.
    pub async fn prepare_proxy(
        &self,
        cfg: &common::config::UpstreamProxy,
    ) -> Result<Option<Arc<crate::upstream_proxy::ProxyEndpoint>>> {
        if !cfg.enabled {
            return Ok(None);
        }
        if let Some(cur) = self.proxy.load().filter(|c| c.same_as(cfg)) {
            return Ok(Some(cur));
        }
        let dns = self.dns().unwrap_or_else(|| {
            Arc::new(crate::dns::CachedResolver::from_settings(
                &Default::default(),
            ))
        });
        crate::upstream_proxy::ProxyEndpoint::prepare(cfg, self.policy.clone(), dns).await
    }

    /// Test `cfg` (not necessarily the one in force): connect through it to `host:port`, finish
    /// a TLS handshake, and report the time taken or why it failed.
    pub async fn test_upstream_proxy(
        &self,
        cfg: &common::config::UpstreamProxy,
        host: &str,
        port: u16,
    ) -> std::result::Result<Duration, String> {
        let mut cfg = cfg.clone();
        cfg.enabled = true;
        let ep = self
            .prepare_proxy(&cfg)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("disabled")?;
        let roots = self.roots_handle(&[]).map_err(|e| e.to_string())?;
        let tls = crate::upstream::client_tls_config(roots, self.certs.clone())
            .map_err(|e| e.to_string())?;
        ep.test(
            tokio_rustls::TlsConnector::from(Arc::new(tls)),
            host,
            port,
            Duration::from_secs(10),
        )
        .await
    }

    /// [`Self::web_ui_for`] for a request on the explicit proxy listener: `host:port` naming
    /// the proxy's own explicit port is the web UI (same reach rules). Returns the web UI port
    /// too, the one to hand over.
    pub(crate) async fn web_ui_via_proxy_port(
        &self,
        host: &str,
        port: u16,
        client: std::net::IpAddr,
        client_local: Option<std::net::IpAddr>,
    ) -> Option<(Arc<dyn crate::self_route::WebUiHandoff>, u16)> {
        let ui = self.policy.web_ui_alias(port)?;
        let web = self.web_ui_for(host, ui, client, client_local).await?;
        Some((web, ui))
    }

    /// The destination policy every upstream dial is checked against.
    pub fn policy(&self) -> &Arc<DestPolicy> {
        &self.policy
    }

    /// The upstream dial override, if any (code-only).
    pub fn resolve_all_to(&self) -> Option<IpAddr> {
        self.resolve_all_to
    }

    /// Shared handle to the request timeout in milliseconds (for live settings updates).
    pub fn request_timeout_handle(&self) -> Arc<AtomicU64> {
        self.request_timeout_ms.clone()
    }

    /// The shared engine handle (used by the WS/h3 paths too).
    pub fn engine(&self) -> &Arc<SharedEngine> {
        &self.engine
    }

    /// The bypass engine (built-in defaults until [`Self::set_bypass`] installs the persisted one).
    pub fn bypass(&self) -> &Arc<common::bypass::BypassEngine> {
        self.bypass.get_or_init(Default::default)
    }

    /// Whether `host:port` presents an Extended Validation certificate. Probed over the same
    /// destination policy as any other dial, with its own short timeout, and cached per
    /// `host:port`: definite answers for a long time, a failed probe only briefly (as
    /// [`crate::ev::EvVerdict::Unknown`], which callers treat as "do not decrypt"). IP literals
    /// are never EV.
    pub async fn ev_verdict(&self, host: &str, port: u16, limit: Duration) -> crate::ev::EvVerdict {
        use crate::ev::EvVerdict;
        if host.parse::<IpAddr>().is_ok() {
            return EvVerdict::NotEv;
        }
        self.ev
            .verdict(host, port, async {
                let addr = match self.policy.resolve(host, port, self.resolve_all_to).await {
                    Ok(a) => a,
                    Err(_) => return EvVerdict::Unknown,
                };
                match crate::ev::probe(host, addr, limit, self.proxy.load().as_deref()).await {
                    Some(true) => EvVerdict::Ev,
                    Some(false) => EvVerdict::NotEv,
                    None => EvVerdict::Unknown,
                }
            })
            .await
    }

    /// Whether `host` is the reserved in-page panel host (answered by the proxy itself, never
    /// dialled).
    pub fn is_panel_host(&self, host: &str) -> bool {
        self.internal.panel.is_panel_host(host)
    }

    /// Install the bypass engine (once, at startup).
    pub fn set_bypass(&self, engine: Arc<common::bypass::BypassEngine>) {
        let _ = self.bypass.set(engine);
    }

    /// Close the idle upstream connections that served downstream connection `conn_id`.
    pub fn evict_conn(&self, conn_id: u64) {
        self.client.load().evict_conn(conn_id);
        self.strict_client.load().evict_conn(conn_id);
    }

    /// The client WebSocket upgrades to `port` go through (the strict one for the proxy's own
    /// ports).
    pub fn ws_client(&self, port: u16) -> UpstreamClient {
        let c = if self.policy.is_own_port(port) {
            self.strict_client.load_full()
        } else {
            self.client.load_full()
        };
        (*c).clone()
    }

    /// The shared pooled upstream client.
    pub fn client(&self) -> UpstreamClient {
        (**self.client.load()).clone()
    }

    /// Rebuild both upstream clients with new connect / read timeouts and swap them in. Requests
    /// in flight finish on the old clients. A no-op when the timeouts are unchanged or the
    /// context was built from a ready-made client.
    pub fn set_upstream_timeouts(&self, connect: Duration, read: Duration) -> Result<()> {
        let browser_like = self
            .upstream_opts
            .lock()
            .as_ref()
            .is_some_and(|o| o.browser_like);
        let prepared = self.prepare_upstream(connect, read, browser_like, self.proxy.load())?;
        self.commit_upstream(prepared);
        Ok(())
    }

    /// Build the replacement clients without installing them (the fallible half of
    /// [`Self::set_upstream_timeouts`]); `None` when nothing changes. `browser_like` picks the
    /// client: with or without the browser fingerprint. `proxy` is the upstream proxy
    /// the new clients (and, once committed, every dialer) use.
    pub fn prepare_upstream(
        &self,
        connect: Duration,
        read: Duration,
        browser_like: bool,
        proxy: Option<Arc<crate::upstream_proxy::ProxyEndpoint>>,
    ) -> Result<Option<PreparedUpstream>> {
        let guard = self.upstream_opts.lock();
        let Some(opts) = guard.as_ref() else {
            return Ok(None);
        };
        if opts.connect_timeout == Some(connect)
            && opts.read_timeout == Some(read)
            && opts.browser_like == browser_like
            && match (&proxy, self.proxy.load()) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, &b),
                _ => false,
            }
        {
            return Ok(None);
        }
        let mut next = opts.clone();
        next.browser_like = browser_like;
        next.connect_timeout = Some(connect);
        next.read_timeout = Some(read);
        Ok(Some(PreparedUpstream {
            client: build_upstream_client_via(&next, proxy.clone())?,
            strict: build_strict_upstream_client_via(&next, proxy.clone())?,
            opts: next,
            proxy,
        }))
    }

    /// Install what [`Self::prepare_upstream_timeouts`] built. Cannot fail.
    pub fn commit_upstream(&self, p: Option<PreparedUpstream>) {
        if let Some(p) = p {
            self.client.store(Arc::new(p.client));
            self.strict_client.store(Arc::new(p.strict));
            self.proxy.store(p.proxy);
            if let Some(pr) = &self.prober {
                pr.set_connect_timeout(p.opts.connect_timeout);
            }
            *self.upstream_opts.lock() = Some(p.opts);
        }
    }

    /// The caching resolver behind the upstream clients, when built from options.
    pub fn dns(&self) -> Option<Arc<crate::dns::CachedResolver>> {
        self.upstream_opts
            .lock()
            .as_ref()
            .and_then(|o| o.dns.clone())
    }

    /// The connect timeout the upstream client currently uses.
    pub fn upstream_connect_timeout(&self) -> Option<Duration> {
        self.upstream_opts
            .lock()
            .as_ref()
            .and_then(|o| o.connect_timeout)
    }

    /// Whether ad blocking is currently enabled (live).
    pub fn adblock_enabled(&self) -> bool {
        self.engine.is_enabled()
    }

    /// Turn ad blocking on or off at runtime.
    pub fn set_adblock_enabled(&self, enabled: bool) {
        self.engine.set_enabled(enabled);
    }

    /// Set the upstream request timeout (time to response headers); `Duration::ZERO` disables it.
    pub fn set_request_timeout(&self, timeout: Duration) {
        self.request_timeout_ms
            .store(timeout.as_millis() as u64, Ordering::Relaxed);
    }

    /// The default profile's slot.
    pub fn default_profile(&self) -> &ProfileSlot {
        &self.default_slot
    }

    /// Register the profile store and its builder (once; later calls are ignored).
    pub fn set_profile_service(
        &self,
        store: Arc<common::profile_store::ProfileStore>,
        builder: Arc<crate::profile_build::ProfileBuilder>,
    ) {
        let _ = self.profile_store.set(store);
        let _ = self.profile_builder.set(builder);
    }

    /// The internal endpoints' state (userscript delivery, panel, extension bridge hub).
    pub fn internal(&self) -> &Arc<Internal> {
        &self.internal
    }

    /// The persistent profile and device store, once registered.
    pub fn profile_store(&self) -> Option<&Arc<common::profile_store::ProfileStore>> {
        self.profile_store.get()
    }

    /// The builder that keeps the live profile table in step with the store, once registered.
    pub fn profile_builder(&self) -> Option<&Arc<crate::profile_build::ProfileBuilder>> {
        self.profile_builder.get()
    }

    /// The device-to-profile table.
    pub fn profiles(&self) -> &Profiles {
        &self.profiles
    }

    /// Require a known device token on explicit-proxy connections (`proxy.require_device_token`).
    pub fn set_require_device_token(&self, require: bool) {
        self.require_device_token.store(require, Ordering::Relaxed);
    }

    pub fn require_device_token(&self) -> bool {
        self.require_device_token.load(Ordering::Relaxed)
    }

    /// Whether a request should be blocked by the profile in `rctx` (respects the engine's
    /// master toggle, records stats). Shared by the WebSocket and HTTP/3 paths.
    pub fn should_block_with(
        &self,
        rctx: &RequestCtx,
        url: &str,
        source_url: &str,
        resource_type: &str,
    ) -> bool {
        let profile = rctx.profile.load();
        profile.engine.is_enabled() && rctx.adblock_on() && {
            // One adblock request serves the base engine and the overlay.
            let q = filter_engine::Query::new(url, source_url, resource_type);
            let base = profile.engine.check_deferred_q(&q);
            let v = apply_overlay(&profile, base, &q);
            profile
                .engine
                .record_verdict(v, url, source_url, resource_type, &profile.label)
                .blocked
        }
    }

    /// Forward a proxied request upstream, filtering it first with the profile in `rctx`.
    ///
    /// `scheme` is the upstream scheme (`http` for plain proxying, `https` for MITM'd traffic).
    /// `fallback_authority` supplies host/port for MITM requests whose URI is origin-form (path
    /// only) — the host then comes from the `Host` header or this fallback.
    pub async fn forward_with(
        &self,
        req: Request<Incoming>,
        scheme: &str,
        fallback_authority: Option<(String, u16)>,
        rctx: &RequestCtx,
    ) -> Result<Response<ProxyBody>> {
        let method = req.method().clone();
        let is_head = method == hyper::Method::HEAD;
        let uri = req.uri().clone();

        // Target host/port: absolute-form URI / `:authority`, else the `Host` header, else the
        // MITM fallback. Authorities are parsed properly (bracketed IPv6, userinfo rejected).
        let named = authority::of_request(&uri, req.headers());
        let host = match named
            .as_ref()
            .map(|(h, _)| h.clone())
            .or_else(|| fallback_authority.as_ref().map(|(h, _)| h.clone()))
        {
            Some(h) => h,
            None => return Ok(bad_request("Missing host")),
        };

        // Behind a CONNECT / transparent entry the port was fixed when the connection was
        // accepted; a port the client puts in the request (h2 `:authority`) must not redirect it.
        let port = fallback_authority
            .as_ref()
            .map(|(_, p)| *p)
            .or(named.as_ref().and_then(|(_, p)| *p))
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        let url_host = authority::url_host(&host);
        // A host in `full` bypass is forwarded as-is: no filtering, rewriting or log event.
        let bypass_full = self.bypass().mode_of(&host) == Some(common::bypass::BypassMode::Full);
        if bypass_full {
            self.bypass().note_bypassed();
        }

        let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let local_url = || format!("{}{pq}", origin_of(scheme, &url_host, port));
        let hdr_type = |h: &hyper::HeaderMap| classify(&method, h, pq);

        // The reserved confirmation host is answered by the proxy alone: never filtered, never
        // forwarded, whatever the entry mode.
        if self.internal.panel.is_panel_host(&host) {
            let origin = origin_of(scheme, &url_host, port);
            let resp = self
                .internal
                .panel
                .handle(&self.internal, req, rctx, &origin)
                .await;
            if !bypass_full {
                log_local(
                    rctx,
                    filter_engine::EventAction::Allowed,
                    method.as_str(),
                    &local_url(),
                    "",
                    INTERNAL_TYPE,
                    resp.status().as_u16(),
                    "",
                );
            }
            return Ok(resp);
        }

        // Internal endpoints are answered locally for every host: never filtered, never
        // forwarded.
        if uri.path().starts_with(csp::INTERNAL_PREFIX) {
            let origin = origin_of(scheme, &url_host, port);
            let up = crate::gm::Upstream {
                client: &self.client.load(),
                strict_client: &self.strict_client.load(),
                policy: &self.policy,
                resolve_all_to: self.resolve_all_to,
                scope: rctx.upstream_scope(),
            };
            let src = req
                .headers()
                .get(hyper::header::REFERER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let resp = self.internal.handle(req, &host, &origin, rctx, &up).await;
            if !bypass_full {
                log_local(
                    rctx,
                    filter_engine::EventAction::Allowed,
                    method.as_str(),
                    &local_url(),
                    &src,
                    INTERNAL_TYPE,
                    resp.status().as_u16(),
                    "",
                );
            }
            return Ok(resp);
        }

        // A service-worker script fetch (also `importScripts` inside one) on a host where a
        // privileged userscript may run: refuse, so registration fails and the worker never sees
        // the page's bundles or GM traffic (see docs/USERSCRIPT-PROTOCOL.md section 6).
        if is_service_worker_fetch(req.headers()) {
            let prof = rctx.profile.load();
            let refuse = prof.script_index.as_ref().is_some_and(|ix| {
                self.internal
                    .gm
                    .blocks_service_workers_in(&ix.load(), &host)
            });
            if refuse {
                debug!("Refused a service worker script fetch for {host}");
                log_local(
                    rctx,
                    filter_engine::EventAction::Blocked,
                    method.as_str(),
                    &local_url(),
                    "",
                    hdr_type(req.headers()).as_str(),
                    403,
                    "service worker refused",
                );
                return Ok(Response::builder()
                    .status(hyper::StatusCode::FORBIDDEN)
                    .header("cache-control", "no-store")
                    .header("x-adblock-note", "service workers are blocked on this site")
                    .body(crate::inject::full_body(bytes::Bytes::new()))
                    .expect("sw refusal"));
            }
        }

        // Service-worker guard: a worker would answer navigations from its cache, so the page
        // never reaches the proxy and gets no injection. On filtered sites its script is replaced
        // by a worker that unregisters itself and never handles fetches (registration still
        // "succeeds", so apps do not error). Full-bypass hosts are left alone.
        if !bypass_full
            && self.guard_service_workers.load(Ordering::Relaxed)
            && req.method() == hyper::Method::GET
            && is_service_worker_fetch(req.headers())
        {
            let prof = rctx.profile.load();
            let site = format!("{scheme}://{host}/");
            if prof.engine.is_enabled()
                && rctx.adblock_on()
                && !self.sw_guard_exempt(rctx, &host, &site)
            {
                debug!("Replaced a service worker script for {host}");
                log_local(
                    rctx,
                    filter_engine::EventAction::Allowed,
                    method.as_str(),
                    &local_url(),
                    "",
                    hdr_type(req.headers()).as_str(),
                    200,
                    "service worker neutralised",
                );
                return Ok(Response::builder()
                    .status(hyper::StatusCode::OK)
                    .header("content-type", "application/javascript; charset=utf-8")
                    .header("cache-control", "no-store")
                    .header("x-adblock-note", "service worker neutralised")
                    .body(crate::inject::full_body(bytes::Bytes::from_static(
                        SW_NOOP.as_bytes(),
                    )))
                    .expect("sw shim"));
            }
        }

        // Take the request apart: the header map is moved, not copied, from here on.
        let (parts, body) = req.into_parts();
        let mut headers = parts.headers;
        // The extension bridge's headers never leave: the session secret and the relay token
        // are read here and removed from the request.
        let relay = crate::ext_bridge::take_headers(&mut headers);

        let path_and_query = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");

        // Absolute URL: prefer the request's own absolute form, else synthesize one.
        // The host in it is the normalised one, never the client's spelling. The scheme's default
        // port is never spelled (see `ext::rule_url`): every filter engine matches patterns such
        // as `||example.com/path` against the URL text, so `https://example.com:443/path` would
        // slip past them on every path (CONNECT, transparent, plain HTTP, WebSocket upgrades).
        let mut url = request_url(
            fallback_authority.is_none() && uri.authority().is_some(),
            uri.scheme_str(),
            scheme,
            &url_host,
            named.as_ref().and_then(|(_, p)| *p),
            port,
            path_and_query,
        );

        // A fetch the extension relays for a userscript: the job must be live and this hop must
        // pass the script's stored `@connect` (the browser follows redirects itself, so every
        // hop arrives here). Like the proxy's own GM requests it is not filtered.
        let mut bypass_full = bypass_full;
        if let Some(r) = relay.as_deref() {
            let allowed = url::Url::parse(&url).is_ok_and(|u| {
                self.internal.gm.ext().check_relay(
                    r,
                    &u,
                    rctx.ext,
                    rctx.ext_store.as_deref().unwrap_or(""),
                )
            });
            if !allowed {
                debug!("Refused a relayed request for {host}");
                log_local(
                    rctx,
                    filter_engine::EventAction::Blocked,
                    method.as_str(),
                    &url,
                    "",
                    RequestType::Other.as_str(),
                    403,
                    "relayed request refused",
                );
                return Ok(Response::builder()
                    .status(hyper::StatusCode::FORBIDDEN)
                    .header("cache-control", "no-store")
                    .header("x-adblock-note", "relayed request refused")
                    .body(crate::inject::full_body(bytes::Bytes::new()))
                    .expect("relay refusal"));
            }
            bypass_full = true;
        }

        // Filter decision. The profile guard is dropped before any `.await`.
        let rtype = classify(&method, &headers, path_and_query);
        let mut csp: Option<String> = None;
        // A document the user switched ad blocking off for (see `SharedEngine::site_off`): no
        // cosmetics, scriptlets or extended rules for it.
        let mut page_off = false;
        // The engine generation this request is judged by (carries the ext-rule index); the
        // response is judged by the same one.
        let mut generation: Option<Arc<filter_engine::Generation>> = None;
        let mut request_edits: Vec<ext_rules::HeaderEdit> = Vec::new();
        {
            let profile = rctx.profile.load();
            let engine = &profile.engine;
            if engine.is_enabled() && rctx.adblock_on() && !bypass_full {
                let source = source_url(&headers, &url, rtype);
                let q = filter_engine::Query::new(&url, source, rtype.as_str());
                let (verdict, gen_) = engine.check_gen_deferred_q(&q);
                let verdict = apply_overlay(&profile, verdict, &q);
                let verdict = engine.record_verdict_meta(
                    verdict,
                    &url,
                    source,
                    rtype.as_str(),
                    &profile.label,
                    method.as_str(),
                    event_mode(rctx),
                );
                generation = Some(gen_);
                if verdict.blocked {
                    debug!("Blocked {} ({})", url, rtype.as_str());
                    if let Some(sc) = &profile.script_control {
                        count_page_block(sc, source_url(&headers, &url, rtype));
                    }
                    if let Some(res) = verdict.redirect_resource() {
                        let origin = headers
                            .get(hyper::header::ORIGIN)
                            .and_then(|v| v.to_str().ok());
                        return Ok(redirect_response(res, origin));
                    }
                    return Ok(block_response(rtype, &verdict, &url));
                }
                // A non-default profile keeps its per-site exceptions in its overlay rules.
                page_off = rtype.is_frame() && {
                    // Base and overlay judge the same probe request.
                    let probe = SharedEngine::site_probe(&url);
                    engine.site_off_with(&probe)
                        || profile
                            .overlay
                            .as_ref()
                            .is_some_and(|o| o.site_off_with(&probe))
                };
                let navigation =
                    rtype == RequestType::Document && (method == hyper::Method::GET || is_head);
                let ext_idx = generation
                    .as_ref()
                    .and_then(|g| g.aux::<ext_rules::ExtIndex>());
                if let Some(mut new_url) = verdict.rewritten_url {
                    // `@@$removeparam` exceptions (the engine cannot parse them) restore the
                    // parameters they exempt.
                    if let Some(idx) = ext_idx {
                        let source = source_url(&headers, &url, rtype);
                        new_url = ext::exempt_engine_rewrite(
                            idx,
                            &url,
                            new_url,
                            method.as_str(),
                            source,
                            rtype,
                        );
                    }
                    if new_url != url {
                        if navigation {
                            log_local(
                                rctx,
                                filter_engine::EventAction::Allowed,
                                method.as_str(),
                                &url,
                                "",
                                rtype.as_str(),
                                307,
                                "url rewritten",
                            );
                            return Ok(rewrite_redirect(&new_url));
                        }
                        // Subresource: fetch the cleaned URL transparently.
                        url = new_url;
                    }
                }
                // Extended rules run after the engine verdict (see `crate::ext` for precedence).
                if let Some(idx) = ext_idx {
                    let source = source_url(&headers, &url, rtype);
                    if let Some(d) =
                        ext::request_decision(idx, &url, method.as_str(), source, rtype, &headers)
                    {
                        if let Some(id) = d.block {
                            let parsed = idx.rule(id);
                            let rule = parsed.map(|r| r.raw.clone()).unwrap_or_default();
                            if tracing::enabled!(tracing::Level::DEBUG) {
                                debug!("Blocked {} by extended rule {}", url, rule);
                            }
                            if let Some(sc) = &profile.script_control {
                                count_page_block(sc, source_url(&headers, &url, rtype));
                            }
                            engine.stats_handle().record_blocked(rtype.as_str(), &host);
                            // Borrowed straight into the ring: no event struct, no clock read here.
                            engine.record_request(&filter_engine::EventRef {
                                action: filter_engine::EventAction::Blocked,
                                method: method.as_str(),
                                url: &url,
                                source_host: "",
                                request_type: rtype.as_str(),
                                rule: &rule,
                                list_id: parsed.map(|r| r.list.as_str()),
                                client: Some(profile.label.as_ref()),
                                status: None,
                                mode: event_mode(rctx),
                                error_kind: None,
                                cert_fp: None,
                            });
                            let v = filter_engine::MatchResult::blocked(rule);
                            return Ok(block_response(rtype, &v, &url));
                        }
                        // `$removeparam` is idempotent: a navigation is redirected to the cleaned
                        // URL (never to a no-op target, so it cannot loop).
                        if navigation {
                            if let Some((cleaned, _)) = d.cleaned_url {
                                if cleaned != url {
                                    log_local(
                                        rctx,
                                        filter_engine::EventAction::Allowed,
                                        method.as_str(),
                                        &url,
                                        "",
                                        rtype.as_str(),
                                        307,
                                        "url rewritten",
                                    );
                                    return Ok(rewrite_redirect(&cleaned));
                                }
                            }
                        }
                        // Fetched transparently, never answered with a redirect: a URL
                        // transform need not be idempotent, so a redirect could loop.
                        if let Some((new_url, _)) = d.rewrite_url {
                            url = new_url;
                        }
                        request_edits = d.header_edits;
                    }
                }
                if rtype.is_frame() {
                    csp = engine.csp_for(&url, source_url(&headers, &url, rtype), rtype.as_str());
                }
            }
            // Script policy network hints: one atomic load when the master switch is off.
            if let Some(sc) = profile
                .script_control
                .as_ref()
                .filter(|sc| sc.enabled() && !bypass_full)
            {
                if sc
                    .check_request(
                        &headers,
                        if scheme == "http" { "http" } else { "https" },
                        &url_host,
                        port,
                    )
                    .is_some()
                {
                    debug!("Blocked {} by script policy", url);
                    log_local(
                        rctx,
                        filter_engine::EventAction::Blocked,
                        method.as_str(),
                        &url,
                        "",
                        rtype.as_str(),
                        403,
                        "script policy",
                    );
                    return Ok(policy_block_response(rtype, &url));
                }
            }
        }

        ext::apply_request_edits(&mut headers, &request_edits);

        // Stealth Mode: header, URL and cookie edits, decided once per request. Off for hosts in
        // full bypass, pages with ad blocking switched off, and options a `$stealth` exception
        // turns off for the page.
        let st = self.stealth.load_full();
        let mut stealth_mask = 0u32;
        let mut stealth_third = false;
        let mut orig_referer: Option<String> = None;
        if st.enabled && !bypass_full {
            let src = source_url(&headers, &url, rtype).to_string();
            stealth_third = rtype != RequestType::Document && stealth::is_third_party(&host, &src);
            let page = if rtype == RequestType::Document || src.is_empty() {
                url.clone()
            } else {
                src.clone()
            };
            let mut m = stealth::mask(&st);
            if m != 0 {
                let profile = rctx.profile.load();
                let probe = SharedEngine::site_probe(&page);
                if profile.engine.site_off_with(&probe)
                    || profile
                        .overlay
                        .as_ref()
                        .is_some_and(|o| o.site_off_with(&probe))
                {
                    m = 0;
                } else if let Some(idx) = profile.generation().aux::<ext_rules::ExtIndex>() {
                    m &= !ext::stealth_off(idx, &url, &src, rtype);
                }
            }
            if m & ext_rules::stealth::TRACKING_PARAMS != 0 {
                if let Some(new_url) = stealth::strip_tracking(&url) {
                    if rtype == RequestType::Document && (method == hyper::Method::GET || is_head) {
                        log_local(
                            rctx,
                            filter_engine::EventAction::Allowed,
                            method.as_str(),
                            &url,
                            "",
                            rtype.as_str(),
                            307,
                            "tracking parameters stripped",
                        );
                        return Ok(rewrite_redirect(&new_url));
                    }
                    url = new_url;
                }
            }
            if m != 0 {
                let kind = stealth::ReqKind {
                    document: rtype == RequestType::Document,
                    unsafe_method: matches!(
                        method,
                        hyper::Method::POST
                            | hyper::Method::PUT
                            | hyper::Method::PATCH
                            | hyper::Method::DELETE
                    ),
                };
                orig_referer =
                    stealth::apply_request(&st, m, &mut headers, &url, stealth_third, kind)
                        .orig_referer;
            }
            stealth_mask = m;
        }

        // Stream the request body upstream; nothing is buffered.
        let has_body = !body.is_end_stream();

        // Destination policy. the client skips its resolver for IP-literal hosts, so literals are
        // judged here; names are judged on what they resolve to, inside the client's resolver.
        if let Err(r) = self.policy.check_literal(&host, port) {
            common::faults::note(common::faults::Fault::PolicyRefusal, &host);
            debug!("Refused destination {host}:{port}: {r}");
            if !bypass_full {
                log_local(
                    rctx,
                    filter_engine::EventAction::Blocked,
                    method.as_str(),
                    &url,
                    "",
                    rtype.as_str(),
                    403,
                    "destination policy",
                );
            }
            return Ok(refused_response());
        }
        let client = if self.policy.is_own_port(port) {
            self.strict_client.load_full()
        } else {
            self.client.load_full()
        };

        let listed = connection_listed(&headers);
        let transformable_request = rtype.is_frame();
        // Code-only resolve override: the client never resolves IP literals, so aim those at the
        // override explicitly (the policy has already judged the requested literal) and keep the
        // original authority in `Host`.
        let mut dial_url = url.clone();
        let mut host_override = None;
        if let (Some(over), Ok(_)) = (self.resolve_all_to, host.parse::<IpAddr>()) {
            if let Ok(mut u) = url::Url::parse(&url) {
                if u.set_ip_host(over).is_ok() {
                    dial_url = u.to_string();
                    host_override = Some(format!("{url_host}:{port}"));
                }
            }
        }
        let mut rb = client.request(method.clone(), &dial_url);
        if let Some(s) = rctx.upstream_scope() {
            rb = rb.scope(s);
        }
        if let Some(h) = host_override {
            rb = rb.header(HOST, h);
        }
        for (name, value) in headers.iter() {
            // the client sets Host itself; don't forward hop-by-hop headers. Content-Length is only
            // kept for streamed bodies (it keeps the upload un-chunked); the client derives it
            // otherwise.
            if is_hop_by_hop(name)
                || listed.contains(name)
                || name == HOST
                // A document we may rewrite must come back whole, never as a 206 fragment.
                || (transformable_request
                    && (name == hyper::header::RANGE || name == hyper::header::IF_RANGE))
                || (!has_body && name.as_str().eq_ignore_ascii_case("content-length"))
            {
                continue;
            }
            rb = rb.header(name, value);
        }
        // One deadline for the whole request: reading a held body and sending it.
        let started = std::time::Instant::now();
        let timeout_ms = self.request_timeout_ms.load(Ordering::Relaxed);
        if has_body {
            // A small body (declared length) is held, so a request that fails on a stale
            // upstream connection can be sent again; anything else streams, and is never replayed.
            let small = headers
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<usize>().ok())
                .is_some_and(|n| n <= crate::upstream::MAX_REPLAY_BODY);
            if small {
                let limit = Duration::from_millis(if timeout_ms == 0 {
                    u64::MAX / 4
                } else {
                    timeout_ms
                });
                match tokio::time::timeout(limit, body.collect()).await {
                    Ok(Ok(c)) => rb = rb.body(c.to_bytes()),
                    Ok(Err(_)) => {
                        return Ok(status_response(
                            StatusCode::BAD_REQUEST,
                            "Request body unreadable",
                        ))
                    }
                    Err(_) => {
                        return Ok(status_response(
                            StatusCode::REQUEST_TIMEOUT,
                            "Request body timeout",
                        ))
                    }
                }
            } else {
                let stream = body
                    .into_data_stream()
                    .map_err(|e| std::io::Error::other(e.to_string()));
                rb = rb.body_stream(stream);
            }
        }

        let sent = if timeout_ms == 0 {
            rb.send().await
        } else {
            match tokio::time::timeout(
                Duration::from_millis(timeout_ms).saturating_sub(started.elapsed()),
                rb.send(),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => {
                    common::faults::note(common::faults::Fault::UpstreamTimeout, &host);
                    if !bypass_full {
                        log_request(
                            None,
                            rctx,
                            filter_engine::EventAction::Error,
                            method.as_str(),
                            &url,
                            src_of(&orig_referer, &headers, &url, rtype),
                            rtype,
                            Some(504),
                            Some(filter_engine::ErrorKind::UpstreamTimeout),
                        );
                    }
                    return Ok(status_response(
                        StatusCode::GATEWAY_TIMEOUT,
                        "Upstream timeout",
                    ));
                }
            }
        };
        let resp = match sent {
            Ok(r) => r,
            Err(e) if is_refusal(&e) => {
                common::faults::note(common::faults::Fault::PolicyRefusal, &host);
                debug!("Refused destination {host}:{port} (resolved): {e}");
                if !bypass_full {
                    log_local(
                        rctx,
                        filter_engine::EventAction::Blocked,
                        method.as_str(),
                        &url,
                        "",
                        rtype.as_str(),
                        403,
                        "destination policy",
                    );
                }
                return Ok(refused_response());
            }
            Err(e) => {
                common::faults::note(common::faults::Fault::UpstreamError, &host);
                warn!("Upstream error for {url}: {}", error_chain(&e));
                let kind = e.kind();
                let hostport = common::certstore::hostport(&url_host, port);
                // A certificate failure: one cached, single-flight probe handshake tells which
                // certificate was presented and why it was rejected.
                let failed_fp = match (&self.prober, kind, scheme) {
                    (Some(p), filter_engine::ErrorKind::UpstreamTls, "https") => {
                        p.probe(&url_host, port).await
                    }
                    _ => None,
                };
                if kind == filter_engine::ErrorKind::UpstreamTls {
                    self.certs.note_seen(&hostport, &rctx.profile.load().label);
                }
                if !bypass_full {
                    log_request(
                        failed_fp.as_deref(),
                        rctx,
                        filter_engine::EventAction::Error,
                        method.as_str(),
                        &url,
                        src_of(&orig_referer, &headers, &url, rtype),
                        rtype,
                        Some(502),
                        Some(kind),
                    );
                }
                if kind == filter_engine::ErrorKind::UpstreamTls {
                    let info = failed_fp
                        .as_deref()
                        .and_then(|fp| self.certs.info(fp, Some(&hostport)))
                        .filter(|i| i.verdict == common::certstore::Verdict::Invalid);
                    return Ok(crate::redirect::cert_error_response(
                        &url_host,
                        info.as_ref(),
                    ));
                }
                return Ok(bad_gateway(&format!("Upstream error: {e}")));
            }
        };

        let status = resp.status();
        if !bypass_full {
            // The certificate of the connection that served this very response.
            let cert_fp = resp.peer_certificate().and_then(|der| {
                // A completed response proves the chain verified for this host and port.
                let hostport = common::certstore::hostport(&url_host, port);
                let fp = self
                    .certs
                    .record_ok(&hostport, der, &|| crate::ev::is_ev_der(der))?;
                self.certs.note_seen(&hostport, &rctx.profile.load().label);
                Some(fp)
            });
            log_request(
                cert_fp.as_deref(),
                rctx,
                filter_engine::EventAction::Allowed,
                method.as_str(),
                &url,
                src_of(&orig_referer, &headers, &url, rtype),
                rtype,
                Some(status.as_u16()),
                None,
            );
        }
        // Moved out of the response (the body stream does not need them): no header-map copy.
        let mut resp = resp;
        let mut resp_headers = std::mem::take(resp.headers_mut());
        stealth::apply_response(&st, stealth_mask, &mut resp_headers, stealth_third);
        // A relayed response that redirects: the hop it names is checked here, before the
        // browser can follow it (Argus decrypted this hop, so it sees every one). Together with
        // the check of the first hop (`route`) this makes every hop the browser follows one the
        // proxy approved beforehand.
        if let (Some(r), true) = (relay.as_deref(), status.is_redirection()) {
            // Exactly one `Location`, non-empty, that parses once decoded the way browsers do
            // (lossy UTF-8), or the response is refused; the browser would follow what we cannot
            // read.
            let ok = match relay_redirect_target(&url, &resp_headers) {
                Ok(None) => true,
                Ok(Some(t)) => {
                    self.internal
                        .gm
                        .ext()
                        .check_hop(r, &t, rctx.ext, rctx.ext_store.as_deref().unwrap_or(""))
                        .await
                }
                Err(()) => false,
            };
            if !ok {
                debug!("Refused a relayed redirect from {host}");
                log_local(
                    rctx,
                    filter_engine::EventAction::Blocked,
                    method.as_str(),
                    &url,
                    "",
                    rtype.as_str(),
                    502,
                    "relayed redirect refused",
                );
                // No Set-Cookie, no Location: only the refusal.
                return Ok(Response::builder()
                    .status(hyper::StatusCode::BAD_GATEWAY)
                    .header("cache-control", "no-store")
                    .header("x-adblock-note", "relayed redirect refused")
                    .body(crate::inject::full_body(bytes::Bytes::new()))
                    .expect("relay redirect refusal"));
            }
        }
        let mut kind = classify_body(is_head, status, rtype, &resp_headers);
        // Script policy applies to every HTML document, `no-transform` or not: it adds headers
        // only, never rewrites a body the origin asked us to leave alone.
        let spol: Option<Arc<crate::scriptctl::DocEntry>> =
            if kind == BodyKind::Html && !is_head && status.as_u16() >= 200 && !bypass_full {
                rctx.profile.load().script_control.as_ref().and_then(|sc| {
                    sc.document(
                        if scheme == "http" { "http" } else { "https" },
                        &url_host,
                        port,
                    )
                })
            } else {
                None
            };
        // The in-page shim (WebRTC, Push, Location, DNT/GPC properties) goes into frames only.
        let stealth_js = if rtype.is_frame() && kind == BodyKind::Html {
            stealth::script(&st, stealth_mask)
        } else {
            None
        };
        let policy_nonce = spol.as_ref().map(|_| crate::inject::new_nonce());
        // `Cache-Control: no-transform`: no body rewriting at all (header edits still apply).
        if self.respect_no_transform.load(Ordering::Relaxed)
            && resp_headers
                .get_all(hyper::header::CACHE_CONTROL)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .any(|d| d.trim().eq_ignore_ascii_case("no-transform"))
        {
            kind = BodyKind::None;
        }
        if bypass_full {
            kind = BodyKind::None;
        }
        // HEAD / 1xx / 204 / 205 / 304 never carry a body, whatever the origin's length says.
        let body_allowed = !is_head
            && status.as_u16() >= 200
            && status != StatusCode::NO_CONTENT
            && status != StatusCode::RESET_CONTENT
            && status != StatusCode::NOT_MODIFIED;

        // Per-response work, decided once from the URL, type and headers.
        let (enabled, cosmetics) = {
            let profile = rctx.profile.load();
            let enabled = profile.engine.is_enabled() && rctx.adblock_on() && !bypass_full;
            let cos = (enabled && !page_off && kind == BodyKind::Html && body_allowed).then(|| {
                let mut c = profile.engine.cosmetic_for(&url);
                if let Some(ov) = &profile.overlay {
                    merge_cosmetics(&mut c, ov.cosmetic_for(&url));
                }
                c
            });
            (enabled, cos)
        };
        // Lock-free read (no refcount traffic); held only across the synchronous lookup.
        let source = self.transform_source.load();
        let mut transforms: ResponseTransforms = if enabled && !page_off {
            source
                .as_ref()
                .as_ref()
                .and_then(|s| {
                    s.transforms_for(&ResponseInfo {
                        generation: generation.as_ref(),
                        method: method.as_str(),
                        source_url: src_of(&orig_referer, &headers, &url, rtype),
                        url: &url,
                        request_type: rtype,
                        status,
                        request_headers: &headers,
                        response_headers: &resp_headers,
                    })
                })
                .unwrap_or_default()
        } else {
            ResponseTransforms::default()
        };
        if let Some(rule) = transforms.block.take() {
            // A `$header` rule matched the response: answer with the block response instead.
            debug!("Blocked {} by response rule {}", url, rule);
            let v = filter_engine::MatchResult::blocked(rule);
            return Ok(block_response(rtype, &v, &url));
        }
        if kind == BodyKind::None {
            // Redirects, 204s, `no-transform`, downloads...: header edits only.
            transforms = ResponseTransforms {
                header_edits: std::mem::take(&mut transforms.header_edits),
                ..Default::default()
            };
        }

        let codings = response_codings(&resp_headers);
        let out_coding = match &codings {
            Ok(c) if !c.is_empty() => choose_encoding(&headers),
            _ => None,
        };
        let origin_coded = matches!(&codings, Ok(c) if !c.is_empty());
        let content_type = resp_headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        let mut csp_values: Vec<Option<String>> = Vec::new();
        let mut csp_ro_values: Vec<Option<String>> = Vec::new();
        let mut rewritten = false;
        let mut utf8_charset = false;
        let mut text_changed = false;
        // Public id of a document that got userscripts (`Server-Timing: argus`).
        let mut server_timing: Option<String> = None;
        let body: ProxyBody = match (kind, codings) {
            (BodyKind::Html, Ok(codings))
                if (enabled || spol.is_some() || stealth_js.is_some()) && body_allowed =>
            {
                let origin = csp::PageOrigin::new(
                    if scheme == "http" { "http" } else { "https" },
                    &url_host,
                    port,
                );
                let nonce = policy_nonce
                    .clone()
                    .unwrap_or_else(crate::inject::new_nonce);
                let csp_headers: Vec<&str> = resp_headers
                    .get_all("content-security-policy")
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .collect();
                let (blocks_scripts, opaque) = csp::sandbox_facts(&csp_headers);
                let mut cos = cosmetics.unwrap_or_default();
                // `$elemhide` / `$specifichide` / `$jsinject` exceptions (seen by the ext index) and
                // `@@...$document` exceptions (accepted by adblock-rust itself, so the ext index
                // never sees them) mask what the cosmetic engine produced too: it implements
                // none of them.
                let disabled = {
                    let prof = rctx.profile.load();
                    let doc = document_excepted(&prof.engine, &url)
                        || prof
                            .overlay
                            .as_ref()
                            .is_some_and(|ov| ov.is_enabled() && document_excepted(ov, &url));
                    transforms.disabled | if doc { ext_rules::target::ALL } else { 0 }
                };
                mask_cosmetics(&mut cos, disabled, || {
                    let prof = rctx.profile.load();
                    generic_hides(&prof.engine, prof.overlay.as_deref())
                });
                if disabled & (ext_rules::target::PCSS | ext_rules::target::SPECIFICHIDE) != 0 {
                    transforms.procedural.clear();
                }
                if disabled
                    & (ext_rules::target::JS
                        | ext_rules::target::SCRIPTLET
                        | ext_rules::target::SNIPPET)
                    != 0
                {
                    transforms.scripts.clear();
                }
                if let Some(js) = &stealth_js {
                    // Runs first, before any page script (the scriptlet slot).
                    cos.injected_script = format!("{js}\n{}", cos.injected_script);
                }
                // Extended CSS the engine rejected goes to the in-page procedural evaluator.
                for (selector, style) in &transforms.procedural {
                    let action = match style {
                        Some(s) if is_remove_style(s) => serde_json::json!({"type": "remove"}),
                        Some(s) => serde_json::json!({"type": "style", "arg": s}),
                        None => serde_json::json!({"type": "hide"}),
                    };
                    cos.procedural_actions.push(
                        serde_json::json!({"selector": [{"type": "css-selector", "arg": selector}], "action": action})
                            .to_string(),
                    );
                }
                let ext_script = transforms.scripts.join(";\n");
                // Userscripts: matched against the profile's index (one atomic load and an
                // emptiness check when there are none); nothing at all under `sandbox`.
                let us = if blocks_scripts || !enabled {
                    None
                } else {
                    let prof = rctx.profile.load();
                    prof.script_index.as_ref().and_then(|ix| {
                        let idx = ix.load();
                        if idx.is_empty() {
                            return None; // zero cost: no allocation, no probe
                        }
                        // Bound to the extension session this connection authenticated as
                        // on the extension listener, if any (never from a header).
                        let session = rctx
                            .ext
                            .filter(|s| self.internal.gm.ext().allows(*s, &prof.name));
                        let store = rctx.ext_store.as_deref().unwrap_or("");
                        self.internal.gm.plan_document_bound(
                            &idx,
                            &prof.name,
                            &host,
                            &url,
                            &origin_of(scheme, &url_host, port),
                            rtype != RequestType::Subdocument,
                            session,
                            store,
                        )
                    })
                };
                server_timing = us.as_ref().and_then(|p| p.mdoc.clone());
                let us_srcs: &[String] = us.as_ref().map_or(&[], |p| &p.srcs);
                let panel_key = if enabled && !blocks_scripts {
                    self.internal.panel.hotkey(rctx)
                } else {
                    None
                };
                let menu_mode = if us.is_some() && enabled && !blocks_scripts {
                    self.internal.panel.menu_mode(rctx)
                } else {
                    None
                };
                let sw_guard = self.guard_service_workers.load(Ordering::Relaxed)
                    && enabled
                    && !page_off
                    && !self.sw_guard_exempt(rctx, &host, &url);
                let unregister_sw = !blocks_scripts
                    && ((us.is_some()
                        && rctx.profile.load().script_index.as_ref().is_some_and(|ix| {
                            self.internal
                                .gm
                                .blocks_service_workers_in(&ix.load(), &host)
                        }))
                        || sw_guard);
                let head = if enabled || stealth_js.is_some() {
                    build_head(&PageSpec {
                        unregister_sw,
                        sw_guard: sw_guard && !blocks_scripts,
                        userscripts: us_srcs,
                        panel: panel_key.as_ref(),
                        menu: menu_mode,
                        ext: us.as_ref().is_some_and(|p| p.ext_bound),
                        ext_script: &ext_script,
                        cosmetics: &cos,
                        internal: &self.internal,
                        host: &host,
                        nonce: &nonce,
                        script_ok: !blocks_scripts,
                        observer_ok: !opaque && enabled,
                    })
                } else {
                    Default::default()
                };
                let needs = csp::Needs {
                    script: head.has_script,
                    style: head.has_style || us.as_ref().is_some_and(|p| p.style),
                    connect: head.observer
                        || panel_key.is_some()
                        || us.as_ref().is_some_and(|p| p.connect),
                };
                let meta_csp: Option<crate::rewrite::MetaCsp> = if needs.connect {
                    let (origin, nonce) = (origin.clone(), nonce.clone());
                    Some(Arc::new(move |c: &str| {
                        let a = csp::adapt(
                            c,
                            csp::PolicyKind::Meta,
                            &origin,
                            &nonce,
                            csp::Needs {
                                connect: true,
                                ..Default::default()
                            },
                        );
                        a.changed.then_some(a.text)
                    }))
                } else {
                    None
                };
                let plan = HtmlPlan {
                    head_html: head.html,
                    injections: transforms.injections.clone(),
                    remove_selectors: transforms.remove_selectors.clone(),
                    replacements: transforms.text_replacements.clone(),
                    element_filters: transforms.element_filters.clone(),
                    meta_csp,
                    policy: spol.as_ref().and_then(|e| e.html.clone()),
                };
                // `$replace` & co. on a document run on the decoded text first; the HTML stages
                // (removals, injections, cosmetics) then see the result.
                let pre = transforms
                    .body
                    .clone()
                    .filter(|t| media_type(&resp_headers).is_some_and(|m| t.applies_to(&m)));
                if plan.is_empty() && pre.is_none() {
                    passthrough_body(resp)
                } else {
                    csp_values = csp::adapt_headers(&csp_headers, &origin, &nonce, needs).0;
                    // Report-Only policies get the same allowances so that our own tags do not
                    // produce violation reports (they are not enforced: nothing is weakened).
                    let ro_headers: Vec<&str> = resp_headers
                        .get_all("content-security-policy-report-only")
                        .iter()
                        .filter_map(|v| v.to_str().ok())
                        .collect();
                    csp_ro_values =
                        csp::adapt_report_only(&ro_headers, &origin, &nonce, needs, blocks_scripts);
                    match transform_html(resp, codings, out_coding, content_type.clone(), plan, pre)
                        .await
                    {
                        Outcome::Html {
                            body,
                            utf8_charset: u,
                            ..
                        } => {
                            rewritten = true;
                            utf8_charset = u;
                            body
                        }
                        Outcome::Untouched(b) => {
                            csp_values.clear();
                            csp_ro_values.clear();
                            b
                        }
                        Outcome::Text { body } => body,
                    }
                }
            }
            (BodyKind::Other | BodyKind::Html, Ok(codings))
                if body_allowed
                    && transforms.body.as_ref().is_some_and(|t| {
                        media_type(&resp_headers).is_some_and(|m| t.applies_to(&m))
                    }) =>
            {
                let t = transforms.body.clone().expect("checked");
                match transform_text(resp, codings, out_coding, t).await {
                    Outcome::Text { body } => {
                        text_changed = true;
                        body
                    }
                    Outcome::Untouched(b) => b,
                    Outcome::Html { body, .. } => body,
                }
            }
            _ if !body_allowed => full_body(Bytes::new()),
            _ => passthrough_body(resp),
        };
        let changed = rewritten || text_changed;
        if !rewritten {
            server_timing = None;
        }

        let listed_resp = connection_listed(&resp_headers);
        let mut builder = Response::builder().status(status);
        let mut csp_idx = 0usize;
        let mut csp_ro_idx = 0usize;
        let mut vary_seen = false;
        for (name, value) in resp_headers.iter() {
            if is_hop_by_hop(name) || listed_resp.contains(name) {
                continue;
            }
            // Never advertise HTTP/3 (QUIC bypasses the proxy): clients keep using TCP.
            if name == hyper::header::ALT_SVC {
                continue;
            }
            if changed {
                // The body is new: framing, encoding, validators and digests no longer describe it.
                let n = name.as_str();
                if name == hyper::header::CONTENT_LENGTH
                    || name == hyper::header::CONTENT_ENCODING
                    || name == hyper::header::ACCEPT_RANGES
                    || matches!(
                        n,
                        "content-md5" | "digest" | "repr-digest" | "content-digest"
                    )
                {
                    continue;
                }
                if name == hyper::header::ETAG {
                    if let Ok(v) = value.to_str() {
                        let weak = if v.starts_with("W/") {
                            v.to_string()
                        } else {
                            format!("W/{v}")
                        };
                        if let Ok(hv) = HeaderValue::from_str(&weak) {
                            builder = builder.header(name, hv);
                            continue;
                        }
                    }
                }
                if name == CONTENT_TYPE && utf8_charset {
                    if let Ok(v) = value.to_str() {
                        if let Ok(hv) = HeaderValue::from_str(
                            &crate::rewrite::charset::with_charset(v, "utf-8"),
                        ) {
                            builder = builder.header(name, hv);
                            continue;
                        }
                    }
                }
                if name == hyper::header::VARY {
                    vary_seen = true;
                    if let Ok(v) = value.to_str() {
                        if v.trim() == "*" {
                            builder = builder.header(name, value);
                        } else if let Ok(hv) =
                            HeaderValue::from_str(&format!("{v}, {}", vary_additions(origin_coded)))
                        {
                            builder = builder.header(name, hv);
                        }
                        continue;
                    }
                }
            }
            if rewritten && name.as_str() == "content-security-policy" {
                let adapted = csp_values.get(csp_idx).cloned().flatten();
                csp_idx += 1;
                if let Some(v) = adapted.and_then(|v| HeaderValue::from_str(&v).ok()) {
                    builder = builder.header(name, v);
                    continue;
                }
            }
            if rewritten && name.as_str() == "content-security-policy-report-only" {
                let adapted = csp_ro_values.get(csp_ro_idx).cloned().flatten();
                csp_ro_idx += 1;
                if let Some(v) = adapted.and_then(|v| HeaderValue::from_str(&v).ok()) {
                    builder = builder.header(name, v);
                    continue;
                }
            }
            builder = builder.header(name, value);
        }
        if changed {
            if !vary_seen {
                builder = builder.header(hyper::header::VARY, vary_additions(origin_coded));
            }
            if let Some(c) = out_coding {
                builder = builder.header(hyper::header::CONTENT_ENCODING, c.token());
            }
        }
        // `$csp`: an additional policy header; the browser enforces the intersection with any
        // policy the origin sent.
        if let Some(csp) = csp {
            if let Ok(v) = HeaderValue::from_str(&csp) {
                builder = builder.header("content-security-policy", v);
            }
        }
        if let Some(m) = server_timing {
            // Appended, so the site's own timing entries survive.
            builder = builder.header("server-timing", format!("argus;desc=\"{m}\""));
        }
        let mut response = builder
            .body(body)
            .map_err(|e| Error::Connection(format!("build response: {e}")))?;
        for edit in &transforms.header_edits {
            match edit {
                HeaderEdit::Set(n, v) => {
                    response.headers_mut().insert(n.clone(), v.clone());
                }
                HeaderEdit::Append(n, v) => {
                    response.headers_mut().append(n.clone(), v.clone());
                }
                HeaderEdit::Remove(n) => {
                    response.headers_mut().remove(n);
                }
            }
        }
        if let Some(e) = &spol {
            self.add_policy_headers(
                &mut response,
                e,
                policy_nonce.as_deref().unwrap_or(""),
                &host,
            );
        }
        Ok(response)
    }

    /// Add the generated policy as separate headers (never merged into the site's own: browsers
    /// intersect, so it can only restrict). Runs after the extended-rule header edits so that
    /// a `$removeheader` rule cannot strip it.
    fn add_policy_headers(
        &self,
        response: &mut Response<ProxyBody>,
        entry: &crate::scriptctl::DocEntry,
        nonce: &str,
        host: &str,
    ) {
        if let Some(c) = entry.csp_for(nonce, &self.internal.doc_token(host)) {
            if let Ok(v) = HeaderValue::from_str(&c) {
                response.headers_mut().append("content-security-policy", v);
            }
        }
        if let Some(pp) = entry.permissions.as_deref() {
            let site: Vec<String> = response
                .headers()
                .get_all("permissions-policy")
                .iter()
                .filter_map(|v| v.to_str().ok().map(str::to_string))
                .collect();
            let site_refs: Vec<&str> = site.iter().map(String::as_str).collect();
            let merged = ext_rules::merge_permissions_policy(&site_refs, &[pp], &[]);
            if let Ok(v) = HeaderValue::from_str(&merged) {
                response.headers_mut().insert("permissions-policy", v);
            }
        }
    }
}

/// Count a blocked request against the page named by `source` (a page URL).
fn count_page_block(sc: &crate::scriptctl::ScriptControl, source: &str) {
    let host = source
        .split_once("://")
        .map(|(_, r)| r)
        .and_then(|r| r.split(['/', '?', '#']).next())
        .map(|a| a.rsplit_once('@').map_or(a, |(_, h)| h))
        .map(|a| {
            a.rsplit_once(':')
                .filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit()))
                .map_or(a, |(h, _)| h)
        });
    if let Some(h) = host {
        sc.count_blocked(h);
    }
}

/// The absolute URL the filters judge. `absolute_form`: the request carried its own scheme and
/// authority outside any CONNECT / transparent entry, so its own scheme and (optional) port are
/// kept; otherwise the URL is synthesized from the accepted target. The scheme's default port is
/// never spelled (see `ext::rule_url` for why).
fn request_url(
    absolute_form: bool,
    uri_scheme: Option<&str>,
    scheme: &str,
    url_host: &str,
    named_port: Option<u16>,
    port: u16,
    path_and_query: &str,
) -> String {
    // Built once, with the scheme's default port left out (see `ext::rule_url`, which still
    // normalises any other spelling).
    let (s, p) = match (absolute_form, uri_scheme) {
        (true, Some(s)) => (s, named_port),
        _ => (scheme, Some(port)),
    };
    let default = match s {
        "https" | "wss" => 443,
        "http" | "ws" => 80,
        _ => 0,
    };
    let mut url = String::with_capacity(s.len() + url_host.len() + path_and_query.len() + 9);
    url.push_str(s);
    url.push_str("://");
    url.push_str(url_host);
    if let Some(p) = p.filter(|&p| p != default) {
        use std::fmt::Write as _;
        let _ = write!(url, ":{p}");
    }
    url.push_str(path_and_query);
    match ext::rule_url(&url) {
        std::borrow::Cow::Owned(fixed) => fixed,
        std::borrow::Cow::Borrowed(_) => url,
    }
}

/// `Vary` members added to a rewritten response: the body depends on the request type and on
/// the negotiated coding.
fn vary_additions(encoded: bool) -> &'static str {
    if encoded {
        "Accept-Encoding, Sec-Fetch-Dest"
    } else {
        "Sec-Fetch-Dest"
    }
}

fn status_response(status: StatusCode, msg: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .body(full_body(Bytes::from(msg.to_string())))
        .expect("static status response")
}

fn bad_request(msg: &str) -> Response<ProxyBody> {
    status_response(StatusCode::BAD_REQUEST, msg)
}

fn bad_gateway(msg: &str) -> Response<ProxyBody> {
    status_response(StatusCode::BAD_GATEWAY, msg)
}

/// A service worker that takes over, never handles a fetch and unregisters itself (open tabs
/// are not reloaded; their next navigation goes through the proxy).
const SW_NOOP: &str = "self.addEventListener('install',function(){self.skipWaiting();});\
self.addEventListener('activate',function(e){e.waitUntil(self.registration.unregister().catch(function(){}));});\n";

/// A request that fetches a service worker's script: `Service-Worker: script` (set by the browser
/// for the main script and its updates) or `Sec-Fetch-Dest: serviceworker`.
fn is_service_worker_fetch(h: &hyper::HeaderMap) -> bool {
    h.get("service-worker")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("script"))
        || h.get("sec-fetch-dest")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("serviceworker"))
}

/// The hop a redirect response names: `Ok(None)` without a `Location`, `Err` unless there is
/// exactly one, non-empty, that joins onto `base` (decoded lossily as UTF-8, like a browser).
fn relay_redirect_target(
    base: &str,
    h: &hyper::HeaderMap,
) -> std::result::Result<Option<url::Url>, ()> {
    let mut it = h.get_all(hyper::header::LOCATION).iter();
    let Some(first) = it.next() else {
        return Ok(None);
    };
    if it.next().is_some() {
        return Err(());
    }
    let raw = String::from_utf8_lossy(first.as_bytes());
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(());
    }
    url::Url::parse(base)
        .ok()
        .and_then(|b| b.join(raw).ok())
        .map(Some)
        .ok_or(())
}

#[cfg(test)]
mod relay_location_tests {
    use super::relay_redirect_target;
    use hyper::header::{HeaderValue, LOCATION};

    fn h(vals: &[&[u8]]) -> hyper::HeaderMap {
        let mut m = hyper::HeaderMap::new();
        for v in vals {
            m.append(LOCATION, HeaderValue::from_bytes(v).unwrap());
        }
        m
    }

    #[test]
    fn exactly_one_parsable_location_is_followed_otherwise_refused() {
        let base = "https://api.test/a/b";
        assert_eq!(relay_redirect_target(base, &h(&[])), Ok(None));
        assert_eq!(
            relay_redirect_target(base, &h(&[b"/c"]))
                .unwrap()
                .unwrap()
                .as_str(),
            "https://api.test/c"
        );
        // empty, blank, two of them, unparsable: refused
        assert!(relay_redirect_target(base, &h(&[b""])).is_err());
        assert!(relay_redirect_target(base, &h(&[b"  "])).is_err());
        assert!(relay_redirect_target(base, &h(&[b"/x", b"https://evil.test/"])).is_err());
        assert!(relay_redirect_target(base, &h(&[b"https://"])).is_err());
    }

    #[test]
    fn non_ascii_locations_are_decoded_lossily_not_skipped() {
        let base = "https://api.test/";
        // UTF-8 host: the target the browser would go to is what is checked
        let t = relay_redirect_target(base, &h(&["https://b\u{fc}cher.test/x".as_bytes()]))
            .unwrap()
            .unwrap();
        assert_eq!(t.host_str(), Some("xn--bcher-kva.test"));
        // invalid UTF-8 bytes become U+FFFD, they do not make the header "disappear"
        let t = relay_redirect_target(base, &h(&[b"/p\xff\xfe"]))
            .unwrap()
            .unwrap();
        assert!(t.path().starts_with("/p"));
    }
}

#[cfg(test)]
mod url_tests {
    use super::request_url;

    #[test]
    fn default_ports_are_never_spelled_on_any_entry_path() {
        // CONNECT / transparent (synthesized from the accepted target).
        assert_eq!(
            request_url(false, None, "https", "example.com", None, 443, "/ads.js"),
            "https://example.com/ads.js"
        );
        assert_eq!(
            request_url(false, None, "http", "example.com", None, 80, "/a?b=1"),
            "http://example.com/a?b=1"
        );
        // Plain proxy, absolute-form, explicit default port.
        assert_eq!(
            request_url(
                true,
                Some("http"),
                "http",
                "example.com",
                Some(80),
                80,
                "/x"
            ),
            "http://example.com/x"
        );
        assert_eq!(
            request_url(true, Some("http"), "http", "[::1]", Some(80), 80, "/x"),
            "http://[::1]/x"
        );
        // Non-default ports stay, so `||example.com/ads.js` does not match them (as in uBO).
        assert_eq!(
            request_url(false, None, "https", "example.com", None, 8443, "/ads.js"),
            "https://example.com:8443/ads.js"
        );
        assert_eq!(
            request_url(
                true,
                Some("http"),
                "http",
                "example.com",
                Some(8080),
                8080,
                "/x"
            ),
            "http://example.com:8080/x"
        );
    }
}

#[cfg(test)]
mod cosmetic_mask_tests {
    use super::{is_remove_style, mask_cosmetics};
    use ext_rules::target::{JS, PCSS, SPECIFICHIDE};
    use filter_engine::{compile_engine, Cosmetics, SharedEngine};

    fn cos() -> Cosmetics {
        Cosmetics {
            hide_selectors: vec![".specific".into(), ".generic-misc".into()],
            procedural_actions: vec!["{}".into()],
            injected_script: "scriptlet();".into(),
            ..Default::default()
        }
    }

    #[test]
    fn elemhide_drops_every_hide_and_the_observer() {
        let mut c = cos();
        mask_cosmetics(&mut c, PCSS, || panic!("not needed"));
        assert!(c.hide_selectors.is_empty() && c.procedural_actions.is_empty());
        assert!(c.generichide, "no class/id observer either");
        assert_eq!(
            c.injected_script, "scriptlet();",
            "scriptlets are not element hiding"
        );
    }

    #[test]
    fn specifichide_keeps_only_the_generic_hides() {
        let mut c = cos();
        mask_cosmetics(&mut c, SPECIFICHIDE, || vec![".generic-misc".into()]);
        assert_eq!(c.hide_selectors, [".generic-misc"]);
        assert!(c.procedural_actions.is_empty() && !c.generichide);
        let mut g = cos();
        g.generichide = true;
        mask_cosmetics(&mut g, SPECIFICHIDE, || vec![".generic-misc".into()]);
        assert!(g.hide_selectors.is_empty());
    }

    #[test]
    fn jsinject_stops_scriptlets_only() {
        let mut c = cos();
        mask_cosmetics(&mut c, JS, Vec::new);
        assert!(c.injected_script.is_empty());
        assert_eq!(c.hide_selectors.len(), 2);
        let mut n = cos();
        mask_cosmetics(&mut n, 0, Vec::new);
        assert_eq!(n.injected_script, "scriptlet();");
        assert_eq!(n.hide_selectors.len(), 2);
    }

    #[test]
    fn masking_an_engines_real_output() {
        let e = SharedEngine::new();
        e.install(compile_engine(&["example.com##.ad
example.com##.box:has-text(X)
"
        .to_string()]));
        let mut c = e.cosmetic_for("https://example.com/");
        assert!(!c.hide_selectors.is_empty());
        mask_cosmetics(&mut c, PCSS, Vec::new);
        assert!(c.hide_selectors.is_empty() && c.generichide);
    }

    #[test]
    fn a_document_exception_is_found_through_adblock_rust() {
        use super::document_excepted;
        use filter_engine::shared::rule_has_document_option;
        let e = |rule: &str| {
            let s = SharedEngine::new();
            s.install(compile_engine(&[format!("example.com##.ad\n{rule}\n")]));
            s
        };
        let url = "https://example.com/page";
        assert!(document_excepted(&e("@@||example.com^$document"), url));
        assert!(document_excepted(&e("@@||example.com^$doc,important"), url));
        // a plain network exception is not a cosmetic one; neither is another site's
        assert!(!document_excepted(&e("@@||example.com^"), url));
        assert!(!document_excepted(&e("@@||example.com^$image"), url));
        assert!(!document_excepted(&e("@@||other.test^$document"), url));
        assert!(rule_has_document_option("@@||a^$all,document"));
        assert!(!rule_has_document_option("@@||a^$domain=document.test"));
        // end to end: the engine's own hides are what gets masked
        let eng = e("@@||example.com^$document");
        let mut c = eng.cosmetic_for(url);
        assert!(!c.hide_selectors.is_empty());
        let disabled = if document_excepted(&eng, url) {
            ext_rules::target::ALL
        } else {
            0
        };
        c.injected_script = "s();".into();
        mask_cosmetics(&mut c, disabled, Vec::new);
        assert!(c.hide_selectors.is_empty() && c.injected_script.is_empty() && c.generichide);
    }

    #[test]
    fn specifichide_uses_both_engines_generics_minus_page_exceptions() {
        use super::{generic_hides, merge_cosmetics};
        use filter_engine::overlay_from_rules;
        let base = SharedEngine::new();
        base.install(compile_engine(&[
            "##[data-g-base]\n##[data-g-excepted]\nexample.com##.specific\n".to_string(),
        ]));
        let ov = overlay_from_rules("##[data-g-overlay]\nexample.com#@#[data-g-excepted]")
            .unwrap()
            .unwrap();
        let url = "https://example.com/";
        let mut c = base.cosmetic_for(url);
        merge_cosmetics(&mut c, ov.cosmetic_for(url));
        assert!(c.hide_selectors.iter().any(|s| s == ".specific"), "{c:?}");
        mask_cosmetics(&mut c, ext_rules::target::SPECIFICHIDE, || {
            generic_hides(&base, Some(&ov))
        });
        let mut got = c.hide_selectors.clone();
        got.sort();
        assert_eq!(got, ["[data-g-base]", "[data-g-overlay]"], "{c:?}");
    }

    #[test]
    fn remove_true_is_a_remove_action() {
        assert!(is_remove_style("remove: true"));
        assert!(is_remove_style(" Remove:true; "));
        assert!(!is_remove_style("remove: false"));
        assert!(!is_remove_style("display: none"));
    }
}

#[cfg(test)]
mod cosmetic_merge_tests {
    use super::merge_cosmetics;
    use filter_engine::{compile_engine, overlay_from_rules, SharedEngine};

    const URL: &str = "https://example.com/page";

    fn engine(list: &str) -> SharedEngine {
        let e = SharedEngine::new();
        e.install(compile_engine(&[list.to_string()]));
        e
    }

    #[test]
    fn overlay_cosmetic_exception_cancels_a_base_hide() {
        let base = engine("example.com##.x\nexample.com##.y\n");
        let ov = overlay_from_rules("example.com#@#.x").unwrap().unwrap();
        let mut c = base.cosmetic_for(URL);
        assert!(c.hide_selectors.iter().any(|s| s == ".x"));
        merge_cosmetics(&mut c, ov.cosmetic_for(URL));
        assert!(!c.hide_selectors.iter().any(|s| s == ".x"), "{c:?}");
        assert!(c.hide_selectors.iter().any(|s| s == ".y"), "{c:?}");
        // Another site is unaffected.
        let mut other = base.cosmetic_for("https://other.test/");
        merge_cosmetics(&mut other, ov.cosmetic_for("https://other.test/"));
        assert!(other.hide_selectors.is_empty());
    }

    #[test]
    fn overlay_generichide_and_exceptions_apply_to_dynamic_selectors() {
        use crate::request_ctx::Profile;
        use std::sync::Arc;
        let classes = ["gen".to_string()];
        let profile = |rules: &str| {
            let base = Arc::new(engine("##.gen\n"));
            let p = Profile::new(1, 1, base);
            p.with_overlay(overlay_from_rules(rules).unwrap())
        };
        let sel = |p: &Profile| super::dynamic_selectors(p, URL, &classes, &[]);
        assert_eq!(sel(&profile("")), vec![".gen"]);
        assert!(sel(&profile("example.com#@#.gen")).is_empty());
        assert!(sel(&profile("@@||example.com^$generichide")).is_empty());
        // An overlay's own generic rule is served too, and other sites keep the base's.
        let p = profile("##.own");
        let both = super::dynamic_selectors(&p, URL, &["gen".into(), "own".into()], &[]);
        assert!(both.contains(&".gen".to_string()) && both.contains(&".own".to_string()));
        let p = profile("example.com#@#.gen");
        assert_eq!(
            super::dynamic_selectors(&p, "https://other.test/", &classes, &[]),
            vec![".gen"]
        );
    }
}

fn event_mode(rctx: &RequestCtx) -> filter_engine::EventMode {
    if rctx.transparent {
        filter_engine::EventMode::Transparent
    } else {
        filter_engine::EventMode::Explicit
    }
}

/// Record a non-blocked request in the profile engine's request log (and live broadcast).
#[allow(clippy::too_many_arguments)]
fn log_request(
    cert_fp: Option<&str>,
    rctx: &RequestCtx,
    action: filter_engine::EventAction,
    method: &str,
    url: &str,
    source: &str,
    rtype: RequestType,
    status: Option<u16>,
    error_kind: Option<filter_engine::ErrorKind>,
) {
    let profile = rctx.profile.load();
    profile.engine.record_request(&filter_engine::EventRef {
        action,
        method,
        url,
        source_host: filter_engine::RequestMatcher::host_of(source),
        request_type: rtype.as_str(),
        rule: "",
        list_id: None,
        client: Some(profile.label.as_ref()),
        status,
        mode: event_mode(rctx),
        error_kind,
        cert_fp,
    });
}

/// Request type of Argus's own `/__adblock__/*` and panel traffic: lets the log UI and API
/// consumers tell it apart from the page's own requests.
const INTERNAL_TYPE: &str = "internal";

/// Record a request Argus answered itself (an internal endpoint, a refusal, a redirect stub):
/// every request it serves or refuses is logged once, like the ones it forwards.
#[allow(clippy::too_many_arguments)]
fn log_local(
    rctx: &RequestCtx,
    action: filter_engine::EventAction,
    method: &str,
    url: &str,
    source: &str,
    rtype: &str,
    status: u16,
    rule: &str,
) {
    let profile = rctx.profile.load();
    profile.engine.record_request(&filter_engine::EventRef {
        action,
        method,
        url,
        source_host: filter_engine::RequestMatcher::host_of(source),
        request_type: rtype,
        rule,
        list_id: None,
        client: Some(profile.label.as_ref()),
        status: Some(status),
        mode: event_mode(rctx),
        error_kind: None,
        cert_fp: None,
    });
}

/// An error with its whole `source()` chain, so a transport failure names its real cause.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = format!("{e}");
    let mut cur = e.source();
    while let Some(s) = cur {
        out.push_str(&format!(": {s}"));
        cur = s.source();
    }
    out
}

#[cfg(test)]
mod error_chain_tests {
    use super::error_chain;

    #[derive(Debug)]
    struct Layer(&'static str, Option<Box<dyn std::error::Error + 'static>>);
    impl std::fmt::Display for Layer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for Layer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.as_deref()
        }
    }

    #[test]
    fn upstream_error_log_names_the_root_cause() {
        let root = Layer("connection reset", None);
        let mid = Layer("connection error", Some(Box::new(root)));
        let top = Layer("error sending request", Some(Box::new(mid)));
        assert_eq!(
            error_chain(&top),
            "error sending request: connection error: connection reset"
        );
    }
}

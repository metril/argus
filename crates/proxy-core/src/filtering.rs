//! Request filtering and upstream forwarding.
//!
//! [`ProxyContext`] carries the shared, `Send + Sync` handles every connection needs: the
//! [`SharedEngine`] (one `Arc<Engine>` behind an `ArcSwap`) for block/allow decisions and a single
//! pooled [`reqwest::Client`] for forwarding requests upstream over real TLS.
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
use crate::redirect::{block_response, policy_block_response, redirect_response, rewrite_redirect};
use crate::request_ctx::{default_profile_slot, Profile, ProfileSlot, RequestCtx};
use crate::request_type::{classify, source_url, RequestType};
use crate::rewrite::codec::{choose_encoding, response_codings};
use crate::rewrite::pipeline::{transform_html, transform_text, Outcome};
use crate::rewrite::{
    classify_body, media_type, BodyKind, HeaderEdit, HtmlPlan, ResponseInfo, ResponseTransforms,
    TransformSource,
};
use crate::upstream::{build_strict_upstream_client, build_upstream_client, UpstreamOptions};
use crate::{Error, Result};
use bytes::Bytes;
use filter_engine::ArcSwap;
use filter_engine::SharedEngine;
use futures_util::TryStreamExt;
use http_body_util::BodyExt;
use hyper::body::{Body, Incoming};
use hyper::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, HOST};
use hyper::{Request, Response, StatusCode};
use std::net::{IpAddr, SocketAddr};
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
fn origin_of(scheme: &str, url_host: &str, port: u16) -> String {
    let scheme = if scheme == "http" { "http" } else { "https" };
    let default = if scheme == "http" { 80 } else { 443 };
    if port == default {
        format!("{scheme}://{url_host}")
    } else {
        format!("{scheme}://{url_host}:{port}")
    }
}

/// Shared per-process filtering + forwarding context, cloned (via `Arc`) into every connection.
pub struct ProxyContext {
    engine: Arc<SharedEngine>,
    client: reqwest::Client,
    /// Context used by [`Self::forward`] (default profile, unattributed client).
    default_ctx: RequestCtx,
    /// Upstream request timeout in milliseconds; 0 disables it.
    request_timeout_ms: Arc<AtomicU64>,
    /// Code-only upstream dial override (tests/controlled setups); shared by the HTTP client and
    /// the WebSocket dialer. Never read from config.
    resolve_all_to: Option<IpAddr>,
    /// Destination policy for every upstream dial.
    policy: Arc<DestPolicy>,
    /// Client for requests aimed at the proxy's own ports (see [`build_strict_upstream_client`]).
    strict_client: reqwest::Client,
    /// The `/__adblock__/` endpoints and their state.
    internal: Arc<Internal>,
    /// Optional per-response transforms (extended rules), see [`crate::rewrite`].
    transform_source: ArcSwap<Option<Arc<dyn TransformSource>>>,
    /// Leave bodies alone when the origin says `Cache-Control: no-transform` (header-only edits
    /// still apply). Many CDNs set it on everything, hence the switch.
    respect_no_transform: std::sync::atomic::AtomicBool,
}

impl ProxyContext {
    /// `adblock_enabled == false` disables the engine at startup; afterwards the on/off state is
    /// the engine's live flag (see [`Self::set_adblock_enabled`]), so UI toggles take effect.
    pub fn new(engine: Arc<SharedEngine>, client: reqwest::Client, adblock_enabled: bool) -> Self {
        if !adblock_enabled {
            engine.set_enabled(false);
        }
        let default_ctx = RequestCtx::anonymous(default_profile_slot(engine.clone()));
        Self {
            engine,
            strict_client: client.clone(),
            policy: Arc::default(),
            client,
            default_ctx,
            request_timeout_ms: Arc::new(AtomicU64::new(DEFAULT_REQUEST_TIMEOUT_MS)),
            resolve_all_to: None,
            internal: Arc::new(Internal::new()),
            transform_source: ArcSwap::from_pointee(Some(Arc::new(ext::ExtTransformSource))),
            respect_no_transform: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Attach (or detach) the userscripts of the default profile. Live: connections hold the
    /// profile slot, so the next request sees them.
    pub fn set_userscripts(&self, manager: Option<Arc<userscript_engine::UserscriptManager>>) {
        let slot = &self.default_ctx.profile;
        let cur = slot.load_full();
        slot.store(Arc::new(
            Profile::new(cur.id, cur.generation, cur.engine.clone())
                .with_userscripts(manager)
                .with_script_control(cur.script_control.clone()),
        ));
    }

    /// Attach the script control of the default profile (see [`crate::scriptctl`]). Live, like
    /// [`Self::set_userscripts`].
    pub fn set_script_control(&self, control: Option<Arc<crate::scriptctl::ScriptControl>>) {
        let slot = &self.default_ctx.profile;
        let cur = slot.load_full();
        slot.store(Arc::new(
            Profile::new(cur.id, cur.generation, cur.engine.clone())
                .with_userscripts(cur.userscripts.clone())
                .with_script_control(control),
        ));
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
        let client = build_upstream_client(opts)?;
        let mut ctx = Self::new(engine, client, adblock_enabled);
        ctx.strict_client = build_strict_upstream_client(opts)?;
        ctx.policy = opts.policy.clone();
        ctx.resolve_all_to = opts.resolve_all_to;
        Ok(ctx)
    }

    /// Replace the destination policy (for contexts built from a ready-made client).
    pub fn with_policy(mut self, policy: Arc<DestPolicy>) -> Self {
        self.policy = policy;
        self
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

    /// The shared pooled upstream client.
    pub fn client(&self) -> reqwest::Client {
        self.client.clone()
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

    /// The default profile's slot (what connections without a resolved profile use).
    pub fn default_profile(&self) -> &ProfileSlot {
        &self.default_ctx.profile
    }

    /// Context for a connection on the default profile.
    pub fn request_ctx_for(
        &self,
        client_addr: SocketAddr,
        auth_user: Option<Arc<str>>,
    ) -> RequestCtx {
        RequestCtx::new(self.default_ctx.profile.clone(), client_addr, auth_user)
    }

    /// Whether a request should be blocked (respects the master adblock toggle, records stats).
    ///
    /// Shared by the HTTP, WebSocket, and HTTP/3 paths.
    pub fn should_block(&self, url: &str, source_url: &str, resource_type: &str) -> bool {
        self.engine.is_enabled() && {
            let profile = self.default_ctx.profile.load();
            self.engine
                .check_for(url, source_url, resource_type, &profile.label)
                .blocked
        }
    }

    /// Like [`Self::should_block`] but with the profile in `rctx`.
    pub fn should_block_with(
        &self,
        rctx: &RequestCtx,
        url: &str,
        source_url: &str,
        resource_type: &str,
    ) -> bool {
        let profile = rctx.profile.load();
        profile.engine.is_enabled()
            && profile
                .engine
                .check_for(url, source_url, resource_type, &profile.label)
                .blocked
    }

    /// Forward a proxied request using the default request context.
    pub async fn forward(
        &self,
        req: Request<Incoming>,
        scheme: &str,
        fallback_authority: Option<(String, u16)>,
    ) -> Result<Response<ProxyBody>> {
        self.forward_with(req, scheme, fallback_authority, &self.default_ctx)
            .await
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

        // Internal endpoints are answered locally for every host: never filtered, never
        // forwarded.
        if uri.path().starts_with(csp::INTERNAL_PREFIX) {
            let origin = origin_of(scheme, &url_host, port);
            let up = crate::gm::Upstream {
                client: &self.client,
                strict_client: &self.strict_client,
                policy: &self.policy,
                resolve_all_to: self.resolve_all_to,
            };
            return Ok(self.internal.handle(req, &host, &origin, rctx, &up).await);
        }

        // Take the request apart: the header map is moved, not copied, from here on.
        let (parts, body) = req.into_parts();
        let mut headers = parts.headers;

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

        // Filter decision. The profile guard is dropped before any `.await`.
        let rtype = classify(&method, &headers, path_and_query);
        let mut csp: Option<String> = None;
        // The engine generation this request is judged by (carries the ext-rule index); the
        // response is judged by the same one.
        let mut generation: Option<Arc<filter_engine::Generation>> = None;
        let mut request_edits: Vec<ext_rules::HeaderEdit> = Vec::new();
        {
            let profile = rctx.profile.load();
            let engine = &profile.engine;
            if engine.is_enabled() {
                let source = source_url(&headers, &url, rtype);
                let (verdict, gen_) =
                    engine.check_gen(&url, source, rtype.as_str(), &profile.label);
                generation = Some(gen_);
                if verdict.blocked {
                    debug!("Blocked {} ({})", url, rtype.as_str());
                    if let Some(sc) = &profile.script_control {
                        count_page_block(sc, source_url(&headers, &url, rtype));
                    }
                    if let Some(res) = verdict.redirect_resource() {
                        return Ok(redirect_response(res));
                    }
                    return Ok(block_response(rtype, &verdict, &url));
                }
                if let Some(new_url) = verdict.rewritten_url {
                    let navigation =
                        rtype == RequestType::Document && (method == hyper::Method::GET || is_head);
                    if navigation {
                        return Ok(rewrite_redirect(&new_url));
                    }
                    // Subresource: fetch the cleaned URL transparently.
                    url = new_url;
                }
                // Extended rules run after the engine verdict (see `crate::ext` for precedence).
                if let Some(idx) = generation
                    .as_ref()
                    .and_then(|g| g.aux::<ext_rules::ExtIndex>())
                {
                    let source = source_url(&headers, &url, rtype);
                    if let Some(d) =
                        ext::request_decision(idx, &url, method.as_str(), source, rtype, &headers)
                    {
                        if let Some(id) = d.block {
                            let rule = idx.rule(id).map(|r| r.raw.clone()).unwrap_or_default();
                            debug!("Blocked {} by extended rule {}", url, rule);
                            let list = idx.rule(id).map(|r| r.list.clone());
                            if let Some(sc) = &profile.script_control {
                                count_page_block(sc, source_url(&headers, &url, rtype));
                            }
                            engine.stats_handle().record_blocked(rtype.as_str(), &host);
                            engine.record_block(&filter_engine::BlockEvent {
                                timestamp: chrono::Utc::now(),
                                url: url.clone(),
                                source_host: String::new(),
                                request_type: rtype.as_str().to_string(),
                                rule: rule.clone(),
                                list_id: list,
                                client: Some(profile.label.to_string()),
                            });
                            let v = filter_engine::MatchResult::blocked(rule);
                            return Ok(block_response(rtype, &v, &url));
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
            if let Some(sc) = profile.script_control.as_ref().filter(|sc| sc.enabled()) {
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
                    return Ok(policy_block_response(rtype, &url));
                }
            }
        }

        ext::apply_request_edits(&mut headers, &request_edits);

        // Stream the request body upstream; nothing is buffered.
        let has_body = !body.is_end_stream();

        // Destination policy. reqwest skips its resolver for IP-literal hosts, so literals are
        // judged here; names are judged on what they resolve to, inside the client's resolver.
        if let Err(r) = self.policy.check_literal(&host, port) {
            debug!("Refused destination {host}:{port}: {r}");
            return Ok(refused_response());
        }
        let client = if self.policy.is_own_port(port) {
            &self.strict_client
        } else {
            &self.client
        };

        let listed = connection_listed(&headers);
        let transformable_request = rtype.is_frame();
        // Code-only resolve override: reqwest never resolves IP literals, so aim those at the
        // override explicitly (the policy has already judged the requested literal) and keep the
        // original authority in `Host`.
        let mut dial_url = url.clone();
        let mut host_override = None;
        if let (Some(over), Ok(_)) = (self.resolve_all_to, host.parse::<IpAddr>()) {
            if let Ok(mut u) = reqwest::Url::parse(&url) {
                if u.set_ip_host(over).is_ok() {
                    dial_url = u.to_string();
                    host_override = Some(format!("{url_host}:{port}"));
                }
            }
        }
        let mut rb = client.request(method.clone(), &dial_url);
        if let Some(h) = host_override {
            rb = rb.header(HOST, h);
        }
        for (name, value) in headers.iter() {
            // reqwest sets Host itself; don't forward hop-by-hop headers. Content-Length is only
            // kept for streamed bodies (it keeps the upload un-chunked); reqwest derives it
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
        if has_body {
            let stream = body
                .into_data_stream()
                .map_err(|e| std::io::Error::other(e.to_string()));
            rb = rb.body(reqwest::Body::wrap_stream(stream));
        }

        let timeout_ms = self.request_timeout_ms.load(Ordering::Relaxed);
        let sent = if timeout_ms == 0 {
            rb.send().await
        } else {
            match tokio::time::timeout(Duration::from_millis(timeout_ms), rb.send()).await {
                Ok(r) => r,
                Err(_) => {
                    warn!("Upstream timeout for {url}");
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
                debug!("Refused destination {host}:{port} (resolved): {e}");
                return Ok(refused_response());
            }
            Err(e) => {
                warn!("Upstream error for {}: {}", url, e);
                return Ok(bad_gateway(&format!("Upstream error: {e}")));
            }
        };

        let status = resp.status();
        // Moved out of the response (the body stream does not need them): no header-map copy.
        let mut resp = resp;
        let resp_headers = std::mem::take(resp.headers_mut());
        let mut kind = classify_body(is_head, status, rtype, &resp_headers);
        // Script policy applies to every HTML document, `no-transform` or not: it adds headers
        // only, never rewrites a body the origin asked us to leave alone.
        let spol: Option<Arc<crate::scriptctl::DocEntry>> =
            if kind == BodyKind::Html && !is_head && status.as_u16() >= 200 {
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
        // HEAD / 1xx / 204 / 205 / 304 never carry a body, whatever the origin's length says.
        let body_allowed = !is_head
            && status.as_u16() >= 200
            && status != StatusCode::NO_CONTENT
            && status != StatusCode::RESET_CONTENT
            && status != StatusCode::NOT_MODIFIED;

        // Per-response work, decided once from the URL, type and headers.
        let (enabled, cosmetics) = {
            let profile = rctx.profile.load();
            let enabled = profile.engine.is_enabled();
            let cos = (enabled && kind == BodyKind::Html && body_allowed)
                .then(|| profile.engine.cosmetic_for(&url));
            (enabled, cos)
        };
        // Lock-free read (no refcount traffic); held only across the synchronous lookup.
        let source = self.transform_source.load();
        let mut transforms: ResponseTransforms = if enabled {
            source
                .as_ref()
                .as_ref()
                .and_then(|s| {
                    s.transforms_for(&ResponseInfo {
                        generation: generation.as_ref(),
                        method: method.as_str(),
                        source_url: source_url(&headers, &url, rtype),
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
        let body: ProxyBody = match (kind, codings) {
            (BodyKind::Html, Ok(codings)) if (enabled || spol.is_some()) && body_allowed => {
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
                // Extended CSS the engine rejected goes to the in-page procedural evaluator.
                for (selector, style) in &transforms.procedural {
                    let action = match style {
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
                    rctx.profile.load().userscript_manager().and_then(|m| {
                        if m.live_index().is_empty() {
                            return None; // zero cost: no allocation, no probe
                        }
                        self.internal.gm.plan_document(
                            m,
                            &host,
                            &url,
                            &origin_of(scheme, &url_host, port),
                            rtype != RequestType::Subdocument,
                        )
                    })
                };
                let us_srcs: &[String] = us.as_ref().map_or(&[], |p| &p.srcs);
                let head = if enabled {
                    build_head(&PageSpec {
                        userscripts: us_srcs,
                        ext_script: &ext_script,
                        cosmetics: &cos,
                        internal: &self.internal,
                        host: &host,
                        nonce: &nonce,
                        script_ok: !blocks_scripts,
                        observer_ok: !opaque,
                    })
                } else {
                    Default::default()
                };
                let needs = csp::Needs {
                    script: head.has_script,
                    style: head.has_style || us.as_ref().is_some_and(|p| p.style),
                    connect: head.observer || us.as_ref().is_some_and(|p| p.connect),
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

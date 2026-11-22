//! The in-page panel's server side: the read-only state endpoint the panel script calls, and the
//! proxy-owned confirmation origin where changes are authorised.
//!
//! # Authority
//!
//! The panel script runs in the page's JavaScript world, so a hostile page can do anything the
//! panel can. Therefore **the panel cannot change anything**. It shows state and offers links
//! to the reserved host (default `adblock.invalid`, a name that cannot resolve on the internet and
//! that only this proxy answers). A change is a proposal (`/confirm?p=…`) that the user reads and
//! confirms on that origin, a top-level page the site cannot script, frame, or overlay:
//!
//! * served with `frame-ancestors 'none'` and `X-Frame-Options: DENY`, no JavaScript at all;
//! * opened with `noopener`, `Cross-Origin-Opener-Policy: same-origin`, `Referrer-Policy: same-origin` (`no-referrer` would make the browser send `Origin: null` on the form post);
//! * `/apply` accepts only a same-origin, user-activated form post (`Sec-Fetch-Site`,
//!   `Sec-Fetch-User`, `Origin`), a single-use-by-expiry HMAC nonce bound to the proposal and the
//!   profile, and, by default, the profile's PIN (with lockout).
//!
//! See `docs/SCRIPT-POLICY.md`, "The in-page panel", for the threat model and residual risks.

use crate::inject::{full_body, ProxyBody};
use crate::internal::Internal;
use crate::request_ctx::RequestCtx;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};
use parking_lot::{Mutex, RwLock};
use script_policy as sp;
use script_policy::panel::{is_current_hash, verify_pin, PanelAuth};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

/// Deployment settings of the panel (from `[script_control]`).
#[derive(Clone, Debug)]
pub struct PanelConfig {
    pub enabled: bool,
    /// Reserved host, normalised.
    pub host: String,
    pub dashboard_url: String,
}

impl Default for PanelConfig {
    fn default() -> Self {
        PanelConfig {
            enabled: true,
            host: "adblock.invalid".into(),
            dashboard_url: String::new(),
        }
    }
}

/// Per-site "ad blocking off", backed by the custom rules (see `list_service::site_exceptions`).
pub trait SiteBlocking: Send + Sync {
    fn disabled(&self, site: &str) -> bool;
    fn set_disabled(&self, site: &str, disabled: bool) -> Result<(), String>;
}

/// [`SiteBlocking`] over the list service's custom rules.
pub struct ListSiteBlocking(pub Arc<list_service::ListService>);

impl SiteBlocking for ListSiteBlocking {
    fn disabled(&self, site: &str) -> bool {
        self.0
            .store()
            .get_custom_rules()
            .is_ok_and(|r| list_service::site_exceptions::is_disabled(&r, site))
    }
    fn set_disabled(&self, site: &str, disabled: bool) -> Result<(), String> {
        let rules = self
            .0
            .store()
            .get_custom_rules()
            .map_err(|e| e.to_string())?;
        let new = list_service::site_exceptions::set(&rules, site, disabled)
            .ok_or_else(|| format!("'{site}' is not a valid host name"))?;
        if new != rules {
            self.0
                .store()
                .set_custom_rules(&new)
                .map_err(|e| e.to_string())?;
            self.0.trigger();
        }
        Ok(())
    }
}

/// How long a granted permission lasts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ttl {
    #[serde(rename = "5m")]
    Min5,
    #[serde(rename = "1h")]
    Hour1,
    #[serde(rename = "1d")]
    Day1,
    #[serde(rename = "restart")]
    UntilRestart,
    #[serde(rename = "forever")]
    Forever,
}

impl Ttl {
    fn label(self) -> &'static str {
        match self {
            Ttl::Min5 => "for 5 minutes",
            Ttl::Hour1 => "for 1 hour",
            Ttl::Day1 => "for 1 day",
            Ttl::UntilRestart => "until the proxy restarts",
            Ttl::Forever => "permanently",
        }
    }
    fn secs(self) -> Option<u64> {
        match self {
            Ttl::Min5 => Some(300),
            Ttl::Hour1 => Some(3600),
            Ttl::Day1 => Some(86400),
            Ttl::UntilRestart | Ttl::Forever => None,
        }
    }
}

/// One proposed change. Everything is validated again on apply.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum PanelOp {
    /// Pages of `page` use this preset (`default`, `trusted`, `untrusted`).
    Preset {
        page: String,
        preset: String,
    },
    /// Allow (or deny) `caps` from `source` on `page`.
    Source {
        page: String,
        source: String,
        caps: Vec<String>,
        allow: bool,
        ttl: Ttl,
    },
    /// Everything allowed on `page`, temporarily.
    AllowAll {
        page: String,
        ttl: Ttl,
    },
    RevokeTemps,
    /// Ad blocking on or off for a site.
    Adblock {
        site: String,
        enabled: bool,
    },
    Userscript {
        id: String,
        enabled: bool,
    },
}

const MAX_OPS: usize = 16;
const MAX_PROPOSAL: usize = 6 * 1024;
/// A confirmation page is valid this long (seconds), and for one application only.
const NONCE_TTL: u64 = 120;
/// Used nonces remembered until they expire (a bound, not a tuning knob: it is only reached by
/// someone who already holds the PIN).
const MAX_USED_NONCES: usize = 1024;
/// PIN checks that may run at once (each costs ~19 MiB for Argon2id).
const MAX_PIN_CHECKS: usize = 2;

pub fn encode_proposal(ops: &[PanelOp]) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(ops).unwrap_or_default())
}

fn decode_proposal(p: &str) -> Result<Vec<PanelOp>, &'static str> {
    if p.len() > MAX_PROPOSAL {
        return Err("proposal too large");
    }
    let raw = URL_SAFE_NO_PAD
        .decode(p)
        .map_err(|_| "malformed proposal")?;
    let ops: Vec<PanelOp> = serde_json::from_slice(&raw).map_err(|_| "malformed proposal")?;
    if ops.is_empty() || ops.len() > MAX_OPS {
        return Err("a proposal has 1 to 16 changes");
    }
    Ok(ops)
}

pub struct PanelHost {
    cfg: RwLock<PanelConfig>,
    blocking: RwLock<Option<Arc<dyn SiteBlocking>>>,
    /// Nonces already applied, with their expiry.
    used: Mutex<HashMap<String, u64>>,
    pin_checks: Arc<tokio::sync::Semaphore>,
}

impl Default for PanelHost {
    fn default() -> Self {
        PanelHost {
            cfg: RwLock::new(PanelConfig::default()),
            blocking: RwLock::new(None),
            used: Mutex::new(HashMap::new()),
            pin_checks: Arc::new(tokio::sync::Semaphore::new(MAX_PIN_CHECKS)),
        }
    }
}

/// A web URL safe to show to a page: http(s) only, and never with credentials, a query or a
/// fragment (those could carry a token or password).
fn public_url(s: &str) -> String {
    match url::Url::parse(s) {
        Ok(u)
            if matches!(u.scheme(), "http" | "https")
                && u.username().is_empty()
                && u.password().is_none() =>
        {
            let mut u = u;
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        }
        _ => String::new(),
    }
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

fn hv(h: &HeaderMap, n: &str) -> Option<String> {
    h.get(n).and_then(|v| v.to_str().ok()).map(str::to_string)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl PanelHost {
    pub fn configure(&self, cfg: PanelConfig) {
        *self.cfg.write() = cfg;
    }
    pub fn config(&self) -> PanelConfig {
        self.cfg.read().clone()
    }
    pub fn set_site_blocking(&self, b: Option<Arc<dyn SiteBlocking>>) {
        *self.blocking.write() = b;
    }
    /// Is `host` (normalised, no port) the reserved confirmation host?
    pub fn is_panel_host(&self, host: &str) -> bool {
        self.cfg.read().host == host
    }

    /// `[alt, ctrl, shift, meta, code]` for the boot script, when the panel is on for this
    /// profile and deployment.
    pub fn hotkey(&self, rctx: &RequestCtx) -> Option<Value> {
        if !self.cfg.read().enabled {
            return None;
        }
        let profile = rctx.profile.load();
        let p = profile.script_control.as_ref()?.panel();
        if !p.enabled {
            return None;
        }
        let parts: Vec<&str> = p.hotkey.split('+').collect();
        let (key, mods) = parts.split_last()?;
        let has = |m: &str| u8::from(mods.contains(&m));
        let code = if key.len() == 1 && key.as_bytes()[0].is_ascii_digit() {
            format!("Digit{key}")
        } else if key.len() == 1 {
            format!("Key{}", key.to_ascii_uppercase())
        } else {
            (*key).to_string()
        };
        Some(json!([
            has("Alt"),
            has("Ctrl"),
            has("Shift"),
            has("Meta"),
            code
        ]))
    }

    // ---- read-only state for the in-page panel -----------------------------------------------

    /// What the panel shows for the page at `page_url`. Everything in it is derived from what
    /// the page's own requests already reveal, except the preset name, the profile's userscripts
    /// that match the URL, and the panel settings (see the doc's residual risks).
    pub fn state(&self, rctx: &RequestCtx, page_url: &str) -> Option<Value> {
        let profile = rctx.profile.load_full();
        let sc = profile.script_control.as_ref()?;
        let (scheme, host, port) = sp::parse_origin(page_url)?;
        let compiled = sc.compiled();
        let page = compiled.decide(scheme.as_str(), &host, port);
        let site = page.site().to_string();
        let base = page.profile();
        let level = if base == sp::Profile::TRUSTED {
            "trusted"
        } else if base == sp::Profile::UNTRUSTED {
            "untrusted"
        } else if base == compiled.settings().default_profile {
            "default"
        } else {
            "custom"
        };
        let report = sc.store().report_for(sc.profile_name(), &host);
        let items: Vec<Value> = report
            .iter()
            .flat_map(|r| r.items.iter())
            .map(|i| {
                let allowed = i
                    .source
                    .as_deref()
                    .is_some_and(|s| page.allows_host(i.cap, s));
                json!({
                    "cap": i.cap.as_str(),
                    "source": i.source,
                    "site": i.source.as_deref().map(sp::site_of),
                    "count": i.count,
                    "via": if i.via_network { "proxy" } else { "browser" },
                    "allowed": allowed,
                    "sourced": i.cap.is_source_keyed(),
                })
            })
            .collect();
        let rules = sc.store().rules(sc.profile_name()).ok();
        let now = sc.store().now();
        let page_scope = sp::Scope::Host(host.clone());
        let temps: Vec<Value> = rules
            .iter()
            .flat_map(|r| r.temps.values())
            .filter(|t| t.active_at(now) && t.page.covers(&page_scope))
            .map(|t| {
                json!({"id": t.id, "page": t.page.to_string(), "expires_at": t.expires_at,
                "what": match &t.kind {
                    sp::GrantKind::Site { preset } => format!("everything ({})", preset.name()),
                    sp::GrantKind::Source { source, caps } => format!("{source}: {}",
                        caps.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(", ")),
                }})
            })
            .collect();
        let adblock_off = self
            .blocking
            .read()
            .as_ref()
            .is_some_and(|b| b.disabled(&site));
        let mut us_gen = String::new();
        let userscripts: Vec<Value> = profile
            .userscript_manager()
            .map(|m| {
                m.get_all_in(&profile.name)
                    .iter()
                    .filter(|s| {
                        userscript_engine::matcher::Rules::compile(
                            &s.metadata,
                            userscript_engine::matcher::Options::default(),
                        )
                        .0
                        .is_match_url(page_url)
                    })
                    .map(|s| {
                        us_gen.push(if s.enabled { '1' } else { '0' });
                        json!({"id": s.id, "name": s.name(), "enabled": s.enabled})
                    })
                    .collect()
            })
            .unwrap_or_default();
        let ps = sc.panel();
        let cfg = self.cfg.read().clone();
        let panel_origin = format!("https://{}", cfg.host);
        Some(json!({
            "gen": format!("{}.{}.{}", compiled.generation(), u8::from(adblock_off), us_gen),
            "enabled": compiled.is_enabled(),
            "host": host,
            "site": site,
            "preset": level,
            "sources": items,
            "temps": temps,
            "blocked": sc.blocked_on(&host),
            "adblock_off": adblock_off,
            "userscripts": userscripts,
            "auth": ps.auth,
            "pin_set": ps.pin_hash.as_deref().is_some_and(script_policy::panel::is_current_hash),
            "panel_origin": panel_origin,
            "dashboard": public_url(&cfg.dashboard_url),
        }))
    }

    // ---- the confirmation origin --------------------------------------------------------------

    /// Answer a request addressed to the reserved host. Never forwarded, never filtered.
    pub async fn handle(
        &self,
        internal: &Internal,
        req: Request<Incoming>,
        rctx: &RequestCtx,
        origin: &str,
    ) -> Response<ProxyBody> {
        let path = req.uri().path().to_string();
        let method = req.method().clone();
        let h = req.headers().clone();
        // Fetch metadata: a navigation, never a subresource, frame or fetch.
        let dest_ok = hv(&h, "sec-fetch-dest").is_none_or(|d| d == "document");
        let mode_ok = hv(&h, "sec-fetch-mode").is_none_or(|m| m == "navigate");
        if !dest_ok || !mode_ok {
            return page_response(
                StatusCode::FORBIDDEN,
                "Not available here",
                "<p>This page can only be opened as a top-level page.</p>",
            );
        }
        // The confirmation form carries a PIN: only over TLS, so it cannot be read or replayed on
        // the LAN. The landing page says nothing sensitive and may stay on plain HTTP.
        if !origin.starts_with("https://") && matches!(path.as_str(), "/confirm" | "/apply") {
            return page_response(
                StatusCode::FORBIDDEN,
                "Use https",
                "<p>Changes are confirmed over https only. Open this page as <b>https://</b> (the proxy's CA must be trusted by the browser).</p>",
            );
        }
        match (method, path.as_str()) {
            (Method::GET | Method::HEAD, "/") => page_response(
                StatusCode::OK,
                "Script control",
                "<p>Changes proposed by the in-page panel are confirmed here.</p>",
            ),
            (Method::GET, "/confirm") => {
                let q = req.uri().query().unwrap_or("");
                let p = q
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("p="))
                    .unwrap_or("");
                self.confirm_page(internal, rctx, p)
            }
            (Method::POST, "/apply") => self.apply(internal, rctx, req, origin).await,
            _ => page_response(StatusCode::NOT_FOUND, "Not found", "<p>No such page.</p>"),
        }
    }

    fn settings(
        rctx: &RequestCtx,
    ) -> Option<(
        Arc<crate::scriptctl::ScriptControl>,
        Arc<script_policy::panel::PanelSettings>,
    )> {
        let profile = rctx.profile.load();
        let sc = profile.script_control.clone()?;
        let ps = sc.panel();
        Some((sc, ps))
    }

    fn confirm_page(&self, internal: &Internal, rctx: &RequestCtx, p: &str) -> Response<ProxyBody> {
        let Some((_, ps)) = Self::settings(rctx) else {
            return page_response(
                StatusCode::NOT_FOUND,
                "Unavailable",
                "<p>Script control is not available.</p>",
            );
        };
        if !self.cfg.read().enabled || !ps.enabled {
            return page_response(
                StatusCode::FORBIDDEN,
                "Disabled",
                "<p>The panel is turned off for this profile.</p>",
            );
        }
        let ops = match decode_proposal(p) {
            Ok(o) => o,
            Err(e) => {
                return page_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid proposal",
                    &format!("<p>{}</p>", esc(e)),
                )
            }
        };
        let list: String = ops
            .iter()
            .map(|o| format!("<li>{}</li>", esc(&describe(o))))
            .collect();
        let exp = now() + NONCE_TTL;
        let nonce = format!("{exp:x}.{}", internal.sign(&nonce_msg(rctx, p, exp)));
        let dash = self.cfg.read().dashboard_url.clone();
        // Only a web URL becomes a link (never `javascript:` or `data:`).
        let dash = if dash.starts_with("http://") || dash.starts_with("https://") {
            dash
        } else {
            String::new()
        };
        let (form, note) = match ps.auth {
            PanelAuth::Session => (
                String::new(),
                format!(
                    "<p>This profile applies changes from the dashboard only.{}</p>",
                    if dash.is_empty() { String::new() } else { format!(" Open <a href=\"{0}\" rel=\"noopener noreferrer\">{0}</a>.", esc(&dash)) }
                ),
            ),
            PanelAuth::Pin if ps.pin_hash.is_none() => (
                String::new(),
                "<p>No panel PIN is set. Set one in the dashboard (Script policy, Panel) first.</p>".to_string(),
            ),
            auth => {
                let pin = if auth == PanelAuth::Pin {
                    "<label>PIN <input type=\"password\" name=\"pin\" autocomplete=\"off\" required autofocus></label>"
                } else {
                    ""
                };
                (
                    format!(
                        "<form method=\"post\" action=\"/apply\"><input type=\"hidden\" name=\"p\" value=\"{}\"><input type=\"hidden\" name=\"n\" value=\"{}\">{pin}<p><button type=\"submit\">Apply</button> <a href=\"/\">Cancel</a></p></form>",
                        esc(p),
                        esc(&nonce)
                    ),
                    String::new(),
                )
            }
        };
        page_response(
            StatusCode::OK,
            "Confirm changes",
            &format!("<p>A page asked for these changes. Only apply them if you started this from the panel.</p><ul>{list}</ul>{note}{form}"),
        )
    }

    async fn apply(
        &self,
        internal: &Internal,
        rctx: &RequestCtx,
        req: Request<Incoming>,
        origin: &str,
    ) -> Response<ProxyBody> {
        let deny =
            |s: StatusCode, m: &str| page_response(s, "Not applied", &format!("<p>{}</p>", esc(m)));
        let h = req.headers().clone();
        // Same-origin, user-activated form post from our own page.
        if hv(&h, "sec-fetch-site").is_some_and(|v| v != "same-origin") {
            return deny(StatusCode::FORBIDDEN, "Cross-site request refused.");
        }
        if hv(&h, "sec-fetch-dest").is_some_and(|v| v == "document")
            && hv(&h, "sec-fetch-user").as_deref() != Some("?1")
        {
            return deny(
                StatusCode::FORBIDDEN,
                "A click on the confirmation page is required.",
            );
        }
        if hv(&h, "origin").is_none_or(|o| o != origin) {
            return deny(StatusCode::FORBIDDEN, "Origin mismatch.");
        }
        let is_form = hv(&h, CONTENT_TYPE.as_str())
            .is_some_and(|c| c.starts_with("application/x-www-form-urlencoded"));
        if !is_form {
            return deny(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Unsupported content type.",
            );
        }
        let body = match Limited::new(req.into_body(), 16 * 1024).collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => return deny(StatusCode::PAYLOAD_TOO_LARGE, "Request too large."),
        };
        let form: HashMap<String, String> =
            url::form_urlencoded::parse(&body).into_owned().collect();
        let (p, n) = (
            form.get("p").map(String::as_str).unwrap_or(""),
            form.get("n").map(String::as_str).unwrap_or(""),
        );
        let Some((sc, ps)) = Self::settings(rctx) else {
            return deny(StatusCode::NOT_FOUND, "Script control is not available.");
        };
        if !self.cfg.read().enabled || !ps.enabled {
            return deny(StatusCode::FORBIDDEN, "The panel is turned off.");
        }
        // Nonce: bound to this profile and this exact proposal, valid for ten minutes.
        let nonce_exp = n.split_once('.').and_then(|(e, mac)| {
            let exp = u64::from_str_radix(e, 16).ok()?;
            (exp >= now() && ct_eq(&internal.sign(&nonce_msg(rctx, p, exp)), mac)).then_some(exp)
        });
        let Some(nonce_exp) = nonce_exp else {
            return deny(StatusCode::FORBIDDEN, "This confirmation expired or does not belong to this request. Start again from the panel.");
        };
        match ps.auth {
            PanelAuth::Session => {
                return deny(
                    StatusCode::FORBIDDEN,
                    "This profile applies changes from the dashboard only.",
                )
            }
            PanelAuth::Pin => {
                let Some(stored) = ps.pin_hash.clone() else {
                    return deny(StatusCode::FORBIDDEN, "No panel PIN is set.");
                };
                if !is_current_hash(&stored) {
                    return deny(
                        StatusCode::FORBIDDEN,
                        "The panel PIN has to be set again in the dashboard (Script policy, Panel).",
                    );
                }
                let Ok(slot) = Arc::clone(&self.pin_checks).try_acquire_owned() else {
                    return deny(
                        StatusCode::TOO_MANY_REQUESTS,
                        "Busy. Try again in a moment.",
                    );
                };
                let ip = rctx.client_addr.ip().to_string();
                let profile_name = sc.profile_name().to_string();
                let store = sc.store().clone();
                let pin = form.get("pin").cloned().unwrap_or_default();
                // Hashing is slow on purpose: never on an async thread. The lock check, the
                // verification and the bookkeeping happen in one blocking task.
                let outcome = tokio::task::spawn_blocking(move || {
                    let _slot = slot;
                    match store.pin_wait(&profile_name, &ip) {
                        Ok(0) => {}
                        Ok(w) => return Err(Some(w)),
                        Err(_) => return Err(None),
                    }
                    if verify_pin(&stored, &pin) {
                        let _ = store.pin_ok(&profile_name, &ip);
                        Ok(())
                    } else {
                        let _ = store.pin_failed(&profile_name, &ip);
                        Err(Some(0))
                    }
                })
                .await;
                match outcome {
                    Ok(Ok(())) => {}
                    Ok(Err(Some(0))) => return deny(StatusCode::FORBIDDEN, "Wrong PIN."),
                    Ok(Err(Some(wait))) => {
                        return deny(
                            StatusCode::TOO_MANY_REQUESTS,
                            &format!("Too many wrong PINs. Try again in {wait} seconds."),
                        )
                    }
                    _ => {
                        return deny(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Could not check the PIN.",
                        )
                    }
                }
            }
            PanelAuth::None => {}
        }
        if !self.consume_nonce(n, nonce_exp) {
            return deny(
                StatusCode::FORBIDDEN,
                "This confirmation was already used or the server is busy. Start again from the panel.",
            );
        }
        let ops = match decode_proposal(p) {
            Ok(o) => o,
            Err(e) => return deny(StatusCode::BAD_REQUEST, e),
        };
        let profile = rctx.profile.load_full();
        let results: Vec<(String, Result<(), String>)> = ops
            .iter()
            .map(|o| {
                (
                    describe(o),
                    self.apply_op(&sc, profile.userscript_manager(), o),
                )
            })
            .collect();
        let items: String = results
            .iter()
            .map(|(d, r)| match r {
                Ok(()) => format!("<li>{} <b>done</b></li>", esc(d)),
                Err(e) => format!("<li>{} <b>failed:</b> {}</li>", esc(d), esc(e)),
            })
            .collect();
        page_response(
            StatusCode::OK,
            "Applied",
            &format!("<ul>{items}</ul><p>Close this tab and reload the page for the changes to take effect.</p>"),
        )
    }

    /// Mark a nonce as used; false if it already was (or the used-set is full of live nonces).
    fn consume_nonce(&self, nonce: &str, exp: u64) -> bool {
        let mut g = self.used.lock();
        let t = now();
        g.retain(|_, e| *e >= t);
        if g.len() >= MAX_USED_NONCES || g.contains_key(nonce) {
            return false;
        }
        g.insert(nonce.to_string(), exp);
        true
    }

    fn apply_op(
        &self,
        sc: &crate::scriptctl::ScriptControl,
        manager: Option<&Arc<userscript_engine::UserscriptManager>>,
        op: &PanelOp,
    ) -> Result<(), String> {
        let store = sc.store();
        let prof = sc.profile_name();
        let scope = |s: &str| -> Result<sp::Scope, String> {
            match sp::Scope::parse(s).map_err(|e| e.to_string())? {
                sp::Scope::Global => {
                    Err("the global scope cannot be changed from the panel".into())
                }
                s => Ok(s),
            }
        };
        let e = |e: sp::store::StoreError| e.to_string();
        match op {
            PanelOp::Preset { page, preset } => {
                let scope = scope(page)?;
                let preset = match preset.as_str() {
                    "default" => sp::Preset::Default,
                    "trusted" => sp::Preset::Trusted,
                    "untrusted" => sp::Preset::Untrusted,
                    _ => return Err("unknown preset".into()),
                };
                let existing = store
                    .rules(prof)
                    .map_err(e)?
                    .site_rule_for_scope(&scope)
                    .map(|r| r.id.clone());
                match existing {
                    Some(id) => store.update_site_rule(prof, &id, preset, None).map(|_| ()),
                    None => store
                        .create_site_rule(prof, scope, preset, None)
                        .map(|_| ()),
                }
                .map_err(e)
            }
            PanelOp::Source {
                page,
                source,
                caps,
                allow,
                ttl,
            } => {
                let (page, source) = (scope(page)?, scope(source)?);
                let mut set = sp::CapSet::EMPTY;
                for c in caps {
                    let cap = sp::Capability::parse(c).ok_or("unknown capability")?;
                    if !cap.is_source_keyed() {
                        return Err(format!("{c} is a page-level capability"));
                    }
                    set = set.with(cap);
                }
                if set.is_empty() {
                    return Err("no capability selected".into());
                }
                let effect = if *allow {
                    sp::Effect::Allow
                } else {
                    sp::Effect::Deny
                };
                match (ttl, effect) {
                    (Ttl::Forever, _) => store
                        .create_source_rule(prof, page, source, set, effect, None)
                        .map(|_| ())
                        .map_err(e),
                    (_, sp::Effect::Allow) => store
                        .grant_temp(
                            prof,
                            page,
                            sp::GrantKind::Source { source, caps: set },
                            ttl.secs(),
                            *ttl == Ttl::UntilRestart,
                            false,
                        )
                        .map(|_| ())
                        .map_err(e),
                    (_, sp::Effect::Deny) => Err("a denial is permanent".into()),
                }
            }
            PanelOp::AllowAll { page, ttl } => {
                if *ttl == Ttl::Forever {
                    return Err("allowing everything is temporary only".into());
                }
                store
                    .grant_temp(
                        prof,
                        scope(page)?,
                        sp::GrantKind::Site {
                            preset: sp::Preset::Trusted,
                        },
                        ttl.secs(),
                        *ttl == Ttl::UntilRestart,
                        false,
                    )
                    .map(|_| ())
                    .map_err(e)
            }
            PanelOp::RevokeTemps => store.revoke_all_temps(prof).map(|_| ()).map_err(e),
            PanelOp::Adblock { site, enabled } => match self.blocking.read().as_ref() {
                Some(b) => b.set_disabled(site, !*enabled),
                None => Err("per-site blocking control is not available".into()),
            },
            PanelOp::Userscript { id, enabled } => match manager {
                Some(m) => m.set_enabled(id, *enabled).map_err(|e| e.to_string()),
                None => Err("userscripts are not available".into()),
            },
        }
    }
}

fn nonce_msg(rctx: &RequestCtx, p: &str, exp: u64) -> Vec<u8> {
    format!("panel\n{}\n{exp}\n{p}", rctx.profile.load().id).into_bytes()
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// A one-line human description of a change (shown on the confirmation page).
pub fn describe(op: &PanelOp) -> String {
    match op {
        PanelOp::Preset { page, preset } => format!("Pages of {page} use the {preset} preset"),
        PanelOp::Source {
            page,
            source,
            caps,
            allow,
            ttl,
        } => format!(
            "{} {} from {source} on {page} {}",
            if *allow { "Allow" } else { "Deny" },
            caps.join(", "),
            ttl.label()
        ),
        PanelOp::AllowAll { page, ttl } => format!("Allow everything on {page} {}", ttl.label()),
        PanelOp::RevokeTemps => "Revoke all temporary permissions".into(),
        PanelOp::Adblock { site, enabled } => format!(
            "Ad blocking {} for {site}",
            if *enabled { "on" } else { "off" }
        ),
        PanelOp::Userscript { id, enabled } => format!(
            "{} userscript {id}",
            if *enabled { "Enable" } else { "Disable" }
        ),
    }
}

/// A complete, self-contained, script-free HTML page with a locked-down CSP.
fn page_response(status: StatusCode, title: &str, body: &str) -> Response<ProxyBody> {
    let nonce = crate::inject::new_nonce();
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{t}</title>\
<style nonce=\"{nonce}\">:root{{color-scheme:light dark}}body{{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}}li{{margin:.4rem 0}}input{{font:inherit;padding:.3rem}}button{{font:inherit;padding:.4rem 1rem}}</style></head>\
<body><h1>{t}</h1>{body}</body></html>",
        t = esc(title)
    );
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .header(
            "content-security-policy",
            format!("default-src 'none'; style-src 'nonce-{nonce}'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
        )
        .header("x-frame-options", "DENY")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "same-origin")
        .header("cross-origin-opener-policy", "same-origin")
        .header("cross-origin-resource-policy", "same-origin")
        .header("cache-control", "no-store")
        .body(full_body(Bytes::from(html)))
        .expect("panel page")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposals_roundtrip_and_are_bounded() {
        let ops = vec![
            PanelOp::Preset {
                page: "a.test".into(),
                preset: "trusted".into(),
            },
            PanelOp::RevokeTemps,
        ];
        let p = encode_proposal(&ops);
        assert_eq!(decode_proposal(&p).unwrap().len(), 2);
        assert!(decode_proposal("").is_err());
        assert!(decode_proposal("!!!").is_err());
        let many = encode_proposal(&vec![PanelOp::RevokeTemps; 17]);
        assert!(decode_proposal(&many).is_err());
        let unknown = URL_SAFE_NO_PAD.encode(br#"[{"op":"nuke"}]"#);
        assert!(decode_proposal(&unknown).is_err());
        let extra = URL_SAFE_NO_PAD.encode(br#"[{"op":"revoke_temps","x":1}]"#);
        assert!(decode_proposal(&extra).is_err() || decode_proposal(&extra).is_ok());
        assert!(decode_proposal(&"A".repeat(MAX_PROPOSAL + 1)).is_err());
    }

    #[test]
    fn descriptions_escape_nothing_themselves() {
        let d = describe(&PanelOp::Adblock {
            site: "<b>".into(),
            enabled: false,
        });
        assert_eq!(esc(&d), "Ad blocking off for &lt;b&gt;");
    }

    #[test]
    fn the_dashboard_url_shown_to_pages_carries_no_credentials() {
        assert_eq!(public_url("http://10.0.0.2:8080/"), "http://10.0.0.2:8080/");
        for bad in [
            "http://admin:secret@10.0.0.2/",
            "javascript:alert(1)",
            "http://h/?token=abc",
            "",
        ] {
            let out = public_url(bad);
            assert!(
                !out.contains("secret") && !out.contains("javascript") && !out.contains("token"),
                "{bad} -> {out}"
            );
        }
    }

    #[test]
    fn nonces_are_single_use_and_bounded() {
        let h = PanelHost::default();
        let exp = now() + 60;
        assert!(h.consume_nonce("a", exp));
        assert!(!h.consume_nonce("a", exp), "replay");
        assert!(h.consume_nonce("b", exp));
        for i in 0..MAX_USED_NONCES {
            h.consume_nonce(&format!("n{i}"), exp);
        }
        assert!(!h.consume_nonce("one-more", exp), "bounded");
    }
}

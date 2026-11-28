//! The hub of the browser-extension bridge (protocol: `docs/USERSCRIPT-PROTOCOL.md` section 8).
//!
//! * **Sessions.** The extension opens a WebSocket on the web API; the hub registers it under a
//!   fresh random `sid` (new on every connection). The extension sends its browser through the
//!   proxy's extension-only listener, which answers `407` until the browser authenticates with
//!   `ext:<sid>`; the connection (and every document decrypted on it) is then bound to the session
//!   with that `sid`. Nothing about a client address, and no request header, is used.
//! * **Menus.** Each such document gets a random public `mdoc`. Its scripts sync their menu
//!   commands to the hub; the popup lists and triggers them through the web API, which only
//!   serves a document bound to the caller's own session. A trigger reaches the page through the
//!   runtime's long poll, so page JavaScript can neither list nor trigger anything.
//! * **Relay.** Non-anonymous `GM_xmlhttpRequest` / `GM_cookie` of a script approved for browser
//!   logins are dispatched as jobs to the session bound to the document, and nowhere else.
//!   Authority is decided by the proxy from the stored script before dispatch; the extension can
//!   only narrow it.

use api_types::{
    ExtAuditEvent, ExtError, ExtGrant, ExtIdent, ExtMenuCommand, ExtMenuResponse, ExtOut,
    ExtTriggerRequest,
};
use bytes::Bytes;
use parking_lot::Mutex;
use rand::RngCore;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify};
use userscript_engine::backend::{ErrorCode, GmError, GmResult};
use userscript_engine::{SecurityAuditor, UserscriptManager};

/// Realm of the extension listener's `407`; the credentials are `ext:<sid>`.
pub const EXT_REALM: &str = "argus-ext";
/// Header the extension's relay fetches carry (the job's relay token); always stripped.
pub const RELAY_HEADER: &str = "x-argus-relay";

/// Concurrent sessions per bridge token (the oldest is closed beyond it).
pub const MAX_SESSIONS_PER_TOKEN: usize = 8;
/// How long a session whose channel dropped stays valid for the extension listener (and
/// resumable by its token) before it is closed.
pub const RESUME_GRACE: Duration = Duration::from_secs(120);
/// Session changes are written to disk this long after the first one.
const PERSIST_DEBOUNCE_MS: u64 = 1000;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
/// Concurrent jobs per session.
pub const MAX_JOBS_PER_SESSION: usize = 32;
/// Documents with a menu record per session (that session's oldest is evicted first).
pub const MENU_DOCS_PER_SESSION: usize = 256;
/// A menu record is dropped after this long without use.
pub const MENU_TTL: Duration = Duration::from_secs(6 * 3600);
/// Long-poll length of `menu/wait`.
pub const WAIT: Duration = Duration::from_secs(25);
/// Commands one script may sync, and the length of their texts.
pub const MAX_CMDS: usize = 64;
const MAX_TEXT: usize = 200;
/// A queued trigger is dropped when the page does not pick it up within this long.
const FIRE_TTL: Duration = Duration::from_secs(10);
/// How long a fallback to the jar keeps the warning on the script's page.
const FALLBACK_TTL: Duration = Duration::from_secs(3600);
/// Queued answers per job before a slow page fails the job.
pub const JOB_QUEUE: usize = 32;
/// A live channel re-verifies its token every this many pings.
pub const REVERIFY_PINGS: u32 = 3;

// frame types (see USERSCRIPT-PROTOCOL.md 5.1 and 8)
pub const F_JOB: u8 = 0;
pub const F_HEAD: u8 = 1;
pub const F_DATA: u8 = 2;
pub const F_END: u8 = 3;
pub const F_ERROR: u8 = 4;
pub const F_CANCEL: u8 = 5;

/// `u8 type | u32 job | payload`.
pub fn job_frame(t: u8, job: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + payload.len());
    v.push(t);
    v.extend_from_slice(&job.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Inverse of [`job_frame`].
pub fn parse_job_frame(b: &[u8]) -> Option<(u8, u32, &[u8])> {
    if b.len() < 5 {
        return None;
    }
    Some((b[0], u32::from_be_bytes([b[1], b[2], b[3], b[4]]), &b[5..]))
}

/// What the extension answered for a job.
#[derive(Debug)]
pub enum JobEvent {
    Head(Vec<u8>),
    Data(Bytes),
    End,
    Error(Vec<u8>),
}

fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hash_sid(sid: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(sid.as_bytes()).into()
}

fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Constant-time equality of two strings (length is not secret here).
fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

// ---- granted host permissions --------------------------------------------------------------

/// Host permissions the extension reported (`permissions.getAll().origins`).
///
/// Relay authority comes only from patterns naming a host (`*://host/*`, `*://*.host/*`), the
/// shape of the popup's per-host grant. `<all_urls>`, `*://*/*`, public-suffix patterns and
/// patterns with a port or path never count: a broad permission held for other reasons must
/// not make every request of a script go through the browser.
#[derive(Debug, Default, Clone)]
pub struct Perms {
    exact: HashSet<String>,
    suffix: HashSet<String>,
}

fn is_public_suffix(host: &str) -> bool {
    psl::suffix(host.as_bytes()).is_some_and(|s| s.as_bytes() == host.as_bytes())
}

impl Perms {
    pub fn from_origins(origins: &[String]) -> Self {
        let mut p = Perms::default();
        for o in origins {
            let Some((scheme, rest)) = o.split_once("://") else {
                continue;
            };
            // Only patterns that cover https (the schemes a relay needs).
            if scheme != "*" && scheme != "https" {
                continue;
            }
            let Some((host, path)) = rest.split_once('/') else {
                continue;
            };
            if path != "*" || host.is_empty() || host.contains(':') {
                continue;
            }
            let host = host.to_ascii_lowercase();
            if let Some(d) = host.strip_prefix("*.") {
                if !d.is_empty() && !d.contains('*') && !is_public_suffix(d) {
                    p.suffix.insert(d.to_string());
                }
            } else if !host.contains('*') && !is_public_suffix(&host) {
                p.exact.insert(host);
            }
        }
        p
    }

    /// Does the extension hold a per-host permission covering `host`?
    pub fn has(&self, host: &str) -> bool {
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        if self.exact.contains(&host) {
            return true;
        }
        self.suffix_covers(&host)
    }

    fn suffix_covers(&self, bare: &str) -> bool {
        let mut rest = bare;
        loop {
            if self.suffix.contains(rest) {
                return true;
            }
            match rest.find('.') {
                Some(i) => rest = &rest[i + 1..],
                None => return false,
            }
        }
    }
}

// ---- host list ------------------------------------------------------------------------------

/// Whether a host is known to be tunnelled or decrypted by the Extended Validation setting.
#[async_trait::async_trait]
pub trait EvGate: Send + Sync {
    /// True only when `host:port` was probed and is not Extended Validation.
    async fn is_not_ev(&self, host: &str, port: u16) -> bool;
}

/// The proxy's own EV probe, held weakly (the proxy owns the hub).
pub struct ProxyEvGate(pub Weak<crate::filtering::ProxyContext>);

#[async_trait::async_trait]
impl EvGate for ProxyEvGate {
    async fn is_not_ev(&self, host: &str, port: u16) -> bool {
        let Some(ctx) = self.0.upgrade() else {
            return false;
        };
        matches!(
            ctx.ev_verdict(host, port, Duration::from_secs(5)).await,
            crate::ev::EvVerdict::NotEv
        )
    }
}

/// Loopback, private, link-local and unspecified targets (and `localhost` names).
pub fn is_local_target(host: &str) -> bool {
    let h = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".local")
        || h.ends_with(".internal")
    {
        return true;
    }
    match h.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => {
            let o = a.octets();
            a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        Ok(std::net::IpAddr::V6(a)) => {
            let seg = a.segments();
            a.is_loopback()
                || a.is_unspecified()
                || (seg[0] & 0xfe00) == 0xfc00
                || (seg[0] & 0xffc0) == 0xfe80
                || a.to_ipv4_mapped()
                    .is_some_and(|v| is_local_target(&v.to_string()))
        }
        Err(_) => false,
    }
}

// ---- state ----------------------------------------------------------------------------------

struct Session {
    /// SHA-256 of the session secret: the raw `sid` is never kept (nor written to disk).
    sid_hash: [u8; 32],
    /// The token's profile restriction as given (kept to persist and rebuild the session).
    ident_profiles: Option<Vec<String>>,
    token_id: String,
    user: String,
    /// Namespaces the session's token may serve (`None`: all).
    profiles: Option<Vec<String>>,
    /// Profile id the session's proxy connections are pinned to (token restricted to profiles).
    pinned: Option<u64>,
    tx: mpsc::Sender<ExtOut>,
    perms: Perms,
    jobs: HashMap<u32, (mpsc::Sender<JobEvent>, Arc<AtomicBool>)>,
    next_job: u32,
    opened: Instant,
    /// Documents registered for this session (bounded by [`MENU_DOCS_PER_SESSION`]).
    ndocs: usize,
    /// Pings received (the channel re-verifies its token every [`REVERIFY_PINGS`]).
    pings: u32,
    /// Set while the channel is down: the session lives (for proxy auth and resume) until then.
    grace_until: Option<Instant>,
    /// Popups the extension reported (`webNavigation.onCreatedNavigationTarget`): target URL,
    /// opener tab URL and when. Bounded by [`MAX_POPUPS`], valid for [`POPUP_TTL`].
    popups: VecDeque<(String, String, Instant)>,
}

/// Reported popups kept per session.
const MAX_POPUPS: usize = 32;
/// How long a reported popup waits for its navigation request.
const POPUP_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
struct MenuCmd {
    id: String,
    name: String,
    access_key: String,
    title: String,
    auto_close: bool,
}

#[derive(Default)]
struct ScriptMenu {
    cmds: Vec<MenuCmd>,
    queue: VecDeque<(String, Instant)>,
    wake: Arc<Notify>,
    gen: u64,
    parked: usize,
    last_wait: Option<Instant>,
}

struct MenuDoc {
    /// Cookie store the document was served to (empty: default). Menus and jobs of a document
    /// are only reachable from that store.
    store: String,
    profile: String,
    origin: String,
    scripts: Vec<(String, String)>,
    session: u64,
    menus: HashMap<String, ScriptMenu>,
    touched: Instant,
}

struct RelayInfo {
    session: u64,
    /// The cookie store token of the job's document (empty: default), for audit.
    store: String,
    profile: String,
    script: String,
    page_host: String,
}

#[derive(Default)]
struct Inner {
    sessions: HashMap<u64, Session>,
    docs: HashMap<String, MenuDoc>,
    doc_order: VecDeque<String>,
    relays: HashMap<String, RelayInfo>,
    fallback: HashMap<(String, String), (Instant, bool)>,
}

/// What the hub needs to know about the proxy to compute host lists and grants.
pub struct HubCtx {
    pub manager: Arc<UserscriptManager>,
    pub profiles: Option<Arc<common::profile_store::ProfileStore>>,
    pub bypass: Arc<common::bypass::BypassEngine>,
}

/// Does `host:port` resolve, right now, to where Argus's own web API listens?
#[async_trait::async_trait]
pub trait OwnResolve: Send + Sync {
    async fn resolves_to_own(&self, host: &str, port: u16) -> bool;
}

/// Is `host:port` Argus itself?
pub type OwnGuard = Arc<dyn Fn(&str, u16) -> bool + Send + Sync>;

/// Where a credentialed request goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Dispatch to this session.
    Ext(u64),
    /// Use the script's own cookie jar.
    Jar(Fallback),
}

/// Why a request did not go through the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fallback {
    /// An anonymous request (or a download) never uses browser logins.
    Anonymous,
    /// The script is not approved for browser logins.
    NotApproved,
    /// The request named no document, or an unknown or foreign one.
    NoDocument,
    /// The bound session is gone.
    Dead,
    /// Argus does not decrypt the target (bypass entry, or the bypass fail-safe is holding
    /// decryption back): the relay's per-hop check could not run.
    Bypassed,
    /// A loopback, private or link-local target.
    LocalTarget,
    /// Argus's own console, panel or dashboard host.
    OwnHost,
    /// `redirect: "manual"`: a browser fetch cannot expose the redirect response.
    ManualRedirect,
    /// The extension holds no host permission for the target.
    NoPermission,
}

/// Outcome of a `menu/wait`.
#[derive(Debug, PartialEq, Eq)]
pub enum Wait {
    /// Commands to run (empty after the poll length, or when superseded by a newer poll).
    Fire(Vec<String>),
    /// The document is not (or no longer) served by a live extension session.
    NoExt,
}

pub struct ExtHub {
    me: Weak<ExtHub>,
    inner: Mutex<Inner>,
    next: AtomicU64,
    ctx: OnceLock<HubCtx>,
    audit: OnceLock<Arc<dyn Fn(ExtAuditEvent) + Send + Sync>>,
    auditor: OnceLock<Arc<SecurityAuditor>>,
    /// Where the extension's proxy listener is (host if specific, port; 0 = off).
    proxy: Mutex<(Option<String>, u16)>,
    persist: OnceLock<std::path::PathBuf>,
    write_pending: AtomicBool,
    ev_gate: OnceLock<Arc<dyn EvGate>>,
    /// Is the extension listener decrypting right now (global MITM on and the listener's own
    /// switch on)? Mirrors `ConnectionHandler::intercepts`.
    mitm_probe: OnceLock<Arc<dyn Fn() -> bool + Send + Sync>>,
    /// Hosts that are Argus itself (the console, the panel): never relayed to.
    own_guard: OnceLock<OwnGuard>,
    own_resolve: OnceLock<Arc<dyn OwnResolve>>,
}

impl Default for ExtHub {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtHub {
    pub fn new() -> Self {
        Self::with_me(Weak::new())
    }

    fn with_me(me: Weak<ExtHub>) -> Self {
        Self {
            me,
            inner: Mutex::new(Inner::default()),
            next: AtomicU64::new(1),
            ctx: OnceLock::new(),
            audit: OnceLock::new(),
            auditor: OnceLock::new(),
            proxy: Mutex::new((None, 0)),
            persist: OnceLock::new(),
            write_pending: AtomicBool::new(false),
            ev_gate: OnceLock::new(),
            mitm_probe: OnceLock::new(),
            own_guard: OnceLock::new(),
            own_resolve: OnceLock::new(),
        }
    }

    /// A hub that can hand out its own `Arc` (needed to push the host list on connect).
    pub fn shared() -> Arc<Self> {
        Arc::new_cyclic(|w| Self::with_me(w.clone()))
    }

    /// This hub's `Arc`, when it was built with [`Self::shared`].
    pub fn arc(&self) -> Option<Arc<Self>> {
        self.me.upgrade()
    }

    pub fn set_mitm_probe(&self, f: Arc<dyn Fn() -> bool + Send + Sync>) {
        let _ = self.mitm_probe.set(f);
    }

    pub fn set_own_guard(&self, f: OwnGuard) {
        let _ = self.own_guard.set(f);
    }

    pub fn set_own_resolver(&self, r: Arc<dyn OwnResolve>) {
        let _ = self.own_resolve.set(r);
    }

    /// Is `host:port` Argus itself by name (the sync guard) or because the name resolves, at this
    /// moment, to the web API's bind address? The caller refuses a relay to it.
    pub async fn is_own_target(&self, host: &str, port: u16) -> bool {
        if self.is_own(host, port) {
            return true;
        }
        match self.own_resolve.get() {
            Some(r) => r.resolves_to_own(host.trim_matches(['[', ']']), port).await,
            None => false,
        }
    }

    /// Will the extension listener decrypt right now? No probe means no.
    fn decrypting(&self) -> bool {
        self.mitm_probe.get().is_some_and(|f| f())
    }

    fn is_own(&self, host: &str, port: u16) -> bool {
        self.own_guard.get().is_some_and(|f| f(host, port))
    }

    /// The session and store token a document was served to.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn doc_binding(&self, mdoc: Option<&str>) -> Option<(u64, String)> {
        let g = self.inner.lock();
        mdoc.and_then(|m| g.docs.get(m))
            .map(|d| (d.session, d.store.clone()))
    }

    pub fn set_ev_gate(&self, g: Arc<dyn EvGate>) {
        let _ = self.ev_gate.set(g);
    }

    /// Will Argus decrypt `host:port` right now as far as the Extended Validation setting goes?
    /// (Bypass entries and the fail-safe are checked by `route` / `check_relay`.) With the setting
    /// on, EV and EV-unknown hosts are tunnelled; without a probe the answer is no.
    pub async fn ev_allows(&self, host: &str, port: u16) -> bool {
        let Some(ctx) = self.ctx.get() else {
            return false;
        };
        if !ctx.bypass.ev_no_decrypt() {
            return true;
        }
        match self.ev_gate.get() {
            Some(g) => g.is_not_ev(host.trim_matches(['[', ']']), port).await,
            None => false,
        }
    }

    /// The full check of one hop a relay response asks the browser to follow, made before the
    /// browser can follow it: [`Self::check_relay`] plus the Extended Validation setting.
    pub async fn check_hop(
        &self,
        relay: &str,
        url: &url::Url,
        conn_session: Option<u64>,
        conn_store: &str,
    ) -> bool {
        self.check_relay(relay, url, conn_session, conn_store)
            && !self
                .is_own_target(
                    url.host_str().unwrap_or_default(),
                    url.port_or_known_default().unwrap_or(443),
                )
                .await
            && self
                .ev_allows(
                    url.host_str().unwrap_or_default(),
                    url.port_or_known_default().unwrap_or(443),
                )
                .await
    }

    pub fn set_ctx(&self, ctx: HubCtx) {
        let _ = self.ctx.set(ctx);
    }

    pub fn set_audit_sink(&self, f: Arc<dyn Fn(ExtAuditEvent) + Send + Sync>) {
        let _ = self.audit.set(f);
    }

    pub fn set_auditor(&self, a: Arc<SecurityAuditor>) {
        let _ = self.auditor.set(a);
    }

    fn audit(&self, actor: &str, action: &str, target: Option<String>) {
        if let Some(f) = self.audit.get() {
            f(ExtAuditEvent {
                actor: actor.to_string(),
                action: action.to_string(),
                target,
            });
        }
    }

    // ---- sessions -----------------------------------------------------------------------

    /// Register a session; returns `(id, sid, frames to send)`. Closes the token's oldest
    /// session beyond [`MAX_SESSIONS_PER_TOKEN`].
    pub fn open(&self, ident: ExtIdent) -> (u64, String, mpsc::Receiver<ExtOut>) {
        self.reap();
        let (tx, rx) = mpsc::channel(256);
        let sid = rand_hex(16);
        let mut g = self.inner.lock();
        let mine: Vec<(u64, Instant)> = g
            .sessions
            .iter()
            .filter(|(_, s)| s.token_id == ident.token_id)
            .map(|(i, s)| (*i, s.opened))
            .collect();
        if mine.len() >= MAX_SESSIONS_PER_TOKEN {
            if let Some((old, _)) = mine.iter().min_by_key(|(_, t)| *t) {
                if let Some(s) = g.sessions.get(old) {
                    let _ = s.tx.try_send(ExtOut::Close(4409));
                }
            }
        }
        let id = self.insert_session(&mut g, ident, hash_sid(&sid), tx, None);
        drop(g);
        self.mark_dirty();
        (id, sid, rx)
    }

    fn insert_session(
        &self,
        g: &mut Inner,
        ident: ExtIdent,
        sid_hash: [u8; 32],
        tx: mpsc::Sender<ExtOut>,
        grace_until: Option<Instant>,
    ) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let pinned = ident
            .profiles
            .as_ref()
            .and_then(|v| v.first())
            .and_then(|p| p.parse::<u64>().ok());
        let profiles = ident.profiles.clone().map(|v| {
            v.iter()
                .filter_map(|p| p.parse::<u64>().ok())
                .map(common::profile_store::namespace)
                .collect::<Vec<_>>()
        });
        g.sessions.insert(
            id,
            Session {
                sid_hash,
                ident_profiles: ident.profiles,
                token_id: ident.token_id,
                user: ident.user,
                profiles,
                pinned,
                tx,
                perms: Perms::default(),
                jobs: HashMap::new(),
                next_job: 1,
                opened: Instant::now(),
                ndocs: 0,
                pings: 0,
                grace_until,
                popups: VecDeque::new(),
            },
        );
        id
    }

    // ---- persistence across a restart -----------------------------------------------------

    /// Where the sessions (hashes only) are kept so a restarted Argus accepts the browser's
    /// sessions again.
    pub fn set_persist_path(&self, p: std::path::PathBuf) {
        let _ = self.persist.set(p);
    }

    fn mark_dirty(&self) {
        if self.persist.get().is_none() || self.write_pending.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(me) = self.me.upgrade() else {
            self.write_pending.store(false, Ordering::Release);
            return;
        };
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            self.write_pending.store(false, Ordering::Release);
            return;
        };
        rt.spawn(async move {
            tokio::time::sleep(Duration::from_millis(PERSIST_DEBOUNCE_MS)).await;
            me.write_pending.store(false, Ordering::Release);
            me.persist_now();
        });
    }

    /// Write the live and grace sessions now (atomically, mode 0600). Also on shutdown.
    pub fn persist_now(&self) {
        let Some(path) = self.persist.get() else {
            return;
        };
        self.reap();
        let now = unix_now();
        let inst = Instant::now();
        let rows: Vec<serde_json::Value> = {
            let g = self.inner.lock();
            g.sessions
                .values()
                .map(|s| {
                    // live: a full grace from now; in grace: the real remaining time
                    let exp = now
                        + s.grace_until.map_or(RESUME_GRACE.as_secs(), |t| {
                            t.saturating_duration_since(inst).as_secs()
                        });
                    serde_json::json!({
                        "sid_sha256": s.sid_hash.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                        "token_id": s.token_id,
                        "user": s.user,
                        "profiles": s.ident_profiles,
                        "expires": exp,
                    })
                })
                .collect()
        };
        let body = serde_json::json!({"v": 1, "sessions": rows}).to_string();
        let tmp = path.with_extension("tmp");
        let write = || -> std::io::Result<()> {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)
        };
        if let Err(e) = write() {
            tracing::warn!("could not persist extension sessions: {e}");
        }
    }

    /// Reload the persisted sessions as grace sessions (they live [`RESUME_GRACE`] from now),
    /// except those whose token `token_live` no longer accepts. Returns how many came back.
    pub fn restore(&self, token_live: &dyn Fn(&str) -> bool) -> usize {
        let Some(path) = self.persist.get() else {
            return 0;
        };
        let Ok(text) = std::fs::read_to_string(path) else {
            return 0;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
            return 0;
        };
        let now = unix_now();
        let mut n = 0;
        let mut g = self.inner.lock();
        for r in v
            .get("sessions")
            .and_then(|s| s.as_array())
            .into_iter()
            .flatten()
        {
            let (Some(h), Some(token_id), Some(user)) = (
                r.get("sid_sha256").and_then(|x| x.as_str()),
                r.get("token_id").and_then(|x| x.as_str()),
                r.get("user").and_then(|x| x.as_str()),
            ) else {
                continue;
            };
            let Some(exp) = r
                .get("expires")
                .and_then(|x| x.as_u64())
                .filter(|e| *e > now)
            else {
                continue;
            };
            if !token_live(token_id) || h.len() != 64 {
                continue;
            }
            let mut hash = [0u8; 32];
            let ok = (0..32).all(|i| {
                u8::from_str_radix(&h[2 * i..2 * i + 2], 16)
                    .map(|b| hash[i] = b)
                    .is_ok()
            });
            if !ok {
                continue;
            }
            let profiles = r.get("profiles").and_then(|p| p.as_array()).map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            });
            let (tx, _rx) = mpsc::channel(1); // no channel: dropped receiver, so `detach` semantics hold
            self.insert_session(
                &mut g,
                ExtIdent {
                    token_id: token_id.into(),
                    user: user.into(),
                    profiles,
                },
                hash,
                tx,
                // never longer than the file says, never longer than a full grace
                Some(Instant::now() + Duration::from_secs((exp - now).min(RESUME_GRACE.as_secs()))),
            );
            n += 1;
        }
        n
    }

    /// The channel of session `id` is gone (network drop, worker restart): keep the session for
    /// [`RESUME_GRACE`] so the browser's connections stay valid and the extension can resume it.
    /// No-op when a resume already replaced the channel. Its jobs fail now.
    pub fn detach(&self, id: u64) {
        let mut g = self.inner.lock();
        let Some(s) = g.sessions.get_mut(&id) else {
            return;
        };
        if !s.tx.is_closed() {
            return;
        }
        s.grace_until = Some(Instant::now() + RESUME_GRACE);
        for (tx, _) in s.jobs.drain().map(|(_, v)| v) {
            let _ = tx.try_send(JobEvent::Error(
                br#"{"kind":"network","code":"network","message":"extension disconnected"}"#
                    .to_vec(),
            ));
        }
        for d in g.docs.values_mut().filter(|d| d.session == id) {
            for m in d.menus.values() {
                m.wake.notify_waiters();
            }
        }
        self.mark_dirty();
    }

    /// Reattach a new channel to the live or grace session `sid` of the same token (same `sid`
    /// kept). `None`: unknown, expired or another token's.
    pub fn resume(
        &self,
        ident: &ExtIdent,
        sid: &str,
    ) -> Option<(u64, String, mpsc::Receiver<ExtOut>)> {
        self.reap();
        let mut g = self.inner.lock();
        let mut found = None;
        for (id, s) in &g.sessions {
            // Both compares always run (no early exit on the first mismatch).
            let a = ct_eq_bytes(&s.sid_hash, &hash_sid(sid));
            let b = ct_eq(&s.token_id, &ident.token_id);
            if a & b {
                found = Some(*id);
            }
        }
        let id = found?;
        let (tx, rx) = mpsc::channel(256);
        let s = g.sessions.get_mut(&id)?;
        s.tx = tx; // the previous channel (if any) sees its queue end and stops
        s.grace_until = None;
        drop(g);
        self.mark_dirty();
        Some((id, sid.to_string(), rx))
    }

    /// Close the sessions whose grace ran out.
    fn reap(&self) {
        let now = Instant::now();
        let dead: Vec<(u64, String)> = {
            let g = self.inner.lock();
            g.sessions
                .iter()
                .filter(|(_, s)| s.grace_until.is_some_and(|t| t <= now))
                .map(|(i, s)| (*i, s.user.clone()))
                .collect()
        };
        for (id, user) in dead {
            self.close(id);
            self.audit(&user, "session_expire", Some(id.to_string()));
        }
    }

    /// Test hook: make a session's grace run out now.
    #[doc(hidden)]
    pub fn expire_grace_for_test(&self, id: u64) {
        if let Some(s) = self.inner.lock().sessions.get_mut(&id) {
            s.grace_until = Some(Instant::now());
        }
    }

    /// Forget a session: its jobs fail, its documents stop being served by it.
    pub fn close(&self, id: u64) {
        filter_engine::session_log().forget(id);
        let mut g = self.inner.lock();
        if let Some(s) = g.sessions.remove(&id) {
            for (tx, _) in s.jobs.values() {
                let _ = tx.try_send(JobEvent::Error(
                    br#"{"kind":"network","code":"network","message":"extension disconnected"}"#
                        .to_vec(),
                ));
            }
        }
        // Wake every waiter bound to it so the runtime can fall back to its own button.
        let g = &mut *g;
        for d in g.docs.values_mut().filter(|d| d.session == id) {
            for m in d.menus.values() {
                m.wake.notify_waiters();
            }
        }
        g.relays.retain(|_, r| {
            // Relays of the closed session's jobs are removed with their guards; nothing here.
            let _ = r;
            true
        });
        self.mark_dirty();
    }

    /// Close every live session of token `token_id` at once (the token was revoked or expired,
    /// or its owner was disabled or deleted). Pending jobs fail; the extension removes its
    /// header rule when its socket closes.
    pub fn close_token(&self, token_id: &str) {
        let ids: Vec<u64> = {
            let g = self.inner.lock();
            g.sessions
                .iter()
                .filter(|(_, s)| s.token_id == token_id)
                .map(|(i, s)| {
                    let _ = s.tx.try_send(ExtOut::Close(4401));
                    *i
                })
                .collect()
        };
        for id in ids {
            self.close(id);
        }
    }

    pub fn is_live(&self, id: u64) -> bool {
        self.reap();
        self.inner.lock().sessions.contains_key(&id)
    }

    pub fn session_count(&self) -> usize {
        self.reap();
        self.inner.lock().sessions.len()
    }

    /// Authenticate the credentials of the extension's proxy listener: the session whose `sid`
    /// is `sid` (constant-time compare against every live session). Nothing else is consulted.
    pub fn authenticate(&self, sid: &str) -> Option<u64> {
        self.reap();
        let h = hash_sid(sid);
        let g = self.inner.lock();
        let mut found = None;
        for (id, s) in &g.sessions {
            if ct_eq_bytes(&s.sid_hash, &h) {
                found = Some(*id);
            }
        }
        found
    }

    /// May documents of namespace `profile` be bound to `session`? (the token's profiles)
    pub fn allows(&self, session: u64, profile: &str) -> bool {
        self.inner.lock().sessions.get(&session).is_some_and(|s| {
            s.profiles
                .as_ref()
                .is_none_or(|p| p.iter().any(|x| x == profile))
        })
    }

    /// The profile a session's connections are pinned to: the first profile its token is
    /// restricted to (`None`: the usual resolution by client address and device token).
    /// The id of the bridge token that opened `session` (a non-secret identifier, stable across
    /// the browser's reconnects).
    pub fn token_id_of(&self, session: u64) -> Option<String> {
        self.inner
            .lock()
            .sessions
            .get(&session)
            .map(|s| s.token_id.clone())
    }

    pub fn pinned_profile(&self, session: u64) -> Option<u64> {
        self.inner.lock().sessions.get(&session)?.pinned
    }

    /// The extension listener's port (0 = off), told to every session after hello.
    pub fn set_proxy(&self, host: Option<String>, port: u16) {
        let msg = self.proxy_msg_for(host.clone(), port);
        *self.proxy.lock() = (host, port);
        let g = self.inner.lock();
        for s in g.sessions.values() {
            let _ = s.tx.try_send(ExtOut::Text(msg.clone()));
        }
    }

    fn proxy_msg_for(&self, host: Option<String>, port: u16) -> String {
        serde_json::json!({"t": "proxy", "host": host, "port": (port != 0).then_some(port)})
            .to_string()
    }

    /// `{"t":"proxy",...}` for the current listener.
    pub fn proxy_msg(&self) -> String {
        let (h, p) = self.proxy.lock().clone();
        self.proxy_msg_for(h, p)
    }

    /// The session of `sid` belonging to token `token_id` (for the web API).
    pub fn session_for(&self, sid: &str, token_id: &str) -> Option<u64> {
        let h = hash_sid(sid);
        let g = self.inner.lock();
        let mut found = None;
        for (id, s) in &g.sessions {
            if ct_eq_bytes(&s.sid_hash, &h) && s.token_id == token_id {
                found = Some(*id);
            }
        }
        found
    }

    /// Text frame from the extension.
    pub async fn on_text(&self, id: u64, text: &str) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
            return;
        };
        match v.get("t").and_then(|t| t.as_str()) {
            Some("ping") => {
                // Never wait on the outgoing queue: the reader loop must keep reading.
                let mut g = self.inner.lock();
                if let Some(s) = g.sessions.get_mut(&id) {
                    s.pings = s.pings.wrapping_add(1);
                    let _ = s.tx.try_send(ExtOut::Text(r#"{"t":"pong"}"#.into()));
                }
            }
            Some("perms") => {
                let origins: Vec<String> = v
                    .get("origins")
                    .and_then(|o| o.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .take(2000)
                            .collect()
                    })
                    .unwrap_or_default();
                let perms = Perms::from_origins(&origins);
                let user = {
                    let mut g = self.inner.lock();
                    let Some(s) = g.sessions.get_mut(&id) else {
                        return;
                    };
                    s.perms = perms;
                    s.user.clone()
                };
                self.audit(&user, "perms", Some(format!("{} origins", origins.len())));
            }
            Some("popup") => {
                let get = |k: &str| {
                    v.get(k)
                        .and_then(|x| x.as_str())
                        .filter(|x| x.len() <= 8192)
                        .map(str::to_string)
                };
                let (Some(url), Some(opener)) = (get("url"), get("opener")) else {
                    return;
                };
                let mut g = self.inner.lock();
                if let Some(s) = g.sessions.get_mut(&id) {
                    let now = Instant::now();
                    s.popups.retain(|p| now.duration_since(p.2) < POPUP_TTL);
                    if s.popups.len() >= MAX_POPUPS {
                        s.popups.pop_front();
                    }
                    s.popups.push_back((url, opener, now));
                }
            }
            _ => {}
        }
    }

    /// The opener the extension reported for a document navigation to `url` in this session,
    /// consumed by the lookup (a popup is one navigation).
    pub fn take_popup(&self, id: u64, url: &str) -> Option<String> {
        let url = url.split('#').next().unwrap_or(url);
        let mut g = self.inner.lock();
        let s = g.sessions.get_mut(&id)?;
        let now = Instant::now();
        s.popups.retain(|p| now.duration_since(p.2) < POPUP_TTL);
        let i = s
            .popups
            .iter()
            .position(|p| p.0.split('#').next().unwrap_or(&p.0) == url)?;
        s.popups.remove(i).map(|p| p.1)
    }

    /// Binary frame from the extension: an answer to one of this session's jobs.
    pub async fn on_binary(&self, id: u64, data: &[u8]) {
        let Some((t, job, payload)) = parse_job_frame(data) else {
            return;
        };
        let ev = match t {
            F_HEAD => JobEvent::Head(payload.to_vec()),
            F_DATA => JobEvent::Data(Bytes::copy_from_slice(payload)),
            F_END => JobEvent::End,
            F_ERROR => JobEvent::Error(payload.to_vec()),
            _ => return,
        };
        // Only this session's own jobs are reachable from its frames. A finished job is
        // forgotten at once, so dropping its handle later sends no cancel frame.
        //
        // Nothing here waits: the WebSocket reader must keep reading (pongs, other jobs). When
        // the job's queue is full the page is too slow: the job is removed, the extension is
        // told to cancel, and the page gets an error (its receiver sees the queue end without
        // an END and reports it). A chunk is never dropped and followed by a normal END.
        let last = matches!(t, F_END | F_ERROR);
        let mut g = self.inner.lock();
        let Some(s) = g.sessions.get_mut(&id) else {
            return;
        };
        let Some((tx, overflow)) = s.jobs.get(&job) else {
            return;
        };
        match tx.try_send(ev) {
            Ok(()) => {
                if last {
                    s.jobs.remove(&job);
                }
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                overflow.store(true, Ordering::Release);
                s.jobs.remove(&job);
                let _ = s.tx.try_send(ExtOut::Binary(job_frame(F_CANCEL, job, &[])));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                s.jobs.remove(&job);
                let _ = s.tx.try_send(ExtOut::Binary(job_frame(F_CANCEL, job, &[])));
            }
        }
    }

    // ---- host list ----------------------------------------------------------------------

    // ---- documents and menus ------------------------------------------------------------

    /// Register a document bound to live session `session`; returns its public `mdoc`. Only
    /// bound documents are registered, so unbound pages never take room here; the session's
    /// own oldest documents are evicted beyond [`MENU_DOCS_PER_SESSION`], never another's.
    pub fn register_doc(
        &self,
        profile: &str,
        origin: &str,
        scripts: Vec<(String, String)>,
        session: u64,
        store: &str,
    ) -> String {
        let mdoc = rand_hex(16);
        let mut g = self.inner.lock();
        let g = &mut *g;
        // Stale documents (any session) expire.
        while let Some(front) = g.doc_order.front() {
            let stale = g
                .docs
                .get(front)
                .is_none_or(|d| d.touched.elapsed() > MENU_TTL);
            if !stale {
                break;
            }
            let f = g.doc_order.pop_front().expect("front");
            if let Some(d) = g.docs.remove(&f) {
                if let Some(s) = g.sessions.get_mut(&d.session) {
                    s.ndocs = s.ndocs.saturating_sub(1);
                }
            }
        }
        while g
            .sessions
            .get(&session)
            .is_some_and(|s| s.ndocs >= MENU_DOCS_PER_SESSION)
        {
            let Some(pos) = g
                .doc_order
                .iter()
                .position(|m| g.docs.get(m).is_some_and(|d| d.session == session))
            else {
                break;
            };
            let m = g.doc_order.remove(pos).expect("pos");
            g.docs.remove(&m);
            if let Some(s) = g.sessions.get_mut(&session) {
                s.ndocs = s.ndocs.saturating_sub(1);
            }
        }
        if let Some(s) = g.sessions.get_mut(&session) {
            s.ndocs += 1;
        }
        g.doc_order.push_back(mdoc.clone());
        g.docs.insert(
            mdoc.clone(),
            MenuDoc {
                store: store.to_string(),
                profile: profile.to_string(),
                origin: origin.to_string(),
                scripts,
                session,
                menus: HashMap::new(),
                touched: Instant::now(),
            },
        );
        mdoc
    }

    fn doc_for<'a>(
        g: &'a mut Inner,
        conn: Option<(u64, &str)>,
        mdoc: &str,
        profile: &str,
        origin: &str,
        script: &str,
    ) -> GmResult<&'a mut MenuDoc> {
        let d = g
            .docs
            .get_mut(mdoc)
            .filter(|d| d.profile == profile && d.origin == origin)
            // Only the connection the document was served to may use it (an mdoc is public).
            .filter(|d| conn.is_some_and(|(s, st)| d.session == s && d.store == st))
            .filter(|d| d.scripts.iter().any(|(s, _)| s == script))
            .ok_or_else(|| GmError::new(ErrorCode::NotFound, "unknown document"))?;
        d.touched = Instant::now();
        Ok(d)
    }

    /// `menu/sync`: replace the commands of `script` in `mdoc`. Returns whether a live
    /// extension session serves the document.
    pub fn menu_sync(
        &self,
        conn: Option<(u64, &str)>,
        profile: &str,
        origin: &str,
        script: &str,
        mdoc: &str,
        cmds: Vec<(String, String, String, String, bool)>,
    ) -> GmResult<bool> {
        if cmds.len() > MAX_CMDS {
            return Err(GmError::new(ErrorCode::QuotaExceeded, "too many commands"));
        }
        let mut g = self.inner.lock();
        let live_ids: HashSet<u64> = g.sessions.keys().copied().collect();
        let d = Self::doc_for(&mut g, conn, mdoc, profile, origin, script)?;
        let live = live_ids.contains(&d.session);
        let clip = |s: String| s.chars().take(MAX_TEXT).collect::<String>();
        let m = d.menus.entry(script.to_string()).or_default();
        m.cmds = cmds
            .into_iter()
            .map(|(id, name, access_key, title, auto_close)| MenuCmd {
                id: clip(id),
                name: clip(name),
                access_key: access_key.chars().take(8).collect(),
                title: clip(title),
                auto_close,
            })
            .collect();
        Ok(live)
    }

    /// `menu/wait`: park until a trigger arrives for `script`, the poll ends, or a newer poll of
    /// the same script supersedes this one.
    pub async fn menu_wait(
        self: &Arc<Self>,
        conn: Option<(u64, &str)>,
        profile: &str,
        origin: &str,
        script: &str,
        mdoc: &str,
        poll: Duration,
    ) -> GmResult<Wait> {
        let (wake, my_gen) = {
            let mut g = self.inner.lock();
            let live_ids: HashSet<u64> = g.sessions.keys().copied().collect();
            let d = Self::doc_for(&mut g, conn, mdoc, profile, origin, script)?;
            if !live_ids.contains(&d.session) {
                return Ok(Wait::NoExt);
            }
            let m = d.menus.entry(script.to_string()).or_default();
            m.gen += 1;
            (m.wake.clone(), m.gen)
        };
        // Release a superseded poll of the same script.
        wake.notify_waiters();
        struct Parked<'a> {
            hub: &'a ExtHub,
            mdoc: &'a str,
            script: &'a str,
        }
        impl Drop for Parked<'_> {
            fn drop(&mut self) {
                let mut g = self.hub.inner.lock();
                if let Some(m) = g
                    .docs
                    .get_mut(self.mdoc)
                    .and_then(|d| d.menus.get_mut(self.script))
                {
                    m.parked = m.parked.saturating_sub(1);
                    m.last_wait = Some(Instant::now());
                }
            }
        }
        {
            let mut g = self.inner.lock();
            if let Some(m) = g.docs.get_mut(mdoc).and_then(|d| d.menus.get_mut(script)) {
                m.parked += 1;
            }
        }
        let _parked = Parked {
            hub: self,
            mdoc,
            script,
        };
        let deadline = tokio::time::Instant::now() + poll;
        loop {
            let notified = wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut g = self.inner.lock();
                let live_ids: HashSet<u64> = g.sessions.keys().copied().collect();
                let Some(d) = g.docs.get_mut(mdoc) else {
                    return Ok(Wait::NoExt);
                };
                if !live_ids.contains(&d.session) {
                    return Ok(Wait::NoExt);
                }
                let Some(m) = d.menus.get_mut(script) else {
                    return Ok(Wait::Fire(vec![]));
                };
                if m.gen != my_gen {
                    return Ok(Wait::Fire(vec![]));
                }
                m.queue.retain(|(_, t)| t.elapsed() < FIRE_TTL);
                if !m.queue.is_empty() {
                    let out: Vec<String> = m.queue.drain(..).map(|(c, _)| c).collect();
                    return Ok(Wait::Fire(out));
                }
            }
            tokio::select! {
                _ = &mut notified => {}
                _ = tokio::time::sleep_until(deadline) => return Ok(Wait::Fire(vec![])),
            }
        }
    }

    /// Does `session` hold the document? (live and bound to it)
    fn bound_doc<'a>(
        g: &'a mut Inner,
        session: u64,
        store: &str,
        mdoc: &str,
    ) -> Result<&'a mut MenuDoc, ExtError> {
        if !g.sessions.contains_key(&session) {
            return Err(ExtError::Forbidden);
        }
        let d = g.docs.get_mut(mdoc).ok_or(ExtError::NotFound)?;
        // Another container's page is as foreign as another browser's.
        if d.session != session || d.store != store {
            return Err(ExtError::Forbidden);
        }
        d.touched = Instant::now();
        Ok(d)
    }

    /// Commands and pending host grants of a document bound to `session`.
    pub fn menu(&self, session: u64, store: &str, mdoc: &str) -> Result<ExtMenuResponse, ExtError> {
        let mut g = self.inner.lock();
        let perms = g
            .sessions
            .get(&session)
            .map(|s| s.perms.clone())
            .unwrap_or_default();
        let d = Self::bound_doc(&mut g, session, store, mdoc)?;
        let mut out = ExtMenuResponse::default();
        for (sid, name) in &d.scripts {
            if let Some(m) = d.menus.get(sid) {
                for c in &m.cmds {
                    out.commands.push(ExtMenuCommand {
                        script: sid.clone(),
                        script_name: name.clone(),
                        cmd: c.id.clone(),
                        name: c.name.clone(),
                        access_key: c.access_key.clone(),
                        title: c.title.clone(),
                        auto_close: c.auto_close,
                    });
                }
            }
        }
        let (profile, origin, scripts) = (d.profile.clone(), d.origin.clone(), d.scripts.clone());
        drop(g);
        if let Some(ctx) = self.ctx.get() {
            let idx = ctx.manager.index_for(&profile);
            let page_host = url::Url::parse(&origin)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
                .unwrap_or_default();
            for (sid, name) in &scripts {
                let Some(cs) = idx.get(sid) else { continue };
                if !cs.script.browser_cookies {
                    continue;
                }
                for (host, pattern) in grant_patterns(&cs.script.metadata.connect, &page_host) {
                    let h = pattern
                        .strip_prefix("*://")
                        .and_then(|r| r.strip_suffix("/*"))
                        .unwrap_or("");
                    let bare = h.strip_prefix("*.").unwrap_or(h);
                    let satisfied = if h.starts_with("*.") {
                        perms.suffix_covers(bare)
                    } else {
                        perms.has(bare)
                    };
                    if satisfied {
                        continue;
                    }
                    out.grants.push(ExtGrant {
                        script: sid.clone(),
                        script_name: name.clone(),
                        host,
                        patterns: vec![pattern],
                    });
                }
            }
        }
        Ok(out)
    }

    /// Queue a command for the page; returns whether the page was waiting for it.
    pub fn trigger(
        &self,
        session: u64,
        store: &str,
        req: &ExtTriggerRequest,
    ) -> Result<bool, ExtError> {
        let mut g = self.inner.lock();
        let d = Self::bound_doc(&mut g, session, store, &req.mdoc)?;
        let m = d.menus.get_mut(&req.script).ok_or(ExtError::NotFound)?;
        if !m.cmds.iter().any(|c| c.id == req.cmd) {
            return Err(ExtError::NotFound);
        }
        m.queue.retain(|(_, t)| t.elapsed() < FIRE_TTL);
        if m.queue.len() >= 16 {
            m.queue.pop_front();
        }
        m.queue.push_back((req.cmd.clone(), Instant::now()));
        let delivered = m.parked > 0
            || m.last_wait
                .is_some_and(|t| t.elapsed() < Duration::from_secs(3));
        m.wake.notify_waiters();
        Ok(delivered)
    }

    // ---- routing of credentialed requests ------------------------------------------------

    /// Decide where a credentialed request of `script` in document `mdoc` goes. The caller has
    /// already established that the script is approved for browser logins, is not anonymous and
    /// passed `@connect`.
    #[allow(clippy::too_many_arguments)]
    pub fn route(
        &self,
        conn: Option<(u64, &str)>,
        mdoc: Option<&str>,
        profile: &str,
        origin: &str,
        script: &str,
        host: &str,
        port: u16,
    ) -> Route {
        let g = self.inner.lock();
        let Some(d) = mdoc
            .and_then(|m| g.docs.get(m))
            .filter(|d| d.profile == profile && d.origin == origin)
            .filter(|d| d.scripts.iter().any(|(s, _)| s == script))
            // The request must come over the connection the document was served to: an mdoc and
            // a GM token are not secrets, another browser or container must not borrow them.
            .filter(|d| conn.is_some_and(|(s, st)| d.session == s && d.store == st))
        else {
            return Route::Jar(Fallback::NoDocument);
        };
        let sid = d.session;
        let Some(s) = g.sessions.get(&sid).filter(|s| s.grace_until.is_none()) else {
            return Route::Jar(Fallback::Dead);
        };
        // The relay's per-hop check runs in the proxy, so it works only on traffic the proxy
        // decrypts; and a browser must not be pointed at local or private targets.
        if is_local_target(host) {
            return Route::Jar(Fallback::LocalTarget);
        }
        if self.ctx.get().is_none_or(|c| {
            c.bypass.failsafe_active() || c.bypass.mode_of(host.trim_matches(['[', ']'])).is_some()
        }) || !self.decrypting()
        {
            return Route::Jar(Fallback::Bypassed);
        }
        if self.is_own(host, port) {
            return Route::Jar(Fallback::OwnHost);
        }
        if !s.perms.has(host) {
            return Route::Jar(Fallback::NoPermission);
        }
        Route::Ext(sid)
    }

    /// The cookie store token of document `mdoc` (empty: default store). The extension maps it
    /// to the real store and relays with that store's cookies.
    pub fn doc_store(&self, mdoc: Option<&str>) -> String {
        mdoc.and_then(|m| self.inner.lock().docs.get(m).map(|d| d.store.clone()))
            .unwrap_or_default()
    }

    /// Remember whether the last credentialed request of a script used the browser.
    pub fn note_route(&self, profile: &str, script: &str, fell_back: bool) {
        let mut g = self.inner.lock();
        if g.fallback.len() > 4096 {
            g.fallback.retain(|_, (t, _)| t.elapsed() < FALLBACK_TTL);
        }
        g.fallback.insert(
            (profile.to_string(), script.to_string()),
            (Instant::now(), fell_back),
        );
    }

    /// An approved script whose last request fell back to the jar, recently.
    pub fn browser_fallback(&self, profile: &str, script: &str) -> bool {
        self.inner
            .lock()
            .fallback
            .get(&(profile.to_string(), script.to_string()))
            .is_some_and(|(t, fb)| *fb && t.elapsed() < FALLBACK_TTL)
    }

    // ---- jobs ---------------------------------------------------------------------------

    /// Dispatch a job to `session`. `meta` is the job description (it gets the `relay` token
    /// added). `upload` streams the request body, when there is one.
    pub async fn dispatch(
        self: &Arc<Self>,
        session: u64,
        mut meta: serde_json::Value,
        profile: &str,
        script: &str,
        page_host: &str,
        upload: Option<mpsc::Receiver<Result<Bytes, std::io::Error>>>,
    ) -> Result<JobHandle, GmError> {
        let relay = rand_hex(16);
        meta["relay"] = serde_json::Value::String(relay.clone());
        meta["hasBody"] = serde_json::Value::Bool(upload.is_some());
        let (etx, erx) = mpsc::channel(JOB_QUEUE);
        let overflow = Arc::new(AtomicBool::new(false));
        let (job, tx) = {
            let mut g = self.inner.lock();
            let s = g
                .sessions
                .get_mut(&session)
                .filter(|s| s.grace_until.is_none())
                .ok_or_else(|| GmError::new(ErrorCode::Internal, "extension session is gone"))?;
            if s.jobs.len() >= MAX_JOBS_PER_SESSION {
                return Err(GmError::new(ErrorCode::QuotaExceeded, "too many jobs"));
            }
            let mut job = s.next_job;
            while s.jobs.contains_key(&job) || job == 0 {
                job = job.wrapping_add(1);
            }
            s.next_job = job.wrapping_add(1);
            s.jobs.insert(job, (etx, overflow.clone()));
            let tx = s.tx.clone();
            g.relays.insert(
                relay.clone(),
                RelayInfo {
                    session,
                    store: meta
                        .get("store")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    profile: profile.to_string(),
                    script: script.to_string(),
                    page_host: page_host.to_string(),
                },
            );
            (job, tx)
        };
        let guard = JobGuard {
            hub: self.clone(),
            session,
            job,
            relay,
        };
        let sent = tx
            .send(ExtOut::Binary(job_frame(
                F_JOB,
                job,
                meta.to_string().as_bytes(),
            )))
            .await;
        if sent.is_err() {
            return Err(GmError::new(
                ErrorCode::Internal,
                "extension session is gone",
            ));
        }
        if let Some(mut up) = upload {
            tokio::spawn(async move {
                while let Some(chunk) = up.recv().await {
                    let Ok(chunk) = chunk else {
                        let _ = tx.send(ExtOut::Binary(job_frame(F_CANCEL, job, &[]))).await;
                        return;
                    };
                    for part in chunk.chunks(64 * 1024) {
                        if tx
                            .send(ExtOut::Binary(job_frame(F_DATA, job, part)))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                let _ = tx.send(ExtOut::Binary(job_frame(F_END, job, &[]))).await;
            });
        }
        Ok(JobHandle {
            rx: erx,
            overflow,
            _guard: guard,
        })
    }

    fn finish_job(&self, session: u64, job: u32, relay: &str) {
        let mut g = self.inner.lock();
        g.relays.remove(relay);
        if let Some(s) = g.sessions.get_mut(&session) {
            if s.jobs.remove(&job).is_some() {
                let _ = s.tx.try_send(ExtOut::Binary(job_frame(F_CANCEL, job, &[])));
            }
        }
    }

    /// Re-check one hop of a relayed request (the browser follows redirects itself, so every
    /// hop that goes through the proxy arrives here): the job is live, its session still holds a
    /// host permission for the hop's host, the hop is not a local or private target, Argus is
    /// decrypting it, and it passes the script's stored `@connect`. `false` for an unknown
    /// relay token.
    pub fn check_relay(
        &self,
        relay: &str,
        url: &url::Url,
        conn_session: Option<u64>,
        conn_store: &str,
    ) -> bool {
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        let (profile, script, page_host) = {
            let g = self.inner.lock();
            let Some(r) = g.relays.get(relay) else {
                return false;
            };
            // The hop must arrive on a connection that authenticated as the job's session.
            if conn_session != Some(r.session) || !conn_store.is_empty() {
                return false;
            }
            let Some(s) = g.sessions.get(&r.session) else {
                return false;
            };
            if !s.perms.has(&host) {
                return false;
            }
            (r.profile.clone(), r.script.clone(), r.page_host.clone())
        };
        if host.is_empty() || is_local_target(&host) {
            return false;
        }
        let Some(ctx) = self.ctx.get() else {
            return false;
        };
        if ctx.bypass.failsafe_active() || ctx.bypass.mode_of(&host).is_some() {
            return false;
        }
        // Argus must be decrypting this listener's traffic, and the target is not Argus itself.
        if !self.decrypting() || self.is_own(&host, url.port_or_known_default().unwrap_or(443)) {
            return false;
        }
        let idx = ctx.manager.index_for(&profile);
        let Some(cs) = idx.get(&script) else {
            return false;
        };
        cs.script.enabled
            && cs.script.browser_cookies
            && userscript_engine::backend::check_connect(&cs.script, &page_host, url).is_ok()
    }

    /// The store token the relay token's job runs for (audit); `None` for an unknown token.
    pub fn relay_store(&self, relay: &str) -> Option<String> {
        self.inner.lock().relays.get(relay).map(|r| r.store.clone())
    }

    /// Audit one relayed request.
    pub fn audit_relay(&self, session: u64, script: &str, host: &str, method: &str, op: &str) {
        let user = self
            .inner
            .lock()
            .sessions
            .get(&session)
            .map(|s| s.user.clone())
            .unwrap_or_default();
        self.audit(
            &user,
            "relay",
            Some(format!("{script} {op} {method} {host}")),
        );
        if let Some(a) = self.auditor.get() {
            a.log_event(
                userscript_engine::AuditEvent::NetworkRequest,
                script,
                &format!("browser relay {op} {method} {host}"),
            );
        }
    }
}

/// `(label, pattern)` host permissions a script's `@connect` list asks the user to grant.
/// Wildcard `@connect *` and TLD wildcards are never offered.
pub fn grant_patterns(connect: &[String], page_host: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for c in connect {
        let c = c.to_ascii_lowercase();
        let host = match c.as_str() {
            "*" => continue,
            "self" => page_host.to_ascii_lowercase(),
            s if s.ends_with(".*") => continue,
            s => s.to_string(),
        };
        if host.is_empty() {
            continue;
        }
        let bare = host.strip_prefix("*.").unwrap_or(&host);
        // A public suffix (`com`, `co.uk`) is never offered: it would be a blanket grant.
        if is_public_suffix(bare) {
            continue;
        }
        let pat = if bare == "localhost" || bare.parse::<std::net::IpAddr>().is_ok() {
            format!("*://{bare}/*")
        } else {
            format!("*://*.{bare}/*")
        };
        if !out.iter().any(|(_, p)| p == &pat) {
            out.push((host, pat));
        }
    }
    out
}

/// An in-flight job: the answers arrive on `rx`; dropping it cancels the job.
pub struct JobHandle {
    pub rx: mpsc::Receiver<JobEvent>,
    overflow: Arc<AtomicBool>,
    _guard: JobGuard,
}

impl JobHandle {
    /// The job was failed because its queue filled up (the page read too slowly): its
    /// receiver ends without an `End`.
    pub fn overflowed(&self) -> bool {
        self.overflow.load(Ordering::Acquire)
    }
}

struct JobGuard {
    hub: Arc<ExtHub>,
    session: u64,
    job: u32,
    relay: String,
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        self.hub.finish_job(self.session, self.job, &self.relay);
    }
}

/// Take the relay header off a request's header map and return its value. Called for every
/// request the proxy is about to forward: it may never leave. (`HeaderMap::remove` drops every
/// value of the name.) The session is never read from a header: it comes from the
/// authenticated connection of the extension's own listener.
pub fn take_headers(h: &mut hyper::HeaderMap) -> Option<String> {
    h.remove(RELAY_HEADER)
        .and_then(|v| v.to_str().ok().map(str::to_string))
}

//! The hub of the browser-extension bridge (protocol: `docs/USERSCRIPT-PROTOCOL.md` section 8).
//!
//! * **Sessions.** The extension opens a WebSocket on the web API; the hub registers it under a
//!   fresh random `sid` (new on every connection). The extension makes its browser send that
//!   `sid` in `X-Argus-Ext` on document requests to the hosts the hub lists; the proxy reads the
//!   header, always strips it, and binds the document it is about to inject scripts into to the
//!   session with that `sid`. Nothing about a client address is used.
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
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify};
use userscript_engine::backend::{ErrorCode, GmError, GmResult};
use userscript_engine::{HostPolicy, SecurityAuditor, UserscriptManager};

/// Header the extension's browser adds to document requests; always stripped by the proxy.
pub const SESSION_HEADER: &str = "x-argus-ext";
/// Header the extension's relay fetches carry (the job's relay token); always stripped.
pub const RELAY_HEADER: &str = "x-argus-relay";

/// Concurrent sessions per bridge token (the oldest is closed beyond it).
pub const MAX_SESSIONS_PER_TOKEN: usize = 8;
/// Concurrent jobs per session.
pub const MAX_JOBS_PER_SESSION: usize = 32;
/// Documents with a menu record (oldest evicted first).
pub const MENU_DOC_CAP: usize = 4096;
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
/// Host list limits (beyond them the hub pushes an empty, fail-safe list).
pub const HOSTS_CAP: usize = 5000;
pub const EXCLUDE_CAP: usize = 20_000;

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
#[derive(Debug, Default, Clone)]
pub struct Perms {
    any: bool,
    exact: HashSet<String>,
    suffix: HashSet<String>,
}

impl Perms {
    pub fn from_origins(origins: &[String]) -> Self {
        let mut p = Perms::default();
        for o in origins {
            if o == "<all_urls>" {
                p.any = true;
                continue;
            }
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
            if host == "*" {
                p.any = true;
            } else if let Some(d) = host.strip_prefix("*.") {
                p.suffix.insert(d.to_string());
            } else {
                p.exact.insert(host);
            }
        }
        p
    }

    /// Does the extension hold a permission covering `host`?
    pub fn has(&self, host: &str) -> bool {
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        if self.any || self.exact.contains(&host) {
            return true;
        }
        let mut rest = host.as_str();
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

/// The list the extension turns into its header rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsMsg {
    pub wildcard: bool,
    pub hosts: Vec<String>,
    pub exclude: Vec<String>,
}

impl HostsMsg {
    pub fn to_json(&self) -> String {
        serde_json::json!({"t": "hosts", "wildcard": self.wildcard, "hosts": self.hosts, "exclude": self.exclude}).to_string()
    }
}

fn under(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

/// Build the host list from what the scripts can inject on, minus every host Argus passes
/// through (`passthrough`: bare domains, matched by suffix like the extension's rule matches).
/// Hosts the proxy does not decrypt must never see the session header.
pub fn build_hosts(policy: &HostPolicy, passthrough: &[String]) -> HostsMsg {
    let fail_safe = HostsMsg {
        wildcard: false,
        hosts: vec![],
        exclude: vec![],
    };
    if policy.any {
        if passthrough.len() > EXCLUDE_CAP {
            return fail_safe;
        }
        return HostsMsg {
            wildcard: true,
            hosts: vec![],
            exclude: passthrough.to_vec(),
        };
    }
    let all: BTreeSet<&String> = policy.exact.iter().chain(policy.suffix.iter()).collect();
    let hosts: Vec<String> = all
        .into_iter()
        .filter(|h| !passthrough.iter().any(|p| under(h, p)))
        .cloned()
        .collect();
    if hosts.len() > HOSTS_CAP {
        return fail_safe;
    }
    // A passthrough domain below a listed host would still get the header from the extension's
    // domain match: exclude it explicitly.
    let exclude: Vec<String> = passthrough
        .iter()
        .filter(|p| hosts.iter().any(|h| under(p, h)))
        .cloned()
        .collect();
    HostsMsg {
        wildcard: false,
        hosts,
        exclude,
    }
}

// ---- state ----------------------------------------------------------------------------------

struct Session {
    sid: String,
    token_id: String,
    user: String,
    /// Namespaces the session's token may serve (`None`: all).
    profiles: Option<Vec<String>>,
    tx: mpsc::Sender<ExtOut>,
    perms: Perms,
    jobs: HashMap<u32, mpsc::Sender<JobEvent>>,
    next_job: u32,
    last_hosts: Option<String>,
    opened: Instant,
}

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
    profile: String,
    origin: String,
    scripts: Vec<(String, String)>,
    session: Option<u64>,
    menus: HashMap<String, ScriptMenu>,
    touched: Instant,
}

struct RelayInfo {
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
    /// The document was not bound to a session when it was served.
    Unbound,
    /// The bound session is gone.
    Dead,
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
        let (tx, rx) = mpsc::channel(256);
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let sid = rand_hex(16);
        let profiles = ident.profiles.map(|v| {
            v.iter()
                .filter_map(|p| p.parse::<u64>().ok())
                .map(common::profile_store::namespace)
                .collect::<Vec<_>>()
        });
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
        g.sessions.insert(
            id,
            Session {
                sid: sid.clone(),
                token_id: ident.token_id,
                user: ident.user,
                profiles,
                tx,
                perms: Perms::default(),
                jobs: HashMap::new(),
                next_job: 1,
                last_hosts: None,
                opened: Instant::now(),
            },
        );
        (id, sid, rx)
    }

    /// Forget a session: its jobs fail, its documents stop being served by it.
    pub fn close(&self, id: u64) {
        let mut g = self.inner.lock();
        if let Some(s) = g.sessions.remove(&id) {
            for tx in s.jobs.values() {
                let _ = tx.try_send(JobEvent::Error(
                    br#"{"kind":"network","code":"network","message":"extension disconnected"}"#
                        .to_vec(),
                ));
            }
        }
        // Wake every waiter bound to it so the runtime can fall back to its own button.
        let g = &mut *g;
        for d in g.docs.values_mut().filter(|d| d.session == Some(id)) {
            for m in d.menus.values() {
                m.wake.notify_waiters();
            }
        }
        g.relays.retain(|_, r| {
            // Relays of the closed session's jobs are removed with their guards; nothing here.
            let _ = r;
            true
        });
    }

    pub fn is_live(&self, id: u64) -> bool {
        self.inner.lock().sessions.contains_key(&id)
    }

    pub fn session_count(&self) -> usize {
        self.inner.lock().sessions.len()
    }

    /// Bind a document of namespace `profile` to the session whose `sid` is `sid`: constant-time
    /// compare against every live session; an unknown `sid` binds nothing.
    pub fn bind(&self, sid: &str, profile: &str) -> Option<u64> {
        let g = self.inner.lock();
        let mut found = None;
        for (id, s) in &g.sessions {
            if ct_eq(&s.sid, sid)
                && s.profiles
                    .as_ref()
                    .is_none_or(|p| p.iter().any(|x| x == profile))
            {
                found = Some(*id);
            }
        }
        found
    }

    /// The session of `sid` belonging to token `token_id` (for the web API).
    pub fn session_for(&self, sid: &str, token_id: &str) -> Option<u64> {
        let g = self.inner.lock();
        let mut found = None;
        for (id, s) in &g.sessions {
            if ct_eq(&s.sid, sid) && s.token_id == token_id {
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
                let tx = self.inner.lock().sessions.get(&id).map(|s| s.tx.clone());
                if let Some(tx) = tx {
                    let _ = tx.send(ExtOut::Text(r#"{"t":"pong"}"#.into())).await;
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
            _ => {}
        }
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
        let last = matches!(t, F_END | F_ERROR);
        let tx = {
            let mut g = self.inner.lock();
            g.sessions.get_mut(&id).and_then(|s| {
                if last {
                    s.jobs.remove(&job)
                } else {
                    s.jobs.get(&job).cloned()
                }
            })
        };
        if let Some(tx) = tx {
            let _ = tokio::time::timeout(Duration::from_secs(30), tx.send(ev)).await;
        }
    }

    // ---- host list ----------------------------------------------------------------------

    fn namespaces_for(&self, profiles: &Option<Vec<String>>) -> Vec<String> {
        let all: Vec<String> = match self.ctx.get().and_then(|c| c.profiles.as_ref()) {
            Some(store) => store
                .list()
                .map(|v| {
                    v.into_iter()
                        .map(|p| common::profile_store::namespace(p.id))
                        .collect()
                })
                .unwrap_or_default(),
            None => vec![userscript_engine::DEFAULT_PROFILE.to_string()],
        };
        match profiles {
            Some(allowed) => all.into_iter().filter(|n| allowed.contains(n)).collect(),
            None => all,
        }
    }

    /// The host list for one session (blocking: reads the profile store).
    pub fn hosts_for(&self, id: u64) -> Option<HostsMsg> {
        let ctx = self.ctx.get()?;
        let profiles = self.inner.lock().sessions.get(&id)?.profiles.clone();
        let mut pol = HostPolicy::default();
        for ns in self.namespaces_for(&profiles) {
            let p = ctx.manager.index_for(&ns).host_policy();
            pol.any |= p.any;
            pol.exact.extend(p.exact);
            pol.suffix.extend(p.suffix);
        }
        pol.exact.sort();
        pol.exact.dedup();
        pol.suffix.sort();
        pol.suffix.dedup();
        Some(build_hosts(&pol, &ctx.bypass.domains()))
    }

    /// Compute and push the host list to session `id` when it changed (or `force`).
    pub async fn push_hosts(self: &Arc<Self>, id: u64, force: bool) {
        let me = self.clone();
        let msg = tokio::task::spawn_blocking(move || me.hosts_for(id))
            .await
            .ok()
            .flatten();
        let Some(msg) = msg else { return };
        let text = msg.to_json();
        let tx = {
            let mut g = self.inner.lock();
            let Some(s) = g.sessions.get_mut(&id) else {
                return;
            };
            if !force && s.last_hosts.as_deref() == Some(text.as_str()) {
                return;
            }
            s.last_hosts = Some(text.clone());
            s.tx.clone()
        };
        let _ = tx.send(ExtOut::Text(text)).await;
    }

    /// Push to every session (used after script or bypass changes, and by the poller).
    pub async fn push_all(self: &Arc<Self>) {
        let ids: Vec<u64> = self.inner.lock().sessions.keys().copied().collect();
        for id in ids {
            self.push_hosts(id, false).await;
        }
    }

    /// Re-push host lists every few seconds (changes only): picks up script and bypass edits.
    pub fn spawn_pusher(self: &Arc<Self>) {
        let weak: Weak<Self> = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let Some(h) = weak.upgrade() else { return };
                h.push_all().await;
            }
        });
    }

    // ---- documents and menus ------------------------------------------------------------

    /// Register a document that is about to get userscripts; returns its public `mdoc`.
    pub fn register_doc(
        &self,
        profile: &str,
        origin: &str,
        scripts: Vec<(String, String)>,
        session: Option<u64>,
    ) -> String {
        let mdoc = rand_hex(16);
        let mut g = self.inner.lock();
        while let Some(front) = g.doc_order.front() {
            let stale = g
                .docs
                .get(front)
                .is_none_or(|d| d.touched.elapsed() > MENU_TTL);
            if stale || g.doc_order.len() >= MENU_DOC_CAP {
                let f = g.doc_order.pop_front().expect("front");
                g.docs.remove(&f);
            } else {
                break;
            }
        }
        g.doc_order.push_back(mdoc.clone());
        g.docs.insert(
            mdoc.clone(),
            MenuDoc {
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
        mdoc: &str,
        profile: &str,
        origin: &str,
        script: &str,
    ) -> GmResult<&'a mut MenuDoc> {
        let d = g
            .docs
            .get_mut(mdoc)
            .filter(|d| d.profile == profile && d.origin == origin)
            .filter(|d| d.scripts.iter().any(|(s, _)| s == script))
            .ok_or_else(|| GmError::new(ErrorCode::NotFound, "unknown document"))?;
        d.touched = Instant::now();
        Ok(d)
    }

    /// `menu/sync`: replace the commands of `script` in `mdoc`. Returns whether a live
    /// extension session serves the document.
    pub fn menu_sync(
        &self,
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
        let d = Self::doc_for(&mut g, mdoc, profile, origin, script)?;
        let live = d.session.is_some_and(|s| live_ids.contains(&s));
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
        profile: &str,
        origin: &str,
        script: &str,
        mdoc: &str,
        poll: Duration,
    ) -> GmResult<Wait> {
        let (wake, my_gen) = {
            let mut g = self.inner.lock();
            let live_ids: HashSet<u64> = g.sessions.keys().copied().collect();
            let d = Self::doc_for(&mut g, mdoc, profile, origin, script)?;
            if !d.session.is_some_and(|s| live_ids.contains(&s)) {
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
                if !d.session.is_some_and(|s| live_ids.contains(&s)) {
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
        mdoc: &str,
    ) -> Result<&'a mut MenuDoc, ExtError> {
        if !g.sessions.contains_key(&session) {
            return Err(ExtError::Forbidden);
        }
        let d = g.docs.get_mut(mdoc).ok_or(ExtError::NotFound)?;
        if d.session != Some(session) {
            return Err(ExtError::Forbidden);
        }
        d.touched = Instant::now();
        Ok(d)
    }

    /// Commands and pending host grants of a document bound to `session`.
    pub fn menu(&self, session: u64, mdoc: &str) -> Result<ExtMenuResponse, ExtError> {
        let mut g = self.inner.lock();
        let perms = g
            .sessions
            .get(&session)
            .map(|s| s.perms.clone())
            .unwrap_or_default();
        let d = Self::bound_doc(&mut g, session, mdoc)?;
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
                        perms.suffix_or_any(bare)
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
    pub fn trigger(&self, session: u64, req: &ExtTriggerRequest) -> Result<bool, ExtError> {
        let mut g = self.inner.lock();
        let d = Self::bound_doc(&mut g, session, &req.mdoc)?;
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
    pub fn route(
        &self,
        mdoc: Option<&str>,
        profile: &str,
        origin: &str,
        script: &str,
        host: &str,
    ) -> Route {
        let g = self.inner.lock();
        let Some(d) = mdoc
            .and_then(|m| g.docs.get(m))
            .filter(|d| d.profile == profile && d.origin == origin)
            .filter(|d| d.scripts.iter().any(|(s, _)| s == script))
        else {
            return Route::Jar(Fallback::NoDocument);
        };
        let Some(sid) = d.session else {
            return Route::Jar(Fallback::Unbound);
        };
        let Some(s) = g.sessions.get(&sid) else {
            return Route::Jar(Fallback::Dead);
        };
        if !s.perms.has(host) {
            return Route::Jar(Fallback::NoPermission);
        }
        Route::Ext(sid)
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
        let (etx, erx) = mpsc::channel(8);
        let (job, tx) = {
            let mut g = self.inner.lock();
            let s = g
                .sessions
                .get_mut(&session)
                .ok_or_else(|| GmError::new(ErrorCode::Internal, "extension session is gone"))?;
            if s.jobs.len() >= MAX_JOBS_PER_SESSION {
                return Err(GmError::new(ErrorCode::QuotaExceeded, "too many jobs"));
            }
            let mut job = s.next_job;
            while s.jobs.contains_key(&job) || job == 0 {
                job = job.wrapping_add(1);
            }
            s.next_job = job.wrapping_add(1);
            s.jobs.insert(job, etx);
            let tx = s.tx.clone();
            g.relays.insert(
                relay.clone(),
                RelayInfo {
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

    /// Re-check one hop of a relayed request: the job is live and the hop passes the script's
    /// stored `@connect`. `None` for an unknown relay token.
    pub fn check_relay(&self, relay: &str, url: &url::Url) -> bool {
        let (profile, script, page_host) = {
            let g = self.inner.lock();
            match g.relays.get(relay) {
                Some(r) => (r.profile.clone(), r.script.clone(), r.page_host.clone()),
                None => return false,
            }
        };
        let Some(ctx) = self.ctx.get() else {
            return false;
        };
        let idx = ctx.manager.index_for(&profile);
        let Some(cs) = idx.get(&script) else {
            return false;
        };
        cs.script.enabled
            && cs.script.browser_cookies
            && userscript_engine::backend::check_connect(&cs.script, &page_host, url).is_ok()
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

impl Perms {
    fn suffix_or_any(&self, bare: &str) -> bool {
        if self.any {
            return true;
        }
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
    _guard: JobGuard,
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

/// Take both bridge headers off a request's header map; returns `(session sid, relay token)`.
/// Called for every request the proxy is about to forward: neither header may ever leave.
/// (`HeaderMap::remove` drops every value of the name.)
pub fn take_headers(h: &mut hyper::HeaderMap) -> (Option<String>, Option<String>) {
    let sid = h
        .remove(SESSION_HEADER)
        .and_then(|v| v.to_str().ok().map(str::to_string));
    let relay = h
        .remove(RELAY_HEADER)
        .and_then(|v| v.to_str().ok().map(str::to_string));
    (sid, relay)
}

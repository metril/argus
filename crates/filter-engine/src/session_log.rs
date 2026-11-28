//! Per-extension-session request log: the requests of the connections bound to one browser
//! extension session, kept in a bounded ring per session so the extension's logger page can show
//! what happened to each request. Process-global (every profile engine feeds it) and entries are
//! never visible to another session. URLs carry their query only when the request log keeps
//! queries too (`set_keep_query`); the caller passes the URL it already stripped.
//!
//! Hot path: [`SessionLog::push`] takes only its own session's lock, stores a few small fields
//! (shared `Arc<str>`s for repeated hosts, rules and lists) and does no domain maths; the
//! third-party flag is computed when the entries are read. Total memory is capped at
//! [`MAX_TOTAL_BYTES`]: past it the oldest entries of the heaviest session go first.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use chrono::{DateTime, TimeZone, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::events::{EventAction, EventOutcome, EventRef};

/// Entries kept per session.
pub const SESSION_CAPACITY: usize = 1000;
/// Sessions kept; the least recently written one is dropped beyond this.
pub const MAX_SESSIONS: usize = 64;
/// Longest URL kept, in bytes.
pub const SESSION_URL_CAP: usize = 2048;
/// Approximate bytes kept across all sessions.
pub const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
/// Fixed cost counted per entry on top of its URL.
const ENTRY_OVERHEAD: usize = 112;
/// Distinct shared strings remembered per session before the table starts over.
const INTERN_CAP: usize = 512;

/// What happened to a request, as the logger shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionKind {
    Blocked,
    Allowed,
    /// Answered by a `$redirect` resource.
    Redirected,
    /// Forwarded after a rewrite (URL parameters stripped, redirect rewrite, ...).
    Modified,
    /// Blocked by failing the connection (no response reached the page).
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEntry {
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub url: String,
    pub method: String,
    pub request_type: String,
    pub source_host: String,
    pub kind: SessionKind,
    pub rule: Option<String>,
    pub list_id: Option<String>,
    /// `None` when the initiating page is unknown.
    pub third_party: Option<bool>,
}

#[derive(Clone)]
struct Stored {
    seq: u64,
    ts_ms: i64,
    url: Arc<str>,
    method: &'static str,
    request_type: &'static str,
    source_host: Arc<str>,
    kind: SessionKind,
    rule: Option<Arc<str>>,
    list_id: Option<Arc<str>>,
}

impl Stored {
    fn size(&self) -> usize {
        ENTRY_OVERHEAD + self.url.len()
    }
}

#[derive(Default)]
struct Ring {
    next: u64,
    entries: VecDeque<Stored>,
    strings: HashSet<Arc<str>>,
}

impl Ring {
    fn intern(&mut self, s: &str) -> Arc<str> {
        if let Some(a) = self.strings.get(s) {
            return a.clone();
        }
        if self.strings.len() >= INTERN_CAP {
            self.strings.clear();
        }
        let a: Arc<str> = Arc::from(s);
        self.strings.insert(a.clone());
        a
    }
}

#[derive(Default)]
struct Session {
    ring: Mutex<Ring>,
    /// Approximate bytes of the entries held.
    bytes: AtomicUsize,
    /// Last write, Unix millis.
    touched: AtomicI64,
}

pub struct SessionLog {
    sessions: DashMap<u64, Arc<Session>>,
    total: AtomicUsize,
    max_total: usize,
}

impl Default for SessionLog {
    fn default() -> Self {
        Self::with_max_bytes(MAX_TOTAL_BYTES)
    }
}

fn registrable(host: &str) -> String {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    psl::domain_str(&h).map_or(h.clone(), str::to_string)
}

fn truncate(s: &str, cap: usize) -> &str {
    if s.len() <= cap {
        return s;
    }
    let mut n = cap;
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
}

const METHODS: [&str; 8] = [
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "OTHER",
];
const TYPES: [&str; 15] = [
    "document",
    "subdocument",
    "stylesheet",
    "script",
    "image",
    "font",
    "media",
    "xhr",
    "fetch",
    "websocket",
    "ping",
    "csp_report",
    "object",
    "beacon",
    "other",
];

fn pick(list: &'static [&'static str], s: &str) -> &'static str {
    list.iter()
        .find(|c| c.eq_ignore_ascii_case(s))
        .copied()
        .unwrap_or(list[list.len() - 1])
}

/// Rules the proxy writes for requests it changed but let through.
const MODIFIED_TAGS: [&str; 3] = [
    "url rewritten",
    "tracking parameters stripped",
    "service worker neutralised",
];

fn kind_of(e: &EventRef<'_>) -> Option<SessionKind> {
    match e.action {
        EventAction::Blocked => Some(match e.outcome {
            Some(EventOutcome::Aborted) => SessionKind::Aborted,
            Some(EventOutcome::Redirected) => SessionKind::Redirected,
            Some(EventOutcome::Synthetic) | None => SessionKind::Blocked,
        }),
        EventAction::Allowed => Some(if MODIFIED_TAGS.contains(&e.rule) {
            SessionKind::Modified
        } else {
            SessionKind::Allowed
        }),
        _ => None,
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

impl SessionLog {
    pub fn with_max_bytes(max_total: usize) -> Self {
        Self {
            sessions: DashMap::new(),
            total: AtomicUsize::new(0),
            max_total,
        }
    }

    fn session(&self, id: u64) -> Arc<Session> {
        if let Some(s) = self.sessions.get(&id) {
            return s.clone();
        }
        if self.sessions.len() >= MAX_SESSIONS {
            let old = self
                .sessions
                .iter()
                .min_by_key(|s| s.touched.load(Ordering::Relaxed))
                .map(|s| *s.key());
            if let Some(old) = old {
                self.forget(old);
            }
        }
        self.sessions.entry(id).or_default().clone()
    }

    /// Record one event of `session` (blocks and allowed requests; tunnels and the proxy's own
    /// pages are not page requests and are skipped). `url` is the event's URL as it may be
    /// kept (query stripped unless the request log keeps queries).
    pub fn push(&self, session: u64, e: &EventRef<'_>, url: &str) {
        let Some(kind) = kind_of(e) else { return };
        if matches!(e.request_type, "tunnel" | "internal") || e.method == "CONNECT" {
            return;
        }
        let sess = self.session(session);
        let now = now_ms();
        let added;
        {
            let mut r = sess.ring.lock().unwrap_or_else(|p| p.into_inner());
            r.next += 1;
            let shown = !e.rule.is_empty() && !MODIFIED_TAGS.contains(&e.rule);
            let entry = Stored {
                seq: r.next,
                ts_ms: now,
                url: Arc::from(truncate(url, SESSION_URL_CAP)),
                method: pick(&METHODS, e.method),
                request_type: pick(&TYPES, e.request_type),
                source_host: r.intern(e.source_host),
                kind,
                rule: shown.then(|| r.intern(e.rule)),
                list_id: e.list_id.map(|l| r.intern(l)),
            };
            added = entry.size();
            r.entries.push_back(entry);
            let mut freed = 0;
            while r.entries.len() > SESSION_CAPACITY {
                freed += r.entries.pop_front().map_or(0, |o| o.size());
            }
            sess.bytes.fetch_add(added, Ordering::Relaxed);
            sess.bytes.fetch_sub(freed, Ordering::Relaxed);
            self.total.fetch_add(added, Ordering::Relaxed);
            self.total.fetch_sub(freed, Ordering::Relaxed);
        }
        sess.touched.store(now, Ordering::Relaxed);
        self.enforce_total();
    }

    /// Past the byte cap, drop the oldest entries of the heaviest session until under it.
    fn enforce_total(&self) {
        while self.total.load(Ordering::Relaxed) > self.max_total {
            let Some(victim) = self
                .sessions
                .iter()
                .max_by_key(|s| s.bytes.load(Ordering::Relaxed))
                .map(|s| s.value().clone())
            else {
                return;
            };
            let mut freed = 0;
            {
                let mut r = victim.ring.lock().unwrap_or_else(|p| p.into_inner());
                // Several at a time: one pass of the loop is a scan of the sessions.
                for _ in 0..16 {
                    match r.entries.pop_front() {
                        Some(o) => freed += o.size(),
                        None => break,
                    }
                }
            }
            if freed == 0 {
                return;
            }
            victim.bytes.fetch_sub(freed, Ordering::Relaxed);
            self.total.fetch_sub(freed, Ordering::Relaxed);
        }
    }

    /// Approximate bytes held across all sessions.
    pub fn total_bytes(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    /// The entries of `session` after `since` (oldest first, at most `limit`) and the sequence to
    /// pass next time. An unknown session has none. The lock is held only to copy the slice.
    pub fn since(&self, session: u64, since: u64, limit: usize) -> (Vec<SessionEntry>, u64) {
        let Some(sess) = self.sessions.get(&session).map(|s| s.clone()) else {
            return (Vec::new(), since);
        };
        let rows: Vec<Stored> = {
            let r = sess.ring.lock().unwrap_or_else(|p| p.into_inner());
            let start = r.entries.partition_point(|e| e.seq <= since);
            r.entries.iter().skip(start).take(limit).cloned().collect()
        };
        let next = rows.last().map_or(since, |e| e.seq);
        let out = rows
            .into_iter()
            .map(|e| {
                let third_party = (!e.source_host.is_empty()).then(|| {
                    registrable(crate::RequestMatcher::host_of(&e.url))
                        != registrable(&e.source_host)
                });
                SessionEntry {
                    seq: e.seq,
                    ts: Utc
                        .timestamp_millis_opt(e.ts_ms)
                        .single()
                        .unwrap_or_default(),
                    url: e.url.to_string(),
                    method: e.method.to_string(),
                    request_type: e.request_type.to_string(),
                    source_host: e.source_host.to_string(),
                    kind: e.kind,
                    rule: e.rule.as_deref().map(str::to_string),
                    list_id: e.list_id.as_deref().map(str::to_string),
                    third_party,
                }
            })
            .collect();
        (out, next)
    }

    /// Drop a session's entries (it closed).
    pub fn forget(&self, session: u64) {
        if let Some((_, s)) = self.sessions.remove(&session) {
            self.total
                .fetch_sub(s.bytes.load(Ordering::Relaxed), Ordering::Relaxed);
        }
    }
}

/// The process-wide log.
pub fn session_log() -> &'static SessionLog {
    static LOG: OnceLock<SessionLog> = OnceLock::new();
    LOG.get_or_init(SessionLog::default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventMode;

    fn ev<'a>(url: &'a str, action: EventAction, rule: &'a str) -> EventRef<'a> {
        EventRef {
            action,
            method: "GET",
            url,
            source_host: "page.test",
            request_type: "script",
            rule,
            list_id: None,
            client: None,
            status: None,
            mode: EventMode::Explicit,
            error_kind: None,
            cert_fp: None,
            outcome: None,
            session: None,
        }
    }

    #[test]
    fn sessions_are_isolated_and_paged_and_bounded() {
        let l = SessionLog::default();
        for i in 0..(SESSION_CAPACITY + 5) {
            let u = format!("https://a.test/{i}?q=1");
            l.push(1, &ev(&u, EventAction::Allowed, ""), &u);
        }
        l.push(
            2,
            &ev("https://b.test/x", EventAction::Blocked, "||b.test^"),
            "https://b.test/x",
        );
        let (all, next) = l.since(1, 0, usize::MAX);
        assert_eq!(all.len(), SESSION_CAPACITY);
        assert_eq!(all[0].seq, 6);
        assert!(all[0].url.ends_with("?q=1"));
        assert_eq!(next, (SESSION_CAPACITY + 5) as u64);
        let (page, n2) = l.since(1, 1000, 10);
        assert_eq!(page.len(), 5);
        assert_eq!(n2, next);
        assert_eq!(l.since(1, next, 10).0.len(), 0);
        let (two, _) = l.since(2, 0, 10);
        assert_eq!(two.len(), 1);
        assert_eq!(two[0].url, "https://b.test/x");
        assert!(l.since(3, 0, 10).0.is_empty());
    }

    fn put(l: &SessionLog, sid: u64, e: &EventRef<'_>) {
        l.push(sid, e, e.url);
    }

    #[test]
    fn kinds_and_third_party() {
        let l = SessionLog::default();
        put(
            &l,
            1,
            &ev("https://cdn.page.test/a.js", EventAction::Allowed, ""),
        );
        let mut e = ev("https://ads.test/a.js", EventAction::Blocked, "||ads.test^");
        put(&l, 1, &e);
        e.outcome = Some(EventOutcome::Aborted);
        put(&l, 1, &e);
        // The kind follows the outcome, not the rule text.
        let mut r = ev("https://x.test/a.js", EventAction::Blocked, "||x.test^");
        r.outcome = Some(EventOutcome::Redirected);
        put(&l, 1, &r);
        let mut plain = ev(
            "https://x.test/b.js",
            EventAction::Blocked,
            "||x.test^$redirect-looking",
        );
        plain.outcome = Some(EventOutcome::Synthetic);
        put(&l, 1, &plain);
        put(
            &l,
            1,
            &ev(
                "https://x.test/a?utm=1",
                EventAction::Allowed,
                "tracking parameters stripped",
            ),
        );
        let mut c = ev("https://x.test:443", EventAction::Allowed, "");
        c.method = "CONNECT";
        put(&l, 1, &c);
        let (v, _) = l.since(1, 0, 10);
        let kinds: Vec<_> = v.iter().map(|x| x.kind).collect();
        assert_eq!(
            kinds,
            [
                SessionKind::Allowed,
                SessionKind::Blocked,
                SessionKind::Aborted,
                SessionKind::Redirected,
                SessionKind::Blocked,
                SessionKind::Modified
            ]
        );
        assert_eq!(v[0].third_party, Some(false));
        assert_eq!(v[1].third_party, Some(true));
        assert_eq!(v[5].rule, None);
    }

    #[test]
    fn the_url_is_stored_as_given_so_a_stripped_query_stays_stripped() {
        let l = SessionLog::default();
        let e = ev(
            "https://a.test/p?token=secret#frag",
            EventAction::Allowed,
            "",
        );
        l.push(1, &e, "https://a.test/p");
        assert_eq!(l.since(1, 0, 10).0[0].url, "https://a.test/p");
    }

    #[test]
    fn total_memory_is_capped_by_evicting_the_oldest_of_the_heaviest_session() {
        let l = SessionLog::with_max_bytes(40_000);
        let u = format!("https://a.test/{}", "x".repeat(800));
        for _ in 0..200 {
            put(&l, 1, &ev(&u, EventAction::Allowed, ""));
        }
        put(&l, 2, &ev("https://b.test/", EventAction::Allowed, ""));
        assert!(l.total_bytes() <= 40_000, "{}", l.total_bytes());
        let (a, next) = l.since(1, 0, usize::MAX);
        assert!(a.len() < 200 && !a.is_empty());
        // The newest entries survive, the oldest went.
        assert_eq!(next, 200);
        assert!(a[0].seq > 1);
        // The small session is untouched.
        assert_eq!(l.since(2, 0, 10).0.len(), 1);
        l.forget(1);
        assert!(l.total_bytes() < 1000);
    }
}

//! Bounded rings of recent request events, plus a live broadcast, for the management API.
//!
//! Writers (the proxy request path) do one lock-free `ArrayQueue::force_push` per ring that
//! overwrites the oldest slot when full, and exactly one small allocation (plus one `Arc`): every
//! field of the event is packed into a single `Box<str>` built in a reused thread-local buffer.
//! The event is decoded into an owned [`RequestEvent`] (more allocations) only when someone is
//! subscribed to the broadcast. Readers ([`RequestLog::recent`], a cold path) drain the queue into
//! a bounded history under a mutex and decode on demand, so reading never blocks writers.
//!
//! Two rings are kept: every event (`recent_all`) and a blocked-only view (`recent`) so a flood of
//! allowed requests cannot evict the blocks the "recent blocked" endpoint reports.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use chrono::{DateTime, TimeZone, Utc};
use crossbeam::queue::ArrayQueue;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Default ring capacity.
pub const DEFAULT_CAPACITY: usize = 1000;
/// Longest URL stored, in bytes (cut at a character boundary).
pub const URL_CAP: usize = 512;
/// Broadcast buffer: a subscriber further behind than this gets a `Lagged` error.
pub const BROADCAST_CAPACITY: usize = 1024;

/// What happened to the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventAction {
    Allowed,
    Blocked,
    /// An opaque tunnel the proxy did not look inside.
    Passthrough,
    Error,
}

impl EventAction {
    fn code(self) -> u8 {
        self as u8
    }
    fn from_code(c: u8) -> Self {
        match c {
            0 => Self::Allowed,
            1 => Self::Blocked,
            2 => Self::Passthrough,
            _ => Self::Error,
        }
    }
}

/// Why an `Error` event happened, for clients that act on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// The client refused the certificate the proxy presented (a bad_certificate, unknown_ca,
    /// certificate_unknown or decrypt_error alert, or an immediate close after our
    /// certificate: what certificate-pinned apps do).
    ClientRejectedCert,
    UpstreamTimeout,
    UpstreamReset,
    /// TLS to the upstream server failed (handshake or certificate).
    UpstreamTls,
    Other,
}

impl ErrorKind {
    fn code(self) -> u8 {
        self as u8 + 1
    }
    fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            1 => Self::ClientRejectedCert,
            2 => Self::UpstreamTimeout,
            3 => Self::UpstreamReset,
            4 => Self::UpstreamTls,
            5 => Self::Other,
            _ => return None,
        })
    }
}

/// How a blocked request was carried out (`proxy.block_response`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcome {
    /// The request failed like a network error (HTTP/2 stream reset, HTTP/1 connection closed).
    Aborted,
    /// The requester got a well-formed answer (block page, blank frame, GIF, 204, redirect resource).
    Synthetic,
    /// A `$redirect` resource answered it (a synthetic answer; the API reports it as such).
    Redirected,
}

impl EventOutcome {
    fn code(self) -> u8 {
        self as u8 + 1
    }
    fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(Self::Aborted),
            2 => Some(Self::Synthetic),
            3 => Some(Self::Redirected),
            _ => None,
        }
    }
}

/// How the connection reached the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventMode {
    Explicit,
    Transparent,
}

/// One request the proxy saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEvent {
    pub ts: DateTime<Utc>,
    pub action: EventAction,
    /// HTTP method (`CONNECT` for tunnels; empty if unknown).
    pub method: String,
    /// Request URL, truncated to [`URL_CAP`] bytes.
    pub url: String,
    /// Host of the initiating page (empty if unknown).
    pub source_host: String,
    /// Opaque client / profile label passed by the caller.
    pub client: Option<String>,
    /// Adblock request type string as passed by the caller (`script`, `image`, ...).
    pub request_type: String,
    /// The matched rule text (`ip-list:<ip>` for IP-list blocks).
    pub rule: Option<String>,
    /// Source list of the rule, when known (domain-set hits).
    pub list_id: Option<String>,
    /// Upstream response status, when there was one.
    pub status: Option<u16>,
    pub mode: EventMode,
    /// Set on `Error` events.
    #[serde(default)]
    pub error_kind: Option<ErrorKind>,
    /// SHA-256 fingerprint (hex) of the upstream server certificate, for decrypted requests.
    #[serde(default)]
    pub cert_fp: Option<String>,
    /// How a block was carried out; set on blocks of requests the proxy judged itself.
    #[serde(default)]
    pub outcome: Option<EventOutcome>,
}

/// An event as broadcast to live subscribers: the decoded event plus its lowercased searchable
/// text, built once per event so each stream's text filter does no per-event allocation.
#[derive(Debug, Clone)]
pub struct LiveEvent {
    pub event: RequestEvent,
    /// Lowercase `url`, `source_host`, `method` and `rule`, newline-separated.
    pub haystack: String,
}

impl LiveEvent {
    fn new(event: RequestEvent) -> Self {
        let mut h = String::with_capacity(event.url.len() + event.source_host.len() + 32);
        for f in [&event.url, &event.source_host, &event.method]
            .into_iter()
            .chain(event.rule.as_ref())
        {
            h.extend(f.chars().flat_map(char::to_lowercase));
            h.push('\n');
        }
        Self { event, haystack: h }
    }
}

/// Borrowed form of an event, so recording does not allocate a struct.
#[derive(Debug, Clone, Copy)]
pub struct EventRef<'a> {
    pub action: EventAction,
    pub method: &'a str,
    pub url: &'a str,
    pub source_host: &'a str,
    pub request_type: &'a str,
    pub rule: &'a str,
    pub list_id: Option<&'a str>,
    pub client: Option<&'a str>,
    pub status: Option<u16>,
    pub mode: EventMode,
    pub error_kind: Option<ErrorKind>,
    pub cert_fp: Option<&'a str>,
    pub outcome: Option<EventOutcome>,
    /// The extension session the connection is bound to; the event also enters that session's
    /// log ([`crate::session_log`]).
    pub session: Option<u64>,
}

const FIELDS: usize = 8;

struct Raw {
    ts_ms: i64,
    text: Box<str>,
    /// End offset in `text` of each field: url, source, type, rule, list, client, method, cert fp.
    ends: [u32; FIELDS],
    has_list: bool,
    has_client: bool,
    has_cert_fp: bool,
    action: u8,
    /// 0 = none.
    status: u16,
    transparent: bool,
    /// 0 = none.
    error_kind: u8,
    /// 0 = none.
    outcome: u8,
}

impl Raw {
    fn decode(&self) -> RequestEvent {
        let field = |i: usize| {
            let s = if i == 0 { 0 } else { self.ends[i - 1] as usize };
            self.text[s..self.ends[i] as usize].to_string()
        };
        let rule = field(3);
        RequestEvent {
            ts: Utc
                .timestamp_millis_opt(self.ts_ms)
                .single()
                .unwrap_or_default(),
            action: EventAction::from_code(self.action),
            method: field(6),
            url: field(0),
            source_host: field(1),
            client: self.has_client.then(|| field(5)),
            request_type: field(2),
            rule: (!rule.is_empty()).then_some(rule),
            list_id: self.has_list.then(|| field(4)),
            status: (self.status != 0).then_some(self.status),
            mode: if self.transparent {
                EventMode::Transparent
            } else {
                EventMode::Explicit
            },
            error_kind: ErrorKind::from_code(self.error_kind),
            cert_fp: self.has_cert_fp.then(|| field(7)),
            outcome: EventOutcome::from_code(self.outcome),
        }
    }
}

thread_local! {
    static BUF: RefCell<String> = RefCell::new(String::with_capacity(1024));
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

/// One lock-free ring with a drained, bounded history for readers. The queue can be swapped for
/// one of another size ([`Ring::resize`]) while writers push and readers read.
struct Ring {
    /// Writers and readers share the lock; only a resize takes it exclusively, so a push can
    /// never land in a queue that is being replaced.
    queue: RwLock<ArrayQueue<Arc<Raw>>>,
    history: Mutex<VecDeque<Arc<Raw>>>,
    cap: AtomicUsize,
}

impl Ring {
    fn new(cap: usize) -> Self {
        Self {
            // `ArrayQueue` cannot be empty; a disabled ring keeps one slot and never pushes.
            queue: RwLock::new(ArrayQueue::new(cap.max(1))),
            history: Mutex::new(VecDeque::new()),
            cap: AtomicUsize::new(cap),
        }
    }

    fn push(&self, raw: Arc<Raw>) {
        // Overwrites the oldest event when full; the displaced event is dropped here.
        drop(
            self.queue
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .force_push(raw),
        );
    }

    /// Move everything queued into the history (oldest first), keeping the newest `cap`.
    fn drain_into(&self, h: &mut VecDeque<Arc<Raw>>, q: &ArrayQueue<Arc<Raw>>) {
        let cap = self.cap.load(Ordering::Relaxed);
        while let Some(e) = q.pop() {
            if h.len() >= cap {
                h.pop_front();
            }
            h.push_back(e);
        }
    }

    fn recent(&self, limit: usize) -> Vec<RequestEvent> {
        let mut h = self.history.lock().unwrap_or_else(|e| e.into_inner());
        let q = self.queue.read().unwrap_or_else(|e| e.into_inner());
        self.drain_into(&mut h, &q);
        h.iter().rev().take(limit).map(|r| r.decode()).collect()
    }

    /// Change the capacity, keeping the newest entries when it shrinks. No event is lost: the
    /// swap happens with writers excluded, and what was queued moves to the history first.
    fn resize(&self, cap: usize) {
        let mut h = self.history.lock().unwrap_or_else(|e| e.into_inner());
        let mut q = self.queue.write().unwrap_or_else(|e| e.into_inner());
        let old = std::mem::replace(&mut *q, ArrayQueue::new(cap.max(1)));
        // Drain under the larger limit so growing drops nothing, then cut to the new size.
        self.cap.fetch_max(cap, Ordering::Relaxed);
        self.drain_into(&mut h, &old);
        self.cap.store(cap, Ordering::Relaxed);
        while h.len() > cap {
            h.pop_front();
        }
    }
}

/// The rings and the live broadcast. Capacity 0 disables recording.
pub struct RequestLog {
    all: Ring,
    blocked: Ring,
    tx: broadcast::Sender<Arc<LiveEvent>>,
    cap: AtomicUsize,
    /// Keep the query string and fragment of recorded URLs (they can carry secrets such as
    /// tokens, so the default is to strip them before anything is stored).
    keep_query: AtomicBool,
}

/// Former name, kept for call sites that only record blocks.
pub type BlockLog = RequestLog;

/// `url` without its query string and fragment.
fn strip_query(url: &str) -> &str {
    url.find(['?', '#']).map_or(url, |i| &url[..i])
}

impl RequestLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            all: Ring::new(capacity),
            blocked: Ring::new(capacity),
            tx: broadcast::channel(BROADCAST_CAPACITY).0,
            cap: AtomicUsize::new(capacity),
            keep_query: AtomicBool::new(false),
        }
    }

    /// Store request URLs with their query string (off by default, see the field docs).
    pub fn set_keep_query(&self, keep: bool) {
        self.keep_query.store(keep, Ordering::Relaxed);
    }

    pub fn capacity(&self) -> usize {
        self.cap.load(Ordering::Relaxed)
    }

    /// Resize both rings live (0 disables recording). Shrinking keeps the newest entries;
    /// growing keeps all. The live broadcast is not touched.
    pub fn set_capacity(&self, capacity: usize) {
        self.all.resize(capacity);
        self.blocked.resize(capacity);
        self.cap.store(capacity, Ordering::Relaxed);
    }

    /// Live events from now on. A receiver that falls more than [`BROADCAST_CAPACITY`] behind
    /// gets `RecvError::Lagged`.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<LiveEvent>> {
        self.tx.subscribe()
    }

    /// Whether anyone is listening to the broadcast.
    pub fn has_subscribers(&self) -> bool {
        self.tx.receiver_count() > 0
    }

    /// Record a block (explicit mode, no method). Lock-free; one allocation plus the `Arc`.
    pub fn record(
        &self,
        url: &str,
        source_host: &str,
        request_type: &str,
        rule: &str,
        list_id: Option<&str>,
        client: Option<&str>,
    ) {
        self.record_event(&EventRef {
            action: EventAction::Blocked,
            method: "",
            url,
            source_host,
            request_type,
            rule,
            list_id,
            client,
            status: None,
            mode: EventMode::Explicit,
            error_kind: None,
            cert_fp: None,
            outcome: None,
            session: None,
        });
    }

    /// Record any event. Blocked events also enter the blocked-only ring.
    pub fn record_event(&self, e: &EventRef<'_>) {
        let url = if self.keep_query.load(Ordering::Relaxed) {
            e.url
        } else {
            strip_query(e.url)
        };
        // The extension's session log does not depend on the request log's capacity (which the
        // user may set to 0), and honours the same query setting.
        if let Some(sid) = e.session {
            crate::session_log::session_log().push(sid, e, url);
        }
        if self.capacity() == 0 {
            return;
        }
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64);
        let raw = BUF.with(|b| {
            let mut b = b.borrow_mut();
            b.clear();
            let mut ends = [0u32; FIELDS];
            let parts = [
                truncate(url, URL_CAP),
                truncate(e.source_host, 253),
                truncate(e.request_type, 32),
                truncate(e.rule, URL_CAP),
                e.list_id.unwrap_or(""),
                e.client.unwrap_or(""),
                truncate(e.method, 16),
                truncate(e.cert_fp.unwrap_or(""), 64),
            ];
            for (i, p) in parts.iter().enumerate() {
                b.push_str(p);
                ends[i] = b.len() as u32;
            }
            Arc::new(Raw {
                ts_ms,
                text: Box::from(b.as_str()),
                ends,
                has_list: e.list_id.is_some(),
                has_client: e.client.is_some(),
                has_cert_fp: e.cert_fp.is_some(),
                action: e.action.code(),
                status: e.status.unwrap_or(0),
                transparent: e.mode == EventMode::Transparent,
                error_kind: e.error_kind.map_or(0, ErrorKind::code),
                outcome: e.outcome.map_or(0, EventOutcome::code),
            })
        });
        if self.tx.receiver_count() > 0 {
            // Nobody subscribed: this decode (several allocations) is skipped entirely.
            let _ = self.tx.send(Arc::new(LiveEvent::new(raw.decode())));
        }
        if e.action == EventAction::Blocked {
            self.blocked.push(raw.clone());
        }
        self.all.push(raw);
    }

    /// The most recent blocked events, newest first, at most `limit`.
    pub fn recent(&self, limit: usize) -> Vec<RequestEvent> {
        self.blocked.recent(limit)
    }

    /// The most recent events of every action, newest first, at most `limit`.
    pub fn recent_all(&self, limit: usize) -> Vec<RequestEvent> {
        self.all.recent(limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_stored_without_query_or_fragment_unless_configured() {
        let log = RequestLog::new(4);
        log.record(
            "https://t.test/p?token=SECRET&a=1#frag",
            "s",
            "script",
            "r",
            None,
            None,
        );
        let url = &log.recent(1)[0].url;
        assert_eq!(url, "https://t.test/p");
        assert!(!url.contains("SECRET"));
        log.set_keep_query(true);
        log.record(
            "https://t.test/p?token=SECRET",
            "s",
            "script",
            "r",
            None,
            None,
        );
        assert_eq!(log.recent(1)[0].url, "https://t.test/p?token=SECRET");
    }

    #[test]
    fn newest_first_bounded_and_overwriting() {
        let log = RequestLog::new(3);
        for i in 0..5 {
            log.record(
                &format!("https://h/{i}"),
                "src.test",
                "script",
                "||h^",
                None,
                None,
            );
        }
        let ev = log.recent(10);
        let urls: Vec<_> = ev.iter().map(|e| e.url.as_str()).collect();
        assert_eq!(urls, ["https://h/4", "https://h/3", "https://h/2"]);
        assert_eq!(log.recent(1).len(), 1);
        // Reading does not consume: a second read sees the same events plus new ones.
        log.record("https://h/5", "", "image", "r", Some("list1"), Some("kid"));
        let ev = log.recent(10);
        assert_eq!(ev.len(), 3);
        assert_eq!(ev[0].list_id.as_deref(), Some("list1"));
        assert_eq!(ev[0].client.as_deref(), Some("kid"));
        assert_eq!(
            (ev[0].request_type.as_str(), ev[0].source_host.as_str()),
            ("image", "")
        );
        assert!(ev[1].list_id.is_none() && ev[1].client.is_none());
    }

    #[test]
    fn url_is_truncated_on_a_char_boundary() {
        let log = RequestLog::new(2);
        let url = format!("https://h/{}", "é".repeat(600));
        log.record(&url, "s", "t", "r", None, None);
        let e = &log.recent(1)[0];
        assert!(e.url.len() <= URL_CAP && url.starts_with(&e.url));
    }

    fn ev(action: EventAction, url: &str) -> EventRef<'_> {
        EventRef {
            action,
            method: "GET",
            url,
            source_host: "",
            request_type: "document",
            rule: "",
            list_id: None,
            client: Some("1"),
            status: Some(200),
            mode: EventMode::Transparent,
            error_kind: None,
            cert_fp: None,
            outcome: None,
            session: None,
        }
    }

    #[test]
    fn allowed_events_skip_the_blocked_view_but_fill_the_full_ring() {
        let log = RequestLog::new(3);
        log.record_event(&ev(EventAction::Allowed, "https://a/1"));
        log.record("https://b/2", "", "image", "||b^", None, None);
        log.record_event(&ev(EventAction::Allowed, "https://a/3"));
        log.record_event(&ev(EventAction::Allowed, "https://a/4"));
        // The blocked view survives a flood of allowed events.
        let b = log.recent(10);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].rule.as_deref(), Some("||b^"));
        let all = log.recent_all(10);
        let urls: Vec<_> = all.iter().map(|e| e.url.as_str()).collect();
        assert_eq!(urls, ["https://a/4", "https://a/3", "https://b/2"]);
        let a = &all[0];
        assert_eq!(
            (a.action, a.status, a.mode, a.method.as_str()),
            (
                EventAction::Allowed,
                Some(200),
                EventMode::Transparent,
                "GET"
            )
        );
        assert!(a.rule.is_none());
    }

    fn urls(v: Vec<RequestEvent>) -> Vec<String> {
        v.into_iter().map(|e| e.url).collect()
    }

    #[test]
    fn shrinking_keeps_the_newest_and_growing_keeps_everything() {
        let log = RequestLog::new(5);
        for i in 0..5 {
            log.record(&format!("https://h/{i}"), "", "script", "r", None, None);
        }
        // Some entries drained into history, some still queued.
        assert_eq!(log.recent(2).len(), 2);
        log.record("https://h/5", "", "script", "r", None, None);
        log.set_capacity(2);
        assert_eq!(log.capacity(), 2);
        assert_eq!(urls(log.recent(10)), ["https://h/5", "https://h/4"]);
        assert_eq!(urls(log.recent_all(10)), ["https://h/5", "https://h/4"]);
        // Grow: nothing is lost, and the new room is used.
        log.set_capacity(4);
        assert_eq!(urls(log.recent(10)), ["https://h/5", "https://h/4"]);
        for i in 6..9 {
            log.record(&format!("https://h/{i}"), "", "script", "r", None, None);
        }
        assert_eq!(
            urls(log.recent(10)),
            ["https://h/8", "https://h/7", "https://h/6", "https://h/5"]
        );
    }

    #[test]
    fn resize_keeps_the_broadcast_and_survives_concurrent_writers() {
        let log = Arc::new(RequestLog::new(8));
        let mut rx = log.subscribe();
        let writers: Vec<_> = (0..4)
            .map(|t| {
                let log = log.clone();
                std::thread::spawn(move || {
                    for i in 0..500 {
                        log.record(&format!("https://h/{t}/{i}"), "", "script", "r", None, None);
                    }
                })
            })
            .collect();
        for n in [3, 50, 1, 20, 8] {
            log.set_capacity(n);
            assert!(log.recent_all(100).len() <= n);
        }
        for w in writers {
            w.join().unwrap();
        }
        assert_eq!(log.capacity(), 8);
        assert!(log.recent_all(100).len() <= 8);
        log.record("https://h/last", "", "script", "r", None, None);
        assert_eq!(log.recent_all(1)[0].url, "https://h/last");
        // The stream saw events across the resizes (it may have lagged, never closed).
        let mut got = 0;
        loop {
            match rx.try_recv() {
                Ok(_) => got += 1,
                Err(broadcast::error::TryRecvError::Lagged(_)) => {}
                Err(_) => break,
            }
        }
        assert!(got > 0);
    }

    #[test]
    fn concurrent_resizes_lose_no_event() {
        use std::collections::HashSet;
        const TOTAL: usize = 4 * 500;
        // Grow-only resizes with room for everything: every pushed event must be present.
        let log = Arc::new(RequestLog::new(3000));
        let writers: Vec<_> = (0..4)
            .map(|t| {
                let log = log.clone();
                std::thread::spawn(move || {
                    for i in 0..500 {
                        log.record(&format!("https://h/{t}/{i}"), "", "script", "r", None, None);
                    }
                })
            })
            .collect();
        for n in [4000, 5000, 100_000, 200_000] {
            log.set_capacity(n);
            std::thread::yield_now();
        }
        for w in writers {
            w.join().unwrap();
        }
        let all = urls(log.recent_all(usize::MAX));
        assert_eq!(all.len(), TOTAL);
        assert_eq!(all.iter().collect::<HashSet<_>>().len(), TOTAL);
        // Shrinking afterwards keeps exactly min(cap, total).
        log.set_capacity(300);
        assert_eq!(log.recent_all(usize::MAX).len(), 300.min(TOTAL));
    }

    #[test]
    fn broadcast_reaches_subscribers_and_reports_lag() {
        let log = RequestLog::new(4);
        assert!(!log.has_subscribers());
        log.record_event(&ev(EventAction::Allowed, "https://before/")); // no subscriber: not sent
        let mut rx = log.subscribe();
        log.record_event(&ev(EventAction::Passthrough, "https://a/"));
        let got = rx.try_recv().unwrap();
        assert_eq!(got.event.action, EventAction::Passthrough);
        assert!(got.haystack.contains("https://a/"));
        for i in 0..BROADCAST_CAPACITY + 10 {
            log.record_event(&ev(EventAction::Allowed, &format!("https://h/{i}")));
        }
        assert!(matches!(
            rx.try_recv(),
            Err(broadcast::error::TryRecvError::Lagged(n)) if n >= 10
        ));
        // After the lag notice the receiver continues with the oldest retained event.
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn disabled_log_records_nothing() {
        let log = RequestLog::new(0);
        log.record("u", "s", "t", "r", None, None);
        assert!(log.recent(5).is_empty());
    }

    #[test]
    fn concurrent_writers_do_not_exceed_capacity() {
        let log = std::sync::Arc::new(RequestLog::new(50));
        let hs: Vec<_> = (0..4)
            .map(|t| {
                let l = log.clone();
                std::thread::spawn(move || {
                    for i in 0..1000 {
                        l.record(&format!("https://h/{t}/{i}"), "s", "t", "r", None, None);
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(log.recent(1000).len(), 50);
    }
}

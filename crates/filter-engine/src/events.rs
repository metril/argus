//! Bounded ring of recent block events for the management API.
//!
//! Writers (the proxy request path) do one lock-free `ArrayQueue::force_push` that overwrites the
//! oldest slot when full, and exactly one small allocation: every field of the event is packed
//! into a single `Box<str>` built in a reused thread-local buffer. Allowed requests never touch
//! it. Readers ([`BlockLog::recent`], a cold path) drain the queue into a bounded history under a
//! mutex and decode on demand, so reading never blocks writers.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use chrono::{DateTime, TimeZone, Utc};
use crossbeam::queue::ArrayQueue;
use serde::{Deserialize, Serialize};

/// Default ring capacity.
pub const DEFAULT_CAPACITY: usize = 1000;
/// Longest URL stored, in bytes (cut at a character boundary).
pub const URL_CAP: usize = 512;

/// One blocked request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockEvent {
    pub timestamp: DateTime<Utc>,
    /// Request URL, truncated to [`URL_CAP`] bytes.
    pub url: String,
    /// Host of the initiating page (empty if unknown).
    pub source_host: String,
    /// Adblock request type string as passed by the caller (`script`, `image`, ...).
    pub request_type: String,
    /// The matched rule text (`ip-list:<ip>` for IP-list blocks).
    pub rule: String,
    /// Source list of the rule, when known (domain-set hits).
    pub list_id: Option<String>,
    /// Opaque client / profile label passed by the caller.
    pub client: Option<String>,
}

const FIELDS: usize = 6;

struct Raw {
    ts_ms: i64,
    text: Box<str>,
    /// End offset in `text` of each field: url, source, type, rule, list, client.
    ends: [u32; FIELDS],
    has_list: bool,
    has_client: bool,
}

impl Raw {
    fn decode(&self) -> BlockEvent {
        let field = |i: usize| {
            let s = if i == 0 { 0 } else { self.ends[i - 1] as usize };
            self.text[s..self.ends[i] as usize].to_string()
        };
        BlockEvent {
            timestamp: Utc
                .timestamp_millis_opt(self.ts_ms)
                .single()
                .unwrap_or_default(),
            url: field(0),
            source_host: field(1),
            request_type: field(2),
            rule: field(3),
            list_id: self.has_list.then(|| field(4)),
            client: self.has_client.then(|| field(5)),
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

/// The ring. Capacity 0 disables recording.
pub struct BlockLog {
    queue: ArrayQueue<Raw>,
    history: Mutex<VecDeque<Raw>>,
    cap: usize,
    /// Keep the query string and fragment of recorded URLs (they can carry secrets such as
    /// tokens, so the default is to strip them before anything is stored).
    keep_query: AtomicBool,
}

/// `url` without its query string and fragment.
fn strip_query(url: &str) -> &str {
    url.find(['?', '#']).map_or(url, |i| &url[..i])
}

impl BlockLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            // `ArrayQueue` cannot be empty; a disabled log keeps one slot and never pushes.
            queue: ArrayQueue::new(capacity.max(1)),
            history: Mutex::new(VecDeque::new()),
            cap: capacity,
            keep_query: AtomicBool::new(false),
        }
    }

    /// Store request URLs with their query string (off by default, see the field docs).
    pub fn set_keep_query(&self, keep: bool) {
        self.keep_query.store(keep, Ordering::Relaxed);
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Record a block. Lock-free; one allocation (the packed event text).
    pub fn record(
        &self,
        url: &str,
        source_host: &str,
        request_type: &str,
        rule: &str,
        list_id: Option<&str>,
        client: Option<&str>,
    ) {
        if self.cap == 0 {
            return;
        }
        let url = if self.keep_query.load(Ordering::Relaxed) {
            url
        } else {
            strip_query(url)
        };
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64);
        let raw = BUF.with(|b| {
            let mut b = b.borrow_mut();
            b.clear();
            let mut ends = [0u32; FIELDS];
            let parts = [
                truncate(url, URL_CAP),
                truncate(source_host, 253),
                truncate(request_type, 32),
                truncate(rule, URL_CAP),
                list_id.unwrap_or(""),
                client.unwrap_or(""),
            ];
            for (i, p) in parts.iter().enumerate() {
                b.push_str(p);
                ends[i] = b.len() as u32;
            }
            Raw {
                ts_ms,
                text: Box::from(b.as_str()),
                ends,
                has_list: list_id.is_some(),
                has_client: client.is_some(),
            }
        });
        // Overwrites the oldest event when full; the displaced event is dropped here.
        drop(self.queue.force_push(raw));
    }

    /// The most recent events, newest first, at most `limit`.
    pub fn recent(&self, limit: usize) -> Vec<BlockEvent> {
        let mut h = self.history.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(e) = self.queue.pop() {
            if h.len() >= self.cap {
                h.pop_front();
            }
            h.push_back(e);
        }
        h.iter().rev().take(limit).map(Raw::decode).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_stored_without_query_or_fragment_unless_configured() {
        let log = BlockLog::new(4);
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
        let log = BlockLog::new(3);
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
        let log = BlockLog::new(2);
        let url = format!("https://h/{}", "é".repeat(600));
        log.record(&url, "s", "t", "r", None, None);
        let e = &log.recent(1)[0];
        assert!(e.url.len() <= URL_CAP && url.starts_with(&e.url));
    }

    #[test]
    fn disabled_log_records_nothing() {
        let log = BlockLog::new(0);
        log.record("u", "s", "t", "r", None, None);
        assert!(log.recent(5).is_empty());
    }

    #[test]
    fn concurrent_writers_do_not_exceed_capacity() {
        let log = std::sync::Arc::new(BlockLog::new(50));
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

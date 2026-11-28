//! Cookie provenance: which response set which cookie, and what a `$cookie` rule did to it, for
//! the browsers that use the Argus extension. Opt-in (`privacy.cookie_provenance`), memory only.
//!
//! What is kept: the cookie's NAME, the response's host and path (never the query), the page
//! host, the attributes the server sent, and the effect. A cookie's VALUE never leaves
//! [`parse_set_cookie`]: it is not copied, stored, logged or hashed, and the type that carries a
//! parsed cookie has no field that could hold one.
//!
//! Hot path: with the setting off the callers do one atomic load and stop. With it on, a response
//! without `Set-Cookie` costs nothing more; each `Set-Cookie` is parsed once outside any lock and
//! pushed under its own session's lock.
//!
//! Sequence numbers come from one process-wide counter and are allocated under the ring's lock, so
//! a ring is always in increasing order and a reader that passes the `next_since` it was given
//! never misses or repeats a record. Rings are per extension session, never visible to another
//! one, bounded in records and bytes, dropped when the session ends and emptied when the setting
//! is turned off.
//!
//! Sessions are registered with [`CookieLog::open`] when the extension hub creates them and
//! dropped with [`CookieLog::forget`] when it closes them; recording never creates a ring, so a
//! response still in flight (or a keep-alive connection still bound to the id) after the session
//! closed records nothing.
//!
//! Memory: every record owns its strings (nothing is shared or interned) and [`Stored::size`]
//! counts the record struct, every string and vector capacity plus a per-allocation allowance, so
//! `RING_BYTES` is the real heap a session's records hold. A ring also keeps at most
//! `RING_CAPACITY` records, whose `VecDeque` can have grown to 4096 slots: at most 1096 unused
//! slots of `size_of::<Stored>()` (under 400 bytes, asserted by a test) are not counted. Worst
//! case per session is therefore under 2.5 MB, at most `MAX_SESSIONS` sessions hold records at a
//! time (the least recently written is emptied beyond that), so the whole log stays under 80 MB
//! however many sessions are open.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use chrono::{DateTime, TimeZone, Utc};
use dashmap::DashMap;

/// Records kept per session.
pub const RING_CAPACITY: usize = 3000;
/// Approximate bytes kept per session.
pub const RING_BYTES: usize = 2 * 1024 * 1024;
/// Sessions that may hold records at once; the least recently written one is emptied beyond this.
pub const MAX_SESSIONS: usize = 32;
/// Most of a `Set-Cookie` header that is parsed.
const PARSE_CAP: usize = 16 * 1024;
const NAME_CAP: usize = 256;
const ATTR_CAP: usize = 256;
const PATH_CAP: usize = 512;
const HOST_CAP: usize = 253;
const RULE_CAP: usize = 512;
/// Allowance counted per heap allocation (allocator header and rounding).
const ALLOC_OVERHEAD: usize = 16;
const LIST_CAP: usize = 128;

/// What happened to one cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// The response's `Set-Cookie` went through unchanged.
    Set,
    /// A `$cookie` rule changed attributes.
    Changed,
    /// A `$cookie` rule removed the `Set-Cookie`.
    Stripped,
    /// A `$cookie` rule removed the cookie from the request's `Cookie` header.
    BlockedSend,
}

impl Effect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::Changed => "changed",
            Self::Stripped => "stripped",
            Self::BlockedSend => "blocked_send",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    None,
    Lax,
    Strict,
}

impl SameSite {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Lax => "lax",
            Self::Strict => "strict",
        }
    }
}

/// The attributes of a `Set-Cookie` as the server sent them. Never a value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attrs {
    /// Lowercase, without a leading dot.
    pub domain: Option<String>,
    /// Only when it starts with `/` (anything else is ignored by browsers).
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<SameSite>,
    /// Seconds; zero or negative expires the cookie.
    pub max_age: Option<i64>,
    /// Seconds since the epoch.
    pub expires: Option<i64>,
    pub partitioned: bool,
}

/// A parsed `Set-Cookie`: the name and the attributes; the value is dropped at parse time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub name: String,
    pub attrs: Attrs,
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

/// RFC 6265 section 5.1.1 date (`Wed, 21 Oct 2099 07:28:00 GMT`, `Wed, 21-Oct-99 07:28:00 GMT`,
/// ...) as seconds since the epoch.
pub fn parse_cookie_date(s: &str) -> Option<i64> {
    let is_delim = |c: char| matches!(c, '\t' | ' '..='/' | ';'..='@' | '['..='`' | '{'..='~');
    let (mut time, mut day, mut month, mut year) = (None, None, None, None);
    for tok in s.split(is_delim).filter(|t| !t.is_empty()) {
        if time.is_none() {
            let mut p = tok.splitn(3, ':');
            if let (Some(h), Some(m), Some(sec)) = (p.next(), p.next(), p.next()) {
                let digits = |x: &str, n: usize| {
                    let d: String = x.chars().take_while(char::is_ascii_digit).collect();
                    (!d.is_empty() && d.len() <= n && x.len() >= d.len())
                        .then(|| d.parse::<u32>().ok())
                        .flatten()
                };
                if let (Some(h), Some(m), Some(sec)) = (digits(h, 2), digits(m, 2), digits(sec, 2))
                {
                    time = Some((h, m, sec));
                    continue;
                }
            }
        }
        if day.is_none() {
            let d: String = tok.chars().take_while(char::is_ascii_digit).collect();
            if (1..=2).contains(&d.len()) {
                day = d.parse::<u32>().ok();
                continue;
            }
        }
        if month.is_none() && tok.len() >= 3 && tok.is_char_boundary(3) {
            const M: [&str; 12] = [
                "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
            ];
            if let Some(i) = M.iter().position(|m| tok[..3].eq_ignore_ascii_case(m)) {
                month = Some(i as u32 + 1);
                continue;
            }
        }
        if year.is_none() {
            let d: String = tok.chars().take_while(char::is_ascii_digit).collect();
            if (2..=4).contains(&d.len()) {
                year = d.parse::<i32>().ok();
            }
        }
    }
    let ((h, mi, sec), day, month, mut year) = (time?, day?, month?, year?);
    if (70..=99).contains(&year) {
        year += 1900;
    } else if (0..=69).contains(&year) {
        year += 2000;
    }
    if year < 1601 || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    let d = chrono::NaiveDate::from_ymd_opt(year, month, day)?;
    Some(d.and_hms_opt(h, mi, sec)?.and_utc().timestamp())
}

/// Parse one `Set-Cookie` header line. The value is skipped, not copied. `None` for a line a
/// browser would refuse outright (no name and no value). Browsers do not treat quotes specially,
/// so the first `;` ends the pair and the first `=` ends the name.
pub fn parse_set_cookie(raw: &[u8]) -> Option<Parsed> {
    let text = String::from_utf8_lossy(&raw[..raw.len().min(PARSE_CAP)]);
    let mut parts = text.split(';');
    let first = parts.next().unwrap_or("");
    let name = match first.split_once('=') {
        Some((n, v)) if n.trim().is_empty() && v.trim().is_empty() => return None,
        Some((n, _)) => n.trim(),
        // `value` without `=`: browsers take it as a cookie with an empty name.
        None if first.trim().is_empty() => return None,
        None => "",
    };
    let mut a = Attrs::default();
    for part in parts {
        let (k, v) = match part.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (part.trim(), ""),
        };
        // Duplicates: the last one wins, as in browsers.
        if k.eq_ignore_ascii_case("domain") {
            let d = v.trim_start_matches('.').to_ascii_lowercase();
            a.domain = (!d.is_empty()).then(|| truncate(&d, ATTR_CAP).to_string());
        } else if k.eq_ignore_ascii_case("path") {
            a.path = v
                .starts_with('/')
                .then(|| truncate(v, PATH_CAP).to_string());
        } else if k.eq_ignore_ascii_case("secure") {
            a.secure = true;
        } else if k.eq_ignore_ascii_case("httponly") {
            a.http_only = true;
        } else if k.eq_ignore_ascii_case("partitioned") {
            a.partitioned = true;
        } else if k.eq_ignore_ascii_case("samesite") {
            a.same_site = match v.to_ascii_lowercase().as_str() {
                "none" => Some(SameSite::None),
                "lax" => Some(SameSite::Lax),
                "strict" => Some(SameSite::Strict),
                _ => None,
            };
        } else if k.eq_ignore_ascii_case("max-age") {
            let digits = v.strip_prefix('-').unwrap_or(v);
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                let n = digits.parse::<i64>().unwrap_or(i64::MAX);
                a.max_age = Some(if v.starts_with('-') { -n } else { n });
            }
        } else if k.eq_ignore_ascii_case("expires") {
            a.expires = parse_cookie_date(v);
        }
    }
    Some(Parsed {
        name: truncate(name, NAME_CAP).to_string(),
        attrs: a,
    })
}

/// The `__Host-` / `__Secure-` prefix of a name and whether the attributes meet what it implies
/// (`Secure`; for `__Host-` also no `Domain` and `Path=/`).
pub fn prefix_facts(name: &str, a: &Attrs) -> Option<(&'static str, bool)> {
    let starts = |p: &str| {
        name.len() >= p.len()
            && name.is_char_boundary(p.len())
            && name[..p.len()].eq_ignore_ascii_case(p)
    };
    if starts("__Host-") {
        Some((
            "__Host-",
            a.secure && a.domain.is_none() && a.path.as_deref() == Some("/"),
        ))
    } else if starts("__Secure-") {
        Some(("__Secure-", a.secure))
    } else {
        None
    }
}

/// One attribute a rule changed, old to new (`None`: absent), and the rule whose value is the
/// final one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// `max_age`, `expires` or `same_site`.
    pub attr: &'static str,
    pub from: Option<String>,
    pub to: Option<String>,
    pub rule: Option<String>,
    pub list_id: Option<String>,
}

/// A rule and its list.
#[derive(Debug, Clone, Copy)]
pub struct Source<'a> {
    pub rule: &'a str,
    pub list_id: Option<&'a str>,
}

/// A `$cookie` rule that touched a `Set-Cookie` line of the response.
#[derive(Debug, Clone, Copy)]
pub struct Touch<'a> {
    /// Position among the visible-ASCII `Set-Cookie` lines (see [`CookieLog::record_response`]).
    pub index: usize,
    pub stripped: bool,
    /// The rule that removed the line; for a changed line, the rule of its first changed attribute.
    pub rule: &'a str,
    pub list_id: Option<&'a str>,
    /// What a rule set (changed lines only) and the rule whose value won.
    pub max_age: Option<(u64, Source<'a>)>,
    pub same_site: Option<(SameSite, Source<'a>)>,
}

/// The request a record belongs to.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    pub host: &'a str,
    /// Path without the query string.
    pub path: &'a str,
    /// Host of the page that made the request (the request's own host for a document); `""`
    /// when unknown.
    pub page_host: &'a str,
}

/// A record as read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieRecord {
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub effect: Effect,
    pub name: String,
    pub host: String,
    pub path: String,
    pub page_host: String,
    /// Whether the response host is on another registrable domain than the page; `None` when the
    /// page is unknown.
    pub third_party: Option<bool>,
    pub attrs: Attrs,
    pub changes: Vec<Change>,
    /// `__Host-` / `__Secure-` and whether the attributes satisfy it.
    pub prefix: Option<(&'static str, bool)>,
    pub rule: Option<String>,
    pub list_id: Option<String>,
}

struct Observed {
    name: String,
    attrs: Attrs,
    effect: Effect,
    changes: Vec<Change>,
    rule: Option<String>,
    list_id: Option<String>,
}

#[derive(Debug, Clone)]
struct Stored {
    seq: u64,
    ts_ms: i64,
    effect: Effect,
    name: String,
    host: String,
    path: String,
    page_host: String,
    attrs: Attrs,
    changes: Vec<Change>,
    rule: Option<String>,
    list_id: Option<String>,
}

fn heap(s: &String) -> usize {
    if s.capacity() == 0 {
        0
    } else {
        s.capacity() + ALLOC_OVERHEAD
    }
}

fn heap_opt(s: &Option<String>) -> usize {
    s.as_ref().map_or(0, heap)
}

impl Stored {
    /// Everything this record keeps alive: the struct, each string and the changes vector.
    fn size(&self) -> usize {
        let a = &self.attrs;
        std::mem::size_of::<Self>()
            + heap(&self.name)
            + heap(&self.host)
            + heap(&self.path)
            + heap(&self.page_host)
            + heap_opt(&self.rule)
            + heap_opt(&self.list_id)
            + heap_opt(&a.domain)
            + heap_opt(&a.path)
            + if self.changes.capacity() == 0 {
                0
            } else {
                self.changes.capacity() * std::mem::size_of::<Change>() + ALLOC_OVERHEAD
            }
            + self
                .changes
                .iter()
                .map(|c| {
                    heap_opt(&c.from) + heap_opt(&c.to) + heap_opt(&c.rule) + heap_opt(&c.list_id)
                })
                .sum::<usize>()
    }
}

#[derive(Default, Debug)]
struct Ring {
    last: u64,
    bytes: usize,
    entries: VecDeque<Stored>,
}

#[derive(Default)]
struct Session {
    ring: Mutex<Ring>,
    /// The ring has held records since it was last emptied (counted against `MAX_SESSIONS`).
    used: AtomicBool,
    /// Last write, Unix millis.
    touched: AtomicI64,
}

#[derive(Default)]
pub struct CookieLog {
    sessions: DashMap<u64, Arc<Session>>,
    seq: AtomicU64,
}

/// Debug shows what the rings hold (so a test can prove no value is in there).
impl fmt::Debug for CookieLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut m = f.debug_map();
        for s in self.sessions.iter() {
            let r = s.ring.lock().unwrap_or_else(|p| p.into_inner());
            m.entry(s.key(), &*r);
        }
        m.finish()
    }
}

fn registrable(host: &str) -> String {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    psl::domain_str(&h).map_or(h.clone(), str::to_string)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

fn changes_of(a: &Attrs, t: &Touch<'_>) -> Vec<Change> {
    let mut out = Vec::new();
    let own = |s: &Source<'_>| {
        (
            Some(truncate(s.rule, RULE_CAP).to_string()),
            s.list_id.map(|l| truncate(l, LIST_CAP).to_string()),
        )
    };
    if let Some((m, src)) = &t.max_age {
        let to = (*m as i64).to_string();
        let (rule, list_id) = own(src);
        if a.max_age.map(|v| v.to_string()).as_deref() != Some(&to) {
            out.push(Change {
                attr: "max_age",
                from: a.max_age.map(|v| v.to_string()),
                to: Some(to),
                rule: rule.clone(),
                list_id: list_id.clone(),
            });
        }
        // A rewritten Max-Age drops Expires.
        if let Some(e) = a.expires {
            out.push(Change {
                attr: "expires",
                from: Some(e.to_string()),
                to: None,
                rule,
                list_id,
            });
        }
    }
    if let Some((s, src)) = &t.same_site {
        if a.same_site != Some(*s) {
            let (rule, list_id) = own(src);
            out.push(Change {
                attr: "same_site",
                from: a.same_site.map(|v| v.as_str().to_string()),
                to: Some(s.as_str().to_string()),
                rule,
                list_id,
            });
        }
    }
    out
}

impl CookieLog {
    /// Register a live session. Idempotent. Only registered sessions are recorded.
    pub fn open(&self, id: u64) {
        self.sessions.entry(id).or_default();
    }

    /// Empty the least recently written rings beyond `MAX_SESSIONS` that hold records, never
    /// `keep`.
    fn limit_used(&self, keep: u64) {
        loop {
            let used: Vec<(u64, i64, Arc<Session>)> = self
                .sessions
                .iter()
                .filter(|s| s.used.load(Ordering::Relaxed))
                .map(|s| {
                    (
                        *s.key(),
                        s.touched.load(Ordering::Relaxed),
                        s.value().clone(),
                    )
                })
                .collect();
            if used.len() <= MAX_SESSIONS {
                return;
            }
            let Some((_, _, old)) = used
                .into_iter()
                .filter(|(id, _, _)| *id != keep)
                .min_by_key(|(_, t, _)| *t)
            else {
                return;
            };
            let mut r = old.ring.lock().unwrap_or_else(|p| p.into_inner());
            *r = Ring::default();
            old.used.store(false, Ordering::Relaxed);
        }
    }

    /// Record the `Set-Cookie` lines of one response of `session`. `lines` yields each line's
    /// bytes and whether it is visible ASCII (what `HeaderValue::to_str` accepts: the lines
    /// the rules saw); `touches` index those. Does nothing when `on` is off.
    pub fn record_response<'a>(
        &self,
        on: &AtomicBool,
        session: u64,
        cx: &Context<'_>,
        lines: impl Iterator<Item = (&'a [u8], bool)>,
        touches: &[Touch<'_>],
    ) {
        if !on.load(Ordering::Relaxed) {
            return;
        }
        let mut obs = Vec::new();
        let mut visible = 0usize;
        for (raw, vis) in lines {
            let idx = vis.then(|| {
                visible += 1;
                visible - 1
            });
            let Some(p) = parse_set_cookie(raw) else {
                continue;
            };
            let touch = idx.and_then(|i| touches.iter().find(|t| t.index == i));
            let (effect, changes, rule, list_id) = match touch {
                Some(t) if t.stripped => (Effect::Stripped, Vec::new(), Some(t.rule), t.list_id),
                Some(t) => {
                    let ch = changes_of(&p.attrs, t);
                    if ch.is_empty() {
                        (Effect::Set, ch, None, None)
                    } else {
                        (Effect::Changed, ch, Some(t.rule), t.list_id)
                    }
                }
                None => (Effect::Set, Vec::new(), None, None),
            };
            obs.push(Observed {
                name: p.name,
                attrs: p.attrs,
                effect,
                changes,
                rule: rule.map(|r| truncate(r, RULE_CAP).to_string()),
                list_id: list_id.map(|l| truncate(l, LIST_CAP).to_string()),
            });
        }
        self.push(on, session, cx, obs);
    }

    /// Record cookies a `$cookie` rule removed from a request's `Cookie` header: the name, the
    /// rule text and its list. Does nothing when `on` is off.
    pub fn record_blocked_send(
        &self,
        on: &AtomicBool,
        session: u64,
        cx: &Context<'_>,
        drops: &[(&str, &str, Option<&str>)],
    ) {
        if !on.load(Ordering::Relaxed) || drops.is_empty() {
            return;
        }
        let obs = drops
            .iter()
            .map(|(name, rule, list)| Observed {
                name: truncate(name, NAME_CAP).to_string(),
                attrs: Attrs::default(),
                effect: Effect::BlockedSend,
                changes: Vec::new(),
                rule: Some(truncate(rule, RULE_CAP).to_string()),
                list_id: list.map(|l| truncate(l, LIST_CAP).to_string()),
            })
            .collect();
        self.push(on, session, cx, obs);
    }

    fn push(&self, on: &AtomicBool, session: u64, cx: &Context<'_>, obs: Vec<Observed>) {
        if obs.is_empty() {
            return;
        }
        // Never creates a ring: a session the hub closed (or never opened) records nothing.
        let Some(sess) = self.sessions.get(&session).map(|s| s.clone()) else {
            return;
        };
        let now = now_ms();
        let host = truncate(&cx.host.to_ascii_lowercase(), HOST_CAP).to_string();
        let path = truncate(cx.path, PATH_CAP).to_string();
        let page_host = truncate(&cx.page_host.to_ascii_lowercase(), HOST_CAP).to_string();
        let first = !sess.used.swap(true, Ordering::Relaxed);
        {
            let mut r = sess.ring.lock().unwrap_or_else(|p| p.into_inner());
            // Re-checked under the lock: a switch-off that already emptied this ring cannot be
            // refilled by a response that was in flight.
            if !on.load(Ordering::Relaxed) {
                return;
            }
            for o in obs {
                let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
                let rec = Stored {
                    seq,
                    ts_ms: now,
                    effect: o.effect,
                    name: o.name,
                    host: host.clone(),
                    path: path.clone(),
                    page_host: page_host.clone(),
                    attrs: o.attrs,
                    changes: o.changes,
                    rule: o.rule,
                    list_id: o.list_id,
                };
                r.last = seq;
                r.bytes += rec.size();
                r.entries.push_back(rec);
            }
            while r.entries.len() > RING_CAPACITY || r.bytes > RING_BYTES {
                match r.entries.pop_front() {
                    Some(o) => r.bytes -= o.size(),
                    None => break,
                }
            }
        }
        sess.touched.store(now, Ordering::Relaxed);
        if first {
            self.limit_used(session);
        }
    }

    /// The records of `session` after `since`, oldest first, at most `limit`, optionally only
    /// those of `host` (a site: its registrable domain and every subdomain), and the value to
    /// pass as `since` next time. That value is the sequence of the last record looked at, so a
    /// filter never makes a reader rescan. A `since` from before a restart (beyond every number
    /// issued) reads from the start. An unknown session has no records. The last value says
    /// whether more records follow because `limit` was reached.
    pub fn since(
        &self,
        session: u64,
        since: u64,
        limit: usize,
        host: Option<&str>,
    ) -> (Vec<CookieRecord>, u64, bool) {
        let since = if since > self.seq.load(Ordering::Relaxed) {
            0
        } else {
            since
        };
        let Some(sess) = self.sessions.get(&session).map(|s| s.clone()) else {
            return (Vec::new(), since, false);
        };
        let site = host
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(registrable);
        let suffix = site.as_ref().map(|s| format!(".{s}"));
        let (rows, next, more): (Vec<Stored>, u64, bool) = {
            let r = sess.ring.lock().unwrap_or_else(|p| p.into_inner());
            let start = r.entries.partition_point(|e| e.seq <= since);
            let mut out: Vec<Stored> = Vec::new();
            let mut next = since;
            let mut scanned_all = true;
            for e in r.entries.iter().skip(start) {
                if out.len() >= limit {
                    scanned_all = false;
                    break;
                }
                next = e.seq;
                let keep = match (&site, &suffix) {
                    (Some(s), Some(suf)) => e.host == *s || e.host.ends_with(suf.as_str()),
                    _ => true,
                };
                if keep {
                    out.push(e.clone());
                }
            }
            if scanned_all {
                next = next.max(r.last).max(since);
            }
            (out, next, !scanned_all)
        };
        let out = rows
            .into_iter()
            .map(|e| {
                let third_party = (!e.page_host.is_empty())
                    .then(|| registrable(&e.host) != registrable(&e.page_host));
                let prefix = prefix_facts(&e.name, &e.attrs);
                CookieRecord {
                    seq: e.seq,
                    ts: Utc
                        .timestamp_millis_opt(e.ts_ms)
                        .single()
                        .unwrap_or_default(),
                    effect: e.effect,
                    name: e.name,
                    host: e.host,
                    path: e.path,
                    page_host: e.page_host,
                    third_party,
                    attrs: e.attrs,
                    changes: e.changes,
                    prefix,
                    rule: e.rule,
                    list_id: e.list_id,
                }
            })
            .collect();
        (out, next, more)
    }

    /// Drop a session's records (it closed).
    pub fn forget(&self, session: u64) {
        if let Some((_, s)) = self.sessions.remove(&session) {
            // Anything still holding the ring (a recorder in flight) pushes into an orphan.
            *s.ring.lock().unwrap_or_else(|p| p.into_inner()) = Ring::default();
        }
    }

    /// Drop every record of every session (the setting was turned off). Sessions stay open.
    pub fn clear(&self) {
        let all: Vec<Arc<Session>> = self.sessions.iter().map(|s| s.value().clone()).collect();
        for s in all {
            let mut r = s.ring.lock().unwrap_or_else(|p| p.into_inner());
            *r = Ring::default();
            s.used.store(false, Ordering::Relaxed);
        }
    }

    /// Records held across all sessions.
    pub fn len(&self) -> usize {
        self.sessions
            .iter()
            .map(|s| {
                s.ring
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .entries
                    .len()
            })
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The process-wide log.
pub fn cookie_log() -> &'static CookieLog {
    static LOG: OnceLock<CookieLog> = OnceLock::new();
    LOG.get_or_init(CookieLog::default)
}

#[cfg(test)]
mod tests;

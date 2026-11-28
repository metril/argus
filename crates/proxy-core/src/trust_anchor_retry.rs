//! Recovery for the `trust_anchors` ClientHello extension (Chrome 153 and newer profiles).
//!
//! The profiles send Chrome's trust anchor ID list, but Argus verifies with its own root set, not
//! Chrome's. A server doing trust-anchor negotiation may answer with a chain rooted in an anchor
//! Argus does not trust, and the handshake then fails certificate verification. Chrome retries
//! such a connection without the extension; so does Argus: once, with nothing else in the profile
//! changed and the same full verification, and it remembers per host for a bounded time that the
//! plain handshake is needed. A retry that fails again is a genuine certificate failure and is
//! surfaced as such (and remembered, so the host is not dialled twice for every request).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// How long a host is dialled without the extension after the plain handshake was needed.
pub const PLAIN_TTL: Duration = Duration::from_secs(3600);
/// How long a host whose plain handshake failed as well is not retried.
pub const USELESS_TTL: Duration = Duration::from_secs(300);
const CAP: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// The handshake without `trust_anchors` verified where the one with it did not.
    NeedsPlain,
    /// Both handshakes failed verification: a retry only doubles the failures.
    RetryUseless,
}

/// Per-host memory of the trust-anchor recovery, keyed by `host:port`.
pub struct TrustAnchorMemory {
    plain_ttl: Duration,
    useless_ttl: Duration,
    map: Mutex<HashMap<String, (Verdict, Instant)>>,
}

impl Default for TrustAnchorMemory {
    fn default() -> Self {
        Self::new(PLAIN_TTL, USELESS_TTL)
    }
}

impl TrustAnchorMemory {
    pub fn new(plain_ttl: Duration, useless_ttl: Duration) -> Self {
        Self {
            plain_ttl,
            useless_ttl,
            map: Default::default(),
        }
    }

    fn live(&self, key: &str, now: Instant) -> Option<Verdict> {
        let mut m = self.map.lock();
        let (v, at) = *m.get(key)?;
        let ttl = match v {
            Verdict::NeedsPlain => self.plain_ttl,
            Verdict::RetryUseless => self.useless_ttl,
        };
        if now.saturating_duration_since(at) >= ttl {
            m.remove(key);
            return None;
        }
        Some(v)
    }

    fn set(&self, key: &str, v: Verdict, now: Instant) {
        let mut m = self.map.lock();
        if m.len() >= CAP && !m.contains_key(key) {
            let (pt, ut) = (self.plain_ttl, self.useless_ttl);
            m.retain(|_, (v, at)| {
                now.saturating_duration_since(*at) < if *v == Verdict::NeedsPlain { pt } else { ut }
            });
            if m.len() >= CAP {
                if let Some(oldest) = m
                    .iter()
                    .min_by_key(|(_, (_, at))| *at)
                    .map(|(k, _)| k.clone())
                {
                    m.remove(&oldest);
                }
            }
        }
        m.insert(key.to_string(), (v, now));
    }

    /// Whether `key` is dialled without the extension from the start.
    pub fn needs_plain(&self, key: &str) -> bool {
        self.live(key, Instant::now()) == Some(Verdict::NeedsPlain)
    }

    /// Whether a failed verification of `key` is worth one retry without the extension.
    pub fn retry_worthwhile(&self, key: &str) -> bool {
        self.live(key, Instant::now()) != Some(Verdict::RetryUseless)
    }

    /// The plain handshake verified where the one with trust anchors did not.
    pub fn plain_was_needed(&self, key: &str) {
        self.set(key, Verdict::NeedsPlain, Instant::now());
    }

    /// The plain handshake failed verification too.
    pub fn plain_failed_too(&self, key: &str) {
        self.set(key, Verdict::RetryUseless, Instant::now());
    }

    #[cfg(test)]
    fn at(&self, key: &str, now: Instant) -> Option<Verdict> {
        self.live(key, now)
    }
}

/// Whether `e` is a handshake aborted by certificate verification (our in-handshake hook), as
/// opposed to a transport failure or an alert from the server.
pub fn is_cert_verify_failure(e: &wreq::Error) -> bool {
    use std::error::Error as _;
    fn stack_has(s: &btls::error::ErrorStack) -> bool {
        s.errors().iter().any(|e| {
            e.reason()
                .is_some_and(|r| r.contains("CERTIFICATE_VERIFY_FAILED"))
        })
    }
    let mut cur: Option<&(dyn std::error::Error + 'static)> = e.source();
    while let Some(err) = cur {
        if let Some(s) = err.downcast_ref::<btls::error::ErrorStack>() {
            if stack_has(s) {
                return true;
            }
        }
        if let Some(ssl) = err.downcast_ref::<btls::ssl::Error>() {
            if ssl.ssl_error().is_some_and(stack_has) {
                return true;
            }
        }
        cur = err.source();
    }
    false
}

/// Whether the emulation sends the `trust_anchors` extension.
pub fn sends_trust_anchors(e: &wreq::Emulation) -> bool {
    e.tls_options
        .as_ref()
        .is_some_and(|t| t.requested_trust_anchors.is_some())
}

/// The same emulation without the `trust_anchors` extension; nothing else changes.
pub fn without_trust_anchors(mut e: wreq::Emulation) -> wreq::Emulation {
    if let Some(t) = e.tls_options.as_mut() {
        t.requested_trust_anchors = None;
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_plain_is_remembered_and_expires() {
        let m = TrustAnchorMemory::new(Duration::from_secs(10), Duration::from_secs(2));
        let t0 = Instant::now();
        assert_eq!(m.at("a:443", t0), None);
        m.set("a:443", Verdict::NeedsPlain, t0);
        assert_eq!(
            m.at("a:443", t0 + Duration::from_secs(9)),
            Some(Verdict::NeedsPlain)
        );
        assert_eq!(m.at("a:443", t0 + Duration::from_secs(10)), None);
        assert_eq!(m.at("a:443", t0), None, "expired entries are dropped");
    }

    #[test]
    fn a_useless_retry_is_remembered_for_less_time() {
        let m = TrustAnchorMemory::new(Duration::from_secs(10), Duration::from_secs(2));
        let t0 = Instant::now();
        m.set("b:443", Verdict::RetryUseless, t0);
        assert_eq!(
            m.at("b:443", t0 + Duration::from_secs(1)),
            Some(Verdict::RetryUseless)
        );
        assert_eq!(m.at("b:443", t0 + Duration::from_secs(2)), None);
    }

    #[test]
    fn the_memory_is_bounded() {
        let m = TrustAnchorMemory::default();
        for i in 0..CAP + 10 {
            m.plain_was_needed(&format!("h{i}:443"));
        }
        assert!(m.map.lock().len() <= CAP);
        assert!(
            m.needs_plain(&format!("h{}:443", CAP + 9)),
            "the newest is kept"
        );
    }

    #[test]
    fn only_the_trust_anchors_extension_is_dropped() {
        let e = crate::browser_profile::BrowserProfile::default().emulation();
        assert!(
            sends_trust_anchors(&e),
            "the default profile sends trust_anchors"
        );
        let p = without_trust_anchors(e.clone());
        assert!(!sends_trust_anchors(&p));
        let (mut a, mut b) = (e.tls_options.unwrap(), p.tls_options.unwrap());
        a.requested_trust_anchors = None;
        b.requested_trust_anchors = None;
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }
}

//! Compact immutable set of hostnames for pure domain block rules (`||host^`, no options) and
//! exact-host rules (`|https://host^`).
//!
//! Design:
//! - Each entry is the 64-bit hash of the host's bytes **read right to left** (FNV-1a steps, then
//!   a murmur3 finalizer). Reading from the end makes every label suffix's hash a prefix state of
//!   the full host's hash, so a lookup walks the request host once, back to front, probing at each
//!   label boundary (`c.com`, `b.c.com`, `a.b.c.com`), with no allocation and at most one probe
//!   per label.
//! - The table is open-addressing (linear probing, load about 0.6) over a `Box<[u64]>` of keys
//!   (0 = empty) with a parallel cold `Box<[u16]>` of metadata (list index, exact-scheme mask), so
//!   a miss touches one cache line of keys. About 17 bytes per domain.
//! - Only hashes are stored, so a host that is not in the set matches with probability
//!   `n / 2^64` per probed suffix: for 1M entries about 5.4e-14 per probe, about 1.6e-13 per
//!   request (3 suffixes); one false block expected per ~6e12 requests. Accepted deliberately.
//! - Persisted as raw little-endian arrays ([`DomainSet::to_bytes`]) and loaded by copying, with
//!   no re-hashing. (A memory map would save one ~17 MB copy at the price of `unsafe` and a new
//!   dependency; the copy takes a few milliseconds.)
//!
//! The semantics are those of the engine rule `||host^` with default options: any request whose
//! host is `host` or a subdomain of it, for the request types and schemes the engine applies a
//! default rule to (see [`crate::precheck`]).

use rayon::prelude::*;

const SEED: u64 = 0xcbf2_9ce4_8422_2325;
const PRIME: u64 = 0x0000_0100_0000_01b3;
const EXACT_SALT: u64 = 0x9e37_79b9_7f4a_7c15;
/// Longest hostname accepted (DNS limit).
pub const MAX_HOST: usize = 253;
/// "List unknown" index in the metadata.
pub const NO_LIST: u16 = 0xff;
const MAGIC: &[u8; 8] = b"ADOMSET1";

/// URL scheme of a request, as far as exact-host rules distinguish it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http = 1,
    Https = 2,
    Ws = 4,
    Wss = 8,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Ws => "ws",
            Self::Wss => "wss",
        }
    }
    pub(crate) fn bit(self) -> u8 {
        self as u8
    }
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            "ws" => Some(Self::Ws),
            "wss" => Some(Self::Wss),
            _ => None,
        }
    }
}

#[inline]
fn step(h: u64, b: u8) -> u64 {
    (h ^ b.to_ascii_lowercase() as u64).wrapping_mul(PRIME)
}

#[inline]
fn finish(h: u64) -> u64 {
    let mut k = h;
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51_afd7_ed55_8ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    k ^= k >> 33;
    if k == 0 {
        1
    } else {
        k
    }
}

fn raw_hash(host: &str) -> u64 {
    host.bytes().rev().fold(SEED, step)
}

/// Table key of the rule `||host^`.
pub fn suffix_key(host: &str) -> u64 {
    finish(raw_hash(host))
}

/// Table key of the exact-host rules for `host` (combine with a scheme bit in the entry).
pub fn exact_key(host: &str) -> u64 {
    finish(raw_hash(host) ^ EXACT_SALT)
}

/// A match in a [`DomainSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainHit {
    /// Source list index (see [`DomainSet::list_id`]); [`NO_LIST`] if unknown.
    pub list: u16,
    /// Byte offset in the looked-up host where the matching suffix starts (0 for the whole host).
    pub start: usize,
    /// `Some` for an exact-host rule (`|scheme://host^`), `None` for `||host^`.
    pub exact: Option<Scheme>,
}

/// One rule going into a [`DomainSetBuilder`]: `bit` is 0 for `||host^`, else the scheme bit of an
/// exact-host rule; `key` already carries the exact salt for the latter.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Entry {
    pub key: u64,
    pub bit: u8,
    pub list: u16,
}

/// Immutable host set (see the module docs).
#[derive(Clone)]
pub struct DomainSet {
    keys: Box<[u64]>,
    meta: Box<[u16]>,
    lists: Vec<String>,
    entries: usize,
    has_exact: bool,
    engine_overrides: bool,
    engine_network: bool,
}

impl Default for DomainSet {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Debug for DomainSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DomainSet({} entries, {} bytes)",
            self.entries,
            self.size_bytes()
        )
    }
}

impl DomainSet {
    pub fn empty() -> Self {
        Self {
            keys: Box::new([]),
            meta: Box::new([]),
            lists: Vec::new(),
            entries: 0,
            has_exact: false,
            engine_overrides: true,
            engine_network: true,
        }
    }

    /// Number of distinct keys (a host with exact rules for several schemes counts once).
    pub fn len(&self) -> usize {
        self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }

    /// Heap size of the table.
    pub fn size_bytes(&self) -> usize {
        self.keys.len() * 8 + self.meta.len() * 2
    }

    /// Whether the engine this set was built with contains exception, `$important` or redirect
    /// rules, i.e. whether a set hit must still consult the engine. `true` for an empty set
    /// (conservative default).
    pub fn engine_overrides(&self) -> bool {
        self.engine_overrides
    }

    /// Whether the engine holds any network rule at all. When `false`, a request that misses
    /// the set cannot be blocked by the engine, so the caller may skip it entirely. `true` for an
    /// empty set (conservative default).
    pub fn engine_has_network_rules(&self) -> bool {
        self.engine_network
    }

    /// Source list id of a hit's `list` index.
    pub fn list_id(&self, list: u16) -> Option<&str> {
        self.lists.get(list as usize).map(String::as_str)
    }

    #[inline]
    fn probe(&self, k: u64) -> Option<u16> {
        let cap = self.keys.len();
        let mut i = ((k as u128 * cap as u128) >> 64) as usize;
        loop {
            let s = self.keys[i];
            if s == k {
                return Some(self.meta[i]);
            }
            if s == 0 {
                return None;
            }
            i += 1;
            if i == cap {
                i = 0;
            }
        }
    }

    /// Look `host` up: its label suffixes from the shortest (two labels) to the whole host, then
    /// exact-host rules for `scheme`. `host` must be a plain ASCII hostname without trailing dot;
    /// letters may be any case. No allocation; at most one probe per label.
    pub fn lookup(&self, host: &str, scheme: Scheme) -> Option<DomainHit> {
        self.lookup_impl(host, scheme, true)
    }

    /// Like [`Self::lookup`] but only exact-host rules (`|scheme://host^`).
    pub fn lookup_exact(&self, host: &str, scheme: Scheme) -> Option<DomainHit> {
        self.lookup_impl(host, scheme, false)
    }

    fn lookup_impl(&self, host: &str, scheme: Scheme, suffixes: bool) -> Option<DomainHit> {
        let b = host.as_bytes();
        let n = b.len();
        if self.entries == 0 || n == 0 || n > MAX_HOST {
            return None;
        }
        let (mut h, mut dots, mut j) = (SEED, 0u32, n);
        loop {
            // `h` is the hash state of b[j..].
            if suffixes && (j == 0 || b[j - 1] == b'.') && dots > 0 && j < n {
                if let Some(m) = self.probe(finish(h)) {
                    if m >> 8 == 0 {
                        return Some(DomainHit {
                            list: m & 0xff,
                            start: j,
                            exact: None,
                        });
                    }
                }
            }
            if j == 0 {
                break;
            }
            if b[j - 1] == b'.' {
                dots += 1;
            }
            h = step(h, b[j - 1]);
            j -= 1;
        }
        if self.has_exact && dots > 0 {
            if let Some(m) = self.probe(finish(h ^ EXACT_SALT)) {
                if (m >> 8) as u8 & scheme.bit() != 0 {
                    return Some(DomainHit {
                        list: m & 0xff,
                        start: 0,
                        exact: Some(scheme),
                    });
                }
            }
        }
        None
    }

    /// Serialize (see [`Self::from_bytes`]).
    pub fn to_bytes(&self) -> Vec<u8> {
        let lists = serde_json::to_vec(&self.lists).unwrap_or_default();
        let mut out = Vec::with_capacity(48 + lists.len() + self.size_bytes());
        out.extend_from_slice(MAGIC);
        out.push(
            self.has_exact as u8
                | (self.engine_overrides as u8) << 1
                | (self.engine_network as u8) << 2,
        );
        out.extend_from_slice(&[0; 7]);
        out.extend_from_slice(&(self.entries as u64).to_le_bytes());
        out.extend_from_slice(&(self.keys.len() as u64).to_le_bytes());
        out.extend_from_slice(&(lists.len() as u64).to_le_bytes());
        out.extend_from_slice(&lists);
        for k in self.keys.iter() {
            out.extend_from_slice(&k.to_le_bytes());
        }
        for m in self.meta.iter() {
            out.extend_from_slice(&m.to_le_bytes());
        }
        out
    }

    /// Inverse of [`Self::to_bytes`]; validates lengths, never re-hashes.
    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        let u64_at = |o: usize| -> Result<u64, String> {
            b.get(o..o + 8)
                .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
                .ok_or_else(|| "truncated domain set".to_string())
        };
        if b.len() < 40 || &b[..8] != MAGIC {
            return Err("bad domain set header".into());
        }
        let flags = b[8];
        let (entries, cap, jl) = (
            u64_at(16)? as usize,
            u64_at(24)? as usize,
            u64_at(32)? as usize,
        );
        let keys_at = 40usize.checked_add(jl).ok_or("bad domain set lengths")?;
        let meta_at = cap
            .checked_mul(8)
            .and_then(|k| keys_at.checked_add(k))
            .ok_or("bad domain set lengths")?;
        let end = cap
            .checked_mul(2)
            .and_then(|k| meta_at.checked_add(k))
            .ok_or("bad domain set lengths")?;
        if b.len() != end || entries > cap || (cap == 0) != (entries == 0) {
            return Err("domain set size mismatch".into());
        }
        let lists: Vec<String> = serde_json::from_slice(&b[40..keys_at])
            .map_err(|e| format!("domain set lists: {e}"))?;
        let keys = b[keys_at..meta_at]
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        let meta = b[meta_at..end]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
            .collect();
        Ok(Self {
            keys,
            meta,
            lists,
            entries,
            has_exact: flags & 1 != 0,
            engine_overrides: flags & 2 != 0,
            engine_network: flags & 4 != 0,
        })
    }
}

/// Collects rules, then builds the table with cross-list deduplication.
#[derive(Default)]
pub struct DomainSetBuilder {
    lists: Vec<String>,
    pub(crate) entries: Vec<Entry>,
    /// `(key, bit)` pairs disabled by a matching `$badfilter` rule.
    pub(crate) removals: Vec<(u64, u8)>,
}

/// Result of [`DomainSetBuilder::finish`].
pub struct DomainSetBuild {
    pub set: DomainSet,
    /// Per list index: rules dropped as duplicates of an earlier rule.
    pub duplicates: Vec<usize>,
}

impl DomainSetBuilder {
    /// `lists`: list id per index used by the entries.
    pub fn new(lists: Vec<String>) -> Self {
        Self {
            lists,
            ..Self::default()
        }
    }

    /// Add `||host^` from list `list`. `host` must already be validated and lowercase.
    pub fn add_suffix(&mut self, host: &str, list: u16) {
        self.entries.push(Entry {
            key: suffix_key(host),
            bit: 0,
            list,
        });
    }

    /// Add `|scheme://host^`.
    pub fn add_exact(&mut self, host: &str, scheme: Scheme, list: u16) {
        self.entries.push(Entry {
            key: exact_key(host),
            bit: scheme.bit(),
            list,
        });
    }

    /// Disable the `||host^` rule (a `||host^$badfilter` rule).
    pub fn remove_suffix(&mut self, host: &str) {
        self.removals.push((suffix_key(host), 0));
    }

    /// Disable the `|scheme://host^` rule.
    pub fn remove_exact(&mut self, host: &str, scheme: Scheme) {
        self.removals.push((exact_key(host), scheme.bit()));
    }

    pub(crate) fn merge(&mut self, entries: Vec<Entry>, removals: Vec<(u64, u8)>) {
        self.entries.extend(entries);
        self.removals.extend(removals);
    }

    /// Sort (in parallel), drop duplicates and disabled rules, and build the table.
    /// `engine_overrides`, `engine_network`: see [`DomainSet::engine_overrides`] and
    /// [`DomainSet::engine_has_network_rules`].
    pub fn finish(self, engine_overrides: bool, engine_network: bool) -> DomainSetBuild {
        let Self {
            lists,
            mut entries,
            mut removals,
        } = self;
        removals.sort_unstable();
        removals.dedup();
        entries.par_sort_unstable_by_key(|e| (e.key, e.bit, e.list));
        let mut duplicates = vec![0usize; lists.len().max(1)];
        // Unique (key, mask, list) triples, in key order.
        let mut uniq: Vec<(u64, u8, u16)> = Vec::with_capacity(entries.len());
        let mut prev: Option<(u64, u8)> = None;
        for e in &entries {
            if prev == Some((e.key, e.bit)) {
                if let Some(d) = duplicates.get_mut(e.list as usize) {
                    *d += 1;
                }
                continue;
            }
            prev = Some((e.key, e.bit));
            if removals.binary_search(&(e.key, e.bit)).is_ok() {
                continue;
            }
            match uniq.last_mut() {
                Some(last) if last.0 == e.key => last.1 |= e.bit,
                _ => uniq.push((e.key, e.bit, e.list)),
            }
        }
        drop(entries);

        let n = uniq.len();
        let cap = if n == 0 { 0 } else { n * 5 / 3 + 8 };
        let mut keys = vec![0u64; cap];
        let mut meta = vec![0u16; cap];
        let mut has_exact = false;
        for (key, mask, list) in uniq {
            has_exact |= mask != 0;
            let mut i = ((key as u128 * cap as u128) >> 64) as usize;
            while keys[i] != 0 {
                i += 1;
                if i == cap {
                    i = 0;
                }
            }
            keys[i] = key;
            meta[i] = (list.min(NO_LIST)) | (mask as u16) << 8;
        }
        DomainSetBuild {
            set: DomainSet {
                keys: keys.into(),
                meta: meta.into(),
                lists,
                entries: n,
                has_exact,
                engine_overrides,
                engine_network,
            },
            duplicates,
        }
    }
}

/// Is `h` a hostname that may be routed into a [`DomainSet`]: lowercase ASCII letters, digits,
/// `-` and `_`, at least two non-empty labels of at most 63 bytes, labels not starting or ending
/// with `-`, a non-numeric last label, at most [`MAX_HOST`] bytes.
pub fn is_set_host(h: &str) -> bool {
    let b = h.as_bytes();
    if b.len() < 3 || b.len() > MAX_HOST {
        return false;
    }
    let mut labels = 0;
    let mut last_numeric = false;
    for label in h.split('.') {
        let l = label.as_bytes();
        if l.is_empty()
            || l.len() > 63
            || l[0] == b'-'
            || l[l.len() - 1] == b'-'
            || !l
                .iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'_')
        {
            return false;
        }
        labels += 1;
        last_numeric = l.iter().all(u8::is_ascii_digit);
    }
    labels >= 2 && !last_numeric
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(rules: &[(&str, u16)], exact: &[(&str, Scheme)]) -> DomainSet {
        let mut b = DomainSetBuilder::new(vec!["a".into(), "b".into()]);
        for (h, l) in rules {
            b.add_suffix(h, *l);
        }
        for (h, s) in exact {
            b.add_exact(h, *s, 1);
        }
        b.finish(false, true).set
    }

    #[test]
    fn suffix_walk_and_boundaries() {
        let s = build(&[("ads.example.com", 0), ("evil.net", 1)], &[]);
        let hit = |h: &str| s.lookup(h, Scheme::Https);
        assert_eq!(hit("ads.example.com").unwrap().start, 0);
        assert_eq!(hit("x.y.ads.example.com").unwrap().start, 4);
        assert_eq!(hit("x.EVIL.net").unwrap().list, 1);
        assert!(hit("example.com").is_none());
        assert!(hit("badads.example.com").is_none(), "label boundary");
        assert!(hit("ads.example.com.evil.org").is_none());
        assert!(hit("net").is_none() && hit("").is_none());
    }

    #[test]
    fn exact_hosts_are_scheme_specific_and_not_suffix() {
        let s = build(&[], &[("h.test", Scheme::Https), ("h.test", Scheme::Ws)]);
        assert!(s.lookup("h.test", Scheme::Https).is_some());
        assert!(s.lookup("h.test", Scheme::Ws).is_some());
        assert!(s.lookup("h.test", Scheme::Http).is_none());
        assert!(s.lookup("sub.h.test", Scheme::Https).is_none());
    }

    #[test]
    fn dedupe_and_badfilter() {
        let mut b = DomainSetBuilder::new(vec!["a".into(), "b".into()]);
        b.add_suffix("x.test", 0);
        b.add_suffix("x.test", 1);
        b.add_suffix("x.test", 1);
        b.add_suffix("y.test", 0);
        b.remove_suffix("y.test");
        let r = b.finish(true, false);
        assert_eq!(r.duplicates, [0, 2]);
        assert_eq!(r.set.len(), 1);
        assert!(r.set.lookup("y.test", Scheme::Http).is_none());
        assert_eq!(r.set.lookup("x.test", Scheme::Http).unwrap().list, 0);
        assert!(r.set.engine_overrides() && !r.set.engine_has_network_rules());
    }

    #[test]
    fn serialization_round_trips_and_rejects_garbage() {
        let s = build(&[("a.test", 0), ("b.test", 1)], &[("c.test", Scheme::Wss)]);
        let t = DomainSet::from_bytes(&s.to_bytes()).unwrap();
        assert_eq!(t.len(), s.len());
        assert_eq!(t.list_id(1), Some("b"));
        assert!(t.lookup("z.b.test", Scheme::Http).is_some());
        assert!(t.lookup("c.test", Scheme::Wss).is_some());
        let e = DomainSet::from_bytes(&DomainSet::empty().to_bytes()).unwrap();
        assert!(e.is_empty() && e.lookup("a.test", Scheme::Http).is_none());
        let bytes = s.to_bytes();
        for cut in [0, 7, 39, bytes.len() - 1] {
            assert!(DomainSet::from_bytes(&bytes[..cut]).is_err(), "cut {cut}");
        }
    }

    #[test]
    fn host_validation() {
        for ok in ["a.b", "ads-1.x_y.example.com", "a.co"] {
            assert!(is_set_host(ok), "{ok}");
        }
        for bad in [
            "com", "A.com", "a..b", ".a.b", "a.b.", "-a.com", "a-.com", "1.2.3.4", "a.b/c", "é.com",
        ] {
            assert!(!is_set_host(bad), "{bad}");
        }
    }

    #[test]
    fn many_hosts_no_false_negatives() {
        let hosts: Vec<String> = (0..20_000)
            .map(|i| format!("h{i}.t{}.example.com", i % 7))
            .collect();
        let mut b = DomainSetBuilder::new(vec!["l".into()]);
        for h in &hosts {
            b.add_suffix(h, 0);
        }
        let s = b.finish(false, true).set;
        assert_eq!(s.len(), hosts.len());
        for h in &hosts {
            assert!(s.lookup(h, Scheme::Http).is_some(), "{h}");
            assert!(s.lookup(&format!("w.{h}"), Scheme::Http).is_some());
        }
        assert!(s.lookup("h20000.t1.example.com", Scheme::Http).is_none());
    }
}

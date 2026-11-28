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
use std::collections::HashSet;
use std::hash::{BuildHasherDefault, Hasher};

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

/// Appends `(host key, ancestor key)` for every proper label suffix of `host` that still has two
/// labels (`a.b.c.com` gives `b.c.com` and `c.com`), derived from the right-to-left hash states.
pub(crate) fn push_ancestors(host: &str, out: &mut Vec<(u64, u64)>) {
    let b = host.as_bytes();
    let child = suffix_key(host);
    let (mut h, mut dots) = (SEED, 0u32);
    for j in (1..b.len()).rev() {
        if b[j] == b'.' {
            // `h` hashes b[j + 1..], a proper suffix with `dots` dots.
            if dots > 0 {
                out.push((child, finish(h)));
            }
            dots += 1;
        }
        h = step(h, b[j]);
    }
}

/// Identity hasher for keys that are already well-mixed 64-bit hashes.
#[derive(Default)]
struct IdHasher(u64);
impl Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, _: &[u8]) {}
    fn write_u64(&mut self, k: u64) {
        self.0 = k;
    }
}
type KeySet = HashSet<u64, BuildHasherDefault<IdHasher>>;

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
        // Bounded by the capacity even if the table has no empty slot (corrupt input).
        for _ in 0..cap {
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
        None
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
        // The builder keeps the load at or below 0.6; anything denser (a table with no empty
        // slot makes a miss probe the whole table) is corrupt.
        if entries.checked_mul(4).is_none_or(|e| e > cap * 3) {
            return Err("domain set load factor too high".into());
        }
        let lists: Vec<String> = serde_json::from_slice(&b[40..keys_at])
            .map_err(|e| format!("domain set lists: {e}"))?;
        let keys: Vec<u64> = b[keys_at..meta_at]
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        if keys.iter().filter(|k| **k != 0).count() != entries {
            return Err("domain set entry count mismatch".into());
        }
        let meta = b[meta_at..end]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
            .collect();
        Ok(Self {
            keys: keys.into(),
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
    /// `(suffix key, key of one proper two-plus-label ancestor)`, for compression.
    pub(crate) ancestors: Vec<(u64, u64)>,
}

/// Result of [`DomainSetBuilder::finish`].
pub struct DomainSetBuild {
    pub set: DomainSet,
    /// Per list index: rules dropped as duplicates of an earlier rule.
    pub duplicates: Vec<usize>,
    /// Per list index: `||host^` rules dropped because a shorter suffix rule already covers them.
    pub compressed: Vec<usize>,
    /// Per list index: rules (every occurrence) disabled by a `$badfilter` rule, which neither
    /// block nor count as duplicates.
    pub disabled: Vec<usize>,
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
        push_ancestors(host, &mut self.ancestors);
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

    pub(crate) fn merge(
        &mut self,
        entries: Vec<Entry>,
        removals: Vec<(u64, u8)>,
        ancestors: Vec<(u64, u64)>,
    ) {
        self.ancestors.extend(ancestors);
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
            ancestors,
        } = self;
        removals.sort_unstable();
        removals.dedup();
        entries.par_sort_unstable_by_key(|e| (e.key, e.bit, e.list));
        let mut duplicates = vec![0usize; lists.len().max(1)];
        // Unique (key, mask, list) triples, in key order; a `$badfilter`-disabled rule is left out.
        let mut uniq: Vec<(u64, u8, u16)> = Vec::with_capacity(entries.len());
        let mut prev: Option<(u64, u8)> = None;
        for e in &entries {
            if prev == Some((e.key, e.bit)) {
                continue;
            }
            prev = Some((e.key, e.bit));
            if removals.binary_search(&(e.key, e.bit)).is_ok() {
                continue;
            }
            match uniq.last_mut() {
                Some(last) if last.0 == e.key => {
                    last.1 |= e.bit;
                    // The host's table entry names the lowest list holding any scheme of it.
                    last.2 = last.2.min(e.list);
                }
                _ => uniq.push((e.key, e.bit, e.list)),
            }
        }

        // Compression: a `||host^` rule is redundant when a proper label suffix of it is also a
        // `||host^` rule (the lookup walks suffixes shortest first, so the ancestor already wins,
        // with the same scheme/type applicability and the same engine exception handling). Exact
        // `|scheme://host^` rules are never touched. Runs after `$badfilter` removal, so a disabled
        // ancestor absorbs nothing. O(n) with hash sets.
        let mut compressed = vec![0usize; lists.len().max(1)];
        let mut disabled = vec![0usize; lists.len().max(1)];
        let mut covered = KeySet::default();
        if !ancestors.is_empty() {
            let present: KeySet = uniq.iter().filter(|u| u.1 == 0).map(|u| u.0).collect();
            covered = ancestors
                .iter()
                .filter(|(_, a)| present.contains(a))
                .map(|(c, _)| *c)
                .collect();
        }
        drop(ancestors);

        // Accounting, per rule (every occurrence, so a rule can be attributed from the final set
        // alone, see `crate::inspect`): a rule an ancestor covers is compressed whatever else
        // holds; a rule disabled by `$badfilter` is neither; of the rest, every occurrence after
        // the first of the same rule is a duplicate. Entries are in (key, bit, list) order, so the
        // first is the one the table keeps (the lowest list).
        let mut i = 0;
        while i < entries.len() {
            let mut j = i;
            while j < entries.len() && entries[j].key == entries[i].key {
                j += 1;
            }
            let group = &entries[i..j];
            i = j;
            let is_removed = |e: &Entry| removals.binary_search(&(e.key, e.bit)).is_ok();
            // The lowest list holding the host (any scheme) is the one the table names.
            let lowest = group
                .iter()
                .filter(|e| !is_removed(e))
                .map(|e| e.list)
                .min();
            let mut prev: Option<u8> = None;
            for e in group {
                let slot = e.list as usize;
                if e.bit == 0 && covered.contains(&e.key) {
                    if let Some(c) = compressed.get_mut(slot) {
                        *c += 1;
                    }
                    continue;
                }
                if is_removed(e) {
                    if let Some(d) = disabled.get_mut(slot) {
                        *d += 1;
                    }
                    continue;
                }
                if prev == Some(e.bit) || Some(e.list) > lowest {
                    if let Some(d) = duplicates.get_mut(slot) {
                        *d += 1;
                    }
                }
                prev = Some(e.bit);
            }
        }
        drop(entries);
        if !covered.is_empty() {
            uniq.retain(|&(k, mask, _)| !(mask == 0 && covered.contains(&k)));
        }

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
            compressed,
            disabled,
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

    /// A hand-made table: `keys` (0 = empty slot) with `entries` claimed.
    fn raw_table(entries: u64, keys: &[u64]) -> Vec<u8> {
        let lists = b"[\"a\"]";
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(0);
        out.extend_from_slice(&[0; 7]);
        out.extend_from_slice(&entries.to_le_bytes());
        out.extend_from_slice(&(keys.len() as u64).to_le_bytes());
        out.extend_from_slice(&(lists.len() as u64).to_le_bytes());
        out.extend_from_slice(lists);
        for k in keys {
            out.extend_from_slice(&k.to_le_bytes());
        }
        out.extend(std::iter::repeat_n(0u8, keys.len() * 2));
        out
    }

    #[test]
    fn full_or_overloaded_tables_are_rejected_and_probe_terminates() {
        // entries == cap: no empty slot, a miss would probe forever.
        let full = raw_table(4, &[11, 22, 33, 44]);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = DomainSet::from_bytes(&full);
            // If a full table were accepted, a miss must still terminate.
            if let Ok(s) = r {
                let _ = s.lookup("miss.example.com", Scheme::Https);
                tx.send(true).ok();
            } else {
                tx.send(false).ok();
            }
        });
        let accepted = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("lookup on a full table must terminate");
        assert!(!accepted, "a table with no empty slot must be rejected");
        // Too dense (above the builder's load factor) is rejected too.
        assert!(DomainSet::from_bytes(&raw_table(7, &[1, 2, 3, 4, 5, 6, 7, 0])).is_err());
        // Claimed entry count must match the occupied slots.
        assert!(DomainSet::from_bytes(&raw_table(1, &[0, 0, 0, 0, 0, 0, 0, 0])).is_err());
        // A real table round-trips.
        let s = build(&[("ads.example.com", 0)], &[]);
        assert!(DomainSet::from_bytes(&s.to_bytes()).is_ok());
    }

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

    fn build_counts(rules: &[(&str, u16)], exact: &[(&str, Scheme)]) -> DomainSetBuild {
        let mut b = DomainSetBuilder::new(vec!["a".into(), "b".into()]);
        for (h, l) in rules {
            b.add_suffix(h, *l);
        }
        for (h, s) in exact {
            b.add_exact(h, *s, 1);
        }
        b.finish(false, true)
    }

    #[test]
    fn parent_absorbs_child_and_reports_parent_list() {
        let r = build_counts(&[("ads.example.com", 1), ("example.com", 0)], &[]);
        assert_eq!(r.set.len(), 1);
        assert_eq!(r.compressed, [0, 1]);
        let hit = r.set.lookup("x.ads.example.com", Scheme::Https).unwrap();
        assert_eq!((hit.list, hit.start), (0, 6));
    }

    #[test]
    fn deep_chain_compresses_even_across_missing_intermediates() {
        let r = build_counts(
            &[
                ("a.b.c.d.com", 0),
                ("b.c.d.com", 0),
                ("x.y.z.d.com", 1),
                ("d.com", 0),
            ],
            &[],
        );
        assert_eq!(r.set.len(), 1);
        assert_eq!(r.compressed, [2, 1]);
        assert!(r.set.lookup("q.x.y.z.d.com", Scheme::Http).is_some());
    }

    #[test]
    fn sibling_and_unrelated_are_kept() {
        let r = build_counts(
            &[
                ("a.example.com", 0),
                ("b.example.com", 0),
                ("example.org", 0),
            ],
            &[],
        );
        assert_eq!(r.set.len(), 3);
        assert_eq!(r.compressed, [0, 0]);
        // A bare label suffix is not a rule: `com` never absorbs anything.
        assert!(r.set.lookup("c.example.com", Scheme::Http).is_none());
    }

    #[test]
    fn exact_rules_are_never_compressed_or_absorbing() {
        // Exact child under a suffix parent: kept (scheme/type applicability differs).
        let r = build_counts(&[("example.com", 0)], &[("ads.example.com", Scheme::Http)]);
        assert_eq!((r.set.len(), r.compressed.iter().sum::<usize>()), (2, 0));
        assert!(r
            .set
            .lookup_exact("ads.example.com", Scheme::Http)
            .is_some());
        // Suffix child under an exact parent: kept (an exact rule is not a suffix rule).
        let r = build_counts(&[("ads.example.com", 0)], &[("example.com", Scheme::Http)]);
        assert_eq!((r.set.len(), r.compressed.iter().sum::<usize>()), (2, 0));
        assert!(r.set.lookup("ads.example.com", Scheme::Https).is_some());
    }

    #[test]
    fn badfiltered_parent_absorbs_nothing() {
        let mut b = DomainSetBuilder::new(vec!["a".into()]);
        b.add_suffix("example.com", 0);
        b.add_suffix("ads.example.com", 0);
        b.remove_suffix("example.com");
        let r = b.finish(false, true);
        assert_eq!((r.set.len(), r.compressed[0]), (1, 0));
        assert!(r.set.lookup("ads.example.com", Scheme::Http).is_some());
        assert!(r.set.lookup("example.com", Scheme::Http).is_none());
    }

    /// Reference: uncompressed suffix walk over plain strings (shortest suffix first).
    fn naive(rules: &[(String, u16)], host: &str) -> Option<(u16, usize)> {
        let mut starts: Vec<usize> = vec![0];
        starts.extend(host.match_indices('.').map(|(i, _)| i + 1));
        starts.reverse();
        for st in starts {
            let suf = &host[st..];
            if !suf.contains('.') {
                continue;
            }
            // Mirror the table: duplicates keep the lowest list index.
            if let Some(l) = rules.iter().filter(|(h, _)| h == suf).map(|r| r.1).min() {
                return Some((l, st));
            }
        }
        None
    }

    #[test]
    fn compression_never_changes_lookups() {
        let mut seed = 0x1234_5678_9abc_def1u64;
        let mut rnd = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        let labels = ["a", "b", "c", "d", "e"];
        let host = |rnd: &mut dyn FnMut(u64) -> u64| {
            let depth = 2 + rnd(4) as usize;
            (0..depth)
                .map(|_| labels[rnd(5) as usize])
                .collect::<Vec<_>>()
                .join(".")
        };
        for _ in 0..30 {
            let rules: Vec<(String, u16)> =
                (0..12).map(|_| (host(&mut rnd), rnd(2) as u16)).collect();
            let mut b = DomainSetBuilder::new(vec!["a".into(), "b".into()]);
            for (h, l) in &rules {
                b.add_suffix(h, *l);
            }
            let set = b.finish(false, true).set;
            for _ in 0..200 {
                let q = host(&mut rnd);
                let got = set.lookup(&q, Scheme::Https).map(|h| (h.list, h.start));
                assert_eq!(got, naive(&rules, &q), "{q} vs {rules:?}");
            }
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

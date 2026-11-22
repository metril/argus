//! Device-to-profile lookup: an immutable table behind one atomic pointer.
//!
//! A connection resolves its profile once ([`Profiles::resolve`]) and keeps the slot and the
//! epoch it resolved at. Reassigning devices publishes a new table (epoch bump); editing a profile
//! swaps the `Arc<Profile>` inside its slot (no epoch bump). Nothing here locks, allocates or
//! touches storage on the lookup path.

use crate::request_ctx::{Profile, ProfileSlot};
use arc_swap::ArcSwap;
use base64::Engine as _;
use ipnet::IpNet;
use rustc_hash::FxHashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// BLAKE3 digest of a device token (the table key; raw tokens are never stored or compared).
pub fn token_digest(raw: &[u8]) -> [u8; 32] {
    *blake3::hash(raw).as_bytes()
}

/// Unwrap IPv4-mapped IPv6 (`::ffff:a.b.c.d`) so a dual-stack socket resolves like plain IPv4.
#[inline]
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// A table entry: the profile slot and, for a stored device, its last-seen cell (unix seconds,
/// 0 = never). Resolving stores the current second into it: one relaxed load, and one store
/// only when the second changed.
#[derive(Clone)]
pub struct Entry {
    slot: ProfileSlot,
    seen: Option<Arc<AtomicU64>>,
}

impl Entry {
    #[inline]
    fn touch(&self) {
        if let Some(s) = &self.seen {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            if s.load(Ordering::Relaxed) != now {
                s.store(now, Ordering::Relaxed);
            }
        }
    }
}

/// Immutable lookup snapshot.
pub struct ProfileTable {
    ips: FxHashMap<IpAddr, Entry>,
    /// Subnets, one hash map per distinct prefix length, longest length first: the first length
    /// that has the masked address wins. Cost is one probe per distinct length in use.
    v4: Vec<PrefixLevel<u32>>,
    v6: Vec<PrefixLevel<u128>>,
    tokens: FxHashMap<[u8; 32], Entry>,
    by_id: FxHashMap<u64, ProfileSlot>,
    default: ProfileSlot,
}

impl ProfileTable {
    pub fn builder(default: ProfileSlot) -> TableBuilder {
        let mut by_id = FxHashMap::default();
        by_id.insert(default.load().id, default.clone());
        TableBuilder {
            ips: FxHashMap::default(),
            prefixes: Vec::new(),
            tokens: FxHashMap::default(),
            by_id,
            default,
        }
    }

    /// Exact device address, then the longest matching prefix, then the default profile.
    #[inline]
    pub fn resolve_ip(&self, ip: IpAddr) -> &ProfileSlot {
        self.find_ip(ip).map_or(&self.default, |e| &e.slot)
    }

    #[inline]
    fn find_ip(&self, ip: IpAddr) -> Option<&Entry> {
        let ip = normalize_ip(ip);
        if let Some(s) = self.ips.get(&ip) {
            return Some(s);
        }
        match ip {
            IpAddr::V4(a) => {
                let a = u32::from(a);
                self.v4.iter().find_map(|l| l.map.get(&(a & l.mask)))
            }
            IpAddr::V6(a) => {
                let a = u128::from(a);
                self.v6.iter().find_map(|l| l.map.get(&(a & l.mask)))
            }
        }
    }

    #[inline]
    pub fn resolve_digest(&self, d: &[u8; 32]) -> Option<&ProfileSlot> {
        self.tokens.get(d).map(|e| &e.slot)
    }

    pub fn slot(&self, id: u64) -> Option<&ProfileSlot> {
        self.by_id.get(&id)
    }

    pub fn default_slot(&self) -> &ProfileSlot {
        &self.default
    }
}

struct PrefixLevel<K> {
    mask: K,
    map: FxHashMap<K, Entry>,
}

pub struct TableBuilder {
    ips: FxHashMap<IpAddr, Entry>,
    prefixes: Vec<(IpNet, Entry)>,
    tokens: FxHashMap<[u8; 32], Entry>,
    by_id: FxHashMap<u64, ProfileSlot>,
    default: ProfileSlot,
}

impl TableBuilder {
    pub fn profile(mut self, id: u64, slot: ProfileSlot) -> Self {
        self.by_id.insert(id, slot);
        self
    }
    fn get(&self, id: u64) -> Option<ProfileSlot> {
        self.by_id.get(&id).cloned()
    }
    /// Entries naming a profile id that was not registered are ignored.
    pub fn ip(self, addr: IpAddr, id: u64) -> Self {
        self.ip_for(addr, id, None)
    }
    pub fn prefix(self, net: IpNet, id: u64) -> Self {
        self.prefix_for(net, id, None)
    }
    pub fn token(self, digest: [u8; 32], id: u64) -> Self {
        self.token_for(digest, id, None)
    }
    /// Like [`Self::ip`], recording resolutions in `seen` (a device's last-seen cell, see
    /// [`Profiles::seen_cell`]).
    pub fn ip_for(mut self, addr: IpAddr, id: u64, seen: Option<Arc<AtomicU64>>) -> Self {
        if let Some(slot) = self.get(id) {
            self.ips.insert(normalize_ip(addr), Entry { slot, seen });
        }
        self
    }
    pub fn prefix_for(mut self, net: IpNet, id: u64, seen: Option<Arc<AtomicU64>>) -> Self {
        if let Some(slot) = self.get(id) {
            self.prefixes.push((net.trunc(), Entry { slot, seen }));
        }
        self
    }
    pub fn token_for(mut self, digest: [u8; 32], id: u64, seen: Option<Arc<AtomicU64>>) -> Self {
        if let Some(slot) = self.get(id) {
            self.tokens.insert(digest, Entry { slot, seen });
        }
        self
    }
    pub fn build(self) -> ProfileTable {
        let (mut v4, mut v6) = (
            Vec::<(u8, u32, Entry)>::new(),
            Vec::<(u8, u128, Entry)>::new(),
        );
        for (net, slot) in self.prefixes {
            match net {
                IpNet::V4(n) => v4.push((n.prefix_len(), u32::from(n.network()), slot)),
                IpNet::V6(n) => v6.push((n.prefix_len(), u128::from(n.network()), slot)),
            }
        }
        ProfileTable {
            ips: self.ips,
            v4: levels(v4, |len| u32::MAX.checked_shl(32 - len as u32).unwrap_or(0)),
            v6: levels(v6, |len| {
                u128::MAX.checked_shl(128 - len as u32).unwrap_or(0)
            }),
            tokens: self.tokens,
            by_id: self.by_id,
            default: self.default,
        }
    }
}

fn levels<K: Copy + Eq + std::hash::Hash>(
    mut entries: Vec<(u8, K, Entry)>,
    mask_of: impl Fn(u8) -> K,
) -> Vec<PrefixLevel<K>> {
    entries.sort_by_key(|e| std::cmp::Reverse(e.0));
    let mut out: Vec<(u8, PrefixLevel<K>)> = Vec::new();
    for (len, net, slot) in entries {
        if out.last().map(|l| l.0) != Some(len) {
            out.push((
                len,
                PrefixLevel {
                    mask: mask_of(len),
                    map: FxHashMap::default(),
                },
            ));
        }
        out.last_mut().unwrap().1.map.entry(net).or_insert(slot);
    }
    out.into_iter().map(|(_, l)| l).collect()
}

/// The live table plus the epoch connections compare against.
pub struct Profiles {
    table: ArcSwap<ProfileTable>,
    epoch: AtomicU64,
    /// Device id to last-seen cell. Locked only by the table builder and the API read path,
    /// never on resolve (the table entries hold the cells).
    seen: parking_lot::Mutex<FxHashMap<u64, Arc<AtomicU64>>>,
}

impl Profiles {
    /// A table holding only `default`.
    pub fn new(default: ProfileSlot) -> Self {
        Self {
            table: ArcSwap::from_pointee(ProfileTable::builder(default).build()),
            epoch: AtomicU64::new(0),
            seen: Default::default(),
        }
    }

    /// The last-seen cell of device `id` (created on first use; survives table publishes).
    pub fn seen_cell(&self, id: u64) -> Arc<AtomicU64> {
        self.seen.lock().entry(id).or_default().clone()
    }

    /// Forget devices not in `keep`.
    pub fn retain_seen(&self, keep: &std::collections::HashSet<u64>) {
        self.seen.lock().retain(|id, _| keep.contains(id));
    }

    /// When a connection last resolved to device `id` (unix seconds; `None`: not since start).
    pub fn last_seen(&self, id: u64) -> Option<u64> {
        self.seen
            .lock()
            .get(&id)
            .map(|c| c.load(Ordering::Relaxed))
            .filter(|&t| t != 0)
    }

    /// Resolve a device: a known token wins over the address. Returns the slot and the epoch it
    /// was resolved at. Clones one `Arc` (a refcount bump) and allocates nothing.
    #[inline]
    pub fn resolve(&self, ip: IpAddr, token: Option<&[u8]>) -> (ProfileSlot, u64) {
        self.resolve_by_digest(ip, token.map(token_digest).as_ref())
    }

    /// Like [`Self::resolve`] with a precomputed digest (used to re-resolve an open connection).
    #[inline]
    pub fn resolve_by_digest(&self, ip: IpAddr, digest: Option<&[u8; 32]>) -> (ProfileSlot, u64) {
        // Epoch first: if a publish races, the connection holds an older epoch and simply
        // re-resolves on its next request.
        let epoch = self.epoch.load(Ordering::Acquire);
        let t = self.table.load();
        if let Some(e) = digest.and_then(|d| t.tokens.get(d)) {
            e.touch();
            return (e.slot.clone(), epoch);
        }
        match t.find_ip(ip) {
            Some(e) => {
                e.touch();
                (e.slot.clone(), epoch)
            }
            None => (t.default.clone(), epoch),
        }
    }

    #[inline]
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Install a new table (device reassignment) and bump the epoch so open connections
    /// re-resolve on their next request.
    pub fn publish(&self, t: ProfileTable) {
        self.table.store(Arc::new(t));
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }

    /// Replace the profile in slot `id` (live edit). Open connections see it through the slot.
    pub fn edit(&self, id: u64, p: Arc<Profile>) -> bool {
        match self.table.load().slot(id) {
            Some(s) => {
                s.store(p);
                true
            }
            None => false,
        }
    }

    pub fn table(&self) -> arc_swap::Guard<Arc<ProfileTable>> {
        self.table.load()
    }
}

/// Digest of the password in a `Proxy-Authorization: Basic base64(user:password)` value. Decodes
/// into a stack buffer; tokens longer than 96 bytes are not device tokens and yield `None`.
pub fn digest_from_proxy_auth(value: &[u8]) -> Option<[u8; 32]> {
    let v = value.trim_ascii();
    let rest = v
        .get(..6)
        .filter(|p| p.eq_ignore_ascii_case(b"basic "))
        .map(|_| v[6..].trim_ascii())?;
    let mut buf = [0u8; 96];
    if rest.len() > 128 {
        return None;
    }
    let n = base64::engine::general_purpose::STANDARD
        .decode_slice(rest, &mut buf)
        .ok()?;
    let colon = buf[..n].iter().position(|&b| b == b':')?;
    Some(token_digest(&buf[colon + 1..n]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_ctx::default_profile_slot;
    use filter_engine::SharedEngine;

    fn slot(id: u64) -> ProfileSlot {
        Arc::new(ArcSwap::from_pointee(Profile::new(
            id,
            0,
            Arc::new(SharedEngine::new()),
        )))
    }
    fn id_of(s: &ProfileSlot) -> u64 {
        s.load().id
    }
    fn table() -> ProfileTable {
        ProfileTable::builder(default_profile_slot(Arc::new(SharedEngine::new())))
            .profile(1, slot(1))
            .profile(2, slot(2))
            .profile(3, slot(3))
            .prefix("10.0.0.0/8".parse().unwrap(), 1)
            .prefix("10.1.0.0/16".parse().unwrap(), 2)
            .ip("10.1.2.3".parse().unwrap(), 3)
            .token(token_digest(b"tok"), 3)
            .build()
    }

    #[test]
    fn longest_prefix_wins_and_unmatched_is_default() {
        let t = table();
        assert_eq!(id_of(t.resolve_ip("10.1.9.9".parse().unwrap())), 2);
        assert_eq!(id_of(t.resolve_ip("10.9.9.9".parse().unwrap())), 1);
        assert_eq!(id_of(t.resolve_ip("192.0.2.1".parse().unwrap())), 0);
    }

    #[test]
    fn exact_ip_beats_prefix() {
        let t = table();
        assert_eq!(id_of(t.resolve_ip("10.1.2.3".parse().unwrap())), 3);
    }

    #[test]
    fn v4_mapped_v6_resolves_like_v4() {
        let t = table();
        assert_eq!(id_of(t.resolve_ip("::ffff:10.1.2.3".parse().unwrap())), 3);
        assert_eq!(id_of(t.resolve_ip("::ffff:10.1.9.9".parse().unwrap())), 2);
    }

    #[test]
    fn token_beats_ip_and_unknown_token_falls_back() {
        let p = Profiles::new(default_profile_slot(Arc::new(SharedEngine::new())));
        p.publish(table());
        let ip = "10.1.9.9".parse().unwrap();
        assert_eq!(id_of(&p.resolve(ip, Some(b"tok")).0), 3);
        assert_eq!(id_of(&p.resolve(ip, Some(b"nope")).0), 2);
        assert_eq!(id_of(&p.resolve(ip, None).0), 2);
    }

    #[test]
    fn publish_bumps_epoch_edit_does_not() {
        let p = Profiles::new(default_profile_slot(Arc::new(SharedEngine::new())));
        let e0 = p.epoch();
        p.publish(table());
        assert_eq!(p.epoch(), e0 + 1);
        let cur = p.table().slot(1).unwrap().load_full();
        assert!(p.edit(1, Arc::new(cur.with(|c| c.generation = 9))));
        assert!(!p.edit(77, cur));
        assert_eq!(p.epoch(), e0 + 1);
        assert_eq!(p.table().slot(1).unwrap().load().generation, 9);
    }

    #[test]
    fn resolving_a_device_records_when_it_was_seen() {
        let p = Profiles::new(default_profile_slot(Arc::new(SharedEngine::new())));
        let cell = p.seen_cell(7);
        let t = ProfileTable::builder(p.table().default_slot().clone())
            .profile(1, slot(1))
            .ip_for("10.0.0.5".parse().unwrap(), 1, Some(cell))
            .token_for(token_digest(b"tok"), 1, Some(p.seen_cell(8)))
            .build();
        p.publish(t);
        assert_eq!(p.last_seen(7), None);
        p.resolve("10.0.0.6".parse().unwrap(), None);
        assert_eq!(p.last_seen(7), None, "other addresses do not count");
        p.resolve("10.0.0.5".parse().unwrap(), None);
        assert!(p.last_seen(7).is_some_and(|t| t > 1_600_000_000));
        assert_eq!(p.last_seen(8), None);
        p.resolve("10.0.0.6".parse().unwrap(), Some(b"tok"));
        assert!(p.last_seen(8).is_some());
        p.retain_seen(&[8].into_iter().collect());
        assert_eq!(p.last_seen(7), None, "forgotten devices are dropped");
    }

    #[test]
    fn proxy_authorization_password_is_the_token() {
        let h = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("u:tok")
        );
        assert_eq!(
            digest_from_proxy_auth(h.as_bytes()),
            Some(token_digest(b"tok"))
        );
        assert_eq!(digest_from_proxy_auth(b"Bearer abc"), None);
        assert_eq!(digest_from_proxy_auth(b"Basic !!!"), None);
    }
}

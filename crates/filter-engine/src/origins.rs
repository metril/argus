//! Which list each compiled network rule came from. adblock-rust reports the matched rule as
//! text (its converted form) but not its list, so the build records `hash(rule text) -> list`
//! next to the per-list rule texts; the engine generation keeps the table.
//!
//! Stored as two parallel arrays sorted by hash (10 bytes per rule, binary search). Pure domain
//! rules are not here: the domain set carries their list.

use sha2::{Digest, Sha256};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RuleOrigins {
    ids: Vec<String>,
    keys: Vec<u64>,
    lists: Vec<u16>,
}

fn hash(rule: &str) -> u64 {
    // Stable across builds and platforms (DefaultHasher is not), since the table is persisted.
    let d = Sha256::digest(rule.as_bytes());
    u64::from_le_bytes(d[..8].try_into().expect("8 bytes"))
}

impl RuleOrigins {
    /// Table for `ids`; `rules` yields `(list index, rule text)`.
    pub fn build<'a>(ids: Vec<String>, rules: impl Iterator<Item = (usize, &'a str)>) -> Self {
        let mut v: Vec<(u64, u16)> = rules
            .filter(|(l, _)| *l <= u16::MAX as usize)
            .map(|(l, r)| (hash(r.trim()), l as u16))
            .collect();
        // First list wins on a (cross-list duplicate) hash, as the build's own dedupe does.
        v.sort_by_key(|(k, _)| *k);
        v.dedup_by_key(|(k, _)| *k);
        Self {
            ids,
            keys: v.iter().map(|(k, _)| *k).collect(),
            lists: v.iter().map(|(_, l)| *l).collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The list id of the compiled rule `rule` (as adblock-rust reports it).
    pub fn lookup(&self, rule: &str) -> Option<&str> {
        if self.keys.is_empty() {
            return None;
        }
        let i = self.keys.binary_search(&hash(rule.trim())).ok()?;
        self.ids.get(self.lists[i] as usize).map(String::as_str)
    }

    /// Serialized form: `n_ids u32 | (len u32, bytes)* | n u64 | keys u64* | lists u16*`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(16 + self.keys.len() * 10);
        o.extend_from_slice(&(self.ids.len() as u32).to_le_bytes());
        for id in &self.ids {
            o.extend_from_slice(&(id.len() as u32).to_le_bytes());
            o.extend_from_slice(id.as_bytes());
        }
        o.extend_from_slice(&(self.keys.len() as u64).to_le_bytes());
        for k in &self.keys {
            o.extend_from_slice(&k.to_le_bytes());
        }
        for l in &self.lists {
            o.extend_from_slice(&l.to_le_bytes());
        }
        o
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        fn take<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8], String> {
            if b.len() < n {
                return Err("short rule origins".into());
            }
            let (h, t) = b.split_at(n);
            *b = t;
            Ok(h)
        }
        let mut b = b;
        let n_ids = u32::from_le_bytes(take(&mut b, 4)?.try_into().unwrap()) as usize;
        let mut ids = Vec::new();
        for _ in 0..n_ids {
            let n = u32::from_le_bytes(take(&mut b, 4)?.try_into().unwrap()) as usize;
            ids.push(String::from_utf8(take(&mut b, n)?.to_vec()).map_err(|_| "bad origin id")?);
        }
        let n = u64::from_le_bytes(take(&mut b, 8)?.try_into().unwrap()) as usize;
        let need = n.checked_mul(10).ok_or("bad rule origins")?;
        if b.len() != need {
            return Err("bad rule origins length".into());
        }
        let keys: Vec<u64> = b[..n * 8]
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        let lists: Vec<u16> = b[n * 8..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
            .collect();
        if lists.iter().any(|l| *l as usize >= ids.len()) || keys.windows(2).any(|w| w[0] >= w[1]) {
            return Err("inconsistent rule origins".into());
        }
        Ok(Self { ids, keys, lists })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_and_round_trip() {
        let o = RuleOrigins::build(
            vec!["a".into(), "b".into()],
            [
                (0, "||x.test^$script"),
                (1, "||y.test^"),
                (1, "||x.test^$script"),
            ]
            .into_iter(),
        );
        assert_eq!(o.lookup("||x.test^$script"), Some("a"));
        assert_eq!(o.lookup("||y.test^"), Some("b"));
        assert_eq!(o.lookup("||z.test^"), None);
        let r = RuleOrigins::from_bytes(&o.to_bytes()).unwrap();
        assert_eq!(r, o);
        assert!(RuleOrigins::from_bytes(&o.to_bytes()[..7]).is_err());
    }
}

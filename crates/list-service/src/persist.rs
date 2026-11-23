//! Persisted compiled engine: written atomically after a successful build and loaded at startup
//! when its cache key still matches, so the proxy blocks within milliseconds and works offline.
//!
//! File layout: `MAGIC | key[32] | body_len u64 LE | body | sha256(body)[32]`, where `body` is
//! `blob_len u64 LE | engine blob | dom_len u64 LE | domain set | sidecar JSON`; the domain set is
//! the raw table of `filter_engine::DomainSet` (loaded without re-hashing) and the sidecar holds
//! the extended-rule list, IP ranges and build summary.
//!
//! The key hashes the converter version, the adblock crate version, and per list its id, format
//! override, allowlist flag and content digest (list text plus resolved includes), plus the custom
//! rules. Scriptlet/redirect resources are deliberately not part of it: they are applied on top of
//! the deserialized engine and do not affect the compiled blob.

use std::io::Write;
use std::path::Path;

use filter_engine::{DomainSet, ExtRule, IpFilter, IpRange, ListFormat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::report::BuildSummary;

const MAGIC: &[u8; 6] = b"ABENG\x03";
pub(crate) const FILE_NAME: &str = "engine.bin";

pub(crate) type Key = [u8; 32];

/// One list's contribution to the cache key.
pub(crate) struct KeyEntry<'a> {
    pub id: &'a str,
    pub format: ListFormat,
    pub allowlist: bool,
    /// Trust changes what the extended rules may do, so it is part of the key.
    pub trusted: bool,
    pub digest: &'a str,
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex SHA-256 of a list's text and its resolved includes.
pub(crate) fn content_digest<'a>(
    content: &str,
    includes: impl IntoIterator<Item = (&'a String, &'a String)>,
) -> String {
    let mut h = Sha256::new();
    h.update(content.as_bytes());
    for (path, text) in includes {
        h.update([0]);
        h.update(path.as_bytes());
        h.update([0]);
        h.update(Sha256::digest(text.as_bytes()));
    }
    hex(&h.finalize())
}

pub(crate) fn engine_key(entries: &mut [KeyEntry<'_>], custom_digest: &str) -> Key {
    entries.sort_by(|a, b| a.id.cmp(b.id));
    let mut h = Sha256::new();
    h.update(b"argus-engine-key\0");
    h.update(filter_engine::formats::CONVERTER_VERSION.to_le_bytes());
    h.update(filter_engine::ADBLOCK_CRATE_VERSION.as_bytes());
    for e in entries.iter() {
        h.update([0]);
        h.update(e.id.as_bytes());
        h.update([0]);
        h.update(e.format.as_str().as_bytes());
        h.update([e.allowlist as u8, e.trusted as u8, 0]);
        h.update(e.digest.as_bytes());
    }
    h.update(b"\0custom\0");
    h.update(custom_digest.as_bytes());
    h.finalize().into()
}

#[derive(Serialize, Deserialize)]
struct Sidecar {
    ext: Vec<ExtRule>,
    ip_block: Vec<IpRange>,
    ip_allow: Vec<IpRange>,
    summary: BuildSummary,
}

/// What [`load`] returns.
#[derive(Debug)]
pub(crate) struct Persisted {
    pub blob: Vec<u8>,
    pub domains: DomainSet,
    pub ext: Vec<ExtRule>,
    pub ip: IpFilter,
    pub summary: BuildSummary,
}

/// Atomically write the engine: temp file in the same directory, fsync, rename.
pub(crate) fn save(
    path: &Path,
    key: &Key,
    blob: &[u8],
    domains: &DomainSet,
    ext: &[ExtRule],
    ip: &IpFilter,
    summary: &BuildSummary,
) -> std::io::Result<()> {
    let sidecar = serde_json::to_vec(&Sidecar {
        ext: ext.to_vec(),
        ip_block: ip.block.ranges(),
        ip_allow: ip.allow.ranges(),
        summary: summary.clone(),
    })
    .map_err(std::io::Error::other)?;
    let dom = domains.to_bytes();
    let mut body = Vec::with_capacity(16 + blob.len() + dom.len() + sidecar.len());
    body.extend_from_slice(&(blob.len() as u64).to_le_bytes());
    body.extend_from_slice(blob);
    body.extend_from_slice(&(dom.len() as u64).to_le_bytes());
    body.extend_from_slice(&dom);
    body.extend_from_slice(&sidecar);

    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("bin.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(MAGIC)?;
        f.write_all(key)?;
        f.write_all(&(body.len() as u64).to_le_bytes())?;
        f.write_all(&body)?;
        f.write_all(&Sha256::digest(&body))?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all(); // make the rename durable; best effort
    }
    Ok(())
}

fn read_len(b: &[u8]) -> Result<usize, String> {
    let n = u64::from_le_bytes(b.try_into().map_err(|_| "short length")?);
    usize::try_from(n).map_err(|_| "length out of range".to_string())
}

/// Split a `u64` length-prefixed chunk off the front of `b`: `(chunk, rest)`.
fn split_chunk(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = read_len(b.get(..8)?).ok()?;
    let end = 8usize.checked_add(len)?;
    Some((b.get(8..end)?, b.get(end..)?))
}

/// Load and verify the persisted engine. `Err` says why it was rejected (missing, wrong key,
/// truncated, corrupt).
pub(crate) fn load(path: &Path, key: &Key) -> Result<Persisted, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read: {e}"))?;
    let head = MAGIC.len() + 32 + 8;
    if bytes.len() < head + 32 || &bytes[..MAGIC.len()] != MAGIC {
        return Err("bad header".into());
    }
    if &bytes[MAGIC.len()..MAGIC.len() + 32] != key {
        return Err("cache key mismatch".into());
    }
    let len = read_len(&bytes[head - 8..head])?;
    // Every length read from the file is checked against what is actually there before slicing.
    let total = head
        .checked_add(len)
        .and_then(|n| n.checked_add(32))
        .ok_or("bad body length")?;
    if bytes.len() != total {
        return Err("truncated or oversized".into());
    }
    let body = &bytes[head..head + len];
    if Sha256::digest(body).as_slice() != &bytes[head + len..] {
        return Err("checksum mismatch".into());
    }
    let (blob, rest) = split_chunk(body).ok_or("short engine blob")?;
    let (dom, side_bytes) = split_chunk(rest).ok_or("short domain set")?;
    let domains = DomainSet::from_bytes(dom)?;
    let side: Sidecar = serde_json::from_slice(side_bytes).map_err(|e| format!("sidecar: {e}"))?;
    Ok(Persisted {
        blob: blob.to_vec(),
        domains,
        ext: side.ext,
        ip: IpFilter::from_ranges(&side.ip_block, &side.ip_allow),
        summary: side.summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> Key {
        [n; 32]
    }

    #[test]
    fn round_trip_and_rejections() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let ip = IpFilter::from_ranges(&[IpRange::parse("10.0.0.0/8").unwrap()], &[]);
        let summary = BuildSummary {
            network: 7,
            ..Default::default()
        };
        let mut db = filter_engine::DomainSetBuilder::new(vec!["l".into()]);
        db.add_suffix("blocked.test", 0);
        let domains = db.finish(true, true).set;
        save(
            &path,
            &key(1),
            b"engine-bytes",
            &domains,
            &[],
            &ip,
            &summary,
        )
        .unwrap();
        let p = load(&path, &key(1)).unwrap();
        assert_eq!(p.blob, b"engine-bytes");
        assert_eq!(p.summary.network, 7);
        assert_eq!(p.domains.len(), 1);
        assert!(p
            .domains
            .lookup("a.blocked.test", filter_engine::Scheme::Https)
            .is_some());
        assert!(p.ip.block.contains("10.1.2.3".parse().unwrap()));
        assert!(load(&path, &key(2)).unwrap_err().contains("key"));

        let good = std::fs::read(&path).unwrap();
        for cut in [0, 5, 20, good.len() - 1] {
            std::fs::write(&path, &good[..cut]).unwrap();
            assert!(load(&path, &key(1)).is_err(), "cut {cut}");
        }
        let mut flipped = good.clone();
        let mid = flipped.len() / 2;
        flipped[mid] ^= 0xff;
        std::fs::write(&path, &flipped).unwrap();
        assert!(load(&path, &key(1)).is_err());
        assert!(load(&dir.path().join("missing"), &key(1)).is_err());
        assert!(!dir.path().join("engine.bin.tmp").exists());
    }

    /// Re-seal `body` into a file image with a valid header and checksum.
    fn seal(key: &Key, body: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(MAGIC);
        f.extend_from_slice(key);
        f.extend_from_slice(&(body.len() as u64).to_le_bytes());
        f.extend_from_slice(body);
        f.extend_from_slice(&Sha256::digest(body));
        f
    }

    /// Load `image` the way the service does, on a thread with a deadline.
    fn load_with_deadline(path: std::path::PathBuf, image: Vec<u8>, key: Key) {
        std::fs::write(&path, image).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = std::panic::catch_unwind(|| {
                if let Ok(p) = load(&path, &key) {
                    let _ = filter_engine::try_build_engine(&p.blob, &[]);
                    let _ = p
                        .domains
                        .lookup("a.blocked.test", filter_engine::Scheme::Https);
                }
            });
            let _ = tx.send(r.is_ok());
        });
        let ok = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("loading a corrupt engine file hung");
        assert!(ok, "loading a corrupt engine file panicked");
    }

    #[test]
    fn corrupt_engine_files_never_panic_or_hang() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let list = filter_engine::ListInput {
            id: "l".into(),
            content: "||ads.example.com^\n||blocked.test^\n##.banner\n".into(),
            format: ListFormat::Auto,
            allowlist: false,
            trusted: false,
            includes: Default::default(),
        };
        let built = filter_engine::build_set(&[list]);
        let k = key(3);
        save(
            &path,
            &k,
            &built.blob,
            &built.domains,
            &[],
            &IpFilter::default(),
            &BuildSummary::default(),
        )
        .unwrap();
        let good = std::fs::read(&path).unwrap();
        let head = MAGIC.len() + 32 + 8;
        let body = good[head..good.len() - 32].to_vec();
        assert!(load(&path, &k).is_ok());

        // Oversized length fields (`8 + len` would overflow).
        let blob_len = u64::from_le_bytes(body[..8].try_into().unwrap()) as usize;
        for huge in [u64::MAX, u64::MAX - 7, u64::MAX - 8, 1 << 63] {
            let mut b = body.clone();
            b[..8].copy_from_slice(&huge.to_le_bytes());
            load_with_deadline(path.clone(), seal(&k, &b), k);
            let mut b = body.clone();
            let at = 8 + blob_len;
            b[at..at + 8].copy_from_slice(&huge.to_le_bytes());
            load_with_deadline(path.clone(), seal(&k, &b), k);
        }
        // Random mutations and truncations, checksum recomputed so the parser really runs.
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..300 {
            let mut b = body.clone();
            match next() % 3 {
                0 => {
                    for _ in 0..1 + next() % 4 {
                        let i = (next() as usize) % b.len();
                        b[i] ^= 1 << (next() % 8);
                    }
                }
                1 => b.truncate((next() as usize) % b.len()),
                _ => {
                    // Corrupt the length prefixes and the domain-set header area in particular.
                    let i = (next() as usize) % 64.min(b.len());
                    b[i] = next() as u8;
                }
            }
            load_with_deadline(path.clone(), seal(&k, &b), k);
        }
    }

    #[test]
    fn key_changes_with_every_input() {
        let base = |d: &str, fmt, allow, custom: &str| {
            engine_key(
                &mut [KeyEntry {
                    id: "a",
                    format: fmt,
                    allowlist: allow,
                    trusted: false,
                    digest: d,
                }],
                custom,
            )
        };
        let k = base("d1", ListFormat::Auto, false, "");
        assert_eq!(k, base("d1", ListFormat::Auto, false, ""));
        assert_ne!(k, base("d2", ListFormat::Auto, false, ""));
        assert_ne!(k, base("d1", ListFormat::Hosts, false, ""));
        assert_ne!(k, base("d1", ListFormat::Auto, true, ""));
        assert_ne!(k, base("d1", ListFormat::Auto, false, "x"));
        let trusted = engine_key(
            &mut [KeyEntry {
                id: "a",
                format: ListFormat::Auto,
                allowlist: false,
                trusted: true,
                digest: "d1",
            }],
            "",
        );
        assert_ne!(k, trusted);
    }
}

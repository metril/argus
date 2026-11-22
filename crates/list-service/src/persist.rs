//! Persisted compiled engine: written atomically after a successful build and loaded at startup
//! when its cache key still matches, so the proxy blocks within milliseconds and works offline.
//!
//! File layout: `MAGIC | key[32] | body_len u64 LE | body | sha256(body)[32]`, where `body` is
//! `blob_len u64 LE | engine blob | sidecar JSON` and the sidecar holds the extended-rule list, IP
//! ranges and build summary.
//!
//! The key hashes the converter version, the adblock crate version, and per list its id, format
//! override, allowlist flag and content digest (list text plus resolved includes), plus the custom
//! rules. Scriptlet/redirect resources are deliberately not part of it: they are applied on top of
//! the deserialized engine and do not affect the compiled blob.

use std::io::Write;
use std::path::Path;

use filter_engine::{ExtRule, IpFilter, IpRange, ListFormat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::report::BuildSummary;

const MAGIC: &[u8; 6] = b"ABENG\x01";
pub(crate) const FILE_NAME: &str = "engine.bin";

pub(crate) type Key = [u8; 32];

/// One list's contribution to the cache key.
pub(crate) struct KeyEntry<'a> {
    pub id: &'a str,
    pub format: ListFormat,
    pub allowlist: bool,
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
    h.update(b"adblocker-engine-key\0");
    h.update(filter_engine::formats::CONVERTER_VERSION.to_le_bytes());
    h.update(filter_engine::ADBLOCK_CRATE_VERSION.as_bytes());
    for e in entries.iter() {
        h.update([0]);
        h.update(e.id.as_bytes());
        h.update([0]);
        h.update(e.format.as_str().as_bytes());
        h.update([e.allowlist as u8, 0]);
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
    pub ext: Vec<ExtRule>,
    pub ip: IpFilter,
    pub summary: BuildSummary,
}

/// Atomically write the engine: temp file in the same directory, fsync, rename.
pub(crate) fn save(
    path: &Path,
    key: &Key,
    blob: &[u8],
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
    let mut body = Vec::with_capacity(8 + blob.len() + sidecar.len());
    body.extend_from_slice(&(blob.len() as u64).to_le_bytes());
    body.extend_from_slice(blob);
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
    let len = u64::from_le_bytes(bytes[head - 8..head].try_into().unwrap()) as usize;
    if bytes.len() != head + len + 32 {
        return Err("truncated or oversized".into());
    }
    let body = &bytes[head..head + len];
    if Sha256::digest(body).as_slice() != &bytes[head + len..] {
        return Err("checksum mismatch".into());
    }
    if body.len() < 8 {
        return Err("short body".into());
    }
    let blob_len = u64::from_le_bytes(body[..8].try_into().unwrap()) as usize;
    if body.len() < 8 + blob_len {
        return Err("short engine blob".into());
    }
    let side: Sidecar =
        serde_json::from_slice(&body[8 + blob_len..]).map_err(|e| format!("sidecar: {e}"))?;
    Ok(Persisted {
        blob: body[8..8 + blob_len].to_vec(),
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
        save(&path, &key(1), b"engine-bytes", &[], &ip, &summary).unwrap();
        let p = load(&path, &key(1)).unwrap();
        assert_eq!(p.blob, b"engine-bytes");
        assert_eq!(p.summary.network, 7);
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

    #[test]
    fn key_changes_with_every_input() {
        let base = |d: &str, fmt, allow, custom: &str| {
            engine_key(
                &mut [KeyEntry {
                    id: "a",
                    format: fmt,
                    allowlist: allow,
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
    }
}

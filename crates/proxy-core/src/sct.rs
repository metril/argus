//! Certificate Transparency receipts (RFC 6962): verify the SCTs embedded in a leaf against a
//! signed list of CT logs, for roots that are only trusted for certificates logged before a date.
//!
//! Static-CT (tiled) logs issue RFC 6962 SCTs too; their SCT `extensions` carry a leaf index.
//! The extensions bytes are part of the signed structure either way, so both log types verify
//! the same way.

use std::collections::HashMap;

use rustls::pki_types::SignatureVerificationAlgorithm;
use sha2::{Digest, Sha256};

/// Object identifier of the embedded SCT list, 1.3.6.1.4.1.11129.2.4.2, as DER content bytes.
const SCT_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];

/// Operational state of a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogState {
    Usable,
    Qualified,
    ReadOnly,
    Retired,
}

/// One CT log from the signed roots file.
#[derive(Debug, Clone)]
pub struct CtLog {
    pub id: [u8; 32],
    /// SubjectPublicKeyInfo DER.
    pub key: Vec<u8>,
    pub state: LogState,
    /// Unix seconds the log entered `state`.
    pub state_since: i64,
    /// Unix seconds `[start, end)` of certificate expiry dates the log accepts.
    pub interval: Option<(i64, i64)>,
}

impl CtLog {
    /// Whether a receipt from this log counts: the log was good when it issued it (usable,
    /// qualified or read-only now, or retired only after the timestamp) and, for a temporal
    /// shard, the certificate expires inside its interval.
    fn accepts(&self, timestamp_ms: u64, not_after: i64) -> bool {
        let ok_state = match self.state {
            LogState::Usable | LogState::Qualified | LogState::ReadOnly => true,
            LogState::Retired => {
                i64::try_from(timestamp_ms / 1000).is_ok_and(|t| t < self.state_since)
            }
        };
        ok_state
            && self
                .interval
                .is_none_or(|(start, end)| not_after >= start && not_after < end)
    }
}

/// A DER TLV split into its tag, content and the bytes after it.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let l0 = *b.get(1)?;
    let (len, hdr) = if l0 < 0x80 {
        (l0 as usize, 2)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    Some((tag, b.get(hdr..end)?, b.get(end..)?))
}

fn put_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[0x81, n as u8]);
    } else if n <= 0xffff {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    } else {
        out.extend_from_slice(&[0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
}

/// The TBSCertificate DER with the embedded-SCT extension removed (the "precertificate TBS" the
/// logs signed). `None` when it cannot be parsed.
fn tbs_without_sct(tbs: &[u8]) -> Option<Vec<u8>> {
    let (tag, body, _) = tlv(tbs)?;
    if tag != 0x30 {
        return None;
    }
    let mut rebuilt = Vec::with_capacity(body.len());
    let mut rest = body;
    while !rest.is_empty() {
        let (t, content, after) = tlv(rest)?;
        let whole = &rest[..rest.len() - after.len()];
        if t == 0xa3 {
            // [3] EXPLICIT Extensions: SEQUENCE OF Extension.
            let (st, exts, _) = tlv(content)?;
            if st != 0x30 {
                return None;
            }
            let mut kept = Vec::new();
            let mut e = exts;
            while !e.is_empty() {
                let (et, econtent, eafter) = tlv(e)?;
                let ewhole = &e[..e.len() - eafter.len()];
                let (ot, oid, _) = tlv(econtent)?;
                if !(et == 0x30 && ot == 0x06 && oid == SCT_OID) {
                    kept.extend_from_slice(ewhole);
                }
                e = eafter;
            }
            if !kept.is_empty() {
                let mut seq = Vec::new();
                put_tlv(&mut seq, 0x30, &kept);
                put_tlv(&mut rebuilt, 0xa3, &seq);
            }
        } else {
            rebuilt.extend_from_slice(whole);
        }
        rest = after;
    }
    let mut out = Vec::with_capacity(rebuilt.len() + 4);
    put_tlv(&mut out, 0x30, &rebuilt);
    Some(out)
}

/// The signed bytes of a precertificate SCT (RFC 6962 section 3.2): version, signature type,
/// timestamp, entry type, issuer key hash, TBS certificate, extensions.
fn signed_message(
    timestamp: u64,
    issuer_key_hash: &[u8; 32],
    tbs: &[u8],
    extensions: &[u8],
) -> Option<Vec<u8>> {
    let tbs_len = u32::try_from(tbs.len()).ok().filter(|n| *n < 1 << 24)?;
    let ext_len = u16::try_from(extensions.len()).ok()?;
    let mut m = Vec::with_capacity(tbs.len() + extensions.len() + 64);
    m.extend_from_slice(&[0, 0]);
    m.extend_from_slice(&timestamp.to_be_bytes());
    m.extend_from_slice(&[0, 1]);
    m.extend_from_slice(issuer_key_hash);
    m.extend_from_slice(&tbs_len.to_be_bytes()[1..]);
    m.extend_from_slice(tbs);
    m.extend_from_slice(&ext_len.to_be_bytes());
    m.extend_from_slice(extensions);
    Some(m)
}

/// Verify `signature` (a DigitallySigned body: DER ECDSA or PKCS#1 RSA) over `message` with the
/// log's `spki`. Only SHA-256 with ECDSA P-256 or RSA is accepted (what CT logs use).
fn verify_log_signature(spki: &[u8], sign_alg: u8, message: &[u8], signature: &[u8]) -> bool {
    use x509_parser::prelude::FromDer;
    let Ok((_, key)) = x509_parser::x509::SubjectPublicKeyInfo::from_der(spki) else {
        return false;
    };
    let alg: &dyn SignatureVerificationAlgorithm = match sign_alg {
        3 => webpki::ring::ECDSA_P256_SHA256,
        1 => webpki::ring::RSA_PKCS1_2048_8192_SHA256,
        _ => return false,
    };
    alg.verify_signature(key.subject_public_key.data.as_ref(), message, signature)
        .is_ok()
}

/// The earliest timestamp (Unix milliseconds) of an embedded SCT in `leaf` that verifies against
/// a log in `logs` that counts for it, or `None` when there is no such SCT. `issuer_spki` is the
/// issuing certificate's SubjectPublicKeyInfo DER. A forged or unknown-log SCT is ignored.
pub fn earliest_valid_sct_ms(
    leaf: &[u8],
    issuer_spki: &[u8],
    logs: &HashMap<[u8; 32], CtLog>,
) -> Option<u64> {
    use x509_parser::extensions::ParsedExtension;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf).ok()?;
    let scts = cert
        .extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::SCT(list) => Some(list),
            _ => None,
        })?;
    let tbs = tbs_without_sct(cert.tbs_certificate.as_ref())?;
    let key_hash: [u8; 32] = Sha256::digest(issuer_spki).into();
    let not_after = cert.validity().not_after.timestamp();
    let mut earliest: Option<u64> = None;
    for sct in scts {
        // Version 1 (value 0) is the only one RFC 6962 defines; anything else is ignored.
        if sct.version.0 != 0 || sct.signature.hash_alg_id != 4 {
            continue;
        }
        let Some(log) = logs.get(sct.id.key_id) else {
            continue;
        };
        if !log.accepts(sct.timestamp, not_after) {
            continue;
        }
        let Some(msg) = signed_message(sct.timestamp, &key_hash, &tbs, sct.extensions.0) else {
            continue;
        };
        if verify_log_signature(
            &log.key,
            sct.signature.sign_alg_id,
            &msg,
            sct.signature.data,
        ) {
            earliest = Some(earliest.map_or(sct.timestamp, |e| e.min(sct.timestamp)));
        }
    }
    earliest
}

#[cfg(test)]
pub(crate) mod testkit {
    //! Generated CT logs and certificates with embedded SCTs, for tests.

    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyPair,
        SerialNumber,
    };
    use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    /// A test log: a signing key and its public identity.
    pub struct TestLog {
        pub id: [u8; 32],
        pub spki: Vec<u8>,
        signer: EcdsaKeyPair,
    }

    impl TestLog {
        pub fn new() -> Self {
            let key = KeyPair::generate().unwrap();
            let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
            let signer = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                &key.serialize_der(),
                &ring::rand::SystemRandom::new(),
            )
            .unwrap();
            Self {
                id: Sha256::digest(&spki).into(),
                spki,
                signer,
            }
        }

        pub fn entry(&self, state: LogState, state_since: i64) -> CtLog {
            CtLog {
                id: self.id,
                key: self.spki.clone(),
                state,
                state_since,
                interval: None,
            }
        }

        fn sct(&self, ts: u64, message: &[u8], extensions: &[u8]) -> Vec<u8> {
            let sig = self
                .signer
                .sign(&ring::rand::SystemRandom::new(), message)
                .unwrap();
            let sig = sig.as_ref();
            let mut s = vec![0];
            s.extend_from_slice(&self.id);
            s.extend_from_slice(&ts.to_be_bytes());
            s.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            s.extend_from_slice(extensions);
            s.extend_from_slice(&[4, 3]);
            s.extend_from_slice(&(sig.len() as u16).to_be_bytes());
            s.extend_from_slice(sig);
            s
        }
    }

    /// A CA, with the DER of its certificate.
    pub struct TestCa {
        pub der: Vec<u8>,
        pub issuer: Issuer<'static, KeyPair>,
        pub spki: Vec<u8>,
    }

    pub fn ca(cn: &str) -> TestCa {
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name.push(DnType::CommonName, cn);
        let key = KeyPair::generate().unwrap();
        let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
        let cert = p.self_signed(&key).unwrap();
        TestCa {
            der: cert.der().to_vec(),
            issuer: Issuer::new(p, key),
            spki,
        }
    }

    /// One SCT to embed: which log, its timestamp (ms), its extensions bytes, and whether to
    /// corrupt the signature.
    pub struct Receipt<'a> {
        pub log: &'a TestLog,
        pub ts: u64,
        pub extensions: Vec<u8>,
        pub forged: bool,
        /// Sign these extension bytes instead of the ones carried (a tampered SCT).
        pub signed_ext: Option<Vec<u8>>,
    }

    impl<'a> Receipt<'a> {
        pub fn ok(log: &'a TestLog, ts: u64) -> Self {
            Self {
                log,
                ts,
                extensions: vec![],
                forged: false,
                signed_ext: None,
            }
        }
    }

    /// A leaf for `name` issued by `ca`, carrying `receipts` as embedded SCTs. The log signs the
    /// certificate as it is without the SCT extension, found by issuing it once without.
    pub fn leaf_with_scts(ca: &TestCa, name: &str, receipts: &[Receipt<'_>]) -> Vec<u8> {
        let params = |ext: Option<Vec<u8>>| {
            let mut p = CertificateParams::new(vec![name.to_string()]).unwrap();
            p.distinguished_name.push(DnType::CommonName, name);
            p.serial_number = Some(SerialNumber::from(vec![1, 2, 3, 4]));
            if let Some(content) = ext {
                p.custom_extensions.push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2],
                    content,
                ));
            }
            p
        };
        let key = KeyPair::generate().unwrap();
        let bare = params(None).signed_by(&key, &ca.issuer).unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(bare.der()).unwrap();
        let tbs = parsed.tbs_certificate.as_ref().to_vec();
        let key_hash: [u8; 32] = Sha256::digest(&ca.spki).into();
        let mut list = Vec::new();
        for r in receipts {
            let signed = r.signed_ext.as_ref().unwrap_or(&r.extensions);
            let msg = signed_message(r.ts, &key_hash, &tbs, signed).unwrap();
            let mut sct = r.log.sct(r.ts, &msg, &r.extensions);
            if r.forged {
                let n = sct.len();
                sct[n - 3] ^= 0xff;
            }
            list.extend_from_slice(&(sct.len() as u16).to_be_bytes());
            list.extend_from_slice(&sct);
        }
        let mut tls = (list.len() as u16).to_be_bytes().to_vec();
        tls.extend_from_slice(&list);
        let mut ext = Vec::new();
        put_tlv(&mut ext, 0x04, &tls);
        params(Some(ext))
            .signed_by(&key, &ca.issuer)
            .unwrap()
            .der()
            .to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    fn logs(entries: &[CtLog]) -> HashMap<[u8; 32], CtLog> {
        entries.iter().map(|l| (l.id, l.clone())).collect()
    }

    const T: u64 = 1_700_000_000_000;

    #[test]
    fn tbs_reconstruction_matches_the_certificate_issued_without_the_sct() {
        let ca = ca("ca");
        let log = TestLog::new();
        let leaf = leaf_with_scts(&ca, "a.test", &[Receipt::ok(&log, T)]);
        let (_, c) = x509_parser::parse_x509_certificate(&leaf).unwrap();
        let rebuilt = tbs_without_sct(c.tbs_certificate.as_ref()).unwrap();
        assert!(!rebuilt.windows(SCT_OID.len()).any(|w| w == SCT_OID));
        assert!(rebuilt.len() < c.tbs_certificate.as_ref().len());
    }

    #[test]
    fn a_valid_receipt_verifies_and_the_earliest_wins() {
        let ca = ca("ca");
        let (a, b) = (TestLog::new(), TestLog::new());
        let leaf = leaf_with_scts(
            &ca,
            "a.test",
            &[Receipt::ok(&a, T + 5000), Receipt::ok(&b, T)],
        );
        let l = logs(&[
            a.entry(LogState::Usable, 0),
            b.entry(LogState::Qualified, 0),
        ]);
        assert_eq!(earliest_valid_sct_ms(&leaf, &ca.spki, &l), Some(T));
    }

    #[test]
    fn a_forged_signature_an_unknown_log_and_a_wrong_issuer_are_ignored() {
        let ca = ca("ca");
        let (good, other) = (TestLog::new(), TestLog::new());
        let leaf = leaf_with_scts(
            &ca,
            "a.test",
            &[
                Receipt {
                    forged: true,
                    ..Receipt::ok(&good, T - 1000)
                },
                Receipt::ok(&other, T - 2000),
                Receipt::ok(&good, T),
            ],
        );
        // `other` is not in the list; the forged receipt of `good` does not verify.
        let l = logs(&[good.entry(LogState::Usable, 0)]);
        assert_eq!(earliest_valid_sct_ms(&leaf, &ca.spki, &l), Some(T));
        // Only forged or unknown receipts: nothing verifies.
        let none = leaf_with_scts(
            &ca,
            "b.test",
            &[Receipt {
                forged: true,
                ..Receipt::ok(&good, T)
            }],
        );
        assert_eq!(earliest_valid_sct_ms(&none, &ca.spki, &l), None);
        // The issuer key is part of the signed data.
        let wrong = super::testkit::ca("other ca");
        assert_eq!(earliest_valid_sct_ms(&leaf, &wrong.spki, &l), None);
    }

    #[test]
    fn a_retired_log_counts_only_for_receipts_before_it_retired() {
        let ca = ca("ca");
        let log = TestLog::new();
        let leaf = leaf_with_scts(&ca, "a.test", &[Receipt::ok(&log, T)]);
        let retired_after = logs(&[log.entry(LogState::Retired, (T / 1000) as i64 + 10)]);
        assert_eq!(
            earliest_valid_sct_ms(&leaf, &ca.spki, &retired_after),
            Some(T)
        );
        let retired_before = logs(&[log.entry(LogState::Retired, (T / 1000) as i64 - 10)]);
        assert_eq!(
            earliest_valid_sct_ms(&leaf, &ca.spki, &retired_before),
            None
        );
    }

    #[test]
    fn a_temporal_shard_must_cover_the_certificates_expiry() {
        let ca = ca("ca");
        let log = TestLog::new();
        let leaf = leaf_with_scts(&ca, "a.test", &[Receipt::ok(&log, T)]);
        let mut e = log.entry(LogState::Usable, 0);
        e.interval = Some((0, 1000));
        assert_eq!(
            earliest_valid_sct_ms(&leaf, &ca.spki, &logs(&[e.clone()])),
            None
        );
        e.interval = Some((0, i64::MAX));
        assert_eq!(earliest_valid_sct_ms(&leaf, &ca.spki, &logs(&[e])), Some(T));
    }

    #[test]
    fn static_ct_receipts_with_extensions_verify_and_the_extensions_are_signed() {
        let ca = ca("ca");
        let log = TestLog::new();
        // A static-CT SCT carries a leaf-index extension (type 0, 5-byte index).
        let ext = vec![0, 0, 5, 0, 0, 0, 0, 42];
        let leaf = leaf_with_scts(
            &ca,
            "a.test",
            &[Receipt {
                extensions: ext.clone(),
                ..Receipt::ok(&log, T)
            }],
        );
        let l = logs(&[log.entry(LogState::Usable, 0)]);
        assert_eq!(earliest_valid_sct_ms(&leaf, &ca.spki, &l), Some(T));
        // The extensions are part of what is signed: a receipt whose carried extensions differ
        // from the signed ones does not verify.
        let tampered = leaf_with_scts(
            &ca,
            "b.test",
            &[Receipt {
                extensions: ext,
                signed_ext: Some(vec![]),
                ..Receipt::ok(&log, T)
            }],
        );
        assert_eq!(earliest_valid_sct_ms(&tampered, &ca.spki, &l), None);
    }
}

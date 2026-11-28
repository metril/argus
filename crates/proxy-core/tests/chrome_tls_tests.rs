//! The upstream TLS ClientHello of the browser emulation profiles against ClientHellos captured
//! from real Chrome builds (fixtures in `tests/fixtures/chrome-tls/`, see `docs/UPSTREAM-TLS.md`).
//!
//! Every test starts a throwaway local listener that records the first TLS record of each
//! connection and drops it, so nothing depends on a third-party service.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use proxy_core::browser_profile::BrowserProfile;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

// ---- ClientHello parsing -------------------------------------------------------------------

struct Hello {
    ciphers: Vec<u16>,
    exts: Vec<(u16, Vec<u8>)>,
}

fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

fn u16s(b: &[u8]) -> Vec<u16> {
    b.chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

fn hex(v: u16) -> String {
    format!("{v:04x}")
}

fn grease_or_hex(v: u16) -> String {
    if is_grease(v) {
        "GREASE".into()
    } else {
        hex(v)
    }
}

fn parse_hello(rec: &[u8]) -> Hello {
    assert_eq!(rec[0], 22, "handshake record");
    let hs = &rec[5..];
    assert_eq!(hs[0], 1, "ClientHello");
    let b = &hs[4..];
    let mut p = 2 + 32;
    p += 1 + b[p] as usize;
    let cl = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    p += 2;
    let ciphers = u16s(&b[p..p + cl]);
    p += cl;
    p += 1 + b[p] as usize;
    let el = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    p += 2;
    let end = p + el;
    let mut exts = Vec::new();
    while p < end {
        let t = u16::from_be_bytes([b[p], b[p + 1]]);
        let l = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        exts.push((t, b[p + 4..p + 4 + l].to_vec()));
        p += 4 + l;
    }
    Hello { ciphers, exts }
}

impl Hello {
    fn ext(&self, t: u16) -> Option<&[u8]> {
        self.exts
            .iter()
            .find(|(x, _)| *x == t && !is_grease(*x))
            .map(|(_, d)| d.as_slice())
    }

    fn ext_order(&self) -> Vec<String> {
        self.exts.iter().map(|(t, _)| grease_or_hex(*t)).collect()
    }

    fn sigalgs(&self) -> Vec<u16> {
        u16s(&self.ext(13).expect("signature_algorithms")[2..])
    }

    /// JA4 (FoxIO): GREASE is ignored in every list, including the signature algorithms.
    fn ja4(&self) -> String {
        let versions: Vec<u16> = u16s(&self.ext(43).unwrap()[1..])
            .into_iter()
            .filter(|v| !is_grease(*v))
            .collect();
        let tv = match versions.iter().max() {
            Some(0x0304) => "13",
            Some(0x0303) => "12",
            _ => "00",
        };
        let alpn = protos(&self.ext(16).unwrap()[2..]);
        let first = alpn.first().cloned().unwrap_or_default();
        let ac = match (first.chars().next(), first.chars().last()) {
            (Some(a), Some(b)) => format!("{a}{b}"),
            _ => "00".into(),
        };
        let mut cs: Vec<String> = self
            .ciphers
            .iter()
            .filter(|c| !is_grease(**c))
            .map(|c| hex(*c))
            .collect();
        cs.sort();
        let mut es: Vec<String> = self
            .exts
            .iter()
            .filter(|(t, _)| !is_grease(*t) && *t != 0 && *t != 16)
            .map(|(t, _)| hex(*t))
            .collect();
        es.sort();
        let ne = self.exts.iter().filter(|(t, _)| !is_grease(*t)).count();
        let sni = if self.ext(0).is_some() { 'd' } else { 'i' };
        let sa: Vec<String> = self
            .sigalgs()
            .into_iter()
            .filter(|s| !is_grease(*s))
            .map(hex)
            .collect();
        let h = |s: String| {
            let d = Sha256::digest(s.as_bytes());
            d[..6]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        format!(
            "t{tv}{sni}{:02}{:02}{ac}_{}_{}",
            cs.len(),
            ne,
            h(cs.join(",")),
            h(format!("{}_{}", es.join(","), sa.join(",")))
        )
    }

    /// The comparable, version-stable view of a ClientHello (the same keys as the fixtures).
    fn canon(&self) -> Value {
        let groups = u16s(&self.ext(10).unwrap()[2..]);
        let ks = {
            let d = &self.ext(51).unwrap()[2..];
            let mut i = 0;
            let mut out = Vec::new();
            while i < d.len() {
                let g = u16::from_be_bytes([d[i], d[i + 1]]);
                let l = u16::from_be_bytes([d[i + 2], d[i + 3]]) as usize;
                out.push(format!("{}:{l}", grease_or_hex(g)));
                i += 4 + l;
            }
            out
        };
        let sigalgs = self.sigalgs();
        let mut ext_set: Vec<String> = self
            .exts
            .iter()
            .filter(|(t, _)| !is_grease(*t))
            .map(|(t, _)| hex(*t))
            .collect();
        ext_set.sort();
        let trust = self
            .ext(0xca34)
            .map(|d| d.iter().map(|b| format!("{b:02x}")).collect::<String>());
        let padding = self
            .ext(0x12e0)
            .map(|d| d.iter().map(|b| format!("{b:02x}")).collect::<String>());
        let ech = self.ext(0xfe0d).map(|d| d.to_vec());
        let order = self.ext_order();
        json!({
            "ja4": self.ja4(),
            "cipher_suites": self.ciphers.iter().map(|c| grease_or_hex(*c)).collect::<Vec<_>>(),
            "groups": groups.iter().map(|g| grease_or_hex(*g)).collect::<Vec<_>>(),
            "key_shares": ks,
            "sigalgs": sigalgs.iter().filter(|s| !is_grease(**s)).map(|s| hex(*s)).collect::<Vec<_>>(),
            "sigalg_grease_first": sigalgs.first().is_some_and(|s| is_grease(*s)),
            "sigalg_grease_count": sigalgs.iter().filter(|s| is_grease(**s)).count(),
            "alpn": protos(&self.ext(16).unwrap()[2..]),
            "alps_17613": self.ext(17613).map(|d| protos(&d[2..])),
            "alps_17513": self.ext(17513).map(|d| protos(&d[2..])),
            "cert_compression": self.ext(27).map(|d| u16s(&d[1..]).iter().map(|v| hex(*v)).collect::<Vec<_>>()),
            "psk_modes": self.ext(45).map(|d| d[1..].to_vec()),
            "supported_versions": u16s(&self.ext(43).unwrap()[1..]).iter().map(|v| grease_or_hex(*v)).collect::<Vec<_>>(),
            "ec_point_formats": self.ext(11).map(|d| d[1..].to_vec()),
            "status_request": self.ext(5).map(|d| d.iter().map(|b| format!("{b:02x}")).collect::<String>()),
            "ext_set": ext_set,
            "ext_grease_first_last": order.first().map(String::as_str) == Some("GREASE")
                && order.last().map(String::as_str) == Some("GREASE"),
            "trust_anchors": trust,
            "server_padding": padding,
            "ech_header": ech.as_ref().map(|d| d[..5].iter().map(|b| format!("{b:02x}")).collect::<String>()),
            "ech_enc_len": ech.as_ref().map(|d| u16::from_be_bytes([d[6], d[7]])),
        })
    }
}

fn protos(d: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < d.len() {
        let n = d[i] as usize;
        out.push(String::from_utf8_lossy(&d[i + 1..i + 1 + n]).into_owned());
        i += 1 + n;
    }
    out
}

// ---- capture -------------------------------------------------------------------------------

/// Records the first TLS record of every connection, then drops it. Returns the port.
async fn capture_server() -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let s2 = s2.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 5];
                if s.read_exact(&mut head).await.is_err() {
                    return;
                }
                let n = u16::from_be_bytes([head[3], head[4]]) as usize;
                let mut body = vec![0u8; n];
                if s.read_exact(&mut body).await.is_err() {
                    return;
                }
                let mut rec = head.to_vec();
                rec.extend(body);
                s2.lock().unwrap().push(rec);
            });
        }
    });
    (port, seen)
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.append(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    h
}

/// The ClientHellos Argus sends (`n` fresh connections) for a browser whose client hints say
/// "Google Chrome" `major`.
async fn argus_hellos(major: u32, n: usize) -> Vec<Hello> {
    let bp = BrowserProfile::classify(&headers(&[(
        "sec-ch-ua",
        &format!(r#""Chromium";v="{major}", "Google Chrome";v="{major}", "Not.A/Brand";v="8""#),
    )]));
    let (port, seen) = capture_server().await;
    for _ in 0..n {
        // A fresh client per connection: no pooled connection and no cached TLS session.
        let client = wreq::Client::builder()
            .emulation(bp.emulation())
            .timeout(std::time::Duration::from_secs(5))
            .no_proxy()
            .build()
            .unwrap();
        let _ = client
            .get(format!("https://localhost:{port}/"))
            .send()
            .await;
    }
    let recs = seen.lock().unwrap().clone();
    assert_eq!(recs.len(), n, "one ClientHello per connection");
    recs.iter().map(|r| parse_hello(r)).collect()
}

fn fixture(major: u32) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("tests/fixtures/chrome-tls/chrome-{major}.json"));
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p:?}: {e}")))
        .unwrap()
}

/// Fields compared exactly. `ech_payload_lens` and the extension order are checked separately.
const FIELDS: &[&str] = &[
    "ja4",
    "cipher_suites",
    "groups",
    "key_shares",
    "sigalgs",
    "sigalg_grease_first",
    "sigalg_grease_count",
    "alpn",
    "alps_17613",
    "alps_17513",
    "cert_compression",
    "psk_modes",
    "supported_versions",
    "ec_point_formats",
    "status_request",
    "ext_set",
    "ext_grease_first_last",
    "trust_anchors",
    "server_padding",
    "ech_header",
    "ech_enc_len",
];

async fn assert_matches_fixture(major: u32) {
    let fx = fixture(major);
    let hellos = argus_hellos(major, 8).await;
    for h in &hellos {
        let got = h.canon();
        for k in FIELDS {
            assert_eq!(got[*k], fx[*k], "Chrome {major}: field {k}");
        }
        let ech_len = h.ext(0xfe0d).unwrap().len();
        assert!(
            fx["ech_payload_lens"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_u64() == Some(ech_len as u64)),
            "Chrome {major}: ECH extension length {ech_len} not among {:?}",
            fx["ech_payload_lens"]
        );
    }
    // Chrome randomises the order of its extensions on every connection (GREASE stays first and
    // last); eight identical orders would be a 1-in-10^13 accident.
    let orders: std::collections::HashSet<_> = hellos.iter().map(|h| h.ext_order()).collect();
    assert!(
        orders.len() > 1,
        "Chrome {major}: extension order is not randomised"
    );
    // GREASE values differ between connections.
    let greases: std::collections::HashSet<_> = hellos.iter().map(|h| h.ciphers[0]).collect();
    assert!(
        greases.len() > 1 || hellos.len() < 3,
        "Chrome {major}: GREASE cipher is constant"
    );
}

#[tokio::test]
async fn chrome_141_matches_captured_fixture() {
    assert_matches_fixture(141).await;
}

#[tokio::test]
async fn chrome_151_matches_captured_fixture() {
    assert_matches_fixture(151).await;
}

#[tokio::test]
async fn chrome_153_matches_captured_fixture() {
    assert_matches_fixture(153).await;
}

#[tokio::test]
async fn chrome_156_matches_captured_fixture() {
    assert_matches_fixture(156).await;
}

/// 159 is newer than the newest profile (156): it sends 156's handshake, as Chrome 159 does.
#[tokio::test]
async fn chrome_159_uses_the_newest_profile_and_matches_its_fixture() {
    assert_matches_fixture(159).await;
}

/// Pins the signature algorithm code points a profile must offer (not only through fixtures).
#[tokio::test]
async fn new_profiles_offer_ml_dsa_and_older_ones_do_not() {
    let h151 = &argus_hellos(151, 1).await[0];
    assert_eq!(
        &h151.sigalgs()[..4],
        &[0x0904, 0x0905, 0x0906, 0x0403],
        "ML-DSA 44/65/87 first, then ecdsa_secp256r1_sha256"
    );
    assert!(
        !h151.sigalgs().iter().any(|s| is_grease(*s)),
        "no GREASE signature algorithm in 151"
    );
    assert!(h151.ext(0xca34).is_none(), "no trust_anchors in 151");
    let h149 = &argus_hellos(149, 1).await[0];
    assert_eq!(
        h149.sigalgs()[0],
        0x0403,
        "Chrome 149 does not offer ML-DSA"
    );
    let h153 = &argus_hellos(153, 1).await[0];
    assert!(
        is_grease(h153.sigalgs()[0]),
        "Chrome 153 sends a GREASE signature algorithm first"
    );
    assert_eq!(h153.ext(0xca34).unwrap().len(), 2 + 184);
    assert!(
        h153.ext(0x12e0).is_none(),
        "server_padding is an experiment, not a default"
    );
}

// ---- version -> profile --------------------------------------------------------------------

#[test]
fn chrome_versions_map_to_the_nearest_profile_at_or_below() {
    use wreq_util::Profile as P;
    let at = |v: u32| {
        BrowserProfile::classify(&headers(&[(
            "sec-ch-ua",
            &format!(r#""Google Chrome";v="{v}", "Chromium";v="{v}""#),
        )]))
        .profile
    };
    assert_eq!(at(149), P::Chrome149);
    assert_eq!(at(150), P::Chrome149, "between profiles: round down");
    assert_eq!(at(151), P::Chrome151);
    assert_eq!(at(152), P::Chrome151);
    assert_eq!(at(153), P::Chrome153);
    assert_eq!(at(155), P::Chrome153);
    assert_eq!(at(156), P::Chrome156);
    assert_eq!(
        at(158),
        P::Chrome156,
        "the owner's 158 gets the newest profile at or below"
    );
    assert_eq!(at(159), P::Chrome156);
    assert_eq!(
        at(400),
        P::Chrome156,
        "newer than every profile: the newest"
    );
}

// ---- live comparison with a real Chrome (never in CI) --------------------------------------

/// `ARGUS_LIVE_CHROME=/path/to/chrome cargo test -p proxy-core --test chrome_tls_tests -- --ignored
/// live_chrome`: launches that browser (own throwaway profile, headless) against a local capture
/// server, builds Argus's handshake for the same version and compares every field. Set
/// `ARGUS_LIVE_CHROME_FLAGS` for extra browser flags (space separated).
#[tokio::test]
#[ignore = "needs a local Chrome binary: set ARGUS_LIVE_CHROME"]
async fn live_chrome_handshake_equals_argus_handshake() {
    let bin = std::env::var("ARGUS_LIVE_CHROME").expect("ARGUS_LIVE_CHROME=/path/to/chrome");
    let ver = std::process::Command::new(&bin)
        .arg("--version")
        .output()
        .unwrap();
    let ver = String::from_utf8_lossy(&ver.stdout);
    let major: u32 = ver
        .split_whitespace()
        .find_map(|w| {
            w.split('.')
                .next()
                .and_then(|m| m.parse().ok())
                .filter(|m: &u32| *m > 50)
        })
        .unwrap_or_else(|| panic!("cannot read a version from {ver:?}"));

    let (port, seen) = capture_server().await;
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = std::process::Command::new(&bin);
    cmd.args([
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--no-first-run",
        "--disable-field-trial-config",
        "--ignore-certificate-errors",
    ])
    .arg(format!("--user-data-dir={}", dir.path().display()))
    .args(
        std::env::var("ARGUS_LIVE_CHROME_FLAGS")
            .unwrap_or_default()
            .split_whitespace(),
    )
    .arg("--dump-dom")
    .arg(format!("https://localhost:{port}/"))
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null());
    let mut child = cmd.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while seen.lock().unwrap().is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    let chrome = parse_hello(&seen.lock().unwrap()[0]).canon();
    let argus = argus_hellos(major, 1).await[0].canon();
    let mut bad = Vec::new();
    for k in FIELDS {
        if chrome[*k] != argus[*k] {
            bad.push(format!(
                "{k}:\n  chrome {}\n  argus  {}",
                chrome[*k], argus[*k]
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "Chrome {major} differs from Argus:\n{}",
        bad.join("\n")
    );
}

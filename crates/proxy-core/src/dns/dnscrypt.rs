//! DNSCrypt v2 client (https://dnscrypt.info/protocol).
//!
//! The provider's certificate is fetched as a TXT record, its Ed25519 signature is checked
//! against the public key from the `sdns://` stamp, and queries are sent as
//! `client-magic | client-pk | client-nonce | box(padded query)` over UDP, falling back to TCP
//! for truncated answers. Both authenticated-encryption suites are supported:
//! X25519-XSalsa20Poly1305 (es-version 1) and X25519-XChaCha20Poly1305 (es-version 2).

use dns_syntax::DnsCryptInfo;
use crypto_box::aead::{generic_array::GenericArray, Aead};
use crypto_box::{ChaChaBox, PublicKey, SalsaBox, SecretKey};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hickory_resolver::net::NetError;
use hickory_resolver::proto::op::{Message, Query};
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use rand::RngCore;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CERT_LEN: usize = 124;
const CERT_MAGIC: &[u8; 4] = b"DNSC";
const RESOLVER_MAGIC: &[u8; 8] = b"r6fnvWj8";
const MIN_PADDED: usize = 256;

enum Suite {
    Salsa(SalsaBox),
    ChaCha(ChaChaBox),
}

struct Cert {
    suite: Suite,
    client_magic: [u8; 8],
    client_pk: [u8; 32],
    serial: u32,
    not_after: u32,
}

pub struct DnsCrypt {
    addr: SocketAddr,
    info: DnsCryptInfo,
    timeout: Duration,
    cert: tokio::sync::Mutex<Option<std::sync::Arc<Cert>>>,
}

fn err(s: impl Into<String>) -> String {
    s.into()
}

impl From<DnsCryptError> for NetError {
    fn from(e: DnsCryptError) -> Self {
        NetError::from(e.0)
    }
}

/// A DNSCrypt failure, as text.
#[derive(Debug)]
pub struct DnsCryptError(pub String);

fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Parse and verify one certificate; `None` if it is not usable.
fn parse_cert(raw: &[u8], pk: &VerifyingKey) -> Option<Cert> {
    if raw.len() != CERT_LEN || &raw[..4] != CERT_MAGIC {
        return None;
    }
    let es = u16::from_be_bytes([raw[4], raw[5]]);
    let sig = Signature::from_slice(&raw[8..72]).ok()?;
    pk.verify(&raw[72..], &sig).ok()?;
    let resolver_pk: [u8; 32] = raw[72..104].try_into().ok()?;
    let client_magic: [u8; 8] = raw[104..112].try_into().ok()?;
    let serial = u32::from_be_bytes(raw[112..116].try_into().ok()?);
    let not_before = u32::from_be_bytes(raw[116..120].try_into().ok()?);
    let not_after = u32::from_be_bytes(raw[120..124].try_into().ok()?);
    let t = now();
    if t < not_before || t > not_after {
        return None;
    }
    let mut sk_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sk_bytes);
    let sk = SecretKey::from(sk_bytes);
    let client_pk = *sk.public_key().as_bytes();
    let rpk = PublicKey::from(resolver_pk);
    let suite = match es {
        1 => Suite::Salsa(SalsaBox::new(&rpk, &sk)),
        2 => Suite::ChaCha(ChaChaBox::new(&rpk, &sk)),
        _ => return None,
    };
    Some(Cert {
        suite,
        client_magic,
        client_pk,
        serial,
        not_after,
    })
}

impl Cert {
    fn seal(&self, nonce: &[u8; 24], plain: &[u8]) -> Result<Vec<u8>, String> {
        let n = GenericArray::from_slice(nonce);
        match &self.suite {
            Suite::Salsa(b) => b.encrypt(n, plain).map_err(|_| err("encryption failed")),
            Suite::ChaCha(b) => {
                // crypto_box returns ciphertext || tag; DNSCrypt puts the tag first.
                let mut v = b.encrypt(n, plain).map_err(|_| err("encryption failed"))?;
                let tag = v.split_off(v.len() - 16);
                let mut out = tag;
                out.extend_from_slice(&v);
                Ok(out)
            }
        }
    }

    fn open(&self, nonce: &[u8; 24], boxed: &[u8]) -> Result<Vec<u8>, String> {
        let n = GenericArray::from_slice(nonce);
        match &self.suite {
            Suite::Salsa(b) => b.decrypt(n, boxed).map_err(|_| err("authentication failed")),
            Suite::ChaCha(b) => {
                if boxed.len() < 16 {
                    return Err(err("short response"));
                }
                let (tag, ct) = boxed.split_at(16);
                let mut v = ct.to_vec();
                v.extend_from_slice(tag);
                b.decrypt(n, v.as_slice())
                    .map_err(|_| err("authentication failed"))
            }
        }
    }
}

/// ISO/IEC 7816-4 padding to a multiple of 64 bytes, at least 256.
fn pad(q: &[u8]) -> Vec<u8> {
    let mut v = q.to_vec();
    v.push(0x80);
    let target = v.len().div_ceil(64).max(1) * 64;
    v.resize(target.max(MIN_PADDED), 0);
    v
}

fn unpad(mut v: Vec<u8>) -> Result<Vec<u8>, String> {
    while v.last() == Some(&0) {
        v.pop();
    }
    if v.pop() != Some(0x80) {
        return Err(err("bad padding"));
    }
    Ok(v)
}

impl DnsCrypt {
    pub fn new(addr: SocketAddr, info: DnsCryptInfo, timeout: Duration) -> Self {
        Self {
            addr,
            info,
            timeout,
            cert: tokio::sync::Mutex::new(None),
        }
    }

    async fn udp(&self, packet: &[u8]) -> Result<Vec<u8>, String> {
        let bind = if self.addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let s = tokio::net::UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
        s.connect(self.addr).await.map_err(|e| e.to_string())?;
        s.send(packet).await.map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(self.timeout, s.recv(&mut buf))
            .await
            .map_err(|_| err("timed out"))?
            .map_err(|e| e.to_string())?;
        buf.truncate(n);
        Ok(buf)
    }

    async fn tcp(&self, packet: &[u8]) -> Result<Vec<u8>, String> {
        let io = async {
            let mut s = tokio::net::TcpStream::connect(self.addr).await?;
            let mut out = (packet.len() as u16).to_be_bytes().to_vec();
            out.extend_from_slice(packet);
            s.write_all(&out).await?;
            let mut l = [0u8; 2];
            s.read_exact(&mut l).await?;
            let mut buf = vec![0u8; u16::from_be_bytes(l) as usize];
            s.read_exact(&mut buf).await?;
            Ok::<_, std::io::Error>(buf)
        };
        tokio::time::timeout(self.timeout, io)
            .await
            .map_err(|_| err("timed out"))?
            .map_err(|e| e.to_string())
    }

    /// Fetch and verify the provider certificate (the valid one with the highest serial).
    async fn fetch_cert(&self) -> Result<Cert, String> {
        let pk = VerifyingKey::from_bytes(&self.info.provider_pk)
            .map_err(|_| err("invalid provider public key"))?;
        let name = Name::from_ascii(&self.info.provider_name).map_err(|e| e.to_string())?;
        let mut m = Message::query();
        m.add_query(Query::query(name, RecordType::TXT));
        m.metadata.id = rand::random();
        let bytes = m.to_vec().map_err(|e| e.to_string())?;
        let mut resp = self.udp(&bytes).await.and_then(|b| {
            Message::from_vec(&b).map_err(|e| e.to_string())
        })?;
        if resp.metadata.truncation {
            let b = self.tcp(&bytes).await?;
            resp = Message::from_vec(&b).map_err(|e| e.to_string())?;
        }
        let mut best: Option<Cert> = None;
        for r in &resp.answers {
            if let RData::TXT(t) = &r.data {
                let raw: Vec<u8> = t.txt_data.iter().flat_map(|s| s.iter().copied()).collect();
                if let Some(c) = parse_cert(&raw, &pk) {
                    if best.as_ref().is_none_or(|b| c.serial > b.serial) {
                        best = Some(c);
                    }
                }
            }
        }
        best.ok_or_else(|| err("no valid DNSCrypt certificate from the provider"))
    }

    async fn cert(&self, force: bool) -> Result<std::sync::Arc<Cert>, String> {
        let mut g = self.cert.lock().await;
        if !force {
            if let Some(c) = g.as_ref() {
                // Renew a minute before it expires.
                if c.not_after > now().saturating_add(60) {
                    return Ok(c.clone());
                }
            }
        }
        let c = std::sync::Arc::new(self.fetch_cert().await?);
        *g = Some(c.clone());
        Ok(c)
    }

    /// Exchange one DNS message.
    pub async fn exchange(&self, msg: Message) -> Result<hickory_resolver::proto::op::DnsResponse, DnsCryptError> {
        self.exchange_inner(msg).await.map_err(DnsCryptError)
    }

    async fn exchange_inner(
        &self,
        msg: Message,
    ) -> Result<hickory_resolver::proto::op::DnsResponse, String> {
        let id = msg.metadata.id;
        let query = msg.to_vec().map_err(|e| e.to_string())?;
        let mut force = false;
        let mut last = err("no response");
        for _ in 0..2 {
            let cert = self.cert(force).await?;
            let mut client_nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut client_nonce);
            let mut nonce = [0u8; 24];
            nonce[..12].copy_from_slice(&client_nonce);
            let boxed = cert.seal(&nonce, &pad(&query))?;
            let mut packet = Vec::with_capacity(8 + 32 + 12 + boxed.len());
            packet.extend_from_slice(&cert.client_magic);
            packet.extend_from_slice(&cert.client_pk);
            packet.extend_from_slice(&client_nonce);
            packet.extend_from_slice(&boxed);

            let mut raw = match self.udp(&packet).await {
                Ok(r) => r,
                Err(e) => {
                    last = e;
                    force = true;
                    continue;
                }
            };
            let mut plain = self.decode(&cert, &client_nonce, &raw);
            // Truncated: ask again over TCP.
            if let Ok(p) = &plain {
                if p.len() > 2 && p[2] & 0x02 != 0 {
                    raw = self.tcp(&packet).await?;
                    plain = self.decode(&cert, &client_nonce, &raw);
                }
            }
            match plain {
                Ok(p) => {
                    let resp = hickory_resolver::proto::op::DnsResponse::from_buffer(p)
                        .map_err(|e| e.to_string())?;
                    if resp.metadata.id != id {
                        return Err(err("response id mismatch"));
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    // A rotated certificate shows up as undecryptable answers: refetch once.
                    last = e;
                    force = true;
                }
            }
        }
        Err(last)
    }

    fn decode(&self, cert: &Cert, client_nonce: &[u8; 12], raw: &[u8]) -> Result<Vec<u8>, String> {
        if raw.len() < 8 + 24 + 16 || &raw[..8] != RESOLVER_MAGIC {
            return Err(err("not a DNSCrypt response"));
        }
        let nonce: [u8; 24] = raw[8..32].try_into().map_err(|_| err("bad nonce"))?;
        if &nonce[..12] != client_nonce {
            return Err(err("response nonce mismatch"));
        }
        unpad(cert.open(&nonce, &raw[32..])?)
    }
}

#[cfg(test)]
pub(crate) mod testserver {
    //! A DNSCrypt server for tests: signs a certificate, answers every A query with `ip`.

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use hickory_resolver::proto::rr::rdata::{A, TXT};
    use hickory_resolver::proto::rr::{RData, Record};
    use std::net::Ipv4Addr;

    pub struct Server {
        pub addr: SocketAddr,
        pub provider_pk: [u8; 32],
        pub provider_name: String,
    }

    pub async fn start(es: u16, answer: Ipv4Addr) -> Server {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let signer = SigningKey::from_bytes(&seed);
        let mut rsk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut rsk);
        let rsk = SecretKey::from(rsk);
        let rpk = *rsk.public_key().as_bytes();
        let magic = [9u8, 8, 7, 6, 5, 4, 3, 2];
        let mut body = Vec::new();
        body.extend_from_slice(&rpk);
        body.extend_from_slice(&magic);
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&(now() - 100).to_be_bytes());
        body.extend_from_slice(&(now() + 3600).to_be_bytes());
        let sig = signer.sign(&body);
        let mut cert = CERT_MAGIC.to_vec();
        cert.extend_from_slice(&es.to_be_bytes());
        cert.extend_from_slice(&[0, 0]);
        cert.extend_from_slice(&sig.to_bytes());
        cert.extend_from_slice(&body);
        assert_eq!(cert.len(), CERT_LEN);

        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let provider_name = "2.dnscrypt-cert.test.example".to_string();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let pkt = &buf[..n];
                if pkt.len() > 8 + 32 + 12 && pkt[..8] == magic {
                    let cpk = PublicKey::from(<[u8; 32]>::try_from(&pkt[8..40]).unwrap());
                    let cn = &pkt[40..52];
                    let mut nonce = [0u8; 24];
                    nonce[..12].copy_from_slice(cn);
                    let suite = if es == 1 {
                        Suite::Salsa(SalsaBox::new(&cpk, &rsk))
                    } else {
                        Suite::ChaCha(ChaChaBox::new(&cpk, &rsk))
                    };
                    let c = Cert {
                        suite,
                        client_magic: magic,
                        client_pk: [0; 32],
                        serial: 1,
                        not_after: 0,
                    };
                    let Ok(q) = c.open(&nonce, &pkt[52..]).and_then(unpad) else {
                        continue;
                    };
                    let q = Message::from_vec(&q).unwrap();
                    let mut r = Message::response(q.metadata.id, q.metadata.op_code);
                    r.queries = q.queries.clone();
                    r.add_answer(Record::from_rdata(
                        q.queries[0].name().clone(),
                        60,
                        RData::A(A(answer)),
                    ));
                    let mut rn = [0u8; 24];
                    rn[..12].copy_from_slice(cn);
                    rand::thread_rng().fill_bytes(&mut rn[12..]);
                    let mut out = RESOLVER_MAGIC.to_vec();
                    out.extend_from_slice(&rn);
                    out.extend(c.seal(&rn, &pad(&r.to_vec().unwrap())).unwrap());
                    let _ = sock.send_to(&out, peer).await;
                } else if let Ok(q) = Message::from_vec(pkt) {
                    let mut r = Message::response(q.metadata.id, q.metadata.op_code);
                    r.queries = q.queries.clone();
                    r.add_answer(Record::from_rdata(
                        q.queries[0].name().clone(),
                        60,
                        RData::TXT(TXT::from_bytes(vec![&cert[..]])),
                    ));
                    let _ = sock.send_to(&r.to_vec().unwrap(), peer).await;
                }
            }
        });
        Server {
            addr,
            provider_pk: signer.verifying_key().to_bytes(),
            provider_name,
        }
    }
}

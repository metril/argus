//! Routes control-plane fetches (lists, roots, extension downloads, userscript imports) through
//! the upstream proxy while it is on.
//!
//! The fetch clients are `reqwest` clients, which hand the proxy a host name. Argus must never do
//! that: it resolves the name itself, vets the address against the control-plane policy and sends
//! the proxy only that address. So while the upstream proxy is on, each client's requests go to a
//! small loopback bridge instead (a per-client random credential selects that client's policy).
//! The bridge resolves and vets, then dials the address through the proxy and relays bytes. TLS
//! (verification, pinning) still runs end to end inside the tunnel, in the client. While the
//! proxy is off the clients connect directly with their guarded resolver, as before. The switch
//! is read on every request, so a settings change applies to the next fetch.

use crate::net_policy::{NetPolicy, ResolveError};
use base64::Engine;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub type DialFuture<'a> = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'a>>;

/// Connects to an address Argus already vetted, through the upstream proxy.
pub trait UpstreamDialer: Send + Sync {
    /// Whether the upstream proxy is on right now.
    fn active(&self) -> bool;
    fn dial(&self, addr: SocketAddr) -> DialFuture<'_>;
}

static DIALER: RwLock<Option<Arc<dyn UpstreamDialer>>> = RwLock::new(None);

/// Install the live upstream proxy (the last one installed wins).
pub fn set_upstream_dialer(d: Arc<dyn UpstreamDialer>) {
    *DIALER.write() = Some(d);
}

fn active_dialer() -> Option<Arc<dyn UpstreamDialer>> {
    DIALER.read().clone().filter(|d| d.active())
}

struct Bridge {
    addr: SocketAddr,
    routes: Mutex<HashMap<String, Arc<NetPolicy>>>,
}

static BRIDGE: OnceLock<Option<Arc<Bridge>>> = OnceLock::new();

fn bridge() -> Option<Arc<Bridge>> {
    BRIDGE.get_or_init(start).clone()
}

fn start() -> Option<Arc<Bridge>> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).ok()?;
    listener.set_nonblocking(true).ok()?;
    let b = Arc::new(Bridge {
        addr: listener.local_addr().ok()?,
        routes: Mutex::default(),
    });
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .thread_name("control-bridge")
        .build()
        .ok()?;
    let served = b.clone();
    std::thread::Builder::new()
        .name("control-bridge".into())
        .spawn(move || {
            rt.block_on(async move {
                let Ok(l) = TcpListener::from_std(listener) else {
                    return;
                };
                loop {
                    let Ok((s, _)) = l.accept().await else {
                        continue;
                    };
                    let b = served.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve(&b, s).await {
                            tracing::debug!("control-plane bridge: {e}");
                        }
                    });
                }
            })
        })
        .ok()?;
    Some(b)
}

/// One client's route: its credential and policy, registered with the bridge on first use and
/// removed when the client is dropped.
struct Route {
    token: String,
    policy: Arc<NetPolicy>,
    registered: OnceLock<()>,
}

impl Route {
    fn url(&self) -> String {
        let Some(b) = bridge() else {
            // Never fall back to a direct connection: nothing listens here.
            return "http://127.0.0.1:1".into();
        };
        self.registered.get_or_init(|| {
            b.routes
                .lock()
                .insert(self.token.clone(), self.policy.clone());
        });
        format!("http://argus:{}@{}", self.token, b.addr)
    }
}

impl Drop for Route {
    fn drop(&mut self) {
        if self.registered.get().is_some() {
            if let Some(Some(b)) = BRIDGE.get() {
                b.routes.lock().remove(&self.token);
            }
        }
    }
}

/// The `reqwest` proxy rule for a control-plane client: the bridge while the upstream proxy is
/// on, none (a direct, guarded connection) while it is off.
pub fn proxy_rule(policy: Arc<NetPolicy>) -> reqwest::Proxy {
    use rand::RngCore;
    let mut raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut raw);
    let route = Route {
        token: raw.iter().map(|b| format!("{b:02x}")).collect(),
        policy,
        registered: OnceLock::new(),
    };
    reqwest::Proxy::custom(move |_| active_dialer().map(|_| route.url()))
}

const MAX_HEAD: usize = 16 * 1024;
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);

async fn serve(b: &Bridge, mut s: TcpStream) -> io::Result<()> {
    let (head, rest) = read_head(&mut s).await?;
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let request = lines.next().unwrap_or_default().to_string();
    let mut token = None;
    let mut kept = String::new();
    for l in lines.filter(|l| !l.is_empty()) {
        let lower = l.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("proxy-authorization:") {
            let enc = l[l.len() - v.len()..].trim();
            token = enc
                .strip_prefix("Basic ")
                .or_else(|| enc.strip_prefix("basic "))
                .and_then(|e| {
                    base64::engine::general_purpose::STANDARD
                        .decode(e.trim())
                        .ok()
                })
                .and_then(|d| String::from_utf8(d).ok())
                .and_then(|d| d.split_once(':').map(|(_, t)| t.to_string()));
        } else if !lower.starts_with("proxy-connection:") {
            kept.push_str(l);
            kept.push_str("\r\n");
        }
    }
    let policy = token.and_then(|t| b.routes.lock().get(&t).cloned());
    let Some(policy) = policy else {
        return reply(&mut s, "407 Proxy Authentication Required").await;
    };
    let mut parts = request.split(' ');
    let (method, target, version) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or("HTTP/1.1"),
    );
    // CONNECT host:port, or an absolute-form request for plain http.
    let connect = method.eq_ignore_ascii_case("CONNECT");
    let (host, port, origin_form) = if connect {
        match target.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(p) => (h.to_string(), p, String::new()),
                Err(_) => return reply(&mut s, "400 Bad Request").await,
            },
            None => return reply(&mut s, "400 Bad Request").await,
        }
    } else {
        match url::Url::parse(target) {
            Ok(u) if u.scheme() == "http" && u.host_str().is_some() => {
                let mut o = u.path().to_string();
                if let Some(q) = u.query() {
                    o.push('?');
                    o.push_str(q);
                }
                (
                    u.host_str().unwrap_or_default().to_string(),
                    u.port_or_known_default().unwrap_or(80),
                    o,
                )
            }
            _ => return reply(&mut s, "400 Bad Request").await,
        }
    };
    let addr = match policy.resolve_control(&host, port).await {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!("control-plane fetch to {host}:{port} refused: {e}");
            let status = match e {
                ResolveError::Refused(_) => "403 Forbidden",
                _ => "502 Bad Gateway",
            };
            return reply(&mut s, status).await;
        }
    };
    let Some(d) = active_dialer() else {
        return reply(&mut s, "503 Service Unavailable").await;
    };
    let mut up = match tokio::time::timeout(DIAL_TIMEOUT, d.dial(addr)).await {
        Ok(Ok(u)) => u,
        Ok(Err(e)) => {
            tracing::warn!("control-plane fetch to {host}:{port} via upstream proxy failed: {e}");
            return reply(&mut s, "502 Bad Gateway").await;
        }
        Err(_) => return reply(&mut s, "504 Gateway Timeout").await,
    };
    if connect {
        s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else {
        up.write_all(format!("{method} {origin_form} {version}\r\n{kept}\r\n").as_bytes())
            .await?;
    }
    if !rest.is_empty() {
        up.write_all(&rest).await?;
    }
    tokio::io::copy_bidirectional(&mut s, &mut up).await?;
    Ok(())
}

async fn reply(s: &mut TcpStream, status: &str) -> io::Result<()> {
    s.write_all(
        format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
}

/// The request head and any bytes read past it.
async fn read_head(s: &mut TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(i + 4);
            buf.truncate(i);
            return Ok((buf, rest));
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::other("request head too large"));
        }
        let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut chunk))
            .await
            .map_err(|_| io::Error::other("request head timed out"))??;
        if n == 0 {
            return Err(io::Error::other("closed before a full request"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_policy::{AddrFuture, NameResolver};
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Answer(&'static str);
    impl NameResolver for Answer {
        fn lookup(&self, _: &str) -> AddrFuture {
            let ip: IpAddr = self.0.parse().unwrap();
            Box::pin(async move { Ok(vec![ip]) })
        }
    }

    /// Dials a local server whatever address it is given, and records the address.
    struct Local {
        on: AtomicBool,
        target: SocketAddr,
        seen: Mutex<Vec<SocketAddr>>,
    }
    impl UpstreamDialer for Local {
        fn active(&self) -> bool {
            self.on.load(Ordering::SeqCst)
        }
        fn dial(&self, addr: SocketAddr) -> DialFuture<'_> {
            self.seen.lock().push(addr);
            Box::pin(TcpStream::connect(self.target))
        }
    }

    async fn origin() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    // Echo the request line so the test sees the rewritten target.
                    let line = req.lines().next().unwrap_or_default().to_string();
                    let _ = s
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{line}",
                                line.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                });
            }
        });
        a
    }

    #[tokio::test]
    async fn fetches_use_the_proxy_with_the_vetted_address_only_while_it_is_on() {
        let target = origin().await;
        let dial = Arc::new(Local {
            on: AtomicBool::new(true),
            target,
            seen: Mutex::default(),
        });
        set_upstream_dialer(dial.clone());
        let policy = Arc::new(
            NetPolicy::control_plane(&[])
                .unwrap()
                .with_resolver(Arc::new(Answer("93.184.216.34"))),
        );
        let client = crate::net_policy::control_plane_client(policy)
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let body = client
            .get("http://lists.example/a/b.txt?x=1")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "GET /a/b.txt?x=1 HTTP/1.1");
        // CONNECT (https): the tunnel is dialled even though the origin does not speak TLS.
        let _ = client.get("https://lists.example/").send().await;
        let seen = dial.seen.lock().clone();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert_eq!(seen[0], "93.184.216.34:80".parse().unwrap());
        assert_eq!(seen[1], "93.184.216.34:443".parse().unwrap());

        // Off: the client no longer uses the bridge (no new dial; the guarded direct path runs).
        dial.on.store(false, Ordering::SeqCst);
        let _ = client.get("http://lists.example/").send().await;
        assert_eq!(dial.seen.lock().len(), 2);
    }

    #[tokio::test]
    async fn the_bridge_refuses_refused_destinations_and_unknown_credentials() {
        let target = origin().await;
        let dial = Arc::new(Local {
            on: AtomicBool::new(true),
            target,
            seen: Mutex::default(),
        });
        set_upstream_dialer(dial.clone());
        let policy = Arc::new(
            NetPolicy::control_plane(&[])
                .unwrap()
                .with_resolver(Arc::new(Answer("10.1.2.3"))),
        );
        let client = crate::net_policy::control_plane_client(policy)
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let r = client.get("http://nas.example/").send().await;
        assert!(
            r.map(|r| r.status() != 200).unwrap_or(true),
            "private answer must not be fetched"
        );
        assert!(dial.seen.lock().is_empty(), "nothing is dialled");

        // Someone else on the machine without the credential gets nothing.
        let b = bridge().unwrap();
        let mut s = TcpStream::connect(b.addr).await.unwrap();
        s.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 407"), "{out}");
    }
}

//! Sending Argus's own upstream traffic through another proxy (HTTP `CONNECT` or SOCKS5).
//!
//! DNS stays on Argus for both kinds: the target is resolved and vetted by the destination
//! policy first, and only that IP is sent to the proxy (a `CONNECT ip:port` line, or a SOCKS5
//! address of type 1 or 4, never a domain). TLS SNI and `Host` stay the host name. There is no
//! fallback to the proxy's DNS.
//!
//! The proxy's own address is chosen by the administrator, so private ranges are fine, but it is
//! never allowed to be one of Argus's own listeners (no chaining to itself).

use crate::dns::CachedResolver;
use crate::policy::{DestPolicy, PolicyRefused};
use crate::{Error, Result};
use arc_swap::ArcSwapOption;
use base64::Engine;
use common::config::{UpstreamProxy, UpstreamProxyKind};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Longest response head accepted from an HTTP proxy.
const MAX_HEAD: usize = 16 * 1024;

/// The live upstream proxy, shared by every dialer (probes, WebSocket, tunnels). Empty when the
/// proxy is off.
#[derive(Default)]
pub struct ProxyHandle(ArcSwapOption<ProxyEndpoint>);

impl ProxyHandle {
    pub fn load(&self) -> Option<Arc<ProxyEndpoint>> {
        self.0.load_full()
    }

    pub fn store(&self, ep: Option<Arc<ProxyEndpoint>>) {
        self.0.store(ep);
    }
}

/// Control-plane fetches (lists, roots) dial through the live proxy.
impl common::control_bridge::UpstreamDialer for ProxyHandle {
    fn active(&self) -> bool {
        self.load().is_some()
    }

    fn dial(&self, addr: SocketAddr) -> common::control_bridge::DialFuture<'_> {
        Box::pin(async move {
            match self.load() {
                Some(p) => p.connect(addr).await,
                None => Err(io::Error::other("upstream proxy is off")),
            }
        })
    }
}

impl std::fmt::Debug for ProxyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.load().is_some() {
            "ProxyHandle(on)"
        } else {
            "ProxyHandle(off)"
        })
    }
}

/// An enabled upstream proxy.
pub struct ProxyEndpoint {
    cfg: UpstreamProxy,
    /// Unguessable stand-in for the proxy's host name inside the HTTP client: the client's
    /// resolver maps exactly this name to the proxy's (re-resolved, loop-checked) addresses and
    /// never applies the private-range refusal to it. No real target can collide with it.
    alias: String,
    policy: Arc<DestPolicy>,
    dns: Arc<CachedResolver>,
}

impl std::fmt::Debug for ProxyEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProxyEndpoint({:?})", self.cfg)
    }
}

impl ProxyEndpoint {
    /// Validate `cfg` and resolve the endpoint once, so a bad host, or an address that is one of
    /// Argus's own listeners, is refused when the setting is applied. `None` when disabled.
    pub async fn prepare(
        cfg: &UpstreamProxy,
        policy: Arc<DestPolicy>,
        dns: Arc<CachedResolver>,
    ) -> Result<Option<Arc<Self>>> {
        if !cfg.enabled {
            return Ok(None);
        }
        cfg.validate().map_err(Error::Config)?;
        let ep = Self::new(cfg.clone(), policy, dns);
        ep.addrs()
            .await
            .map_err(|e| Error::Config(format!("upstream proxy {}: {e}", ep.display())))?;
        Ok(Some(Arc::new(ep)))
    }

    /// Without the resolution check of [`Self::prepare`].
    pub fn new(cfg: UpstreamProxy, policy: Arc<DestPolicy>, dns: Arc<CachedResolver>) -> Self {
        use rand::Rng;
        let alias = format!(
            "argus-proxy-{:032x}.invalid",
            rand::thread_rng().gen::<u128>()
        );
        Self {
            cfg,
            alias,
            policy,
            dns,
        }
    }

    pub fn config(&self) -> &UpstreamProxy {
        &self.cfg
    }

    /// Whether `other` is the same proxy setup (the clients built for it stay valid).
    pub fn same_as(&self, other: &UpstreamProxy) -> bool {
        &self.cfg == other
    }

    fn display(&self) -> String {
        format!("{}:{}", self.cfg.bare_host(), self.cfg.port)
    }

    /// The name the HTTP client uses for the proxy host (see the field).
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// The proxy's addresses (cached DNS), each checked against the own-listener loop rule.
    pub async fn addrs(&self) -> io::Result<Vec<SocketAddr>> {
        let host = self.cfg.bare_host();
        let port = self.cfg.port;
        let ips: Vec<IpAddr> = match host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => self
                .dns
                .resolve(host)
                .await
                .map_err(|e| io::Error::other(format!("dns lookup failed: {e}")))?
                .to_vec(),
        };
        let mut ok = Vec::with_capacity(ips.len());
        let mut denied = None;
        for ip in ips {
            match self.policy.check_proxy_endpoint(ip, port) {
                Ok(()) => ok.push(SocketAddr::new(ip, port)),
                Err(r) => {
                    denied.get_or_insert(r);
                }
            }
        }
        if ok.is_empty() {
            return Err(match denied {
                Some(r) => io::Error::other(PolicyRefused(r)),
                None => io::Error::other("no addresses"),
            });
        }
        Ok(ok)
    }

    /// The proxy as the HTTP client sees it: its alias as host (resolved by the client's
    /// resolver, see [`Self::alias`]), target names resolved locally and sent as IPs.
    pub fn wreq_proxy(&self) -> std::result::Result<wreq::Proxy, wreq::Error> {
        let scheme = match self.cfg.kind {
            UpstreamProxyKind::Http => "http",
            UpstreamProxyKind::Socks5 => "socks5",
        };
        let mut p = wreq::Proxy::all(format!("{scheme}://{}:{}", self.alias, self.cfg.port))?
            .resolve_locally(true);
        if !self.cfg.username.is_empty() {
            p = p.basic_auth(&self.cfg.username, &self.cfg.password);
        }
        Ok(p)
    }

    /// Connect to the vetted `target` through the proxy. A failure to reach the proxy
    /// re-resolves its name once.
    pub async fn connect(&self, target: SocketAddr) -> io::Result<TcpStream> {
        let mut last = io::Error::other("no addresses");
        for attempt in 0..2 {
            for addr in self.addrs().await? {
                match TcpStream::connect(addr).await {
                    Ok(s) => {
                        let _ = s.set_nodelay(true);
                        return self.handshake(s, target).await;
                    }
                    Err(e) => last = e,
                }
            }
            if attempt == 0 && self.cfg.bare_host().parse::<IpAddr>().is_err() {
                self.dns.forget(self.cfg.bare_host()).await;
            } else {
                break;
            }
        }
        Err(io::Error::new(
            last.kind(),
            format!("cannot reach upstream proxy {}: {last}", self.display()),
        ))
    }

    async fn handshake(&self, mut s: TcpStream, target: SocketAddr) -> io::Result<TcpStream> {
        match self.cfg.kind {
            UpstreamProxyKind::Http => self.http_connect(&mut s, target).await?,
            UpstreamProxyKind::Socks5 => self.socks5(&mut s, target).await?,
        }
        Ok(s)
    }

    async fn http_connect(&self, s: &mut TcpStream, target: SocketAddr) -> io::Result<()> {
        let t = match target.ip() {
            IpAddr::V4(a) => format!("{a}:{}", target.port()),
            IpAddr::V6(a) => format!("[{a}]:{}", target.port()),
        };
        let mut req = format!("CONNECT {t} HTTP/1.1\r\nHost: {t}\r\n");
        if !self.cfg.username.is_empty() {
            let cred = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", self.cfg.username, self.cfg.password));
            req.push_str(&format!("Proxy-Authorization: Basic {cred}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).await?;
        // Byte at a time: whatever follows the head belongs to the tunnel.
        let mut head = Vec::with_capacity(256);
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() >= MAX_HEAD {
                return Err(io::Error::other(
                    "upstream proxy sent an oversized response",
                ));
            }
            if s.read(&mut b).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream proxy closed the connection during CONNECT",
                ));
            }
            head.push(b[0]);
        }
        let line =
            String::from_utf8_lossy(head.split(|c| *c == b'\r').next().unwrap_or(&[])).into_owned();
        let code = line.split_whitespace().nth(1).unwrap_or("");
        match code {
            "200" => Ok(()),
            "407" => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "upstream proxy rejected the username or password (407)",
            )),
            _ => Err(io::Error::other(format!(
                "upstream proxy refused CONNECT: {line}"
            ))),
        }
    }

    async fn socks5(&self, s: &mut TcpStream, target: SocketAddr) -> io::Result<()> {
        let creds = !self.cfg.username.is_empty();
        if creds {
            s.write_all(&[5, 2, 0, 2]).await?;
        } else {
            s.write_all(&[5, 1, 0]).await?;
        }
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await?;
        if r[0] != 5 {
            return Err(io::Error::other("upstream proxy does not speak SOCKS5"));
        }
        match r[1] {
            0 => {}
            2 if creds => {
                let (u, p) = (self.cfg.username.as_bytes(), self.cfg.password.as_bytes());
                let mut m = vec![1, u.len() as u8];
                m.extend_from_slice(u);
                m.push(p.len() as u8);
                m.extend_from_slice(p);
                s.write_all(&m).await?;
                let mut a = [0u8; 2];
                s.read_exact(&mut a).await?;
                if a[1] != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "upstream proxy rejected the username or password",
                    ));
                }
            }
            0xFF => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    if creds {
                        "upstream proxy accepts none of Argus's SOCKS5 login methods"
                    } else {
                        "upstream proxy requires a username and password"
                    },
                ))
            }
            m => {
                return Err(io::Error::other(format!(
                    "upstream proxy chose an unsupported SOCKS5 method ({m})"
                )))
            }
        }
        // The vetted IP, never a domain (ATYP 1 / 4).
        let mut m = vec![5, 1, 0];
        match target.ip() {
            IpAddr::V4(a) => {
                m.push(1);
                m.extend_from_slice(&a.octets());
            }
            IpAddr::V6(a) => {
                m.push(4);
                m.extend_from_slice(&a.octets());
            }
        }
        m.extend_from_slice(&target.port().to_be_bytes());
        s.write_all(&m).await?;
        let mut h = [0u8; 4];
        s.read_exact(&mut h).await?;
        if h[1] != 0 {
            return Err(io::Error::other(format!(
                "upstream proxy refused the SOCKS5 connection: {}",
                match h[1] {
                    1 => "general failure",
                    2 => "not allowed by its ruleset",
                    3 => "network unreachable",
                    4 => "host unreachable",
                    5 => "connection refused",
                    6 => "TTL expired",
                    7 => "command not supported",
                    8 => "address type not supported",
                    _ => "unknown error",
                }
            )));
        }
        let skip = match h[3] {
            1 => 4,
            4 => 16,
            3 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await?;
                l[0] as usize
            }
            _ => return Err(io::Error::other("upstream proxy sent a bad SOCKS5 reply")),
        } + 2;
        let mut sink = vec![0u8; skip];
        s.read_exact(&mut sink).await?;
        Ok(())
    }

    /// Connect through the proxy to `host:port` (resolved and vetted here), complete a TLS
    /// handshake, and report how long it took.
    pub async fn test(
        &self,
        tls: tokio_rustls::TlsConnector,
        host: &str,
        port: u16,
        limit: Duration,
    ) -> std::result::Result<Duration, String> {
        let started = Instant::now();
        let run = async {
            let addr = self
                .policy
                .resolve(host, port, None)
                .await
                .map_err(|e| format!("cannot resolve {host} on Argus: {e}"))?;
            let tcp = self.connect(addr).await.map_err(|e| e.to_string())?;
            let name = rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| e.to_string())?;
            tls.connect(name, tcp)
                .await
                .map_err(|e| format!("TLS to {host} through the proxy failed: {e}"))?;
            Ok::<(), String>(())
        };
        match tokio::time::timeout(limit, run).await {
            Ok(Ok(())) => Ok(started.elapsed()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(format!("timed out after {}s", limit.as_secs())),
        }
    }
}

/// Resolve `host:port` through the destination policy and connect to exactly that address,
/// directly or through the upstream proxy when one is on.
pub async fn dial(
    policy: &DestPolicy,
    proxy: Option<&ProxyEndpoint>,
    host: &str,
    port: u16,
    override_ip: Option<IpAddr>,
) -> Result<TcpStream> {
    let addr = policy.resolve(host, port, override_ip).await?;
    connect_vetted(proxy, addr).await
}

/// Connect to an address the policy already vetted.
pub async fn connect_vetted(proxy: Option<&ProxyEndpoint>, addr: SocketAddr) -> Result<TcpStream> {
    match proxy {
        Some(p) => p.connect(addr).await.map_err(Error::Io),
        None => TcpStream::connect(addr).await.map_err(Error::Io),
    }
}

#[cfg(test)]
#[path = "upstream_proxy_tests.rs"]
mod tests;

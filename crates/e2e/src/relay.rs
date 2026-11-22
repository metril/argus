//! A TCP relay that dials its upstream from a chosen local source address, so one client
//! (a browser context, say) reaches the proxy as a particular `127.0.0.N` device.

use std::net::{IpAddr, SocketAddr};

use tokio::net::{TcpListener, TcpSocket};

/// Listens on an ephemeral loopback port; every connection is relayed to `upstream` from
/// `source`. Stops when dropped.
pub struct SourceRelay {
    pub addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl SourceRelay {
    pub async fn start(upstream: SocketAddr, source: IpAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("relay bind");
        let addr = listener.local_addr().expect("relay addr");
        let task = tokio::spawn(async move {
            while let Ok((mut down, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let sock = TcpSocket::new_v4().expect("socket");
                    if sock.bind(SocketAddr::new(source, 0)).is_err() {
                        return;
                    }
                    if let Ok(mut up) = sock.connect(upstream).await {
                        let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
                    }
                });
            }
        });
        Self { addr, task }
    }

    /// `http://127.0.0.1:<port>`, for a browser's proxy setting.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for SourceRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

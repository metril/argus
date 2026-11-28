//! CNAME uncloaking through the real server: a request whose host is an alias of a blocked name
//! is blocked, and counted and logged once.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use filter_engine::{compile_engine, SharedEngine};
use proxy_core::config::ProxyConfig;
use proxy_core::dns::{CachedResolver, CanonResult, DnsCacheConfig, DnsFailure, Resolver};
use proxy_core::upstream::UpstreamOptions;
use proxy_core::{ProxyContext, ProxyServer};
use tokio::net::TcpListener;

/// Every name resolves to a documentation address; `cmp.site.test` is an alias of
/// `d2gt.tracker.test`.
struct Aliased;

impl Resolver for Aliased {
    fn lookup(
        &self,
        name: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<std::net::IpAddr>, Duration), DnsFailure>> + Send>>
    {
        let f = self.lookup_canon(name);
        Box::pin(async move { f.await.map(|(a, t, _)| (a, t)) })
    }

    fn lookup_canon(&self, name: &str) -> Pin<Box<dyn Future<Output = CanonResult> + Send>> {
        let canon = (name == "cmp.site.test").then(|| "d2gt.tracker.test".to_string());
        Box::pin(async move {
            Ok((
                vec!["192.0.2.1".parse().unwrap()],
                Duration::from_secs(60),
                canon,
            ))
        })
    }
}

async fn start() -> (u16, Arc<SharedEngine>) {
    let mut config = ProxyConfig::default();
    config.proxy.host = "127.0.0.1".into();
    config.mitm.enabled = false;
    let engine = Arc::new(SharedEngine::new());
    engine.install(compile_engine(&["||tracker.test^\n".to_string()]));
    let mut opts = UpstreamOptions::from_config(&config);
    opts.dns = Some(Arc::new(CachedResolver::new(
        Arc::new(Aliased),
        DnsCacheConfig::default(),
    )));
    let ctx = Arc::new(ProxyContext::with_upstream(engine.clone(), &opts, true).unwrap());
    ctx.set_cname(&config.adblock.cname);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = ProxyServer::new(config, ctx).unwrap();
    let (tx, _) = tokio::sync::broadcast::channel(1);
    tokio::spawn(async move {
        let _ = server.serve(listener, tx).await;
    });
    (port, engine)
}

#[tokio::test]
async fn an_alias_of_a_blocked_name_is_blocked_and_counted_once() {
    let (port, engine) = start().await;
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{port}")).unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let err = client
        .get("http://cmp.site.test/consent.js")
        .header("referer", "http://news.example/")
        .send()
        .await
        .expect_err("the aliased request is aborted");
    assert!(!err.is_timeout(), "{err:?}");
    let s = engine.stats_handle().snapshot();
    assert_eq!(
        (s.total_requests, s.blocked_requests, s.allowed_requests),
        (1, 1, 0)
    );
    let log = engine.recent_blocked(10);
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!(log[0].rule.as_deref(), Some("cname:d2gt.tracker.test"));
    // Statistics keep the rule that matched the canonical name, not the `cname:` reason.
    let (_, by_rule) = engine.stats_handle().take_sources();
    assert_eq!(by_rule, vec![("||tracker.test^".to_string(), 1)]);
}

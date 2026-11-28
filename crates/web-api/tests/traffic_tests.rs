//! `GET /stats/traffic` and `POST /stats/traffic/reset`: shape, grouping, sorting, limits,
//! profile scoping and reset, over a runtime that serves a fixed snapshot.

mod common;

use ::common::traffic::{DeviceTraffic, HandlingBytes, HostTraffic, TrafficRow, TrafficSnapshot};
use axum::http::StatusCode;
use common::TestContext;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use web_api::{ProxyBind, RuntimeControl};

fn row(up: u64, down: u64, up_rate: f64, down_rate: f64) -> TrafficRow {
    TrafficRow {
        up,
        down,
        up_rate,
        down_rate,
        connections_total: 2,
        connections_active: 1,
        local_requests: 1,
        local_bytes: 10,
        handling: HandlingBytes {
            decrypted: down,
            tunnelled: 0,
            plain: up,
        },
        last_active_ms: Some(1_700_000_000_000),
    }
}

fn host(h: &str, r: TrafficRow) -> HostTraffic {
    HostTraffic {
        host: h.into(),
        row: r,
    }
}

struct Fake {
    snap: Mutex<TrafficSnapshot>,
    resets: Mutex<u32>,
}

#[async_trait::async_trait]
impl RuntimeControl for Fake {
    async fn rebind_proxy(&self, _: &str, p: u16, _: Option<u16>) -> Result<ProxyBind, String> {
        Ok(ProxyBind {
            proxy: SocketAddr::from(([127, 0, 0, 1], p)),
            transparent: None,
            proxy_down: false,
            transparent_down: false,
            proxy_error: None,
            transparent_error: None,
        })
    }
    async fn apply_access(&self, _: &::common::config::ProxyConfig) -> Result<(), String> {
        Ok(())
    }
    fn listener_counters(&self) -> (web_api::ListenerCounters, web_api::ListenerCounters) {
        Default::default()
    }
    async fn proxy_bind(&self) -> Option<ProxyBind> {
        None
    }
    async fn note_webui(&self, _: &str, _: u16) {}
    fn traffic_snapshot(&self) -> Option<TrafficSnapshot> {
        Some(self.snap.lock().unwrap().clone())
    }
    fn traffic_totals(&self) -> Option<(u64, u64)> {
        let s = self.snap.lock().unwrap();
        Some((s.up_total, s.down_total))
    }
    fn traffic_reset(&self) {
        *self.resets.lock().unwrap() += 1;
        *self.snap.lock().unwrap() = TrafficSnapshot::default();
    }
}

fn snapshot(p_a: u64, p_b: u64) -> TrafficSnapshot {
    TrafficSnapshot {
        at_ms: 1_700_000_005_000,
        interval_ms: 1000,
        up_total: 1_000 + 500 + 40,
        down_total: 9_000 + 100 + 7,
        devices: vec![
            DeviceTraffic {
                key: "i:10.0.0.5".into(),
                profile_id: p_a,
                row: row(1_000, 9_000, 100.0, 5_000.0),
                hosts: vec![
                    host("slow.example", row(10, 100, 1.0, 10.0)),
                    host("fast.example", row(900, 8_000, 99.0, 4_990.0)),
                ],
                other: row(90, 900, 0.0, 0.0),
            },
            DeviceTraffic {
                key: format!("t:{}", "ab".repeat(32)),
                profile_id: p_b,
                row: row(500, 100, 10.0, 20.0),
                hosts: vec![host("fast.example", row(500, 100, 10.0, 20.0))],
                other: TrafficRow::default(),
            },
            DeviceTraffic {
                key: "x:7".into(),
                profile_id: p_b,
                row: row(40, 7, 0.0, 0.0),
                hosts: vec![host("ext.example", row(40, 7, 0.0, 0.0))],
                other: TrafficRow::default(),
            },
        ],
    }
}

async fn setup(p_a: u64, p_b: u64) -> (TestContext, Arc<Fake>) {
    let ctx = TestContext::new().await.unwrap();
    let fake = Arc::new(Fake {
        snap: Mutex::new(snapshot(p_a, p_b)),
        resets: Mutex::new(0),
    });
    assert!(ctx.state.runtime.set(fake.clone()).is_ok());
    (ctx, fake)
}

const T: &str = "/api/v1/stats/traffic";

#[tokio::test]
async fn device_rows_carry_totals_rates_handling_and_top_hosts() {
    let (ctx, _) = setup(0, 0).await;
    let admin = ctx.admin().await;
    let r = admin.get(T).await;
    r.assert_status_ok();
    let v: Value = r.json();
    assert_eq!(v["group"], "device");
    assert_eq!(v["interval_ms"], 1000);
    assert_eq!(v["at_ms"], 1_700_000_005_000u64);
    assert!(v["at"].as_str().unwrap().starts_with("2023-11-14T"));
    assert_eq!(v["totals"], json!({"up": 1540, "down": 9107}));
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    // Busiest first by current rate.
    assert_eq!(rows[0]["device_id"], "i:10.0.0.5");
    assert_eq!(rows[0]["device_name"], "10.0.0.5");
    assert_eq!(rows[0]["up"], 1000);
    assert_eq!(rows[0]["down"], 9000);
    assert_eq!(rows[0]["down_rate"], 5000.0);
    assert_eq!(rows[0]["connections_active"], 1);
    assert_eq!(rows[0]["handling"]["decrypted"], 9000);
    assert_eq!(rows[0]["local_requests"], 1);
    let top = rows[0]["top_hosts"].as_array().unwrap();
    assert_eq!(top[0]["host"], "fast.example");
    assert_eq!(top[1]["host"], "slow.example");
    // The token digest is never shown whole.
    let id = rows[1]["device_id"].as_str().unwrap();
    assert_eq!(id, format!("t:{}", "ab".repeat(6)));
    assert_eq!(rows[2]["device_id"], "x:7");
}

#[tokio::test]
async fn host_group_merges_devices_and_keeps_other_hosts() {
    let (ctx, _) = setup(0, 0).await;
    let admin = ctx.admin().await;
    let v: Value = admin.get(&format!("{T}?group=host")).await.json();
    assert_eq!(v["group"], "host");
    let rows = v["rows"].as_array().unwrap();
    let get = |h: &str| rows.iter().find(|r| r["host"] == h).unwrap();
    // fast.example is seen by two devices and added up.
    assert_eq!(get("fast.example")["down"], 8_100);
    assert_eq!(get("fast.example")["connections_total"], 4);
    assert_eq!(get("(other hosts)")["other"], true);
    assert!(rows.iter().all(|r| r["device_id"].is_null()));
    // The totals of all rows equal the process totals (nothing lost to "other").
    let sum: u64 = rows.iter().map(|r| r["down"].as_u64().unwrap()).sum();
    assert_eq!(sum, 9_000 + 100 + 7);
    // Filtered to one device: that device's hosts, with its identity.
    let v: Value = admin
        .get(&format!("{T}?group=host&device=i:10.0.0.5"))
        .await
        .json();
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|r| r["device_id"] == "i:10.0.0.5"));
    assert_eq!(v["totals"], json!({"up": 1000, "down": 9000}));
}

#[tokio::test]
async fn sorting_limit_and_validation() {
    let (ctx, _) = setup(0, 0).await;
    let admin = ctx.admin().await;
    let ids = |v: &Value| -> Vec<String> {
        v["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["device_id"].as_str().unwrap().to_string())
            .collect()
    };
    let v: Value = admin.get(&format!("{T}?sort=up")).await.json();
    assert_eq!(ids(&v)[0], "i:10.0.0.5");
    assert_eq!(ids(&v)[2], "x:7");
    let v: Value = admin.get(&format!("{T}?sort=down&limit=2")).await.json();
    assert_eq!(ids(&v).len(), 2);
    assert_eq!(ids(&v)[1], format!("t:{}", "ab".repeat(6)));
    for bad in ["group=nope", "sort=nope", "limit=0", "limit=5000"] {
        admin
            .get(&format!("{T}?{bad}"))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
}

async fn mk_profile(admin: &common::Sess, name: &str) -> String {
    let r = admin
        .post("/api/v1/profiles")
        .json(&json!({"name": name}))
        .await;
    assert_eq!(r.status_code(), StatusCode::CREATED, "{}", r.text());
    r.json::<Value>()["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn a_restricted_token_sees_only_its_profiles_devices() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let p1 = mk_profile(&admin, "kids").await;
    let p1n: u64 = p1.parse().unwrap();
    let fake = Arc::new(Fake {
        snap: Mutex::new(snapshot(p1n, 0)),
        resets: Mutex::new(0),
    });
    assert!(ctx.state.runtime.set(fake.clone()).is_ok());
    let resp = admin
        .post("/api/v1/tokens")
        .json(&json!({"name": "r", "scopes": ["stats:read", "logs:read", "stats:reset"], "profiles": [p1]}))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let secret = resp.json::<Value>()["secret"].as_str().unwrap().to_string();

    let v: Value = ctx.bearer("GET", T, &secret).await.json();
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["device_id"], "i:10.0.0.5");
    assert_eq!(rows[0]["profile_id"], p1);
    // Totals are the visible devices', never the whole proxy's.
    assert_eq!(v["totals"], json!({"up": 1000, "down": 9000}));
    // Hosts of other profiles' devices do not leak through the host grouping either.
    let v: Value = ctx
        .bearer("GET", &format!("{T}?group=host"), &secret)
        .await
        .json();
    assert!(v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["host"] != "ext.example"));
    let sum: u64 = v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["down"].as_u64().unwrap())
        .sum();
    assert_eq!(sum, 9000);
    // Asking for another profile's device is the same as asking for none.
    let v: Value = ctx
        .bearer("GET", &format!("{T}?device=x:7"), &secret)
        .await
        .json();
    assert!(v["rows"].as_array().unwrap().is_empty());
    // The counters span every device: not resettable by a restricted token.
    ctx.bearer("POST", &format!("{T}/reset"), &secret)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    assert_eq!(*fake.resets.lock().unwrap(), 0);
}

#[tokio::test]
async fn scopes_are_enforced_and_reset_clears() {
    let (ctx, fake) = setup(0, 0).await;
    let admin = ctx.admin().await;
    let read = ctx.token(&admin, &["stats:read"]).await;
    ctx.bearer("GET", T, &read).await.assert_status_ok();
    ctx.bearer("POST", &format!("{T}/reset"), &read)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    let reset = ctx.token(&admin, &["stats:reset"]).await;
    ctx.bearer("GET", T, &reset)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    ctx.bearer("POST", &format!("{T}/reset"), &reset)
        .await
        .assert_status_ok();
    assert_eq!(*fake.resets.lock().unwrap(), 1);
    let v: Value = admin.get(T).await.json();
    assert!(v["rows"].as_array().unwrap().is_empty());
    assert_eq!(v["totals"], json!({"up": 0, "down": 0}));
}

#[tokio::test]
async fn proxy_stats_byte_counters_follow_the_traffic_totals() {
    let (ctx, _) = setup(0, 0).await;
    let admin = ctx.admin().await;
    let v: Value = admin.get("/api/v1/stats/proxy").await.json();
    assert_eq!(v["requests"]["bytes_received"], 1540);
    assert_eq!(v["requests"]["bytes_sent"], 9107);
}

#[tokio::test]
async fn without_a_proxy_the_table_is_empty() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let v: Value = admin.get(T).await.json();
    assert!(v["rows"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn per_host_figures_need_logs_read_besides_stats_read() {
    let (ctx, _) = setup(0, 0).await;
    let admin = ctx.admin().await;
    let stats_only = ctx.token(&admin, &["stats:read"]).await;
    // Device rows: totals, rates and counts, but no hosts, and the response says so.
    let v: Value = ctx.bearer("GET", T, &stats_only).await.json();
    assert_eq!(v["hosts_visible"], false);
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["down"], 9000);
    assert_eq!(rows[0]["connections_active"], 1);
    assert!(rows
        .iter()
        .all(|r| r["top_hosts"].as_array().unwrap().is_empty()));
    assert!(
        !v.to_string().contains("example"),
        "no host name leaks: {v}"
    );
    // group=host is refused with the standard insufficient-scope shape.
    let r = ctx
        .bearer("GET", &format!("{T}?group=host"), &stats_only)
        .await;
    r.assert_status(StatusCode::FORBIDDEN);
    let b: Value = r.json();
    assert_eq!(b["error"]["code"], "insufficient_scope");
    assert!(b["error"]["message"]
        .as_str()
        .unwrap()
        .contains("logs:read"));
    // With logs:read as well: hosts are there.
    let both = ctx.token(&admin, &["stats:read", "logs:read"]).await;
    let v: Value = ctx.bearer("GET", T, &both).await.json();
    assert_eq!(v["hosts_visible"], true);
    assert!(!v["rows"][0]["top_hosts"].as_array().unwrap().is_empty());
    ctx.bearer("GET", &format!("{T}?group=host"), &both)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn a_restricted_token_without_logs_read_sees_no_hosts() {
    let ctx = TestContext::new().await.unwrap();
    let admin = ctx.admin().await;
    let p1 = mk_profile(&admin, "kids").await;
    let fake = Arc::new(Fake {
        snap: Mutex::new(snapshot(p1.parse().unwrap(), 0)),
        resets: Mutex::new(0),
    });
    assert!(ctx.state.runtime.set(fake).is_ok());
    let resp = admin
        .post("/api/v1/tokens")
        .json(&json!({"name": "r", "scopes": ["stats:read"], "profiles": [p1]}))
        .await;
    let secret = resp.json::<Value>()["secret"].as_str().unwrap().to_string();
    let v: Value = ctx.bearer("GET", T, &secret).await.json();
    assert_eq!(v["rows"].as_array().unwrap().len(), 1);
    assert_eq!(v["hosts_visible"], false);
    assert!(v["rows"][0]["top_hosts"].as_array().unwrap().is_empty());
    ctx.bearer("GET", &format!("{T}?group=host"), &secret)
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

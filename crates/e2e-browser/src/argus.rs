//! A real Argus process for the browser-extension suites: the production binary with its own
//! temp data directory, ephemeral ports, a stub DNS resolver (every name resolves to loopback)
//! and an admin account, so a real browser with the real extension can talk to it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};

const PASSWORD: &str = "SecurePassword123!";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("free port")
}

/// Path of the `argus` binary: `ARGUS_BIN`, else built (and located) through cargo.
pub fn argus_binary() -> PathBuf {
    if let Some(p) = std::env::var_os("ARGUS_BIN") {
        return p.into();
    }
    let out = std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args([
            "build",
            "-q",
            "-p",
            "proxy-core",
            "--bin",
            "argus",
            "--features",
            "full",
            "--message-format=json",
        ])
        .stderr(Stdio::inherit())
        .output()
        .expect("cargo build argus");
    assert!(out.status.success(), "building the argus binary failed");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["reason"] == "compiler-artifact" && v["target"]["name"] == "argus")
        .filter_map(|v| v["executable"].as_str().map(PathBuf::from))
        .next_back()
        .expect("argus executable in cargo output")
}

/// Answers every `A` question with 127.0.0.1 and every other type with an empty answer.
async fn dns_stub() -> SocketAddr {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("dns socket");
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            if n < 12 {
                continue;
            }
            // question section: labels, then type and class
            let mut i = 12;
            while i < n && buf[i] != 0 {
                i += buf[i] as usize + 1;
            }
            if i + 5 > n {
                continue;
            }
            let qend = i + 5;
            let qtype = u16::from_be_bytes([buf[i + 1], buf[i + 2]]);
            let mut r = buf[..qend].to_vec();
            r[2] = 0x81; // response, recursion desired
            r[3] = 0x80; // recursion available, no error
            r[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
            if qtype == 1 {
                r[7] = 1;
                r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
            }
            let _ = sock.send_to(&r, from).await;
        }
    });
    addr
}

pub struct Argus {
    child: tokio::process::Child,
    pub dir: tempfile::TempDir,
    pub web: u16,
    pub proxy: u16,
    pub ext: u16,
    /// PEM of the Argus CA (what a browser must trust).
    pub ca_pem: Vec<u8>,
    http: reqwest::Client,
    access: String,
    csrf: String,
    /// Bearer token with the bridge scope (what the extension is configured with).
    pub token: String,
}

impl Argus {
    /// Start Argus trusting `upstream_ca_pem` for origins (the test origin's CA).
    pub async fn start(upstream_ca_pem: &str) -> Argus {
        let dir = tempfile::tempdir().expect("argus dir");
        let (web, proxy, ext) = (free_port(), free_port(), free_port());
        let dns = dns_stub().await;
        let up_ca = dir.path().join("origin-ca.pem");
        std::fs::write(&up_ca, upstream_ca_pem).unwrap();
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/default.toml");
        let mut cfg: toml::Table = std::fs::read_to_string(&base).unwrap().parse().unwrap();
        let abs = |p: &str| dir.path().join(p).to_string_lossy().to_string();
        let set = |cfg: &mut toml::Table, sec: &str, k: &str, v: toml::Value| {
            cfg.entry(sec)
                .or_insert_with(|| toml::Value::Table(Default::default()))
                .as_table_mut()
                .unwrap()
                .insert(k.into(), v);
        };
        use toml::Value as V;
        set(&mut cfg, "proxy", "host", V::String("127.0.0.1".into()));
        set(&mut cfg, "proxy", "port", V::Integer(proxy as i64));
        set(&mut cfg, "proxy", "ext_port", V::Integer(ext as i64));
        cfg["proxy"]
            .as_table_mut()
            .unwrap()
            .remove("transparent_port");
        set(
            &mut cfg,
            "proxy",
            "allowed_destinations",
            V::Array(vec![V::String("127.0.0.0/8".into())]),
        );
        set(
            &mut cfg,
            "proxy",
            "extra_upstream_ca_paths",
            V::Array(vec![V::String(up_ca.to_string_lossy().into())]),
        );
        set(
            &mut cfg,
            "mitm",
            "ca_cert_path",
            V::String(abs("certs/root-ca.crt")),
        );
        set(
            &mut cfg,
            "mitm",
            "ca_key_path",
            V::String(abs("certs/root-ca.key")),
        );
        set(
            &mut cfg,
            "adblock",
            "data_dir",
            V::String(abs("data/filters")),
        );
        set(&mut cfg, "adblock", "auto_update", V::Boolean(false));
        set(&mut cfg, "webui", "host", V::String("127.0.0.1".into()));
        set(&mut cfg, "webui", "port", V::Integer(web as i64));
        set(
            &mut cfg,
            "webui",
            "jwt_secret_path",
            V::String(abs("data/jwt_secret")),
        );
        set(
            &mut cfg,
            "dns",
            "servers",
            V::Array(vec![V::String(dns.to_string())]),
        );
        set(
            &mut cfg,
            "bypass",
            "lists_base_url",
            V::String("http://127.0.0.1:1".into()),
        );
        set(&mut cfg, "userscripts", "enabled", V::Boolean(true));
        set(
            &mut cfg,
            "script_control",
            "panel_enabled",
            V::Boolean(false),
        );
        let cfg_path = dir.path().join("config.toml");
        std::fs::write(&cfg_path, toml::to_string(&cfg).unwrap()).unwrap();
        let log = std::fs::File::create(dir.path().join("argus.log")).unwrap();
        let child = tokio::process::Command::new(argus_binary())
            .current_dir(dir.path())
            .env("CONFIG_PATH", &cfg_path)
            .env(
                "RUST_LOG",
                std::env::var("ARGUS_RUST_LOG").unwrap_or_else(|_| "info".into()),
            )
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .kill_on_drop(true)
            .spawn()
            .expect("spawn argus");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap();
        let base = format!("http://127.0.0.1:{web}");
        let mut up = false;
        for _ in 0..600 {
            if http
                .get(format!("{base}/api/v1/health"))
                .send()
                .await
                .is_ok()
            {
                up = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            up,
            "argus did not start:\n{}",
            std::fs::read_to_string(dir.path().join("argus.log"))
                .unwrap_or_default()
                .lines()
                .filter(|l| !l.contains("destination"))
                .skip(20)
                .take(40)
                .collect::<Vec<_>>()
                .join("\n")
        );
        let r = http
            .post(format!("{base}/api/v1/auth/register"))
            .json(&json!({"username": "admin_user", "password": PASSWORD, "password_confirm": PASSWORD}))
            .send()
            .await
            .unwrap();
        let st = r.status();
        assert!(st.is_success(), "register: {st}");
        let hdrs = r.headers().clone();
        let cookie = |name: &str| {
            hdrs.get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .find_map(|s| {
                    s.strip_prefix(&format!("{name}="))
                        .map(|x| x.split(';').next().unwrap_or("").to_string())
                })
                .unwrap_or_default()
        };
        let (access, csrf) = (cookie("access_token"), cookie("csrf_token"));
        let mut a = Argus {
            child,
            dir,
            web,
            proxy,
            ext,
            ca_pem: Vec::new(),
            http,
            access,
            csrf,
            token: String::new(),
        };
        let t = a
            .admin(
                "POST",
                "/api/v1/tokens",
                Some(json!({"name": "ext", "scopes": ["userscripts:bridge", "logs:read"]})),
            )
            .await;
        a.token = t["secret"].as_str().expect("token secret").to_string();
        // Nothing to wait for: lists are not reachable in a test, the admin override decrypts anyway.
        a.admin(
            "PUT",
            "/api/v1/bypass/settings",
            Some(json!({"decrypt_without_lists": true, "ev_no_decrypt": false})),
        )
        .await;
        for _ in 0..100 {
            if let Ok(b) = std::fs::read(a.dir.path().join("certs/root-ca.crt")) {
                a.ca_pem = b;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!a.ca_pem.is_empty(), "the Argus CA was not created");
        a
    }

    pub fn web_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.web)
    }

    /// An admin API call (cookie session with CSRF); returns the JSON body (`null` when empty).
    pub async fn admin(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let mut rb = self
            .http
            .request(m, format!("{}{path}", self.web_url()))
            .header("cookie", format!("access_token={}", self.access))
            .header("x-csrf-token", &self.csrf);
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let r = rb.send().await.unwrap();
        let st = r.status();
        let text = r.text().await.unwrap_or_default();
        assert!(st.is_success(), "{method} {path}: {st} {text}");
        serde_json::from_str(&text).unwrap_or(Value::Null)
    }

    /// Install a userscript approved for browser logins (`browser_cookies`); returns its id.
    pub async fn install_script(&self, source: &str) -> String {
        let plan = self
            .admin(
                "POST",
                "/api/v1/userscripts/plan",
                Some(json!({"source": source})),
            )
            .await;
        let id = plan["plan_id"].as_str().expect("plan id").to_string();
        let s = self
            .admin(
                "POST",
                &format!("/api/v1/userscripts/plan/{id}/confirm"),
                Some(json!({"browser_cookies": true})),
            )
            .await;
        s["id"].as_str().expect("script id").to_string()
    }

    /// A bridge-scope call as the extension's popup makes it.
    pub async fn bridge(
        &self,
        method: &str,
        path: &str,
        sid: &str,
        store: Option<&str>,
        body: Option<Value>,
    ) -> (u16, Value) {
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let mut rb = self
            .http
            .request(m, format!("{}{path}", self.web_url()))
            .bearer_auth(&self.token)
            .header("x-argus-session", sid);
        if let Some(s) = store {
            rb = rb.header("x-argus-store", s);
        }
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let r = rb.send().await.unwrap();
        let st = r.status().as_u16();
        (st, r.json().await.unwrap_or(Value::Null))
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("argus.log")).unwrap_or_default()
    }

    pub async fn stop(mut self) {
        let _ = self.child.kill().await;
    }
}

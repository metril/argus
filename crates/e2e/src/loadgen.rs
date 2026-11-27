//! Load generator library behind `cargo run --release -p e2e --bin loadgen`.
//!
//! Drives a [`TestClient`] against the in-process [`TestOrigin`], directly or through a proxy,
//! closed loop (N workers back to back) or open loop (fixed request rate, latency measured from
//! the scheduled send time so a stalled proxy is charged for the queueing it causes).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use parking_lot::Mutex;
use serde_json::{json, Value};

use crate::{HttpVersion, MockResponse, TestClient, TestOrigin};

pub const SMALL_LEN: usize = 1024;
pub const MEDIUM_LEN: usize = 64 * 1024;

/// What a request asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// 1 KiB, allowed.
    Small = 0,
    /// 64 KiB, allowed.
    Medium = 1,
    /// Matched by a network rule: the proxy answers.
    Blocked = 2,
    /// HTML document that gets a cosmetic rule injected.
    Html = 3,
}

pub const CLASSES: [Class; 4] = [Class::Small, Class::Medium, Class::Blocked, Class::Html];

impl Class {
    pub fn name(self) -> &'static str {
        ["small", "medium", "blocked", "html"][self as usize]
    }

    fn path(self) -> &'static str {
        ["/small", "/medium", "/ads/banner.gif", "/page.html"][self as usize]
    }

    fn host(self, idx: usize, suffix: &str) -> String {
        let p = ["a", "a", "ads", "www"][self as usize];
        format!("{p}{idx}.{suffix}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    H1,
    H2,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::H1 => "h1",
            Proto::H2 => "h2",
        }
    }
    pub fn version(self) -> HttpVersion {
        match self {
            Proto::H1 => HttpVersion::Http1,
            Proto::H2 => HttpVersion::Http2,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Model {
    /// `conns` workers, each sending the next request when the last finished (h1: connections,
    /// h2: concurrent streams).
    Closed { conns: usize },
    /// `rate` requests/s on a fixed schedule; at most `max_inflight` outstanding (more are
    /// counted as dropped, which means the target cannot keep up).
    Open { rate: u32, max_inflight: usize },
}

/// Request mix: weights per [`Class`] and how many hostnames each class spreads over.
#[derive(Clone, Debug)]
pub struct Workload {
    pub weights: [u32; 4],
    pub hosts: usize,
    pub seed: u64,
    pub suffix: String,
}

impl Workload {
    pub fn parse_mix(s: &str) -> Result<[u32; 4], String> {
        let mut w = [0u32; 4];
        for part in s.split(',').filter(|p| !p.is_empty()) {
            let (k, v) = part
                .split_once('=')
                .ok_or(format!("bad mix entry {part}"))?;
            let i = CLASSES
                .iter()
                .position(|c| c.name() == k)
                .ok_or(format!("unknown class {k}"))?;
            w[i] = v.parse().map_err(|_| format!("bad weight {v}"))?;
        }
        if w.iter().sum::<u32>() == 0 {
            return Err("mix has no weight".into());
        }
        Ok(w)
    }

    /// The `i`-th request, a pure function of the seed (both paths replay the same sequence).
    fn nth(&self, i: u64) -> (Class, usize) {
        let h = splitmix(self.seed ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let total: u64 = self.weights.iter().map(|w| *w as u64).sum();
        let mut x = h % total;
        let mut class = Class::Small;
        for c in CLASSES {
            let w = self.weights[c as usize] as u64;
            if x < w {
                class = c;
                break;
            }
            x -= w;
        }
        (class, (h >> 40) as usize % self.hosts.max(1))
    }

    /// Filter rules every list must contain so the mix behaves as labelled.
    pub fn required_rules(&self) -> String {
        let mut s = String::new();
        for i in 0..self.hosts {
            s += &format!("||{}^\n", Class::Blocked.host(i, &self.suffix));
            s += &format!("{}##.ad-banner\n", Class::Html.host(i, &self.suffix));
        }
        s
    }
}

fn splitmix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A generated ABP list of `n` rules (network, exception, cosmetic) plus the workload's
/// required rules; `seed` changes the content so a reload is a real rebuild.
pub fn generate_list(n: usize, seed: u64, w: &Workload) -> String {
    let mut s = w.required_rules();
    s.reserve(n * 40);
    for i in 0..n as u64 {
        let h = splitmix(seed.wrapping_mul(1_000_003).wrapping_add(i));
        let k = h % 100;
        let id = (h >> 8) % 10_000_000;
        match k {
            0..=54 => s += &format!("||ad{id}.tracker{}.example^\n", k % 7),
            55..=74 => s += &format!("/ads{}/banner{id}*.js$script,third-party\n", k % 13),
            75..=84 => s += &format!("@@||ok{id}.example^$image\n"),
            85..=94 => s += &format!("site{}.example##.ad-{id}\n", id % 5000),
            _ => s += &format!("##.sponsored-{id}\n"),
        }
    }
    s
}

/// Register the origin's routes and stop it recording requests.
pub fn setup_origin(origin: &TestOrigin) {
    origin.set_recording(false);
    origin.route("/small", MockResponse::ok(vec![b'x'; SMALL_LEN]));
    origin.route("/ads/banner.gif", MockResponse::ok(vec![b'x'; SMALL_LEN]));
    origin.route("/medium", MockResponse::ok(vec![b'y'; MEDIUM_LEN]));
    let mut page = String::from(
        "<!DOCTYPE html><html><head><title>page</title></head><body><div class=\"ad-banner\">ad</div>",
    );
    while page.len() < 6000 {
        page.push_str("<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>");
    }
    page.push_str("</body></html>");
    origin.route("/page.html", MockResponse::html(page));
}

#[derive(Clone, Copy)]
pub struct Sample {
    /// Scheduled (open loop) or actual (closed loop) send time since the phase start.
    pub t_ns: u64,
    pub lat_ns: u64,
    pub class: u8,
}

enum Outcome {
    Ok,
    Rejected,
    Err(String),
}

#[derive(Default)]
struct Sink {
    samples: Mutex<Vec<Sample>>,
    errors: Mutex<BTreeMap<String, u64>>,
    ok: AtomicU64,
    rejected: AtomicU64,
    dropped: AtomicU64,
}

/// What a phase saw.
pub struct PhaseOut {
    pub samples: Vec<Sample>,
    pub ok: u64,
    pub rejected: u64,
    pub dropped: u64,
    pub errors: BTreeMap<String, u64>,
    pub wall: Duration,
}

impl PhaseOut {
    pub fn failed(&self) -> bool {
        self.rejected > 0 || self.dropped > 0 || !self.errors.is_empty()
    }
    pub fn error_total(&self) -> u64 {
        self.errors.values().sum()
    }
}

/// Settings of one phase.
#[derive(Clone)]
pub struct PhaseCfg {
    pub proto: Proto,
    pub model: Model,
    pub duration: Duration,
    pub workload: Workload,
    pub port: u16,
    /// The target is the filtering proxy (responses are checked for blocking/rewriting).
    pub proxied: bool,
}

async fn fire(client: &TestClient, cfg: &PhaseCfg, class: Class, host: usize) -> Outcome {
    let url = format!(
        "https://{}:{}{}",
        class.host(host, &cfg.workload.suffix),
        cfg.port,
        class.path()
    );
    let mut rb = client
        .request(reqwest::Method::GET, &url)
        .header("user-agent", "Mozilla/5.0 loadgen")
        .header("accept-language", "en");
    rb = if class == Class::Html {
        rb.header("sec-fetch-dest", "document")
            .header("sec-fetch-mode", "navigate")
            .header("accept", "text/html")
    } else {
        rb.header("accept", "*/*")
    };
    let resp = match rb.send().await {
        Ok(r) => r,
        Err(e) => return Outcome::Err(err_kind(&e)),
    };
    let status = resp.status();
    let want = match cfg.proto {
        Proto::H1 => reqwest::Version::HTTP_11,
        Proto::H2 => reqwest::Version::HTTP_2,
    };
    if resp.version() != want {
        return Outcome::Err(format!("version {:?}", resp.version()));
    }
    let blocked = resp
        .headers()
        .get("x-adblock")
        .is_some_and(|v| v == "blocked");
    let body = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => return Outcome::Err(format!("body: {}", err_kind(&e))),
    };
    if cfg.proxied && matches!(status.as_u16(), 429 | 503) {
        return Outcome::Rejected;
    }
    let good = match (class, cfg.proxied) {
        (Class::Blocked, true) => blocked,
        (Class::Html, true) => {
            status == 200
                && body
                    .windows(22)
                    .any(|w| w == &b"display:none!important"[..])
        }
        (Class::Medium, _) => status == 200 && body.len() == MEDIUM_LEN,
        (Class::Html, false) => status == 200 && !body.is_empty(),
        _ => status == 200 && body.len() == SMALL_LEN,
    };
    if good {
        Outcome::Ok
    } else {
        Outcome::Err(format!(
            "unexpected {} {} ({} B)",
            class.name(),
            status,
            body.len()
        ))
    }
}

fn err_kind(e: &reqwest::Error) -> String {
    let mut s = String::new();
    if e.is_timeout() {
        s += "timeout ";
    }
    if e.is_connect() {
        s += "connect ";
    }
    let mut src: Option<&dyn std::error::Error> = Some(e);
    let mut last = String::new();
    while let Some(x) = src {
        last = x.to_string();
        src = x.source();
    }
    s + &last.chars().take(80).collect::<String>()
}

async fn one(
    client: &TestClient,
    cfg: &PhaseCfg,
    sink: &Sink,
    i: u64,
    t0: Instant,
    sched: Option<Instant>,
) {
    let (class, host) = cfg.workload.nth(i);
    let start = sched.unwrap_or_else(Instant::now);
    let out = fire(client, cfg, class, host).await;
    let lat = start.elapsed();
    match out {
        Outcome::Ok => {
            sink.ok.fetch_add(1, Ordering::Relaxed);
            sink.samples.lock().push(Sample {
                t_ns: start.saturating_duration_since(t0).as_nanos() as u64,
                lat_ns: lat.as_nanos() as u64,
                class: class as u8,
            });
        }
        Outcome::Rejected => {
            sink.rejected.fetch_add(1, Ordering::Relaxed);
        }
        Outcome::Err(e) => {
            *sink.errors.lock().entry(e).or_default() += 1;
        }
    }
}

/// Run one phase starting at `t0` (sample times are relative to it).
pub async fn run_phase(client: Arc<TestClient>, cfg: &PhaseCfg, t0: Instant) -> PhaseOut {
    let sink = Arc::new(Sink::default());
    let cfg = Arc::new(cfg.clone());
    let stop = t0 + cfg.duration;
    let counter = Arc::new(AtomicU64::new(0));
    match cfg.model {
        Model::Closed { conns } => {
            let mut tasks = Vec::new();
            for _ in 0..conns {
                let (client, cfg, sink, counter) =
                    (client.clone(), cfg.clone(), sink.clone(), counter.clone());
                tasks.push(tokio::spawn(async move {
                    while Instant::now() < stop {
                        let i = counter.fetch_add(1, Ordering::Relaxed);
                        one(&client, &cfg, &sink, i, t0, None).await;
                    }
                }));
            }
            for t in tasks {
                let _ = t.await;
            }
        }
        Model::Open { rate, max_inflight } => {
            let total = (rate as f64 * cfg.duration.as_secs_f64()) as u64;
            let gap = 1e9 / rate as f64;
            let inflight = Arc::new(AtomicUsize::new(0));
            // Dispatch from a plain thread: tokio timers tick at 1 ms, which would delay sends
            // by up to a millisecond and show up as latency. Sleep coarsely, spin the last bit.
            let handle = tokio::runtime::Handle::current();
            let (c2, g2, s2, i2) = (client.clone(), cfg.clone(), sink.clone(), inflight.clone());
            let _ = tokio::task::spawn_blocking(move || {
                for i in 0..total {
                    let sched = t0 + Duration::from_nanos((i as f64 * gap) as u64);
                    let wait = sched.saturating_duration_since(Instant::now());
                    if wait > Duration::from_micros(300) {
                        std::thread::sleep(wait - Duration::from_micros(200));
                    }
                    while Instant::now() < sched {
                        std::hint::spin_loop();
                    }
                    if i2.load(Ordering::Relaxed) >= max_inflight {
                        s2.dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    i2.fetch_add(1, Ordering::Relaxed);
                    let (client, cfg, sink, inflight) =
                        (c2.clone(), g2.clone(), s2.clone(), i2.clone());
                    handle.spawn(async move {
                        one(&client, &cfg, &sink, i, t0, Some(sched)).await;
                        inflight.fetch_sub(1, Ordering::Relaxed);
                    });
                }
            })
            .await;
            drain(&inflight, DRAIN, &sink).await;
        }
    }
    collect(&sink, t0.elapsed())
}

/// How long a phase waits for outstanding requests after the last one was sent.
pub const DRAIN: Duration = Duration::from_secs(35);

/// Error key under which requests still outstanding when the drain gave up are counted.
pub const UNFINISHED: &str = "request still in flight when the drain gave up";

/// Wait up to `wait` for `inflight` to reach zero; whatever is still outstanding is a failure
/// (those requests neither succeeded nor were measured), never silently nothing.
async fn drain(inflight: &AtomicUsize, wait: Duration, sink: &Sink) {
    let deadline = Instant::now() + wait;
    while inflight.load(Ordering::Relaxed) > 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let left = inflight.load(Ordering::Relaxed) as u64;
    if left > 0 {
        *sink
            .errors
            .lock()
            .entry(UNFINISHED.to_string())
            .or_default() += left;
    }
}

fn collect(sink: &Sink, wall: Duration) -> PhaseOut {
    PhaseOut {
        samples: std::mem::take(&mut *sink.samples.lock()),
        ok: sink.ok.load(Ordering::Relaxed),
        rejected: sink.rejected.load(Ordering::Relaxed),
        dropped: sink.dropped.load(Ordering::Relaxed),
        errors: sink.errors.lock().clone(),
        wall,
    }
}

/// Drive the direct and the proxied path in the same run: open loop, and on every scheduled tick
/// the same request (same class and host) goes out on both paths, in alternating order, timed
/// from the same scheduled instant. Both see the same host load and the same stalls, so the
/// per-percentile difference between them is the proxy's cost, not drift between runs. Needs
/// `Model::Open`; the rate is per path.
pub async fn run_paired(
    direct: (Arc<TestClient>, &PhaseCfg),
    proxy: (Arc<TestClient>, &PhaseCfg),
    t0: Instant,
) -> (PhaseOut, PhaseOut) {
    let Model::Open { rate, max_inflight } = proxy.1.model else {
        panic!("paired runs need the open-loop model");
    };
    let (dsink, psink) = (Arc::new(Sink::default()), Arc::new(Sink::default()));
    let (dcfg, pcfg) = (Arc::new(direct.1.clone()), Arc::new(proxy.1.clone()));
    let total = (rate as f64 * pcfg.duration.as_secs_f64()) as u64;
    let gap = 1e9 / rate as f64;
    let inflight = Arc::new(AtomicUsize::new(0));
    let handle = tokio::runtime::Handle::current();
    let (dc, pc) = (direct.0, proxy.0);
    let (ds, ps, inf) = (dsink.clone(), psink.clone(), inflight.clone());
    let _ = tokio::task::spawn_blocking(move || {
        for i in 0..total {
            let sched = t0 + Duration::from_nanos((i as f64 * gap) as u64);
            let wait = sched.saturating_duration_since(Instant::now());
            if wait > Duration::from_micros(300) {
                std::thread::sleep(wait - Duration::from_micros(200));
            }
            while Instant::now() < sched {
                std::hint::spin_loop();
            }
            // `max_inflight` is per path; a pair is two requests.
            if inf.load(Ordering::Relaxed) + 2 > 2 * max_inflight {
                ds.dropped.fetch_add(1, Ordering::Relaxed);
                ps.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            inf.fetch_add(2, Ordering::Relaxed);
            let spawn_direct = |handle: &tokio::runtime::Handle| {
                let (c, g, s, f) = (dc.clone(), dcfg.clone(), ds.clone(), inf.clone());
                handle.spawn(async move {
                    one(&c, &g, &s, i, t0, Some(sched)).await;
                    f.fetch_sub(1, Ordering::Relaxed);
                });
            };
            let spawn_proxy = |handle: &tokio::runtime::Handle| {
                let (c, g, s, f) = (pc.clone(), pcfg.clone(), ps.clone(), inf.clone());
                handle.spawn(async move {
                    one(&c, &g, &s, i, t0, Some(sched)).await;
                    f.fetch_sub(1, Ordering::Relaxed);
                });
            };
            // Alternate who goes first so neither path owns the head of every pair.
            if i % 2 == 0 {
                spawn_direct(&handle);
                spawn_proxy(&handle);
            } else {
                spawn_proxy(&handle);
                spawn_direct(&handle);
            }
        }
    })
    .await;
    // Unfinished requests are charged to both paths' failure counts (we cannot tell which).
    drain(&inflight, DRAIN, &psink).await;
    let left = psink.errors.lock().get(UNFINISHED).copied();
    if let Some(n) = left {
        dsink.errors.lock().insert(UNFINISHED.to_string(), n);
    }
    let wall = t0.elapsed();
    (collect(&dsink, wall), collect(&psink, wall))
}

/// Touch every (class, host) once and fill the pools, then run the model for `warm` and drop
/// the results: certificates are generated and connections open before measurement starts.
pub async fn warm_up(client: Arc<TestClient>, cfg: &PhaseCfg, warm: Duration) -> PhaseOut {
    let sweep = PhaseCfg {
        model: Model::Closed {
            conns: (cfg.workload.hosts * CLASSES.len()).max(8),
        },
        duration: Duration::from_millis(1),
        ..cfg.clone()
    };
    let mut first = run_phase(client.clone(), &sweep, Instant::now()).await;
    // The 1 ms sweep may not reach every host; walk them explicitly too.
    for c in CLASSES {
        for h in 0..cfg.workload.hosts {
            if let Outcome::Err(e) = fire(&client, cfg, c, h).await {
                *first.errors.entry(e).or_default() += 1;
            }
        }
    }
    let mut wcfg = cfg.clone();
    wcfg.duration = warm;
    let o = run_phase(client, &wcfg, Instant::now()).await;
    for (k, v) in o.errors {
        *first.errors.entry(k).or_default() += v;
    }
    first.rejected += o.rejected;
    first.dropped += o.dropped;
    first
}

/// Latency summary in milliseconds.
#[derive(Clone, Copy, Debug, Default)]
pub struct Lat {
    pub count: u64,
    pub min: f64,
    pub mean: f64,
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub p999: f64,
    pub max: f64,
}

impl Lat {
    pub fn of<'a>(samples: impl Iterator<Item = &'a Sample>) -> Lat {
        let mut h = Histogram::<u64>::new_with_bounds(1, 600_000_000, 3).expect("histogram");
        for s in samples {
            let _ = h.record((s.lat_ns / 1000).max(1));
        }
        if h.is_empty() {
            return Lat::default();
        }
        let ms = |v: u64| v as f64 / 1000.0;
        Lat {
            count: h.len(),
            min: ms(h.min()),
            mean: h.mean() / 1000.0,
            p50: ms(h.value_at_quantile(0.5)),
            p90: ms(h.value_at_quantile(0.9)),
            p99: ms(h.value_at_quantile(0.99)),
            p999: ms(h.value_at_quantile(0.999)),
            max: ms(h.max()),
        }
    }

    pub fn json(&self) -> Value {
        json!({"count": self.count, "min_ms": r3(self.min), "mean_ms": r3(self.mean),
            "p50_ms": r3(self.p50), "p90_ms": r3(self.p90), "p99_ms": r3(self.p99),
            "p99_9_ms": r3(self.p999), "max_ms": r3(self.max)})
    }

    /// `self - base` per percentile.
    pub fn delta_json(&self, base: &Lat) -> Value {
        json!({"p50_ms": r3(self.p50 - base.p50), "p90_ms": r3(self.p90 - base.p90),
            "p99_ms": r3(self.p99 - base.p99), "p99_9_ms": r3(self.p999 - base.p999),
            "max_ms": r3(self.max - base.max)})
    }
}

fn r3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

type Spans = Vec<(f64, f64)>;

/// One reload during a measurement, seconds since the measurement started.
#[derive(Clone, Copy, Debug)]
pub struct ReloadEvent {
    pub start_s: f64,
    pub installed_s: f64,
}

/// The list rebuilt and swapped in every `interval` during the measurement.
#[derive(Clone)]
pub struct ReloadCfg {
    /// The real list service over `engine`; each reload stores the next list as the custom
    /// rules and runs `reload_now`, so parse, compile and install go through the service's build
    /// pool exactly as a rebuild in the running process does.
    pub service: Arc<list_service::ListService>,
    /// Lists to alternate between.
    pub lists: Vec<Arc<String>>,
    pub interval: Duration,
    /// Runtime the service runs on (the proxy's, as in the real process).
    pub builder: tokio::runtime::Handle,
    /// Keeps the service's data directory alive for the run.
    pub dir: Arc<tempfile::TempDir>,
}

async fn reload_loop(cfg: ReloadCfg, t0: Instant, duration: Duration) -> Vec<ReloadEvent> {
    let mut events = Vec::new();
    let mut k = 0usize;
    loop {
        let at = t0 + cfg.interval * (k as u32 + 1);
        if at + Duration::from_secs(2) > t0 + duration {
            break;
        }
        tokio::time::sleep_until(at.into()).await;
        let text = cfg.lists[k % cfg.lists.len()].clone();
        let service = cfg.service.clone();
        let start = Instant::now();
        let _ = cfg
            .builder
            .spawn(async move {
                service
                    .store()
                    .set_custom_rules(&text)
                    .expect("store custom rules");
                service.reload_now().await;
            })
            .await;
        events.push(ReloadEvent {
            start_s: start.saturating_duration_since(t0).as_secs_f64(),
            installed_s: t0.elapsed().as_secs_f64(),
        });
        k += 1;
    }
    events
}

/// Everything measured for one (protocol, path).
pub struct Measured {
    pub proto: Proto,
    pub path: &'static str,
    pub cfg: PhaseCfg,
    pub warm: PhaseOut,
    pub out: PhaseOut,
    pub reloads: Vec<ReloadEvent>,
    /// Measured in a paired run (see [`run_paired`]) alongside the other path.
    pub paired: bool,
}

impl Measured {
    pub fn failed(&self) -> bool {
        self.out.failed() || self.warm.failed()
    }

    pub fn lat(&self) -> Lat {
        Lat::of(self.out.samples.iter())
    }

    pub fn class_lat(&self, c: Class) -> Lat {
        Lat::of(self.out.samples.iter().filter(|s| s.class == c as u8))
    }

    fn windows(&self) -> (Spans, Spans) {
        let around = self
            .reloads
            .iter()
            .map(|e| (e.start_s, e.installed_s + 1.0))
            .collect();
        let swap = self
            .reloads
            .iter()
            .map(|e| (e.installed_s - 0.5, e.installed_s + 0.5))
            .collect();
        (around, swap)
    }

    pub fn json(&self) -> Value {
        let lat = self.lat();
        let mut by_class = serde_json::Map::new();
        for c in CLASSES {
            let l = self.class_lat(c);
            if l.count > 0 {
                by_class.insert(c.name().into(), l.json());
            }
        }
        let mut v = json!({
            "proto": self.proto.name(), "path": self.path,
            "requests_ok": self.out.ok, "errors": self.out.error_total(),
            "error_kinds": self.out.errors, "rejected": self.out.rejected,
            "dropped": self.out.dropped,
            "warmup_errors": self.warm.error_total() + self.warm.rejected + self.warm.dropped,
            "throughput_rps": r3(self.out.ok as f64 / self.cfg.duration.as_secs_f64()),
            "latency": lat.json(), "by_class": by_class,
        });
        if !self.reloads.is_empty() {
            let (around, swap) = self.windows();
            let inside = |ws: &[(f64, f64)], s: &Sample| {
                let t = s.t_ns as f64 / 1e9;
                ws.iter().any(|(a, b)| t >= *a && t <= *b)
            };
            let around_l = Lat::of(self.out.samples.iter().filter(|s| inside(&around, s)));
            let swap_l = Lat::of(self.out.samples.iter().filter(|s| inside(&swap, s)));
            let steady = Lat::of(self.out.samples.iter().filter(|s| !inside(&around, s)));
            v["reload"] = json!({
                "events": self.reloads.iter().map(|e| json!({
                    "start_s": r3(e.start_s), "installed_s": r3(e.installed_s),
                    "build_ms": r3((e.installed_s - e.start_s) * 1000.0)})).collect::<Vec<_>>(),
                "window": "around = [build start, install + 1 s]; swap = install -/+ 0.5 s; steady = outside around",
                "steady": steady.json(), "around": around_l.json(), "swap": swap_l.json(),
            });
        }
        v
    }
}

/// Warm up, then measure one (protocol, path) with an optional list reload scenario.
pub async fn measure(
    client: Arc<TestClient>,
    path: &'static str,
    cfg: PhaseCfg,
    warm: Duration,
    reload: Option<ReloadCfg>,
) -> Measured {
    let warm_out = warm_up(client.clone(), &cfg, warm).await;
    // Let post-warm-up garbage (closed connections, timers) settle.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let t0 = Instant::now();
    let ctl = reload.map(|r| tokio::spawn(reload_loop(r, t0, cfg.duration)));
    let out = run_phase(client, &cfg, t0).await;
    let reloads = match ctl {
        Some(h) => h.await.unwrap_or_default(),
        None => Vec::new(),
    };
    Measured {
        proto: cfg.proto,
        path,
        cfg,
        warm: warm_out,
        out,
        reloads,
        paired: false,
    }
}

/// Warm both paths up, then measure direct and proxy in one paired open-loop run (see
/// [`run_paired`]) with the optional reload scenario acting on the proxy. Returns
/// `(direct, proxy)`.
pub async fn measure_paired(
    direct: (Arc<TestClient>, PhaseCfg),
    proxy: (Arc<TestClient>, PhaseCfg),
    warm: Duration,
    reload: Option<ReloadCfg>,
) -> (Measured, Measured) {
    let dwarm = warm_up(direct.0.clone(), &direct.1, warm).await;
    let pwarm = warm_up(proxy.0.clone(), &proxy.1, warm).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let t0 = Instant::now();
    let duration = proxy.1.duration;
    let ctl = reload.map(|r| tokio::spawn(reload_loop(r, t0, duration)));
    let (dout, pout) = run_paired((direct.0, &direct.1), (proxy.0, &proxy.1), t0).await;
    let reloads = match ctl {
        Some(h) => h.await.unwrap_or_default(),
        None => Vec::new(),
    };
    let mk = |path, cfg: PhaseCfg, warm, out, reloads| Measured {
        proto: cfg.proto,
        path,
        cfg,
        warm,
        out,
        reloads,
        paired: true,
    };
    (
        mk("direct", direct.1, dwarm, dout, Vec::new()),
        mk("proxy", proxy.1, pwarm, pout, reloads),
    )
}

/// Pin the calling thread to `cpus` (Linux only; a no-op elsewhere).
pub fn pin_current_thread(cpus: &[usize]) {
    #[cfg(target_os = "linux")]
    // SAFETY: `set` is a zeroed `cpu_set_t` filled via the libc macros; pid 0 is this thread.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        for c in cpus {
            libc::CPU_SET(*c, &mut set);
        }
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cpus;
}

/// A multi-thread runtime of `threads` workers whose threads (blocking pool included) are
/// pinned to `cpus` (empty: unpinned).
pub fn runtime(name: &str, threads: usize, cpus: Vec<usize>) -> tokio::runtime::Runtime {
    let mut b = tokio::runtime::Builder::new_multi_thread();
    b.worker_threads(threads).thread_name(name).enable_all();
    if !cpus.is_empty() {
        b.on_thread_start(move || pin_current_thread(&cpus));
    }
    b.build().expect("runtime")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn requests_still_in_flight_when_the_drain_gives_up_are_failures() {
        let sink = Sink::default();
        let inflight = AtomicUsize::new(3);
        drain(&inflight, Duration::from_millis(30), &sink).await;
        let out = collect(&sink, Duration::ZERO);
        assert_eq!(out.errors.get(UNFINISHED), Some(&3));
        assert!(out.failed());
        // Nothing outstanding: nothing counted.
        let sink = Sink::default();
        drain(&AtomicUsize::new(0), Duration::from_millis(30), &sink).await;
        assert!(!collect(&sink, Duration::ZERO).failed());
    }
}

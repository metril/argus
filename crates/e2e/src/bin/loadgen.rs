//! Load generator: latency of the MITM proxy versus a direct connection, steady and during list
//! reloads. Run with `cargo run --release -p e2e --bin loadgen -- --help`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use e2e::loadgen::{
    generate_list, measure, pin_current_thread, runtime, setup_origin, Measured, Model, PhaseCfg,
    Proto, ReloadCfg, Workload, CLASSES,
};
use e2e::{EntryMode, TestClient, TestOrigin, TestProxy};
use serde_json::{json, Value};

const HELP: &str = "loadgen: proxy latency load generator

  --proto h1,h2            protocols (default h1,h2)
  --paths direct,proxy     paths (default direct,proxy)
  --mode explicit|transparent   in-process proxy entry mode (default explicit)
  --model closed|open      load model (default closed)
  --conns N                closed loop: connections (h1) / concurrent streams (h2) (default 16)
  --rate R                 open loop: requests per second (default 2000)
  --max-inflight N         open loop: outstanding cap, beyond it requests count as dropped (512)
  --duration S             measured seconds (default 10)
  --warmup S               warm-up seconds, excluded (default 3)
  --mix small=60,medium=10,blocked=20,html=10   request weights
  --hosts N                hostnames per class (default 2)
  --rules N                generated filter list size (default 50000)
  --lists F1,F2            real list files instead of a generated list
  --scenario steady|reload reload swaps a rebuilt list in during the run (proxy path only)
  --reload-rules N         size of the reloaded list (default 100000)
  --reload-interval S      seconds between reloads (default 5)
  --repeat N               full repetitions (default 1)
  --seed N                 request sequence seed
  --proxy-addr H:P --ca F  drive an external proxy (explicit mode) trusting its CA file
  --origin-ca-dir D        keep the origin CA in D (origin-ca.crt/.key) so an external proxy can
                           trust it across runs
  --host-suffix S          hostname suffix (default test; use localhost for an external proxy
                           that resolves names itself)
  --no-pin                 do not pin runtimes to CPUs
  --json                   one JSON object on stdout instead of a table";

struct Args {
    protos: Vec<Proto>,
    paths: Vec<&'static str>,
    mode: EntryMode,
    model: Model,
    duration: u64,
    warmup: u64,
    mix: [u32; 4],
    hosts: usize,
    rules: usize,
    lists: Vec<String>,
    reload: bool,
    reload_rules: usize,
    reload_interval: u64,
    repeat: usize,
    seed: u64,
    proxy_addr: Option<String>,
    ca: Option<String>,
    origin_ca_dir: Option<String>,
    suffix: Option<String>,
    pin: bool,
    json: bool,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        protos: vec![Proto::H1, Proto::H2],
        paths: vec!["direct", "proxy"],
        mode: EntryMode::Explicit,
        model: Model::Closed { conns: 16 },
        duration: 10,
        warmup: 3,
        mix: [60, 10, 20, 10],
        hosts: 2,
        rules: 50_000,
        lists: vec![],
        reload: false,
        reload_rules: 100_000,
        reload_interval: 5,
        repeat: 1,
        seed: 1,
        proxy_addr: None,
        ca: None,
        origin_ca_dir: None,
        suffix: None,
        pin: true,
        json: false,
    };
    let (mut open, mut conns, mut rate, mut inflight) = (false, 16usize, 2000u32, 512usize);
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut val = || it.next().ok_or(format!("{k} needs a value"));
        let num = |s: String| s.parse::<u64>().map_err(|_| format!("bad number {s}"));
        match k.as_str() {
            "--help" | "-h" => return Err(HELP.into()),
            "--json" => a.json = true,
            "--no-pin" => a.pin = false,
            "--proto" => {
                a.protos = val()?
                    .split(',')
                    .map(|p| match p {
                        "h1" => Ok(Proto::H1),
                        "h2" => Ok(Proto::H2),
                        _ => Err(format!("bad proto {p}")),
                    })
                    .collect::<Result<_, _>>()?
            }
            "--paths" => {
                a.paths = val()?
                    .split(',')
                    .map(|p| match p {
                        "direct" => Ok("direct"),
                        "proxy" => Ok("proxy"),
                        _ => Err(format!("bad path {p}")),
                    })
                    .collect::<Result<_, _>>()?
            }
            "--mode" => {
                a.mode = match val()?.as_str() {
                    "explicit" => EntryMode::Explicit,
                    "transparent" => EntryMode::Transparent,
                    m => return Err(format!("bad mode {m}")),
                }
            }
            "--model" => {
                open = match val()?.as_str() {
                    "closed" => false,
                    "open" => true,
                    m => return Err(format!("bad model {m}")),
                }
            }
            "--conns" => conns = num(val()?)? as usize,
            "--rate" => rate = num(val()?)? as u32,
            "--max-inflight" => inflight = num(val()?)? as usize,
            "--duration" => a.duration = num(val()?)?,
            "--warmup" => a.warmup = num(val()?)?,
            "--mix" => a.mix = Workload::parse_mix(&val()?)?,
            "--hosts" => a.hosts = num(val()?)? as usize,
            "--rules" => a.rules = num(val()?)? as usize,
            "--lists" => a.lists = val()?.split(',').map(String::from).collect(),
            "--scenario" => {
                a.reload = match val()?.as_str() {
                    "steady" => false,
                    "reload" => true,
                    s => return Err(format!("bad scenario {s}")),
                }
            }
            "--reload-rules" => a.reload_rules = num(val()?)? as usize,
            "--reload-interval" => a.reload_interval = num(val()?)?,
            "--repeat" => a.repeat = num(val()?)? as usize,
            "--seed" => a.seed = num(val()?)?,
            "--proxy-addr" => a.proxy_addr = Some(val()?),
            "--ca" => a.ca = Some(val()?),
            "--origin-ca-dir" => a.origin_ca_dir = Some(val()?),
            "--host-suffix" => a.suffix = Some(val()?),
            _ => return Err(format!("unknown option {k}\n\n{HELP}")),
        }
    }
    a.model = if open {
        Model::Open {
            rate,
            max_inflight: inflight,
        }
    } else {
        Model::Closed { conns }
    };
    if a.proxy_addr.is_some() != a.ca.is_some() {
        return Err("--proxy-addr and --ca go together".into());
    }
    if a.proxy_addr.is_some() && (a.reload || a.mode == EntryMode::Transparent) {
        return Err("external proxy: explicit mode, no reload scenario".into());
    }
    if a.reload {
        a.paths = vec!["proxy"];
    }
    Ok(a)
}

fn main() {
    let args = match parse() {
        Ok(a) => a,
        Err(m) => {
            eprintln!("{m}");
            std::process::exit(2);
        }
    };
    std::process::exit(run(args));
}

fn run(a: Args) -> i32 {
    let n = std::thread::available_parallelism().map_or(1, |n| n.get());
    let (lg, og, px) = if !a.pin || n < 4 {
        (vec![], vec![], vec![])
    } else {
        // Whole physical cores per role (SMT siblings together) so roles do not share a core.
        let groups = core_groups(n);
        if groups.len() >= 4 {
            (groups[0].clone(), groups[1].clone(), groups[2..].concat())
        } else {
            (vec![0], vec![1], (2..n).collect::<Vec<_>>())
        }
    };
    let threads = |c: &Vec<usize>| if c.is_empty() { 2 } else { c.len() };
    eprintln!("cpus: loadgen {lg:?} origin {og:?} proxy {px:?} (empty = unpinned)");
    pin_current_thread(&lg);
    let load_rt = runtime("loadgen", threads(&lg), lg.clone());
    let origin_rt = runtime("origin", threads(&og), og.clone());
    let proxy_rt = runtime("proxy", threads(&px).max(2), px.clone());

    let suffix = a.suffix.clone().unwrap_or_else(|| {
        if a.proxy_addr.is_some() {
            "localhost"
        } else {
            "test"
        }
        .into()
    });
    let workload = Workload {
        weights: a.mix,
        hosts: a.hosts,
        seed: a.seed,
        suffix,
    };

    // Origin (own runtime).
    let ca_files = a.origin_ca_dir.as_ref().map(|d| {
        (
            std::path::Path::new(d).join("origin-ca.crt"),
            std::path::Path::new(d).join("origin-ca.key"),
        )
    });
    let saved = ca_files.as_ref().and_then(|(c, k)| {
        Some((
            std::fs::read_to_string(c).ok()?,
            std::fs::read_to_string(k).ok()?,
        ))
    });
    let origin = origin_rt.block_on(TestOrigin::start_with_ca(
        saved.as_ref().map(|(c, k)| (c.as_str(), k.as_str())),
    ));
    if let (Some((c, k)), None) = (&ca_files, &saved) {
        let _ = std::fs::create_dir_all(c.parent().unwrap());
        std::fs::write(c, origin.ca_pem()).expect("write origin ca");
        std::fs::write(k, origin.ca_key_pem()).expect("write origin key");
    }
    setup_origin(&origin);

    // Filter list.
    let list_text = if a.lists.is_empty() {
        generate_list(a.rules, 1, &workload)
    } else {
        let mut t = workload.required_rules();
        for f in &a.lists {
            t += &std::fs::read_to_string(f).unwrap_or_else(|e| panic!("{f}: {e}"));
            t.push('\n');
        }
        t
    };

    // Proxy (own runtime), or an external one.
    let want_proxy = a.paths.contains(&"proxy");
    let inproc = if want_proxy && a.proxy_addr.is_none() {
        let p = proxy_rt
            .block_on(TestProxy::start_tweaked(a.mode, &origin, &[], &|c| {
                c.performance.max_connections = 10_000;
                c.performance.connection_rate_limit = Some(1_000_000);
            }))
            .expect("start proxy");
        let t = Instant::now();
        e2e::install_rules_text(&p.engine, list_text.clone(), true);
        eprintln!(
            "initial list: {} lines compiled in {} ms",
            list_text.lines().count(),
            t.elapsed().as_millis()
        );
        Some(p)
    } else {
        None
    };
    let ext_ca = a.ca.as_ref().map(|f| std::fs::read(f).expect("read --ca"));

    let reload = match (&inproc, a.reload) {
        (Some(p), true) => Some(ReloadCfg {
            engine: p.engine.clone(),
            lists: [11u64, 12]
                .iter()
                .map(|s| Arc::new(generate_list(a.reload_rules, *s, &workload)))
                .collect(),
            interval: Duration::from_secs(a.reload_interval),
            builder: proxy_rt.handle().clone(),
        }),
        _ => None,
    };

    let mut runs: Vec<Value> = Vec::new();
    let mut failed = false;
    for run in 0..a.repeat {
        let mut results: Vec<Measured> = Vec::new();
        for proto in &a.protos {
            for path in &a.paths {
                eprintln!("run {} {} {path} ...", run + 1, proto.name());
                let client = Arc::new(match (*path, &inproc) {
                    ("direct", _) => TestClient::direct(&origin, proto.version()),
                    (_, Some(p)) => TestClient::new(p, proto.version()),
                    (_, None) => TestClient::explicit(
                        &format!("http://{}", a.proxy_addr.as_ref().unwrap()),
                        ext_ca.as_ref().unwrap(),
                        proto.version(),
                    ),
                });
                let cfg = PhaseCfg {
                    proto: *proto,
                    model: a.model,
                    duration: Duration::from_secs(a.duration),
                    workload: workload.clone(),
                    port: origin.https_port(),
                    proxied: *path == "proxy",
                };
                let m = load_rt.block_on(measure(
                    client,
                    path,
                    cfg,
                    Duration::from_secs(a.warmup),
                    if *path == "proxy" {
                        reload.clone()
                    } else {
                        None
                    },
                ));
                if m.failed() {
                    failed = true;
                    eprintln!(
                        "  FAILED: errors {:?} rejected {} dropped {} warmup {:?}",
                        m.out.errors, m.out.rejected, m.out.dropped, m.warm.errors
                    );
                }
                results.push(m);
            }
        }
        runs.push(run_json(run, &results));
    }

    let config = json!({
        "protos": a.protos.iter().map(|p| p.name()).collect::<Vec<_>>(),
        "paths": a.paths,
        "mode": format!("{:?}", a.mode).to_lowercase(),
        "model": match a.model {
            Model::Closed { conns } => json!({"kind": "closed", "conns": conns}),
            Model::Open { rate, max_inflight } =>
                json!({"kind": "open", "rate": rate, "max_inflight": max_inflight}),
        },
        "duration_s": a.duration, "warmup_s": a.warmup, "repeat": a.repeat,
        "mix": CLASSES.iter().map(|c| (c.name(), a.mix[*c as usize])).collect::<std::collections::BTreeMap<_, _>>(),
        "hosts_per_class": a.hosts, "list_lines": list_text.lines().count(),
        "lists": a.lists, "reload": a.reload.then(|| json!({
            "rules": a.reload_rules, "interval_s": a.reload_interval})),
        "external_proxy": a.proxy_addr, "seed": a.seed,
        "cpus": {"loadgen": lg, "origin": og, "proxy": px},
        "cores": n,
    });
    let out = json!({"config": config, "runs": runs, "repeatability": repeatability(&runs)});
    if a.json {
        println!("{}", serde_json::to_string(&out).unwrap());
    } else {
        print_table(&out);
    }

    drop(inproc);
    drop(origin);
    load_rt.shutdown_background();
    origin_rt.shutdown_background();
    proxy_rt.shutdown_background();
    i32::from(failed)
}

/// CPUs grouped by physical core (from sysfs; one group per CPU when unavailable).
fn core_groups(n: usize) -> Vec<Vec<usize>> {
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for c in 0..n {
        let f = format!("/sys/devices/system/cpu/cpu{c}/topology/thread_siblings_list");
        let mut g: Vec<usize> = std::fs::read_to_string(f)
            .map(|t| {
                t.trim()
                    .split(',')
                    .flat_map(|r| match r.split_once('-') {
                        Some((a, b)) => (a.parse().unwrap_or(c)..=b.parse().unwrap_or(c)).collect(),
                        None => vec![r.parse().unwrap_or(c)],
                    })
                    .collect()
            })
            .unwrap_or_else(|_| vec![c]);
        g.sort_unstable();
        if !groups.contains(&g) {
            groups.push(g);
        }
    }
    groups
}

fn run_json(run: usize, results: &[Measured]) -> Value {
    let mut deltas = Vec::new();
    for proto in [Proto::H1, Proto::H2] {
        let d = results
            .iter()
            .find(|m| m.proto == proto && m.path == "direct");
        let p = results
            .iter()
            .find(|m| m.proto == proto && m.path == "proxy");
        if let (Some(d), Some(p)) = (d, p) {
            let mut by_class = serde_json::Map::new();
            for c in CLASSES {
                if p.class_lat(c).count > 0 && d.class_lat(c).count > 0 {
                    by_class.insert(c.name().into(), p.class_lat(c).delta_json(&d.class_lat(c)));
                }
            }
            deltas.push(
                json!({"proto": proto.name(), "added_latency": p.lat().delta_json(&d.lat()),
                "added_latency_by_class": by_class,
                "note": "blocked: proxy answers locally; direct goes to the origin"}),
            );
        }
    }
    json!({"run": run + 1, "results": results.iter().map(|m| m.json()).collect::<Vec<_>>(),
        "deltas": deltas})
}

/// Spread of p99 across runs, per (proto, path): (max - min) / median.
fn repeatability(runs: &[Value]) -> Value {
    let mut out = serde_json::Map::new();
    if runs.len() < 2 {
        return Value::Object(out);
    }
    let mut keys: Vec<(String, String)> = Vec::new();
    for r in runs[0]["results"].as_array().unwrap() {
        keys.push((
            r["proto"].as_str().unwrap().into(),
            r["path"].as_str().unwrap().into(),
        ));
    }
    for (proto, path) in keys {
        let mut v: Vec<f64> = runs
            .iter()
            .flat_map(|r| r["results"].as_array().unwrap())
            .filter(|r| r["proto"] == proto.as_str() && r["path"] == path.as_str())
            .map(|r| r["latency"]["p99_ms"].as_f64().unwrap())
            .collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let med = v[v.len() / 2];
        out.insert(
            format!("{proto}/{path}"),
            json!({"p99_ms": v, "spread_pct": ((v[v.len() - 1] - v[0]) / med * 1000.0).round() / 10.0}),
        );
    }
    Value::Object(out)
}

fn print_table(o: &Value) {
    let f = |v: &Value| format!("{:8.3}", v.as_f64().unwrap_or(0.0));
    for r in o["runs"].as_array().unwrap() {
        println!("run {}", r["run"]);
        println!("  proto path    rps     ok  err  rej drop |   p50     p90     p99   p99.9     max (ms)");
        for m in r["results"].as_array().unwrap() {
            let l = &m["latency"];
            println!(
                "  {:5} {:6} {:7.0} {:6} {:4} {:4} {:4} |{}{}{}{}{}",
                m["proto"].as_str().unwrap(),
                m["path"].as_str().unwrap(),
                m["throughput_rps"].as_f64().unwrap(),
                m["requests_ok"],
                m["errors"],
                m["rejected"],
                m["dropped"],
                f(&l["p50_ms"]),
                f(&l["p90_ms"]),
                f(&l["p99_ms"]),
                f(&l["p99_9_ms"]),
                f(&l["max_ms"]),
            );
            if let Some(rl) = m.get("reload") {
                for w in ["steady", "around", "swap"] {
                    let l = &rl[w];
                    println!(
                        "    reload {w:7} n={:7} |{}{}{}{}{}",
                        l["count"],
                        f(&l["p50_ms"]),
                        f(&l["p90_ms"]),
                        f(&l["p99_ms"]),
                        f(&l["p99_9_ms"]),
                        f(&l["max_ms"])
                    );
                }
                let ev = rl["events"].as_array().unwrap();
                let b: Vec<String> = ev
                    .iter()
                    .map(|e| format!("{:.0}", e["build_ms"].as_f64().unwrap()))
                    .collect();
                println!("    reloads: {} (build ms: {})", ev.len(), b.join(", "));
            }
        }
        for d in r["deltas"].as_array().unwrap() {
            let a = &d["added_latency"];
            println!(
                "  added {:5}                          |{}{}{}{}{}",
                d["proto"].as_str().unwrap(),
                f(&a["p50_ms"]),
                f(&a["p90_ms"]),
                f(&a["p99_ms"]),
                f(&a["p99_9_ms"]),
                f(&a["max_ms"])
            );
        }
    }
    if let Some(m) = o["repeatability"].as_object() {
        for (k, v) in m {
            println!("p99 spread {k}: {}% {}", v["spread_pct"], v["p99_ms"]);
        }
    }
}

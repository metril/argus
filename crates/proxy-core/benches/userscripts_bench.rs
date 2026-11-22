//! Per-document and per-call cost of userscripts with 500 installed scripts.
//!
//! * `plan_document/*`: what the proxy adds to every HTML response (index probe; with matches
//!   also the per-document record and the script URLs).
//! * `bundle/*`: generating the served bundle(s) of a matching document.
//! * `gm/*`: the GM endpoints without HTTP or upstream I/O: token verification, authorisation,
//!   quotas and the storage operation.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hyper::{HeaderMap, Method};
use proxy_core::gm::{Caller, GmHost};
use serde_json::json;
use std::sync::Arc;
use userscript_engine::install::{finish_install, plan_install, Approvals, Fetched};
use userscript_engine::token::{self, TokenClaims};
use userscript_engine::{UserscriptManager, DEFAULT_PROFILE};

fn src(i: usize, host: &str, grants: &str) -> String {
    format!(
        "// ==UserScript==\n// @name s{i}\n// @namespace bench\n// @version 1.0\n// @match *://{host}/*\n{grants}\n// ==/UserScript==\nconsole.log({i});\n"
    )
}

fn setup() -> (Arc<UserscriptManager>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let m = Arc::new(UserscriptManager::new(dir.path().to_path_buf()).unwrap());
    for i in 0..500 {
        let host = format!("site{i}.test");
        let plan = plan_install(&src(i, &host, "// @grant none"), None).unwrap();
        let s = finish_install(plan, Fetched::default(), Approvals::default()).unwrap();
        m.install_script(DEFAULT_PROFILE, s).unwrap();
    }
    for i in 0..3 {
        let g = "// @grant GM_getValue\n// @grant GM_setValue\n// @grant GM_xmlhttpRequest\n// @connect api.test";
        let plan = plan_install(&src(1000 + i, "hit.test", g), None).unwrap();
        let s = finish_install(plan, Fetched::default(), Approvals::default()).unwrap();
        m.install_script(DEFAULT_PROFILE, s).unwrap();
    }
    (m, dir)
}

fn bench(c: &mut Criterion) {
    let (m, _dir) = setup();
    assert_eq!(m.live_index().len(), 503);
    let host = GmHost::new();
    let origin = "https://hit.test";

    c.bench_function("plan_document/0_matching_of_503", |b| {
        b.iter(|| {
            black_box(host.plan_document(
                &m,
                "miss.test",
                "https://miss.test/page?x=1",
                "https://miss.test",
                true,
            ))
        })
    });
    c.bench_function("plan_document/3_matching_of_503", |b| {
        b.iter(|| {
            black_box(host.plan_document(&m, "hit.test", "https://hit.test/page?x=1", origin, true))
        })
    });
    let caller = Caller {
        manager: &m,
        host: "hit.test",
        origin,
        profile: userscript_engine::DEFAULT_PROFILE,
    };
    c.bench_function("bundle/serve_3_scripts", |b| {
        b.iter(|| {
            let plan = host
                .plan_document(&m, "hit.test", "https://hit.test/", origin, true)
                .unwrap();
            for src in &plan.srcs {
                let rest = src.strip_prefix("/__adblock__/us/").unwrap();
                black_box(host.serve_chunk(&m, &caller, &Method::GET, &HeaderMap::new(), rest));
            }
        })
    });

    let script = m
        .live_index()
        .iter()
        .find(|s| s.script.metadata.grants.len() == 3)
        .unwrap()
        .script
        .clone();
    let caps = token::caps_hash(&script.metadata, script.allow_connect_all);
    let tok = token::mint(
        m.token_key(),
        &TokenClaims {
            profile: DEFAULT_PROFILE,
            script_id: &script.id,
            script_version: "1.0",
            origin,
            caps_hash: &caps,
            exp: u64::MAX / 2,
        },
    );
    let set = json!({"values": {"k": "v"}, "src": "t"}).to_string();
    let get = json!({"names": ["k"]}).to_string();
    c.bench_function("gm/values_set", |b| {
        b.iter(|| black_box(host.json_call(&m, &caller, "values/set", Some(&tok), set.as_bytes())))
    });
    c.bench_function("gm/values_get", |b| {
        b.iter(|| black_box(host.json_call(&m, &caller, "values/get", Some(&tok), get.as_bytes())))
    });
    c.bench_function("gm/token_refresh", |b| {
        b.iter(|| black_box(host.json_call(&m, &caller, "token/refresh", Some(&tok), b"{}")))
    });
    // The xhr request path before any I/O: framing parse + grant/@connect/header checks.
    let meta: userscript_engine::backend::XhrRequest = serde_json::from_value(json!({
        "op": "xhr", "method": "POST", "url": "https://api.test/x",
        "headers": [["Content-Type", "text/plain"], ["X-A", "b"]], "timeout": 1000
    }))
    .unwrap();
    c.bench_function("gm/xhr_build_outbound", |b| {
        b.iter(|| {
            let ctx = userscript_engine::backend::ScriptCtx {
                profile: DEFAULT_PROFILE,
                script: &script,
                page_host: "hit.test",
            };
            black_box(m.gm().build_outbound(&ctx, &meta, vec![0u8; 64]).unwrap())
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);

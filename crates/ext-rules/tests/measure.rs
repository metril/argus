//! Production-list measurement (ignored): `MEASURE_MANIFEST=<json> cargo nextest run -p ext-rules
//! --run-ignored only measure -- --nocapture`. The manifest is `[{id, path, trusted}]`.
use std::collections::BTreeMap;

use ext_rules::*;
use filter_engine::pipeline::{build_set, ListInput};

#[test]
#[ignore]
fn measure() {
    let Ok(path) = std::env::var("MEASURE_MANIFEST") else {
        return;
    };
    let man: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let inputs: Vec<ListInput> = man
        .iter()
        .map(|m| ListInput {
            id: m["id"].as_str().unwrap().into(),
            content: std::fs::read_to_string(m["path"].as_str().unwrap()).unwrap(),
            trusted: m["trusted"].as_bool().unwrap(),
            ..Default::default()
        })
        .collect();
    let built = build_set(&inputs);
    let mut ext = built.ext.clone();
    for r in &mut ext {
        r.trusted = inputs.iter().any(|i| i.id == r.list && i.trusted);
    }
    let idx = ExtIndex::build(&ext);
    let mut by_state: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_kind: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    for (i, r) in ext.iter().enumerate() {
        let st = idx.state_of(i).unwrap();
        *by_state.entry(st.as_str().into()).or_default() += 1;
        *by_kind
            .entry((r.kind.as_str().into(), st.as_str().into()))
            .or_default() += 1;
        if let Some(why) = st.reason() {
            let why = why.lines().next().unwrap_or("");
            let key = why;
            *reasons
                .entry(format!("{}: {key}", st.as_str()))
                .or_default() += 1;
        }
    }
    println!("TOTAL {}", ext.len());
    println!("BY_STATE {by_state:#?}");
    println!("BY_KIND {by_kind:#?}");
    let mut rs: Vec<_> = reasons.into_iter().collect();
    rs.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (k, n) in rs.iter().take(60) {
        println!("REASON {n:5} {k}");
    }
    let loc = ext
        .iter()
        .enumerate()
        .filter(|(_, r)| r.kind == ExtKind::CosmeticLocation)
        .collect::<Vec<_>>();
    let active = loc
        .iter()
        .filter(|(i, _)| matches!(idx.state_of(*i), Some(RuleState::Active)))
        .count();
    println!("COSMETIC_LOCATION total {} active {}", loc.len(), active);
    // None of them may act on an unrelated document.
    let mut global = 0;
    for (i, r) in &loc {
        if !matches!(idx.state_of(*i), Some(RuleState::Active)) {
            continue;
        }
        let one = ExtIndex::build(&[(*r).clone()]);
        for url in [
            "https://zzz-unrelated.example/",
            "https://zzz-unrelated.example/a/b?q=1",
        ] {
            let req = RequestInfo::new(url, "GET", ResourceType::Document);
            let h = [("Content-Type", "text/html")];
            let p = one.response_plan(
                &req,
                &ResponseInfo {
                    status: 200,
                    headers: &h,
                },
            );
            if !p.is_noop() {
                global += 1;
                println!("GLOBAL {}", r.raw);
            }
        }
    }
    println!("COSMETIC_LOCATION acting on unrelated docs: {global}");
}

#[test]
#[ignore]
fn measure_dump() {
    let Ok(path) = std::env::var("MEASURE_MANIFEST") else {
        return;
    };
    let Ok(pat) = std::env::var("MEASURE_REASON") else {
        return;
    };
    let man: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let inputs: Vec<ListInput> = man
        .iter()
        .map(|m| ListInput {
            id: m["id"].as_str().unwrap().into(),
            content: std::fs::read_to_string(m["path"].as_str().unwrap()).unwrap(),
            trusted: m["trusted"].as_bool().unwrap(),
            ..Default::default()
        })
        .collect();
    let built = build_set(&inputs);
    let idx = ExtIndex::build(&built.ext);
    for (i, r) in built.ext.iter().enumerate() {
        if idx
            .state_of(i)
            .and_then(|s| s.reason())
            .is_some_and(|w| w.contains(&pat))
        {
            println!(
                "DUMP {} | {}",
                idx.state_of(i)
                    .unwrap()
                    .reason()
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap(),
                r.raw
            );
        }
    }
}

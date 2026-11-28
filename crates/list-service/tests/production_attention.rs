//! Which production lists the attention rule flags, with the real extended-rule index.

use filter_engine::{build_set, ListFormat, ListInput};

#[test]
#[ignore = "needs ARGUS_LISTS_DIR"]
fn attention_over_production_lists() {
    let dir = std::env::var("ARGUS_LISTS_DIR").expect("ARGUS_LISTS_DIR");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    paths.sort();
    let inputs: Vec<ListInput> = paths
        .iter()
        .filter_map(|p| {
            Some(ListInput {
                id: p.file_name()?.to_string_lossy()[..12].to_string(),
                content: std::fs::read_to_string(p).ok()?,
                format: ListFormat::Auto,
                ..Default::default()
            })
        })
        .collect();
    let built = build_set(&inputs);
    let mut flagged = Vec::new();
    for (i, rep) in inputs.iter().zip(&built.reports) {
        let rules: Vec<filter_engine::ExtRule> = built
            .ext
            .iter()
            .filter(|e| e.list == i.id)
            .cloned()
            .collect();
        let mut r = rep.clone();
        let mut states = std::collections::BTreeMap::new();
        for v in list_service::inspect::judge_ext(&rules) {
            *states.entry(v.state.as_str().to_string()).or_insert(0usize) += 1;
        }
        r.apply_ext_states(states);
        eprintln!(
            "{} invalid={} (conv {} + rejected {} + ext {}) of {} rules, ext states {:?}: attention={}",
            i.id,
            r.problems(),
            r.error_count,
            r.rejected,
            r.ext_states.get("invalid").copied().unwrap_or(0),
            r.total_rules(),
            r.ext_states,
            r.attention
        );
        if r.attention {
            flagged.push(i.id.clone());
        }
    }
    eprintln!("flagged: {flagged:?}");
}

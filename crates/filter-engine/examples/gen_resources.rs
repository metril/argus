//! Regenerates `resources/ubo-resources.json` from a directory of uBlock Origin
//! `src/js/resources/*.js` files:
//!
//! `cargo run -p filter-engine --example gen_resources -- <dir with .js files> <output.json>`
//!
//! Files are concatenated in name order, exactly as the runtime fetcher does.

fn main() {
    let mut args = std::env::args().skip(1);
    let (dir, out) = (
        args.next().expect("input dir"),
        args.next().expect("output file"),
    );
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .expect("read dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "js"))
        .collect();
    names.sort();
    let mut combined = String::new();
    for p in &names {
        combined.push('\n');
        combined.push_str(&std::fs::read_to_string(p).expect("read js"));
    }
    let json = filter_engine::ubo_scriptlets_to_json(&combined).expect("convert");
    std::fs::write(&out, &json).expect("write");
    let n = serde_json::from_str::<Vec<serde_json::Value>>(&json)
        .unwrap()
        .len();
    println!(
        "{} files -> {n} resources, {} bytes",
        names.len(),
        json.len()
    );
}

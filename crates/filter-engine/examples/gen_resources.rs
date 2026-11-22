//! Regenerates `resources/ubo-resources.json` from a directory of uBlock Origin
//! `src/js/resources/*.js` files:
//!
//! `cargo run -p filter-engine --example gen_resources -- <dir with .js files> <output.json>`
//!
//! Files are converted in name order, exactly as the runtime fetcher does; resources that fail
//! validation are dropped and listed.

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
    let sources: Vec<String> = names
        .iter()
        .map(|p| std::fs::read_to_string(p).expect("read js"))
        .collect();
    let (json, dropped) = filter_engine::ubo_sources_to_json(&sources).expect("convert");
    std::fs::write(&out, &json).expect("write");
    let n = serde_json::from_str::<Vec<serde_json::Value>>(&json)
        .unwrap()
        .len();
    println!(
        "{} files -> {n} resources, {} bytes, {} dropped",
        names.len(),
        json.len(),
        dropped.len()
    );
    for d in &dropped {
        println!("  dropped {}: {}", d.name, d.reason);
    }
}

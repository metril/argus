//! Regenerates `resources/ubo-resources.json` from a directory of uBlock Origin
//! `src/js/resources/*.js` files:
//!
//! `cargo run -p filter-engine --example gen_resources -- <dir with .js files> <output.json>`
//!
//! Files are converted in name order, exactly as the runtime fetcher does; resources that fail
//! validation are dropped and listed.
//!
//! With three more arguments it also converts the `$redirect` resources:
//! `... <output.json> <redirect-resources.js> <web_accessible_resources dir> <redirects.json> [<AdGuard dist/redirects.json>]`

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
    if let (Some(map), Some(wa), Some(rout)) = (args.next(), args.next(), args.next()) {
        let map_js = std::fs::read_to_string(&map).expect("read map");
        let mut files = std::collections::HashMap::new();
        for name in filter_engine::redirect_file_names(&map_js).expect("map") {
            if let Ok(b) = std::fs::read(std::path::Path::new(&wa).join(&name)) {
                files.insert(name, b);
            }
        }
        let (json, dropped) =
            filter_engine::ubo_redirects_to_json(&map_js, &files).expect("convert");
        // Optional: AdGuard Scriptlets `dist/redirects.json`, for the names uBO lacks.
        let (json, mut dropped) = match args.next() {
            Some(ag) => {
                let src = std::fs::read_to_string(ag).expect("read adguard redirects");
                let (j, d) = filter_engine::with_adguard_redirects(&json, &src).expect("adguard");
                (j, d.into_iter().chain(dropped).collect::<Vec<_>>())
            }
            None => (json, dropped),
        };
        dropped.sort_by(|a, b| a.name.cmp(&b.name));
        std::fs::write(&rout, &json).expect("write");
        let n = serde_json::from_str::<Vec<serde_json::Value>>(&json)
            .unwrap()
            .len();
        println!(
            "redirects: {n} resources, {} bytes, {} dropped",
            json.len(),
            dropped.len()
        );
        for d in &dropped {
            println!("  dropped {}: {}", d.name, d.reason);
        }
    }
}

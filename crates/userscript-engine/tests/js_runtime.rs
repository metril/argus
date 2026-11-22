//! Runs the node test suite for `assets/gm.js` and smoke-tests a Rust-generated bundle in node.
//! Skips (with a message) when `node` is not installed.

use serde_json::{json, Map, Value};
use std::{collections::HashMap, path::PathBuf, process::Command};
use userscript_engine::{
    bundle::{generate, BundleOptions},
    index::ScriptIndex,
    matcher::Options,
    token::TokenKey,
    Userscript,
};

fn tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/tests")
}

fn node() -> Option<Command> {
    let ok = Command::new("node").arg("--version").output().map(|o| o.status.success()).unwrap_or(false);
    if !ok {
        eprintln!("SKIPPED: `node` not found on PATH; install node >= 20 to run the gm.js tests");
        return None;
    }
    Some(Command::new("node"))
}

#[test]
fn gm_js_unit_tests() {
    let Some(mut cmd) = node() else { return };
    let dir = tests_dir();
    let out = cmd
        .current_dir(&dir)
        .args(["--test", "runtime.test.mjs", "hostile.test.mjs"])
        .output()
        .expect("run node");
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "node tests failed:\n{text}");
}

#[test]
fn generated_bundle_runs_scripts_with_hostile_metadata() {
    let Some(mut cmd) = node() else { return };
    let evil = "</script><!-- \"';alert(1)// */ &amp;"; // (U+2028 inside the header comment would end it: that is the script's own code, covered in bundle unit tests)
    let src = format!(
        "// ==UserScript==\n// @name {evil}\n// @namespace {evil}\n// @version 1.2\n// @match *://*/*\n// @grant GM_getValue\n// @grant GM_setValue\n// @run-at document-start\n// ==/UserScript==\nwindow.__out = {{ name: GM_info.script.name, value: GM_getValue('a'), same: unsafeWindow === window, hasXhr: typeof GM_xmlhttpRequest }};\nGM_setValue('b', 1);\n"
    );
    let scripts = vec![
        Userscript::new(src).unwrap(),
        Userscript::new("// ==UserScript==\n// @name second\n// @grant none\n// @run-at document-end\n// ==/UserScript==\nwindow.__out2 = typeof GM_getValue;\n".into()).unwrap(),
    ];
    let idx = ScriptIndex::build("p", &scripts, Options::default()).index;
    let key = TokenKey::new(vec![3; 32]);
    let mut vals: HashMap<String, Map<String, Value>> = HashMap::new();
    let mut m = Map::new();
    m.insert("a".into(), json!("embedded"));
    vals.insert(scripts[0].id.clone(), m);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let opts = BundleOptions::new("p", "https://page.test", true, &key, now, &vals);
    let b = generate(&idx.iter().collect::<Vec<_>>(), &opts);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("bundle.js");
    std::fs::write(&file, &b.js).unwrap();
    let out = cmd.current_dir(tests_dir()).arg("bundle_smoke.mjs").arg(&file).output().expect("run node");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "smoke failed:\n{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
    let v: Value = serde_json::from_str(stdout.lines().last().unwrap()).unwrap();
    assert_eq!(v["errors"], json!([]), "{v}");
    assert_eq!(v["out"]["name"], evil);
    assert_eq!(v["out"]["value"], "embedded");
    assert_eq!(v["out"]["same"], true);
    assert_eq!(v["out"]["hasXhr"], "undefined");
    assert!(v["calls"].as_array().unwrap().iter().any(|c| c == "values/set"), "{v}");
}

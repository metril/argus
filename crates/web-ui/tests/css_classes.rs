//! Fails when a `class="..."` literal in the UI sources names a class main.css never defines.
//!
//! Not covered: `class=move || format!(..)` and other computed values, `class:name=` toggles,
//! classes in `classes=`/`class=` props passed to components, and classes set from JS.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Classes set dynamically, by third parties, or purely as JS/test hooks.
const ALLOW: &[&str] = &[];

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn is_ident(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[test]
fn every_class_literal_is_defined_in_css() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut css = fs::read_to_string(root.join("style/main.css")).unwrap();
    // Drop comments so `.foo` mentioned in prose does not count as defined.
    while let Some(a) = css.find("/*") {
        let end = css[a..].find("*/").map_or(css.len(), |e| a + e + 2);
        css.replace_range(a..end, "");
    }
    let mut defined = BTreeSet::new();
    for (i, _) in css.match_indices('.') {
        let rest = &css[i + 1..];
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .unwrap_or(rest.len());
        if end > 0 {
            defined.insert(rest[..end].to_string());
        }
    }
    let mut files = Vec::new();
    rs_files(&root.join("src"), &mut files);
    let mut missing = BTreeSet::new();
    let mut seen = 0usize;
    for f in files {
        let src = fs::read_to_string(&f).unwrap();
        let mut rest = src.as_str();
        while let Some(i) = rest.find("class=\"") {
            rest = &rest[i + 7..];
            let Some(end) = rest.find('"') else { break };
            let lit = &rest[..end];
            for c in lit.split_whitespace().filter(|c| is_ident(c)) {
                seen += 1;
                if !defined.contains(c) && !ALLOW.contains(&c) {
                    missing.insert(format!(
                        "{c} ({})",
                        f.file_name().unwrap().to_string_lossy()
                    ));
                }
            }
            rest = &rest[end..];
        }
    }
    assert!(!defined.is_empty(), "no classes found in main.css");
    assert!(seen > 0, "no class literals found in src");
    assert!(
        missing.is_empty(),
        "classes missing from main.css: {missing:#?}"
    );
}

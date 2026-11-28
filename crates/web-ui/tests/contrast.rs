//! The text and control tokens of `style/main.css` keep their contrast in every theme block:
//! primary and secondary text >= 4.5:1, disabled text and control borders >= 3:1, on every surface.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn hex(v: &str) -> [f64; 3] {
    let v = v.trim().trim_start_matches('#');
    let n = |i: usize| f64::from(u8::from_str_radix(&v[i..i + 2], 16).unwrap());
    [n(0), n(2), n(4)]
}

fn lum(c: [f64; 3]) -> f64 {
    let f = |x: f64| {
        let x = x / 255.0;
        if x <= 0.03928 {
            x / 12.92
        } else {
            ((x + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2])
}

fn ratio(a: [f64; 3], b: [f64; 3]) -> f64 {
    let (x, y) = (lum(a), lum(b));
    (x.max(y) + 0.05) / (x.min(y) + 0.05)
}

/// `--name: value` declarations of the block that starts at `selector`.
fn block(css: &str, selector: &str) -> HashMap<String, String> {
    let start = css
        .find(selector)
        .unwrap_or_else(|| panic!("no block {selector}"));
    let open = start + css[start..].find('{').unwrap();
    let close = open + css[open..].find('}').unwrap();
    css[open + 1..close]
        .split(';')
        .filter_map(|d| d.split_once(':'))
        .filter(|(k, v)| k.trim().starts_with("--") && v.trim().starts_with('#'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

#[test]
fn text_and_control_tokens_keep_their_contrast_in_every_theme_block() {
    let mut css =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("style/main.css")).unwrap();
    while let Some(a) = css.find("/*") {
        let end = css[a..].find("*/").map_or(css.len(), |e| a + e + 2);
        css.replace_range(a..end, "");
    }
    let blocks = [
        ("dark :root", ":root{"),
        ("light media", ":root:not([data-theme=\"dark\"]){"),
        ("light attr", ":root[data-theme=\"light\"]{"),
        ("dark attr", ":root[data-theme=\"dark\"]{"),
    ];
    let mut bad = Vec::new();
    for (name, sel) in blocks {
        let sel_tight = sel.replace('{', "");
        let b = block(&css, &sel_tight);
        for surface in ["--bg", "--surface", "--surface-2", "--surface-3"] {
            let s = hex(b
                .get(surface)
                .unwrap_or_else(|| panic!("{name}: {surface} missing in {b:?}")));
            for (tok, need) in [
                ("--text", 4.5),
                ("--text-2", 4.5),
                ("--text-3", 3.0),
                ("--ctl", 3.0),
            ] {
                let r = ratio(hex(&b[tok]), s);
                if r < need {
                    bad.push(format!(
                        "{name}: {tok} on {surface} is {r:.2}, needs {need}"
                    ));
                }
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

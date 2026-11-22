//! Convert uBlock Origin scriptlet source into adblock-rust [`Resource`]s.
//!
//! uBO defines scriptlets across several files in its `src/js/resources/` directory using the
//! shape:
//!
//! ```js
//! builtinScriptlets.push({
//!     name: 'abort-current-script.js',
//!     aliases: ['acs.js', 'abort-current-script'],
//!     fn: abortCurrentScript,
//!     dependencies: ['safe-self.fn', 'should-debug.fn'],
//! });
//! function abortCurrentScript(...args) { /* ... */ }
//! ```
//!
//! `fn` references a top-level function defined nearby. adblock-rust's resource model wants the
//! function *source* as the resource content (it extracts the function name and invokes it with the
//! filter's arguments) plus the dependency names. We collect every top-level function in the
//! (concatenated) source, then emit one [`Resource`] per `builtinScriptlets.push` entry.
//!
//! These scriptlets are GPLv3 (uBlock Origin) — they are fetched at runtime, never vendored.

use std::collections::HashMap;

use adblock::resources::{MimeType, Resource, ResourceType};
use base64::Engine as _;

/// Find the matching `}` for the first `{` at or after `from`. Returns its byte index (inclusive).
fn brace_end(b: &[u8], from: usize) -> Option<usize> {
    let ob = (from..b.len()).find(|&k| b[k] == b'{')?;
    let mut depth = 0usize;
    for (j, &byte) in b.iter().enumerate().skip(ob) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
            }
            _ => {}
        }
    }
    None
}

/// Collect top-level `function NAME(...) {...}` definitions (including `export function`), mapping
/// name → source text. The source starts at the `function` keyword so adblock-rust can extract the
/// function name (the `export` prefix, if any, is dropped).
fn collect_functions(js: &str) -> HashMap<String, String> {
    let b = js.as_bytes();
    let mut map = HashMap::new();
    let mut i = 0;
    while let Some(rel) = js[i..].find("function ") {
        let p = i + rel; // index of the `function` keyword
        i = p + "function ".len();

        // Must be top-level: at column 0, or `export function` at column 0.
        let at_line_start = p >= 1 && b[p - 1] == b'\n';
        let after_export = p >= 8 && &js[p - 7..p] == "export " && b[p - 8] == b'\n';
        if !at_line_start && !after_export {
            continue;
        }

        let after = p + "function ".len();
        if let Some(paren) = js[after..].find('(') {
            let ne = after + paren;
            let name = js[after..ne].trim().to_string();
            if let Some(end) = brace_end(b, ne) {
                if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    map.insert(name, js[p..=end].to_string());
                    i = end + 1;
                }
            }
        }
    }
    map
}

/// Read a single-quoted/double-quoted string value for `key` within `block`.
fn field_str(block: &str, key: &str) -> Option<String> {
    let p = block.find(key)?;
    let rest = &block[p + key.len()..];
    let q = rest.find(['\'', '"'])?;
    let quote = rest.as_bytes()[q] as char;
    let tail = &rest[q + 1..];
    let e = tail.find(quote)?;
    Some(tail[..e].to_string())
}

/// Read an identifier value for `key` (e.g. `fn: someFunction`).
fn field_ident(block: &str, key: &str) -> Option<String> {
    let p = block.find(key)?;
    let id: String = block[p + key.len()..]
        .trim_start()
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!id.is_empty()).then_some(id)
}

/// Read a string-array value for `key` (e.g. `aliases: ['a.js', 'b']`).
fn field_arr(block: &str, key: &str) -> Vec<String> {
    let Some(p) = block.find(key) else {
        return vec![];
    };
    let rest = &block[p + key.len()..];
    let Some(ob) = rest.find('[') else {
        return vec![];
    };
    let Some(cb) = rest[ob..].find(']') else {
        return vec![];
    };
    rest[ob + 1..ob + cb]
        .split(',')
        .map(|s| {
            s.trim()
                .trim_matches(|c| c == '\'' || c == '"')
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// True if the block opts into `requiresTrust` (we skip those — trusted scriptlets must not run
/// from untrusted lists).
fn requires_trust(block: &str) -> bool {
    block
        .find("requiresTrust:")
        .map(|p| {
            block[p + "requiresTrust:".len()..]
                .trim_start()
                .starts_with("true")
        })
        .unwrap_or(false)
}

/// A scriptlet entry parsed from either registration form, before dependency resolution.
struct Entry {
    fn_ref: String,
    name: String,
    aliases: Vec<String>,
    deps_raw: Vec<String>,
}

/// Parse every scriptlet registration in the source. uBO uses two interchangeable forms:
/// - `builtinScriptlets.push({ name, fn: <funcRef>, dependencies: ['a.fn', ...] })` (string deps)
/// - `registerScriptlet(<funcRef>, { name, dependencies: [funcRefA, funcRefB] })` (function-ref deps)
fn parse_entries(js: &str) -> Vec<Entry> {
    let b = js.as_bytes();
    let mut entries = Vec::new();
    let mut i = 0;

    loop {
        let push_at = js[i..].find("builtinScriptlets.push({").map(|r| i + r);
        let reg_at = js[i..].find("registerScriptlet(").map(|r| i + r);

        // Take whichever marker comes first.
        let (is_push, at) = match (push_at, reg_at) {
            (Some(p), Some(r)) => {
                if p < r {
                    (true, p)
                } else {
                    (false, r)
                }
            }
            (Some(p), None) => (true, p),
            (None, Some(r)) => (false, r),
            (None, None) => break,
        };

        let (fn_ref, block, next) = if is_push {
            let start = at + "builtinScriptlets.push({".len();
            let Some(end) = brace_end(b, start - 1) else {
                break;
            };
            let block = js[start..end].to_string();
            let fn_ref = field_ident(&block, "fn:").unwrap_or_default();
            (fn_ref, block, end + 1)
        } else {
            // registerScriptlet(<funcRef>, { ... })
            let after = at + "registerScriptlet(".len();
            let fn_ref: String = js[after..]
                .trim_start()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let Some(end) = brace_end(b, after) else {
                break;
            };
            let ob = (after..b.len()).find(|&k| b[k] == b'{').unwrap_or(after);
            let block = js[ob + 1..end].to_string();
            (fn_ref, block, end + 1)
        };
        i = next;

        if fn_ref.is_empty() || requires_trust(&block) {
            continue;
        }
        let Some(name) = field_str(&block, "name:") else {
            continue;
        };
        entries.push(Entry {
            fn_ref,
            name,
            aliases: field_arr(&block, "aliases:"),
            deps_raw: field_arr(&block, "dependencies:"),
        });
    }

    entries
}

/// Convert concatenated uBO scriptlet source into adblock-rust resources.
pub fn convert_ubo_scriptlets(js: &str) -> Vec<Resource> {
    let fns = collect_functions(js);
    let entries = parse_entries(js);

    // Map each scriptlet's function-reference to its resource name, so dependencies expressed as
    // function references (the `registerScriptlet` form) resolve to resource names.
    let fnref_to_name: HashMap<&str, &str> = entries
        .iter()
        .map(|e| (e.fn_ref.as_str(), e.name.as_str()))
        .collect();

    entries
        .iter()
        .filter_map(|e| {
            let src = fns.get(&e.fn_ref)?;
            let kind = if e.name.ends_with(".fn") {
                ResourceType::Mime(MimeType::FnJavascript)
            } else {
                ResourceType::Mime(MimeType::ApplicationJavascript)
            };
            // Resolve dependency tokens: a function ref → its resource name; otherwise it's already
            // a resource name (the `.push` string form).
            let dependencies = e
                .deps_raw
                .iter()
                .map(|d| {
                    fnref_to_name
                        .get(d.as_str())
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| d.clone())
                })
                .collect();
            Some(Resource {
                name: e.name.clone(),
                aliases: e.aliases.clone(),
                kind,
                content: base64::engine::general_purpose::STANDARD.encode(src),
                dependencies,
                permission: Default::default(),
            })
        })
        .collect()
}

/// Convert uBO scriptlet source into a JSON array of resources (the format
/// [`crate::SharedEngine::set_resources_from_json`] expects).
pub fn ubo_scriptlets_to_json(js: &str) -> Result<String, serde_json::Error> {
    serde_json::to_string(&convert_ubo_scriptlets(js))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A self-contained sample in uBO's format: one dependency + one scriptlet that uses it.
    const SAMPLE: &str = r#"
builtinScriptlets.push({
    name: 'safe-self.fn',
    fn: safeSelf,
});
function safeSelf() {
    return { Object_defineProperty: Object.defineProperty.bind(Object) };
}

builtinScriptlets.push({
    name: 'set-constant.js',
    aliases: ['set-constant', 'sc'],
    fn: setConstant,
    dependencies: ['safe-self.fn'],
});
function setConstant(...args) {
    const safe = safeSelf();
    safe.Object_defineProperty(window, args[0], { value: args[1] });
}

builtinScriptlets.push({
    name: 'trusted-thing.js',
    requiresTrust: true,
    fn: trustedThing,
});
function trustedThing() { /* dangerous */ }
"#;

    #[test]
    fn converts_scriptlet_with_dependency_and_skips_trusted() {
        let res = convert_ubo_scriptlets(SAMPLE);
        let names: Vec<&str> = res.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"safe-self.fn"), "got {names:?}");
        assert!(names.contains(&"set-constant.js"), "got {names:?}");
        assert!(
            !names.contains(&"trusted-thing.js"),
            "requiresTrust scriptlets must be skipped"
        );

        let sc = res.iter().find(|r| r.name == "set-constant.js").unwrap();
        assert_eq!(sc.aliases, vec!["set-constant", "sc"]);
        assert_eq!(sc.dependencies, vec!["safe-self.fn"]);
    }

    #[test]
    fn produced_resources_inject_via_engine() {
        use adblock::lists::{FilterSet, ParseOptions};
        use adblock::Engine;

        let resources = convert_ubo_scriptlets(SAMPLE);
        let mut fs = FilterSet::new(false);
        fs.add_filter(
            "example.com##+js(set-constant, foo, 1)",
            ParseOptions::default(),
        )
        .unwrap();
        let mut engine = Engine::from_filter_set(fs, true);
        engine.use_resources(resources);

        let r = engine.url_cosmetic_resources("https://example.com/");
        assert!(
            !r.injected_script.is_empty(),
            "converted scriptlet (with its dependency) should inject"
        );
    }
}

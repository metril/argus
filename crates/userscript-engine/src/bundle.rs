//! Page bundle generation: the JS the proxy serves for a document's matched scripts.
//!
//! Layout of the generated file (one external, synchronous, nonce'd `<script src>` at the top
//! of `<head>`, so `document-start` scripts run before any page script):
//!
//! ```text
//! (<assets/gm.js>)({base, top, handler, handlerVersion}, [ {d: <descriptor>, f: function(<params>){...}}, ... ], window);
//! ```
//!
//! Every user-controlled string (names, URLs, `@match` values, tokens, stored values) reaches
//! the output only through [`js_json`], which escapes `<`, `>`, `&`, U+2028 and U+2029, so
//! metadata can neither close a surrounding `<script>` nor break a JS string. The script
//! *source itself* is emitted raw (it is code); serve the bundle as an external script, never
//! inline it into HTML ([`Bundle::inline_safe`] says when inlining would also be safe).
//! One syntax error in any script's source makes the whole file fail to parse; callers that
//! want isolation can call [`generate`] once per script.

use crate::{
    index::CompiledScript,
    metadata::{RunAt, UserscriptMetadata},
    token::{self, TokenClaims, TokenKey},
};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

/// The hand-written GM runtime (a single function expression).
pub const RUNTIME_JS: &str = include_str!("../assets/gm.js");

/// `Symbol.for` key under which the shared runtime script publishes its entry point.
pub const RUNTIME_HOOK: &str = "adblock.userscript.runtime";
/// The menu button (a function expression), inlined into the shared runtime closure so the
/// command registry is never reachable from page code.
pub const MENU_JS: &str = include_str!("../assets/menu.js");

/// The script that installs the GM runtime once per document: the runtime function, the command
/// registry every script of the page registers into (and the in-page panel reads), and one
/// non-writable, non-configurable entry point the per-script bundles call. It holds no secret:
/// tokens arrive only in the per-document bundles. Content-addressed and immutable, so it is
/// served once from a hash URL and cached.
pub fn runtime_script() -> String {
    format!(
        "({})(window);\n",
        SHARED_JS
            .replace("/*RUNTIME*/null", RUNTIME_JS.trim())
            .replace("/*MENU*/null", MENU_JS.trim())
            .trim()
    )
}

const SHARED_JS: &str = include_str!("../assets/gm_shared.js");

/// Canonical grant -> the `GM_*` name the script sees as a variable (and the runtime exposes).
pub const API_TABLE: &[(&str, &str)] = &[
    ("gm_getvalue", "GM_getValue"),
    ("gm_setvalue", "GM_setValue"),
    ("gm_deletevalue", "GM_deleteValue"),
    ("gm_listvalues", "GM_listValues"),
    ("gm_getvalues", "GM_getValues"),
    ("gm_setvalues", "GM_setValues"),
    ("gm_deletevalues", "GM_deleteValues"),
    ("gm_addvaluechangelistener", "GM_addValueChangeListener"),
    (
        "gm_removevaluechangelistener",
        "GM_removeValueChangeListener",
    ),
    ("gm_addstyle", "GM_addStyle"),
    ("gm_addelement", "GM_addElement"),
    ("gm_getresourcetext", "GM_getResourceText"),
    ("gm_getresourceurl", "GM_getResourceURL"),
    ("gm_xmlhttprequest", "GM_xmlhttpRequest"),
    ("gm_download", "GM_download"),
    ("gm_openintab", "GM_openInTab"),
    ("gm_setclipboard", "GM_setClipboard"),
    ("gm_notification", "GM_notification"),
    ("gm_registermenucommand", "GM_registerMenuCommand"),
    ("gm_unregistermenucommand", "GM_unregisterMenuCommand"),
    ("gm_log", "GM_log"),
    ("gm_gettab", "GM_getTab"),
    ("gm_savetab", "GM_saveTab"),
    ("gm_gettabs", "GM_getTabs"),
    ("gm_cookie", "GM_cookie"),
    ("gm_webrequest", "GM_webRequest"),
];

pub struct BundleOptions<'a> {
    pub profile: &'a str,
    /// Page origin as in the `Origin` header (`https://example.com`).
    pub page_origin: &'a str,
    pub is_top_frame: bool,
    pub key: &'a TokenKey,
    /// Unix seconds.
    pub now: u64,
    /// Token lifetime; the runtime refreshes at half-life.
    pub ttl_secs: u64,
    /// Where the GM endpoints live, e.g. `/__adblock__/gm`.
    pub base_path: &'a str,
    /// Current stored values per script id, embedded so `GM_getValue` is synchronous. Scripts
    /// without an entry load their values lazily (and start asynchronously).
    pub values: &'a HashMap<String, Map<String, Value>>,
    /// `@resource`s up to this size are embedded for synchronous `GM_getResourceText/URL`.
    pub inline_resource_limit: usize,
    /// Call the runtime installed once by [`runtime_script`] instead of repeating it in the
    /// bundle (the page must load that script first).
    pub shared_runtime: bool,
    /// Public id of the document, set only when the document is bound to a live browser
    /// extension session (menu commands sync to it).
    pub mdoc: Option<&'a str>,
}

impl<'a> BundleOptions<'a> {
    pub fn new(
        profile: &'a str,
        page_origin: &'a str,
        is_top_frame: bool,
        key: &'a TokenKey,
        now: u64,
        values: &'a HashMap<String, Map<String, Value>>,
    ) -> Self {
        Self {
            profile,
            page_origin,
            is_top_frame,
            key,
            now,
            ttl_secs: 3600,
            base_path: "/__adblock__/gm",
            values,
            inline_resource_limit: 256 * 1024,
            shared_runtime: false,
            mdoc: None,
        }
    }
}

/// One script's slot in the bundle.
#[derive(Debug, Clone)]
pub struct ScriptChunk {
    pub id: String,
    pub run_at: RunAt,
    /// The `{d:...,f:...}` entry text.
    pub js: String,
}

#[derive(Debug, Clone)]
pub struct Bundle {
    /// Complete file to serve (empty when no scripts).
    pub js: String,
    /// Scripts by `@run-at` group order (start, body, end, idle), install order inside.
    pub chunks: Vec<ScriptChunk>,
    /// Number of scripts per run-at: `[start, body, end, idle]`.
    pub counts: [usize; 4],
}

impl Bundle {
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// True when the file contains no `</script` / `<!--` sequence, i.e. inlining it in an
    /// HTML `<script>` could not be broken out of by script *source* either.
    pub fn inline_safe(&self) -> bool {
        let lc = self.js.to_ascii_lowercase();
        !lc.contains("</script") && !lc.contains("<!--")
    }
}

/// JSON text safe to embed in JS and in an HTML `<script>`: escapes `<`, `>`, `&`, U+2028/9.
pub fn js_json(v: &Value) -> String {
    let s = serde_json::to_string(v).unwrap_or_else(|_| "null".into());
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out
}

fn run_at_name(r: RunAt) -> &'static str {
    match r {
        RunAt::DocumentStart => "document-start",
        RunAt::DocumentBody => "document-body",
        RunAt::DocumentEnd => "document-end",
        RunAt::DocumentIdle => "document-idle",
        RunAt::ContextMenu => "document-end", // never indexed; harmless fallback
    }
}

fn group(r: RunAt) -> usize {
    match r {
        RunAt::DocumentStart => 0,
        RunAt::DocumentBody => 1,
        RunAt::DocumentEnd | RunAt::ContextMenu => 2,
        RunAt::DocumentIdle => 3,
    }
}

/// Grants the runtime should honour: canonical, with `@grant none` -> empty, and granting
/// `GM_addValueChangeListener` also exposing its remover.
pub fn runtime_grants(meta: &UserscriptMetadata) -> Vec<String> {
    let mut g = meta.effective_grants();
    if g.iter().any(|x| x == "gm_addvaluechangelistener")
        && !g.iter().any(|x| x == "gm_removevaluechangelistener")
    {
        g.push("gm_removevaluechangelistener".into());
    }
    g
}

/// Parameter names of the script function: granted `GM_*` APIs, `GM`, `GM_info`, `unsafeWindow`.
pub fn params(grants: &[String]) -> Vec<&'static str> {
    let mut p = Vec::new();
    if !grants.is_empty() {
        p.push("GM_info");
        p.push("GM");
    }
    for (canon, name) in API_TABLE {
        if grants.iter().any(|g| g == canon) {
            p.push(*name);
        }
    }
    p.push("unsafeWindow");
    p
}

fn meta_json(m: &UserscriptMetadata) -> Value {
    let lc = |s: &Option<String>| s.clone().map(Value::String).unwrap_or(Value::Null);
    json!({
        "name": m.name, "namespace": lc(&m.namespace), "version": lc(&m.version), "description": lc(&m.description),
        "author": lc(&m.author), "homepage": lc(&m.homepage), "icon": lc(&m.icon), "icon64": lc(&m.icon64),
        "supportURL": lc(&m.support_url), "updateURL": lc(&m.update_url), "downloadURL": lc(&m.download_url),
        "matches": m.matches, "includes": m.includes, "excludes": m.excludes, "excludeMatches": m.exclude_matches,
        "connects": m.connect, "grants": m.grants, "run-at": run_at_name(m.run_at), "noframes": m.noframes,
        "unwrap": m.unwrap, "topLevelAwait": m.top_level_await, "license": lc(&m.license),
        "antifeatures": m.antifeatures, "tags": m.tags, "compatible": m.compatible,
        "requires": m.requires.iter().map(|r| r.url.clone()).collect::<Vec<_>>(),
        "resources": m.resources.iter().map(|r| json!({"name": r.name, "url": r.url})).collect::<Vec<_>>(),
        "localizedNames": m.localized_names, "localizedDescriptions": m.localized_descriptions,
    })
}

fn meta_str(m: &UserscriptMetadata) -> String {
    let mut s = String::from("// ==UserScript==\n");
    for l in &m.raw_metadata {
        s.push_str(l);
        s.push('\n');
    }
    s.push_str("// ==/UserScript==\n");
    s
}

/// Script body: `@require` contents in order, then the source, in one scope.
fn body(cs: &CompiledScript) -> String {
    let s = &cs.script;
    let mut b = String::new();
    for r in &s.assets.requires {
        b.push_str(r.content.trim_start_matches('\u{feff}'));
        b.push_str("\n;\n");
    }
    b.push_str(s.source.trim_start_matches('\u{feff}'));
    b.push('\n');
    b
}

/// The `{d:...,f:...}` entry for one script.
pub fn entry_js(cs: &CompiledScript, opts: &BundleOptions<'_>) -> String {
    let s = &cs.script;
    let m = &s.metadata;
    let grants = runtime_grants(m);
    let params = params(&grants);
    let caps = token::caps_hash(m, s.allow_connect_all);
    let exp = opts.now + opts.ttl_secs;
    let tok = token::mint(
        opts.key,
        &TokenClaims {
            profile: opts.profile,
            script_id: &s.id,
            script_version: m.version.as_deref().unwrap_or(""),
            origin: opts.page_origin,
            caps_hash: &caps,
            exp,
        },
    );
    let mut d = Map::new();
    d.insert("id".into(), json!(s.id));
    d.insert("name".into(), json!(m.name));
    d.insert("runAt".into(), json!(run_at_name(m.run_at)));
    d.insert("grants".into(), json!(grants));
    d.insert("params".into(), json!(params));
    d.insert("token".into(), json!(tok));
    d.insert(
        "chan".into(),
        json!(token::channel_secret(
            opts.key,
            opts.profile,
            &s.id,
            opts.page_origin
        )),
    );
    if let Some(md) = opts.mdoc {
        d.insert("mdoc".into(), json!(md));
    }
    d.insert("meta".into(), meta_json(m));
    d.insert("metaStr".into(), json!(meta_str(m)));
    d.insert("unwrap".into(), json!(m.unwrap));
    let uses = |c: &str| grants.iter().any(|g| g == c);
    if uses("gm_getvalue")
        || uses("gm_getvalues")
        || uses("gm_listvalues")
        || uses("gm_addvaluechangelistener")
        || uses("gm_setvalue")
        || uses("gm_setvalues")
    {
        if let Some(v) = opts.values.get(&s.id) {
            d.insert("values".into(), Value::Object(v.clone()));
        }
    } else {
        // Nothing to read: an empty snapshot, so the runtime does not try to load values (a
        // lazy load would be refused for lack of a read grant, and the script would never run).
        d.insert("values".into(), Value::Object(Map::new()));
    }
    if uses("gm_getresourcetext") || uses("gm_getresourceurl") {
        let mut res = Map::new();
        for r in s
            .assets
            .resources
            .iter()
            .filter(|r| r.data_b64.len() <= opts.inline_resource_limit * 4 / 3 + 4)
        {
            let bytes = r.bytes();
            let is_text = r.mime.starts_with("text/")
                || r.mime.contains("json")
                || r.mime.contains("javascript")
                || r.mime.contains("xml");
            match (is_text, String::from_utf8(bytes)) {
                (true, Ok(t)) => res.insert(r.name.clone(), json!({"mime": r.mime, "text": t})),
                _ => res.insert(r.name.clone(), json!({"mime": r.mime, "b64": r.data_b64})),
            };
        }
        d.insert("resources".into(), Value::Object(res));
    }
    if m.unwrap {
        d.insert("code".into(), json!(body(cs)));
        return format!("{{d:{},f:null}}", js_json(&Value::Object(d)));
    }
    let kw = if m.top_level_await {
        "async function"
    } else {
        "function"
    };
    format!(
        "{{d:{},f:function({}){{return ({kw}(){{\n{}}}).call(this);}}}}",
        js_json(&Value::Object(d)),
        params.join(","),
        body(cs)
    )
}

/// Render the bundle for `scripts` (already filtered by the index) in one document.
pub fn generate(scripts: &[&CompiledScript], opts: &BundleOptions<'_>) -> Bundle {
    let mut chunks: Vec<ScriptChunk> = scripts
        .iter()
        .map(|cs| ScriptChunk {
            id: cs.script.id.clone(),
            run_at: cs.script.metadata.run_at,
            js: entry_js(cs, opts),
        })
        .collect();
    // Stable: group order start, body, end, idle; install order inside a group.
    chunks.sort_by_key(|c| group(c.run_at));
    let mut counts = [0usize; 4];
    for c in &chunks {
        counts[group(c.run_at)] += 1;
    }
    if chunks.is_empty() {
        return Bundle {
            js: String::new(),
            chunks,
            counts,
        };
    }
    let cfg = json!({"base": opts.base_path, "top": opts.is_top_frame, "handler": "Argus Userscripts", "handlerVersion": env!("CARGO_PKG_VERSION")});
    let entries: Vec<&str> = chunks.iter().map(|c| c.js.as_str()).collect();
    let call = format!(
        "(function(r){{if(r)r({},[{}]);}})(window[Symbol.for(\"{RUNTIME_HOOK}\")]);\n",
        js_json(&cfg),
        entries.join(",\n")
    );
    // Self-contained (the runtime installs itself first; a later bundle reuses the earlier
    // install) unless the page loads the shared runtime script.
    let js = if opts.shared_runtime {
        call
    } else {
        runtime_script() + &call
    };
    Bundle { js, chunks, counts }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        index::ScriptIndex,
        matcher::Options,
        script::Userscript,
        token::{claimed_script_id, verify, ScriptRecord},
    };

    fn us(hdr: &str, code: &str) -> Userscript {
        Userscript::new(format!(
            "// ==UserScript==\n{hdr}\n// ==/UserScript==\n{code}"
        ))
        .unwrap()
    }

    fn compile(scripts: Vec<Userscript>) -> ScriptIndex {
        ScriptIndex::build("p", &scripts, Options::default()).index
    }

    fn opts<'a>(
        key: &'a TokenKey,
        vals: &'a HashMap<String, Map<String, Value>>,
    ) -> BundleOptions<'a> {
        BundleOptions::new("p", "https://example.com", true, key, 1000, vals)
    }

    #[test]
    fn golden_entry() {
        let idx = compile(vec![us("// @name Hi\n// @namespace n\n// @version 1.0\n// @match *://*/*\n// @grant GM_getValue", "console.log(GM_getValue('a'));")]);
        let key = TokenKey::new(vec![1; 32]);
        let vals = HashMap::new();
        let o = opts(&key, &vals);
        let cs = idx.iter().next().unwrap();
        let js = entry_js(cs, &o);
        // Structure (token and metadata JSON are checked separately).
        assert!(js.starts_with("{d:{"), "{js}");
        assert!(js.contains("\"grants\":[\"gm_getvalue\"]"), "{js}");
        assert!(
            js.contains("\"params\":[\"GM_info\",\"GM\",\"GM_getValue\",\"unsafeWindow\"]"),
            "{js}"
        );
        assert!(js.contains("\"run-at\":\"document-end\""));
        assert!(js.ends_with("f:function(GM_info,GM,GM_getValue,unsafeWindow){return (function(){\n// ==UserScript==\n// @name Hi\n// @namespace n\n// @version 1.0\n// @match *://*/*\n// @grant GM_getValue\n// ==/UserScript==\nconsole.log(GM_getValue('a'));\n}).call(this);}}"), "{js}");
    }

    #[test]
    fn grant_none_exposes_no_api_and_unwrap_wrapper_variants() {
        let idx = compile(vec![
            us("// @name A\n// @grant none", "x();"),
            us(
                "// @name B\n// @grant GM.getValue\n// @top-level-await",
                "await 1;",
            ),
            us("// @name C\n// @unwrap", "window.foo = 1;"),
        ]);
        let (key, vals) = (TokenKey::new(vec![1; 32]), HashMap::new());
        let o = opts(&key, &vals);
        let js: Vec<String> = idx.iter().map(|c| entry_js(c, &o)).collect();
        assert!(js[0].contains("f:function(unsafeWindow){") && js[0].contains("\"grants\":[]"));
        assert!(js[1].contains("(async function(){"));
        assert!(js[1].contains("function(GM_info,GM,GM_getValue,unsafeWindow)"));
        assert!(
            js[2].contains("f:null")
                && js[2].contains("\"code\":")
                && js[2].contains("window.foo = 1;")
        );
    }

    #[test]
    fn requires_come_first_in_the_same_scope() {
        let mut s = us("// @name R", "main();");
        s.assets.requires.push(crate::script::RequireBlob {
            url: "https://x/a.js".into(),
            content: "\u{feff}libA();".into(),
        });
        s.assets.requires.push(crate::script::RequireBlob {
            url: "https://x/b.js".into(),
            content: "libB(); // no newline".into(),
        });
        let idx = compile(vec![s]);
        let (key, vals) = (TokenKey::new(vec![1; 32]), HashMap::new());
        let js = entry_js(idx.iter().next().unwrap(), &opts(&key, &vals));
        let a = js.find("libA();").unwrap();
        let b = js.find("libB();").unwrap();
        let m = js.find("main();").unwrap();
        assert!(a < b && b < m);
        assert!(
            js[b..m].contains("\n;\n"),
            "a trailing line comment must not swallow the next code"
        );
        assert!(!js.contains('\u{feff}'));
    }

    #[test]
    fn run_at_grouping_and_empty() {
        let idx = compile(vec![
            us("// @name idle\n// @run-at document-idle", ""),
            us("// @name start\n// @run-at document-start", ""),
            us("// @name end", ""),
            us("// @name body\n// @run-at document-body", ""),
        ]);
        let (key, vals) = (TokenKey::new(vec![1; 32]), HashMap::new());
        let all: Vec<_> = idx.iter().collect();
        let b = generate(&all, &opts(&key, &vals));
        let order: Vec<_> = b
            .chunks
            .iter()
            .map(|c| idx.get(&c.id).unwrap().script.name().to_string())
            .collect();
        assert_eq!(order, ["start", "body", "end", "idle"]);
        assert_eq!(b.counts, [1, 1, 1, 1]);
        assert!(b.js.starts_with("(function (W)") || b.js.starts_with("(/*"));
        assert!(
            b.js.contains(RUNTIME_HOOK)
                && b.js
                    .trim_end()
                    .ends_with("(window[Symbol.for(\"adblock.userscript.runtime\")]);")
        );
        assert!(generate(&[], &opts(&key, &vals)).js.is_empty());
    }

    #[test]
    fn hostile_metadata_is_neutralised() {
        let evil = "</script><!-- \u{2028}\u{2029} \"\\' */ alert(1) // &amp;";
        let hdr = format!("// @name {evil}\n// @namespace {evil}\n// @version {evil}\n// @description {evil}\n// @author {evil}\n// @match *://*/*\n// @grant GM_getValue\n// @grant GM_getResourceText\n// @resource r https://x/{evil}\n// @connect {evil}");
        let mut s = us(&hdr, "ok();");
        s.assets.resources.push(crate::script::ResourceBlob {
            name: "r".into(),
            url: "https://x/r".into(),
            mime: "text/plain".into(),
            data_b64: "PC9zY3JpcHQ+PCEtLQ==".into(),
        }); // "</script><!--"
        let idx = compile(vec![s]);
        let key = TokenKey::new(vec![1; 32]);
        let mut vals = HashMap::new();
        let mut m = Map::new();
        m.insert(evil.to_string(), json!(evil));
        vals.insert(idx.iter().next().unwrap().script.id.clone(), m);
        // The descriptor (everything but the raw script source) must hold no breakout sequence.
        let entry = entry_js(idx.iter().next().unwrap(), &opts(&key, &vals));
        let desc = &entry[3..entry.find(",f:function").unwrap()];
        for bad in ["</script", "<!--", "\u{2028}", "\u{2029}", "<", ">"] {
            assert!(!desc.contains(bad), "descriptor contains {bad:?}");
        }
        assert!(desc.contains("\\u003c/script\\u003e\\u003c!--"));
        assert!(desc.contains("\\u2028"));
        // and it is still valid JSON that round-trips to the original values
        let v: Value = serde_json::from_str(desc).unwrap();
        assert_eq!(v["name"], evil);
        assert_eq!(v["values"][evil], evil);
        assert_eq!(v["meta"]["description"], evil);
        assert_eq!(v["resources"]["r"]["text"], "</script><!--");
    }

    #[test]
    fn js_json_escapes() {
        let s = js_json(&json!({"a": "</script><!--\u{2028}&"}));
        assert_eq!(
            s,
            "{\"a\":\"\\u003c/script\\u003e\\u003c!--\\u2028\\u0026\"}"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&s).unwrap()["a"],
            "</script><!--\u{2028}&"
        );
    }

    #[test]
    fn token_in_bundle_verifies() {
        let idx = compile(vec![us(
            "// @name T\n// @version 2\n// @grant GM_getValue\n// @connect a.com",
            "",
        )]);
        let cs = idx.iter().next().unwrap();
        let key = TokenKey::new(vec![9; 32]);
        let vals = HashMap::new();
        let js = entry_js(cs, &opts(&key, &vals));
        let start = js.find("\"token\":\"").unwrap() + 9;
        let tok = &js[start..start + js[start..].find('"').unwrap()];
        assert_eq!(claimed_script_id(tok).as_deref(), Some(cs.id()));
        let caps = token::caps_hash(&cs.script.metadata, false);
        assert_eq!(
            verify(&key, tok, 1500, "p", "https://example.com", |_| Some(
                ScriptRecord {
                    version: "2",
                    caps_hash: &caps
                }
            ))
            .unwrap(),
            cs.id()
        );
        assert!(verify(&key, tok, 1500, "p", "https://evil.com", |_| Some(
            ScriptRecord {
                version: "2",
                caps_hash: &caps
            }
        ))
        .is_err());
        assert!(
            verify(&key, tok, 4601, "p", "https://example.com", |_| Some(
                ScriptRecord {
                    version: "2",
                    caps_hash: &caps
                }
            ))
            .is_err()
        );
    }

    #[test]
    fn runtime_implements_every_table_entry() {
        for (_, name) in API_TABLE {
            assert!(RUNTIME_JS.contains(name), "gm.js is missing {name}");
        }
    }

    #[test]
    fn inline_safety_flag() {
        let idx = compile(vec![us("// @name A", "var s = '</script>';")]);
        let (key, vals) = (TokenKey::new(vec![1; 32]), HashMap::new());
        let b = generate(&idx.iter().collect::<Vec<_>>(), &opts(&key, &vals));
        assert!(!b.inline_safe());
        let idx = compile(vec![us("// @name A", "var s = 1;")]);
        let b = generate(&idx.iter().collect::<Vec<_>>(), &opts(&key, &vals));
        assert!(
            b.inline_safe(),
            "the runtime itself must not contain breakout sequences"
        );
    }
}

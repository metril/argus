//! What we put into a page, and the shared body types.
//!
//! The per-page delta is small: an inline `<style>` (so hiding applies before first paint), a
//! non-executing JSON config block, and one or two same-origin external scripts under
//! `/__adblock__/`: the content-hashed, immutable `boot.js` and (only when the page has
//! scriptlets) a hash-addressed scriptlet bundle. The config is inline JSON because a
//! `<script type="application/json">` is not governed by `script-src`, and it saves a round
//! trip; scriptlets are code, so they must be an external script (or an inline script that a
//! strict CSP would block, or `eval`, which CSP forbids), and being hash-addressed they are
//! cached across pages that share them. Everything emitted here is pure ASCII so it is valid in
//! any ASCII-compatible document encoding.

use crate::internal::{boot_path, Internal};
use bytes::Bytes;
use filter_engine::Cosmetics;
use futures_util::StreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use std::fmt::Write as _;
use std::io;

/// Unified streaming response body used throughout the proxy.
///
/// `Unsync` because stream stages hold `Send`-only state; hyper only requires `Send`.
pub type ProxyBody = UnsyncBoxBody<Bytes, io::Error>;

/// A fresh 128-bit nonce, base64-encoded. Drawn from the thread-local CSPRNG (ChaCha12, seeded
/// from the OS and reseeded periodically), so no syscall per nonce.
pub fn new_nonce() -> String {
    use base64::Engine as _;
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Wrap a `Full` of bytes as a [`ProxyBody`].
pub fn full_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes).map_err(|e| match e {}).boxed_unsync()
}

/// Stream an upstream response body straight through (no buffering, original encoding preserved).
pub fn passthrough_body(resp: crate::upstream::UpstreamResponse) -> ProxyBody {
    let stream = resp.bytes_stream().map(|res| res.map(Frame::data));
    BodyExt::boxed_unsync(StreamBody::new(stream))
}

/// Procedural pseudo-classes that aren't valid CSS and must be evaluated in JS. Note `:has()` and
/// `:not()` are deliberately excluded: a plain one stays in the stylesheet (browsers support it
/// natively), and one that nests a procedural operator contains that operator's marker anyway.
const PROC_MARKERS: &[&str] = &[
    ":has-text(",
    ":matches-css(",
    ":matches-css-before(",
    ":matches-css-after(",
    ":matches-attr(",
    ":matches-path(",
    ":min-text-length(",
    ":upward(",
    ":xpath(",
    ":-abp-contains(",
    ":contains(",
    ":-abp-has(",
    ":-abp-properties(",
    ":properties(",
    ":matches-prop(",
    ":matches-property(",
    ":matches-media(",
    ":nth-ancestor(",
    ":if(",
    ":if-not(",
    ":shadow(",
    ":spath(",
    ":others(",
    ":watch-attr(",
    ":remove(",
    ":style(",
    ":remove-attr(",
    ":remove-class(",
];

/// Whether a selector contains a procedural pseudo-class (needs JS, not CSS).
fn is_procedural(sel: &str) -> bool {
    PROC_MARKERS.iter().any(|m| sel.contains(m))
}

/// Cheap sanity check of a plain selector before it is emitted as a CSS rule: brackets and
/// parentheses balanced (quotes and escapes honoured) and no `{`, `}` or `;` outside a string, so it
/// cannot end its own rule early. A selector the browser still rejects voids only its own rule.
fn selector_shape_ok(sel: &str) -> bool {
    let (mut paren, mut bracket) = (0i32, 0i32);
    let mut quote: Option<char> = None;
    let mut chars = sel.chars();
    if sel.trim().is_empty() || sel.contains("/*") || sel.contains("*/") {
        return false;
    }
    while let Some(c) = chars.next() {
        if c == '\\' {
            if chars.next().is_none() {
                return false; // a trailing escape would eat the rule's `{`
            }
            continue;
        }
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '(' => paren += 1,
            ')' => paren -= 1,
            '[' => bracket += 1,
            ']' => bracket -= 1,
            '{' | '}' | ';' => return false,
            _ => {}
        }
        if paren < 0 || bracket < 0 {
            return false;
        }
    }
    quote.is_none() && paren == 0 && bracket == 0
}

/// Every `:style(...)` argument embedded in selector text passes the style safety policy.
fn embedded_styles_safe(sel: &str) -> bool {
    let mut rest = sel;
    while let Some(i) = rest.find(":style(") {
        let body = &rest[i + ":style(".len()..];
        let mut depth = 1;
        let mut end = body.len();
        let mut esc = false;
        for (k, c) in body.char_indices() {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
                if depth == 0 {
                    end = k;
                    break;
                }
            }
        }
        if !ext_rules::is_safe_style(&body[..end]) {
            return false;
        }
        rest = &body[end..];
    }
    true
}

/// CSS text restricted to ASCII: anything else becomes a CSS escape (`\XX `), `<` included so the
/// text can never close the `<style>` element.
fn css_ascii(s: &str, out: &mut String) {
    for c in s.chars() {
        if c.is_ascii() && c != '<' && !c.is_ascii_control() {
            out.push(c);
        } else {
            let _ = write!(out, "\\{:x} ", c as u32);
        }
    }
}

/// JSON text restricted to ASCII with `<`, `>` and `&` escaped (safe inside `<script>`).
fn json_ascii(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        match c {
            '<' | '>' | '&' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c if c.is_ascii() => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{u:04x}");
                }
            }
        }
    }
    out
}

static UNSAFE_STYLES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn note_unsafe_style() {
    UNSAFE_STYLES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Style declarations dropped at delivery because they could load resources (engine
/// `:style()` results; ext-rule rejects are counted in the ext stats at build time).
pub fn unsafe_styles_dropped() -> u64 {
    UNSAFE_STYLES.load(std::sync::atomic::Ordering::Relaxed)
}

/// Inputs for [`build_head`].
pub struct PageSpec<'a> {
    /// Unregister the page's service workers at document start (see [`crate::gm`]).
    pub unregister_sw: bool,
    /// The service-worker guard applies to this document: the boot script carries `sw` even
    /// when nothing else needs it.
    pub sw_guard: bool,
    pub cosmetics: &'a Cosmetics,
    pub internal: &'a Internal,
    /// Host name the beacon token is bound to.
    pub host: &'a str,
    /// Per-response nonce put on our tags.
    pub nonce: &'a str,
    /// Scripts may be injected (no `sandbox` without `allow-scripts`).
    pub script_ok: bool,
    /// The class/id observer may call back (same-origin document, not generic-hide excepted).
    pub observer_ok: bool,
    /// Scripts from trusted extended rules (`#%#`, scriptlets, snippets): one hash-addressed
    /// bundle loaded after the boot script, which provides their runtime hook.
    pub ext_script: &'a str,
    /// Per-document userscript bundle URLs (see [`crate::gm`]), one classic synchronous
    /// `<script src>` each, after the blocker's own scripts so the page sees them first.
    pub userscripts: &'a [String],
    /// The in-page panel's hotkey (`[alt, ctrl, shift, meta, code]`), when the panel is on: the
    /// boot script then registers a key listener that loads the panel on first use.
    pub panel: Option<&'a serde_json::Value>,
    /// On-demand menu button for userscript menu commands: `"on_demand"` or `"always"`. Passed to
    /// the runtime script as `data-m`; only meaningful together with `userscripts`.
    pub menu: Option<&'a str>,
    /// The document is bound to a live browser-extension session: the runtime does not mount
    /// the in-page button and syncs its menu commands instead (`data-m="ext:<mode>"`).
    pub ext: bool,
}

/// The markup for one page, plus what it needs from the page's CSP.
#[derive(Debug, Clone, Default)]
pub struct PageHead {
    pub html: String,
    pub has_style: bool,
    pub has_script: bool,
    pub observer: bool,
}

/// Build the head injection for a page; empty (`html == ""`) when there is nothing to do.
pub fn build_head(spec: &PageSpec<'_>) -> PageHead {
    let cos = spec.cosmetics;
    let mut head = PageHead::default();
    let nonce = spec.nonce;

    // Plain CSS hides; procedural selectors need JS (mixed into CSS they would invalidate the
    // whole rule).
    let plain: Vec<&str> = cos
        .hide_selectors
        .iter()
        .map(String::as_str)
        .filter(|s| !is_procedural(s))
        .collect();
    if !plain.is_empty() {
        head.has_style = true;
        let _ = write!(
            head.html,
            "<style id=\"__adblock_cosmetic\" nonce=\"{nonce}\">"
        );
        let valid: Vec<&str> = plain
            .iter()
            .copied()
            .filter(|s| selector_shape_ok(s))
            .collect();
        let mut css = String::new();
        // One rule per selector: the browser drops a whole rule when any selector in its list
        // fails to parse. (Measured in Chrome: no slower than batches up to 10k selectors.)
        for sel in valid {
            css_ascii(sel, &mut css);
            css.push_str("{display:none!important}");
        }
        head.html.push_str(&css);
        head.html.push_str("</style>");
    }

    if spec.script_ok {
        let mut proc_items: Vec<serde_json::Value> = Vec::new();
        for sel in cos
            .hide_selectors
            .iter()
            .filter(|s| is_procedural(s) && embedded_styles_safe(s))
        {
            proc_items.push(serde_json::json!({ "s": sel, "a": "hide" }));
        }
        for raw in &cos.procedural_actions {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
                // The whole operator array goes to the in-page engine, which applies the
                // operators in order, with the action last.
                let ops: Vec<serde_json::Value> = v["selector"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter(|o| o["type"].is_string())
                            .map(|o| {
                                serde_json::json!({
                                    "type": o["type"],
                                    "arg": o.get("arg").cloned().unwrap_or_default(),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                if ops.is_empty()
                    || ops
                        .iter()
                        .any(|o| o["arg"].as_str().is_some_and(|a| !embedded_styles_safe(a)))
                {
                    if !ops.is_empty() {
                        note_unsafe_style();
                    }
                    continue;
                }
                let act = v["action"]["type"].as_str().unwrap_or("hide");
                let arg = v["action"]["arg"].as_str().unwrap_or("");
                // Whatever list or engine produced it, a style block is judged here, last.
                if act == "style" && !ext_rules::is_safe_style(arg) {
                    note_unsafe_style();
                    continue;
                }
                proc_items.push(serde_json::json!({ "o": ops, "a": act, "g": arg }));
            }
        }
        let observer = spec.observer_ok && !cos.generichide;
        let scriptlet = (!cos.injected_script.is_empty()).then(|| {
            spec.internal
                .put_scriptlet(&wrap_scriptlets(&cos.injected_script))
        });

        // Scriptlets first: they must run before any page script.
        if let Some(path) = &scriptlet {
            let _ = write!(
                head.html,
                "<script src=\"{path}\" nonce=\"{nonce}\"></script>"
            );
            head.has_script = true;
        }
        if observer
            || !proc_items.is_empty()
            || !spec.ext_script.is_empty()
            || spec.panel.is_some()
            || spec.sw_guard
        {
            let mut cfg = serde_json::json!({
                "p": proc_items,
                "o": observer,
                "t": spec.internal.token_for(spec.host),
            });
            if spec.unregister_sw {
                cfg["sw"] = serde_json::Value::from(1);
            }
            if let Some(k) = spec.panel {
                cfg["k"] = k.clone();
                cfg["pn"] = serde_json::Value::String(crate::internal::panel_path().to_string());
            }
            let json = json_ascii(&cfg.to_string());
            let _ = write!(
                head.html,
                "<script type=\"application/json\" id=\"__ab_cfg\">{json}</script>\
                 <script src=\"{}\" nonce=\"{nonce}\"></script>",
                boot_path()
            );
            head.has_script = true;
            head.observer = observer;
            if !spec.ext_script.is_empty() {
                let path = spec.internal.put_scriptlet(spec.ext_script);
                let _ = write!(
                    head.html,
                    "<script src=\"{path}\" nonce=\"{nonce}\"></script>"
                );
            }
        }
        if !spec.userscripts.is_empty() {
            // The runtime once, before any bundle (bundles carry no runtime of their own).
            let m = match (spec.ext, spec.menu) {
                (true, Some("always")) => " data-m=\"ext:always\"",
                (true, Some(_)) => " data-m=\"ext:on_demand\"",
                (true, None) => " data-m=\"ext:off\"",
                (false, Some("always")) => " data-m=\"always\"",
                (false, Some(_)) => " data-m=\"on_demand\"",
                (false, None) => "",
            };
            let _ = write!(
                head.html,
                "<script src=\"{}\" nonce=\"{nonce}\"{m}></script>",
                crate::internal::gm_runtime_path()
            );
            head.has_script = true;
        }
        for src in spec.userscripts {
            let _ = write!(
                head.html,
                "<script src=\"{src}\" nonce=\"{nonce}\"></script>"
            );
            head.has_script = true;
        }
    }
    head
}

/// Run the engine's scriptlet bundle in a private function scope that provides uBO's
/// `scriptletGlobals` (state shared by the page's scriptlets; `safeSelf` and others read it and
/// throw without it). The scope also keeps the helper functions (`safeSelf`, `setConstant`, ...)
/// off the page's global object.
fn wrap_scriptlets(js: &str) -> String {
    format!("(function(){{\nconst scriptletGlobals = {{}};\n{js}\n}})();")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_mode_rides_on_the_runtime_tag() {
        let (cos, internal) = (Cosmetics::default(), Internal::default());
        let srcs = vec!["/__adblock__/gm/u1.js".to_string()];
        let mut s = spec(&cos, &internal);
        s.userscripts = &srcs;
        assert!(!build_head(&s).html.contains("data-m"));
        s.menu = Some("always");
        let h = build_head(&s).html;
        assert!(h.contains("nonce=\"NONCE\" data-m=\"always\""), "{h}");
        assert!(!h.contains("menu."), "no separate menu script");
        s.userscripts = &[];
        assert!(
            !build_head(&s).html.contains("data-m"),
            "never without userscripts"
        );
    }

    #[test]
    fn a_document_bound_to_an_extension_session_is_marked_ext() {
        let (cos, internal) = (Cosmetics::default(), Internal::default());
        let srcs = vec!["/__adblock__/gm/u1.js".to_string()];
        let mut s = spec(&cos, &internal);
        s.userscripts = &srcs;
        s.ext = true;
        s.menu = Some("on_demand");
        let h = build_head(&s).html;
        assert!(
            h.contains("nonce=\"NONCE\" data-m=\"ext:on_demand\""),
            "{h}"
        );
        s.menu = Some("always");
        assert!(build_head(&s).html.contains("data-m=\"ext:always\""));
        s.menu = None;
        assert!(build_head(&s).html.contains("data-m=\"ext:off\""));
        // the same document without a bound session has none of it
        s.ext = false;
        assert!(!build_head(&s).html.contains("ext:"));
        s.userscripts = &[];
        s.ext = true;
        assert!(
            !build_head(&s).html.contains("data-m"),
            "never without userscripts"
        );
    }

    #[test]
    fn scriptlets_get_a_private_scope_with_scriptlet_globals() {
        let w = wrap_scriptlets("a();");
        assert!(w.starts_with("(function(){"));
        assert!(w.contains("const scriptletGlobals = {};"));
        assert!(w.trim_end().ends_with("})();"));
    }

    fn spec<'a>(cos: &'a Cosmetics, internal: &'a Internal) -> PageSpec<'a> {
        PageSpec {
            unregister_sw: false,
            sw_guard: false,
            cosmetics: cos,
            internal,
            host: "example.test",
            nonce: "NONCE",
            script_ok: true,
            observer_ok: true,
            ext_script: "",
            userscripts: &[],
            panel: None,
            menu: None,
            ext: false,
        }
    }

    #[test]
    fn head_has_style_config_and_boot() {
        let i = Internal::new();
        let cos = Cosmetics {
            hide_selectors: vec![".ad".into(), "#banner".into()],
            ..Default::default()
        };
        let h = build_head(&spec(&cos, &i));
        assert!(h
            .html
            .contains(".ad{display:none!important}#banner{display:none!important}"));
        assert!(h
            .html
            .contains("<style id=\"__adblock_cosmetic\" nonce=\"NONCE\">"));
        assert!(h.html.contains("id=\"__ab_cfg\""));
        assert!(h
            .html
            .contains(&format!("src=\"{}\" nonce=\"NONCE\"", boot_path())));
        assert!(h.has_style && h.has_script && h.observer);
        assert!(h.html.is_ascii());
    }

    #[test]
    fn head_empty_when_nothing_to_do() {
        let i = Internal::new();
        let cos = Cosmetics {
            generichide: true,
            ..Default::default()
        };
        assert!(build_head(&spec(&cos, &i)).html.is_empty());
    }

    #[test]
    fn script_not_emitted_when_not_allowed() {
        let i = Internal::new();
        let cos = Cosmetics {
            hide_selectors: vec![".ad".into(), ".b:has-text(x)".into()],
            injected_script: "alert(1)".into(),
            ..Default::default()
        };
        let mut s = spec(&cos, &i);
        s.script_ok = false;
        let h = build_head(&s);
        assert!(h.html.contains("<style"));
        assert!(!h.html.contains("<script"));
        assert!(!h.has_script);
    }

    #[test]
    fn procedural_selector_kept_out_of_stylesheet() {
        let i = Internal::new();
        let cos = Cosmetics {
            hide_selectors: vec![".real-ad".into(), ".box:has-text(Sponsored)".into()],
            generichide: true,
            ..Default::default()
        };
        let h = build_head(&spec(&cos, &i)).html;
        assert!(h.contains(".real-ad{display:none!important}"));
        assert!(!h.contains("<style id=\"__adblock_cosmetic\" nonce=\"NONCE\">.box:has-text"));
        assert!(h.contains(r#""s":".box:has-text(Sponsored)""#));
        assert!(h.contains(r#""a":"hide""#));
    }

    #[test]
    fn action_filters_parsed() {
        let i = Internal::new();
        let cos = Cosmetics {
            procedural_actions: vec![
                r#"{"selector":[{"type":"css-selector","arg":".ad:has-text(Ad)"}],"action":{"type":"remove"}}"#.to_string(),
            ],
            generichide: true,
            ..Default::default()
        };
        let h = build_head(&spec(&cos, &i)).html;
        assert!(
            h.contains(r#""o":[{"arg":".ad:has-text(Ad)","type":"css-selector"}]"#),
            "{h}"
        );
        assert!(h.contains(r#""a":"remove""#));
    }

    #[test]
    fn every_operator_reaches_the_engine_and_the_base_css_is_not_hidden() {
        let i = Internal::new();
        let act = |ty: &str, arg: &str| {
            serde_json::json!({"selector":[
                {"type":"css-selector","arg":".ad"},
                {"type":"has-text","arg":"Sponsored"},
                {"type":"upward","arg":"2"}],
                "action":{"type":ty,"arg":arg}})
            .to_string()
        };
        for (ty, arg) in [("remove", ""), ("style", "color: red")] {
            let cos = Cosmetics {
                procedural_actions: vec![act(ty, arg)],
                generichide: true,
                ..Default::default()
            };
            let h = build_head(&spec(&cos, &i)).html;
            // All three operators and the action are in the config, in order...
            let cfg = h
                .split("id=\"__ab_cfg\">")
                .nth(1)
                .and_then(|r| r.split("</script>").next())
                .expect("cfg block");
            let v: serde_json::Value = serde_json::from_str(cfg).unwrap();
            let it = &v["p"][0];
            let types: Vec<&str> = it["o"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| o["type"].as_str().unwrap())
                .collect();
            assert_eq!(types, ["css-selector", "has-text", "upward"], "{h}");
            assert_eq!(it["a"], ty);
            // ...and the base selector is never emitted as a stylesheet hide.
            assert!(
                !h.contains("<style"),
                "base CSS must not hide every .ad: {h}"
            );
            assert!(!h.contains("display:none"), "{h}");
        }
    }

    #[test]
    fn nested_and_extended_operators_are_routed_to_the_engine_not_to_css() {
        let i = Internal::new();
        let sels = [
            "div:has(> a:has-text(X))",
            ".a:not(:has-text(Y))",
            ".b:matches-prop(x=1)",
            ".c:others()",
            ".d:watch-attr(class)",
            ".e:matches-media(print)",
            ".f:nth-ancestor(2)",
            ".g:remove()",
            ".h:style(color: red)",
            ".k:remove-attr(x)",
            ".l:shadow(.x)",
            ".m:spath(> b)",
            ".n:-abp-has(.z)",
        ];
        let cos = Cosmetics {
            hide_selectors: sels
                .iter()
                .map(|s| s.to_string())
                .chain([".plain".to_string(), "a:has(.ok)".to_string()])
                .collect(),
            generichide: true,
            ..Default::default()
        };
        let h = build_head(&spec(&cos, &i)).html;
        let style = h.split("</style>").next().unwrap();
        assert_eq!(
            style.matches("{display:none!important}").count(),
            2,
            "only the two plain selectors are CSS: {style}"
        );
        assert!(style.contains(".plain{") && style.contains("a:has(.ok){"));
        assert_eq!(h.matches("\"a\":\"hide\"").count(), sels.len(), "{h}");
    }

    #[test]
    fn one_bad_selector_voids_only_its_own_rule() {
        let i = Internal::new();
        let cos = Cosmetics {
            hide_selectors: vec![
                ".a".into(),
                "div[unclosed".into(),
                ".b{color:red}".into(),
                ".c(".into(),
                "".into(),
                "[title=\"a]b\"]".into(),
                ".d".into(),
            ],
            generichide: true,
            ..Default::default()
        };
        let h = build_head(&spec(&cos, &i)).html;
        // one rule per selector, so a selector the browser rejects cannot take the others down
        assert!(h.contains(".a{display:none!important}"), "{h}");
        assert!(h.contains(".d{display:none!important}"), "{h}");
        assert!(h.contains("[title=\"a]b\"]{display:none!important}"), "{h}");
        assert!(
            !h.contains("unclosed") && !h.contains("color:red") && !h.contains(".c("),
            "{h}"
        );
        assert!(!h.contains(".a,"), "selectors must not share a rule: {h}");
    }

    #[test]
    fn hostile_selector_shapes_are_dropped() {
        let i = Internal::new();
        let cos = Cosmetics {
            hide_selectors: vec![
                ".ok".into(),
                ".a/*".into(),
                "*/.b".into(),
                ".c\\".into(),
                ".d".into(),
            ],
            generichide: true,
            ..Default::default()
        };
        let h = build_head(&spec(&cos, &i)).html;
        assert!(h.contains(".ok{") && h.contains(".d{"), "{h}");
        assert!(
            !h.contains("/*") && !h.contains("*/") && !h.contains(".c"),
            "{h}"
        );
    }

    #[test]
    fn embedded_unsafe_styles_never_reach_the_page() {
        let i = Internal::new();
        let act = |sel: &str| {
            serde_json::json!({"selector":[{"type":"css-selector","arg":sel}],"action":{"type":"hide"}})
                .to_string()
        };
        let cos = Cosmetics {
            hide_selectors: vec![
                "a:style(background: url(http://evil.test/1))".into(),
                "b:style(color: red; /*)".into(),
                "u:style(color: red)".into(),
            ],
            procedural_actions: vec![
                act("i:style(background:image-set('http://evil.test/2' 1x))"),
                act("s:has-text(x):style(@import 'z')"),
                act("q:style(margin: 0)"),
            ],
            generichide: true,
            ..Default::default()
        };
        let h = build_head(&spec(&cos, &i)).html;
        assert!(
            !h.contains("evil.test") && !h.contains("/*") && !h.contains("@import"),
            "{h}"
        );
        assert!(
            h.contains("u:style(color: red)") && h.contains("q:style(margin: 0)"),
            "{h}"
        );
    }

    #[test]
    fn one_rule_per_selector_stays_bounded_at_50k_selectors() {
        let i = Internal::new();
        let cos = Cosmetics {
            hide_selectors: (0..50_000)
                .map(|n| format!(".ad-c{n}-x .item_{}>a[href*=\"t{n}\"]", n % 97))
                .collect(),
            generichide: true,
            ..Default::default()
        };
        let t = std::time::Instant::now();
        let h = build_head(&spec(&cos, &i)).html;
        let took = t.elapsed();
        eprintln!("50k selectors: head {} bytes, built in {took:?}", h.len());
        assert_eq!(h.matches("{display:none!important}").count(), 50_000);
        assert!(h.len() < 4 << 20, "{}", h.len());
        assert!(took < std::time::Duration::from_secs(2), "{took:?}");
    }

    #[test]
    fn engine_and_config_run_synchronously_with_the_nonce_before_page_scripts() {
        let i = Internal::new();
        let cos = Cosmetics {
            hide_selectors: vec![".x:has-text(Ad)".into()],
            generichide: true,
            ..Default::default()
        };
        let h = build_head(&spec(&cos, &i)).html;
        // a classic, non-async, nonce-carrying external script: it runs when parsed, before any
        // later page script, and a strict `script-src 'nonce-..'` admits it
        let tag = h.split("<script src=").nth(1).expect("boot tag");
        assert!(tag.contains("nonce=\"NONCE\""), "{h}");
        assert!(
            !tag.contains("async") && !tag.contains("defer") && !tag.contains("type=\"module\"")
        );
        assert!(h.find("__ab_cfg").unwrap() < h.find("<script src=").unwrap());
        assert!(crate::internal::boot_script().contains("function argusProceduralEngine"));
    }

    #[test]
    fn scriptlet_is_external_and_first() {
        let i = Internal::new();
        let cos = Cosmetics {
            hide_selectors: vec![".ad".into()],
            injected_script: "window.x=1;</script><b>".into(),
            ..Default::default()
        };
        let h = build_head(&spec(&cos, &i)).html;
        assert!(
            !h.contains("window.x"),
            "scriptlet code must not be inlined"
        );
        let s = h.find("/__adblock__/s/").expect("scriptlet tag");
        let b = h.find("/__adblock__/boot.").expect("boot tag");
        assert!(s < b);
    }

    #[test]
    fn hostile_selectors_cannot_break_out() {
        let i = Internal::new();
        let cos = Cosmetics {
            hide_selectors: vec!["a</style><script>x()</script>".into(), "[title=\"\u{5e7f}\"]".into()],
            procedural_actions: vec![
                r#"{"selector":[{"type":"css-selector","arg":"</script><b>:has-text(é)"}],"action":{"type":"hide"}}"#.to_string(),
            ],
            ..Default::default()
        };
        let h = build_head(&spec(&cos, &i)).html;
        assert!(h.is_ascii(), "{h}");
        assert_eq!(h.matches("</style>").count(), 1);
        assert_eq!(h.matches("</script>").count(), 2, "only our own tags: {h}");
        assert!(!h.contains("x()</script>"));
    }

    #[test]
    fn unsafe_style_actions_never_reach_the_page() {
        let i = Internal::new();
        let act = |css: &str| {
            serde_json::json!({"selector":[{"type":"css-selector","arg":"body"}],
                "action":{"type":"style","arg":css}})
            .to_string()
        };
        let cos = Cosmetics {
            procedural_actions: vec![
                act("background: url(http://evil.test/x)"),
                act("background:image-set('http://evil.test/y' 1x)"),
                act("color: red; @import 'z'"),
                act("display: none !important"),
            ],
            generichide: true,
            ..Default::default()
        };
        let h = build_head(&spec(&cos, &i)).html;
        assert!(!h.contains("evil.test") && !h.contains("@import"), "{h}");
        assert!(h.contains("display: none !important"), "{h}");
    }
}

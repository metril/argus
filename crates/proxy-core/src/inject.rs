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

/// A fresh 128-bit nonce from the OS CSPRNG, base64-encoded.
pub fn new_nonce() -> String {
    use base64::Engine as _;
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Wrap a `Full` of bytes as a [`ProxyBody`].
pub fn full_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes).map_err(|e| match e {}).boxed_unsync()
}

/// Stream a reqwest response body straight through (no buffering, original encoding preserved).
pub fn passthrough_body(resp: reqwest::Response) -> ProxyBody {
    let stream = resp
        .bytes_stream()
        .map(|res| res.map(Frame::data).map_err(io::Error::other));
    BodyExt::boxed_unsync(StreamBody::new(stream))
}

/// Procedural pseudo-classes that aren't valid CSS and must be evaluated in JS. Note `:has()` is
/// deliberately excluded: modern browsers support it natively, so it stays in the stylesheet.
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
];

/// Whether a selector contains a procedural pseudo-class (needs JS, not CSS).
fn is_procedural(sel: &str) -> bool {
    PROC_MARKERS.iter().any(|m| sel.contains(m))
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
        let mut css = String::new();
        css_ascii(&plain.join(","), &mut css);
        head.html.push_str(&css);
        head.html.push_str("{display:none!important}</style>");
    }

    if spec.script_ok {
        let mut proc_items: Vec<serde_json::Value> = Vec::new();
        for sel in cos.hide_selectors.iter().filter(|s| is_procedural(s)) {
            proc_items.push(serde_json::json!({ "s": sel, "a": "hide" }));
        }
        for raw in &cos.procedural_actions {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
                let sel = v["selector"]
                    .get(0)
                    .and_then(|s| s["arg"].as_str())
                    .unwrap_or("");
                if sel.is_empty() {
                    continue;
                }
                let act = v["action"]["type"].as_str().unwrap_or("hide");
                let arg = v["action"]["arg"].as_str().unwrap_or("");
                // Whatever list or engine produced it, a style block is judged here, last.
                if act == "style" && !ext_rules::is_safe_style(arg) {
                    note_unsafe_style();
                    continue;
                }
                proc_items.push(serde_json::json!({ "s": sel, "a": act, "g": arg }));
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
        if observer || !proc_items.is_empty() || !spec.ext_script.is_empty() {
            let cfg = serde_json::json!({
                "p": proc_items,
                "o": observer,
                "t": spec.internal.token_for(spec.host),
            });
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
    fn scriptlets_get_a_private_scope_with_scriptlet_globals() {
        let w = wrap_scriptlets("a();");
        assert!(w.starts_with("(function(){"));
        assert!(w.contains("const scriptletGlobals = {};"));
        assert!(w.trim_end().ends_with("})();"));
    }

    fn spec<'a>(cos: &'a Cosmetics, internal: &'a Internal) -> PageSpec<'a> {
        PageSpec {
            cosmetics: cos,
            internal,
            host: "example.test",
            nonce: "NONCE",
            script_ok: true,
            observer_ok: true,
            ext_script: "",
            userscripts: &[],
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
        assert!(h.html.contains(".ad,#banner{display:none!important}"));
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
        assert!(h.contains(r#""s":".ad:has-text(Ad)""#));
        assert!(h.contains(r#""a":"remove""#));
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

//! Small built-in set of uBlock-compatible `$redirect` resources, so redirects work offline.
//!
//! A loaded resource library (see `SharedEngine::set_resources_from_json`) overrides these by name.

use adblock::resources::Resource;
use base64::Engine as _;

const GIF_1X1: &str = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
const PNG_1X1: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
/// Smallest MP3 frame header + padding (silent).
const MP3_SILENT: &[u8] = &[0xff, 0xfb, 0x10, 0xc4, 0, 0, 0, 0];

fn res(name: &str, aliases: &[&str], mime: &str, content_b64: String) -> Resource {
    serde_json::from_value(serde_json::json!({
        "name": name,
        "aliases": aliases,
        "kind": {"mime": mime},
        "content": content_b64,
    }))
    .expect("built-in resource is valid")
}

fn text(name: &str, aliases: &[&str], mime: &str, body: &str) -> Resource {
    res(
        name,
        aliases,
        mime,
        base64::engine::general_purpose::STANDARD.encode(body),
    )
}

/// The built-in redirect resources (noop.js, noop.css, noopframe, 1x1.gif, ...).
pub fn builtin_redirect_resources() -> Vec<Resource> {
    vec![
        text(
            "noop.js",
            &["noopjs"],
            "application/javascript",
            "(function(){})();",
        ),
        text("noop.css", &["noopcss"], "text/css", ""),
        text(
            "noop.html",
            &["noopframe"],
            "text/html",
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head><body></body></html>",
        ),
        text("noop.txt", &["nooptext"], "text/plain", ""),
        text("noop.json", &["noopjson"], "application/json", "{}"),
        text(
            "noop-vmap1.0.xml",
            &["noopvmap-1.0"],
            "text/xml",
            "<VMAP version=\"1.0\"/>",
        ),
        res(
            "1x1.gif",
            &["1x1-transparent.gif"],
            "image/gif",
            GIF_1X1.into(),
        ),
        res(
            "1x1.png",
            &[
                "2x2.png",
                "2x2-transparent.png",
                "3x2.png",
                "3x2-transparent.png",
                "32x32.png",
                "32x32-transparent.png",
            ],
            "image/png",
            PNG_1X1.into(),
        ),
        res(
            "noop-0.1s.mp3",
            &["noopmp3-0.1s"],
            "audio/mp3",
            base64::engine::general_purpose::STANDARD.encode(MP3_SILENT),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_parse() {
        assert!(builtin_redirect_resources().len() >= 8);
    }
}

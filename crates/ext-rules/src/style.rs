//! Validation of cosmetic style declarations (`#$#`, `#$?#`, `:style(...)`).
//!
//! A style block that reaches a page's `cssText` must not be able to fetch anything or break out
//! of the declaration list, so (as uBlock Origin does for every list, trusted or not) it is
//! refused when it contains a URL-capable function, an at-rule, a comment, an escape, a block
//! delimiter or a legacy script hook.

/// Longest accepted declaration block.
const MAX_STYLE_LEN: usize = 2048;

/// Functions that can load a resource (CSS `<image>` producers and `attr()` typed as a URL).
const FETCHING_FUNCTIONS: &[&str] = &[
    "url",
    "image-set",
    "src",
    "image",
    "cross-fade",
    "element",
    "paint",
    "attr",
    "expression",
];

/// Is `css` (a `prop: value; prop: value` list) safe to hand to a page?
pub fn is_safe_style(css: &str) -> bool {
    if css.len() > MAX_STYLE_LEN || css.chars().any(|c| c.is_control() && c != '\t') {
        return false;
    }
    if css.contains(['\\', '{', '}', '@', '<']) || css.contains("/*") || css.contains("*/") {
        return false;
    }
    let lower = css.to_ascii_lowercase();
    if lower.contains("-moz-binding") || lower.contains("behavior") {
        return false;
    }
    // `name(` with optional whitespace before the parenthesis, at any identifier boundary.
    for name in FETCHING_FUNCTIONS {
        let mut from = 0;
        while let Some(i) = lower[from..].find(name) {
            let end = from + i + name.len();
            if lower[end..].trim_start().starts_with('(') {
                return false;
            }
            from = end;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::is_safe_style;

    #[test]
    fn accepts_plain_declarations() {
        assert!(is_safe_style("display: none !important"));
        assert!(is_safe_style("color: red; margin: 0 auto"));
        assert!(is_safe_style(
            "background: rgb(1, 2, 3) linear-gradient(red, blue)"
        ));
        assert!(is_safe_style("content: \"a\""));
    }

    #[test]
    fn rejects_fetching_and_breakout() {
        for bad in [
            "background:url(x)",
            "background: URL (x)",
            "x: image-set(y)",
            "x: -webkit-image-set(y)",
            "color:red;@import x",
            "x: expression(1)",
            "a: b\\\n",
            "a: b /* c */",
            "a: b}",
            "a: b{",
        ] {
            assert!(!is_safe_style(bad), "{bad}");
        }
    }
}

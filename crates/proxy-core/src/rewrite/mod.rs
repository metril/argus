//! The response-rewriting pipeline.
//!
//! ```text
//! upstream bytes ─ decode (gzip/deflate/br/zstd, stacked, in order)
//!                ─ peek (sniff + charset)  ── not HTML / not decodable ─▶ original bytes, untouched
//!                ─ charset handling ─ lol_html transforms ─ re-encode ─▶ client
//! ```
//!
//! Every stage is a pull-driven stream over fixed-size windows, so backpressure reaches the
//! upstream socket and dropping the client body drops the upstream read.
//!
//! # Plug point
//!
//! A [`TransformSource`] (installed with `ProxyContext::set_transform_source`) is asked once per
//! response for a [`ResponseTransforms`]; the pipeline applies whatever is present. The built-in
//! cosmetic injection is independent of it.

pub mod charset;
pub mod codec;
pub mod html;
pub mod pipeline;

#[cfg(test)]
mod stage_tests;

use crate::request_type::RequestType;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::StatusCode;
use std::sync::Arc;

/// Where an [`Injection`] goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectPos {
    /// Immediately after `<head>` opens (before the built-in injection).
    HeadStart,
    /// Before `</head>` (only when the document has that end tag).
    HeadEnd,
    /// Immediately after `<body>` opens.
    BodyStart,
    /// Before `</body>` (only when the document has that end tag).
    BodyEnd,
}

/// Extra markup to insert into an HTML document.
#[derive(Debug, Clone)]
pub struct Injection {
    pub pos: InjectPos,
    /// HTML. Must be ASCII for non-UTF-8 documents to stay byte-exact (non-ASCII is encoded by
    /// the rewriter but may not be representable in the document's charset).
    pub html: String,
}

/// A text-node replacement for HTML documents (`$replace` against markup text).
#[derive(Debug, Clone)]
pub struct TextReplacement {
    /// Only text inside elements matching this CSS selector; `None` for every text node outside
    /// `<script>`/`<style>`.
    pub selector: Option<String>,
    pub find: regex::Regex,
    pub replace: String,
}

/// An edit to the response headers (applied whether or not the body is touched).
#[derive(Debug, Clone)]
pub enum HeaderEdit {
    Set(HeaderName, HeaderValue),
    Append(HeaderName, HeaderValue),
    Remove(HeaderName),
}

/// Whole-body transform for non-HTML responses (JSON, JavaScript, text). The body is buffered
/// up to [`BodyTransform::max_body_bytes`]; larger bodies are passed through untouched.
pub trait BodyTransform: Send + Sync {
    /// Largest decoded body to buffer.
    fn max_body_bytes(&self) -> usize {
        4 * 1024 * 1024
    }
    /// Whether to look at a body with this (lowercased, parameter-free) media type.
    fn applies_to(&self, media_type: &str) -> bool {
        media_type == "application/json"
            || media_type.ends_with("+json")
            || media_type == "application/javascript"
            || media_type == "text/javascript"
            || media_type == "text/plain"
    }
    /// `Some(new_body)` to replace the body, `None` to leave it as it was. The input is UTF-8 or
    /// whatever bytes the origin sent; honour the response's charset yourself if it matters.
    fn apply(&self, body: &[u8]) -> Option<Vec<u8>>;
}

/// Everything to do to one response, computed once from the request URL, type and headers.
#[derive(Default, Clone)]
pub struct ResponseTransforms {
    /// Elements to delete from HTML documents (HTML filters, `##^`).
    pub remove_selectors: Vec<String>,
    /// Text replacements in HTML text nodes.
    pub text_replacements: Vec<TextReplacement>,
    /// Header edits.
    pub header_edits: Vec<HeaderEdit>,
    /// Extra injections into HTML documents.
    pub injections: Vec<Injection>,
    /// Transform for non-HTML bodies.
    pub body: Option<Arc<dyn BodyTransform>>,
}

impl ResponseTransforms {
    pub fn is_empty(&self) -> bool {
        self.remove_selectors.is_empty()
            && self.text_replacements.is_empty()
            && self.header_edits.is_empty()
            && self.injections.is_empty()
            && self.body.is_none()
    }

    /// Whether any HTML-body work is requested.
    pub fn touches_html(&self) -> bool {
        !self.remove_selectors.is_empty()
            || !self.text_replacements.is_empty()
            || !self.injections.is_empty()
    }
}

/// What a [`TransformSource`] sees of the exchange.
pub struct ResponseInfo<'a> {
    pub url: &'a str,
    pub request_type: RequestType,
    pub status: StatusCode,
    pub request_headers: &'a HeaderMap,
    pub response_headers: &'a HeaderMap,
}

/// Supplies [`ResponseTransforms`] per response (implemented by the extended-rules crate).
pub trait TransformSource: Send + Sync {
    /// Called once per response, before any body byte is read. `None` means nothing to do.
    fn transforms_for(&self, info: &ResponseInfo<'_>) -> Option<ResponseTransforms>;
}

/// Adapts the `content` of a meta CSP; `None` means unchanged.
pub type MetaCsp = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The HTML-body work for one response, resolved by the caller.
#[derive(Clone, Default)]
pub struct HtmlPlan {
    /// Our own markup, inserted right after `<head>` (or before the first element).
    pub head_html: String,
    pub injections: Vec<Injection>,
    pub remove_selectors: Vec<String>,
    pub replacements: Vec<TextReplacement>,
    /// Adapts `<meta http-equiv="content-security-policy">` content; `None` return = unchanged.
    pub meta_csp: Option<MetaCsp>,
}

impl HtmlPlan {
    pub fn is_empty(&self) -> bool {
        self.head_html.is_empty()
            && self.injections.is_empty()
            && self.remove_selectors.is_empty()
            && self.replacements.is_empty()
    }
}

/// Classification of a response body for rewriting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    Html,
    Other,
    None,
}

/// Decide from the request type, status, method and headers whether the body may be rewritten as
/// an HTML document; `Other` (any rewritable non-HTML type) is left to the text slot.
pub fn classify_body(
    is_head: bool,
    status: StatusCode,
    request_type: RequestType,
    response_headers: &HeaderMap,
) -> BodyKind {
    let code = status.as_u16();
    // Never touch 1xx/204/205/206/304 or redirects; error pages (4xx/5xx) may be HTML documents.
    if is_head || code < 200 || (300..400).contains(&code) || matches!(code, 204 | 205 | 206) {
        return BodyKind::None;
    }
    if response_headers
        .get(hyper::header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim_start().to_ascii_lowercase().starts_with("attachment"))
    {
        return BodyKind::None;
    }
    // Content-Range on a non-206 would be odd; be conservative.
    if response_headers.contains_key(hyper::header::CONTENT_RANGE) {
        return BodyKind::None;
    }
    let Some(media) = media_type(response_headers) else {
        return BodyKind::None;
    };
    if media == "text/html" {
        // Only documents: navigations and frames. XHR/fetch/script/etc. responses are left alone.
        if request_type.is_frame() {
            BodyKind::Html
        } else {
            BodyKind::Other
        }
    } else {
        BodyKind::Other
    }
}

/// Lowercased media type of the response, without parameters.
pub fn media_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(|m| m.trim().to_ascii_lowercase())
        .filter(|m| !m.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn classification_table() {
        use BodyKind::*;
        let html = [("content-type", "text/html; charset=utf-8")];
        let cases: &[(bool, u16, RequestType, &[(&str, &str)], BodyKind)] = &[
            (false, 200, RequestType::Document, &html, Html),
            (false, 200, RequestType::Subdocument, &html, Html),
            (false, 404, RequestType::Document, &html, Html),
            (false, 200, RequestType::Xhr, &html, Other),
            (false, 200, RequestType::Script, &html, Other),
            (true, 200, RequestType::Document, &html, None),
            (false, 204, RequestType::Document, &html, None),
            (false, 206, RequestType::Document, &html, None),
            (false, 304, RequestType::Document, &html, None),
            (false, 301, RequestType::Document, &html, None),
            (
                false,
                200,
                RequestType::Document,
                &[
                    ("content-type", "text/html"),
                    ("content-disposition", "attachment; filename=a.html"),
                ],
                None,
            ),
            (
                false,
                200,
                RequestType::Document,
                &[("content-type", "application/json")],
                Other,
            ),
            (false, 200, RequestType::Document, &[], None),
        ];
        for (head, status, ty, hdrs, want) in cases {
            assert_eq!(
                classify_body(*head, StatusCode::from_u16(*status).unwrap(), *ty, &hm(hdrs)),
                *want,
                "{head} {status} {ty:?} {hdrs:?}"
            );
        }
    }
}

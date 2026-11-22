//! Plain-data request / response descriptions and the evaluation results.

use std::borrow::Cow;

use crate::headers::{find, HeaderEdit};
use crate::hls::{apply_hls, HlsPrune, MAX_HLS_BYTES};
use crate::jsonprune::{apply_jsonprune, JsonPrune, MAX_JSON_BYTES};
use crate::parse::{HtmlRemoval, Injection};
use crate::replace::{apply_replace, ReplaceSpec, MAX_REPLACE_BYTES};
use crate::xmlprune::{apply_xmlprune, XmlPrune, MAX_XML_BYTES};

/// Index of an active rule inside an [`crate::ExtIndex`].
pub type RuleId = u32;

/// Request destination class (the `$script`, `$image`, ... option types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceType {
    Document,
    Subdocument,
    Stylesheet,
    Script,
    Image,
    Font,
    Media,
    Xhr,
    WebSocket,
    Ping,
    Object,
    Other,
}

impl ResourceType {
    pub(crate) fn bit(self) -> u16 {
        1 << (self as u16)
    }

    /// Map a `Sec-Fetch-Dest` value to a type (`empty` is XHR/fetch).
    pub fn from_fetch_dest(d: &str) -> Self {
        match d {
            "document" => Self::Document,
            "iframe" | "frame" | "fencedframe" => Self::Subdocument,
            "style" => Self::Stylesheet,
            "script" | "worker" | "sharedworker" | "serviceworker" => Self::Script,
            "image" => Self::Image,
            "font" => Self::Font,
            "audio" | "video" | "track" => Self::Media,
            "empty" => Self::Xhr,
            "object" | "embed" => Self::Object,
            "report" => Self::Ping,
            _ => Self::Other,
        }
    }
}

/// What the proxy knows about a request.
#[derive(Debug, Clone, Copy)]
pub struct RequestInfo<'a> {
    /// Absolute URL (`scheme://host[:port]/path?query`).
    pub url: &'a str,
    pub method: &'a str,
    /// URL of the page that issued the request (`Referer`/initiator); `None` for top-level
    /// navigations (then the request counts as first-party and domain options match its own host).
    pub source_url: Option<&'a str>,
    pub resource_type: ResourceType,
    /// Precomputed third-party flag (e.g. from the network engine); computed lazily when `None`.
    pub third_party: Option<bool>,
    /// The caller detected that this navigation opens a popup. Browsers send no reliable popup
    /// signal in request headers (`Sec-Fetch-*` does not mention openers), so this is `false`
    /// unless the caller has out-of-band knowledge; `$popup` rules are then simply inert.
    pub opened_as_popup: bool,
    /// Request headers (any case); only read when a cookie / header rule matched. Check
    /// [`crate::ExtIndex::needs_request_headers`] to skip building it.
    pub headers: &'a [(&'a str, &'a str)],
}

impl<'a> RequestInfo<'a> {
    pub fn new(url: &'a str, method: &'a str, resource_type: ResourceType) -> Self {
        Self {
            url,
            method,
            source_url: None,
            resource_type,
            third_party: None,
            opened_as_popup: false,
            headers: &[],
        }
    }
}

/// What the proxy knows about a response.
#[derive(Debug, Clone, Copy)]
pub struct ResponseInfo<'a> {
    pub status: u16,
    /// Response headers (any case; repeated headers appear repeatedly).
    pub headers: &'a [(&'a str, &'a str)],
}

impl<'a> ResponseInfo<'a> {
    pub fn header(&self, name: &str) -> Option<&'a str> {
        find(self.headers, name)
    }
    pub fn content_type(&self) -> Option<&'a str> {
        self.header("content-type")
    }
    pub fn content_length(&self) -> Option<u64> {
        self.header("content-length")
            .and_then(|v| v.trim().parse().ok())
    }
    pub fn is_encoded(&self) -> bool {
        self.header("content-encoding")
            .is_some_and(|e| !e.trim().is_empty() && !e.trim().eq_ignore_ascii_case("identity"))
    }
}

/// Extra network verdict for a request (before it is sent upstream).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RequestDecision {
    /// Block the request.
    pub block: Option<RuleId>,
    /// Send the request to this URL instead (`$urltransform`; same origin, path/query only).
    pub rewrite_url: Option<(String, RuleId)>,
    /// Edits to the *request* headers (`$cookie`, `$removeheader=request:`).
    pub header_edits: Vec<HeaderEdit>,
    /// Every rule that took part (for logging).
    pub matched: Vec<RuleId>,
}

impl RequestDecision {
    pub fn is_noop(&self) -> bool {
        self.block.is_none() && self.rewrite_url.is_none() && self.header_edits.is_empty()
    }
}

/// One body rewrite, applicable to the buffered, decoded response body.
#[derive(Debug, Clone)]
pub enum BodyTransform<'a> {
    Replace(&'a ReplaceSpec),
    JsonPrune(Vec<&'a JsonPrune>),
    XmlPrune(Vec<&'a XmlPrune>),
    Hls(Vec<&'a HlsPrune>),
}

impl BodyTransform<'_> {
    /// Largest body this transform will touch.
    pub fn limit(&self) -> usize {
        match self {
            Self::Replace(_) => MAX_REPLACE_BYTES,
            Self::JsonPrune(_) => MAX_JSON_BYTES,
            Self::XmlPrune(_) => MAX_XML_BYTES,
            Self::Hls(_) => MAX_HLS_BYTES,
        }
    }
    pub fn apply<'b>(&self, body: &'b [u8]) -> Cow<'b, [u8]> {
        match self {
            Self::Replace(s) => apply_replace(body, s),
            Self::JsonPrune(s) => apply_jsonprune(body, s),
            Self::XmlPrune(s) => apply_xmlprune(body, s),
            Self::Hls(s) => apply_hls(body, s),
        }
    }
}

/// Everything to do to one response, computed once.
#[derive(Debug, Default, Clone)]
pub struct ResponsePlan<'a> {
    /// Block the response (`$header` matched).
    pub block: Option<RuleId>,
    /// Edits to the response headers, in order.
    pub header_edits: Vec<HeaderEdit>,
    /// Body rewrites in application order (list order).
    pub body: Vec<BodyTransform<'a>>,
    /// The body is content-encoded: decode before [`Self::apply_body`] (and drop
    /// `Content-Encoding` / fix `Content-Length` afterwards).
    pub requires_decoded_body: bool,
    /// Element removals for the streaming HTML rewriter.
    pub html_removals: Vec<&'a HtmlRemoval>,
    /// Script / procedural-CSS injections for the page.
    pub injections: Vec<&'a Injection>,
    /// Every rule that took part (for logging).
    pub matched: Vec<RuleId>,
}

impl ResponsePlan<'_> {
    pub fn is_noop(&self) -> bool {
        self.block.is_none()
            && self.header_edits.is_empty()
            && self.body.is_empty()
            && self.html_removals.is_empty()
            && self.injections.is_empty()
    }
    /// Must the body be buffered (and bounded by [`Self::body_limit`])?
    pub fn needs_body(&self) -> bool {
        !self.body.is_empty()
    }
    /// Needs the HTML rewriter (removals or injections)?
    pub fn needs_html_rewrite(&self) -> bool {
        !self.html_removals.is_empty() || !self.injections.is_empty()
    }
    /// Maximum body size worth buffering: larger bodies must be streamed through untouched.
    pub fn body_limit(&self) -> usize {
        self.body.iter().map(|t| t.limit()).max().unwrap_or(0)
    }
    /// Apply all body transforms in order. Borrowed when nothing changed.
    pub fn apply_body<'b>(&self, body: &'b [u8]) -> Cow<'b, [u8]> {
        let mut cur = Cow::Borrowed(body);
        for t in &self.body {
            if let Cow::Owned(v) = t.apply(&cur) {
                cur = Cow::Owned(v);
            }
        }
        cur
    }
}

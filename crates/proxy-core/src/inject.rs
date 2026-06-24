//! Streaming HTML cosmetic injection.
//!
//! For `text/html` responses we insert an element-hiding `<style>`, any scriptlet `<script>`, and a
//! small dynamic-hiding helper near `</head>`. The body is processed as a stream: we buffer only up
//! to the injection point (bounded), inject once, then pass the remainder through unbuffered — so
//! memory stays flat regardless of page size. Compressed HTML is decoded on the fly and re-emitted
//! as identity.

use std::io;
use std::pin::Pin;

use bytes::Bytes;
use filter_engine::Cosmetics;
use futures_util::StreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::io::StreamReader;

/// Unified streaming response body used throughout the proxy.
///
/// `Unsync` because the HTML-injection path holds a `dyn AsyncRead + Send` decoder (Send but not
/// Sync); hyper only requires the body to be `Send`.
pub type ProxyBody = UnsyncBoxBody<Bytes, io::Error>;

/// Max bytes to buffer while searching for the injection anchor before giving up and prepending.
const MAX_SEARCH: usize = 256 * 1024;

/// The dynamic class/id hiding helper injected into pages (see `/__adblock__/cc`).
const HELPER_JS: &str = r#"(function(){if(window.__abH)return;window.__abH=1;
var seen=new Set(),applied=new Set(),style=null,timer=null,pending=false;
function ensureStyle(){if(!style){style=document.createElement('style');style.id='__adblock_dynamic';(document.head||document.documentElement).appendChild(style);}return style;}
function collect(){var cls=new Set(),ids=new Set(),all=document.getElementsByTagName('*');
for(var i=0;i<all.length;i++){var e=all[i];if(e.classList){for(var j=0;j<e.classList.length;j++)cls.add(e.classList[j]);}if(e.id)ids.add(e.id);}
var nc=[],ni=[];cls.forEach(function(c){if(!seen.has('c:'+c)){seen.add('c:'+c);nc.push(c);}});ids.forEach(function(d){if(!seen.has('i:'+d)){seen.add('i:'+d);ni.push(d);}});return{classes:nc,ids:ni};}
function request(){pending=false;var t=collect();if(!t.classes.length&&!t.ids.length)return;
fetch('/__adblock__/cc',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:location.href,classes:t.classes,ids:t.ids}),credentials:'omit'})
.then(function(r){return r.ok?r.json():null;}).then(function(d){if(!d||!d.selectors)return;var add='';d.selectors.forEach(function(s){if(!applied.has(s)){applied.add(s);add+=s+',';}});if(add){ensureStyle().appendChild(document.createTextNode(add.slice(0,-1)+'{display:none!important}'));}}).catch(function(){});}
function schedule(){if(pending)return;pending=true;if(timer)clearTimeout(timer);timer=setTimeout(request,200);}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',request);else request();
try{new MutationObserver(schedule).observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:['class','id']});}catch(e){}})();"#;

/// Build the HTML snippet to inject for a page, or `None` if there's nothing to do.
///
/// `include_helper` adds the dynamic class/id hiding helper (skipped when the page is generic-hide
/// excepted).
pub fn build_payload(cos: &Cosmetics, include_helper: bool) -> Option<Bytes> {
    let mut out = String::new();

    if !cos.hide_selectors.is_empty() {
        // Selectors come from the engine and are valid CSS; guard only against breaking the tag.
        let css = cos.hide_selectors.join(",");
        if !css.contains("</style") {
            out.push_str("<style id=\"__adblock_cosmetic\">");
            out.push_str(&css);
            out.push_str("{display:none!important}</style>");
        }
    }

    if !cos.injected_script.is_empty() && !cos.injected_script.contains("</script") {
        out.push_str("<script>");
        out.push_str(&cos.injected_script);
        out.push_str("</script>");
    }

    if include_helper {
        out.push_str("<script id=\"__adblock_helper\">");
        out.push_str(HELPER_JS);
        out.push_str("</script>");
    }

    if out.is_empty() {
        None
    } else {
        Some(Bytes::from(out))
    }
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

/// Decode (per `content_encoding`) and inject `payload` into a streaming HTML body.
pub fn inject_body(
    resp: reqwest::Response,
    payload: Bytes,
    content_encoding: Option<&str>,
) -> ProxyBody {
    let io_stream = resp
        .bytes_stream()
        .map(|res| res.map_err(io::Error::other));
    let reader = StreamReader::new(io_stream);

    let decoded: Pin<Box<dyn AsyncRead + Send>> = match content_encoding {
        Some(e) if e.eq_ignore_ascii_case("gzip") || e.eq_ignore_ascii_case("x-gzip") => {
            Box::pin(async_compression::tokio::bufread::GzipDecoder::new(reader))
        }
        Some(e) if e.eq_ignore_ascii_case("br") => {
            Box::pin(async_compression::tokio::bufread::BrotliDecoder::new(reader))
        }
        Some(e) if e.eq_ignore_ascii_case("deflate") => {
            Box::pin(async_compression::tokio::bufread::ZlibDecoder::new(reader))
        }
        _ => Box::pin(reader),
    };

    let stream = inject_stream(decoded, payload).map(|res| res.map(Frame::data));
    BodyExt::boxed_unsync(StreamBody::new(stream))
}

/// Stream decompressed HTML, injecting `payload` once near the `</head>` anchor.
fn inject_stream(
    mut reader: Pin<Box<dyn AsyncRead + Send>>,
    payload: Bytes,
) -> impl futures_util::Stream<Item = io::Result<Bytes>> + Send {
    async_stream::try_stream! {
        let mut search: Vec<u8> = Vec::new();
        let mut injected = false;
        let mut buf = vec![0u8; 16 * 1024];

        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if injected {
                yield Bytes::copy_from_slice(&buf[..n]);
                continue;
            }

            search.extend_from_slice(&buf[..n]);
            if let Some(pos) = find_injection_point(&search) {
                let mut out = Vec::with_capacity(search.len() + payload.len());
                out.extend_from_slice(&search[..pos]);
                out.extend_from_slice(&payload);
                out.extend_from_slice(&search[pos..]);
                injected = true;
                search = Vec::new();
                yield Bytes::from(out);
            } else if search.len() > MAX_SEARCH {
                // No anchor found in a reasonable window: prepend and flush.
                let mut out = Vec::with_capacity(search.len() + payload.len());
                out.extend_from_slice(&payload);
                out.append(&mut search);
                injected = true;
                yield Bytes::from(out);
            }
            // otherwise keep buffering until the anchor arrives (bounded by MAX_SEARCH)
        }

        if !injected {
            let pos = find_injection_point(&search).unwrap_or(0);
            let mut out = Vec::with_capacity(search.len() + payload.len());
            out.extend_from_slice(&search[..pos]);
            out.extend_from_slice(&payload);
            out.extend_from_slice(&search[pos..]);
            yield Bytes::from(out);
        }
    }
}

/// Find the byte offset to insert the payload at: just before `</head>`, else before `<body`.
fn find_injection_point(buf: &[u8]) -> Option<usize> {
    let lower = buf.to_ascii_lowercase();
    find_sub(&lower, b"</head>").or_else(|| find_sub(&lower, b"<body"))
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_builds_style_and_helper() {
        let cos = Cosmetics {
            hide_selectors: vec![".ad".into(), "#banner".into()],
            injected_script: String::new(),
            generichide: false,
        };
        let p = build_payload(&cos, true).expect("payload");
        let s = String::from_utf8(p.to_vec()).unwrap();
        assert!(s.contains(".ad,#banner{display:none!important}"));
        assert!(s.contains("__adblock_helper"));
    }

    #[test]
    fn payload_empty_when_nothing_to_do() {
        let cos = Cosmetics::default();
        assert!(build_payload(&cos, false).is_none());
    }

    #[test]
    fn finds_head_anchor() {
        let html = b"<html><head><title>x</title></head><body>hi</body></html>";
        let pos = find_injection_point(html).unwrap();
        assert_eq!(&html[pos..pos + 7], b"</head>");
    }

    #[test]
    fn falls_back_to_body_anchor() {
        let html = b"<html><body>no head here</body></html>";
        let pos = find_injection_point(html).unwrap();
        assert_eq!(&html[pos..pos + 5], b"<body");
    }

    #[tokio::test]
    async fn injects_once_before_head() {
        use http_body_util::BodyExt;
        let html = b"<html><head><title>t</title></head><body><p>hello</p></body></html>".to_vec();
        let reader: Pin<Box<dyn AsyncRead + Send>> = Box::pin(std::io::Cursor::new(html));
        let payload = Bytes::from_static(b"<style>INJECTED</style>");
        let stream = inject_stream(reader, payload);
        let body = StreamBody::new(stream.map(|r| r.map(Frame::data))).boxed_unsync();
        let collected = body.collect().await.unwrap().to_bytes();
        let out = String::from_utf8(collected.to_vec()).unwrap();
        assert!(out.contains("<style>INJECTED</style></head>"), "got: {out}");
        assert_eq!(out.matches("INJECTED").count(), 1);
    }
}

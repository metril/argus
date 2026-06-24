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

/// Procedural pseudo-classes that aren't valid CSS and must be evaluated in JS. Note `:has()` is
/// deliberately excluded — modern browsers support it natively, so it stays in the stylesheet.
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

/// Client-side evaluator for procedural cosmetic filters. It parses a raw procedural selector
/// (e.g. `.box:has-text(Ad):upward(2)`) into a CSS anchor plus operators, evaluates them against
/// the DOM, and applies the filter's action. The work-list is spliced in at `__AB_PROC__`; each
/// item is `{s: "<raw selector>", a: "<action>", g: "<action arg>"}`.
const PROCEDURAL_JS: &str = r#"(function(){if(window.__abPr)return;var items=__AB_PROC__;if(!items||!items.length)return;window.__abPr=1;
var NAMES=['has-text','matches-css-before','matches-css-after','matches-css','matches-attr','matches-path','min-text-length','upward','xpath','-abp-contains','contains'];
function parseSel(sel){var ops=[],out='',n=sel.length,i=0;
while(i<n){if(sel[i]===':'){var matched=null;for(var k=0;k<NAMES.length;k++){var nm=NAMES[k];if(sel.substr(i+1,nm.length)===nm&&sel.charAt(i+1+nm.length)==='('){matched=nm;break;}}
if(matched){var start=i+1+matched.length+1,depth=1,j=start;while(j<n){var c=sel[j];if(c==='(')depth++;else if(c===')'){depth--;if(depth===0)break;}j++;}
ops.push({n:(matched==='-abp-contains'||matched==='contains')?'has-text':matched,a:sel.slice(start,j)});i=j+1;continue;}}
out+=sel[i];i++;}
return{css:out.trim(),ops:ops};}
function rx(s){if(s&&s.length>1&&s[0]==='/'){var i=s.lastIndexOf('/');if(i>0){try{return new RegExp(s.slice(1,i),s.slice(i+1));}catch(e){}}}return null;}
function applyOp(nodes,op){var nm=op.n,a=op.a,out=[];
for(var i=0;i<nodes.length;i++){var el=nodes[i];
if(nm==='has-text'){var re=rx(a),t=el.textContent||'';if(re?re.test(t):t.indexOf(a)!==-1)out.push(el);}
else if(nm==='min-text-length'){if((el.textContent||'').length>=parseInt(a,10))out.push(el);}
else if(nm==='matches-path'){var re=rx(a);if(re?re.test(location.pathname):location.pathname.indexOf(a)!==-1)out.push(el);}
else if(nm==='matches-css'||nm==='matches-css-before'||nm==='matches-css-after'){var p=nm==='matches-css'?null:(nm==='matches-css-before'?'::before':'::after');var ix=a.indexOf(':');if(ix>=0){var pr=a.slice(0,ix).trim(),v=a.slice(ix+1).trim();var cs=getComputedStyle(el,p);var ac=cs.getPropertyValue(pr)||'';var re=rx(v);if(re?re.test(ac):ac.trim()===v)out.push(el);}}
else if(nm==='matches-attr'){var m=a.match(/^([^=]+)(?:=([\s\S]*))?$/);if(m){var name=m[1].trim();if(el.hasAttribute(name)){if(m[2]===undefined)out.push(el);else{var v=el.getAttribute(name)||'';var re=rx(m[2]);if(re?re.test(v):v===m[2].replace(/^"|"$/g,''))out.push(el);}}}}
else if(nm==='upward'){var num=parseInt(a,10);if(!isNaN(num)&&String(num)===a.trim()){var e=el;while(num-->0&&e)e=e.parentElement;if(e)out.push(e);}else{try{var c=el.closest(a);if(c)out.push(c);}catch(e){}}}
else if(nm==='xpath'){try{var r=document.evaluate(a,el,null,XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,null);for(var q=0;q<r.snapshotLength;q++){var nd=r.snapshotItem(q);if(nd.nodeType===1)out.push(nd);}}catch(e){}}
else out.push(el);}
return out.filter(function(v,ix){return out.indexOf(v)===ix;});}
function evalItem(it){var ps=parseSel(it.s),nodes;
try{nodes=ps.css?[].slice.call(document.querySelectorAll(ps.css)):[].slice.call(document.querySelectorAll('*'));}catch(e){return[];}
for(var i=0;i<ps.ops.length;i++){nodes=applyOp(nodes,ps.ops[i]);if(!nodes.length)break;}return nodes;}
function run(){for(var f=0;f<items.length;f++){var it=items[f],nodes;try{nodes=evalItem(it);}catch(e){continue;}
for(var i=0;i<nodes.length;i++){var el=nodes[i];try{
if(it.a==='remove')el.remove();
else if(it.a==='style')el.style.cssText+=';'+(it.g||'');
else if(it.a==='remove-attr')el.removeAttribute(it.g||'');
else if(it.a==='remove-class')el.classList.remove(it.g||'');
else el.style.setProperty('display','none','important');}catch(e){}}}}
var t=null;function sch(){if(t)clearTimeout(t);t=setTimeout(run,200);}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',run);else run();
try{new MutationObserver(sch).observe(document.documentElement,{childList:true,subtree:true,attributes:true});}catch(e){}})();"#;

/// Build the HTML snippet to inject for a page, or `None` if there's nothing to do.
///
/// `include_helper` adds the dynamic class/id hiding helper (skipped when the page is generic-hide
/// excepted).
pub fn build_payload(cos: &Cosmetics, include_helper: bool) -> Option<Bytes> {
    let mut out = String::new();

    // Partition element-hiding selectors: plain CSS goes in a stylesheet; procedural selectors are
    // evaluated in JS (mixing them into CSS would invalidate the whole rule).
    let plain: Vec<&str> = cos
        .hide_selectors
        .iter()
        .map(|s| s.as_str())
        .filter(|s| !is_procedural(s))
        .collect();
    if !plain.is_empty() {
        let css = plain.join(",");
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

    // Build the procedural work-list: procedural hide selectors + parsed action filters.
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
            proc_items.push(serde_json::json!({ "s": sel, "a": act, "g": arg }));
        }
    }
    if !proc_items.is_empty() {
        let array = serde_json::to_string(&proc_items).unwrap_or_else(|_| "[]".to_string());
        if !array.contains("</script") {
            out.push_str("<script id=\"__adblock_procedural\">");
            out.push_str(&PROCEDURAL_JS.replace("__AB_PROC__", &array));
            out.push_str("</script>");
        }
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
            generichide: false,
            ..Default::default()
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
    fn procedural_hide_selector_kept_out_of_stylesheet() {
        // A procedural selector must NOT leak into the <style> (it would be invalid CSS and break
        // the whole rule); it goes to the procedural evaluator instead.
        let cos = Cosmetics {
            hide_selectors: vec![".real-ad".into(), ".box:has-text(Sponsored)".into()],
            generichide: true, // skip the helper to isolate this
            ..Default::default()
        };
        let s = String::from_utf8(build_payload(&cos, false).unwrap().to_vec()).unwrap();
        // Plain selector is in the stylesheet; procedural one is not.
        assert!(s.contains(".real-ad{display:none!important}"));
        assert!(!s.contains("<style id=\"__adblock_cosmetic\">.box:has-text"));
        // The procedural selector is handed to the evaluator (JSON key order is not significant).
        assert!(s.contains("__adblock_procedural"));
        assert!(s.contains(r#""s":".box:has-text(Sponsored)""#));
        assert!(s.contains(r#""a":"hide""#));
        assert!(!s.contains("__AB_PROC__"), "placeholder must be replaced");
    }

    #[test]
    fn payload_parses_action_filter() {
        let cos = Cosmetics {
            procedural_actions: vec![
                r#"{"selector":[{"type":"css-selector","arg":".ad:has-text(Ad)"}],"action":{"type":"remove"}}"#.to_string(),
            ],
            generichide: true,
            ..Default::default()
        };
        let s = String::from_utf8(build_payload(&cos, false).unwrap().to_vec()).unwrap();
        assert!(s.contains(r#""s":".ad:has-text(Ad)""#));
        assert!(s.contains(r#""a":"remove""#));
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

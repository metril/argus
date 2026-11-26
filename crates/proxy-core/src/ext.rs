//! Extended (uBO / AdGuard) rules on the wire.
//!
//! The index lives in the engine's [`filter_engine::Generation`] (built and swapped with the
//! engine, so a request never pairs an engine from one build with ext rules from another).
//!
//! # Precedence against the network engine
//!
//! * An engine **block** is final: the ext index is not consulted (nothing is sent upstream).
//! * An engine **exception** (`@@||host^`) does *not* switch ext rules off. Like uBO and AdGuard,
//!   every modifier-based behaviour (`$replace`, `$removeheader`, `$cookie`, `$denyallow`,
//!   `$urltransform`, HTML filters, ...) is disabled only by an exception that names that
//!   modifier (`@@||host^$replace`), or by a bare ext exception that carries no value; those
//!   pairings are resolved inside the index (see `ext_rules::ExtIndex`), where `$important`
//!   wins over a plain exception.
//! * The engine's `$removeparam` rewrite is applied first, then `$urltransform` sees the
//!   rewritten URL.
//! * The master switch (`SharedEngine::is_enabled`) turns ext rules off with the engine.

use crate::request_type::RequestType;
use crate::rewrite::{
    ElementFilter, HeaderEdit as RwEdit, ResponseInfo, ResponseTransforms, TransformSource,
};
use ext_rules::{ExtIndex, HeaderEdit, RequestDecision, RequestInfo, ResourceType, RuleId};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use std::sync::Arc;

/// Map the proxy's request type to the ext-rule one.
pub fn resource_type(t: RequestType) -> ResourceType {
    match t {
        RequestType::Document => ResourceType::Document,
        RequestType::Subdocument => ResourceType::Subdocument,
        RequestType::Script => ResourceType::Script,
        RequestType::Stylesheet => ResourceType::Stylesheet,
        RequestType::Image => ResourceType::Image,
        RequestType::Font => ResourceType::Font,
        RequestType::Media => ResourceType::Media,
        RequestType::Xhr => ResourceType::Xhr,
        RequestType::Websocket => ResourceType::WebSocket,
        RequestType::Ping => ResourceType::Ping,
        RequestType::Object => ResourceType::Object,
        RequestType::Other => ResourceType::Other,
    }
}

/// The URL as rules see it: the default port of the scheme is dropped (`https://a.test:443/x` ->
/// `https://a.test/x`), because patterns like `||example.com/path` are written against that form
/// and the engines match them literally. Other ports stay: like uBO, `||example.com/path` does
/// not match `https://example.com:8443/path` (`||example.com^` does).
pub fn rule_url(url: &str) -> std::borrow::Cow<'_, str> {
    for (scheme, port) in [
        ("https://", ":443"),
        ("http://", ":80"),
        ("wss://", ":443"),
        ("ws://", ":80"),
    ] {
        if let Some(rest) = url.strip_prefix(scheme) {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            if let Some(host) = rest[..end].strip_suffix(port) {
                return std::borrow::Cow::Owned(format!("{scheme}{host}{}", &rest[end..]));
            }
        }
    }
    std::borrow::Cow::Borrowed(url)
}

/// Request-side verdict from the ext index. `None` (without building anything) when the index
/// has no request rules; request headers are only collected when a rule reads them.
pub fn request_decision(
    idx: &ExtIndex,
    url: &str,
    method: &str,
    source: &str,
    rtype: RequestType,
    headers: &HeaderMap,
) -> Option<RequestDecision> {
    if !idx.has_request_rules() {
        return None;
    }
    let pairs: Vec<(&str, &str)> = if idx.needs_request_headers() {
        headers
            .iter()
            .filter_map(|(n, v)| Some((n.as_str(), v.to_str().ok()?)))
            .collect()
    } else {
        Vec::new()
    };
    let url = rule_url(url);
    let mut info = RequestInfo::new(&url, method, resource_type(rtype));
    info.source_url = (rtype != RequestType::Document && !source.is_empty()).then_some(source);
    info.headers = &pairs;
    let d = idx.request_decision(&info);
    (!d.is_noop()).then_some(d)
}

/// Stealth options a `$stealth` exception turns off for this request (0 without any).
pub fn stealth_off(idx: &ExtIndex, url: &str, source: &str, rtype: RequestType) -> u32 {
    let url = rule_url(url);
    let mut info = RequestInfo::new(&url, "GET", resource_type(rtype));
    info.source_url = (rtype != RequestType::Document && !source.is_empty()).then_some(source);
    idx.stealth_off(&info)
}

/// Apply ext header edits to a request's header map.
pub fn apply_request_edits(headers: &mut HeaderMap, edits: &[HeaderEdit]) {
    for e in edits {
        let Ok(name) = HeaderName::from_bytes(e.name().as_bytes()) else {
            continue;
        };
        match e {
            HeaderEdit::Remove(_) => {
                headers.remove(&name);
            }
            HeaderEdit::SetAll(_, vals) => {
                headers.remove(&name);
                for v in vals {
                    if let Ok(v) = HeaderValue::from_str(v) {
                        headers.append(name.clone(), v);
                    }
                }
            }
            HeaderEdit::Append(_, v) => {
                if let Ok(v) = HeaderValue::from_str(v) {
                    headers.append(name, v);
                }
            }
        }
    }
}

fn response_edits(edits: &[HeaderEdit], out: &mut Vec<RwEdit>) {
    for e in edits {
        let Ok(name) = HeaderName::from_bytes(e.name().as_bytes()) else {
            continue;
        };
        match e {
            HeaderEdit::Remove(_) => out.push(RwEdit::Remove(name)),
            HeaderEdit::SetAll(_, vals) => {
                out.push(RwEdit::Remove(name.clone()));
                for v in vals {
                    if let Ok(v) = HeaderValue::from_str(v) {
                        out.push(RwEdit::Append(name.clone(), v));
                    }
                }
            }
            HeaderEdit::Append(_, v) => {
                if let Ok(v) = HeaderValue::from_str(v) {
                    out.push(RwEdit::Append(name, v));
                }
            }
        }
    }
}

/// Body transform backed by the index: keeps owned rule ids and re-derives the borrowed
/// transforms on use. Each transform runs only when the body is within its own size cap.
struct ExtBody {
    generation: Arc<filter_engine::Generation>,
    ids: Vec<RuleId>,
    cap: usize,
}

impl crate::rewrite::BodyTransform for ExtBody {
    fn max_body_bytes(&self) -> usize {
        self.cap
    }
    fn applies_to(&self, _media_type: &str) -> bool {
        true // the plan already matched on the response's type
    }
    fn apply(&self, body: &[u8]) -> Option<Vec<u8>> {
        let idx = self.generation.aux::<ExtIndex>()?;
        let mut cur: std::borrow::Cow<'_, [u8]> = std::borrow::Cow::Borrowed(body);
        let mut changed = false;
        for t in idx.body_transforms_for(&self.ids) {
            if cur.len() > t.limit() {
                continue;
            }
            if let std::borrow::Cow::Owned(v) = t.apply(&cur) {
                cur = std::borrow::Cow::Owned(v);
                changed = true;
            }
        }
        changed.then(|| cur.into_owned())
    }
}

/// Selector fast path: no content predicate and no explicit length bounds.
fn plain_selector(r: &ext_rules::HtmlRemoval) -> bool {
    !r.needs_text() && r.min_len == 0 && r.max_len == ext_rules::DEFAULT_MAX_ELEMENT_LEN
}

/// The built-in [`TransformSource`]: turns [`ExtIndex::response_plan`] into pipeline work.
pub struct ExtTransformSource;

impl TransformSource for ExtTransformSource {
    fn transforms_for(&self, info: &ResponseInfo<'_>) -> Option<ResponseTransforms> {
        let generation = info.generation?;
        let idx = generation.aux::<ExtIndex>()?;
        if !idx.has_response_rules() {
            return None;
        }
        let url = rule_url(info.url);
        let mut req = RequestInfo::new(&url, info.method, resource_type(info.request_type));
        req.source_url = (info.request_type != RequestType::Document
            && !info.source_url.is_empty())
        .then_some(info.source_url);
        let headers: Vec<(&str, &str)> = info
            .response_headers
            .iter()
            .filter_map(|(n, v)| Some((n.as_str(), v.to_str().ok()?)))
            .collect();
        let plan = idx.response_plan(
            &req,
            &ext_rules::ResponseInfo {
                status: info.status.as_u16(),
                headers: &headers,
            },
        );
        if plan.is_noop() {
            return None;
        }
        let mut t = ResponseTransforms {
            block: plan.block.map(|id| {
                idx.rule(id)
                    .map_or_else(|| "$header".to_string(), |r| r.raw.clone())
            }),
            ..Default::default()
        };
        response_edits(&plan.header_edits, &mut t.header_edits);
        if plan.needs_body() {
            let ids: Vec<RuleId> = plan
                .matched
                .iter()
                .copied()
                .filter(|&i| idx.is_body_rule(i))
                .collect();
            t.body = Some(Arc::new(ExtBody {
                generation: generation.clone(),
                ids,
                cap: plan.body_limit(),
            }));
        }
        for r in &plan.html_removals {
            if plain_selector(r) {
                t.remove_selectors.push(r.css.clone());
            } else {
                let r2 = (*r).clone();
                t.element_filters.push(ElementFilter {
                    selector: r.css.clone(),
                    min_len: r.min_len,
                    max_len: r.max_len,
                    accept: Arc::new(move |s: &str| r2.text_matches(s)),
                });
            }
        }
        for inj in &plan.injections {
            match inj {
                ext_rules::Injection::ProceduralCss { selector, style } => {
                    t.procedural.push((selector.clone(), style.clone()));
                }
                other => {
                    if let Some(js) = other.script_body() {
                        t.scripts.push(js);
                    }
                }
            }
        }
        Some(t)
    }
}

#[cfg(test)]
mod tests {
    use super::rule_url;

    #[test]
    fn default_ports_are_dropped_for_rule_matching() {
        assert_eq!(rule_url("https://a.test:443/x?y=1"), "https://a.test/x?y=1");
        assert_eq!(rule_url("http://a.test:80/"), "http://a.test/");
        assert_eq!(rule_url("https://a.test:443"), "https://a.test");
        assert_eq!(rule_url("https://a.test:8443/x"), "https://a.test:8443/x");
        assert_eq!(rule_url("wss://a.test:443/s"), "wss://a.test/s");
        assert_eq!(rule_url("ws://[::1]:80/s"), "ws://[::1]/s");
        assert_eq!(rule_url("https://[::1]:443/s"), "https://[::1]/s");
        assert_eq!(rule_url("http://a.test:443/x"), "http://a.test:443/x");
        assert_eq!(rule_url("https://a.test/x:443/"), "https://a.test/x:443/");
    }
}

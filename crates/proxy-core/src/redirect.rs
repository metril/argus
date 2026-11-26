//! Synthetic responses the proxy answers itself: block responses shaped to the request type,
//! `$redirect` resource bodies, and `$removeparam` navigation redirects.
//!
//! Every response carries `x-adblock`: `blocked`, `redirected` or `rewritten`.

use crate::inject::{full_body, ProxyBody};
use crate::request_type::RequestType;
use bytes::Bytes;
use filter_engine::{MatchResult, RedirectResource};
use hyper::{Response, StatusCode};

/// 1x1 transparent GIF.
const GIF_1X1: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x01, 0x44, 0x00, 0x3b,
];

fn base(status: StatusCode, tag: &'static str) -> hyper::http::response::Builder {
    Response::builder()
        .status(status)
        .header("x-adblock", tag)
        .header("cache-control", "no-store")
        // Let blocked/redirected cross-origin subresources and fetches be consumed quietly.
        .header("cross-origin-resource-policy", "cross-origin")
        .header("access-control-allow-origin", "*")
}

fn html_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

fn block_page(url: &str, rule: &str) -> String {
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Blocked</title>\
         <style>body{{font:16px system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#222}}\
         code{{background:#eee;padding:.1em .3em;word-break:break-all}}</style></head><body>\
         <h1>Request blocked</h1><p>This page was blocked by the ad blocker.</p>\
         <p>URL: <code>{}</code></p><p>Rule: <code>{}</code></p></body></html>",
        html_escape(url),
        html_escape(rule)
    )
}

fn reason_text(r: Option<common::certstore::FailReason>) -> &'static str {
    use common::certstore::FailReason as R;
    match r {
        Some(R::Expired) => "The certificate has expired.",
        Some(R::NotYetValid) => "The certificate is not valid yet.",
        Some(R::NameMismatch) => "The certificate is not valid for this host name.",
        Some(R::UnknownIssuer) => {
            "The certificate was issued by an unknown or untrusted authority."
        }
        Some(R::Distrusted) => {
            "The authority that issued the certificate is no longer trusted for certificates like this one."
        }
        _ => "The server's certificate or TLS handshake could not be verified.",
    }
}

fn cert_error_page(host: &str, info: Option<&common::certstore::CertInfo>) -> String {
    let details = info.map_or_else(String::new, |i| {
        format!(
            "<p>Issuer: <code>{}</code></p><p>Subject: <code>{}</code></p>\
             <p>Valid: <code>{}</code> to <code>{}</code></p>\
             <p>Fingerprint (SHA-256): <code>{}</code></p>",
            html_escape(&i.issuer),
            html_escape(&i.subject),
            html_escape(&i.not_before),
            html_escape(&i.not_after),
            html_escape(&i.fp)
        )
    });
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Insecure connection blocked</title>\
         <style>body{{font:16px system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#222}}\
         code{{background:#eee;padding:.1em .3em;word-break:break-all}}</style></head><body>\
         <h1>Connection blocked</h1>\
         <p>Argus did not connect to <code>{}</code> because the server's certificate is not trustworthy.</p>\
         <p>{}</p>{}\
         <p>The request was not forwarded. Inspect the certificate in the Argus web UI request log.</p>\
         </body></html>",
        html_escape(host),
        reason_text(info.and_then(|i| i.reason)),
        details
    )
}

/// Page served when the upstream server's TLS certificate failed verification: names the host,
/// the reason and the issuer. The request stays blocked (`502`, `x-adblock: cert-error`).
pub fn cert_error_response(
    host: &str,
    info: Option<&common::certstore::CertInfo>,
) -> Response<ProxyBody> {
    base(StatusCode::BAD_GATEWAY, "cert-error")
        .header("content-type", "text/html; charset=utf-8")
        .body(full_body(Bytes::from(cert_error_page(host, info))))
        .expect("static cert error response")
}

/// Response for a blocked request, shaped to what the requester expects.
pub fn block_response(ty: RequestType, verdict: &MatchResult, url: &str) -> Response<ProxyBody> {
    let (status, ctype, body): (StatusCode, Option<&str>, Bytes) = match ty {
        RequestType::Document => (
            StatusCode::FORBIDDEN,
            Some("text/html; charset=utf-8"),
            Bytes::from(block_page(
                url,
                verdict.matched_rule.as_deref().unwrap_or("unknown"),
            )),
        ),
        // A blank frame, not a nested error page.
        RequestType::Subdocument => (
            StatusCode::OK,
            Some("text/html; charset=utf-8"),
            Bytes::from_static(b"<!DOCTYPE html><html><head></head><body></body></html>"),
        ),
        RequestType::Image => (
            StatusCode::OK,
            Some("image/gif"),
            Bytes::from_static(GIF_1X1),
        ),
        RequestType::Script => (StatusCode::OK, Some("application/javascript"), Bytes::new()),
        RequestType::Stylesheet => (StatusCode::OK, Some("text/css"), Bytes::new()),
        // XHR/fetch, media, fonts, pings, objects, other: nothing to say.
        _ => (StatusCode::NO_CONTENT, None, Bytes::new()),
    };
    let mut b = base(status, "blocked");
    if let Some(c) = ctype {
        b = b.header("content-type", c);
    }
    b.body(full_body(body)).expect("static block response")
}

/// Response for a request the script policy refused: the shape of [`block_response`], tagged
/// `x-adblock: policy`.
pub fn policy_block_response(ty: RequestType, url: &str) -> Response<ProxyBody> {
    let mut r = block_response(ty, &MatchResult::blocked("script-policy"), url);
    r.headers_mut().insert(
        "x-adblock",
        hyper::header::HeaderValue::from_static("policy"),
    );
    r
}

/// Serve a `$redirect` resource in place of the original response.
///
/// Status 200 with the resource's MIME type. `origin` is the request's `Origin` header: a
/// credentialed cross-origin `fetch`/XHR (which a wildcard `access-control-allow-origin` would
/// fail) gets that origin echoed back, so the page cannot tell the answer from a real one.
pub fn redirect_response(res: RedirectResource, origin: Option<&str>) -> Response<ProxyBody> {
    let mut r = base(StatusCode::OK, "redirected")
        .header("content-type", res.mime)
        .body(full_body(Bytes::from(res.body)))
        .expect("redirect response");
    if let Some(o) = origin.filter(|o| *o != "null") {
        if let Ok(v) = hyper::header::HeaderValue::from_str(o) {
            let h = r.headers_mut();
            h.insert("access-control-allow-origin", v);
            h.insert(
                "access-control-allow-credentials",
                hyper::header::HeaderValue::from_static("true"),
            );
            h.insert("vary", hyper::header::HeaderValue::from_static("origin"));
        }
    }
    r
}

/// 307 to the `$removeparam`-cleaned URL (document navigations). Default ports are normalized
/// away so the client sees a natural URL.
pub fn rewrite_redirect(new_url: &str) -> Response<ProxyBody> {
    let location = url::Url::parse(new_url)
        .map(String::from)
        .unwrap_or_else(|_| new_url.to_string());
    base(StatusCode::TEMPORARY_REDIRECT, "rewritten")
        .header("location", location)
        .body(full_body(Bytes::new()))
        .expect("rewrite redirect")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn body_of(r: Response<ProxyBody>) -> Bytes {
        r.into_body().collect().await.unwrap().to_bytes()
    }

    #[tokio::test]
    async fn block_response_shapes() {
        let v = MatchResult::blocked("||a.test^<x>");
        let doc = block_response(RequestType::Document, &v, "https://a.test/?q=\"1\"");
        assert_eq!(doc.status(), 403);
        assert_eq!(doc.headers()["x-adblock"], "blocked");
        let html = String::from_utf8(body_of(doc).await.to_vec()).unwrap();
        assert!(html.contains("||a.test^&lt;x&gt;"), "{html}");
        assert!(html.contains("q=&quot;1&quot;"), "{html}");

        let img = block_response(RequestType::Image, &v, "u");
        assert_eq!(img.headers()["content-type"], "image/gif");
        assert_eq!(body_of(img).await.as_ref(), GIF_1X1);

        for (ty, ct) in [
            (RequestType::Script, "application/javascript"),
            (RequestType::Stylesheet, "text/css"),
        ] {
            let r = block_response(ty, &v, "u");
            assert_eq!(r.status(), 200);
            assert_eq!(r.headers()["content-type"], ct);
            assert!(body_of(r).await.is_empty());
        }
        for ty in [
            RequestType::Xhr,
            RequestType::Ping,
            RequestType::Media,
            RequestType::Other,
        ] {
            let r = block_response(ty, &v, "u");
            assert_eq!(r.status(), 204);
            assert_eq!(r.headers()["x-adblock"], "blocked");
        }
        let sub = block_response(RequestType::Subdocument, &v, "u");
        assert_eq!(sub.status(), 200);
    }

    #[test]
    fn every_synthetic_response_is_tagged_and_uncacheable() {
        use RequestType::*;
        let v = MatchResult::blocked("||a.test^");
        for ty in [
            Document,
            Subdocument,
            Image,
            Script,
            Stylesheet,
            Xhr,
            Ping,
            Media,
            Other,
        ] {
            let r = block_response(ty, &v, "u");
            assert_eq!(r.headers()["x-adblock"], "blocked", "{ty:?}");
            assert_eq!(r.headers()["cache-control"], "no-store", "{ty:?}");
        }
        let r = redirect_response(
            RedirectResource {
                mime: "text/javascript".into(),
                body: vec![],
            },
            None,
        );
        assert_eq!(r.headers()["cache-control"], "no-store");
        assert_eq!(
            rewrite_redirect("https://a.test/").headers()["cache-control"],
            "no-store"
        );
    }

    #[test]
    fn redirect_echoes_the_request_origin_for_credentialed_cors() {
        let res = || RedirectResource {
            mime: "application/javascript".into(),
            body: vec![],
        };
        let r = redirect_response(res(), Some("https://site.test"));
        let h = r.headers();
        assert_eq!(h["access-control-allow-origin"], "https://site.test");
        assert_eq!(h["access-control-allow-credentials"], "true");
        assert_eq!(h["content-type"], "application/javascript");
        assert_eq!(r.status(), 200);
        // No `nosniff`: a text/plain stub for a `$script` / `$stylesheet` redirect must still run.
        assert!(h.get("x-content-type-options").is_none());
        assert_eq!(h["cross-origin-resource-policy"], "cross-origin");
        let r = redirect_response(res(), Some("null"));
        assert_eq!(r.headers()["access-control-allow-origin"], "*");
    }

    #[tokio::test]
    async fn redirect_and_rewrite_responses() {
        let r = redirect_response(
            RedirectResource {
                mime: "image/gif".into(),
                body: vec![1, 2, 3],
            },
            None,
        );
        assert_eq!(r.headers()["content-type"], "image/gif");
        assert_eq!(r.headers()["x-adblock"], "redirected");
        assert_eq!(body_of(r).await.as_ref(), &[1, 2, 3]);

        let r = rewrite_redirect("https://a.test:443/p?x=1");
        assert_eq!(r.status(), 307);
        assert_eq!(r.headers()["location"], "https://a.test/p?x=1");
    }
}

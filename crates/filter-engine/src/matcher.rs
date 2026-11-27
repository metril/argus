//! Network request matching using adblock-rust

use crate::{Error, Result};
use adblock::request::Request as AdblockRequest;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Decoded `$redirect` resource to serve instead of the original response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectResource {
    /// MIME type, e.g. `image/gif`.
    pub mime: String,
    pub body: Vec<u8>,
}

/// Represents the result of a request match.
///
/// Precedence is resolved by the engine: `$important` blocks beat exceptions, exceptions beat
/// normal blocks.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MatchResult {
    /// Whether the request should not go upstream (blocked, or answered by a `$redirect` resource).
    pub blocked: bool,
    /// A `$important` rule matched (exceptions were not consulted).
    pub important: bool,
    /// The filter rule that matched (if any)
    pub matched_rule: Option<String>,
    /// The exception rule that allowed the request (if any)
    pub exception_rule: Option<String>,
    /// `$redirect` resource as a `data:<mime>;base64,<body>` URI; only set when `blocked`.
    /// Decode with [`MatchResult::redirect_resource`].
    pub redirect: Option<String>,
    /// URL after `$removeparam`, when the request was not blocked and the URL changed.
    pub rewritten_url: Option<String>,
    /// Source list of `matched_rule`, when known (hosts/domain-set rules; engine rules do not
    /// carry their list).
    #[serde(default)]
    pub list_id: Option<String>,
}

impl MatchResult {
    /// Create a blocked result
    pub fn blocked(rule: impl Into<String>) -> Self {
        Self {
            blocked: true,
            matched_rule: Some(rule.into()),
            ..Self::default()
        }
    }

    /// Create an allowed result
    pub fn allowed() -> Self {
        Self::default()
    }

    /// Create an allowed result with exception rule
    pub fn allowed_by_exception(rule: impl Into<String>) -> Self {
        Self {
            exception_rule: Some(rule.into()),
            ..Self::default()
        }
    }

    /// Create a redirect result: the request is answered with the `redirect` data URI.
    pub fn redirect(url: impl Into<String>, rule: impl Into<String>) -> Self {
        Self {
            blocked: true,
            matched_rule: Some(rule.into()),
            redirect: Some(url.into()),
            ..Self::default()
        }
    }

    /// A block without a stub takes the stub of `script`, the verdict for the same URL as a
    /// script. A page that loaded a `$script` redirect and then `fetch`es the URL gets the same
    /// answer instead of a network error, so the pair cannot be told from an original that is
    /// merely small.
    #[must_use]
    pub fn with_sibling_stub(mut self, url: &str, script: &MatchResult) -> Self {
        let path = url
            .split(['?', '#'])
            .next()
            .unwrap_or(url)
            .to_ascii_lowercase();
        let is_js = path.ends_with(".js") || path.ends_with(".mjs");
        // An extensionless final segment (`/gtag/js?id=..`) qualifies when the script verdict is
        // a redirect to a JavaScript resource: a data endpoint is not named like that.
        let bare_segment = path
            .rsplit('/')
            .next()
            .is_some_and(|seg| !seg.is_empty() && !seg.contains('.'));
        let js_stub = bare_segment
            && script
                .redirect_resource()
                .is_some_and(|r| r.mime.contains("javascript"));
        if (is_js || js_stub)
            && self.blocked
            && self.redirect.is_none()
            && script.blocked
            && script.redirect.is_some()
        {
            self.redirect = script.redirect.clone();
            self.matched_rule = script.matched_rule.clone();
            self.list_id = script.list_id.clone();
        }
        self
    }

    /// Decode the `$redirect` data URI into its MIME type and body.
    pub fn redirect_resource(&self) -> Option<RedirectResource> {
        use base64::Engine as _;
        let rest = self.redirect.as_deref()?.strip_prefix("data:")?;
        let (meta, data) = rest.split_once(',')?;
        let mime = meta.strip_suffix(";base64")?;
        let body = base64::engine::general_purpose::STANDARD
            .decode(data)
            .ok()?;
        Some(RedirectResource {
            mime: mime.to_string(),
            body,
        })
    }
}

/// Request matcher wrapper around adblock-rust
pub struct RequestMatcher;

/// Parsed source page of the last request on this thread: a page's sub-requests share it, so
/// its URL parse and public-suffix lookup run once per page instead of once per check.
struct SourceMemo {
    url: String,
    /// `(hostname, registrable domain)`; `None` when the source URL does not parse.
    parsed: Option<(String, String)>,
}

thread_local! {
    static SOURCE: std::cell::RefCell<SourceMemo> =
        const { std::cell::RefCell::new(SourceMemo { url: String::new(), parsed: None }) };
}

/// Same request as `AdblockRequest::new(url, source_url, resource_type)`, with the source page
/// parse memoized (see [`SourceMemo`]).
pub(crate) fn make_request(
    url: &str,
    source_url: &str,
    resource_type: &str,
) -> std::result::Result<AdblockRequest, adblock::request::RequestError> {
    let Some(target) = adblock::url_parser::parse_url(url) else {
        return AdblockRequest::new(url, source_url, resource_type);
    };
    Ok(SOURCE.with(|m| {
        let mut m = m.borrow_mut();
        if m.url != source_url || (m.parsed.is_none() && m.url.is_empty()) {
            m.parsed = adblock::url_parser::parse_url(source_url)
                .map(|p| (p.hostname().to_string(), p.domain().to_string()));
            m.url.clear();
            m.url.push_str(source_url);
        }
        match &m.parsed {
            Some((host, domain)) => AdblockRequest::preparsed(
                &target.url,
                target.hostname(),
                host,
                resource_type,
                domain != target.domain(),
            ),
            None => {
                AdblockRequest::preparsed(&target.url, target.hostname(), "", resource_type, true)
            }
        }
    }))
}

impl RequestMatcher {
    /// Check if a network request should be blocked
    ///
    /// # Arguments
    /// * `url` - The request URL
    /// * `source_url` - The source/initiator URL
    /// * `resource_type` - The type of resource (script, image, stylesheet, etc.)
    pub fn check_request(
        engine: &adblock::Engine,
        url: &str,
        source_url: &str,
        resource_type: &str,
    ) -> Result<MatchResult> {
        debug!(
            "Checking request: url={}, source={}, type={}",
            url, source_url, resource_type
        );

        // Create adblock request
        let request = AdblockRequest::new(url, source_url, resource_type)
            .map_err(|e| Error::InvalidSyntax(format!("Invalid request: {}", e)))?;

        let result = engine.check_network_request(&request);
        Ok(Self::to_match_result(result))
    }

    pub(crate) fn to_match_result(result: adblock::blocker::BlockerResult) -> MatchResult {
        if let Some(exception) = result.exception {
            // The engine clears `matched` when an exception applies (never for `$important`).
            debug!("Request allowed by exception: {exception}");
            let mut r = MatchResult::allowed_by_exception(exception);
            r.rewritten_url = result.rewritten_url;
            return r;
        }
        if result.matched {
            let rule = result.filter.unwrap_or_else(|| "unknown".to_string());
            let mut r = match result.redirect {
                Some(redirect) => MatchResult::redirect(redirect, rule.clone()),
                None => MatchResult::blocked(rule.clone()),
            };
            // A `$redirect=` that resolved to a scriptlet (through one of its aliases) must not
            // serve the scriptlet's source: treat it like a missing resource, a plain block.
            if r.redirect_resource()
                .is_some_and(|res| crate::ubo_redirects::looks_like_scriptlet(&res.body))
            {
                r = MatchResult::blocked(rule);
            }
            r.important = result.important;
            return r;
        }
        MatchResult {
            rewritten_url: result.rewritten_url,
            ..MatchResult::default()
        }
    }

    /// Extra CSP directives (`$csp`) to add to the response of a document/subdocument request.
    pub fn csp_directives(
        engine: &adblock::Engine,
        url: &str,
        source_url: &str,
        resource_type: &str,
    ) -> Option<String> {
        let request = AdblockRequest::new(url, source_url, resource_type).ok()?;
        engine.get_csp_directives(&request)
    }

    /// Host part of an absolute URL, without allocating (strips userinfo and port).
    pub fn host_of(url: &str) -> &str {
        let rest = url.split_once("://").map_or(url, |(_, r)| r);
        let auth = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        let auth = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
        if let Some(v6) = auth.strip_prefix('[') {
            return v6.split(']').next().unwrap_or(v6);
        }
        auth.split(':').next().unwrap_or(auth)
    }

    /// Extract domain from URL
    pub fn extract_domain(url: &str) -> Result<String> {
        let parsed = url::Url::parse(url)?;
        Ok(parsed.host_str().unwrap_or("unknown").to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memoized_request_matches_plain_request() {
        let mut set = adblock::lists::FilterSet::new(false);
        set.add_filters(
            [
                "||ads.example.com^$third-party",
                "/Banner/*$script,domain=page.test",
                "||cdn.test^$~third-party",
                "@@||ok.example.com^",
                "|http://Mixed.test/Path",
            ],
            Default::default(),
        );
        let engine = adblock::Engine::from_filter_set(set, true);
        let urls = [
            "https://ads.example.com/x.js",
            "https://site.test/Banner/a.js",
            "https://cdn.test/a",
            "https://ok.example.com/a",
            "http://Mixed.test/Path?Q=1",
            "https://user@ads.example.com:8443/x",
            "not a url",
        ];
        for source in ["https://page.test/", "https://cdn.test/", "garbage", ""] {
            for url in urls {
                for _ in 0..2 {
                    let a = AdblockRequest::new(url, source, "script");
                    let b = make_request(url, source, "script");
                    assert_eq!(a.is_ok(), b.is_ok(), "{url} from {source}");
                    if let (Ok(a), Ok(b)) = (a, b) {
                        let (ra, rb) = (
                            engine.check_network_request(&a),
                            engine.check_network_request(&b),
                        );
                        assert_eq!(
                            (ra.matched, ra.filter, ra.exception),
                            (rb.matched, rb.filter, rb.exception),
                            "{url} from {source}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_match_result_creation() {
        let blocked = MatchResult::blocked("test-rule");
        assert!(blocked.blocked);
        assert_eq!(blocked.matched_rule, Some("test-rule".to_string()));

        let allowed = MatchResult::allowed();
        assert!(!allowed.blocked);
        assert!(allowed.matched_rule.is_none());

        let exception = MatchResult::allowed_by_exception("exception-rule");
        assert!(!exception.blocked);
        assert_eq!(exception.exception_rule, Some("exception-rule".to_string()));
    }

    #[test]
    fn host_of_strips_userinfo_and_port() {
        assert_eq!(RequestMatcher::host_of("https://a.b:8080/x?y=1"), "a.b");
        assert_eq!(RequestMatcher::host_of("http://u:p@h.test/"), "h.test");
        assert_eq!(RequestMatcher::host_of("http://[::1]:80/"), "::1");
        assert_eq!(RequestMatcher::host_of("https://h.test?q"), "h.test");
    }

    #[test]
    fn block_adopts_the_script_stub_only_when_it_has_none() {
        let mut stub = MatchResult::redirect("data:application/javascript;base64,AA==", "s");
        stub.list_id = Some("L".into());
        let js = "https://a.test/t.js?x=1.json";
        let adopted = MatchResult::blocked("b").with_sibling_stub(js, &stub);
        assert_eq!(adopted.redirect, stub.redirect);
        assert_eq!(adopted.matched_rule.as_deref(), Some("s"));
        assert_eq!(adopted.list_id.as_deref(), Some("L"));
        let m = MatchResult::blocked("b").with_sibling_stub("https://a.test/T.MJS#f", &stub);
        assert!(m.redirect.is_some());
        for u in [
            "https://a.test/api.json",
            "https://a.test/",
            "https://a.test/a/b/",
        ] {
            let r = MatchResult::blocked("b").with_sibling_stub(u, &stub);
            assert!(
                r.redirect.is_none() && r.matched_rule.as_deref() == Some("b"),
                "{u}"
            );
        }
        // A script path without an extension takes a JavaScript stub, never another type.
        let gtag = "https://a.test/gtag/js?id=G-1.2";
        let m = MatchResult::blocked("b").with_sibling_stub(gtag, &stub);
        assert_eq!(m.redirect, stub.redirect);
        let img = MatchResult::redirect("data:image/gif;base64,AA==", "i");
        assert!(MatchResult::blocked("b")
            .with_sibling_stub(gtag, &img)
            .redirect
            .is_none());
        let own = MatchResult::redirect("data:image/gif;base64,AA==", "o");
        assert_eq!(
            own.clone().with_sibling_stub(js, &stub).redirect,
            own.redirect
        );
        let plain = MatchResult::blocked("b");
        assert!(plain
            .clone()
            .with_sibling_stub(js, &plain)
            .redirect
            .is_none());
        assert!(!MatchResult::allowed().with_sibling_stub(js, &stub).blocked);
    }

    #[test]
    fn redirect_resource_decodes_data_uri() {
        let r = MatchResult::redirect("data:image/gif;base64,R0lGOA==", "rule");
        let res = r.redirect_resource().unwrap();
        assert_eq!(res.mime, "image/gif");
        assert_eq!(res.body, b"GIF8");
        assert!(r.blocked);
        assert!(MatchResult::blocked("x").redirect_resource().is_none());
    }

    #[test]
    fn test_extract_domain() {
        let domain = RequestMatcher::extract_domain("https://example.com/path").unwrap();
        assert_eq!(domain, "example.com");

        let domain2 =
            RequestMatcher::extract_domain("http://subdomain.example.com:8080/path").unwrap();
        assert_eq!(domain2, "subdomain.example.com");
    }
}

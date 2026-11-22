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

    fn to_match_result(result: adblock::blocker::BlockerResult) -> MatchResult {
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
                Some(redirect) => MatchResult::redirect(redirect, rule),
                None => MatchResult::blocked(rule),
            };
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

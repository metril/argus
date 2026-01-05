//! Network request matching using adblock-rust

use crate::{Error, Result};
use adblock::request::Request as AdblockRequest;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Represents the result of a request match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    /// Whether the request should be blocked
    pub blocked: bool,
    /// The filter rule that matched (if any)
    pub matched_rule: Option<String>,
    /// The exception rule that allowed the request (if any)
    pub exception_rule: Option<String>,
    /// Redirect URL if the request should be redirected
    pub redirect: Option<String>,
}

impl MatchResult {
    /// Create a blocked result
    pub fn blocked(rule: impl Into<String>) -> Self {
        Self {
            blocked: true,
            matched_rule: Some(rule.into()),
            exception_rule: None,
            redirect: None,
        }
    }

    /// Create an allowed result
    pub fn allowed() -> Self {
        Self {
            blocked: false,
            matched_rule: None,
            exception_rule: None,
            redirect: None,
        }
    }

    /// Create an allowed result with exception rule
    pub fn allowed_by_exception(rule: impl Into<String>) -> Self {
        Self {
            blocked: false,
            matched_rule: None,
            exception_rule: Some(rule.into()),
            redirect: None,
        }
    }

    /// Create a redirect result
    pub fn redirect(url: impl Into<String>, rule: impl Into<String>) -> Self {
        Self {
            blocked: false,
            matched_rule: Some(rule.into()),
            exception_rule: None,
            redirect: Some(url.into()),
        }
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
        let request = AdblockRequest::new(
            url,
            source_url,
            resource_type,
        )
        .map_err(|e| Error::InvalidSyntax(format!("Invalid request: {}", e)))?;

        // Check against the engine
        let result = engine.check_network_request(&request);

        // Process the result
        if result.matched {
            if let Some(exception) = result.exception {
                debug!("Request allowed by exception: {}", exception);
                Ok(MatchResult::allowed_by_exception(exception))
            } else if let Some(redirect) = result.redirect {
                debug!("Request redirected to: {}", redirect);
                Ok(MatchResult::redirect(
                    redirect,
                    result.filter.unwrap_or_default(),
                ))
            } else {
                debug!("Request blocked: {:?}", result.filter);
                Ok(MatchResult::blocked(
                    result.filter.unwrap_or_else(|| "unknown".to_string()),
                ))
            }
        } else {
            debug!("Request allowed");
            Ok(MatchResult::allowed())
        }
    }

    /// Extract domain from URL
    pub fn extract_domain(url: &str) -> Result<String> {
        let parsed = url::Url::parse(url)?;
        Ok(parsed
            .host_str()
            .unwrap_or("unknown")
            .to_string())
    }

    /// Determine if request is third-party
    pub fn is_third_party(url: &str, source_url: &str) -> bool {
        let url_domain = Self::extract_domain(url).ok();
        let source_domain = Self::extract_domain(source_url).ok();

        match (url_domain, source_domain) {
            (Some(url_d), Some(source_d)) => url_d != source_d,
            _ => false,
        }
    }

    /// Convert HTTP header content-type to resource type
    pub fn content_type_to_resource_type(content_type: &str) -> &'static str {
        let ct = content_type.to_lowercase();

        if ct.contains("text/html") {
            "document"
        } else if ct.contains("text/css") {
            "stylesheet"
        } else if ct.contains("javascript") || ct.contains("application/javascript") {
            "script"
        } else if ct.contains("image/") {
            "image"
        } else if ct.contains("font/") || ct.contains("application/font") {
            "font"
        } else if ct.contains("video/") {
            "media"
        } else if ct.contains("audio/") {
            "media"
        } else {
            "other"
        }
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
    fn test_extract_domain() {
        let domain = RequestMatcher::extract_domain("https://example.com/path").unwrap();
        assert_eq!(domain, "example.com");

        let domain2 = RequestMatcher::extract_domain("http://subdomain.example.com:8080/path").unwrap();
        assert_eq!(domain2, "subdomain.example.com");
    }

    #[test]
    fn test_is_third_party() {
        let is_third_party = RequestMatcher::is_third_party(
            "https://ads.example.com/script.js",
            "https://example.com/page.html",
        );
        assert!(is_third_party);

        let is_first_party = RequestMatcher::is_third_party(
            "https://example.com/script.js",
            "https://example.com/page.html",
        );
        assert!(!is_first_party);
    }

    #[test]
    fn test_content_type_mapping() {
        assert_eq!(
            RequestMatcher::content_type_to_resource_type("text/html; charset=utf-8"),
            "document"
        );
        assert_eq!(
            RequestMatcher::content_type_to_resource_type("text/css"),
            "stylesheet"
        );
        assert_eq!(
            RequestMatcher::content_type_to_resource_type("application/javascript"),
            "script"
        );
        assert_eq!(
            RequestMatcher::content_type_to_resource_type("image/png"),
            "image"
        );
    }
}

//! AdGuard-specific modifier implementations
//!
//! Implements advanced modifiers like $removeparam, $removeheader, $replace, and $redirect

use crate::{Error, Result};
use regex::Regex;
use tracing::debug;
use url::Url;

/// $removeparam modifier - removes query parameters from URLs
pub struct RemoveParamModifier {
    /// Parameters to remove (can be exact names or regex patterns)
    patterns: Vec<ParamPattern>,
}

#[derive(Debug, Clone)]
enum ParamPattern {
    /// Exact parameter name match
    Exact(String),
    /// Regex pattern for parameter matching
    Regex(Regex),
    /// Remove all parameters
    All,
}

impl RemoveParamModifier {
    /// Parse $removeparam modifier value
    ///
    /// Supports:
    /// - `$removeparam=utm_source` - exact match
    /// - `$removeparam=/^utm_/` - regex pattern
    /// - `$removeparam` - remove all parameters
    pub fn parse(value: Option<&str>) -> Result<Self> {
        match value {
            None => Ok(Self {
                patterns: vec![ParamPattern::All],
            }),
            Some(v) if v.is_empty() => Ok(Self {
                patterns: vec![ParamPattern::All],
            }),
            Some(v) => {
                let mut patterns = Vec::new();

                for part in v.split('|') {
                    let part = part.trim();

                    if part.starts_with('/') && part.ends_with('/') {
                        // Regex pattern
                        let pattern = &part[1..part.len() - 1];
                        let regex = Regex::new(pattern)
                            .map_err(|e| Error::InvalidSyntax(format!("Invalid regex in $removeparam: {}", e)))?;
                        patterns.push(ParamPattern::Regex(regex));
                    } else if part.starts_with('/') && part.contains("/i") {
                        // Case-insensitive regex
                        let end = part.rfind("/i").unwrap();
                        let pattern = &part[1..end];
                        let regex = Regex::new(&format!("(?i){}", pattern))
                            .map_err(|e| Error::InvalidSyntax(format!("Invalid regex in $removeparam: {}", e)))?;
                        patterns.push(ParamPattern::Regex(regex));
                    } else {
                        // Exact match
                        patterns.push(ParamPattern::Exact(part.to_string()));
                    }
                }

                Ok(Self { patterns })
            }
        }
    }

    /// Apply parameter removal to a URL
    pub fn apply(&self, url: &str) -> Result<String> {
        let mut parsed = Url::parse(url)?;

        // Check if URL has query parameters
        if parsed.query().is_none() {
            return Ok(url.to_string());
        }

        let original_pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        // Remove matching parameters
        parsed.query_pairs_mut().clear();

        for (key, value) in original_pairs {
            if !self.should_remove(&key) {
                parsed.query_pairs_mut().append_pair(&key, &value);
            } else {
                debug!("Removing parameter: {}={}", key, value);
            }
        }

        // Clear query string if empty
        if parsed.query_pairs().count() == 0 {
            parsed.set_query(None);
        }

        Ok(parsed.to_string())
    }

    fn should_remove(&self, param: &str) -> bool {
        for pattern in &self.patterns {
            match pattern {
                ParamPattern::All => return true,
                ParamPattern::Exact(name) => {
                    if param == name {
                        return true;
                    }
                }
                ParamPattern::Regex(regex) => {
                    if regex.is_match(param) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// $removeheader modifier - removes HTTP headers from requests/responses
pub struct RemoveHeaderModifier {
    /// Header name to remove
    header_name: String,
    /// Whether to remove from request (true) or response (false)
    is_request: bool,
}

impl RemoveHeaderModifier {
    /// Restricted headers that cannot be removed for security
    const RESTRICTED_HEADERS: &'static [&'static str] = &[
        "host",
        "content-length",
        "content-encoding",
        "transfer-encoding",
        "connection",
        "upgrade",
        "expect",
        "te",
        "trailer",
        "proxy-authorization",
        "proxy-authenticate",
        "authorization",
        "www-authenticate",
        "cookie",
        "set-cookie",
        "cookie2",
        "set-cookie2",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-expose-headers",
        "access-control-max-age",
        "access-control-request-method",
        "access-control-request-headers",
        "origin",
        "timing-allow-origin",
        "content-security-policy",
        "content-security-policy-report-only",
        "x-frame-options",
        "x-xss-protection",
        "strict-transport-security",
    ];

    /// Parse $removeheader modifier value
    ///
    /// Supports:
    /// - `$removeheader=refresh` - remove response header
    /// - `$removeheader=request:user-agent` - remove request header
    pub fn parse(value: &str) -> Result<Self> {
        if value.is_empty() {
            return Err(Error::InvalidSyntax("$removeheader requires a header name".to_string()));
        }

        let (is_request, header_name) = if let Some(stripped) = value.strip_prefix("request:") {
            (true, stripped.to_lowercase())
        } else {
            (false, value.to_lowercase())
        };

        // Check if header is restricted
        if Self::RESTRICTED_HEADERS.contains(&header_name.as_str()) {
            return Err(Error::InvalidSyntax(format!(
                "Cannot remove restricted header: {}",
                header_name
            )));
        }

        Ok(Self {
            header_name,
            is_request,
        })
    }

    /// Get the header name to remove
    pub fn header_name(&self) -> &str {
        &self.header_name
    }

    /// Check if this removes a request header
    pub fn is_request_header(&self) -> bool {
        self.is_request
    }

    /// Check if this removes a response header
    pub fn is_response_header(&self) -> bool {
        !self.is_request
    }
}

/// $replace modifier - replaces content in responses
pub struct ReplaceModifier {
    /// Regex pattern to match
    pattern: Regex,
    /// Replacement string
    replacement: String,
}

impl ReplaceModifier {
    /// Maximum response size for $replace (10 MB)
    const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

    /// Parse $replace modifier value
    ///
    /// Format: /regexp/replacement/modifiers
    /// Example: /test1/test2/i
    pub fn parse(value: &str) -> Result<Self> {
        if !value.starts_with('/') {
            return Err(Error::InvalidSyntax("$replace must start with /".to_string()));
        }

        let parts: Vec<&str> = value[1..].splitn(3, '/').collect();

        if parts.len() < 2 {
            return Err(Error::InvalidSyntax("Invalid $replace format, expected /regex/replacement/".to_string()));
        }

        let pattern_str = parts[0];
        let replacement = parts[1].replace(r"\$", "$").replace(r"\,", ",");
        let modifiers = parts.get(2).unwrap_or(&"");

        // Build regex with modifiers
        let regex_str = if modifiers.contains('i') {
            format!("(?i){}", pattern_str)
        } else {
            pattern_str.to_string()
        };

        let pattern = Regex::new(&regex_str)
            .map_err(|e| Error::InvalidSyntax(format!("Invalid regex in $replace: {}", e)))?;

        Ok(Self {
            pattern,
            replacement,
        })
    }

    /// Apply content replacement
    ///
    /// Only applies to text content types, respects size limit
    pub fn apply(&self, content: &str, content_type: &str) -> Result<String> {
        // Check if content type is text
        let ct = content_type.to_lowercase();
        if !ct.contains("text/")
            && !ct.contains("javascript")
            && !ct.contains("json")
            && !ct.contains("xml")
        {
            debug!("Skipping $replace for non-text content type: {}", content_type);
            return Ok(content.to_string());
        }

        // Check size limit
        if content.len() > Self::MAX_RESPONSE_SIZE {
            debug!("Content too large for $replace: {} bytes", content.len());
            return Ok(content.to_string());
        }

        // Apply replacement
        let result = self.pattern.replace_all(content, self.replacement.as_str());

        if result.as_ref() != content {
            debug!("Applied $replace: {} matches", self.pattern.find_iter(content).count());
        }

        Ok(result.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_removeparam_exact() {
        let modifier = RemoveParamModifier::parse(Some("utm_source")).unwrap();
        let result = modifier.apply("https://example.com/page?utm_source=test&other=value").unwrap();
        assert_eq!(result, "https://example.com/page?other=value");
    }

    #[test]
    fn test_removeparam_regex() {
        let modifier = RemoveParamModifier::parse(Some("/^utm_/")).unwrap();
        let result = modifier.apply("https://example.com/page?utm_source=a&utm_medium=b&other=c").unwrap();
        assert_eq!(result, "https://example.com/page?other=c");
    }

    #[test]
    fn test_removeparam_all() {
        let modifier = RemoveParamModifier::parse(None).unwrap();
        let result = modifier.apply("https://example.com/page?a=1&b=2").unwrap();
        assert_eq!(result, "https://example.com/page");
    }

    #[test]
    fn test_removeheader_response() {
        let modifier = RemoveHeaderModifier::parse("refresh").unwrap();
        assert_eq!(modifier.header_name(), "refresh");
        assert!(!modifier.is_request_header());
        assert!(modifier.is_response_header());
    }

    #[test]
    fn test_removeheader_request() {
        let modifier = RemoveHeaderModifier::parse("request:user-agent").unwrap();
        assert_eq!(modifier.header_name(), "user-agent");
        assert!(modifier.is_request_header());
    }

    #[test]
    fn test_removeheader_restricted() {
        let result = RemoveHeaderModifier::parse("content-length");
        assert!(result.is_err());
    }

    #[test]
    fn test_replace_basic() {
        let modifier = ReplaceModifier::parse("/test1/test2/").unwrap();
        let result = modifier.apply("This is test1 content", "text/html").unwrap();
        assert_eq!(result, "This is test2 content");
    }

    #[test]
    fn test_replace_case_insensitive() {
        let modifier = ReplaceModifier::parse("/TEST/replaced/i").unwrap();
        let result = modifier.apply("This is Test content", "text/html").unwrap();
        assert_eq!(result, "This is replaced content");
    }

    #[test]
    fn test_replace_skip_binary() {
        let modifier = ReplaceModifier::parse("/test/replaced/").unwrap();
        let result = modifier.apply("test content", "image/png").unwrap();
        assert_eq!(result, "test content"); // Unchanged
    }
}

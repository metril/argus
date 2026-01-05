//! Cosmetic filtering - element hiding and CSS injection
//!
//! Implements AdGuard's cosmetic filtering rules for hiding elements and injecting
//! custom CSS styles into web pages.

use crate::{Error, Result};
use regex::Regex;
use selectors::parser::SelectorParseErrorKind;
use std::collections::HashMap;
use tracing::debug;

/// Type of cosmetic rule
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CosmeticRuleType {
    /// Element hiding rule (##)
    ElementHiding,
    /// Element hiding exception (#@#)
    ElementHidingException,
    /// Extended CSS element hiding (#?#)
    ExtendedElementHiding,
    /// Extended CSS element hiding exception (#@?#)
    ExtendedElementHidingException,
    /// CSS injection rule (#$#)
    CssInjection,
    /// CSS injection exception (#@$#)
    CssInjectionException,
}

/// Represents a cosmetic filtering rule
#[derive(Debug, Clone)]
pub struct CosmeticRule {
    /// Type of cosmetic rule
    pub rule_type: CosmeticRuleType,
    /// Domain restrictions (None = all domains)
    pub domains: Option<Vec<String>>,
    /// CSS selector or XPath expression
    pub selector: String,
    /// CSS style declarations (for injection rules only)
    pub style: Option<String>,
    /// Whether this uses extended CSS selectors
    pub is_extended: bool,
    /// Original rule text
    pub raw_rule: String,
}

impl CosmeticRule {
    /// Parse a cosmetic filtering rule
    ///
    /// Supports:
    /// - `##selector` - hide elements matching selector
    /// - `#@#selector` - exception for hiding rule
    /// - `#?#selector` - hide with extended CSS
    /// - `#@?#selector` - exception for extended CSS
    /// - `#$#selector { style }` - inject CSS
    /// - `#@$#selector { style }` - exception for CSS injection
    /// - `domain.com##selector` - domain-specific rules
    pub fn parse(rule: &str) -> Result<Self> {
        let rule = rule.trim();

        if rule.is_empty() || rule.starts_with('!') {
            return Err(Error::InvalidSyntax("Empty or comment rule".to_string()));
        }

        // Determine rule type and split into domains and selector parts
        let (rule_type, domains_part, selector_part) = Self::parse_rule_type(rule)?;

        // Parse domain restrictions
        let domains = if domains_part.is_empty() {
            None
        } else {
            Some(Self::parse_domains(domains_part)?)
        };

        // For CSS injection, split selector and style
        let (selector, style) = if matches!(
            rule_type,
            CosmeticRuleType::CssInjection | CosmeticRuleType::CssInjectionException
        ) {
            Self::parse_css_injection(selector_part)?
        } else {
            (selector_part.to_string(), None)
        };

        // Detect if extended CSS is needed
        let is_extended = matches!(
            rule_type,
            CosmeticRuleType::ExtendedElementHiding | CosmeticRuleType::ExtendedElementHidingException
        ) || Self::has_extended_selectors(&selector);

        Ok(Self {
            rule_type,
            domains,
            selector,
            style,
            is_extended,
            raw_rule: rule.to_string(),
        })
    }

    /// Determine rule type from marker
    fn parse_rule_type(rule: &str) -> Result<(CosmeticRuleType, &str, &str)> {
        // Try to find the cosmetic marker
        if let Some(pos) = rule.find("#@?#") {
            return Ok((
                CosmeticRuleType::ExtendedElementHidingException,
                &rule[..pos],
                &rule[pos + 4..],
            ));
        }
        if let Some(pos) = rule.find("#?#") {
            return Ok((
                CosmeticRuleType::ExtendedElementHiding,
                &rule[..pos],
                &rule[pos + 3..],
            ));
        }
        if let Some(pos) = rule.find("#@$#") {
            return Ok((
                CosmeticRuleType::CssInjectionException,
                &rule[..pos],
                &rule[pos + 4..],
            ));
        }
        if let Some(pos) = rule.find("#$#") {
            return Ok((
                CosmeticRuleType::CssInjection,
                &rule[..pos],
                &rule[pos + 3..],
            ));
        }
        if let Some(pos) = rule.find("#@#") {
            return Ok((
                CosmeticRuleType::ElementHidingException,
                &rule[..pos],
                &rule[pos + 3..],
            ));
        }
        if let Some(pos) = rule.find("##") {
            return Ok((
                CosmeticRuleType::ElementHiding,
                &rule[..pos],
                &rule[pos + 2..],
            ));
        }

        Err(Error::InvalidSyntax(format!(
            "No cosmetic filter marker found in rule: {}",
            rule
        )))
    }

    /// Parse domain restrictions
    fn parse_domains(domains_part: &str) -> Result<Vec<String>> {
        let domains: Vec<String> = domains_part
            .split(',')
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty())
            .collect();

        if domains.is_empty() {
            return Err(Error::InvalidSyntax("Empty domain list".to_string()));
        }

        Ok(domains)
    }

    /// Parse CSS injection rule to extract selector and style
    fn parse_css_injection(part: &str) -> Result<(String, Option<String>)> {
        if let Some(open_brace) = part.find('{') {
            if let Some(close_brace) = part.rfind('}') {
                if open_brace < close_brace {
                    let selector = part[..open_brace].trim().to_string();
                    let style = part[open_brace + 1..close_brace].trim().to_string();

                    // Validate style doesn't contain url() for security
                    if style.to_lowercase().contains("url(") {
                        return Err(Error::InvalidSyntax(
                            "CSS injection cannot use url() values".to_string(),
                        ));
                    }

                    return Ok((selector, Some(style)));
                }
            }
        }

        // No style declaration - treat as selector-only
        Ok((part.to_string(), None))
    }

    /// Check if selector contains extended CSS features
    fn has_extended_selectors(selector: &str) -> bool {
        selector.contains(":contains(")
            || selector.contains(":matches-css(")
            || selector.contains(":has(")
            || selector.contains(":xpath(")
            || selector.contains(":nth-ancestor(")
            || selector.contains(":upward(")
            || selector.contains(":remove(")
            || selector.contains(":-abp-")
    }

    /// Check if this rule applies to a given domain
    pub fn matches_domain(&self, domain: &str) -> bool {
        match &self.domains {
            None => true, // No domain restrictions = applies to all domains
            Some(domains) => {
                for rule_domain in domains {
                    if rule_domain.starts_with('~') {
                        // Negation - if domain matches, rule doesn't apply
                        let excluded = &rule_domain[1..];
                        if Self::domain_matches(domain, excluded) {
                            return false;
                        }
                    } else {
                        // Positive match
                        if Self::domain_matches(domain, rule_domain) {
                            return true;
                        }
                    }
                }
                // If we have domains but none matched positively
                false
            }
        }
    }

    /// Check if a domain matches a rule domain (supports wildcards)
    fn domain_matches(domain: &str, rule_domain: &str) -> bool {
        // Exact match
        if domain == rule_domain {
            return true;
        }

        // Subdomain match (rule for example.com matches www.example.com)
        if domain.ends_with(&format!(".{}", rule_domain)) {
            return true;
        }

        false
    }

    /// Generate CSS to hide matching elements
    pub fn to_hiding_css(&self) -> Option<String> {
        match self.rule_type {
            CosmeticRuleType::ElementHiding | CosmeticRuleType::ExtendedElementHiding => {
                Some(format!("{} {{ display: none !important; }}", self.selector))
            }
            _ => None,
        }
    }

    /// Get CSS injection style
    pub fn to_injection_css(&self) -> Option<String> {
        match self.rule_type {
            CosmeticRuleType::CssInjection => {
                if let Some(style) = &self.style {
                    Some(format!("{} {{ {} }}", self.selector, style))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Check if this is an exception rule
    pub fn is_exception(&self) -> bool {
        matches!(
            self.rule_type,
            CosmeticRuleType::ElementHidingException
                | CosmeticRuleType::ExtendedElementHidingException
                | CosmeticRuleType::CssInjectionException
        )
    }
}

/// Manager for cosmetic filtering rules
pub struct CosmeticFilterManager {
    /// All cosmetic rules indexed by domain
    rules: HashMap<String, Vec<CosmeticRule>>,
    /// Global rules (no domain restriction)
    global_rules: Vec<CosmeticRule>,
}

impl CosmeticFilterManager {
    /// Create a new cosmetic filter manager
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            global_rules: Vec::new(),
        }
    }

    /// Add a cosmetic rule
    pub fn add_rule(&mut self, rule: CosmeticRule) {
        if let Some(domains) = &rule.domains {
            for domain in domains {
                let domain_key = domain.trim_start_matches('~').to_string();
                self.rules
                    .entry(domain_key)
                    .or_insert_with(Vec::new)
                    .push(rule.clone());
            }
        } else {
            self.global_rules.push(rule);
        }
    }

    /// Parse and add a rule from string
    pub fn add_rule_from_string(&mut self, rule_str: &str) -> Result<()> {
        let rule = CosmeticRule::parse(rule_str)?;
        self.add_rule(rule);
        Ok(())
    }

    /// Get all rules that apply to a domain
    pub fn get_rules_for_domain(&self, domain: &str) -> Vec<&CosmeticRule> {
        let mut applicable_rules = Vec::new();

        // Add global rules
        for rule in &self.global_rules {
            if rule.matches_domain(domain) {
                applicable_rules.push(rule);
            }
        }

        // Add domain-specific rules
        if let Some(domain_rules) = self.rules.get(domain) {
            for rule in domain_rules {
                if rule.matches_domain(domain) {
                    applicable_rules.push(rule);
                }
            }
        }

        // Check parent domains
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let parent_domain = parts[i..].join(".");
            if let Some(parent_rules) = self.rules.get(&parent_domain) {
                for rule in parent_rules {
                    if rule.matches_domain(domain) {
                        applicable_rules.push(rule);
                    }
                }
            }
        }

        applicable_rules
    }

    /// Generate combined CSS for element hiding
    pub fn get_hiding_css(&self, domain: &str) -> String {
        let rules = self.get_rules_for_domain(domain);
        let mut selectors = Vec::new();
        let mut exceptions = Vec::new();

        for rule in rules {
            if rule.is_exception() {
                exceptions.push(&rule.selector);
            } else if let Some(_) = rule.to_hiding_css() {
                if !exceptions.contains(&&rule.selector) {
                    selectors.push(&rule.selector);
                }
            }
        }

        if selectors.is_empty() {
            return String::new();
        }

        format!(
            "{} {{ display: none !important; }}",
            selectors.join(", ")
        )
    }

    /// Generate combined CSS for injection
    pub fn get_injection_css(&self, domain: &str) -> String {
        let rules = self.get_rules_for_domain(domain);
        let mut css_parts = Vec::new();

        for rule in rules {
            if !rule.is_exception() {
                if let Some(css) = rule.to_injection_css() {
                    css_parts.push(css);
                }
            }
        }

        css_parts.join("\n")
    }
}

impl Default for CosmeticFilterManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_element_hiding() {
        let rule = CosmeticRule::parse("##.ad-banner").unwrap();
        assert_eq!(rule.rule_type, CosmeticRuleType::ElementHiding);
        assert_eq!(rule.selector, ".ad-banner");
        assert!(rule.domains.is_none());
    }

    #[test]
    fn test_parse_domain_specific() {
        let rule = CosmeticRule::parse("example.com##.ad-banner").unwrap();
        assert_eq!(rule.domains, Some(vec!["example.com".to_string()]));
    }

    #[test]
    fn test_parse_multiple_domains() {
        let rule = CosmeticRule::parse("example.com,test.org##.ad-banner").unwrap();
        assert_eq!(
            rule.domains,
            Some(vec!["example.com".to_string(), "test.org".to_string()])
        );
    }

    #[test]
    fn test_parse_extended_css() {
        let rule = CosmeticRule::parse("##div:has(> .ad)").unwrap();
        assert!(rule.is_extended);
        assert!(rule.has_extended_selectors(&rule.selector));
    }

    #[test]
    fn test_parse_css_injection() {
        let rule = CosmeticRule::parse("example.com#$#.element { color: red; }").unwrap();
        assert_eq!(rule.rule_type, CosmeticRuleType::CssInjection);
        assert_eq!(rule.selector, ".element");
        assert_eq!(rule.style, Some("color: red;".to_string()));
    }

    #[test]
    fn test_css_injection_no_url() {
        let result = CosmeticRule::parse("##.element { background: url(ad.png); }");
        assert!(result.is_err());
    }

    #[test]
    fn test_domain_matching() {
        let rule = CosmeticRule::parse("example.com##.ad").unwrap();
        assert!(rule.matches_domain("example.com"));
        assert!(rule.matches_domain("www.example.com"));
        assert!(!rule.matches_domain("test.com"));
    }

    #[test]
    fn test_domain_negation() {
        let rule = CosmeticRule::parse("~example.com##.ad").unwrap();
        assert!(!rule.matches_domain("example.com"));
        assert!(rule.matches_domain("test.com"));
    }

    #[test]
    fn test_exception_rule() {
        let rule = CosmeticRule::parse("example.com#@#.ad").unwrap();
        assert!(rule.is_exception());
        assert_eq!(rule.rule_type, CosmeticRuleType::ElementHidingException);
    }

    #[test]
    fn test_manager_add_rules() {
        let mut manager = CosmeticFilterManager::new();
        manager.add_rule_from_string("##.ad-banner").unwrap();
        manager
            .add_rule_from_string("example.com##.specific-ad")
            .unwrap();

        let css = manager.get_hiding_css("example.com");
        assert!(css.contains(".ad-banner"));
        assert!(css.contains(".specific-ad"));
    }

    #[test]
    fn test_manager_exceptions() {
        let mut manager = CosmeticFilterManager::new();
        manager.add_rule_from_string("##.ad-banner").unwrap();
        manager
            .add_rule_from_string("example.com#@#.ad-banner")
            .unwrap();

        let css = manager.get_hiding_css("example.com");
        assert!(!css.contains(".ad-banner")); // Exception should prevent hiding
    }
}

//! Filter rule safety validation
//!
//! Provides protection against malicious filter rules, particularly:
//! - ReDoS (Regular Expression Denial of Service) attacks
//! - Overly complex rules that consume excessive resources
//! - Rules with dangerous patterns

use crate::{Error, Result};
use regex::Regex;
use std::time::Duration;
use tracing::{debug, warn};

/// Configuration for filter rule validation
#[derive(Debug, Clone)]
pub struct FilterSafetyConfig {
    /// Maximum allowed rule length in characters
    pub max_rule_length: usize,
    /// Maximum regex compilation timeout
    pub regex_compile_timeout: Duration,
    /// Maximum regex pattern complexity (estimated)
    pub max_pattern_complexity: u32,
    /// Whether to block potentially dangerous patterns
    pub block_dangerous_patterns: bool,
}

impl Default for FilterSafetyConfig {
    fn default() -> Self {
        Self {
            max_rule_length: 4096,
            regex_compile_timeout: Duration::from_secs(1),
            max_pattern_complexity: 1000,
            block_dangerous_patterns: true,
        }
    }
}

/// Result of filter rule validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the rule is safe to use
    pub is_safe: bool,
    /// Estimated complexity score
    pub complexity_score: u32,
    /// Warning messages (rule is safe but has issues)
    pub warnings: Vec<String>,
    /// Error messages (rule is not safe)
    pub errors: Vec<String>,
}

impl ValidationResult {
    /// Create a valid result
    pub fn valid(complexity_score: u32) -> Self {
        Self {
            is_safe: true,
            complexity_score,
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Create a valid result with warnings
    pub fn valid_with_warnings(complexity_score: u32, warnings: Vec<String>) -> Self {
        Self {
            is_safe: true,
            complexity_score,
            warnings,
            errors: Vec::new(),
        }
    }

    /// Create an invalid result
    pub fn invalid(errors: Vec<String>) -> Self {
        Self {
            is_safe: false,
            complexity_score: 0,
            warnings: Vec::new(),
            errors,
        }
    }
}

/// Filter rule validator for safety checks
pub struct FilterValidator {
    config: FilterSafetyConfig,
    /// Dangerous regex patterns that can cause ReDoS
    dangerous_patterns: Vec<&'static str>,
}

impl FilterValidator {
    /// Create a new validator with the given configuration
    pub fn new(config: FilterSafetyConfig) -> Self {
        Self {
            config,
            dangerous_patterns: vec![
                // Nested quantifiers - common ReDoS patterns
                r"(\w+)*",
                r"(\w*)+",
                r"(.*)*",
                r"(.+)+",
                r"([a-zA-Z]+)*",
                r"(\d+)+",
                // Multiple wildcards
                r".*.*.*",
                r".+.+.+",
                // Alternation with overlapping patterns
                r"(a|a)+",
                r"(aa|a)+",
                // Exponential backtracking patterns
                r"(a+)+",
                r"(a*)+",
            ],
        }
    }

    /// Create a validator with default configuration
    pub fn with_defaults() -> Self {
        Self::new(FilterSafetyConfig::default())
    }

    /// Validate a filter rule
    pub fn validate_rule(&self, rule: &str) -> ValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut complexity_score = 0u32;

        // Check rule length
        if rule.len() > self.config.max_rule_length {
            errors.push(format!(
                "Rule exceeds maximum length ({} > {})",
                rule.len(),
                self.config.max_rule_length
            ));
            return ValidationResult::invalid(errors);
        }

        // Check for regex patterns (indicated by / delimiters)
        if self.contains_regex(rule) {
            if let Some(regex_part) = self.extract_regex(rule) {
                // Validate the regex pattern
                match self.validate_regex(&regex_part) {
                    Ok((score, regex_warnings)) => {
                        complexity_score += score;
                        warnings.extend(regex_warnings);
                    }
                    Err(regex_errors) => {
                        errors.extend(regex_errors);
                    }
                }
            }
        }

        // Calculate complexity score for non-regex parts
        complexity_score += self.calculate_complexity(rule);

        // Check for overly complex rules
        if complexity_score > self.config.max_pattern_complexity {
            errors.push(format!(
                "Rule complexity score ({}) exceeds maximum ({})",
                complexity_score, self.config.max_pattern_complexity
            ));
        }

        if errors.is_empty() {
            if warnings.is_empty() {
                ValidationResult::valid(complexity_score)
            } else {
                ValidationResult::valid_with_warnings(complexity_score, warnings)
            }
        } else {
            ValidationResult::invalid(errors)
        }
    }

    /// Check if rule contains regex patterns
    fn contains_regex(&self, rule: &str) -> bool {
        // Filter rules with regex are typically delimited with /regex/
        rule.contains('/')
    }

    /// Extract regex portion from a rule
    fn extract_regex(&self, rule: &str) -> Option<String> {
        // Look for /.../ patterns
        let mut in_regex = false;
        let mut regex_start = 0;
        let chars: Vec<char> = rule.chars().collect();

        for (i, &c) in chars.iter().enumerate() {
            if c == '/' && !in_regex {
                if i > 0 || rule.starts_with('/') {
                    in_regex = true;
                    regex_start = i + 1;
                }
            } else if c == '/' && in_regex {
                if regex_start < i {
                    return Some(chars[regex_start..i].iter().collect());
                }
            }
        }

        None
    }

    /// Validate a regex pattern
    fn validate_regex(&self, pattern: &str) -> std::result::Result<(u32, Vec<String>), Vec<String>> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut complexity_score = 0u32;

        // Check for dangerous patterns
        if self.config.block_dangerous_patterns {
            for dangerous in &self.dangerous_patterns {
                if pattern.contains(dangerous) {
                    errors.push(format!(
                        "Pattern contains potentially dangerous regex: {}",
                        dangerous
                    ));
                }
            }
        }

        // Check for nested quantifiers (main ReDoS vector)
        if self.has_nested_quantifiers(pattern) {
            errors.push("Pattern contains nested quantifiers (ReDoS risk)".to_string());
        }

        // Calculate complexity
        complexity_score += self.calculate_regex_complexity(pattern);

        // Try to compile the regex with a complexity check
        if complexity_score > 100 {
            warnings.push(format!(
                "High complexity regex pattern (score: {})",
                complexity_score
            ));
        }

        // Actually try to compile the regex
        match Regex::new(pattern) {
            Ok(_) => {
                debug!("Regex compiled successfully: {}", pattern);
            }
            Err(e) => {
                errors.push(format!("Invalid regex: {}", e));
            }
        }

        if errors.is_empty() {
            Ok((complexity_score, warnings))
        } else {
            Err(errors)
        }
    }

    /// Check for nested quantifiers that can cause ReDoS
    fn has_nested_quantifiers(&self, pattern: &str) -> bool {
        // Check for consecutive quantifiers (++, *+, +*, **)
        let chars: Vec<char> = pattern.chars().collect();
        for i in 0..chars.len().saturating_sub(1) {
            let c1 = chars[i];
            let c2 = chars[i + 1];
            if (c1 == '+' || c1 == '*') && (c2 == '+' || c2 == '*') {
                return true;
            }
        }

        // Check for patterns like (x+)* or (x*)+
        let mut in_group = false;
        let mut group_has_quantifier = false;
        for (i, c) in chars.iter().enumerate() {
            match c {
                '(' => {
                    in_group = true;
                    group_has_quantifier = false;
                }
                '+' | '*' if in_group => {
                    group_has_quantifier = true;
                }
                ')' => {
                    in_group = false;
                    if group_has_quantifier {
                        if i + 1 < chars.len() && (chars[i + 1] == '+' || chars[i + 1] == '*') {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }

        false
    }

    /// Calculate complexity score for regex pattern
    fn calculate_regex_complexity(&self, pattern: &str) -> u32 {
        let mut score = 0u32;

        // Count quantifiers
        let quantifiers = pattern.matches('*').count()
            + pattern.matches('+').count()
            + pattern.matches('?').count();
        score += (quantifiers as u32) * 10;

        // Count groups
        let groups = pattern.matches('(').count();
        score += (groups as u32) * 5;

        // Count alternations
        let alternations = pattern.matches('|').count();
        score += (alternations as u32) * 15;

        // Count character classes
        let char_classes = pattern.matches('[').count();
        score += (char_classes as u32) * 5;

        // Count wildcards
        let wildcards = pattern.matches('.').count();
        score += (wildcards as u32) * 3;

        // Length factor
        score += (pattern.len() as u32) / 10;

        score
    }

    /// Calculate overall rule complexity
    fn calculate_complexity(&self, rule: &str) -> u32 {
        let mut score = 0u32;

        // Count modifiers
        let modifiers = rule.matches('$').count();
        score += (modifiers as u32) * 5;

        // Count domain specifiers
        let domain_ops = rule.matches("domain=").count();
        score += (domain_ops as u32) * 10;

        // Count pipes (used in domain lists)
        let pipes = rule.matches('|').count();
        score += (pipes as u32) * 2;

        // Count negations
        let negations = rule.matches('~').count();
        score += (negations as u32) * 3;

        // Length factor
        score += (rule.len() as u32) / 20;

        score
    }

    /// Validate a list of rules, returning only the safe ones
    pub fn validate_and_filter(&self, rules: &[String]) -> (Vec<String>, Vec<(String, String)>) {
        let mut valid_rules = Vec::new();
        let mut rejected_rules = Vec::new();

        for rule in rules {
            let result = self.validate_rule(rule);
            if result.is_safe {
                valid_rules.push(rule.clone());
                if !result.warnings.is_empty() {
                    debug!(
                        "Rule has warnings: {} - {:?}",
                        truncate_rule(rule, 50),
                        result.warnings
                    );
                }
            } else {
                warn!(
                    "Rejecting unsafe rule: {} - {:?}",
                    truncate_rule(rule, 50),
                    result.errors
                );
                rejected_rules.push((rule.clone(), result.errors.join("; ")));
            }
        }

        (valid_rules, rejected_rules)
    }
}

/// Truncate a rule for logging purposes
fn truncate_rule(rule: &str, max_len: usize) -> String {
    if rule.len() <= max_len {
        rule.to_string()
    } else {
        format!("{}...", &rule[..max_len])
    }
}

/// Validate a single filter rule with default settings
pub fn validate_filter_rule(rule: &str) -> Result<()> {
    let validator = FilterValidator::with_defaults();
    let result = validator.validate_rule(rule);

    if result.is_safe {
        Ok(())
    } else {
        Err(Error::InvalidSyntax(result.errors.join("; ")))
    }
}

/// Validate a list of filter rules with default settings
pub fn validate_filter_rules(rules: &[String]) -> (Vec<String>, Vec<(String, String)>) {
    let validator = FilterValidator::with_defaults();
    validator.validate_and_filter(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_simple_rule() {
        let validator = FilterValidator::with_defaults();

        let result = validator.validate_rule("||example.com^");
        assert!(result.is_safe);

        let result = validator.validate_rule("||ads.example.com^$third-party");
        assert!(result.is_safe);
    }

    #[test]
    fn test_reject_long_rule() {
        let validator = FilterValidator::with_defaults();

        let long_rule = "x".repeat(5000);
        let result = validator.validate_rule(&long_rule);
        assert!(!result.is_safe);
        assert!(result.errors.iter().any(|e| e.contains("maximum length")));
    }

    #[test]
    fn test_detect_dangerous_regex() {
        let config = FilterSafetyConfig {
            block_dangerous_patterns: true,
            ..Default::default()
        };
        let validator = FilterValidator::new(config);

        // Nested quantifiers - ReDoS risk
        let result = validator.validate_rule("/(.*)*/");
        assert!(!result.is_safe);
    }

    #[test]
    fn test_complexity_calculation() {
        let validator = FilterValidator::with_defaults();

        // Simple rule
        let simple_result = validator.validate_rule("||example.com^");
        let simple_complexity = simple_result.complexity_score;

        // Complex rule
        let complex_result = validator.validate_rule(
            "||example.com^$domain=a.com|b.com|c.com,third-party,~popup",
        );
        let complex_complexity = complex_result.complexity_score;

        assert!(complex_complexity > simple_complexity);
    }

    #[test]
    fn test_validate_and_filter() {
        let validator = FilterValidator::with_defaults();

        let rules = vec![
            "||example.com^".to_string(),
            "||ads.com^".to_string(),
            "x".repeat(5000), // Too long
        ];

        let (valid, rejected) = validator.validate_and_filter(&rules);

        assert_eq!(valid.len(), 2);
        assert_eq!(rejected.len(), 1);
    }

    #[test]
    fn test_extract_regex() {
        let validator = FilterValidator::with_defaults();

        // Simple regex
        assert_eq!(
            validator.extract_regex("/test/"),
            Some("test".to_string())
        );
    }

    #[test]
    fn test_nested_quantifier_detection() {
        let validator = FilterValidator::with_defaults();

        // These should be detected as dangerous
        let dangerous = vec![
            "/(a+)+/",
            "/(.*)+/",
        ];

        for rule in dangerous {
            let result = validator.validate_rule(rule);
            assert!(!result.errors.is_empty() || !result.is_safe);
        }
    }
}

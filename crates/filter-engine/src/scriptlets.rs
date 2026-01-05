//! Scriptlet injection for advanced filtering
//!
//! Implements AdGuard/uBlock Origin scriptlet syntax for JavaScript injection
//! that modifies page behavior without blocking network requests.

use crate::{Error, Result};
use std::collections::HashMap;
use tracing::debug;

/// Represents a scriptlet injection rule
#[derive(Debug, Clone)]
pub struct ScriptletRule {
    /// Domain restrictions (None = all domains)
    pub domains: Option<Vec<String>>,
    /// Scriptlet name
    pub scriptlet_name: String,
    /// Scriptlet arguments
    pub arguments: Vec<String>,
    /// Whether this is an exception rule
    pub is_exception: bool,
    /// Original rule text
    pub raw_rule: String,
}

impl ScriptletRule {
    /// Parse a scriptlet rule
    ///
    /// Supports:
    /// - `#%#//scriptlet('name', 'arg1', 'arg2')` - AdGuard syntax
    /// - `#@%#//scriptlet('name')` - Exception rule
    /// - `domain.com#%#//scriptlet('name')` - Domain-specific
    pub fn parse(rule: &str) -> Result<Self> {
        let rule = rule.trim();

        if rule.is_empty() || rule.starts_with('!') {
            return Err(Error::InvalidSyntax("Empty or comment rule".to_string()));
        }

        // Check if this is an exception rule
        let is_exception = rule.contains("#@%#");
        let marker = if is_exception { "#@%#" } else { "#%#" };

        // Find the marker position
        let marker_pos = rule
            .find(marker)
            .ok_or_else(|| Error::InvalidSyntax("No scriptlet marker found".to_string()))?;

        // Split into domains and scriptlet parts
        let domains_part = &rule[..marker_pos];
        let scriptlet_part = &rule[marker_pos + marker.len()..];

        // Parse domain restrictions
        let domains = if domains_part.is_empty() {
            None
        } else {
            Some(Self::parse_domains(domains_part)?)
        };

        // Parse scriptlet function call
        let (scriptlet_name, arguments) = Self::parse_scriptlet_call(scriptlet_part)?;

        Ok(Self {
            domains,
            scriptlet_name,
            arguments,
            is_exception,
            raw_rule: rule.to_string(),
        })
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

    /// Parse scriptlet function call
    ///
    /// Supports formats:
    /// - //scriptlet('name')
    /// - //scriptlet('name', 'arg1')
    /// - //scriptlet("name", "arg1", "arg2")
    /// - //scriptlet('name', 'arg with spaces')
    fn parse_scriptlet_call(call: &str) -> Result<(String, Vec<String>)> {
        let call = call.trim();

        // Must start with //scriptlet(
        if !call.starts_with("//scriptlet(") {
            return Err(Error::InvalidSyntax(format!(
                "Scriptlet must start with //scriptlet(, got: {}",
                call
            )));
        }

        // Must end with )
        if !call.ends_with(')') {
            return Err(Error::InvalidSyntax(format!(
                "Scriptlet must end with ), got: {}",
                call
            )));
        }

        // Extract content between ( and )
        let content = &call[12..call.len() - 1]; // "//scriptlet(".len() == 12

        if content.is_empty() {
            return Err(Error::InvalidSyntax(
                "Scriptlet name is required".to_string(),
            ));
        }

        // Parse arguments (handle both single and double quotes)
        let parts = Self::parse_quoted_arguments(content)?;

        if parts.is_empty() {
            return Err(Error::InvalidSyntax(
                "Scriptlet name is required".to_string(),
            ));
        }

        let scriptlet_name = parts[0].clone();
        let arguments = parts[1..].to_vec();

        Ok((scriptlet_name, arguments))
    }

    /// Parse quoted arguments from scriptlet call
    fn parse_quoted_arguments(content: &str) -> Result<Vec<String>> {
        let mut parts = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut quote_char = ' ';
        let mut chars = content.chars().peekable();

        while let Some(ch) = chars.next() {
            match ch {
                '\'' | '"' if !in_quotes => {
                    in_quotes = true;
                    quote_char = ch;
                }
                '\'' | '"' if in_quotes && ch == quote_char => {
                    in_quotes = false;
                    if !current.is_empty() {
                        parts.push(current.clone());
                        current.clear();
                    }
                }
                ',' if !in_quotes => {
                    // Skip comma separators outside quotes
                    continue;
                }
                ' ' | '\t' if !in_quotes => {
                    // Skip whitespace outside quotes
                    continue;
                }
                '\\' if in_quotes => {
                    // Handle escape sequences
                    if let Some(next_ch) = chars.next() {
                        current.push(next_ch);
                    }
                }
                _ if in_quotes => {
                    current.push(ch);
                }
                _ => {
                    // Unexpected character outside quotes
                    if !ch.is_whitespace() {
                        return Err(Error::InvalidSyntax(format!(
                            "Unexpected character outside quotes: {}",
                            ch
                        )));
                    }
                }
            }
        }

        if in_quotes {
            return Err(Error::InvalidSyntax(
                "Unclosed quote in scriptlet arguments".to_string(),
            ));
        }

        Ok(parts)
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

    /// Check if a domain matches a rule domain
    fn domain_matches(domain: &str, rule_domain: &str) -> bool {
        // Exact match
        if domain == rule_domain {
            return true;
        }

        // Subdomain match
        if domain.ends_with(&format!(".{}", rule_domain)) {
            return true;
        }

        false
    }
}

/// Manager for scriptlet injection rules
pub struct ScriptletManager {
    /// All scriptlet rules indexed by domain
    rules: HashMap<String, Vec<ScriptletRule>>,
    /// Global rules (no domain restriction)
    global_rules: Vec<ScriptletRule>,
    /// Built-in scriptlet implementations
    scriptlet_library: ScriptletLibrary,
}

impl ScriptletManager {
    /// Create a new scriptlet manager
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            global_rules: Vec::new(),
            scriptlet_library: ScriptletLibrary::new(),
        }
    }

    /// Add a scriptlet rule
    pub fn add_rule(&mut self, rule: ScriptletRule) {
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
        let rule = ScriptletRule::parse(rule_str)?;
        self.add_rule(rule);
        Ok(())
    }

    /// Get all rules that apply to a domain
    pub fn get_rules_for_domain(&self, domain: &str) -> Vec<&ScriptletRule> {
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

    /// Get JavaScript code for all applicable scriptlets
    pub fn get_scriptlet_code(&self, domain: &str) -> String {
        let rules = self.get_rules_for_domain(domain);
        let mut code_parts = Vec::new();

        for rule in rules {
            if !rule.is_exception {
                if let Some(code) = self
                    .scriptlet_library
                    .get_scriptlet(&rule.scriptlet_name, &rule.arguments)
                {
                    code_parts.push(code);
                }
            }
        }

        if code_parts.is_empty() {
            return String::new();
        }

        // Wrap in IIFE for isolation
        format!(
            "(function() {{\n'use strict';\n{}\n}})();",
            code_parts.join("\n\n")
        )
    }
}

impl Default for ScriptletManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Built-in scriptlet library
struct ScriptletLibrary {
    scriptlets: HashMap<String, Box<dyn Fn(&[String]) -> String>>,
}

impl ScriptletLibrary {
    fn new() -> Self {
        let mut scriptlets: HashMap<String, Box<dyn Fn(&[String]) -> String>> = HashMap::new();

        // abort-on-property-read
        scriptlets.insert(
            "abort-on-property-read".to_string(),
            Box::new(|args: &[String]| {
                if args.is_empty() {
                    return String::new();
                }
                let property = &args[0];
                format!(
                    r#"
(function() {{
    var property = '{}';
    var descriptor = Object.getOwnPropertyDescriptor(window, property);
    if (descriptor && !descriptor.configurable) {{
        return;
    }}
    Object.defineProperty(window, property, {{
        get: function() {{
            throw new ReferenceError('Prevented access to ' + property);
        }},
        set: function() {{}}
    }});
}})();
"#,
                    property
                )
            }),
        );

        // abort-on-property-write
        scriptlets.insert(
            "abort-on-property-write".to_string(),
            Box::new(|args: &[String]| {
                if args.is_empty() {
                    return String::new();
                }
                let property = &args[0];
                format!(
                    r#"
(function() {{
    var property = '{}';
    var descriptor = Object.getOwnPropertyDescriptor(window, property);
    if (descriptor && !descriptor.configurable) {{
        return;
    }}
    Object.defineProperty(window, property, {{
        set: function() {{
            throw new ReferenceError('Prevented write to ' + property);
        }}
    }});
}})();
"#,
                    property
                )
            }),
        );

        // set-constant
        scriptlets.insert(
            "set-constant".to_string(),
            Box::new(|args: &[String]| {
                if args.len() < 2 {
                    return String::new();
                }
                let property = &args[0];
                let value = &args[1];
                format!(
                    r#"
(function() {{
    var property = '{}';
    var value = '{}';
    var parsedValue;
    if (value === 'true') parsedValue = true;
    else if (value === 'false') parsedValue = false;
    else if (value === 'null') parsedValue = null;
    else if (value === 'undefined') parsedValue = undefined;
    else if (!isNaN(value)) parsedValue = parseFloat(value);
    else parsedValue = value;

    Object.defineProperty(window, property, {{
        get: function() {{ return parsedValue; }},
        set: function() {{}}
    }});
}})();
"#,
                    property, value
                )
            }),
        );

        // remove-attr
        scriptlets.insert(
            "remove-attr".to_string(),
            Box::new(|args: &[String]| {
                if args.len() < 2 {
                    return String::new();
                }
                let attr = &args[0];
                let selector = &args[1];
                format!(
                    r#"
(function() {{
    var attr = '{}';
    var selector = '{}';
    var removeAttr = function() {{
        var elements = document.querySelectorAll(selector);
        elements.forEach(function(el) {{
            el.removeAttribute(attr);
        }});
    }};
    if (document.readyState === 'loading') {{
        document.addEventListener('DOMContentLoaded', removeAttr);
    }} else {{
        removeAttr();
    }}
    var observer = new MutationObserver(removeAttr);
    observer.observe(document.documentElement, {{
        childList: true,
        subtree: true
    }});
}})();
"#,
                    attr, selector
                )
            }),
        );

        // remove-class
        scriptlets.insert(
            "remove-class".to_string(),
            Box::new(|args: &[String]| {
                if args.len() < 2 {
                    return String::new();
                }
                let class = &args[0];
                let selector = &args[1];
                format!(
                    r#"
(function() {{
    var className = '{}';
    var selector = '{}';
    var removeClass = function() {{
        var elements = document.querySelectorAll(selector);
        elements.forEach(function(el) {{
            el.classList.remove(className);
        }});
    }};
    if (document.readyState === 'loading') {{
        document.addEventListener('DOMContentLoaded', removeClass);
    }} else {{
        removeClass();
    }}
    var observer = new MutationObserver(removeClass);
    observer.observe(document.documentElement, {{
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['class']
    }});
}})();
"#,
                    class, selector
                )
            }),
        );

        // noopjs - no-operation function
        scriptlets.insert(
            "noopjs".to_string(),
            Box::new(|_args: &[String]| {
                r#"
(function() {
    // No-operation scriptlet
})();
"#
                .to_string()
            }),
        );

        Self { scriptlets }
    }

    fn get_scriptlet(&self, name: &str, args: &[String]) -> Option<String> {
        // Support common aliases
        let canonical_name = match name {
            "ubo-abort-on-property-read.js" | "abp-abort-on-property-read" => {
                "abort-on-property-read"
            }
            "ubo-abort-on-property-write.js" | "abp-abort-on-property-write" => {
                "abort-on-property-write"
            }
            "ubo-set-constant.js" | "abp-override-property-read" => "set-constant",
            _ => name,
        };

        self.scriptlets.get(canonical_name).map(|f| f(args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scriptlet_basic() {
        let rule = ScriptletRule::parse("##%#//scriptlet('abort-on-property-read', 'alert')").unwrap();
        assert_eq!(rule.scriptlet_name, "abort-on-property-read");
        assert_eq!(rule.arguments, vec!["alert"]);
        assert!(!rule.is_exception);
    }

    #[test]
    fn test_parse_scriptlet_domain_specific() {
        let rule =
            ScriptletRule::parse("example.com#%#//scriptlet('set-constant', 'ads', 'false')")
                .unwrap();
        assert_eq!(rule.domains, Some(vec!["example.com".to_string()]));
        assert_eq!(rule.scriptlet_name, "set-constant");
        assert_eq!(rule.arguments, vec!["ads", "false"]);
    }

    #[test]
    fn test_parse_scriptlet_exception() {
        let rule = ScriptletRule::parse("example.com#@%#//scriptlet('noopjs')").unwrap();
        assert!(rule.is_exception);
    }

    #[test]
    fn test_parse_scriptlet_double_quotes() {
        let rule =
            ScriptletRule::parse(r#"##%#//scriptlet("remove-class", "ad-class", "div.ads")"#)
                .unwrap();
        assert_eq!(rule.scriptlet_name, "remove-class");
        assert_eq!(rule.arguments, vec!["ad-class", "div.ads"]);
    }

    #[test]
    fn test_domain_matching() {
        let rule = ScriptletRule::parse("example.com#%#//scriptlet('noopjs')").unwrap();
        assert!(rule.matches_domain("example.com"));
        assert!(rule.matches_domain("www.example.com"));
        assert!(!rule.matches_domain("test.com"));
    }

    #[test]
    fn test_scriptlet_manager() {
        let mut manager = ScriptletManager::new();
        manager
            .add_rule_from_string("example.com#%#//scriptlet('noopjs')")
            .unwrap();

        let code = manager.get_scriptlet_code("example.com");
        assert!(!code.is_empty());
        assert!(code.contains("use strict"));
    }

    #[test]
    fn test_scriptlet_library_abort_on_property_read() {
        let library = ScriptletLibrary::new();
        let code = library
            .get_scriptlet("abort-on-property-read", &["alert".to_string()])
            .unwrap();
        assert!(code.contains("alert"));
        assert!(code.contains("ReferenceError"));
    }
}

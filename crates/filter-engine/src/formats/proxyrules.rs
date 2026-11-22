//! Proxy-client rule lists: Surge, Quantumult X, Shadowrocket, Loon (`.list` / `[Rule]`) and
//! Clash / Mihomo rule providers.

use super::hostlike::{add_domain, host_regex_rule, no_dollar};
use super::iplist::IpRange;
use super::{norm_host, ConvertOptions, Converted, ListMeta, Out};

const TYPES: &[&str] = &[
    "domain",
    "domain-suffix",
    "domain-keyword",
    "domain-regex",
    "url-regex",
    "ip-cidr",
    "ip-cidr6",
    "ip6-cidr",
    "host",
    "host-suffix",
    "host-keyword",
];

/// Does a (lowercased) line look like `TYPE,value[,policy]`?
pub(crate) fn is_rule_line(low: &str) -> bool {
    low.split_once(',')
        .is_some_and(|(t, _)| TYPES.contains(&t.trim()))
}

fn unquote(s: &str) -> &str {
    s.trim().trim_matches(|c| c == '"' || c == '\'')
}

/// Apply one `TYPE,value[,policy[,options]]` rule. Returns false if it was not a rule.
fn apply_rule(out: &mut Out, line_no: usize, rule: &str) {
    let parts: Vec<&str> = rule.split(',').map(str::trim).collect();
    if parts.len() < 2 {
        out.stats.error(line_no, "malformed rule");
        return;
    }
    let ty = parts[0].to_ascii_lowercase();
    let value = unquote(parts[1]);
    // A policy column, if any, decides whether this is a block rule.
    let policy = parts[2..].iter().find(|p| {
        let p = p.to_ascii_lowercase();
        !p.is_empty()
            && !matches!(
                p.as_str(),
                "no-resolve" | "extended-matching" | "force-remote-dns" | "pre-matching"
            )
    });
    if let Some(p) = policy {
        let p = p.to_ascii_lowercase();
        if !(p.starts_with("reject") || p == "block" || p == "blackhole") {
            out.stats.skip("non-reject-policy");
            return;
        }
    }
    match ty.as_str() {
        "domain" | "host" => match norm_host(value) {
            Ok(h) => out.exact_host(&h, false),
            Err(e) => out.stats.error(line_no, format!("{e}: `{value}`")),
        },
        "domain-suffix" | "host-suffix" => add_domain(out, line_no, value, false),
        "domain-keyword" | "host-keyword" => {
            if value.is_empty() || value.contains(['/', ' ']) {
                out.stats.error(line_no, "invalid keyword");
            } else {
                out.keyword(&value.to_ascii_lowercase(), false);
            }
        }
        "domain-regex" => match host_regex_rule(value) {
            Ok(r) => out.raw(&r, false),
            Err(e) => out.stats.error(line_no, e),
        },
        "url-regex" => match regex::RegexBuilder::new(value).size_limit(1 << 20).build() {
            Ok(_) if !value.is_empty() => out.raw(&format!("/{}/", no_dollar(value)), false),
            _ => out.stats.error(line_no, "invalid regex"),
        },
        "ip-cidr" | "ip-cidr6" | "ip6-cidr" => match IpRange::parse(value) {
            Some(r) => out.ip(r, false),
            None => out.stats.error(line_no, format!("invalid CIDR `{value}`")),
        },
        other => out.stats.skip(&format!("type-{other}")),
    }
}

pub(crate) fn convert_surge(content: &str, opts: &ConvertOptions) -> Converted {
    let mut out = Out::new(content, opts);
    let mut in_rules = true;
    for (i, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', ';']) || line.starts_with("//") {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_rules = line.eq_ignore_ascii_case("[rule]");
            continue;
        }
        if !in_rules {
            out.stats.skip("section");
            continue;
        }
        // Strip a trailing `// comment`.
        let line = line.split(" //").next().unwrap_or(line).trim();
        if is_rule_line(&line.to_ascii_lowercase()) {
            apply_rule(&mut out, i + 1, line);
        } else {
            let ty = line.split(',').next().unwrap_or("").to_ascii_lowercase();
            if ty.contains(char::is_whitespace) || line.contains(',') {
                out.stats.skip(&format!("type-{ty}")); // GEOIP, FINAL, PROCESS-NAME, AND, ...
            } else {
                out.stats.error(i + 1, "unrecognised line");
            }
        }
    }
    out.finish(ListMeta::default())
}

pub(crate) fn convert_clash(content: &str, opts: &ConvertOptions) -> Converted {
    let mut out = Out::new(content, opts);
    for (i, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(entry) = line.strip_prefix('-') else {
            continue; // `payload:`, `behavior: domain`, ... (structure)
        };
        let entry = entry.split(" #").next().unwrap_or(entry);
        let entry = unquote(entry);
        if entry.is_empty() {
            continue;
        }
        if entry.contains(',') {
            let low = entry.to_ascii_lowercase();
            if is_rule_line(&low) {
                apply_rule(&mut out, i + 1, entry);
            } else {
                let ty = low.split(',').next().unwrap_or("").to_string();
                out.stats.skip(&format!("type-{ty}"));
            }
        } else if entry.contains('/') || entry.parse::<std::net::IpAddr>().is_ok() {
            match IpRange::parse(entry) {
                Some(r) => out.ip(r, false),
                None => out.stats.error(i + 1, format!("invalid CIDR `{entry}`")),
            }
        } else if entry.starts_with("+.") || entry.starts_with('.') || entry.starts_with("*.") {
            add_domain(&mut out, i + 1, entry, false);
        } else {
            match norm_host(entry) {
                Ok(h) => out.exact_host(&h, false),
                Err(e) => out.stats.error(i + 1, format!("{e}: `{entry}`")),
            }
        }
    }
    out.finish(ListMeta::default())
}

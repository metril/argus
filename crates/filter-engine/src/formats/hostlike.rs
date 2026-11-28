//! Domain-oriented formats: hosts, domain lists, dnsmasq, unbound, RPZ, Pi-hole, AdGuard Home and
//! Little Snitch.

use std::net::IpAddr;
use std::str::FromStr;

use super::{is_local_name, norm_host, ConvertOptions, Converted, ListMeta, Out};

/// Strip a `#` comment (at line start or preceded by whitespace).
fn strip_hash_comment(line: &str) -> &str {
    if line.starts_with('#') {
        return "";
    }
    let b = line.as_bytes();
    for i in 1..b.len() {
        if b[i] == b'#' && b[i - 1].is_ascii_whitespace() {
            return line[..i].trim_end();
        }
    }
    line
}

/// Normalise a domain entry (accepting `*.d`, `.d`, `+.d` forms) and emit it.
pub(crate) fn add_domain(out: &mut Out, line_no: usize, raw: &str, exception: bool) {
    let d = raw
        .trim()
        .trim_start_matches("*.")
        .trim_start_matches("+.")
        .trim_start_matches('.');
    if is_local_name(&d.to_ascii_lowercase()) {
        out.stats.skip("localhost");
        return;
    }
    match norm_host(d) {
        Ok(h) => out.domain(&h, exception),
        Err(e) => out.stats.error(line_no, format!("{e}: `{raw}`")),
    }
}

pub(crate) fn is_plain_domain(line: &str) -> bool {
    let l = line.trim();
    let l = l
        .strip_prefix("*.")
        .or_else(|| l.strip_prefix('.'))
        .unwrap_or(l);
    !l.contains(char::is_whitespace) && norm_host(l).is_ok()
}

/// A non-domain line that could be a Pi-hole style regex.
pub(crate) fn is_regex_like(line: &str) -> bool {
    !line.contains(char::is_whitespace)
        && line.contains(['\\', '^', '$', '(', '[', '|', '+', '?', '*'])
        && !line.starts_with(['|', '@', '!'])
}

fn is_sinkhole(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_unspecified() || a.octets()[0] == 127,
        IpAddr::V6(a) => a.is_unspecified() || a.is_loopback(),
    }
}

fn is_sinkhole_str(s: &str) -> bool {
    IpAddr::from_str(s).is_ok_and(is_sinkhole)
}

pub(crate) fn is_hosts_line(line: &str) -> bool {
    let line = strip_hash_comment(line.trim());
    let mut t = line.split_whitespace();
    let (Some(ip), Some(host)) = (t.next(), t.next()) else {
        return false;
    };
    IpAddr::from_str(ip).is_ok() && (is_local_name(host) || norm_host(host).is_ok())
}

// ---- hosts ------------------------------------------------------------------------------------

pub(crate) fn convert_hosts(content: &str, opts: &ConvertOptions) -> Converted {
    let mut out = Out::new(content, opts);
    for (i, raw) in content.lines().enumerate() {
        out.stats.cur = i + 1;
        let line = strip_hash_comment(raw.trim());
        if line.is_empty() {
            continue;
        }
        let mut t = line.split_whitespace();
        let first = t.next().unwrap_or("");
        match IpAddr::from_str(first.split('%').next().unwrap_or(first)) {
            Ok(ip) => {
                if !is_sinkhole(ip) {
                    // `192.168.1.5 nas`: a real address mapping, not a block entry.
                    out.stats.skip("non-sinkhole-ip");
                    continue;
                }
                let mut any = false;
                for h in t {
                    any = true;
                    add_domain(&mut out, i + 1, h, false);
                }
                if !any {
                    out.stats.error(i + 1, "address without hostname");
                }
            }
            Err(_) => {
                // Some "hosts" lists mix in bare domains.
                if t.next().is_none() {
                    add_domain(&mut out, i + 1, first, false);
                } else {
                    out.stats.error(i + 1, "not a hosts entry");
                }
            }
        }
    }
    out.finish(ListMeta::default())
}

// ---- domain lists -----------------------------------------------------------------------------

pub(crate) fn convert_domains(content: &str, opts: &ConvertOptions) -> Converted {
    let mut out = Out::new(content, opts);
    for (i, raw) in content.lines().enumerate() {
        out.stats.cur = i + 1;
        let mut line = raw.trim();
        if line.is_empty() || line.starts_with(['#', '!', ';']) || line.starts_with("//") {
            continue;
        }
        line = strip_hash_comment(line);
        let mut toks = line.split_whitespace();
        let Some(tok) = toks.next() else { continue };
        if toks.next().is_some() {
            out.stats.error(i + 1, "unrecognised line");
            continue;
        }
        add_domain(&mut out, i + 1, tok, false);
    }
    out.finish(ListMeta::default())
}

// ---- dnsmasq ----------------------------------------------------------------------------------

pub(crate) fn convert_dnsmasq(content: &str, opts: &ConvertOptions) -> Converted {
    let mut out = Out::new(content, opts);
    for (i, raw) in content.lines().enumerate() {
        out.stats.cur = i + 1;
        let line = strip_hash_comment(raw.trim());
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            out.stats.skip("directive");
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if !matches!(key.as_str(), "address" | "server" | "local") {
            out.stats.skip("directive");
            continue;
        }
        let Some(rest) = value.strip_prefix('/') else {
            out.stats.error(i + 1, "expected `/domain/` form");
            continue;
        };
        let mut parts: Vec<&str> = rest.split('/').collect();
        // Trailing target: empty when the directive ends with `/`.
        let target = if rest.ends_with('/') {
            ""
        } else {
            parts.pop().unwrap_or("")
        };
        parts.retain(|p| !p.is_empty());
        let blocks = match key.as_str() {
            "local" => target.is_empty(),
            "server" => target.is_empty(),
            _ => target.is_empty() || target == "#" || is_sinkhole_str(target),
        };
        if !blocks {
            out.stats.skip("custom-answer");
            continue;
        }
        if parts.is_empty() {
            out.stats.error(i + 1, "no domain in directive");
        }
        for d in parts {
            add_domain(&mut out, i + 1, d, false);
        }
    }
    out.finish(ListMeta::default())
}

// ---- unbound ----------------------------------------------------------------------------------

fn unquote(s: &str) -> &str {
    s.trim().trim_matches(|c| c == '"' || c == '\'')
}

pub(crate) fn convert_unbound(content: &str, opts: &ConvertOptions) -> Converted {
    let mut out = Out::new(content, opts);
    for (i, raw) in content.lines().enumerate() {
        out.stats.cur = i + 1;
        let line = raw.trim();
        let line = line.split(" #").next().unwrap_or(line).trim();
        if line.is_empty() || line.starts_with('#') || line.eq_ignore_ascii_case("server:") {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            out.stats.error(i + 1, "unrecognised line");
            continue;
        };
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            "local-zone" => {
                // `"d." always_nxdomain` — the name may be quoted and contain no spaces.
                let (name, ty) = if let Some(rest) = value.strip_prefix('"') {
                    match rest.split_once('"') {
                        Some((n, t)) => (n, t.trim()),
                        None => {
                            out.stats.error(i + 1, "unterminated quote");
                            continue;
                        }
                    }
                } else {
                    value.split_once(char::is_whitespace).unwrap_or((value, ""))
                };
                match ty.split_whitespace().next().unwrap_or("") {
                    "always_nxdomain" | "always_null" | "always_refuse" | "refuse" | "deny"
                    | "static" | "redirect" | "inform_deny" => {
                        add_domain(&mut out, i + 1, name, false)
                    }
                    _ => out.stats.skip("zone-type"),
                }
            }
            "local-data" => {
                let rec: Vec<&str> = unquote(value).split_whitespace().collect();
                let ty_pos = rec
                    .iter()
                    .position(|t| matches!(*t, "A" | "AAAA" | "a" | "aaaa"));
                match (rec.first(), ty_pos.and_then(|p| rec.get(p + 1))) {
                    (Some(name), Some(ip)) if is_sinkhole_str(ip) => {
                        add_domain(&mut out, i + 1, name, false)
                    }
                    _ => out.stats.skip("custom-answer"),
                }
            }
            _ => out.stats.skip("directive"),
        }
    }
    out.finish(ListMeta::default())
}

// ---- RPZ --------------------------------------------------------------------------------------

pub(crate) fn convert_rpz(content: &str, opts: &ConvertOptions) -> Converted {
    let mut out = Out::new(content, opts);
    let mut origin: Option<String> = None;
    let mut depth = 0i32;
    for (i, raw) in content.lines().enumerate() {
        out.stats.cur = i + 1;
        let line = raw.split(';').next().unwrap_or("");
        let in_paren = depth > 0;
        depth += line.matches('(').count() as i32 - line.matches(')').count() as i32;
        depth = depth.max(0);
        if in_paren || line.trim().is_empty() {
            continue; // continuation of a multi-line SOA
        }
        if let Some(d) = line.trim().strip_prefix('$') {
            let mut t = d.split_whitespace();
            if t.next().is_some_and(|k| k.eq_ignore_ascii_case("ORIGIN")) {
                origin = t
                    .next()
                    .map(|o| o.trim_end_matches('.').to_ascii_lowercase());
            }
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            out.stats.skip("no-owner");
            continue;
        }
        let tok: Vec<&str> = line.split_whitespace().collect();
        let Some(ty_idx) = tok.iter().skip(1).position(|t| {
            matches!(
                t.to_ascii_uppercase().as_str(),
                "CNAME" | "A" | "AAAA" | "SOA" | "NS" | "TXT" | "MX" | "PTR"
            )
        }) else {
            out.stats.error(i + 1, "no record type");
            continue;
        };
        let ty = tok[ty_idx + 1].to_ascii_uppercase();
        if matches!(ty.as_str(), "SOA" | "NS" | "TXT" | "MX" | "PTR") {
            continue;
        }
        let Some(rdata) = tok.get(ty_idx + 2) else {
            out.stats.error(i + 1, "record without data");
            continue;
        };
        let owner = tok[0].to_ascii_lowercase();
        if owner == "@" {
            continue;
        }
        if ["rpz-nsdname", "rpz-nsip", "rpz-ip", "rpz-client-ip"]
            .iter()
            .any(|k| owner.contains(k))
        {
            out.stats.skip(if owner.contains("rpz-nsdname") {
                "rpz-nsdname"
            } else {
                "rpz-ip"
            });
            continue;
        }
        let mut name = owner.as_str();
        if name.ends_with('.') {
            name = name.trim_end_matches('.');
            if let Some(o) = &origin {
                if let Some(stripped) = name.strip_suffix(o.as_str()) {
                    name = stripped.trim_end_matches('.');
                }
            }
        }
        let target = rdata.trim_end_matches('.').to_ascii_lowercase();
        let (block, exception) = if ty == "CNAME" {
            match target.as_str() {
                "rpz-passthru" => (true, true),
                _ => (true, false), // `.` NXDOMAIN, `*.` NODATA, rpz-drop, walled-garden redirect
            }
        } else if IpAddr::from_str(rdata).is_ok_and(is_sinkhole) {
            (true, false)
        } else {
            (false, false)
        };
        if !block {
            out.stats.skip("custom-answer");
            continue;
        }
        add_domain(&mut out, i + 1, name, exception);
    }
    out.finish(ListMeta::default())
}

// ---- Pi-hole and AdGuard Home ------------------------------------------------------------------

/// Index of the first unescaped, out-of-class occurrence of `ch` in `re`.
fn find_unescaped(re: &str, ch: u8, from: usize) -> Option<usize> {
    let b = re.as_bytes();
    let (mut i, mut in_class) = (0, false);
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b'[' => in_class = true,
            b']' => in_class = false,
            c if c == ch && !in_class && i >= from => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Rewrite `$` in a regex so adblock-rust does not read it as the option separator: an
/// unescaped end anchor becomes `\z` and a literal dollar becomes `\x24`.
pub(crate) fn no_dollar(re: &str) -> String {
    let (mut out, mut in_class) = (String::with_capacity(re.len()), false);
    let mut chars = re.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('$') => out.push_str("\\x24"),
                Some(n) => {
                    out.push('\\');
                    out.push(n);
                }
                None => out.push('\\'),
            },
            '[' => {
                in_class = true;
                out.push(c);
            }
            ']' => {
                in_class = false;
                out.push(c);
            }
            '/' => out.push_str("\\/"),
            '$' if in_class => out.push_str("\\x24"),
            '$' => out.push_str("\\z"),
            _ => out.push(c),
        }
    }
    out
}

/// Turn a DNS-name regex (Pi-hole / AdGuard Home semantics: matched against the domain) into an
/// adblock regex rule matched against the URL's host.
///
/// Supported anchors: a leading `^` or the `(\.|^)` / `(^|\.)` idiom, and a trailing `$`.
pub(crate) fn host_regex_rule(re: &str) -> Result<String, String> {
    let re = re.trim();
    if re.is_empty() {
        return Err("empty regex".into());
    }
    let mut body = re;
    let mut start = "[^\\/?#]*"; // unanchored: anywhere in the host
    if let Some(r) = body.strip_prefix('^') {
        body = r;
        start = "";
    } else if let Some(r) = body
        .strip_prefix("(\\.|^)")
        .or_else(|| body.strip_prefix("(^|\\.)"))
    {
        body = r;
        start = "(?:[^\\/?#@]*\\.)?";
    }
    let end = if let Some(r) = body.strip_suffix('$') {
        if !r.ends_with('\\') {
            body = r;
            "(?::\\d+)?(?:[\\/?#]|$)"
        } else {
            ""
        }
    } else {
        ""
    };
    if find_unescaped(body, b'^', 0).is_some() || find_unescaped(body, b'$', 0).is_some() {
        return Err("unsupported anchor inside regex".into());
    }
    if body.contains('/') {
        return Err("regex contains `/`".into());
    }
    let userinfo = if start.is_empty() {
        "(?:[^\\/?#@]*@)?"
    } else {
        ""
    };
    let full = format!("^[a-z][a-z0-9+.-]*:\\/\\/{userinfo}{start}(?:{body}){end}");
    regex::RegexBuilder::new(&full)
        .size_limit(1 << 20)
        .build()
        .map_err(|e| {
            format!(
                "invalid regex: {}",
                e.to_string().lines().last().unwrap_or("")
            )
        })?;
    Ok(format!("/{}/", no_dollar(&full)))
}

pub(crate) fn convert_pihole(content: &str, opts: &ConvertOptions) -> Converted {
    let mut out = Out::new(content, opts);
    for (i, raw) in content.lines().enumerate() {
        out.stats.cur = i + 1;
        let line = strip_hash_comment(raw.trim());
        if line.is_empty() || line.starts_with(['!', ';']) {
            continue;
        }
        if line.starts_with("||") || line.starts_with("@@") {
            let (exc, body) = match line.strip_prefix("@@") {
                Some(b) => (true, b),
                None => (false, line),
            };
            out.raw(body, exc);
        } else if is_plain_domain(line) {
            add_domain(&mut out, i + 1, line, false);
        } else if line.contains(char::is_whitespace) {
            // A hosts line in a Pi-hole list.
            if is_hosts_line(line) {
                let mut t = line.split_whitespace();
                t.next();
                for h in t {
                    add_domain(&mut out, i + 1, h, false);
                }
            } else {
                out.stats.error(i + 1, "unrecognised line");
            }
        } else {
            match host_regex_rule(line) {
                Ok(rule) => out.raw(&rule, false),
                Err(e) => out.stats.error(i + 1, e),
            }
        }
    }
    out.finish(ListMeta::default())
}

pub(crate) fn convert_agh(content: &str, opts: &ConvertOptions) -> Converted {
    let mut out = Out::new(content, opts);
    for (i, raw) in content.lines().enumerate() {
        out.stats.cur = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['!', '#']) {
            continue;
        }
        let (exc, rule) = match line.strip_prefix("@@") {
            Some(r) => (true, r),
            None => (false, line),
        };
        // Split modifiers (not for `/regex/` bodies, whose `$` is an anchor unless followed by
        // a modifier list after the closing slash).
        let (pattern, mods) = match rule.rfind('$') {
            Some(p)
                if !rule[p + 1..].is_empty()
                    && rule[p + 1..]
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_-=,|~.:".contains(c))
                    && (!rule.starts_with('/') || rule[..p].ends_with('/')) =>
            {
                (&rule[..p], &rule[p + 1..])
            }
            _ => (rule, ""),
        };
        let mut important = false;
        let mut skip_reason = None;
        for m in mods.split(',').filter(|m| !m.is_empty()) {
            let name = m.split('=').next().unwrap_or(m);
            match name {
                "important" => important = true,
                "badfilter" => {}
                "dnstype" | "client" | "dnsrewrite" | "ctag" | "denyallow" => {
                    skip_reason = Some(name.to_string())
                }
                other => skip_reason = Some(format!("modifier-{other}")),
            }
        }
        if let Some(r) = skip_reason {
            out.stats.skip(&r);
            continue;
        }
        let suffix = if important { "$important" } else { "" };
        if pattern.starts_with('/') && pattern.ends_with('/') && pattern.len() > 2 {
            match host_regex_rule(&pattern[1..pattern.len() - 1]) {
                Ok(r) => out.raw(&format!("{r}{suffix}"), exc),
                Err(e) => out.stats.error(i + 1, e),
            }
        } else if let Some(h) = pattern.strip_prefix("||") {
            let host = h.trim_end_matches('^');
            match norm_host(host) {
                Ok(d) => out.raw(&format!("||{d}^{suffix}"), exc),
                // Wildcards etc.: ABP handles them natively.
                Err(_) if host.contains('*') => out.raw(&format!("{pattern}{suffix}"), exc),
                Err(e) => out.stats.error(i + 1, format!("{e}: `{host}`")),
            }
        } else if pattern.starts_with('|') {
            out.raw(&format!("{pattern}{suffix}"), exc);
        } else if is_hosts_line(pattern) {
            let mut t = pattern.split_whitespace();
            t.next();
            for h in t {
                add_domain(&mut out, i + 1, h, exc);
            }
        } else if is_plain_domain(pattern) {
            let bare = pattern.trim_start_matches("*.").trim_start_matches('.');
            match norm_host(bare) {
                Ok(d) => out.raw(&format!("||{d}^{suffix}"), exc),
                Err(e) => out.stats.error(i + 1, e),
            }
        } else {
            out.stats.error(i + 1, "unrecognised rule");
        }
    }
    out.finish(ListMeta::default())
}

// ---- Little Snitch ----------------------------------------------------------------------------

fn as_list(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::String(s) => s
            .split([',', ' ', '\n'])
            .filter(|p| !p.is_empty())
            .map(String::from)
            .collect(),
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn convert_snitch(content: &str, opts: &ConvertOptions) -> Converted {
    let mut out = Out::new(content, opts);
    let v: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(e) => {
            out.stats.error(e.line(), format!("invalid JSON: {e}"));
            return out.finish(ListMeta::default());
        }
    };
    let meta = ListMeta {
        title: v["name"].as_str().map(String::from),
        homepage: v["website"].as_str().map(String::from),
        ..Default::default()
    };
    let domains = |out: &mut Out, names: Vec<String>, exact: bool, exception: bool| {
        for n in names {
            let n = n.trim_start_matches("*.").to_string();
            if is_local_name(&n.to_ascii_lowercase()) {
                out.stats.skip("localhost");
                continue;
            }
            match norm_host(&n) {
                Ok(h) if exact => out.exact_host(&h, exception),
                Ok(h) => out.domain(&h, exception),
                Err(e) => out.stats.error(0, format!("{e}: `{n}`")),
            }
        }
    };
    domains(&mut out, as_list(&v["denied-remote-domains"]), false, false);
    domains(&mut out, as_list(&v["denied-remote-hosts"]), true, false);
    for rule in v["rules"].as_array().into_iter().flatten() {
        if rule["disabled"].as_bool() == Some(true) {
            out.stats.skip("disabled");
            continue;
        }
        let action = rule["action"].as_str().unwrap_or("");
        let exception = match action {
            "deny" => false,
            "allow" => true,
            _ => {
                out.stats.skip("action");
                continue;
            }
        };
        let (d, h) = (
            as_list(&rule["remote-domains"]),
            as_list(&rule["remote-hosts"]),
        );
        if d.is_empty() && h.is_empty() {
            out.stats.skip("no-domain-target");
            continue;
        }
        domains(&mut out, d, false, exception);
        domains(&mut out, h, true, exception);
    }
    out.finish(meta)
}

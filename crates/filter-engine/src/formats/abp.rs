//! ABP / uBlock Origin / AdGuard filter syntax: preprocessor directives, header metadata,
//! translation of AdGuard-only constructs, and classification of rules the engine cannot run.
//!
//! Preprocessor environment (this is a proxy, not a browser extension): `ext_ublock` is true;
//! `adguard`, `ext_abp`, `ext_ubol`, `env_chromium`, `env_firefox`, `env_edge`, `env_safari`,
//! `env_mobile`, `cap_html_filtering` and every unknown token are false.

use std::collections::HashMap;

use super::ext::{ubo_scriptlet_name, ExtKind, ExtRule};
use super::{ConvertOptions, Converted, ListMeta, Out};

const MAX_INCLUDE_DEPTH: usize = 3;
const MAX_INCLUDES: usize = 64;

// ---- lexical helpers ---------------------------------------------------------------------------

pub(crate) struct Cosmetic<'a> {
    pub domains: &'a str,
    pub sep: &'a str,
    pub body: &'a str,
}

const COSMETIC_SEPS: &[&str] = &[
    "#@$?#", "#@?#", "#@$#", "#@%#", "#$?#", "#?#", "#$#", "#%#", "#@#", "##",
];

fn valid_domain_part(s: &str) -> bool {
    s.bytes()
        .all(|c| c.is_ascii_alphanumeric() || b".,~*_-".contains(&c))
}

/// Split a cosmetic / HTML-filter rule into `(domains, separator, body)`.
pub(crate) fn split_cosmetic(line: &str) -> Option<Cosmetic<'_>> {
    if let Some(p) = line.find("$@$").or_else(|| line.find("$$")) {
        if valid_domain_part(&line[..p]) && !line.starts_with("||") && !line.starts_with("@@") {
            let sep_len = if line[p..].starts_with("$@$") { 3 } else { 2 };
            return Some(Cosmetic {
                domains: &line[..p],
                sep: "$$",
                body: &line[p + sep_len..],
            });
        }
    }
    let mut from = 0;
    while let Some(rel) = line[from..].find('#') {
        let p = from + rel;
        if !valid_domain_part(&line[..p]) {
            return None;
        }
        for sep in COSMETIC_SEPS {
            if line[p..].starts_with(sep) {
                return Some(Cosmetic {
                    domains: &line[..p],
                    sep,
                    body: &line[p + sep.len()..],
                });
            }
        }
        from = p + 1;
    }
    None
}

/// Split `pattern$options`. Regex rules (`/.../`) without options return no options.
pub(crate) fn split_options(line: &str) -> (&str, Option<&str>) {
    if line.len() > 1 && line.starts_with('/') && line.ends_with('/') {
        return (line, None);
    }
    // The option separator is the last `$` that is not escaped (`\$` appears in `$jsonprune`).
    let b = line.as_bytes();
    let Some(p) = (0..b.len())
        .rev()
        .find(|&i| b[i] == b'$' && (i == 0 || b[i - 1] != b'\\'))
    else {
        return (line, None);
    };
    let opts = &line[p + 1..];
    let first = opts.split(',').next().unwrap_or("");
    let name = first
        .split('=')
        .next()
        .unwrap_or("")
        .trim_start_matches('~');
    let ok = !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
    if ok {
        (&line[..p], Some(opts))
    } else {
        (line, None)
    }
}

/// Domains a rule is restricted to.
pub(crate) fn rule_domains(raw: &str) -> Vec<String> {
    let raw = raw.trim();
    if let Some(c) = split_cosmetic(raw) {
        return c
            .domains
            .split(',')
            .filter(|d| !d.is_empty())
            .map(String::from)
            .collect();
    }
    if let (_, Some(opts)) = split_options(raw) {
        for tok in opts.split(',') {
            if let Some(v) = tok
                .strip_prefix("domain=")
                .or_else(|| tok.strip_prefix("from="))
            {
                return v
                    .split('|')
                    .filter(|d| !d.is_empty())
                    .map(String::from)
                    .collect();
            }
        }
    }
    Vec::new()
}

fn opt_name(tok: &str) -> String {
    tok.trim_start_matches('~')
        .split('=')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

// ---- detection helpers -------------------------------------------------------------------------

pub(crate) fn looks_like_snitch(s: &str) -> bool {
    let head = &s[..s.len().min(8192)];
    head.contains("denied-remote-domains")
        || head.contains("denied-remote-hosts")
        || (head.contains("\"rules\"") && head.contains("\"action\""))
}

const KNOWN_OPTS: &[&str] = &[
    "third-party",
    "3p",
    "first-party",
    "1p",
    "script",
    "image",
    "stylesheet",
    "css",
    "xhr",
    "xmlhttprequest",
    "subdocument",
    "frame",
    "document",
    "doc",
    "all",
    "domain",
    "important",
    "popup",
    "media",
    "font",
    "object",
    "ping",
    "websocket",
    "other",
    "redirect",
    "redirect-rule",
    "removeparam",
    "csp",
    "badfilter",
    "match-case",
    "denyallow",
    "from",
    "to",
    "method",
    "replace",
    "cookie",
    "removeheader",
    "jsonprune",
    "inline-script",
    "inline-font",
];

pub(crate) fn is_abp_like(line: &str) -> bool {
    if line.starts_with("||")
        || line.starts_with("@@")
        || line.starts_with("##")
        || line.starts_with("#@#")
        || line.starts_with("#?#")
        || split_cosmetic(line).is_some()
        || (line.starts_with('/') && line.ends_with('/') && line.len() > 2)
    {
        return true;
    }
    if let (_, Some(opts)) = split_options(line) {
        return opts
            .split(',')
            .next()
            .is_some_and(|t| KNOWN_OPTS.contains(&opt_name(t).as_str()));
    }
    line.starts_with('|') || line.ends_with('^') || line.starts_with("/")
}

pub(crate) fn is_adguard_only(line: &str) -> bool {
    ["#%#", "#@%#", "#$#", "#@$#", "#$?#", "#?#", "$$", "$@$"]
        .iter()
        .any(|m| line.contains(m))
        || [
            "denyallow=",
            "$app=",
            "$stealth",
            "$network",
            "$urlblock",
            ",to=",
        ]
        .iter()
        .any(|m| line.contains(m))
}

pub(crate) fn is_agh_dns_only(line: &str) -> bool {
    split_options(line).1.is_some_and(|o| {
        o.split(',').any(|t| {
            matches!(
                opt_name(t).as_str(),
                "dnstype" | "dnsrewrite" | "client" | "ctag"
            )
        })
    })
}

// ---- metadata ----------------------------------------------------------------------------------

fn parse_expires(v: &str) -> Option<u64> {
    let v = v.trim();
    let digits: String = v.chars().take_while(char::is_ascii_digit).collect();
    let n: u64 = digits.parse().ok()?;
    let unit = v[digits.len()..].trim_start().to_ascii_lowercase();
    let secs = if unit.starts_with('h') {
        n * 3600
    } else if unit.starts_with('d') || unit.is_empty() {
        n * 86_400
    } else {
        return None;
    };
    Some(secs.clamp(3600, 14 * 86_400))
}

/// Parse `! Title:`-style header comments (also `# Title:` as used by hosts files).
pub(crate) fn scan_meta(content: &str) -> ListMeta {
    let mut m = ListMeta::default();
    for line in content.lines().take(200) {
        let l = line.trim();
        let Some(rest) = l.strip_prefix('!').or_else(|| l.strip_prefix('#')) else {
            continue;
        };
        let Some((k, v)) = rest.split_once(':') else {
            continue;
        };
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        match k.trim().to_ascii_lowercase().as_str() {
            "title" if m.title.is_none() => m.title = Some(v.to_string()),
            "homepage" if m.homepage.is_none() => m.homepage = Some(v.to_string()),
            "version" if m.version.is_none() => m.version = Some(v.to_string()),
            "expires" if m.expires_secs.is_none() => m.expires_secs = parse_expires(v),
            "redirect" if m.redirect.is_none() => m.redirect = Some(v.to_string()),
            _ => {}
        }
    }
    m
}

// ---- preprocessor ------------------------------------------------------------------------------

struct Cond<'a> {
    s: &'a [u8],
    i: usize,
}

impl Cond<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }
    fn or(&mut self) -> bool {
        let mut v = self.and();
        loop {
            self.ws();
            if self.s[self.i..].starts_with(b"||") {
                self.i += 2;
                let r = self.and();
                v = v || r;
            } else {
                return v;
            }
        }
    }
    fn and(&mut self) -> bool {
        let mut v = self.not();
        loop {
            self.ws();
            if self.s[self.i..].starts_with(b"&&") {
                self.i += 2;
                let r = self.not();
                v = v && r;
            } else {
                return v;
            }
        }
    }
    fn not(&mut self) -> bool {
        self.ws();
        if self.s.get(self.i) == Some(&b'!') {
            self.i += 1;
            return !self.not();
        }
        if self.s.get(self.i) == Some(&b'(') {
            self.i += 1;
            let v = self.or();
            self.ws();
            if self.s.get(self.i) == Some(&b')') {
                self.i += 1;
            }
            return v;
        }
        let st = self.i;
        while self.i < self.s.len()
            && (self.s[self.i].is_ascii_alphanumeric() || self.s[self.i] == b'_')
        {
            self.i += 1;
        }
        if st == self.i {
            self.i = (self.i + 1).min(self.s.len()); // garbage: consume to guarantee progress
            return false;
        }
        &self.s[st..self.i] == b"ext_ublock"
    }
}

fn eval_cond(expr: &str) -> bool {
    Cond {
        s: expr.as_bytes(),
        i: 0,
    }
    .or()
}

/// Names of `!#include` targets in `content`.
pub fn find_includes(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|l| l.trim().strip_prefix("!#include"))
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

fn preprocess_into<'a>(
    content: &'a str,
    includes: &'a HashMap<String, String>,
    depth: usize,
    budget: &mut usize,
    base_line: Option<usize>,
    out: &mut Vec<(usize, &'a str)>,
) {
    // Stack of (this branch active, any branch taken, parent active).
    let mut stack: Vec<(bool, bool, bool)> = Vec::new();
    let active = |s: &Vec<(bool, bool, bool)>| s.last().is_none_or(|t| t.0);
    for (n, line) in content.lines().enumerate() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("!#if") {
            let parent = active(&stack);
            let v = parent && eval_cond(rest);
            stack.push((v, v, parent));
        } else if t.starts_with("!#else") {
            if let Some(top) = stack.last_mut() {
                let v = top.2 && !top.1;
                *top = (v, top.1 || v, top.2);
            }
        } else if t.starts_with("!#endif") {
            stack.pop();
        } else if let Some(path) = t.strip_prefix("!#include") {
            if active(&stack) && depth < MAX_INCLUDE_DEPTH && *budget > 0 {
                if let Some(inc) = includes.get(path.trim()) {
                    *budget -= 1;
                    preprocess_into(
                        inc,
                        includes,
                        depth + 1,
                        budget,
                        Some(base_line.unwrap_or(n + 1)),
                        out,
                    );
                }
            }
        } else if active(&stack) {
            out.push((base_line.unwrap_or(n + 1), line));
        }
    }
}

/// Evaluate `!#if` / `!#else` / `!#endif`, splice `!#include`s from `includes`, and parse header
/// metadata. Returns the resulting text.
pub fn preprocess_and_meta(
    content: &str,
    includes: &HashMap<String, String>,
) -> (String, ListMeta) {
    let mut lines = Vec::new();
    preprocess_into(
        content,
        includes,
        0,
        &mut { MAX_INCLUDES },
        None,
        &mut lines,
    );
    let text: String = lines.iter().flat_map(|(_, l)| [*l, "\n"]).collect();
    (text, scan_meta(content))
}

// ---- rule processing ---------------------------------------------------------------------------

enum Rule {
    /// Rules to emit; `true` if rewritten from the input.
    Emit(Vec<String>, bool),
    Ext(ExtRule),
    Skip(&'static str),
    Error(&'static str),
}

/// Network option names kept on the exception rules generated for `$denyallow`.
const SCOPE_OPTS: &[&str] = &[
    "third-party",
    "3p",
    "first-party",
    "1p",
    "script",
    "image",
    "stylesheet",
    "css",
    "xhr",
    "xmlhttprequest",
    "subdocument",
    "frame",
    "document",
    "doc",
    "media",
    "font",
    "object",
    "ping",
    "websocket",
    "other",
    "domain",
    "from",
    "all",
];

fn network_rule(t: &str) -> Rule {
    let (pattern, Some(opts)) = split_options(t) else {
        // A rule with no pattern (`||`, `@@`) would match every request.
        if t.trim_matches(['|', '^', '*', '@']).is_empty() {
            return Rule::Error("empty pattern");
        }
        return Rule::Emit(vec![t.to_string()], false);
    };
    let (exception, bare) = match pattern.strip_prefix("@@") {
        Some(p) => (true, p),
        None => (false, pattern),
    };
    let mut toks: Vec<String> = opts.split(',').map(|s| s.trim().to_string()).collect();
    let has =
        |toks: &[String], n: &str| toks.iter().any(|t| opt_name(t) == n && !t.starts_with('~'));
    let ext = |k: ExtKind| Rule::Ext(ExtRule::new(k, t));
    for tok in &toks {
        let kind = match opt_name(tok).as_str() {
            "replace" => ExtKind::Replace,
            "jsonprune" => ExtKind::JsonPrune,
            "xmlprune" => ExtKind::XmlPrune,
            "cookie" => ExtKind::Cookie,
            "removeheader" => ExtKind::RemoveHeader,
            "hls" => ExtKind::Hls,
            "permissions" => ExtKind::Permissions,
            "urltransform" => ExtKind::UrlTransform,
            "method" => ExtKind::Method,
            "header" => return Rule::Skip("header"),
            _ => continue,
        };
        return ext(kind);
    }
    let mut changed = false;
    if has(&toks, "popup") {
        if has(&toks, "document") || has(&toks, "doc") || has(&toks, "all") {
            toks.retain(|t| opt_name(t) != "popup");
            changed = true;
        } else {
            return ext(ExtKind::Popup);
        }
    }
    for t in toks.iter_mut() {
        match t.as_str() {
            "empty" => {
                *t = "redirect=nooptext".into();
                changed = true;
            }
            _ => {}
        }
    }
    let join_opts = |toks: &[String]| {
        if toks.is_empty() {
            String::new()
        } else {
            format!("${}", toks.join(","))
        }
    };
    let neg_or_empty =
        |v: &str| v.is_empty() || v.split('|').any(|d| d.starts_with('~') || d.is_empty());

    // $denyallow=a|b: the rule applies except to requests for those domains.
    if let Some(i) = toks.iter().position(|t| opt_name(t) == "denyallow") {
        let val = toks[i]
            .split_once('=')
            .map(|x| x.1)
            .unwrap_or("")
            .to_string();
        if exception || neg_or_empty(&val) {
            return ext(ExtKind::DenyAllow);
        }
        toks.remove(i);
        let scope: Vec<String> = toks
            .iter()
            .filter(|t| SCOPE_OPTS.contains(&opt_name(t).as_str()))
            .cloned()
            .collect();
        let mut rules = vec![format!("{bare}{}", join_opts(&toks))];
        for d in val.split('|') {
            rules.push(format!("@@||{d}^{}", join_opts(&scope)));
        }
        return Rule::Emit(rules, true);
    }
    // $to=a|b with a match-all pattern: block those hosts under the remaining options.
    if let Some(i) = toks.iter().position(|t| opt_name(t) == "to") {
        let val = toks[i]
            .split_once('=')
            .map(|x| x.1)
            .unwrap_or("")
            .to_string();
        if !matches!(bare, "" | "*" | "|" | "||") || neg_or_empty(&val) {
            return ext(ExtKind::To);
        }
        toks.remove(i);
        let rules = val
            .split('|')
            .map(|d| {
                format!(
                    "{}||{d}^{}",
                    if exception { "@@" } else { "" },
                    join_opts(&toks)
                )
            })
            .collect();
        return Rule::Emit(rules, true);
    }
    if changed {
        let at = if exception { "@@" } else { "" };
        return Rule::Emit(vec![format!("{at}{bare}{}", join_opts(&toks))], true);
    }
    Rule::Emit(vec![t.to_string()], false)
}

/// Split quote-aware, comma-separated scriptlet arguments.
fn split_args(s: &str) -> Vec<String> {
    let (mut args, mut cur, mut quote) = (Vec::new(), String::new(), None::<char>);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quote) {
            ('\\', _) => {
                cur.push(c);
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            ('\'' | '"', None) => quote = Some(c),
            (q, Some(open)) if q == open => quote = None,
            (',', None) => args.push(std::mem::take(&mut cur).trim().to_string()),
            _ => cur.push(c),
        }
    }
    args.push(cur.trim().to_string());
    args.retain(|a| !a.is_empty());
    args
}

fn cosmetic_rule(t: &str, c: &Cosmetic<'_>) -> Rule {
    let exception = c.sep.starts_with("#@");
    let ext = |k: ExtKind| Rule::Ext(ExtRule::new(k, t));
    match c.sep {
        "$$" => ext(ExtKind::HtmlFilter),
        "##" | "#@#" if c.body.starts_with('^') => ext(ExtKind::HtmlFilter),
        "##" | "#@#" | "#?#" | "#@?#" => Rule::Emit(vec![t.to_string()], false),
        "#$#" | "#@$#" | "#$?#" | "#@$?#" => {
            let body = c.body.trim();
            match (body.find('{'), body.ends_with('}')) {
                (Some(open), true) => {
                    let sel = body[..open].trim();
                    let style = body[open + 1..body.len() - 1].trim().trim_end_matches(';');
                    let sep = if exception { "#@#" } else { "##" };
                    Rule::Emit(
                        vec![format!("{}{sep}{sel}:style({style})", c.domains)],
                        true,
                    )
                }
                _ => ext(ExtKind::Snippet),
            }
        }
        "#%#" | "#@%#" => {
            let Some(inner) = c
                .body
                .trim()
                .strip_prefix("//scriptlet(")
                .and_then(|b| b.strip_suffix(')'))
            else {
                return ext(ExtKind::JsInject);
            };
            let args = split_args(inner);
            let Some(ubo) = args.first().and_then(|n| ubo_scriptlet_name(n)) else {
                return ext(ExtKind::Scriptlet);
            };
            let mut call = ubo.to_string();
            for a in &args[1..] {
                call.push_str(", ");
                call.push_str(&a.replace(',', "\\,"));
            }
            let sep = if exception { "#@#" } else { "##" };
            Rule::Emit(vec![format!("{}{sep}+js({call})", c.domains)], true)
        }
        _ => Rule::Emit(vec![t.to_string()], false),
    }
}

/// `rule` as an exception (`@@...` / `#@#`).
fn to_exception(rule: &str) -> String {
    if rule.starts_with("@@") {
        return rule.to_string();
    }
    if let Some(c) = split_cosmetic(rule) {
        let sep = match c.sep {
            "##" => "#@#",
            "#?#" => "#@?#",
            "#$#" => "#@$#",
            "#%#" => "#@%#",
            other => other,
        };
        return format!("{}{sep}{}", c.domains, c.body);
    }
    format!("@@{rule}")
}

pub(crate) fn convert_abp(content: &str, opts: &ConvertOptions) -> Converted {
    let mut out = Out::new(content, opts);
    let mut lines = Vec::new();
    preprocess_into(
        content,
        &opts.includes,
        0,
        &mut { MAX_INCLUDES },
        None,
        &mut lines,
    );
    for (line_no, raw) in lines {
        let t = raw.trim();
        if t.is_empty() || t.starts_with('!') || (t.starts_with('[') && t.ends_with(']')) {
            continue;
        }
        if t.starts_with('#') && t[1..].chars().next().is_none_or(char::is_whitespace) {
            continue; // `# comment`
        }
        let rule = match split_cosmetic(t) {
            Some(c) => cosmetic_rule(t, &c),
            None => network_rule(t),
        };
        match rule {
            Rule::Emit(rules, translated) => {
                if translated {
                    out.stats.translated += 1;
                }
                for r in rules {
                    let r = if opts.allowlist { to_exception(&r) } else { r };
                    out.buf.push_str(&r);
                    out.buf.push('\n');
                    out.stats.converted += 1;
                }
            }
            Rule::Ext(mut e) => {
                out.stats.ext(e.kind);
                if opts.allowlist {
                    e.raw = to_exception(&e.raw);
                }
                out.ext.push(e);
            }
            Rule::Skip(reason) => out.stats.skip(reason),
            Rule::Error(reason) => out.stats.error(line_no, reason),
        }
    }
    out.finish(scan_meta(content))
}

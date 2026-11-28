//! ABP / uBlock Origin / AdGuard filter syntax: preprocessor directives, header metadata,
//! translation of AdGuard-only constructs, and classification of rules the engine cannot run.
//!
//! Preprocessor environment (this is a proxy, not a browser extension): `ext_ublock` is true;
//! `adguard`, `ext_abp`, `ext_ubol`, `env_chromium`, `env_firefox`, `env_edge`, `env_safari`,
//! `env_mobile` and every unknown token are false. `cap_html_filtering` is true for trusted lists
//! only (they run HTML filtering and `$replace`; an untrusted list keeps its `!#else` branch).

use std::collections::HashMap;

use super::ext::{ubo_scriptlet_name, ExtKind, ExtRule};
use super::{ConvertOptions, Converted, ListMeta, Out};

const MAX_INCLUDE_DEPTH: usize = 3;
const MAX_INCLUDES: usize = 64;

// ---- lexical helpers ---------------------------------------------------------------------------

pub struct Cosmetic<'a> {
    /// Domain list before the separator (may hold `/regex/` items).
    pub domains: &'a str,
    pub sep: &'a str,
    pub body: &'a str,
    /// Parsed AdGuard `[$…]` modifiers (`domain=a.com|b.com`, `path=/x`), without the brackets.
    pub modifiers: Vec<&'a str>,
    /// The raw `[$…]` prefix (empty when absent).
    pub prefix: &'a str,
}

impl Cosmetic<'_> {
    /// Hosts of a plain `[$domain=…]` modifier when it is the only modifier.
    fn plain_modifier_domains(&self) -> Option<String> {
        let [m] = self.modifiers.as_slice() else {
            return None;
        };
        if !self.domains.is_empty() {
            return None;
        }
        let v = m.strip_prefix("domain=")?;
        let hosts: Vec<&str> = Tokens::new(v, b'|').collect();
        (hosts
            .iter()
            .all(|h| !h.is_empty() && valid_domain_part(h) && !h.contains(',')))
        .then(|| hosts.join(","))
    }

    /// A `[$…]` prefix that is more than a plain host list.
    fn has_location_modifiers(&self) -> bool {
        !self.modifiers.is_empty() && self.plain_modifier_domains().is_none()
    }

    /// Rules that depend on the page location beyond a hostname list: `[$path]`, regex domains,
    /// regex hostnames, any other `[$…]` modifier.
    pub fn is_location(&self) -> bool {
        self.has_location_modifiers()
            || (self.domains.contains('/')
                && domain_items(self.domains)
                    .iter()
                    .any(|d| d.trim_start_matches('~').starts_with('/')))
    }
}

const COSMETIC_SEPS: &[&str] = &[
    "#@$?#", "#@?#", "#@$#", "#@%#", "#$?#", "#?#", "#$#", "#%#", "#@#", "##",
];

fn valid_domain_part(s: &str) -> bool {
    s.bytes()
        .all(|c| c.is_ascii_alphanumeric() || b".,~*_-".contains(&c))
}

/// Index of the unescaped `/` closing the regex that opens at `s[start]`, honouring `\` escapes
/// and `[...]` classes.
fn regex_end(s: &[u8], start: usize) -> Option<usize> {
    let (mut i, mut class) = (start + 1, false);
    while i < s.len() {
        match s[i] {
            b'\\' => i += 1,
            b'[' => class = true,
            b']' => class = false,
            b'/' if !class => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// End of a `/regex/` that opens at `s[i]` and is followed by one of `terms` (or the end);
/// with `flags`, regex flags (`i`, `gi`, ...) may sit between the closing `/` and the terminator.
fn regex_unit(s: &[u8], i: usize, terms: &[u8], flags: bool) -> Option<usize> {
    let e = regex_end(s, i)?;
    let mut j = e + 1;
    if flags {
        while s.get(j).is_some_and(u8::is_ascii_alphabetic) {
            j += 1;
        }
    }
    s.get(j).is_none_or(|c| terms.contains(c)).then_some(e)
}

/// Iterator over `s` split on `sep` (`,` or `|`), keeping `/regex/flags` values whole. A regex
/// value starts at the beginning of a token or after `=`, `:` or `|`.
struct Tokens<'a> {
    s: &'a str,
    sep: u8,
    pos: usize,
    done: bool,
}

impl<'a> Tokens<'a> {
    fn new(s: &'a str, sep: u8) -> Self {
        Self {
            s,
            sep,
            pos: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for Tokens<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<&'a str> {
        if self.done {
            return None;
        }
        let b = self.s.as_bytes();
        let start = self.pos;
        let mut i = start;
        while i < b.len() {
            match b[i] {
                b'\\' => i += 1,
                b'/' if i == start || matches!(b[i - 1], b'=' | b':' | b'|') => {
                    if let Some(e) = regex_unit(b, i, b",|", true) {
                        i = e;
                    }
                }
                c if c == self.sep => {
                    self.pos = i + 1;
                    return Some(&self.s[start..i]);
                }
                _ => {}
            }
            i += 1;
        }
        self.done = true;
        Some(&self.s[start..])
    }
}

/// Split a network rule's option string on `,`, keeping `/regex/flags` values (which may hold `,`)
/// whole.
pub fn split_option_tokens(opts: &str) -> Vec<&str> {
    Tokens::new(opts, b',').collect()
}

/// Split a `|`-separated value (`domain=`), keeping `/regex/flags` items (which may hold `|`) whole.
pub fn split_pipe_tokens(v: &str) -> Vec<&str> {
    Tokens::new(v, b'|').collect()
}

/// Domain-list items of a cosmetic rule (`a.com,/re/,~b.com`); regex items stay whole.
fn domain_items(list: &str) -> Vec<&str> {
    let b = list.as_bytes();
    let (mut out, mut start, mut i) = (Vec::new(), 0, 0);
    while i <= b.len() {
        if i == start {
            let s = if b.get(i) == Some(&b'~') { i + 1 } else { i };
            if b.get(s) == Some(&b'/') {
                if let Some(e) = regex_end(b, s) {
                    i = e + 1;
                }
            }
        }
        if i >= b.len() || b[i] == b',' {
            out.push(&list[start..i.min(b.len())]);
            start = i + 1;
        }
        i += 1;
    }
    out
}

/// Index of the `#` that ends the domain list at the start of `line`.
fn domain_list_end(line: &str) -> Option<usize> {
    let b = line.as_bytes();
    let mut i = 0;
    loop {
        let s = if b.get(i) == Some(&b'~') { i + 1 } else { i };
        if b.get(s) == Some(&b'/') {
            let e = regex_unit(b, s, b",#", false)?;
            i = e + 1;
        } else {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b".~*_-".contains(&b[i])) {
                i += 1;
            }
        }
        match b.get(i) {
            Some(b',') => i += 1,
            Some(b'#') => return Some(i),
            _ => return None,
        }
    }
}

/// Parse a leading AdGuard `[$…]` prefix: `(modifiers, end index after ']')`.
fn bracket_prefix(line: &str) -> Option<(Vec<&str>, usize)> {
    if !line.starts_with("[$") {
        return None;
    }
    let b = line.as_bytes();
    let (mut i, mut start, mut mods) = (2, 2, Vec::new());
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b'/' if matches!(b[i - 1], b'=' | b'|') => {
                if let Some(e) = regex_unit(b, i, b",]|", true) {
                    i = e;
                }
            }
            b',' => {
                mods.push(&line[start..i]);
                start = i + 1;
            }
            b']' => {
                mods.push(&line[start..i]);
                return Some((mods, i + 1));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Split a cosmetic / HTML-filter rule into `(domains, separator, body)` plus `[$…]` modifiers.
pub fn split_cosmetic(line: &str) -> Option<Cosmetic<'_>> {
    if let Some((modifiers, end)) = bracket_prefix(line) {
        let rest = &line[end..];
        // AdGuard also writes `[$path=/x]example.com##sel`.
        let p = domain_list_end(rest)?;
        let sep = COSMETIC_SEPS.iter().find(|s| rest[p..].starts_with(**s))?;
        return Some(Cosmetic {
            domains: &rest[..p],
            sep,
            body: &rest[p + sep.len()..],
            modifiers,
            prefix: &line[..end],
        });
    }
    if let Some(p) = line.find("$@$").or_else(|| line.find("$$")) {
        if valid_domain_part(&line[..p]) && !line.starts_with("||") && !line.starts_with("@@") {
            let sep_len = if line[p..].starts_with("$@$") { 3 } else { 2 };
            return Some(Cosmetic {
                domains: &line[..p],
                sep: "$$",
                body: &line[p + sep_len..],
                modifiers: Vec::new(),
                prefix: "",
            });
        }
    }
    let p = domain_list_end(line)?;
    COSMETIC_SEPS
        .iter()
        .find(|s| line[p..].starts_with(**s))
        .map(|sep| Cosmetic {
            domains: &line[..p],
            sep,
            body: &line[p + sep.len()..],
            modifiers: Vec::new(),
            prefix: "",
        })
}

fn plain_name(t: &str) -> bool {
    let name = t
        .split('=')
        .next()
        .unwrap_or("")
        .trim()
        .trim_start_matches('~');
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// Split `pattern$options`. A `$` inside a `/…/` regex (a pure-regex pattern or an option value)
/// is not a separator. Pure-regex rules (`/.../`) without options return no options.
pub fn split_options(line: &str) -> (&str, Option<&str>) {
    let b = line.as_bytes();
    if !b.contains(&b'$') {
        return (line, None);
    }
    let pat0 = if line.starts_with("@@") { 2 } else { 0 };
    // A leading regex pattern (its closing `/` is followed by `$` or ends the rule): any `$`
    // before that `/` belongs to the regex.
    let regex_close = (b.get(pat0) == Some(&b'/'))
        .then(|| regex_unit(b, pat0, b"$", false))
        .flatten();
    if regex_close.is_some_and(|e| e + 1 == b.len()) {
        return (line, None);
    }
    let min = regex_close.map_or(0, |e| e + 1);
    // Unescaped `$` candidates, rightmost first (`\$` appears in `$jsonprune`).
    let cands = (min..b.len())
        .rev()
        .filter(|&i| b[i] == b'$' && (i == 0 || b[i - 1] != b'\\'));
    let first_ok = |p: usize| plain_name(line[p + 1..].split(',').next().unwrap_or(""));
    // Prefer a split whose every token is a plain option (regex values skipped as a unit), then
    // fall back to the legacy rule: the rightmost `$` whose first option is plain.
    let pick = cands
        .clone()
        .find(|&p| first_ok(p) && Tokens::new(&line[p + 1..], b',').all(plain_name))
        .or_else(|| cands.clone().find(|&p| first_ok(p)));
    match pick {
        Some(p) => (&line[..p], Some(&line[p + 1..])),
        None => (line, None),
    }
}

/// Domains a rule is restricted to.
pub(crate) fn rule_domains(raw: &str) -> Vec<String> {
    let raw = raw.trim();
    if let Some(c) = split_cosmetic(raw) {
        if let Some(m) = c.modifiers.iter().find_map(|m| m.strip_prefix("domain=")) {
            return split_pipe_tokens(m)
                .into_iter()
                .filter(|d| !d.is_empty())
                .map(String::from)
                .collect();
        }
        return domain_items(c.domains)
            .into_iter()
            .filter(|d| !d.is_empty())
            .map(String::from)
            .collect();
    }
    if let (_, Some(opts)) = split_options(raw) {
        for tok in split_option_tokens(opts) {
            if let Some(v) = tok
                .strip_prefix("domain=")
                .or_else(|| tok.strip_prefix("from="))
            {
                return split_pipe_tokens(v)
                    .into_iter()
                    .filter(|d| !d.is_empty())
                    .map(String::from)
                    .collect();
            }
        }
    }
    Vec::new()
}

/// `tok` is the option `name` (any `~` prefix and `=value` ignored, case-insensitive).
fn opt_is(tok: &str, name: &str) -> bool {
    tok.trim_start_matches('~')
        .split('=')
        .next()
        .is_some_and(|n| n.eq_ignore_ascii_case(name))
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
    /// Value of `cap_html_filtering`.
    html: bool,
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
        match &self.s[st..self.i] {
            b"ext_ublock" => true,
            b"cap_html_filtering" => self.html,
            _ => false,
        }
    }
}

fn eval_cond(expr: &str, html: bool) -> bool {
    Cond {
        s: expr.as_bytes(),
        i: 0,
        html,
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

/// What the preprocessor made of one source line (see [`preprocess_trace`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pre {
    /// Handed to rule conversion (an included rule carries its `!#include` line's number).
    Active,
    /// Inside a branch whose `!#if` is false.
    Inactive,
    /// `!#if`, `!#else`, `!#endif` or `!#include`.
    Directive,
}

#[allow(clippy::too_many_arguments)]
fn preprocess_into<'a>(
    content: &'a str,
    includes: &'a HashMap<String, String>,
    depth: usize,
    budget: &mut usize,
    base_line: Option<usize>,
    html: bool,
    out: &mut Vec<(usize, &'a str)>,
    mut trace: Option<&mut Vec<(usize, &'a str, Pre)>>,
) {
    // Stack of (this branch active, any branch taken, parent active).
    let mut stack: Vec<(bool, bool, bool)> = Vec::new();
    let active = |s: &Vec<(bool, bool, bool)>| s.last().is_none_or(|t| t.0);
    for (n, line) in content.lines().enumerate() {
        let t = line.trim();
        if base_line.is_none() {
            // Directives and inactive lines of the list itself (not of an include) are traced.
            if let Some(tr) = trace.as_deref_mut() {
                let directive = t.starts_with("!#if")
                    || t.starts_with("!#else")
                    || t.starts_with("!#endif")
                    || t.starts_with("!#include");
                if directive {
                    tr.push((n + 1, line, Pre::Directive));
                } else if !active(&stack) {
                    tr.push((n + 1, line, Pre::Inactive));
                }
            }
        }
        if let Some(rest) = t.strip_prefix("!#if") {
            let parent = active(&stack);
            let v = parent && eval_cond(rest, html);
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
                        html,
                        out,
                        trace.as_deref_mut(),
                    );
                }
            }
        } else if active(&stack) {
            let at = base_line.unwrap_or(n + 1);
            out.push((at, line));
            if let Some(tr) = trace.as_deref_mut() {
                tr.push((at, line, Pre::Active));
            }
        }
    }
}

/// The preprocessor's decision for every line of `content`, in source order: directives and
/// inactive lines of the list itself, and every active line (included rules carry the number of
/// their `!#include` line). Same evaluation as [`convert`](super::convert).
pub(crate) fn preprocess_trace<'a>(
    content: &'a str,
    includes: &'a HashMap<String, String>,
    trusted: bool,
) -> Vec<(usize, &'a str, Pre)> {
    let mut out = Vec::new();
    let mut trace = Vec::new();
    preprocess_into(
        content,
        includes,
        0,
        &mut { MAX_INCLUDES },
        None,
        trusted,
        &mut out,
        Some(&mut trace),
    );
    trace
}

/// Evaluate `!#if` / `!#else` / `!#endif`, splice `!#include`s from `includes`, and parse header
/// metadata, for an untrusted list. Returns the resulting text.
pub fn preprocess_and_meta(
    content: &str,
    includes: &HashMap<String, String>,
) -> (String, ListMeta) {
    preprocess_and_meta_for(content, includes, false)
}

/// Like [`preprocess_and_meta`]; `trusted` lists see `cap_html_filtering` as true.
pub fn preprocess_and_meta_for(
    content: &str,
    includes: &HashMap<String, String>,
    trusted: bool,
) -> (String, ListMeta) {
    let mut lines = Vec::new();
    preprocess_into(
        content,
        includes,
        0,
        &mut { MAX_INCLUDES },
        None,
        trusted,
        &mut lines,
        None,
    );
    let text: String = lines.iter().flat_map(|(_, l)| [*l, "\n"]).collect();
    (text, scan_meta(content))
}

// ---- rule processing ---------------------------------------------------------------------------

pub(crate) enum Rule {
    /// Rules to emit; `true` if rewritten from the input.
    Emit(Vec<String>, bool),
    Ext(ExtRule),
    Error(&'static str),
}

fn network_rule(t: &str) -> Rule {
    let (pattern, Some(opts)) = split_options(t) else {
        // A rule with no pattern (`||`, `@@`) would match every request.
        if t.trim_matches(['|', '^', '*', '@']).is_empty() {
            return Rule::Error("empty pattern");
        }
        // The engine's own option splitter takes the `$` of a closing `$/` for an option
        // separator ("unrecognised option"); `\z` is the same end-of-text anchor.
        let at = if t.starts_with("@@") { "@@" } else { "" };
        let body = &t[at.len()..];
        // An odd run of backslashes escapes the `$`; an even one leaves it an anchor.
        let slashes = body
            .bytes()
            .rev()
            .skip(2)
            .take_while(|&b| b == b'\\')
            .count();
        if body.len() > 3 && body.starts_with('/') && body.ends_with("$/") && slashes % 2 == 0 {
            return Rule::Emit(vec![format!("{at}{}\\z/", &body[..body.len() - 2])], true);
        }
        return Rule::Emit(vec![t.to_string()], false);
    };
    let (exception, bare) = match pattern.strip_prefix("@@") {
        Some(p) => (true, p),
        None => (false, pattern),
    };
    let mut toks: Vec<String> = split_option_tokens(opts)
        .into_iter()
        .map(|s| s.trim().to_string())
        .collect();
    // Normalisation: `reason=` is metadata, `uritransform` is AdGuard's `urltransform`, and
    // `rewrite=abp-resource:x` is `redirect=x`.
    let mut changed = false;
    let before = toks.len();
    toks.retain(|t| !opt_is(t, "reason"));
    changed |= toks.len() != before;
    for t in toks.iter_mut() {
        if let Some(v) = t.strip_prefix("rewrite=abp-resource:") {
            *t = format!("redirect={v}");
            changed = true;
        } else if let Some(v) = t.strip_prefix("uritransform=") {
            *t = format!("urltransform={v}");
            changed = true;
        } else if t == "uritransform" {
            *t = "urltransform".into();
            changed = true;
        }
    }
    let has = |toks: &[String], n: &str| toks.iter().any(|t| opt_is(t, n) && !t.starts_with('~'));
    let norm = if changed {
        format!(
            "{pattern}{}",
            if toks.is_empty() {
                String::new()
            } else {
                format!("${}", toks.join(","))
            }
        )
    } else {
        t.to_string()
    };
    let ext = |k: ExtKind| Rule::Ext(ExtRule::new(k, &norm));
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
            "header" => ExtKind::Header,
            _ => continue,
        };
        return ext(kind);
    }
    if has(&toks, "popup") {
        if has(&toks, "document") || has(&toks, "doc") || has(&toks, "all") {
            toks.retain(|t| !opt_is(t, "popup"));
            changed = true;
        } else {
            return ext(ExtKind::Popup);
        }
    }
    for t in toks.iter_mut() {
        if t == "empty" {
            *t = "redirect=nooptext".into();
            changed = true;
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

    // $denyallow=a|b: "the rule applies except to requests for those hosts". Not expressible
    // exactly with native syntax: an `@@||a^` exception would also unblock `a` for every *other*
    // rule in the same scope, silently changing decisions. So it is handed off, never approximated.
    if toks.iter().any(|t| opt_is(t, "denyallow")) {
        return ext(ExtKind::DenyAllow);
    }
    // $to=a|b with a match-all pattern: block those hosts under the remaining options.
    if let Some(i) = toks.iter().position(|t| opt_is(t, "to")) {
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
        if toks.is_empty() && bare.trim_matches(['|', '^', '*']).is_empty() {
            return Rule::Error("empty pattern");
        }
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

/// `remove: true` (any spacing, case, trailing `;`): AdGuard's "remove the element" declaration.
fn is_remove_decl(style: &str) -> bool {
    let n: String = style
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ';')
        .collect();
    n.eq_ignore_ascii_case("remove:true")
}

/// The selector of `sel:style(remove: true)`, or `None` for any other body.
fn remove_form(body: &str) -> Option<&str> {
    let b = body.trim_end();
    let i = b.rfind(":style(")?;
    let inner = b[i + 7..].strip_suffix(')')?;
    (is_remove_decl(inner) && !b[..i].trim().is_empty()).then(|| b[..i].trim_end())
}

fn cosmetic_rule(t: &str, c: &Cosmetic<'_>) -> Rule {
    if c.has_location_modifiers() {
        return Rule::Ext(ExtRule::new(ExtKind::CosmeticLocation, t));
    }
    // adblock-rust drops regex hostnames silently (the rest of the list is then applied too
    // widely or narrowly), so such a rule never goes to the engine.
    if c.is_location() {
        return Rule::Ext(ExtRule::new(ExtKind::CosmeticLocation, t));
    }
    cosmetic_rule_inner(t, c)
}

fn cosmetic_rule_inner(t: &str, c: &Cosmetic<'_>) -> Rule {
    let exception = c.sep.starts_with("#@");
    if let Some(hosts) = c.plain_modifier_domains() {
        // `[$domain=a.com|b.com]##sel` is `a.com,b.com##sel`.
        let t2 = format!("{hosts}{}{}", c.sep, c.body);
        let c2 = Cosmetic {
            domains: &hosts,
            sep: c.sep,
            body: c.body,
            modifiers: Vec::new(),
            prefix: "",
        };
        return match cosmetic_rule(&t2, &c2) {
            Rule::Emit(r, _) => Rule::Emit(r, true),
            o => o,
        };
    }
    let ext = |k: ExtKind| Rule::Ext(ExtRule::new(k, t));
    match c.sep {
        "$$" => ext(ExtKind::HtmlFilter),
        "##" | "#@#" if c.body.starts_with('^') => ext(ExtKind::HtmlFilter),
        "##" | "#@#" | "#?#" | "#@?#" => match remove_form(c.body) {
            // `sel:style(remove: true)` is the remove action, not a style declaration.
            Some(sel) => Rule::Emit(vec![format!("{}{}{sel}:remove()", c.domains, c.sep)], true),
            None => Rule::Emit(vec![t.to_string()], false),
        },
        "#$#" | "#@$#" | "#$?#" | "#@$?#" => {
            let body = c.body.trim();
            match (body.find('{'), body.ends_with('}')) {
                (Some(open), true) => {
                    let sel = body[..open].trim();
                    let style = body[open + 1..body.len() - 1].trim().trim_end_matches(';');
                    let sep = if exception { "#@#" } else { "##" };
                    let action = if is_remove_decl(style) {
                        ":remove()".to_string()
                    } else {
                        format!(":style({style})")
                    };
                    Rule::Emit(vec![format!("{}{sep}{sel}{action}", c.domains)], true)
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
        return format!("{}{}{sep}{}", c.prefix, c.domains, c.body);
    }
    format!("@@{rule}")
}

/// Convert one preprocessed line. `None` for blanks, comments and headers.
pub(crate) fn convert_line(raw: &str, allowlist: bool) -> Option<Rule> {
    let t = raw.trim();
    if t.is_empty() || t.starts_with('!') {
        return None;
    }
    let cosmetic = split_cosmetic(t);
    if t.starts_with('[') && t.ends_with(']') && cosmetic.is_none() {
        return None; // `[Adblock Plus 2.0]`
    }
    if t.starts_with('#') && t[1..].chars().next().is_none_or(char::is_whitespace) {
        return None; // `# comment`
    }
    let rule = match cosmetic {
        Some(c) => cosmetic_rule(t, &c),
        None => network_rule(t),
    };
    Some(match rule {
        Rule::Emit(rules, translated) if allowlist => {
            Rule::Emit(rules.iter().map(|r| to_exception(r)).collect(), translated)
        }
        Rule::Ext(mut e) if allowlist => {
            e.raw = to_exception(&e.raw);
            Rule::Ext(e)
        }
        r => r,
    })
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
        opts.trusted,
        &mut lines,
        None,
    );
    for (line_no, raw) in lines {
        let Some(rule) = convert_line(raw, opts.allowlist) else {
            continue;
        };
        match rule {
            Rule::Emit(rules, translated) => {
                if translated {
                    out.stats.translated += 1;
                }
                for r in rules {
                    out.buf.push_str(&r);
                    out.buf.push('\n');
                    out.stats.converted += 1;
                }
            }
            Rule::Ext(e) => {
                out.stats.ext(e.kind);
                out.ext.push(e);
            }
            Rule::Error(reason) => {
                out.stats.error(line_no, reason);
                if out.stats.error_texts.len() < super::MAX_ERRORS {
                    out.stats.error_texts.push(raw.trim().to_string());
                }
            }
        }
    }
    out.finish(scan_meta(content))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routed(line: &str) -> String {
        match convert_line(line, false) {
            None => "skip".into(),
            Some(Rule::Emit(r, _)) => format!("emit:{}", r.join("\n")),
            Some(Rule::Ext(e)) => format!("ext:{}", e.kind.as_str()),
            Some(Rule::Error(e)) => format!("err:{e}"),
        }
    }

    #[test]
    fn split_options_table() {
        let cases: &[(&str, &str, Option<&str>)] = &[
            // Bug A: `$` inside a regex.
            (r"/^88\.208\.22\.[1234]$/", r"/^88\.208\.22\.[1234]$/", None),
            (
                r"@@/^88\.208\.22\.[1234]$/",
                r"@@/^88\.208\.22\.[1234]$/",
                None,
            ),
            (
                r"/^88\.208\.22\.[1234]$/$script",
                r"/^88\.208\.22\.[1234]$/",
                Some("script"),
            ),
            (
                r"@@/ads\/[a-z$]+/$script,1p",
                r"@@/ads\/[a-z$]+/",
                Some("script,1p"),
            ),
            (r"/a$b,c/", r"/a$b,c/", None),
            (
                r"$removeparam=/^x-\d{6}$/",
                "",
                Some(r"removeparam=/^x-\d{6}$/"),
            ),
            (
                r"||a.com^$removeparam=/^x$/,xhr",
                "||a.com^",
                Some("removeparam=/^x$/,xhr"),
            ),
            (
                r"||a.com^$removeparam=/^x{1,2}$/",
                "||a.com^",
                Some("removeparam=/^x{1,2}$/"),
            ),
            (
                r"*$ipaddress=/^1\.2\.3\.\d+$/,third-party",
                "*",
                Some(r"ipaddress=/^1\.2\.3\.\d+$/,third-party"),
            ),
            (
                r"||a.com^$script,domain=/example\.(com|org)$/",
                "||a.com^",
                Some(r"script,domain=/example\.(com|org)$/"),
            ),
            (
                r"||a.com^$domain=/re$/|b.com",
                "||a.com^",
                Some("domain=/re$/|b.com"),
            ),
            (
                r"||a.com^$header=via:/1\.1 g$/",
                "||a.com^",
                Some(r"header=via:/1\.1 g$/"),
            ),
            (
                r"||a.com^$header=via:/x$/,script",
                "||a.com^",
                Some("header=via:/x$/,script"),
            ),
            // Ordinary rules.
            (
                "||a.com^$script,domain=b.com",
                "||a.com^",
                Some("script,domain=b.com"),
            ),
            (
                "$removeparam=utm_source",
                "",
                Some("removeparam=utm_source"),
            ),
            ("||a.com^", "||a.com^", None),
            (r"||a.com/x\$y$script", r"||a.com/x\$y", Some("script")),
            ("/ads/banner$script", "/ads/banner", Some("script")),
            (
                "/ads/$script,domain=a.com",
                "/ads/",
                Some("script,domain=a.com"),
            ),
            ("/a/b/", "/a/b/", None),
            ("/banner/", "/banner/", None),
            ("||a.com^$~third-party", "||a.com^", Some("~third-party")),
            // A leading `/` is a regex only when its closing `/` ends the pattern.
            (
                "/search$removeparam=/^utm_/",
                "/search",
                Some("removeparam=/^utm_/"),
            ),
            (
                "/ads$csp=script-src https://x.com",
                "/ads",
                Some("csp=script-src https://x.com"),
            ),
            ("/x$domain=/re/", "/x", Some("domain=/re/")),
            ("/x$header=name:/re/", "/x", Some("header=name:/re/")),
            ("/ads$/", "/ads$/", None),
            ("/ads/$script", "/ads/", Some("script")),
            ("||a.com/ads/$script", "||a.com/ads/", Some("script")),
        ];
        for (line, pat, opts) in cases {
            assert_eq!(split_options(line), (*pat, *opts), "{line}");
        }
    }

    #[test]
    fn regex_flags_and_pipes_stay_inside_values() {
        assert_eq!(
            split_option_tokens(r"removeparam=/a{1,2}$/i,xhr"),
            vec![r"removeparam=/a{1,2}$/i", "xhr"]
        );
        assert_eq!(
            split_options(r"||a^$removeparam=/a{1,2}$/i,xhr"),
            ("||a^", Some(r"removeparam=/a{1,2}$/i,xhr"))
        );
        assert_eq!(
            rule_domains(r"||a^$script,domain=/(a|b)\.com/|c.com"),
            vec![r"/(a|b)\.com/", "c.com"]
        );
        assert_eq!(
            rule_domains(r"[$domain=/(a|b)\.com/|c.com]##x"),
            vec![r"/(a|b)\.com/", "c.com"]
        );
        assert_eq!(
            split_pipe_tokens("a.com|/x|y/|b.com"),
            vec!["a.com", "/x|y/", "b.com"]
        );
        assert!(split_cosmetic(r"[$domain=/(a|b)\.com/]##x").is_some_and(|c| c.is_location()));
    }

    #[test]
    fn location_rule_body_may_contain_slashes() {
        assert_eq!(
            routed(r#"[$path=/x]##a[href="/ads/x"]"#),
            "ext:cosmetic-location"
        );
        assert_eq!(
            routed(r#"[$domain=a.com]##a[href^="/ads/"]"#),
            r#"emit:a.com##a[href^="/ads/"]"#
        );
    }

    #[test]
    fn option_tokens_keep_regex_whole() {
        assert_eq!(
            split_option_tokens(r"removeparam=/^x{1,2}$/,xhr,domain=a.com|/b,c/"),
            vec![r"removeparam=/^x{1,2}$/", "xhr", "domain=a.com|/b,c/"]
        );
    }

    #[test]
    fn cosmetic_prefix_and_regex_hosts() {
        let c = split_cosmetic("[$domain=a.com|b.com]##.ad").unwrap();
        assert_eq!((c.sep, c.body, c.domains), ("##", ".ad", ""));
        assert_eq!(c.modifiers, vec!["domain=a.com|b.com"]);
        let c = split_cosmetic("[$path=/x/,domain=/a$/]#$#body { x: y }").unwrap();
        assert_eq!((c.sep, c.body), ("#$#", "body { x: y }"));
        assert_eq!(c.modifiers, vec!["path=/x/", "domain=/a$/"]);
        let c = split_cosmetic(r"/^www\d{1,2}\.example\.com$/,b.com##.ad").unwrap();
        assert_eq!(c.domains, r"/^www\d{1,2}\.example\.com$/,b.com");
        assert!(c.is_location());
        assert!(split_cosmetic("a.com,~b.com##.ad").is_some_and(|c| !c.is_location()));
        // Not cosmetic.
        assert!(split_cosmetic("/foo##bar/").is_none());
        assert!(split_cosmetic("||a.com^$script").is_none());
        assert!(split_cosmetic("[$path=/x").is_none());
        assert!(split_cosmetic("[$path=/x]").is_none());
    }

    #[test]
    fn routing_table() {
        let cases: &[(&str, &str)] = &[
            // Bug B and D: AdGuard `[$…]` prefixes.
            ("[$domain=a.com|b.com]##sel", "emit:a.com,b.com##sel"),
            ("[$domain=~a.com]##sel", "emit:~a.com##sel"),
            ("[$domain=a.com]#@#sel", "emit:a.com#@#sel"),
            (
                "[$domain=a.com]#$#body { margin: 0 }",
                "emit:a.com##body:style(margin: 0)",
            ),
            (
                "[$domain=a.com]#%#//scriptlet('abort-on-property-read', 'x')",
                "emit:a.com##+js(abort-on-property-read, x)",
            ),
            ("[$path=/foo]##.ad", "ext:cosmetic-location"),
            (r"[$path=/^\/a\/[0-9]+$/]##.ad", "ext:cosmetic-location"),
            ("[$path=/foo]#$#body { x: y }", "ext:cosmetic-location"),
            (
                "[$path=/foo]#%#//scriptlet('abort-on-property-read', 'x')",
                "ext:cosmetic-location",
            ),
            ("[$path=/foo]#?#div:has(a)", "ext:cosmetic-location"),
            ("[$domain=/re$/]##sel", "ext:cosmetic-location"),
            (
                "[$domain=/re$/|b.com,path=/x]##sel",
                "ext:cosmetic-location",
            ),
            ("[$domain=a.com,path=/x]##sel", "ext:cosmetic-location"),
            ("[$domain=a.com]##a[href]", "emit:a.com##a[href]"),
            // Bug C and E: regex hostnames.
            // The engine takes plain regex-hostname cosmetics natively; they pass through.
            (r"/^www\d\.example\.com$/##.ad", "ext:cosmetic-location"),
            (r"/^x\.(com|org)$/,b.com#@#.ad", "ext:cosmetic-location"),
            ("[$path=/x]example.com,b.com##.ad", "ext:cosmetic-location"),
            (
                "[$path]f95zone.to##.node:not(.node--forum)",
                "ext:cosmetic-location",
            ),
            ("[$domain=a.com]b.com##.ad", "ext:cosmetic-location"),
            (
                r"/^x\.com$/##^script:has-text(foo)",
                "ext:cosmetic-location",
            ),
            // Headers and comments are still skipped.
            ("[Adblock Plus 2.0]", "skip"),
            ("! comment", "skip"),
            ("# comment", "skip"),
            // Regression: `$` in non-regex positions.
            (
                "||a.com^$script,domain=b.com",
                "emit:||a.com^$script,domain=b.com",
            ),
            (
                "example.com#$#body { x: y }",
                "emit:example.com##body:style(x: y)",
            ),
            ("$removeparam=utm_source", "emit:$removeparam=utm_source"),
            // Bug A in network rules.
            (
                r"$removeparam=/^x-\d{6}$/",
                r"emit:$removeparam=/^x-\d{6}$/",
            ),
            // The engine mistakes a closing `$/` for an option separator: `\z` is the same anchor.
            (r"/^88\.208\.22\.[1234]$/", r"emit:/^88\.208\.22\.[1234]\z/"),
            (r"@@/^a\.b$/", r"emit:@@/^a\.b\z/"),
            (r"/^a\.b\$/", r"emit:/^a\.b\$/"),
            (
                r"*$ipaddress=/^1\.2\.3\.\d+$/",
                r"emit:*$ipaddress=/^1\.2\.3\.\d+$/",
            ),
            // Normalisation.
            ("||a.com^$script,reason=Ad server", "emit:||a.com^$script"),
            ("||a.com^$uritransform=/a/b/", "ext:urltransform"),
            (
                "||a.com^$rewrite=abp-resource:blank-js",
                "emit:||a.com^$redirect=blank-js",
            ),
            (
                "||a.com^$script,rewrite=abp-resource:blank-js",
                "emit:||a.com^$script,redirect=blank-js",
            ),
        ];
        for (line, want) in cases {
            assert_eq!(routed(line), *want, "{line}");
        }
    }

    /// Real rules from the production lists, grouped by how their class changed with P1.
    #[test]
    fn real_list_rules() {
        let cases: &[(&str, &str)] = &[
            // rejected -> ext:cosmetic-location (`[$…]` prefixes)
            (r##"[$domain=/7tv\d+\.com$/]##.a-d-block"##, "ext:cosmetic-location"),
            (r##"[$domain=/7tv\d+\.com$/]##.player_tv_pop"##, "ext:cosmetic-location"),
            (r##"[$domain=/anime\d+\.site/]##a[rel="nofollow sponsored"]"##, "ext:cosmetic-location"),
            (r##"[$domain=/cosmic\d+\.co/]###floatcenter"##, "ext:cosmetic-location"),
            (r##"[$domain=/tigoals\d+\.com/]##.banner"##, "ext:cosmetic-location"),
            (r##"[$domain=/^kiryuu0\d+\.com/]##div[class*=" ads-"] > a > img"##, "ext:cosmetic-location"),
            (r##"[$domain=/^kiryuu0\d+\.com/]#%#//scriptlet('prevent-window-open')"##, "ext:cosmetic-location"),
            (r##"[$domain=/mi?\d?xdrop\d{0,2}\.(net|com)/]#%#//scriptlet("abort-current-inline-script", "document.createElement", "dtnoppu")"##, "ext:cosmetic-location"),
            (r##"[$path=/jobs]linkedin.com###ember33"##, "ext:cosmetic-location"),
            (r##"[$path=/vp]video4k.cc##.video-view-ads-control"##, "ext:cosmetic-location"),
            (r##"[$path]f95zone.to##.node:not(.node--forum):has(a[data-xf-init])"##, "ext:cosmetic-location"),
            (r##"[$path=/^\/$/]cinejosh.com##.container-fluid + br + .container-fluid"##, "ext:cosmetic-location"),
            (r##"[$domain=facebook.com,path=/gaming]#$#body > .AdBox.Ad.advert { display: block !important; }"##, "ext:cosmetic-location"),
            (r##"[$path=/marketplace/item]facebook.com,facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion##a[href*="ads/about"]"##, "ext:cosmetic-location"),
            // regex hostnames the engine takes natively pass through unchanged
            (r##"/(\d{0,1})?tamilprint(\d{1,2})?\.[a-z]{3,7}/##+js(nano-stb, countdown)"##, "ext:cosmetic-location"),
            (r##"/(\d{0,1})?tamilprint(\d{1,2})?\.[a-z]{3,7}/##+js(no-fetch-if, googlesyndication)"##, "ext:cosmetic-location"),
            (r##"/betivotv\d+\.com/##.nk-post-share > div"##, "ext:cosmetic-location"),
            (r##"/^www\.selcuksportshd[a-z0-9-]+\.xyz$/##.footer"##, "ext:cosmetic-location"),
            (r##"/rezka/##.b-wrapper:has(> div.vk-group)"##, "ext:cosmetic-location"),
            // HTML filter on a regex hostname
            (r##"/^x\.com$/##^script:has-text(foo)"##, "ext:cosmetic-location"),
            // rejected -> network: pure regex ending in `$/`
            (r##"/^anon1.gt\d{6}.com$/"##, r##"emit:/^anon1.gt\d{6}.com\z/"##),
            (r##"/^88\.208\.22\.[1234]$/"##, r##"emit:/^88\.208\.22\.[1234]\z/"##),
            (r##"/^(a|c)\.[0-9a-f]{56}\.com$/"##, r##"emit:/^(a|c)\.[0-9a-f]{56}\.com\z/"##),
            (r##"/^23\.109\.170\.(18[7-9]|19[0-2])$/"##, r##"emit:/^23\.109\.170\.(18[7-9]|19[0-2])\z/"##),
            (r##"/^https:\/\/(a|c)\.[0-9a-f]{56}\.com$/"##, r##"emit:/^https:\/\/(a|c)\.[0-9a-f]{56}\.com\z/"##),
            // ext:unsupported-option -> network: `reason=` and `rewrite=abp-resource:`
            ("||prf.hn^$doc,reason=tracker", "emit:||prf.hn^$doc"),
            ("||adjust.com^$doc,reason=tracker", "emit:||adjust.com^$doc"),
            ("||beroniw.com^$all,reason=malicious", "emit:||beroniw.com^$all"),
            ("||guildpass.one^$doc,reason=malicious", "emit:||guildpass.one^$doc"),
            (
                "||googlevideo.com/videoplayback?$rewrite=abp-resource:blank-mp4,domain=laurelberninteriors.com|safeframe.googlesyndication.com",
                "emit:||googlevideo.com/videoplayback?$redirect=blank-mp4,domain=laurelberninteriors.com|safeframe.googlesyndication.com",
            ),
            // ext:unsupported-option / rejected -> ext:urltransform
            (r##"||onual.com/*^link_t=$doc,uritransform=/#[^\/?]+//"##, "ext:urltransform"),
            (r##"||upera.shop/ref/$doc,uritransform=/^\/ref\/[^\/]+//"##, "ext:urltransform"),
            (r##"||amazon.com/s/ref=$doc,uritransform=/\/ref=[^\/?#]+//"##, "ext:urltransform"),
            ("||sulasokvids.net/watch.php?$doc,uritransform=/watch\\.php/video.php/", "ext:urltransform"),
            (r##"$uritransform=/#Echobox=[\d]{10}$//,to=iltalehti.fi|hs.fi"##, "ext:urltransform"),
            // rejected -> ext (regex `$` inside option values and patterns)
            (r##"/_static/delivery.js?nonce=$script,1p,header=server:/^openresty\//"##, "ext:header"),
            (r##"/https?:\/\/[a-z]{10,15}\.com\/[0-9a-zA-Z]{5,20}\/[0-9]{1,10}$/$script,match-case,header=set-cookie:/^GL_UI4=/"##, "ext:header"),
            (r##"/^https:\/\/d[0-9a-z]{12,13}\.cloudfront\.net\/loader\.min\.js$/$script,3p,match-case,header=etag:/^W\/"[0-9a-f]{32}"$/"##, "ext:header"),
            (r##"/^https?:\/\/[^\/]+\/_fd$/$xhr,1p,strict1p,header=X-Request-Id:/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/"##, "ext:header"),
            (r##"/^https?:\/\/[a-z]{8,15}\.com\/$/$xhr,3p,to=com,method=head,header=access-control-expose-headers:/X-DirectionPartner-Id/"##, "ext:method"),
            (r##"/^https?:\/\/[a-z]{8,15}\.net\/$/$xhr,3p,to=net,method=head,header=access-control-expose-headers:/X-DirectionPartner-Id/"##, "ext:method"),
            (r##"/^https:\/\/[-a-z]{8,}\.com\/[f-j][-0-9A-Z_a-z]{2,}\/[0-9A-Za-z][-\/0-9A-Z_a-z]{115,132}$/$script,xhr,3p,match-case,to=com,method=get,header=X-Request-ID:/^[0-9a-f]{32}$/"##, "ext:method"),
            (r##"/theme/002/js/application.js?2.0|$script,1p,replace=/video\.maxPop/0/"##, "ext:replace"),
            (r##"/^https:\/\/[a-z]{5,}-[a-z]{5,}\.space\/[a-z0-9]{6,8}\.js$/$script,3p,to=space,replace=/^function a0_0x.+//"##, "ext:replace"),
            (r##"$removeparam=/^weekend-reading-link-\d{6}$/"##, r##"emit:$removeparam=/^weekend-reading-link-\d{6}$/"##),
            (r##"||link.theplatform.com/s/*/media*=rotten_tomatoes_video$xhr,removeparam=/^((?!SMIL|formats).)*$/"##, r##"emit:||link.theplatform.com/s/*/media*=rotten_tomatoes_video$xhr,removeparam=/^((?!SMIL|formats).)*$/"##),
            (r##"||bing.com/ck/a*u=a1$doc,urlskip=?u /^a1(.*)$/ -safebase64"##, r##"emit:||bing.com/ck/a*u=a1$doc,urlskip=?u /^a1(.*)$/ -safebase64"##),
            (r##"||click.convertkit-mail4.com/$doc,urlskip=/([^/]+$)/ -base64"##, r##"emit:||click.convertkit-mail4.com/$doc,urlskip=/([^/]+$)/ -base64"##),
            (r##"@@/stream/*.m3u8$stealth=referrer,domain=/betanotv\d+\.site$/"##, r##"emit:@@/stream/*.m3u8$stealth=referrer,domain=/betanotv\d+\.site$/"##),
            (r##"||blogger.googleusercontent.com/img/$domain=/^main\.uxsyplayer[a-z0-9-]+\.click$/"##, r##"emit:||blogger.googleusercontent.com/img/$domain=/^main\.uxsyplayer[a-z0-9-]+\.click$/"##),
        ];
        for (line, want) in cases {
            assert_eq!(routed(line), *want, "{line}");
        }
    }

    #[test]
    fn real_list_rules_split() {
        let cases: &[(&str, &str, &str)] = &[
            (r##"/_static/delivery.js?nonce=$script,1p,header=server:/^openresty\//"##, "/_static/delivery.js?nonce=", r##"script,1p,header=server:/^openresty\//"##),
            (r##"/\/_static\/[a-z0-9]{12}\.js\?nonce=\d+$/$script,1p,match-case,header=server:/openresty\//"##, r##"/\/_static\/[a-z0-9]{12}\.js\?nonce=\d+$/"##, r##"script,1p,match-case,header=server:/openresty\//"##),
            (r##"$removeparam=/^weekend-reading-link-\d{6}$/"##, "", r##"removeparam=/^weekend-reading-link-\d{6}$/"##),
            (r##"||bing.com/ck/a*u=a1$doc,urlskip=?u /^a1(.*)$/ -safebase64"##, "||bing.com/ck/a*u=a1", "doc,urlskip=?u /^a1(.*)$/ -safebase64"),
            (r##"@@/stream/*.m3u8$stealth=referrer,domain=/betanotv\d+\.site$/"##, "@@/stream/*.m3u8", r##"stealth=referrer,domain=/betanotv\d+\.site$/"##),
            (r##"||blogger.googleusercontent.com/img/$domain=/^main\.uxsyplayer[a-z0-9-]+\.click$/"##, "||blogger.googleusercontent.com/img/", r##"domain=/^main\.uxsyplayer[a-z0-9-]+\.click$/"##),
            (r##"||link.theplatform.com/s/*/media*=rotten_tomatoes_video$xhr,removeparam=/^((?!SMIL|formats).)*$/"##, "||link.theplatform.com/s/*/media*=rotten_tomatoes_video", r##"xhr,removeparam=/^((?!SMIL|formats).)*$/"##),
            (r##"/^https:\/\/d[0-9a-z]{12,13}\.cloudfront\.net\/loader\.min\.js$/$script,3p,match-case,header=etag:/^W\/"[0-9a-f]{32}"$/"##, r##"/^https:\/\/d[0-9a-z]{12,13}\.cloudfront\.net\/loader\.min\.js$/"##, r##"script,3p,match-case,header=etag:/^W\/"[0-9a-f]{32}"$/"##),
            (r##"/^https?:\/\/[a-z]{8,15}\.com\/$/$xhr,3p,to=com,method=head,header=access-control-expose-headers:/X-DirectionPartner-Id/"##, r##"/^https?:\/\/[a-z]{8,15}\.com\/$/"##, "xhr,3p,to=com,method=head,header=access-control-expose-headers:/X-DirectionPartner-Id/"),
            (r##"/theme/002/js/application.js?2.0|$script,1p,replace=/video\.maxPop/0/"##, "/theme/002/js/application.js?2.0|", r##"script,1p,replace=/video\.maxPop/0/"##),
            (r##"*$script,third-party,denyallow=tvableon.me|mega.co.nz"##, "*", "script,third-party,denyallow=tvableon.me|mega.co.nz"),
        ];
        for (line, pat, opts) in cases {
            assert_eq!(split_options(line), (*pat, Some(*opts)), "{line}");
        }
    }

    #[test]
    fn real_regex_hostnames_rejected_by_the_engine_are_cosmetic_location() {
        for l in [
            r##"/rezka/##.b-wrapper:has(> div.vk-group)"##,
            r##"/apl.*\.me/##[onclick="adr();"]:upward(3)"##,
            r##"/cimcime\d+\.(com|live)/##.telegram-follow-button"##,
            r##"/betivotv\d+\.com/##.nk-post-share > div"##,
            r##"/^www\.selcuksportshd[a-z0-9-]+\.xyz$/##.footer"##,
        ] {
            let e = crate::formats::classify_rejected(l).unwrap();
            assert_eq!(e.kind, ExtKind::CosmeticLocation, "{l}");
        }
    }

    #[test]
    fn any_regex_host_or_modifier_is_never_handed_to_the_engine() {
        for l in [
            r"/re/,b.com##x",
            r"b.com,~/^m\.b\.com$/##x",
            r"/re/##+js(set, a, b)",
            r"/re/#@#x",
            r"/re/#$#body { x: y }",
            r"/re/#%#//scriptlet('abort-on-property-read', 'x')",
            r"/re/##^script:has-text(a)",
            r"[$path=/x]##+js(set, a, b)",
            r"[$path=/x]#@#x",
        ] {
            assert_eq!(routed(l), "ext:cosmetic-location", "{l}");
        }
    }

    #[test]
    fn cap_html_filtering_follows_trust() {
        let list = "!#if cap_html_filtering\nyes\n!#else\nno\n!#endif\n\
                    !#if !cap_html_filtering\nno2\n!#else\nyes2\n!#endif\n";
        let rules = |trusted: bool| {
            let c = convert_abp(
                list,
                &ConvertOptions {
                    trusted,
                    ..Default::default()
                },
            );
            c.rules
        };
        assert_eq!(rules(true), "yes\nyes2\n");
        assert_eq!(rules(false), "no\nno2\n");
        // Other conditions do not depend on trust.
        let c = |trusted| {
            convert_abp(
                "!#if ext_ublock\na\n!#endif\n!#if adguard\nb\n!#endif\n",
                &ConvertOptions {
                    trusted,
                    ..Default::default()
                },
            )
            .rules
        };
        assert_eq!(c(true), c(false));
    }

    #[test]
    fn regex_end_anchor_rewrite_counts_backslashes() {
        // Odd run: `\$` is a literal dollar, left alone. Even run: a real anchor.
        assert_eq!(routed(r"/re\$/"), r"emit:/re\$/");
        assert_eq!(routed(r"/re\\$/"), r"emit:/re\\\z/");
        assert_eq!(routed(r"/re\\\$/"), r"emit:/re\\\$/");
        assert_eq!(routed(r"@@/re\\\\$/"), r"emit:@@/re\\\\\z/");
    }

    #[test]
    fn uritransform_is_urltransform() {
        let Some(Rule::Ext(e)) = convert_line("||a.com^$uritransform=/a/b/,reason=x", false) else {
            panic!("not ext")
        };
        assert_eq!(e.raw, "||a.com^$urltransform=/a/b/");
        assert_eq!(e.kind, ExtKind::UrlTransform);
    }

    #[test]
    fn allowlist_keeps_bracket_prefix() {
        let Some(Rule::Ext(e)) = convert_line("[$path=/x]##.ad", true) else {
            panic!("not ext")
        };
        assert_eq!(
            (e.kind, e.raw.as_str()),
            (ExtKind::CosmeticLocation, "[$path=/x]#@#.ad")
        );
    }

    #[test]
    fn rejected_cosmetic_location_classifies_as_ext() {
        for l in [
            "[$path=/x]##.ad",
            "[$domain=/re$/]#?#div:has(a)",
            r"/^a\.com$/##.ad",
        ] {
            let e = crate::formats::classify_rejected(l).unwrap();
            assert_eq!(e.kind, ExtKind::CosmeticLocation, "{l}");
        }
    }

    #[test]
    fn domains_of_prefixed_and_regex_rules() {
        assert_eq!(
            rule_domains("[$domain=a.com|~b.com]##x"),
            vec!["a.com", "~b.com"]
        );
        assert_eq!(
            rule_domains(r"/^a{1,2}\.com$/,b.com##x"),
            vec![r"/^a{1,2}\.com$/", "b.com"]
        );
        assert_eq!(
            rule_domains(r"||a^$script,domain=/x,y$/|b.com"),
            vec!["/x,y$/", "b.com"]
        );
    }
}

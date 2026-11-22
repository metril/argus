//! Rule text -> typed rule.

use filter_engine::formats::{split_cosmetic, split_options, ExtKind, ExtRule};
use regex::{Regex, RegexBuilder};

use crate::cookie::CookieSpec;
use crate::headers::is_removable_header;
use crate::hls::HlsPrune;
use crate::jsonprune::JsonPrune;
use crate::pattern::Pattern;
use crate::replace::ReplaceSpec;
use crate::util::{host_is_or_under, DomainSet};
use crate::xmlprune::XmlPrune;

/// Bit set of rule behaviours; exceptions carry a mask of what they disable.
pub mod target {
    pub const BLOCK: u32 = 1;
    pub const REPLACE: u32 = 1 << 1;
    pub const JSONPRUNE: u32 = 1 << 2;
    pub const XMLPRUNE: u32 = 1 << 3;
    pub const HLS: u32 = 1 << 4;
    pub const REMOVEHEADER: u32 = 1 << 5;
    pub const COOKIE: u32 = 1 << 6;
    pub const PERMISSIONS: u32 = 1 << 7;
    pub const URLTRANSFORM: u32 = 1 << 8;
    pub const HEADER: u32 = 1 << 9;
    pub const HTML: u32 = 1 << 10;
    pub const JS: u32 = 1 << 11;
    pub const SNIPPET: u32 = 1 << 12;
    pub const SCRIPTLET: u32 = 1 << 13;
    pub const PCSS: u32 = 1 << 14;
    pub const ALL: u32 = (1 << 15) - 1;
}

/// Stage bits: when a rule is evaluated.
pub(crate) const STAGE_REQ: u8 = 1;
pub(crate) const STAGE_RESP: u8 = 2;

pub(crate) const T_DOC: u16 = 1;
pub(crate) const T_ALL: u16 = (1 << 12) - 1;

/// Why a rule could not be turned into an active rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    /// Malformed.
    Invalid(String),
    /// Well-formed but uses something this crate does not implement.
    Unsupported(String),
    /// A style block that could load resources or escape the declaration list.
    Unsafe(String),
}

impl RuleError {
    pub fn reason(&self) -> &str {
        match self {
            Self::Invalid(s) | Self::Unsupported(s) | Self::Unsafe(s) => s,
        }
    }
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(s) => write!(f, "invalid: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported: {s}"),
            Self::Unsafe(s) => write!(f, "unsafe: {s}"),
        }
    }
}

fn inv<T>(s: impl Into<String>) -> Result<T, RuleError> {
    Err(RuleError::Invalid(s.into()))
}
fn uns<T>(s: impl Into<String>) -> Result<T, RuleError> {
    Err(RuleError::Unsupported(s.into()))
}

/// A `$header=` condition on a response header.
#[derive(Debug, Clone)]
pub struct HeaderMatch {
    pub value: String,
    name: String,
    cond: HeaderCond,
    negate: bool,
}

#[derive(Debug, Clone)]
enum HeaderCond {
    Present,
    Equals(String),
    Regex(Regex),
}

impl HeaderMatch {
    /// `name`, `name:value`, `name:/regex/i`, `name:~value` (uBO "Static filter syntax: header=").
    pub fn parse(v: &str) -> Result<Self, String> {
        let (name, val) = match v.split_once(':') {
            Some((n, x)) => (n, Some(x)),
            None => (v, None),
        };
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err("empty header name".into());
        }
        let (mut negate, mut cond) = (false, HeaderCond::Present);
        if let Some(x) = val {
            let x = match x.strip_prefix('~') {
                Some(r) => {
                    negate = true;
                    r
                }
                None => x,
            };
            cond = match x
                .strip_prefix('/')
                .and_then(|r| r.rfind('/').map(|i| (&r[..i], &r[i + 1..])))
            {
                Some((re, fl)) => HeaderCond::Regex(
                    RegexBuilder::new(re)
                        .case_insensitive(fl.contains('i'))
                        .size_limit(1 << 20)
                        .build()
                        .map_err(|e| format!("unsupported regex: {e}"))?,
                ),
                None => HeaderCond::Equals(x.to_string()),
            };
        }
        Ok(Self {
            value: v.to_string(),
            name,
            cond,
            negate,
        })
    }

    /// Does any response header satisfy the condition?
    pub fn matches(&self, headers: &[(&str, &str)]) -> bool {
        let mut any = false;
        for (_, v) in headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(&self.name))
        {
            let m = match &self.cond {
                HeaderCond::Present => true,
                HeaderCond::Equals(e) => v.trim().eq_ignore_ascii_case(e),
                HeaderCond::Regex(r) => r.is_match(v),
            };
            any |= m;
        }
        match (&self.cond, self.negate) {
            // `~value`: the header may be absent; it matches when no value equals / matches.
            (HeaderCond::Present, _) => any,
            (_, true) => !any,
            (_, false) => any,
        }
    }
}

/// Default cap on the length of an element a `$$` / `##^` filter may remove.
// TODO(verify): the AdGuard KB documents `max-length` but states no default; 8192 is unverified.
pub const DEFAULT_MAX_ELEMENT_LEN: usize = 8192;

#[derive(Debug, Clone)]
pub enum TextPred {
    Contains(String),
    Regex(Regex),
}

impl TextPred {
    fn matches(&self, s: &str) -> bool {
        match self {
            Self::Contains(c) => s.contains(c.as_str()),
            Self::Regex(r) => r.is_match(s),
        }
    }
}

/// An HTML element-removal filter (`##^`, AdGuard `$$`) as data for a streaming rewriter: select
/// candidate elements with `css`, buffer at most `max_len` bytes of the element, require every
/// `text` predicate to match its inner text / markup and `min_len..=max_len` to hold, then drop it.
#[derive(Debug, Clone)]
pub struct HtmlRemoval {
    /// CSS selector for candidate elements (`*` when only text conditions are given).
    pub css: String,
    /// Leading tag name, when the selector names one (cheap pre-filter for the rewriter).
    pub tag: Option<String>,
    /// All must match the element's content (AdGuard `tag-content` / `wildcard`, uBO `:has-text`).
    pub text: Vec<TextPred>,
    pub min_len: usize,
    pub max_len: usize,
    /// AdGuard `parent-elements`: ancestor tag names (kept as data; the rewriter may ignore it).
    pub parent_elements: Vec<String>,
}

impl HtmlRemoval {
    /// Do all text predicates match `content`?
    pub fn text_matches(&self, content: &str) -> bool {
        self.text.iter().all(|p| p.matches(content))
    }
    /// Is an element of `len` bytes within the length bounds?
    pub fn length_ok(&self, len: usize) -> bool {
        len >= self.min_len && len <= self.max_len
    }
    /// Whether the rewriter must buffer the element's content to decide.
    pub fn needs_text(&self) -> bool {
        !self.text.is_empty()
    }
}

/// Something to inject into the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Injection {
    /// Raw JavaScript (`#%#`).
    Script(String),
    /// AdGuard scriptlet with no uBO equivalent.
    Scriptlet { name: String, args: Vec<String> },
    /// ABP snippet calls (`#$#a 1; b 2`).
    Snippet(Vec<(String, Vec<String>)>),
    /// Extended / procedural CSS the engine rejected: selector (+ optional style declarations)
    /// for the in-page procedural evaluator.
    ProceduralCss {
        selector: String,
        style: Option<String>,
    },
}

fn js_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '<' => o.push_str("\\u003c"),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

impl Injection {
    /// JavaScript to put in a `<script>` for script-like injections. Scriptlets and snippets call
    /// the in-page runtime hook `self.__adblockerRuntime.run(kind, name, args)`; when the hook is
    /// absent they are no-ops. `ProceduralCss` returns `None` (use the selector data).
    pub fn script_body(&self) -> Option<String> {
        let call = |kind: &str, name: &str, args: &[String]| {
            let a: Vec<String> = args.iter().map(|x| js_str(x)).collect();
            format!(
                "try{{var r=self.__adblockerRuntime;r&&r.run({},{},[{}])}}catch(e){{}}",
                js_str(kind),
                js_str(name),
                a.join(",")
            )
        };
        match self {
            Self::Script(s) => Some(s.clone()),
            Self::Scriptlet { name, args } => Some(call("scriptlet", name, args)),
            Self::Snippet(calls) => Some(
                calls
                    .iter()
                    .map(|(n, a)| call("snippet", n, a))
                    .collect::<Vec<_>>()
                    .join(";"),
            ),
            Self::ProceduralCss { .. } => None,
        }
    }
}

/// What a rule does.
#[derive(Debug, Clone)]
pub enum Action {
    /// Block the request / response.
    Block,
    Replace(ReplaceSpec),
    JsonPrune(JsonPrune),
    XmlPrune(XmlPrune),
    Hls(HlsPrune),
    RemoveHeader {
        name: String,
        request: bool,
    },
    Cookie(CookieSpec),
    /// `Permissions-Policy` directives to add.
    Permissions(String),
    UrlTransform(ReplaceSpec),
    /// Block when a response header matches.
    Header(HeaderMatch),
    HtmlRemove(HtmlRemoval),
    Inject(Injection),
    /// An exception: disables rules whose [`target`] bit is in `mask` and whose
    /// [`ParsedRule::value`] equals the exception's (an empty value disables all of them).
    Disable {
        mask: u32,
    },
}

impl Action {
    /// The [`target`] bit of a positive action (0 for exceptions).
    pub fn target(&self) -> u32 {
        use target::*;
        match self {
            Self::Block => BLOCK,
            Self::Replace(_) => REPLACE,
            Self::JsonPrune(_) => JSONPRUNE,
            Self::XmlPrune(_) => XMLPRUNE,
            Self::Hls(_) => HLS,
            Self::RemoveHeader { .. } => REMOVEHEADER,
            Self::Cookie(_) => COOKIE,
            Self::Permissions(_) => PERMISSIONS,
            Self::UrlTransform(_) => URLTRANSFORM,
            Self::Header(_) => HEADER,
            Self::HtmlRemove(_) => HTML,
            Self::Inject(Injection::Script(_)) => JS,
            Self::Inject(Injection::Scriptlet { .. }) => SCRIPTLET,
            Self::Inject(Injection::Snippet(_)) => SNIPPET,
            Self::Inject(Injection::ProceduralCss { .. }) => PCSS,
            Self::Disable { .. } => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Party {
    Any,
    Third,
    First,
}

#[derive(Debug, Clone)]
pub(crate) struct NetMatch {
    pub pat: Pattern,
    pub types: u16,
    pub party: Party,
    pub src: DomainSet,
    pub to: DomainSet,
    pub deny: Vec<String>,
    pub methods_in: Vec<String>,
    pub methods_out: Vec<String>,
    pub popup: bool,
}

impl NetMatch {
    pub fn method_ok(&self, m: &str) -> bool {
        (self.methods_in.is_empty() || self.methods_in.iter().any(|x| x.eq_ignore_ascii_case(m)))
            && !self.methods_out.iter().any(|x| x.eq_ignore_ascii_case(m))
    }
    pub fn host_ok(&self, host: &str) -> bool {
        self.to.matches(host) && !self.deny.iter().any(|d| host_is_or_under(host, d))
    }
}

/// A rule in typed form.
#[derive(Debug, Clone)]
pub struct ParsedRule {
    /// The kind the filter converter classified it as.
    pub src_kind: ExtKind,
    pub raw: String,
    /// Source list id and trust, carried from [`ExtRule`].
    pub list: String,
    pub trusted: bool,
    pub exception: bool,
    pub important: bool,
    pub badfilter: bool,
    pub action: Action,
    /// Pairing key: an exception with a non-empty value disables the rule with the same value.
    pub value: String,
    /// Evaluation stage bits (request / response); 0 for page-scoped rules.
    pub(crate) stage: u8,
    /// Normalised text used to pair `$badfilter` rules with their target.
    pub(crate) key: String,
    pub(crate) net: Option<NetMatch>,
    /// Page-domain scope of cosmetic rules.
    pub(crate) dom: Option<DomainSet>,
}

impl ParsedRule {
    /// Behaviour bit(s): the action's target, or the mask an exception disables.
    pub fn target_mask(&self) -> u32 {
        match &self.action {
            Action::Disable { mask } => *mask,
            a => a.target(),
        }
    }
}

/// Split options on unescaped commas; `\,` becomes `,`.
fn split_opts(opts: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut it = opts.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\\' if it.peek() == Some(&',') => {
                it.next();
                out.last_mut().unwrap().push(',');
            }
            ',' => out.push(String::new()),
            _ => out.last_mut().unwrap().push(c),
        }
    }
    out
}

fn type_bit(n: &str) -> Option<u16> {
    Some(match n {
        "document" | "doc" => 1,
        "subdocument" | "frame" => 1 << 1,
        "stylesheet" | "css" => 1 << 2,
        "script" => 1 << 3,
        "image" => 1 << 4,
        "font" => 1 << 5,
        "media" => 1 << 6,
        "xmlhttprequest" | "xhr" => 1 << 7,
        "websocket" => 1 << 8,
        "ping" => 1 << 9,
        "object" | "object-subrequest" => 1 << 10,
        "other" => 1 << 11,
        _ => return None,
    })
}

fn unquote_arg(s: &str) -> String {
    let s = s.trim();
    for q in ['\'', '"'] {
        if s.len() >= 2 && s.starts_with(q) && s.ends_with(q) {
            return s[1..s.len() - 1].to_string();
        }
    }
    s.to_string()
}

/// Normalised identity of a network rule for `$badfilter` pairing.
fn norm_key(pattern: &str, opts: &[String]) -> String {
    let mut o: Vec<String> = opts
        .iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.eq_ignore_ascii_case("badfilter") && !t.is_empty())
        .map(|t| match t.split_once('=') {
            Some((k, v)) => format!("{}={v}", k.to_ascii_lowercase()),
            None => t.to_ascii_lowercase(),
        })
        .collect();
    o.sort();
    format!("{pattern}${}", o.join(","))
}

/// Parse one handed-off rule.
pub fn parse_rule(r: &ExtRule) -> Result<ParsedRule, RuleError> {
    let raw = r.raw.trim();
    if raw.is_empty() {
        return inv("empty rule");
    }
    let mut rule = if let Some(c) = split_cosmetic(raw) {
        let ex = raw[c.domains.len()..].starts_with("$@$") || c.sep.starts_with("#@");
        parse_cosmetic(raw, c.domains, c.sep, c.body, ex)?
    } else {
        parse_network(raw)?
    };
    rule.src_kind = r.kind;
    rule.list = r.list.clone();
    rule.trusted = r.trusted;
    Ok(rule)
}

fn blank(raw: &str, action: Action, exception: bool) -> ParsedRule {
    ParsedRule {
        src_kind: ExtKind::Other,
        raw: raw.to_string(),
        list: String::new(),
        trusted: false,
        exception,
        important: false,
        badfilter: false,
        action,
        value: String::new(),
        stage: 0,
        key: raw.to_string(),
        net: None,
        dom: None,
    }
}

fn parse_network(raw: &str) -> Result<ParsedRule, RuleError> {
    use target::*;
    let (pattern, opts) = split_options(raw);
    let Some(opts) = opts else {
        return uns("not an extended network rule");
    };
    let (exception, pat) = match pattern.strip_prefix("@@") {
        Some(p) => (true, p),
        None => (false, pattern),
    };
    let toks = split_opts(opts);
    let key = norm_key(pattern, &toks);

    let mut match_case = false;
    let mut important = false;
    let mut badfilter = false;
    let mut party = Party::Any;
    let (mut incl, mut excl) = (0u16, 0u16);
    let mut src = DomainSet::default();
    let mut to = DomainSet::default();
    let mut deny: Vec<String> = Vec::new();
    let (mut m_in, mut m_out) = (Vec::new(), Vec::new());
    let mut popup = false;
    let mut scope_mask = 0u32;
    // (target, value, compiled-lazily action builder input)
    let mut act: Option<(String, String)> = None;

    for t in &toks {
        let t = t.trim();
        if t.is_empty() {
            continue;
        }
        let (neg, body) = match t.strip_prefix('~') {
            Some(b) => (true, b),
            None => (false, t),
        };
        let (name, val) = match body.split_once('=') {
            Some((n, v)) => (n.to_ascii_lowercase(), Some(v)),
            None => (body.to_ascii_lowercase(), None),
        };
        let need = |what: &str| -> Result<&str, RuleError> {
            match val {
                Some(v) if !v.is_empty() => Ok(v),
                _ => inv(format!("${what} needs a value")),
            }
        };
        match name.as_str() {
            "domain" | "from" => {
                src = DomainSet::parse(need("domain")?, '|').map_err(RuleError::Invalid)?
            }
            "to" => to = DomainSet::parse(need("to")?, '|').map_err(RuleError::Invalid)?,
            "denyallow" => {
                for d in need("denyallow")?.split('|') {
                    if d.starts_with('~') || d.is_empty() || d.contains('/') {
                        return inv("bad $denyallow entry");
                    }
                    deny.push(d.to_ascii_lowercase());
                }
            }
            "method" => {
                for m in need("method")?.split('|') {
                    let (n, m) = match m.strip_prefix('~') {
                        Some(x) => (true, x),
                        None => (false, m),
                    };
                    if m.is_empty() || !m.bytes().all(|c| c.is_ascii_alphabetic()) {
                        return inv("bad $method entry");
                    }
                    (if n { &mut m_out } else { &mut m_in }).push(m.to_ascii_uppercase());
                }
            }
            "third-party" | "3p" => party = if neg { Party::First } else { Party::Third },
            "first-party" | "1p" => party = if neg { Party::Third } else { Party::First },
            "match-case" => match_case = !neg,
            "important" => important = !neg,
            "badfilter" => badfilter = true,
            "popup" => popup = !neg,
            "all" => incl = T_ALL,
            "content" if exception => scope_mask |= REPLACE | HTML | HLS | JSONPRUNE | XMLPRUNE,
            "jsinject" if exception => scope_mask |= JS | SCRIPTLET | SNIPPET,
            "elemhide" | "ehide" if exception => scope_mask |= PCSS | HTML,
            "urlblock" if exception => scope_mask |= BLOCK | URLTRANSFORM,
            "replace" | "jsonprune" | "xmlprune" | "hls" | "cookie" | "removeheader"
            | "permissions" | "urltransform" | "header" => {
                if neg {
                    return inv("action modifiers cannot be negated");
                }
                if act.is_some() {
                    return inv("more than one action modifier");
                }
                act = Some((name.clone(), val.unwrap_or("").to_string()));
            }
            n => {
                if let Some(b) = type_bit(n) {
                    if exception && b == T_DOC && !neg {
                        // `@@...$document` lifts every rule on the page (AdGuard KB "$document").
                        scope_mask = ALL;
                    }
                    if neg {
                        excl |= b
                    } else {
                        incl |= b
                    }
                } else {
                    return uns(format!("modifier `{n}`"));
                }
            }
        }
    }

    // Build the action.
    let mut value = String::new();
    let mut stage = STAGE_REQ;
    let action = match &act {
        None => {
            if exception {
                let mask = if scope_mask != 0 {
                    scope_mask
                } else {
                    BLOCK | HEADER
                };
                stage = STAGE_REQ | STAGE_RESP;
                Action::Disable { mask }
            } else {
                if scope_mask != 0 {
                    return uns("exception-only modifier on a blocking rule");
                }
                Action::Block
            }
        }
        Some((name, v)) => {
            value = v.clone();
            let tgt = match name.as_str() {
                "replace" => REPLACE,
                "jsonprune" => JSONPRUNE,
                "xmlprune" => XMLPRUNE,
                "hls" => HLS,
                "cookie" => COOKIE,
                "removeheader" => REMOVEHEADER,
                "permissions" => PERMISSIONS,
                "urltransform" => URLTRANSFORM,
                _ => HEADER,
            };
            let (req_side, resp_side) = match name.as_str() {
                "cookie" => (true, true),
                "urltransform" => (true, false),
                "removeheader" => (
                    v.to_ascii_lowercase().starts_with("request:"),
                    !v.to_ascii_lowercase().starts_with("request:"),
                ),
                _ => (false, true),
            };
            stage =
                (if req_side { STAGE_REQ } else { 0 }) | (if resp_side { STAGE_RESP } else { 0 });
            if exception {
                Action::Disable { mask: tgt }
            } else {
                let need_val = || -> Result<(), RuleError> {
                    if v.is_empty() {
                        inv(format!("${name} needs a value"))
                    } else {
                        Ok(())
                    }
                };
                match name.as_str() {
                    "replace" => {
                        need_val()?;
                        Action::Replace(ReplaceSpec::parse(v).map_err(unsupported_or_invalid)?)
                    }
                    "urltransform" => {
                        need_val()?;
                        Action::UrlTransform(ReplaceSpec::parse(v).map_err(unsupported_or_invalid)?)
                    }
                    "jsonprune" => Action::JsonPrune(
                        JsonPrune::parse(&v.replace("\\$", "$")).map_err(unsupported_or_invalid)?,
                    ),
                    "xmlprune" => {
                        Action::XmlPrune(XmlPrune::parse(v).map_err(unsupported_or_invalid)?)
                    }
                    "hls" => Action::Hls(HlsPrune::parse(v).map_err(unsupported_or_invalid)?),
                    "cookie" => Action::Cookie(CookieSpec::parse(v).map_err(RuleError::Invalid)?),
                    "permissions" => {
                        need_val()?;
                        let v = v.replace("\\,", ",");
                        if !crate::permissions::is_valid(&v) {
                            return inv(format!("`{v}` is not a Permissions-Policy value"));
                        }
                        Action::Permissions(v)
                    }
                    "removeheader" => {
                        need_val()?;
                        let lv = v.to_ascii_lowercase();
                        let (request, n) = match lv.strip_prefix("request:") {
                            Some(n) => (true, n.to_string()),
                            None => (false, lv.clone()),
                        };
                        if !is_removable_header(&n) {
                            return inv(format!("header `{n}` may not be removed"));
                        }
                        Action::RemoveHeader { name: n, request }
                    }
                    _ => {
                        need_val()?;
                        Action::Header(HeaderMatch::parse(v).map_err(RuleError::Invalid)?)
                    }
                }
            }
        }
    };
    // `$popup` only fires for popup navigations; it implies the document type.
    let is_block = matches!(action, Action::Block)
        || matches!(&action, Action::Disable { mask } if mask & BLOCK != 0);
    let types = if popup {
        T_DOC
    } else {
        let base = if incl != 0 {
            incl
        } else if is_block {
            T_ALL & !T_DOC
        } else {
            T_ALL
        };
        base & !excl
    };
    // Permissions-Policy only matters on documents.
    let types = if matches!(action, Action::Permissions(_)) && incl == 0 {
        types & (T_DOC | 2)
    } else {
        types
    };
    let pat = Pattern::parse(pat, match_case).map_err(unsupported_or_invalid)?;
    let net = NetMatch {
        pat,
        types,
        party,
        src,
        to,
        deny,
        methods_in: m_in,
        methods_out: m_out,
        popup,
    };
    let mut r = blank(raw, action, exception);
    r.important = important;
    r.badfilter = badfilter;
    r.value = value;
    r.stage = stage;
    r.key = key;
    r.net = Some(net);
    Ok(r)
}

fn unsupported_or_invalid(e: String) -> RuleError {
    if e.contains("unsupported") {
        RuleError::Unsupported(e)
    } else {
        RuleError::Invalid(e)
    }
}

/// Split on `sep` outside quotes and parentheses.
fn split_top(s: &str, sep: char) -> Vec<&str> {
    let (mut out, mut depth, mut q, mut start) = (Vec::new(), 0i32, None::<char>, 0);
    let mut esc = false;
    for (i, c) in s.char_indices() {
        if esc {
            esc = false;
            continue;
        }
        match (q, c) {
            (_, '\\') => esc = true,
            (Some(x), c) if c == x => q = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => q = Some(c),
            (None, '(') => depth += 1,
            (None, ')') => depth -= 1,
            (None, c) if c == sep && depth == 0 => {
                out.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

fn re_from(s: &str) -> Result<Regex, String> {
    let (src, fl) = match s
        .strip_prefix('/')
        .and_then(|r| r.rfind('/').map(|i| (&r[..i], &r[i + 1..])))
    {
        Some(x) => x,
        None => return Err("not a regex".into()),
    };
    RegexBuilder::new(src)
        .case_insensitive(fl.contains('i'))
        .dot_matches_new_line(fl.contains('s'))
        .size_limit(1 << 20)
        .build()
        .map_err(|e| format!("unsupported regex: {e}"))
}

/// uBO `script:has-text(...)`-style selector -> CSS + text predicates.
fn parse_html_selector(body: &str) -> Result<HtmlRemoval, RuleError> {
    let mut css = String::new();
    let mut text = Vec::new();
    let mut rest = body;
    'outer: while !rest.is_empty() {
        for pseudo in [":has-text(", ":contains("] {
            if let Some(p) = rest.find(pseudo) {
                let args = &rest[p + pseudo.len()..];
                // find the matching ')' honouring nesting, quotes and regex literals
                let (mut depth, mut end, mut esc) = (1i32, None, false);
                for (i, c) in args.char_indices() {
                    if esc {
                        esc = false;
                        continue;
                    }
                    match c {
                        '\\' => esc = true,
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                end = Some(i);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let end =
                    end.ok_or_else(|| RuleError::Invalid("unterminated :has-text(".into()))?;
                let a = args[..end].trim();
                text.push(if a.starts_with('/') && a.len() > 2 {
                    TextPred::Regex(re_from(a).map_err(unsupported_or_invalid_rule)?)
                } else {
                    TextPred::Contains(unquote_arg(a))
                });
                css.push_str(&rest[..p]);
                rest = &args[end + 1..];
                continue 'outer;
            }
        }
        css.push_str(rest);
        break;
    }
    let css = css.trim().to_string();
    if css.contains("responseheader(") {
        return uns("responseheader() combined with other selectors");
    }
    let css = if css.is_empty() { "*".to_string() } else { css };
    let tag = css
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .next()
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_lowercase());
    Ok(HtmlRemoval {
        css,
        tag,
        text,
        min_len: 0,
        max_len: DEFAULT_MAX_ELEMENT_LEN,
        parent_elements: vec![],
    })
}

fn unsupported_or_invalid_rule(e: String) -> RuleError {
    unsupported_or_invalid(e)
}

/// AdGuard `$$tag[attr="v"][tag-content="x"][max-length="N"]`.
fn parse_adguard_html(body: &str) -> Result<HtmlRemoval, RuleError> {
    let body = body.trim();
    let p = body.find('[').unwrap_or(body.len());
    let tag = body[..p].trim();
    let mut out = HtmlRemoval {
        css: String::new(),
        tag: (!tag.is_empty()).then(|| tag.to_ascii_lowercase()),
        text: vec![],
        min_len: 0,
        max_len: DEFAULT_MAX_ELEMENT_LEN,
        parent_elements: vec![],
    };
    let mut css = if tag.is_empty() {
        String::new()
    } else {
        tag.to_string()
    };
    let b = body.as_bytes();
    let mut i = p;
    while i < b.len() {
        if b[i] != b'[' {
            return inv("unexpected text between attribute blocks");
        }
        // find closing ']' outside quotes (AdGuard escapes `"` as `""`)
        let mut j = i + 1;
        let mut inq = false;
        while j < b.len() {
            if b[j] == b'"' {
                if inq && b.get(j + 1) == Some(&b'"') {
                    j += 2;
                    continue;
                }
                inq = !inq;
            } else if b[j] == b']' && !inq {
                break;
            }
            j += 1;
        }
        if j >= b.len() {
            return inv("unterminated [ ]");
        }
        let inner = &body[i + 1..j];
        i = j + 1;
        let (name, val) = match inner.split_once('=') {
            Some((n, v)) => (n.trim(), Some(v.trim())),
            None => (inner.trim(), None),
        };
        let unq = |v: &str| -> String {
            let v = v.trim();
            if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
                v[1..v.len() - 1].replace("\"\"", "\"")
            } else {
                v.to_string()
            }
        };
        let plain = name.trim_end_matches(['*', '^', '$', '~', '|']);
        match (plain, val) {
            ("tag-content", Some(v)) => out.text.push(TextPred::Contains(unq(v))),
            ("wildcard", Some(v)) => {
                let g = unq(v);
                let re = format!(
                    "(?s)^{}$",
                    g.split('*')
                        .map(regex::escape)
                        .collect::<Vec<_>>()
                        .join(".*")
                );
                out.text.push(TextPred::Regex(
                    Regex::new(&re).map_err(|e| RuleError::Invalid(e.to_string()))?,
                ));
            }
            ("max-length", Some(v)) => {
                out.max_len = unq(v)
                    .parse()
                    .map_err(|_| RuleError::Invalid("bad max-length".into()))?
            }
            ("min-length", Some(v)) => {
                out.min_len = unq(v)
                    .parse()
                    .map_err(|_| RuleError::Invalid("bad min-length".into()))?
            }
            ("parent-elements", Some(v)) => {
                out.parent_elements = unq(v)
                    .split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
            (_, Some(v)) => {
                let op = &name[plain.len()..];
                css.push_str(&format!(
                    "[{plain}{op}=\"{}\"]",
                    unq(v).replace('\\', "\\\\").replace('"', "\\\"")
                ));
            }
            (_, None) => css.push_str(&format!("[{plain}]")),
        }
    }
    out.css = if css.is_empty() { "*".into() } else { css };
    Ok(out)
}

fn parse_cosmetic(
    raw: &str,
    domains: &str,
    sep: &str,
    body: &str,
    exception: bool,
) -> Result<ParsedRule, RuleError> {
    use target::*;
    let dom = DomainSet::parse(domains, ',').map_err(RuleError::Invalid)?;
    let body_t = body.trim();
    let (action, value) = match sep {
        "$$" => {
            let b = body.strip_prefix("@$").unwrap_or(body);
            if exception {
                (Action::Disable { mask: HTML }, b.trim().to_string())
            } else {
                (
                    Action::HtmlRemove(parse_adguard_html(b)?),
                    b.trim().to_string(),
                )
            }
        }
        "##" | "#@#" if body_t.starts_with('^') => {
            let inner = body_t[1..].trim();
            if exception {
                (Action::Disable { mask: HTML }, inner.to_string())
            } else if let Some(h) = inner
                .strip_prefix("responseheader(")
                .and_then(|r| r.strip_suffix(')'))
            {
                let n = unquote_arg(h).to_ascii_lowercase();
                if !is_removable_header(&n) {
                    return inv(format!("header `{n}` may not be removed"));
                }
                (
                    Action::RemoveHeader {
                        name: n,
                        request: false,
                    },
                    inner.to_string(),
                )
            } else {
                (
                    Action::HtmlRemove(parse_html_selector(inner)?),
                    inner.to_string(),
                )
            }
        }
        "#%#" | "#@%#" => {
            if let Some(inner) = body_t
                .strip_prefix("//scriptlet(")
                .and_then(|b| b.strip_suffix(')'))
            {
                let args: Vec<String> = split_top(inner, ',')
                    .into_iter()
                    .map(unquote_arg)
                    .filter(|a| !a.is_empty())
                    .collect();
                let Some((name, rest)) = args.split_first() else {
                    return inv("scriptlet without a name");
                };
                if exception {
                    (Action::Disable { mask: SCRIPTLET }, body_t.to_string())
                } else {
                    (
                        Action::Inject(Injection::Scriptlet {
                            name: name.clone(),
                            args: rest.to_vec(),
                        }),
                        body_t.to_string(),
                    )
                }
            } else if exception {
                (
                    Action::Disable {
                        mask: if body_t.is_empty() {
                            JS | SCRIPTLET
                        } else {
                            JS
                        },
                    },
                    body_t.to_string(),
                )
            } else if body_t.is_empty() {
                return inv("empty script");
            } else {
                (
                    Action::Inject(Injection::Script(body_t.to_string())),
                    body_t.to_string(),
                )
            }
        }
        "#$#" | "#@$#" => {
            if exception {
                (Action::Disable { mask: SNIPPET }, body_t.to_string())
            } else {
                let calls: Vec<(String, Vec<String>)> = split_top(body_t, ';')
                    .into_iter()
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                    .map(|c| {
                        let w = split_top(c, ' ');
                        let name = w[0].to_string();
                        (
                            name,
                            w[1..]
                                .iter()
                                .filter(|x| !x.is_empty())
                                .map(|x| unquote_arg(x))
                                .collect(),
                        )
                    })
                    .collect();
                if calls.is_empty() {
                    return inv("empty snippet");
                }
                (
                    Action::Inject(Injection::Snippet(calls)),
                    body_t.to_string(),
                )
            }
        }
        "#?#" | "#@?#" | "#$?#" | "#@$?#" | "##" | "#@#" => {
            if exception {
                (Action::Disable { mask: PCSS }, body_t.to_string())
            } else {
                let (selector, style) =
                    match (sep.contains('$'), body_t.find('{'), body_t.ends_with('}')) {
                        (true, Some(o), true) => (
                            body_t[..o].trim().to_string(),
                            Some(body_t[o + 1..body_t.len() - 1].trim().to_string()),
                        ),
                        _ => (body_t.to_string(), None),
                    };
                if selector.is_empty() {
                    return inv("empty selector");
                }
                if style
                    .as_deref()
                    .is_some_and(|s| !crate::style::is_safe_style(s))
                {
                    return Err(RuleError::Unsafe(
                        "style declaration can load resources or break out of the rule".into(),
                    ));
                }
                (
                    Action::Inject(Injection::ProceduralCss { selector, style }),
                    body_t.to_string(),
                )
            }
        }
        other => return uns(format!("cosmetic separator `{other}`")),
    };
    let mut r = blank(raw, action, exception);
    r.value = value;
    r.stage = 0;
    r.dom = Some(dom);
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(raw: &str) -> Result<ParsedRule, RuleError> {
        parse_rule(&ExtRule::new(ExtKind::Other, raw))
    }

    #[test]
    fn options_and_exceptions() {
        let r = p("||a.example^$replace=/x\\,y/z/,domain=b.example|~c.b.example,script,important,match-case").unwrap();
        assert!(r.important && !r.exception);
        assert!(matches!(r.action, Action::Replace(_)));
        let r = p("@@||a.example^$replace").unwrap();
        assert!(
            matches!(
                r.action,
                Action::Disable {
                    mask: target::REPLACE
                }
            ) && r.value.is_empty()
        );
        let r = p("||a.example^$method=post|~get,badfilter,denyallow=x.example|y.example").unwrap();
        assert!(r.badfilter && matches!(r.action, Action::Block));
        assert_eq!(
            p("||a^$replace=/a/b/").unwrap().key,
            p("||a^$badfilter,replace=/a/b/").unwrap().key
        );
    }

    #[test]
    fn errors_are_structured() {
        assert!(matches!(
            p("||a^$redirect=x,method=get"),
            Err(RuleError::Unsupported(_))
        ));
        assert!(matches!(
            p("||a^$replace=/(?=x)/y/"),
            Err(RuleError::Unsupported(_))
        ));
        assert!(matches!(
            p("||a^$removeheader=content-length"),
            Err(RuleError::Invalid(_))
        ));
        assert!(matches!(p("||a^$replace"), Err(RuleError::Invalid(_))));
        assert!(matches!(
            p("||a^$replace=/a/b/,jsonprune=\\$.x"),
            Err(RuleError::Invalid(_))
        ));
        assert!(p("").is_err());
    }

    #[test]
    fn cosmetic_forms() {
        let r = p("example.com##^script:has-text(adblock)").unwrap();
        let Action::HtmlRemove(h) = &r.action else {
            panic!()
        };
        assert_eq!(
            (h.css.as_str(), h.tag.as_deref(), h.text.len()),
            ("script", Some("script"), 1)
        );
        let r = p(
            "example.com$$script[tag-content=\"say \"\"hi\"\"\"][max-length=\"500\"][data-x=\"1\"]",
        )
        .unwrap();
        let Action::HtmlRemove(h) = &r.action else {
            panic!()
        };
        assert_eq!((h.css.as_str(), h.max_len), ("script[data-x=\"1\"]", 500));
        assert!(h.text_matches("... say \"hi\" ..."));
        let r = p("example.com#@#^script:has-text(x)").unwrap();
        assert!(r.exception && r.value == "script:has-text(x)");
        let r = p("a.com#%#//scriptlet('foo', 'x', 'y')").unwrap();
        let Action::Inject(Injection::Scriptlet { name, args }) = &r.action else {
            panic!()
        };
        assert_eq!((name.as_str(), args.len()), ("foo", 2));
        let r = p("a.com#$#hide-if-contains 'x y' .sel; log hi").unwrap();
        let Action::Inject(Injection::Snippet(c)) = &r.action else {
            panic!()
        };
        assert_eq!(c.len(), 2);
        assert!(p("a.com#?#div:-abp-has(.x)").is_ok());
        assert!(p("a.com#$?#div:xpath(//a) { display:none }").is_ok());
    }
}

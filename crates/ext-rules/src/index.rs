//! The immutable rule index and the request / response evaluators.
//!
//! Precedence (per behaviour, see each modifier's docs): among the rules that match a request, a
//! rule is switched off by a matching exception (`@@`) whose [`target`] mask covers it and whose
//! value is empty (disable all) or equal to the rule's value, unless the rule is `$important` and
//! the exception is not. `$badfilter` removes the identical rule (any list) at build time.

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{BTreeMap, HashSet};

use filter_engine::formats::ExtRule;
use serde::{Deserialize, Serialize};

use crate::cookie::{apply_set_cookie, filter_request_cookie, CookieSpec, SetCookie};
use crate::headers::HeaderEdit;
use crate::parse::{parse_rule, target, Action, Injection, NetMatch, ParsedRule, Party, RuleError};
use crate::pattern::{for_each_token, token_hash};
use crate::replace::is_textual_content_type;
use crate::types::{
    BodyTransform, RequestDecision, RequestInfo, ResourceType, ResponseInfo, ResponsePlan, RuleId,
};
use crate::util::{host_range, lower, suffixes, FxMap};

/// Per-kind build statistics (kinds are [`filter_engine::formats::ExtKind::as_str`] names).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindStats {
    /// Parsed successfully.
    pub parsed: usize,
    /// In the index.
    pub active: usize,
    /// Dropped because the source list is not trusted for this kind.
    pub dropped_untrusted: usize,
    /// Well-formed but outside what this crate implements.
    pub unsupported: usize,
    /// Malformed.
    pub parse_errors: usize,
    /// Switched off by a `$badfilter` rule.
    pub badfiltered: usize,
}

/// One rule that could not be used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleIssue {
    pub kind: String,
    pub list: String,
    pub raw: String,
    pub reason: String,
    pub unsupported: bool,
}

/// What the build did with the handed-off rules.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtStats {
    pub total: usize,
    pub per_kind: BTreeMap<String, KindStats>,
    /// Untrusted rules dropped, per source list id.
    pub dropped_untrusted_by_list: BTreeMap<String, usize>,
    /// First [`BuildOptions::max_issues`] failures.
    pub issues: Vec<RuleIssue>,
    /// Failures beyond the kept ones.
    pub issues_truncated: usize,
}

/// What the build did with one handed-off rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleState {
    /// In the index (enforced; exceptions disable matching rules at request time).
    Active,
    /// Needs a trusted list and the list is not trusted.
    DroppedUntrusted,
    /// Well-formed but not implemented.
    Unsupported(String),
    /// Malformed.
    Invalid(String),
    /// Switched off by a `$badfilter` rule.
    Badfiltered,
    /// A `$badfilter` rule itself (no effect of its own).
    Badfilter,
}

impl RuleState {
    /// Stable machine name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::DroppedUntrusted => "dropped_untrusted",
            Self::Unsupported(_) => "unsupported",
            Self::Invalid(_) => "invalid",
            Self::Badfiltered => "badfiltered",
            Self::Badfilter => "badfilter",
        }
    }
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Unsupported(r) | Self::Invalid(r) => Some(r),
            _ => None,
        }
    }
}

/// Index build options.
#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// Ids of lists whose rules are trusted in addition to rules already marked
    /// [`ExtRule::trusted`].
    pub trusted_lists: HashSet<String>,
    /// How many [`RuleIssue`]s to keep.
    pub max_issues: usize,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            trusted_lists: HashSet::new(),
            max_issues: 50,
        }
    }
}

/// Rules that run code in pages or rewrite content arbitrarily; honoured only from trusted
/// sources (uBO "trusted-only" modifiers). Exceptions never need trust: they only disable.
fn needs_trust(r: &ParsedRule) -> bool {
    // `$permissions` is honoured from any list only while it can merely restrict.
    if let Action::Permissions(v) = &r.action {
        return !r.exception && !crate::permissions::is_restrictive(v);
    }
    !r.exception
        && matches!(
            r.action,
            Action::Replace(_)
                | Action::UrlTransform(_)
                | Action::Inject(
                    Injection::Script(_) | Injection::Scriptlet { .. } | Injection::Snippet(_)
                )
        )
}

#[derive(Default)]
struct NetIdx {
    by_host: FxMap<Box<str>, Vec<u32>>,
    by_src: FxMap<Box<str>, Vec<u32>>,
    by_tok: FxMap<u64, Vec<u32>>,
    generic: Vec<u32>,
    len: usize,
}

impl NetIdx {
    fn add(&mut self, id: u32, n: &NetMatch) {
        self.len += 1;
        if let Some(h) = n.pat.host_key() {
            self.by_host
                .entry(h.to_ascii_lowercase().into())
                .or_default()
                .push(id);
        } else if let Some(keys) = n.to.bucket_keys() {
            for k in keys {
                self.by_host.entry(k.into()).or_default().push(id);
            }
        } else if let Some(keys) = n.src.bucket_keys() {
            for k in keys {
                self.by_src.entry(k.into()).or_default().push(id);
            }
        } else if let Some(t) = n.pat.token() {
            self.by_tok.entry(token_hash(&t)).or_default().push(id);
        } else {
            self.generic.push(id);
        }
    }

    /// Visit candidate ids (possibly repeated).
    fn candidates(&self, ctx: &Ctx<'_>, mut f: impl FnMut(u32)) {
        if !self.by_host.is_empty() {
            for s in suffixes(&ctx.host) {
                if let Some(v) = self.by_host.get(s) {
                    v.iter().for_each(|&i| f(i));
                }
            }
        }
        if !self.by_src.is_empty() {
            for s in suffixes(&ctx.src_host) {
                if let Some(v) = self.by_src.get(s) {
                    v.iter().for_each(|&i| f(i));
                }
            }
        }
        if !self.by_tok.is_empty() {
            for_each_token(ctx.url, |h| {
                if let Some(v) = self.by_tok.get(&h) {
                    v.iter().for_each(|&i| f(i));
                }
                false
            });
        }
        self.generic.iter().for_each(|&i| f(i));
    }
}

#[derive(Default)]
struct DomIdx {
    by_dom: FxMap<Box<str>, Vec<u32>>,
    generic: Vec<u32>,
    len: usize,
}

struct Ctx<'a> {
    url: &'a str,
    host: Cow<'a, str>,
    hr: (usize, usize),
    src_host: Cow<'a, str>,
    has_source: bool,
    source_url: Option<&'a str>,
    rt: u16,
    method: &'a str,
    popup: bool,
    third: Cell<Option<bool>>,
}

impl<'a> Ctx<'a> {
    fn new(r: &RequestInfo<'a>) -> Option<Ctx<'a>> {
        let hr = host_range(r.url)?;
        let host = lower(&r.url[hr.0..hr.1]);
        let src = r
            .source_url
            .and_then(|s| host_range(s).map(|h| lower(&s[h.0..h.1])));
        let has_source = src.is_some();
        Some(Ctx {
            url: r.url,
            src_host: src.unwrap_or_else(|| host.clone()),
            host,
            hr,
            has_source,
            source_url: r.source_url,
            rt: r.resource_type.bit(),
            method: r.method,
            popup: r.opened_as_popup,
            third: Cell::new(r.third_party),
        })
    }

    fn third_party(&self) -> bool {
        if let Some(t) = self.third.get() {
            return t;
        }
        let t = match (self.has_source, self.source_url) {
            (true, Some(s)) => match (
                adblock::url_parser::parse_url(self.url),
                adblock::url_parser::parse_url(s),
            ) {
                (Some(a), Some(b)) => a.domain() != b.domain(),
                _ => *self.host != *self.src_host,
            },
            _ => false,
        };
        self.third.set(Some(t));
        t
    }

    fn matches(&self, n: &NetMatch) -> bool {
        n.types & self.rt != 0
            && (!n.popup || self.popup)
            && n.method_ok(self.method)
            && n.pat.matches(self.url, self.hr)
            && (n.src.is_unrestricted() || n.src.matches(&self.src_host))
            && ((n.to.is_unrestricted() && n.deny.is_empty()) || n.host_ok(&self.host))
            && match n.party {
                Party::Any => true,
                Party::Third => self.third_party(),
                Party::First => !self.third_party(),
            }
    }
}

/// Immutable, shareable index of extended rules.
pub struct ExtIndex {
    rules: Vec<ParsedRule>,
    req: NetIdx,
    resp: NetIdx,
    dom: DomIdx,
    present: u32,
    needs_req_headers: bool,
    stats: ExtStats,
    /// Fate of every input rule, in input order.
    states: Vec<RuleState>,
}

impl std::fmt::Debug for ExtIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtIndex")
            .field("rules", &self.rules.len())
            .finish()
    }
}

impl ExtIndex {
    /// Build with default options (trust only from [`ExtRule::trusted`]).
    pub fn build(rules: &[ExtRule]) -> Self {
        Self::build_with(rules, &BuildOptions::default())
    }

    pub fn build_with(rules: &[ExtRule], opts: &BuildOptions) -> Self {
        let mut stats = ExtStats {
            total: rules.len(),
            ..Default::default()
        };
        let mut parsed: Vec<(usize, ParsedRule)> = Vec::with_capacity(rules.len());
        let mut states: Vec<RuleState> = vec![RuleState::Active; rules.len()];
        for (ri, r) in rules.iter().enumerate() {
            let k = stats
                .per_kind
                .entry(r.kind.as_str().to_string())
                .or_default();
            match parse_rule(r) {
                Ok(mut p) => {
                    k.parsed += 1;
                    if opts.trusted_lists.contains(&p.list) {
                        p.trusted = true;
                    }
                    parsed.push((ri, p));
                }
                Err(e) => {
                    let unsupported = matches!(e, RuleError::Unsupported(_));
                    states[ri] = if unsupported {
                        RuleState::Unsupported(e.reason().to_string())
                    } else {
                        RuleState::Invalid(e.reason().to_string())
                    };
                    if unsupported {
                        k.unsupported += 1
                    } else {
                        k.parse_errors += 1
                    }
                    if stats.issues.len() < opts.max_issues {
                        stats.issues.push(RuleIssue {
                            kind: r.kind.as_str().into(),
                            list: r.list.clone(),
                            raw: r.raw.clone(),
                            reason: e.reason().to_string(),
                            unsupported,
                        });
                    } else {
                        stats.issues_truncated += 1;
                    }
                }
            }
        }
        let bad: HashSet<String> = parsed
            .iter()
            .filter(|(_, p)| p.badfilter)
            .map(|(_, p)| p.key.clone())
            .collect();
        let mut idx = ExtIndex {
            rules: Vec::new(),
            req: NetIdx::default(),
            resp: NetIdx::default(),
            dom: DomIdx::default(),
            present: 0,
            needs_req_headers: false,
            stats: ExtStats::default(),
            states: Vec::new(),
        };
        for (ri, p) in parsed {
            let k = stats
                .per_kind
                .get_mut(p.src_kind.as_str())
                .expect("counted above");
            if p.badfilter {
                states[ri] = RuleState::Badfilter;
                continue;
            }
            if bad.contains(&p.key) {
                states[ri] = RuleState::Badfiltered;
                k.badfiltered += 1;
                continue;
            }
            if needs_trust(&p) && !p.trusted {
                k.dropped_untrusted += 1;
                *stats
                    .dropped_untrusted_by_list
                    .entry(p.list.clone())
                    .or_default() += 1;
                states[ri] = RuleState::DroppedUntrusted;
                continue;
            }
            k.active += 1;
            idx.insert(p);
        }
        idx.stats = stats;
        idx.states = states;
        idx
    }

    fn insert(&mut self, p: ParsedRule) {
        let id = self.rules.len() as u32;
        self.present |= p.target_mask();
        if let Some(n) = &p.net {
            if p.stage & crate::parse::STAGE_REQ != 0 {
                self.req.add(id, n);
                if matches!(p.action, Action::Cookie(_))
                    || matches!(p.action, Action::RemoveHeader { request: true, .. })
                {
                    self.needs_req_headers = true;
                }
            }
            if p.stage & crate::parse::STAGE_RESP != 0 {
                self.resp.add(id, n);
            }
        } else if let Some(d) = &p.dom {
            self.dom.len += 1;
            match d.bucket_keys() {
                Some(keys) => keys
                    .into_iter()
                    .for_each(|k| self.dom.by_dom.entry(k.into()).or_default().push(id)),
                None => self.dom.generic.push(id),
            }
        }
        self.rules.push(p);
    }

    /// No active rules at all: callers can skip every evaluation.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
    /// Any rule that [`Self::request_decision`] could act on?
    pub fn has_request_rules(&self) -> bool {
        self.req.len > 0
    }
    /// Any rule that [`Self::response_plan`] could act on?
    pub fn has_response_rules(&self) -> bool {
        self.resp.len > 0 || self.dom.len > 0
    }
    /// Any HTML-removal / injection rule?
    pub fn has_html_rules(&self) -> bool {
        self.dom.len > 0
    }
    /// Union of [`target`] bits present among active rules.
    pub fn kinds_present(&self) -> u32 {
        self.present
    }
    /// Does any request-side rule read request headers (cookie / removeheader)?
    pub fn needs_request_headers(&self) -> bool {
        self.needs_req_headers
    }
    pub fn len(&self) -> usize {
        self.rules.len()
    }
    /// Fate of the `i`-th rule handed to [`Self::build_with`].
    pub fn state_of(&self, i: usize) -> Option<&RuleState> {
        self.states.get(i)
    }
    pub fn stats(&self) -> &ExtStats {
        &self.stats
    }
    pub fn rule(&self, id: RuleId) -> Option<&ParsedRule> {
        self.rules.get(id as usize)
    }

    fn net_ids(&self, idx: &NetIdx, ctx: &Ctx<'_>) -> Vec<u32> {
        let mut out: Vec<u32> = Vec::new();
        if idx.len == 0 {
            return out;
        }
        idx.candidates(ctx, |i| {
            if let Some(n) = &self.rules[i as usize].net {
                if ctx.matches(n) && !out.contains(&i) {
                    out.push(i);
                }
            }
        });
        out.sort_unstable();
        out
    }

    fn dom_ids(&self, host: &str) -> Vec<u32> {
        let mut out: Vec<u32> = Vec::new();
        if self.dom.len == 0 {
            return out;
        }
        let mut check = |i: u32| {
            if self.rules[i as usize]
                .dom
                .as_ref()
                .is_some_and(|d| d.matches(host))
                && !out.contains(&i)
            {
                out.push(i)
            }
        };
        for s in suffixes(host) {
            if let Some(v) = self.dom.by_dom.get(s) {
                v.iter().for_each(|&i| check(i));
            }
        }
        self.dom.generic.iter().for_each(|&i| check(i));
        out.sort_unstable();
        out
    }

    /// Positive rules in `ids` covered by `mask` and not disabled by an exception in `ids`.
    fn survivors(&self, ids: &[u32], mask: u32) -> Vec<u32> {
        ids.iter()
            .copied()
            .filter(|&i| {
                let r = &self.rules[i as usize];
                if r.exception || r.target_mask() & mask == 0 {
                    return false;
                }
                !ids.iter().any(|&j| {
                    let e = &self.rules[j as usize];
                    e.exception
                        && e.target_mask() & r.target_mask() != 0
                        && (e.value.is_empty() || e.value == r.value)
                        && (!r.important || e.important)
                })
            })
            .collect()
    }

    /// Extra network verdict for a request. Pure; allocation-free when no rule matches.
    pub fn request_decision(&self, req: &RequestInfo<'_>) -> RequestDecision {
        let mut d = RequestDecision::default();
        if self.req.len == 0 {
            return d;
        }
        let Some(ctx) = Ctx::new(req) else { return d };
        let ids = self.net_ids(&self.req, &ctx);
        if ids.is_empty() {
            return d;
        }
        let live = self.survivors(
            &ids,
            target::BLOCK | target::URLTRANSFORM | target::COOKIE | target::REMOVEHEADER,
        );
        let mut cur: Cow<'_, str> = Cow::Borrowed(req.url);
        let mut cookies: Vec<&CookieSpec> = Vec::new();
        for id in live {
            match &self.rules[id as usize].action {
                Action::Block => {
                    d.block.get_or_insert(id);
                }
                Action::UrlTransform(spec) => {
                    if let Some(n) = transform_url(&cur, spec) {
                        d.rewrite_url = Some((n.clone(), id));
                        cur = Cow::Owned(n);
                    }
                }
                Action::Cookie(c) if !c.modifies() => cookies.push(c),
                Action::RemoveHeader {
                    name,
                    request: true,
                } => {
                    d.header_edits.push(HeaderEdit::Remove(name.clone()));
                }
                _ => continue,
            }
            d.matched.push(id);
        }
        if !cookies.is_empty() {
            let joined: Vec<&str> = req
                .headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case("cookie"))
                .map(|(_, v)| *v)
                .collect();
            if !joined.is_empty() {
                if let Some(new) = filter_request_cookie(&joined.join("; "), &cookies) {
                    d.header_edits.push(if new.is_empty() {
                        HeaderEdit::Remove("cookie".into())
                    } else {
                        HeaderEdit::SetAll("cookie".into(), vec![new])
                    });
                }
            }
        }
        d
    }

    /// The body transforms among `ids` (rule ids from [`ResponsePlan::matched`]), grouped like
    /// [`Self::response_plan`] groups them, so a caller can keep owned ids instead of borrows.
    pub fn body_transforms_for(&self, ids: &[RuleId]) -> Vec<BodyTransform<'_>> {
        let mut out: Vec<BodyTransform<'_>> = Vec::new();
        for &id in ids {
            let Some(r) = self.rules.get(id as usize) else {
                continue;
            };
            match &r.action {
                Action::Replace(s) => out.push(BodyTransform::Replace(s)),
                Action::JsonPrune(s) => match out.iter_mut().find_map(|t| match t {
                    BodyTransform::JsonPrune(v) => Some(v),
                    _ => None,
                }) {
                    Some(v) => v.push(s),
                    None => out.push(BodyTransform::JsonPrune(vec![s])),
                },
                Action::XmlPrune(s) => match out.iter_mut().find_map(|t| match t {
                    BodyTransform::XmlPrune(v) => Some(v),
                    _ => None,
                }) {
                    Some(v) => v.push(s),
                    None => out.push(BodyTransform::XmlPrune(vec![s])),
                },
                Action::Hls(s) => match out.iter_mut().find_map(|t| match t {
                    BodyTransform::Hls(v) => Some(v),
                    _ => None,
                }) {
                    Some(v) => v.push(s),
                    None => out.push(BodyTransform::Hls(vec![s])),
                },
                _ => {}
            }
        }
        out
    }

    /// Is `id` a body-rewriting rule (`$replace`, `$jsonprune`, `$xmlprune`, `$hls`)?
    pub fn is_body_rule(&self, id: RuleId) -> bool {
        self.rules.get(id as usize).is_some_and(|r| {
            matches!(
                r.action,
                Action::Replace(_) | Action::JsonPrune(_) | Action::XmlPrune(_) | Action::Hls(_)
            )
        })
    }

    /// Everything to do to a response. Compute once per response.
    pub fn response_plan<'a>(
        &'a self,
        req: &RequestInfo<'_>,
        resp: &ResponseInfo<'_>,
    ) -> ResponsePlan<'a> {
        let mut plan = ResponsePlan::default();
        if !self.has_response_rules() {
            return plan;
        }
        let Some(ctx) = Ctx::new(req) else {
            return plan;
        };
        let mime_raw = resp
            .content_type()
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let is_doc = matches!(
            req.resource_type,
            ResourceType::Document | ResourceType::Subdocument
        );
        let is_html = is_doc
            && (mime_raw.eq_ignore_ascii_case("text/html")
                || mime_raw.eq_ignore_ascii_case("application/xhtml+xml"));
        let mut ids = self.net_ids(&self.resp, &ctx);
        if is_html {
            ids.extend(self.dom_ids(&ctx.host));
        }
        if ids.is_empty() {
            return plan;
        }
        let mime = mime_raw.to_ascii_lowercase();
        let live = self.survivors(&ids, target::ALL);
        let clen = resp.content_length();
        let mut set_cookies: Vec<&CookieSpec> = Vec::new();
        let (mut perm_restrict, mut perm_trusted): (Vec<&str>, Vec<&str>) =
            (Vec::new(), Vec::new());
        for id in live {
            let r = &self.rules[id as usize];
            let mut used = true;
            match &r.action {
                Action::Header(h) => {
                    if h.matches(resp.headers) {
                        plan.block.get_or_insert(id);
                    } else {
                        used = false
                    }
                }
                Action::RemoveHeader {
                    name,
                    request: false,
                } => plan.header_edits.push(HeaderEdit::Remove(name.clone())),
                Action::Cookie(c) => set_cookies.push(c),
                Action::Permissions(v) if is_doc => {
                    if r.trusted && !crate::permissions::is_restrictive(v) {
                        perm_trusted.push(v)
                    } else {
                        perm_restrict.push(v)
                    }
                }
                Action::Replace(s)
                    if is_textual_content_type(&mime)
                        && fits(clen, crate::replace::MAX_REPLACE_BYTES) =>
                {
                    plan.body.push(BodyTransform::Replace(s))
                }
                Action::JsonPrune(s)
                    if mime.contains("json") && fits(clen, crate::jsonprune::MAX_JSON_BYTES) =>
                {
                    match plan.body.iter_mut().find_map(|t| {
                        if let BodyTransform::JsonPrune(v) = t {
                            Some(v)
                        } else {
                            None
                        }
                    }) {
                        Some(v) => v.push(s),
                        None => plan.body.push(BodyTransform::JsonPrune(vec![s])),
                    }
                }
                Action::XmlPrune(s)
                    if mime.contains("xml") && fits(clen, crate::xmlprune::MAX_XML_BYTES) =>
                {
                    match plan.body.iter_mut().find_map(|t| {
                        if let BodyTransform::XmlPrune(v) = t {
                            Some(v)
                        } else {
                            None
                        }
                    }) {
                        Some(v) => v.push(s),
                        None => plan.body.push(BodyTransform::XmlPrune(vec![s])),
                    }
                }
                Action::Hls(s)
                    if mime.contains("mpegurl") && fits(clen, crate::hls::MAX_HLS_BYTES) =>
                {
                    match plan.body.iter_mut().find_map(|t| {
                        if let BodyTransform::Hls(v) = t {
                            Some(v)
                        } else {
                            None
                        }
                    }) {
                        Some(v) => v.push(s),
                        None => plan.body.push(BodyTransform::Hls(vec![s])),
                    }
                }
                Action::HtmlRemove(h) => plan.html_removals.push(h),
                Action::Inject(i) => {
                    if !plan.injections.contains(&i) {
                        plan.injections.push(i)
                    }
                }
                _ => used = false,
            }
            if used {
                plan.matched.push(id);
            }
        }
        if !perm_restrict.is_empty() || !perm_trusted.is_empty() {
            let site: Vec<&str> = resp
                .headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case("permissions-policy"))
                .map(|(_, v)| *v)
                .collect();
            plan.header_edits.push(HeaderEdit::SetAll(
                "permissions-policy".into(),
                vec![crate::permissions::merge(
                    &site,
                    &perm_restrict,
                    &perm_trusted,
                )],
            ));
        }
        if !set_cookies.is_empty() {
            let old: Vec<&str> = resp
                .headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie"))
                .map(|(_, v)| *v)
                .collect();
            let mut changed = false;
            let mut new: Vec<String> = Vec::with_capacity(old.len());
            for line in old {
                match apply_set_cookie(line, &set_cookies) {
                    SetCookie::Keep => new.push(line.to_string()),
                    SetCookie::Remove => changed = true,
                    SetCookie::Replace(s) => {
                        changed = true;
                        new.push(s)
                    }
                }
            }
            if changed {
                plan.header_edits
                    .push(HeaderEdit::SetAll("set-cookie".into(), new));
            }
        }
        plan.requires_decoded_body = !plan.body.is_empty() && resp.is_encoded();
        plan
    }

    /// Test hook: ids matching a request, via the index or by scanning every rule. Both must agree.
    #[doc(hidden)]
    pub fn debug_net_matches(
        &self,
        req: &RequestInfo<'_>,
        response_stage: bool,
        indexed: bool,
    ) -> Vec<RuleId> {
        let Some(ctx) = Ctx::new(req) else {
            return vec![];
        };
        let (idx, bit) = if response_stage {
            (&self.resp, crate::parse::STAGE_RESP)
        } else {
            (&self.req, crate::parse::STAGE_REQ)
        };
        if indexed {
            return self.net_ids(idx, &ctx);
        }
        (0..self.rules.len() as u32)
            .filter(|&i| {
                let r = &self.rules[i as usize];
                r.stage & bit != 0 && r.net.as_ref().is_some_and(|n| ctx.matches(n))
            })
            .collect()
    }

    /// Test hook: cosmetic-rule ids matching a page host, indexed or by scan.
    #[doc(hidden)]
    pub fn debug_dom_matches(&self, host: &str, indexed: bool) -> Vec<RuleId> {
        if indexed {
            return self.dom_ids(host);
        }
        (0..self.rules.len() as u32)
            .filter(|&i| {
                self.rules[i as usize]
                    .dom
                    .as_ref()
                    .is_some_and(|d| d.matches(host))
            })
            .collect()
    }
}

fn fits(len: Option<u64>, cap: usize) -> bool {
    len.is_none_or(|l| l <= cap as u64)
}

/// `$urltransform`: rewrite path+query only (uBO "urltransform="); the result must stay an
/// absolute path on the same origin and contain no control characters or whitespace.
fn transform_url(url: &str, spec: &crate::replace::ReplaceSpec) -> Option<String> {
    let (_, e) = host_range(url)?;
    let rest_start = url[e..].find(['/', '?', '#']).map_or(url.len(), |p| e + p);
    let (origin, rest) = url.split_at(rest_start);
    let rest = if rest.is_empty() { "/" } else { rest };
    let new = spec.apply_str(rest);
    if new == rest
        || !new.starts_with('/')
        || new.starts_with("//")
        || new.bytes().any(|c| c <= b' ' || c == 0x7f)
    {
        return None;
    }
    Some(format!("{origin}{new}"))
}

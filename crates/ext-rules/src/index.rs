//! The immutable rule index and the request / response evaluators.
//!
//! Precedence (per behaviour, see each modifier's docs): among the rules that match a request, a
//! rule is switched off by a matching exception (`@@`) whose [`target`] mask covers it and whose
//! value is empty (disable all) or equal to the rule's value, unless the rule is `$important` and
//! the exception is not. `$badfilter` removes the identical rule (any list) at build time.

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

use filter_engine::formats::ExtRule;
use serde::{Deserialize, Serialize};

use crate::cookie::{
    apply_set_cookie_traced, filter_request_cookie, removed_request_cookies, CookieSpec, SetCookie,
};
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
    /// Style blocks refused because they could load resources (counted in `parse_errors` too).
    #[serde(default)]
    pub rejected_unsafe_style: usize,
    /// Switched off by a `$badfilter` rule.
    pub badfiltered: usize,
    /// Parsed and matchable, but nothing in the proxy applies the verdict yet (not in `active`).
    #[serde(default)]
    pub not_enforced: usize,
    /// Meaningless for a proxy (`$popunder`).
    #[serde(default)]
    pub not_applicable: usize,
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
    /// Parsed and matched by this index, but the proxy has no hook that applies the verdict yet.
    NotEnforced(String),
    /// Well-formed but meaningless for a proxy (not an error).
    NotApplicable(String),
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
            Self::NotEnforced(_) => "not_enforced",
            Self::NotApplicable(_) => "not_applicable",
        }
    }
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Unsupported(r)
            | Self::Invalid(r)
            | Self::NotEnforced(r)
            | Self::NotApplicable(r) => Some(r),
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
    // Scriptlets are gated where they are resolved, by the resource's own trust requirement
    // (the rule's `trusted` flag travels with the injection); never by name, aliases exist.
    !r.exception
        && matches!(
            r.action,
            Action::Replace(_)
                | Action::UrlTransform(_)
                | Action::Inject(Injection::Script(_) | Injection::Snippet(_))
        )
}

/// Why a parsed rule is matched here but not yet applied by the proxy (`None`: enforced). One
/// place to flip when the proxy hook for a feature lands.
fn not_enforced(r: &ParsedRule) -> Option<&'static str> {
    let mask = r.target_mask();
    if mask & target::URLSKIP != 0 {
        return Some("urlskip is matched (ExtIndex::urlskip_target) but the proxy does not redirect navigations yet");
    }
    if mask & target::REDIRECT != 0 {
        return Some("redirect is matched (RequestDecision::redirect) but the proxy does not serve redirect resources for extended rules yet");
    }
    if r.net.as_ref().is_some_and(|n| n.ip.is_some()) {
        return Some("ipaddress is matched (ExtIndex::ip_decision) but the proxy does not check the resolved upstream address yet");
    }
    if r.net.as_ref().is_some_and(|n| n.cname) {
        return Some("cname is matched (ExtIndex::cname_decision) but the proxy does not resolve CNAME chains for extended rules yet");
    }
    if r.exception && mask & target::GENERICBLOCK != 0 {
        return Some("$genericblock has no effect yet; the main engine's generic network rules are not switched off");
    }
    if r.exception && mask & target::GENERICHIDE != 0 {
        return Some("$generichide: only extended generic cosmetics are suppressed; the main engine's generic hiding is not affected yet");
    }
    None
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
    /// Resolved upstream address, when the caller knows it (`$ipaddress`).
    ip: Option<IpAddr>,
    /// Evaluating a CNAME-uncloaked request: only `$cname` rules apply (and only then).
    cname: bool,
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
            ip: None,
            cname: false,
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
            && n.cname == self.cname
            && n.ip
                .as_ref()
                .is_none_or(|c| self.ip.is_some_and(|ip| c.matches(ip)))
            && (!n.popup || self.popup)
            && n.method_ok(self.method)
            && n.pat.matches(self.url, self.hr)
            && (n.src.is_unrestricted() || n.src.matches(&self.src_host))
            && ((n.to.is_unrestricted() && n.deny.is_empty()) || n.host_ok(&self.host))
            && match n.party {
                Party::Any => true,
                Party::Third => self.third_party(),
                Party::First => !self.third_party(),
                Party::StrictFirst => self.host == self.src_host,
                Party::StrictThird => self.has_source && self.host != self.src_host,
            }
    }
}

/// Verdict of [`ExtIndex::cname_decision`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CnameDecision {
    /// A `$cname` blocking rule applies to the uncloaked request.
    pub block: Option<RuleId>,
    /// An `@@...$cname` exception covers the uncloaked request.
    pub exempt: Option<RuleId>,
}

/// Immutable, shareable index of extended rules.
pub struct ExtIndex {
    rules: Vec<ParsedRule>,
    req: NetIdx,
    resp: NetIdx,
    dom: DomIdx,
    present: u32,
    /// Active rules with an `$ipaddress` / `$cname` condition.
    ip_rules: usize,
    cname_rules: usize,
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
                Err(RuleError::NotApplicable(why)) => {
                    k.not_applicable += 1;
                    states[ri] = RuleState::NotApplicable(why);
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
                    if matches!(e, RuleError::Unsafe(_)) {
                        k.rejected_unsafe_style += 1
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
            ip_rules: 0,
            cname_rules: 0,
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
            if let Some(why) = not_enforced(&p) {
                k.not_enforced += 1;
                states[ri] = RuleState::NotEnforced(why.to_string());
            } else {
                k.active += 1;
            }
            let mut p = p;
            if let Action::Cookie(c) = &mut p.action {
                c.trusted = p.trusted;
            }
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
            self.ip_rules += n.ip.is_some() as usize;
            self.cname_rules += n.cname as usize;
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
            let (keys, generic) = d.bucket_plan();
            keys.into_iter()
                .for_each(|k| self.dom.by_dom.entry(k.into()).or_default().push(id));
            if generic {
                self.dom.generic.push(id);
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

    /// Page-scoped rules (cosmetics, scriptlets, HTML filters) that apply to the document at
    /// `host` with `pq` as its path plus query.
    fn dom_ids(&self, host: &str, pq: &str) -> Vec<u32> {
        let mut out: Vec<u32> = Vec::new();
        if self.dom.len == 0 {
            return out;
        }
        let mut check = |i: u32| {
            if self.rules[i as usize].applies_to_page(host, pq) && !out.contains(&i) {
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

    /// Stealth options turned off for a request by `$stealth` exceptions (a [`crate::stealth`]
    /// bit set; 0 when none match). Judged like any network rule: the request's URL and type, and
    /// `$domain=` against the page that issued it.
    pub fn stealth_off(&self, req: &RequestInfo<'_>) -> u32 {
        if self.present & target::STEALTH == 0 || self.req.len == 0 {
            return 0;
        }
        let Some(ctx) = Ctx::new(req) else { return 0 };
        self.net_ids(&self.req, &ctx)
            .into_iter()
            .map(|i| &self.rules[i as usize])
            .filter(|r| r.exception && r.target_mask() & target::STEALTH != 0)
            .fold(0, |m, r| {
                m | crate::stealth::parse_value(&r.value).unwrap_or(0)
            })
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
            target::BLOCK
                | target::URLTRANSFORM
                | target::COOKIE
                | target::REMOVEHEADER
                | target::REMOVEPARAM
                | target::REDIRECT,
        );
        let mut cur: Cow<'_, str> = Cow::Borrowed(req.url);
        // `$removeparam` first (so `$urltransform` sees the cleaned URL); all rules in one pass.
        let rp: Vec<(u32, &crate::RemoveParam)> = live
            .iter()
            .filter_map(|&id| match &self.rules[id as usize].action {
                Action::RemoveParam(s) => Some((id, s)),
                _ => None,
            })
            .collect();
        if !rp.is_empty() {
            let specs: Vec<&crate::RemoveParam> = rp.iter().map(|(_, s)| *s).collect();
            if let Some(n) = crate::removeparam::apply(&cur, &specs) {
                d.cleaned_url = Some((n.clone(), rp[0].0));
                d.rewrite_url = Some((n.clone(), rp[0].0));
                d.matched.extend(rp.iter().map(|(i, _)| *i));
                cur = Cow::Owned(n);
            }
        }
        let mut cookies: Vec<&CookieSpec> = Vec::new();
        let mut cookie_ids: Vec<u32> = Vec::new();
        for id in live {
            match &self.rules[id as usize].action {
                Action::Block => {
                    d.block.get_or_insert(id);
                }
                Action::Redirect {
                    resource,
                    rule_only,
                } => {
                    let slot = if *rule_only {
                        &mut d.redirect_rule
                    } else {
                        &mut d.redirect
                    };
                    slot.get_or_insert((resource.clone(), id));
                }
                Action::UrlTransform(spec) => {
                    if let Some(n) = transform_url(&cur, spec) {
                        d.rewrite_url = Some((n.clone(), id));
                        cur = Cow::Owned(n);
                    }
                }
                Action::Cookie(c) if !c.modifies() => {
                    cookies.push(c);
                    if req.want_cookie_drops {
                        cookie_ids.push(id);
                    }
                }
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
                let joined = joined.join("; ");
                if let Some(new) = filter_request_cookie(&joined, &cookies) {
                    if req.want_cookie_drops {
                        d.cookie_drops = removed_request_cookies(&joined, &cookies)
                            .into_iter()
                            .map(|(n, i)| (n, cookie_ids[i]))
                            .collect();
                    }
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

    /// Destination of a `$urlskip=` redirector URL for a navigation `req`: the extracted URL and
    /// the rule. `None` when no live rule matches or every matching rule's steps fail. The caller
    /// performs the navigation redirect. `blocked` says another rule blocks the request (only
    /// `-blocked` rules then apply).
    pub fn urlskip_target(&self, req: &RequestInfo<'_>, blocked: bool) -> Option<(String, RuleId)> {
        if self.present & target::URLSKIP == 0 {
            return None;
        }
        let ctx = Ctx::new(req)?;
        let ids = self.net_ids(&self.req, &ctx);
        self.survivors(&ids, target::URLSKIP)
            .into_iter()
            .find_map(|id| match &self.rules[id as usize].action {
                Action::UrlSkip(u) if !blocked || u.allow_blocked => {
                    u.apply(req.url).map(|t| (t, id))
                }
                _ => None,
            })
    }

    /// `$ipaddress=` verdict once the upstream address of `req` is known: the blocking rule, if
    /// a live rule with an address condition matches `ip` and no exception covers it.
    pub fn ip_decision(&self, req: &RequestInfo<'_>, ip: IpAddr) -> Option<RuleId> {
        if self.ip_rules == 0 {
            return None;
        }
        let mut ctx = Ctx::new(req)?;
        ctx.ip = Some(ip);
        let ids = self.net_ids(&self.req, &ctx);
        self.survivors(&ids, target::BLOCK).into_iter().find(|&i| {
            let r = &self.rules[i as usize];
            matches!(r.action, Action::Block) && r.net.as_ref().is_some_and(|n| n.ip.is_some())
        })
    }

    /// `$cname` verdict for a request whose host CNAME-resolves to `cname_host`: the pattern is
    /// matched against `req.url` with its host replaced. `block` is a live `$cname` blocking rule;
    /// `exempt` an `@@...$cname` exception that matched (it bypasses blocking of uncloaked
    /// requests, including the network engine's own).
    pub fn cname_decision(&self, req: &RequestInfo<'_>, cname_host: &str) -> CnameDecision {
        let mut out = CnameDecision::default();
        if self.cname_rules == 0 {
            return out;
        }
        let Some((a, b)) = host_range(req.url) else {
            return out;
        };
        let url = format!("{}{}{}", &req.url[..a], cname_host, &req.url[b..]);
        let info = RequestInfo { url: &url, ..*req };
        let Some(mut ctx) = Ctx::new(&info) else {
            return out;
        };
        ctx.cname = true;
        let ids = self.net_ids(&self.req, &ctx);
        out.exempt = ids.iter().copied().find(|&i| {
            let r = &self.rules[i as usize];
            r.exception && r.value.is_empty() && r.target_mask() & target::BLOCK != 0
        });
        out.block = self.survivors(&ids, target::BLOCK).into_iter().next();
        out
    }

    /// What request-side `$removeparam` exceptions matching `req` exempt from the network
    /// engine's own (plain-name) removal: `(all, names)`. `None` when no exception matches.
    pub fn removeparam_exemption(&self, req: &RequestInfo<'_>) -> Option<(bool, Vec<String>)> {
        if self.present & target::REMOVEPARAM == 0 {
            return None;
        }
        let ctx = Ctx::new(req)?;
        let mut out: Option<(bool, Vec<String>)> = None;
        for id in self.net_ids(&self.req, &ctx) {
            let r = &self.rules[id as usize];
            if r.exception && r.target_mask() & target::REMOVEPARAM != 0 {
                let o = out.get_or_insert((false, Vec::new()));
                if r.value.is_empty() {
                    o.0 = true;
                } else {
                    o.1.push(r.value.clone());
                }
            }
        }
        out
    }

    /// Does a bare exception that switches off page-level behaviour (`@@||host^$document`,
    /// `$elemhide`, `$jsinject`) match `req`?
    pub fn page_exempt(&self, req: &RequestInfo<'_>) -> bool {
        let mask = target::PCSS | target::JS;
        if self.present & mask == 0 {
            return false;
        }
        let Some(ctx) = Ctx::new(req) else {
            return false;
        };
        self.net_ids(&self.req, &ctx).into_iter().any(|id| {
            let r = &self.rules[id as usize];
            r.exception && r.value.is_empty() && r.target_mask() & mask != 0
        })
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
        plan.disabled = ids
            .iter()
            .map(|&i| &self.rules[i as usize])
            .filter(|r| r.exception && r.value.is_empty())
            .filter(|r| matches!(r.action, Action::Disable { .. }))
            .fold(0, |m, r| m | r.target_mask());
        if is_html {
            let pq = crate::util::path_and_query(ctx.url);
            ids.extend(self.dom_ids(&ctx.host, &pq));
        }
        if ids.is_empty() {
            return plan;
        }
        let mime = mime_raw.to_ascii_lowercase();
        let mut live = self.survivors(&ids, target::ALL);
        if plan.disabled & target::GENERICHIDE != 0 {
            live.retain(|&i| !self.rules[i as usize].is_generic_cosmetic());
        }
        let clen = resp.content_length();
        let mut set_cookies: Vec<&CookieSpec> = Vec::new();
        let mut set_cookie_ids: Vec<u32> = Vec::new();
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
                Action::Cookie(c) => {
                    set_cookies.push(c);
                    set_cookie_ids.push(id);
                }
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
            for (index, line) in old.into_iter().enumerate() {
                let ap = apply_set_cookie_traced(line, &set_cookies);
                let id = |i: usize| set_cookie_ids[i];
                let touch = |stripped| {
                    let max_age = ap.max_age.map(|(m, i)| (m, id(i)));
                    let same_site = ap.same_site.map(|(s, i)| (s, id(i)));
                    let rule = ap
                        .by
                        .map(id)
                        .or(max_age.map(|x| x.1))
                        .or(same_site.map(|x| x.1))?;
                    Some(crate::types::CookieTouch {
                        index,
                        stripped,
                        rule,
                        max_age,
                        same_site,
                    })
                };
                match ap.action {
                    SetCookie::Keep => new.push(line.to_string()),
                    SetCookie::Remove => {
                        changed = true;
                        plan.cookie_touches.extend(touch(true));
                    }
                    SetCookie::Replace(s) => {
                        changed = true;
                        plan.cookie_touches.extend(touch(false));
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
        self.debug_dom_matches_at(host, "/", indexed)
    }

    /// Like [`Self::debug_dom_matches`] for a document whose path plus query is `pq`.
    #[doc(hidden)]
    pub fn debug_dom_matches_at(&self, host: &str, pq: &str, indexed: bool) -> Vec<RuleId> {
        if indexed {
            return self.dom_ids(host, pq);
        }
        (0..self.rules.len() as u32)
            .filter(|&i| self.rules[i as usize].applies_to_page(host, pq))
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

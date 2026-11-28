//! Per-line inspection of a list: what the build makes of every SOURCE line.
//!
//! [`classify_list`] re-runs, on demand, exactly the transforms [`crate::build_set`] applies to a
//! list (format detection, the `!#if` preprocessor with the list's trust, line conversion, the
//! allowlist exception rewrite, AdGuard redirect stripping, pure-domain routing, deduplication,
//! engine parsing) and keeps the verdict per line instead of per list, so the totals equal the
//! build's [`crate::ListReport`]. Cross-list facts (a rule another list provides first, a host
//! covered by a shorter domain rule) come from the live build ([`Live`]: the rule origins and the
//! domain set); without it the list is judged standalone, as if it were the only list.
//!
//! One source line yields one [`Record`], or several when it emits several rules (`0.0.0.0 a b`)
//! or is a `!#include` (the included rules carry the line of the directive, which also gets its
//! own `comment` record). The extended-rule index lives in a crate above this one, so the caller
//! supplies its verdicts ([`ExtVerdict`]).
//!
//! Known residuals against the build report, all for pure domain rules: the same exact-host
//! (`|https://h^`) rule in two lists with different schemes, which the domain set attributes to
//! one list. A `||host^` rule disabled by a `$badfilter` rule counts as a network rule, as the
//! build counts it.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use adblock::lists::{parse_filter, ParseOptions, ParsedFilter};
use adblock::resources::PermissionMask;
use rayon::prelude::*;

use crate::compile::{route, Route};
use crate::domainset::{exact_key, push_ancestors, suffix_key, DomainSet, Scheme};
use crate::formats::{
    classify_rejected, convert, convert_line, detect, preprocess_trace, ConvertOptions, ExtKind,
    ExtRule, ListFormat, Pre, Rule,
};
use crate::origins::RuleOrigins;
use crate::pipeline::{
    is_adguard_origin, is_host_only_exception, strip_redirects_line, ListInput, STRIPPED_HOST_ONLY,
    STRIPPED_REDIRECT,
};

/// `Record::other` when no other list is involved.
pub const NO_LIST: u16 = u16::MAX;
const NO_EXTRA: u32 = u32::MAX;

/// What a source line is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Blank, header, comment or preprocessor directive.
    Comment,
    /// Inside a branch of an `!#if` that is false.
    Inactive,
    /// A network rule the engine (or the domain set, or the IP matcher) enforces.
    Network,
    Cosmetic,
    /// Handed to the extended-rule index; see [`Record::ext_state`].
    Extended,
    /// The same rule is already provided earlier (see [`Record::other`]).
    Duplicate,
    /// A host rule a shorter domain rule already covers (see [`Record::other`]).
    Covered,
    /// A domain rule a `$badfilter` rule disables.
    Disabled,
    /// Recognised but not expressible, or dropped on purpose.
    Unsupported,
    /// Could not be converted ([`Stage::Conversion`]) or was rejected by the engine
    /// ([`Stage::Compile`]).
    Invalid,
}

/// How an extended rule's state counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtClass {
    /// In effect.
    Applied,
    /// Something is wrong with the rule or the list: it needs a look.
    Problem,
    /// Fine, but not in effect (yet).
    NotApplied,
    /// Not meant to do anything here; never an issue.
    Ignored,
}

/// Every extended-rule state, with how it counts. This table is the one place a new state is
/// added: the report, the line filters and the API read it. A state the table does not know is
/// carried as it is and counts as a [`ExtClass::Problem`].
pub const EXT_STATES: &[(&str, ExtClass)] = &[
    ("enforced", ExtClass::Applied),
    ("unsupported", ExtClass::Problem),
    ("invalid", ExtClass::Problem),
    ("needs_trust", ExtClass::Problem),
    ("not_enforced", ExtClass::NotApplied),
    ("not_applicable", ExtClass::Ignored),
];

/// What the extended-rule index made of an extended rule: a name from [`EXT_STATES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtState(&'static str);

impl ExtState {
    pub const ENFORCED: ExtState = ExtState("enforced");
    pub const UNSUPPORTED: ExtState = ExtState("unsupported");
    pub const INVALID: ExtState = ExtState("invalid");
    pub const NEEDS_TRUST: ExtState = ExtState("needs_trust");

    /// The state called `name`: the table's entry, else the name as given.
    pub fn named(name: &'static str) -> Self {
        Self(
            EXT_STATES
                .iter()
                .find(|(n, _)| *n == name)
                .map_or(name, |(n, _)| n),
        )
    }

    /// The table's state called `name`, if any.
    pub fn from_name(name: &str) -> Option<Self> {
        EXT_STATES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(n, _)| Self(n))
    }

    pub fn as_str(self) -> &'static str {
        self.0
    }

    pub fn class(self) -> ExtClass {
        EXT_STATES
            .iter()
            .find(|(n, _)| *n == self.0)
            .map_or(ExtClass::Problem, |(_, c)| *c)
    }
}

/// The index's verdict on one extended rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtVerdict {
    pub state: ExtState,
    pub reason: Option<String>,
}

impl ExtVerdict {
    pub fn enforced() -> Self {
        Self {
            state: ExtState::ENFORCED,
            reason: None,
        }
    }
}

/// The caller's judge of extended rules: one verdict per rule, in order. The rules carry the
/// list id and its trust.
pub type Judge<'a> = &'a (dyn Fn(&[ExtRule]) -> Vec<ExtVerdict> + Sync);

/// Where an [`Kind::Invalid`] line failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    Conversion,
    Compile,
}

/// The verdict on one rule of one source line (20 bytes: text, reasons and list names live in
/// the [`Classified`] and are shared).
#[derive(Debug, Clone)]
pub struct Record {
    /// 1-based source line.
    pub line: u32,
    extra: u32,
    reason: u32,
    /// The other list ([`Classified::list_name`]) for [`Kind::Duplicate`] / [`Kind::Covered`].
    pub other: u16,
    pub kind: Kind,
    /// 0, or 1 + the index of the state for [`Kind::Extended`] (see [`Record::ext_state`]).
    state: u8,
    /// For [`Kind::Extended`].
    pub ext_kind: Option<ExtKind>,
    /// For [`Kind::Invalid`].
    pub stage: Stage,
    /// A [`Kind::Network`] record that is an IP / CIDR range.
    pub ip: bool,
    /// The rule was rewritten into engine syntax (set on the first rule of a rewritten line).
    pub translated: bool,
}

const NO_REASON: u32 = u32::MAX;

fn state_names() -> &'static std::sync::Mutex<Vec<&'static str>> {
    static R: std::sync::OnceLock<std::sync::Mutex<Vec<&'static str>>> = std::sync::OnceLock::new();
    R.get_or_init(|| std::sync::Mutex::new(EXT_STATES.iter().map(|(n, _)| *n).collect()))
}

fn state_code(s: ExtState) -> u8 {
    let mut v = state_names().lock().unwrap_or_else(|e| e.into_inner());
    let i = match v.iter().position(|n| *n == s.0) {
        Some(i) => i,
        None if v.len() < 250 => {
            v.push(s.0);
            v.len() - 1
        }
        None => 0,
    };
    i as u8 + 1
}

impl Record {
    /// The extended-rule state, for [`Kind::Extended`].
    pub fn ext_state(&self) -> Option<ExtState> {
        let i = self.state.checked_sub(1)? as usize;
        state_names()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(i)
            .map(|n| ExtState(n))
    }
}

/// Typed totals, comparable with the build's [`crate::ListReport`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counts {
    /// Lines of the source text.
    pub lines: usize,
    pub comment: usize,
    pub inactive: usize,
    /// Network rules, not counting IP ranges.
    pub network: usize,
    pub ip_ranges: usize,
    pub cosmetic: usize,
    pub ext_enforced: usize,
    pub ext_unsupported: usize,
    pub ext_invalid: usize,
    pub ext_needs_trust: usize,
    /// Extended rules per state name, every state included.
    pub ext_states: std::collections::BTreeMap<&'static str, usize>,
    pub duplicate: usize,
    pub covered: usize,
    pub disabled: usize,
    pub unsupported: usize,
    pub invalid_conversion: usize,
    pub invalid_compile: usize,
    /// Lines rewritten into engine syntax.
    pub translated: usize,
}

impl Counts {
    /// All extended rules.
    pub fn ext(&self) -> usize {
        self.ext_states.values().sum()
    }
}

/// A filter over [`Record`]s: the status names the API accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Filter {
    Comment,
    Inactive,
    /// Network rules, IP ranges included.
    Network,
    Cosmetic,
    /// Every extended rule.
    Extended,
    Duplicate,
    Covered,
    /// Domain rules a `$badfilter` rule disables.
    Disabled,
    /// Unsupported lines and extended rules in the `unsupported` state.
    Unsupported,
    /// Invalid lines and extended rules in the `invalid` state.
    Invalid,
    /// Extended rules in one state (any [`EXT_STATES`] name other than `unsupported` and
    /// `invalid`, which also cover plain lines).
    State(ExtState),
}

impl Filter {
    /// Every filter, in the order of [`Classified::filter_counts`].
    pub fn all() -> Vec<Filter> {
        let mut v = vec![
            Self::Comment,
            Self::Inactive,
            Self::Network,
            Self::Cosmetic,
            Self::Extended,
            Self::Duplicate,
            Self::Covered,
            Self::Disabled,
            Self::Unsupported,
            Self::Invalid,
        ];
        v.extend(
            EXT_STATES
                .iter()
                .filter(|(n, _)| !matches!(*n, "unsupported" | "invalid"))
                .map(|(n, _)| Self::State(ExtState(n))),
        );
        v
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Comment => "comment",
            Self::Inactive => "inactive",
            Self::Network => "network",
            Self::Cosmetic => "cosmetic",
            Self::Extended => "extended",
            Self::Duplicate => "duplicate",
            Self::Covered => "covered",
            Self::Disabled => "disabled",
            Self::Unsupported => "unsupported",
            Self::Invalid => "invalid",
            Self::State(s) => s.as_str(),
        }
    }

    /// The filters a status name stands for: one of [`Self::as_str`], or the groups `issues`
    /// (every [`Self::is_issue`] filter), `applied` (network, cosmetic and extended rules in
    /// effect) and `ignored` (inactive lines and extended rules that do nothing here on
    /// purpose).
    pub fn parse(name: &str) -> Option<Vec<Filter>> {
        let name = name.trim();
        let group = |keep: fn(&Filter) -> bool| -> Vec<Filter> {
            Self::all().into_iter().filter(keep).collect()
        };
        match name {
            "issues" => Some(group(Filter::is_issue)),
            "applied" => Some(group(Filter::is_applied)),
            "ignored" => Some(group(Filter::is_ignored)),
            _ => Self::all()
                .into_iter()
                .find(|f| f.as_str() == name)
                .map(|f| vec![f]),
        }
    }

    /// Part of the `issues` group: unsupported and invalid lines, extended rules that are
    /// problems or not in effect yet.
    pub fn is_issue(&self) -> bool {
        match self {
            Self::Unsupported | Self::Invalid => true,
            Self::State(s) => matches!(s.class(), ExtClass::Problem | ExtClass::NotApplied),
            _ => false,
        }
    }

    /// Part of the `applied` group.
    pub fn is_applied(&self) -> bool {
        match self {
            Self::Network | Self::Cosmetic => true,
            Self::State(s) => s.class() == ExtClass::Applied,
            _ => false,
        }
    }

    /// Part of the `ignored` group (inactive lines, rules disabled on purpose).
    pub fn is_ignored(&self) -> bool {
        match self {
            Self::Inactive | Self::Disabled => true,
            Self::State(s) => s.class() == ExtClass::Ignored,
            _ => false,
        }
    }

    pub fn matches(self, r: &Record) -> bool {
        let ext = |s: ExtState| r.kind == Kind::Extended && r.ext_state() == Some(s);
        match self {
            Self::Comment => r.kind == Kind::Comment,
            Self::Inactive => r.kind == Kind::Inactive,
            Self::Network => r.kind == Kind::Network,
            Self::Cosmetic => r.kind == Kind::Cosmetic,
            Self::Extended => r.kind == Kind::Extended,
            Self::Duplicate => r.kind == Kind::Duplicate,
            Self::Covered => r.kind == Kind::Covered,
            Self::Disabled => r.kind == Kind::Disabled,
            Self::Unsupported => r.kind == Kind::Unsupported || ext(ExtState::UNSUPPORTED),
            Self::Invalid => r.kind == Kind::Invalid || ext(ExtState::INVALID),
            Self::State(s) => ext(s),
        }
    }
}

/// Whether `r` passes any of `filters` (all pass when empty).
pub fn matches_any(filters: &[Filter], r: &Record) -> bool {
    filters.is_empty() || filters.iter().any(|f| f.matches(r))
}

/// The cross-list facts of the live build.
#[derive(Clone, Copy)]
pub struct Live<'a> {
    pub origins: &'a RuleOrigins,
    pub domains: &'a DomainSet,
}

/// Every source line of a list, classified.
#[derive(Debug)]
pub struct Classified {
    pub id: String,
    /// The format used (detected when the list's override is `auto`).
    pub format: ListFormat,
    /// The list was judged against the live build (otherwise standalone).
    pub in_build: bool,
    /// Digest of the text and includes this was computed from (set by the caller that caches).
    pub digest: String,
    pub records: Vec<Record>,
    pub counts: Counts,
    /// Records matching each [`Filter`], in [`Filter::all`] order.
    pub filter_counts: Vec<usize>,
    /// Records in the `issues`, `applied` and `ignored` groups (see [`Filter::parse`]).
    pub group_counts: [usize; 3],
    names: Vec<String>,
    reasons: Vec<Box<str>>,
    text: Arc<str>,
    starts: Vec<u32>,
    extras: Vec<String>,
}

impl Classified {
    /// The rule as written: the source line, or the included rule.
    pub fn rule(&self, r: &Record) -> &str {
        if r.extra != NO_EXTRA {
            return self.extras.get(r.extra as usize).map_or("", String::as_str);
        }
        self.line_text(r.line as usize)
    }

    /// Source line `n` (1-based), without its line ending and (on line 1) byte-order mark.
    pub fn line_text(&self, n: usize) -> &str {
        let Some(&start) = n.checked_sub(1).and_then(|i| self.starts.get(i)) else {
            return "";
        };
        let end = self.starts.get(n).map_or(self.text.len(), |e| *e as usize);
        let line = self.text[start as usize..end].trim_end_matches(['\n', '\r']);
        if n == 1 {
            line.strip_prefix('\u{feff}').unwrap_or(line)
        } else {
            line
        }
    }

    /// Why, for the records that have a reason.
    pub fn reason(&self, r: &Record) -> Option<&str> {
        self.reasons.get(r.reason as usize).map(|s| &**s)
    }

    /// Id of the list named by [`Record::other`].
    pub fn list_name(&self, other: u16) -> Option<&str> {
        self.names.get(other as usize).map(String::as_str)
    }

    /// Records matching `filter`.
    pub fn count(&self, filter: Filter) -> usize {
        Filter::all()
            .iter()
            .position(|f| *f == filter)
            .map_or(0, |i| self.filter_counts[i])
    }

    /// Heap size held, for cache accounting: records, source text, line offsets, reasons,
    /// included rule texts and list names.
    pub fn approx_bytes(&self) -> usize {
        self.records.capacity() * std::mem::size_of::<Record>()
            + self.text.len()
            + self.starts.capacity() * 4
            + self.extras.iter().map(|e| e.len() + 24).sum::<usize>()
            + self.reasons.iter().map(|r| r.len() + 16).sum::<usize>()
            + self.names.iter().map(|n| n.len() + 24).sum::<usize>()
            + self.filter_counts.len() * 8
    }
}

// ---- stage A: source line -> emitted rules -------------------------------------------------------

/// What one source line (or one rule of it) turned into during conversion.
enum What {
    Comment,
    Inactive,
    /// An emitted rule; `translated` on the first rule of a rewritten line.
    Rule {
        rule: String,
        translated: bool,
    },
    /// An emitted IP range.
    Ip,
    /// Dropped on purpose after conversion (AdGuard stubs).
    Stripped(&'static str),
    Ext(ExtRule),
    Skip(String),
    Invalid(String),
}

struct Item {
    line: u32,
    /// The rule text when it is not the source line (an included rule).
    extra: Option<String>,
    what: What,
}

fn is_in(content: &str, s: &str) -> bool {
    let (c, p) = (content.as_ptr() as usize, s.as_ptr() as usize);
    p >= c && p + s.len() <= c + content.len()
}

/// Fold the AdGuard-origin rewrites into an emitted rule: `None` keeps it (maybe rewritten),
/// `Some(reason)` drops it.
fn strip(adguard: bool, rule: &mut String) -> Option<&'static str> {
    if !adguard {
        return None;
    }
    match strip_redirects_line(rule) {
        None => return Some(STRIPPED_REDIRECT),
        Some(std::borrow::Cow::Owned(l)) => *rule = l,
        Some(std::borrow::Cow::Borrowed(_)) => {}
    }
    is_host_only_exception(rule).then_some(STRIPPED_HOST_ONLY)
}

fn stripped_reason(reason: &str) -> String {
    match reason {
        STRIPPED_REDIRECT => "AdGuard redirect stub, dropped".into(),
        _ => "AdGuard host-only exception, dropped".into(),
    }
}

/// Stage A: the format and the items, in source order.
fn items_of(input: &ListInput, content: &str) -> (ListFormat, Vec<Item>) {
    let format = if input.format == ListFormat::Auto {
        detect(content)
    } else {
        input.format
    };
    let adguard = is_adguard_origin(input);
    if format.is_abp_family() || format == ListFormat::Auto {
        let pre = preprocess_trace(content, &input.includes, input.trusted);
        let items = pre
            .par_iter()
            .flat_map_iter(|&(line, raw, p)| {
                let line = line as u32;
                let extra = (!is_in(content, raw)).then(|| raw.trim().to_string());
                let mut out: Vec<Item> = Vec::new();
                let one = |what| Item {
                    line,
                    extra: extra.clone(),
                    what,
                };
                match p {
                    Pre::Directive => out.push(one(What::Comment)),
                    Pre::Inactive => out.push(one(What::Inactive)),
                    Pre::Active => match convert_line(raw, input.allowlist) {
                        None => out.push(one(What::Comment)),
                        Some(Rule::Error(e)) => out.push(one(What::Invalid(e.to_string()))),
                        Some(Rule::Ext(e)) => out.push(one(What::Ext(e))),
                        Some(Rule::Emit(rules, translated)) => {
                            for (k, mut rule) in rules.into_iter().enumerate() {
                                out.push(one(match strip(adguard, &mut rule) {
                                    Some(r) => What::Stripped(r),
                                    None => What::Rule {
                                        rule,
                                        translated: translated && k == 0,
                                    },
                                }));
                            }
                        }
                    },
                }
                out
            })
            .collect();
        return (format, items);
    }
    let c = convert(
        content,
        &ConvertOptions {
            format,
            allowlist: input.allowlist,
            includes: input.includes.clone(),
            trusted: input.trusted,
            trace: true,
        },
    );
    let mut rules = c.rules.lines();
    let events = c.stats.trace.unwrap_or_default();
    let n_lines = content.lines().count();
    let mut seen = vec![false; n_lines + 2];
    let mut items: Vec<Item> = Vec::with_capacity(events.len() + n_lines);
    for (line, ev) in events {
        let line = line.clamp(1, n_lines.max(1));
        seen[line] = true;
        let what = match ev {
            crate::formats::Ev::Rule => {
                let mut rule = rules.next().unwrap_or("").to_string();
                match strip(adguard, &mut rule) {
                    Some(r) => What::Stripped(r),
                    None => What::Rule {
                        rule,
                        translated: false,
                    },
                }
            }
            crate::formats::Ev::Ip => What::Ip,
            crate::formats::Ev::Skip(r) => What::Skip(r),
            crate::formats::Ev::Error(r) => What::Invalid(r),
        };
        items.push(Item {
            line: line as u32,
            extra: None,
            what,
        });
    }
    for (i, s) in seen.iter().enumerate().take(n_lines + 1).skip(1) {
        if !s {
            items.push(Item {
                line: i as u32,
                extra: None,
                what: What::Comment,
            });
        }
    }
    items.sort_by_key(|i| i.line);
    (format, items)
}

/// For each of the `wanted` converted rules, the first source line that emits it and that line's
/// text. Used to trace compiler rejections back to the source.
pub fn locate(input: &ListInput, wanted: &HashSet<&str>) -> HashMap<String, (usize, String)> {
    let content = input
        .content
        .strip_prefix('\u{feff}')
        .unwrap_or(&input.content);
    let (_, items) = items_of(input, content);
    let lines: Vec<&str> = content.lines().collect();
    let mut found = HashMap::new();
    for it in items {
        if let What::Rule { rule, .. } = &it.what {
            if wanted.contains(rule.trim()) && !found.contains_key(rule.trim()) {
                let text = it.extra.clone().unwrap_or_else(|| {
                    lines
                        .get(it.line as usize - 1)
                        .map_or("", |l| l.trim())
                        .to_string()
                });
                found.insert(rule.trim().to_string(), (it.line as usize, text));
            }
        }
    }
    found
}

// ---- stage B: the engine's verdict on a rule ---------------------------------------------------------

enum Parsed {
    Network,
    Cosmetic,
    Ext(ExtRule),
    Invalid(String),
}

fn parse_rule(rule: &str, trusted: bool) -> Parsed {
    let opts = ParseOptions {
        permissions: if trusted {
            crate::scriptlet_resources::TRUSTED_PERMISSION
        } else {
            PermissionMask::default()
        },
        ..Default::default()
    };
    match parse_filter(rule, true, opts) {
        Ok(ParsedFilter::Network(_)) => Parsed::Network,
        Ok(ParsedFilter::Cosmetic(_)) => Parsed::Cosmetic,
        // An empty rule never reaches the build's parser either.
        Err(adblock::lists::FilterParseError::Empty) => Parsed::Network,
        Err(e) => match classify_rejected(rule) {
            Some(x) => Parsed::Ext(x),
            None => Parsed::Invalid(e.to_string()),
        },
    }
}

/// Parallel part of a rule's verdict: the engine path's origin and parse result.
struct Engine {
    /// The list that owns the rule in the live build.
    origin: Option<u16>,
    parsed: Option<Parsed>,
}

fn line_hash(s: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

// ---- classification -----------------------------------------------------------------------------

fn record(line: u32, kind: Kind) -> Record {
    Record {
        line,
        kind,
        state: 0,
        ext_kind: None,
        stage: Stage::Conversion,
        ip: false,
        translated: false,
        other: NO_LIST,
        extra: NO_EXTRA,
        reason: NO_REASON,
    }
}

/// Classify every line of `input`. With `live` the list is judged inside the live build (it must
/// be one of the build's lists and `input` must be what was built); otherwise standalone.
pub fn classify_list(input: &ListInput, live: Option<Live<'_>>, judge: Judge<'_>) -> Classified {
    let live = live.filter(|l| l.origins.ids().contains(&input.id));
    let content = input
        .content
        .strip_prefix('\u{feff}')
        .unwrap_or(&input.content);
    let me: u16 = live
        .and_then(|l| l.origins.ids().iter().position(|i| *i == input.id))
        .map_or(0, |p| p as u16);
    let names: Vec<String> = match live {
        Some(l) => l.origins.ids().to_vec(),
        None => vec![input.id.clone()],
    };
    let (format, mut items) = items_of(input, content);

    // Stage B (parallel): engine-path rules, judged against the owner and the parser.
    let engine: Vec<Option<Engine>> = items
        .par_iter()
        .map(|it| {
            let What::Rule { rule, .. } = &it.what else {
                return None;
            };
            let t = rule.trim();
            if !matches!(route(t), Route::Engine) {
                return None;
            }
            let origin = live.and_then(|l| l.origins.lookup_index(t));
            let parsed = match origin {
                Some(o) if o != me => None,
                _ => Some(parse_rule(t, input.trusted)),
            };
            Some(Engine { origin, parsed })
        })
        .collect();

    // Standalone domain rules: which hosts the list itself provides.
    let (mut present, mut removed): (HashSet<u64>, HashSet<(u64, u8)>) = Default::default();
    if live.is_none() {
        for it in &items {
            if let What::Rule { rule, .. } = &it.what {
                match route(rule.trim()) {
                    Route::Suffix(h) => {
                        present.insert(suffix_key(h));
                    }
                    Route::BadSuffix(h) => {
                        removed.insert((suffix_key(h), 0));
                    }
                    Route::BadExact(s, h) => {
                        removed.insert((exact_key(h), s.bit()));
                    }
                    _ => {}
                }
            }
        }
        // `present` holds the rules a `$badfilter` has not disabled.
        present.retain(|k| !removed.contains(&(*k, 0)));
    }

    // Stage C (sequential, in source order): cross-rule facts.
    let mut records: Vec<Record> = Vec::with_capacity(items.len());
    let mut extras: Vec<String> = Vec::new();
    let mut counts = Counts {
        lines: content.lines().count(),
        ..Default::default()
    };
    let mut reasons: Vec<Box<str>> = Vec::new();
    let mut reason_ids: HashMap<Box<str>, u32> = HashMap::new();
    let mut intern = |s: &str| -> u32 {
        if let Some(i) = reason_ids.get(s) {
            return *i;
        }
        let i = reasons.len() as u32;
        reasons.push(s.into());
        reason_ids.insert(s.into(), i);
        i
    };
    let mut seen_engine: HashSet<u64> = HashSet::new();
    let mut seen_dom: HashSet<(u64, u8)> = HashSet::new();
    let mut ext_rules: Vec<ExtRule> = Vec::new();
    // Index of the record each pending extended rule belongs to.
    let mut ext_at: Vec<usize> = Vec::new();
    for (it, eng) in items.iter_mut().zip(engine) {
        let mut r = record(it.line, Kind::Comment);
        if let Some(x) = it.extra.take() {
            r.extra = extras.len() as u32;
            extras.push(x);
        }
        match std::mem::replace(&mut it.what, What::Comment) {
            What::Comment => counts.comment += 1,
            What::Inactive => {
                r.kind = Kind::Inactive;
                counts.inactive += 1;
            }
            What::Skip(reason) => {
                r.kind = Kind::Unsupported;
                r.reason = intern(&reason);
                counts.unsupported += 1;
            }
            What::Stripped(reason) => {
                r.kind = Kind::Unsupported;
                r.reason = intern(&stripped_reason(reason));
                counts.unsupported += 1;
            }
            What::Invalid(reason) => {
                r.kind = Kind::Invalid;
                r.stage = Stage::Conversion;
                r.reason = intern(&reason);
                counts.invalid_conversion += 1;
            }
            What::Ip => {
                r.kind = Kind::Network;
                r.ip = true;
                counts.ip_ranges += 1;
            }
            What::Ext(e) => {
                r.kind = Kind::Extended;
                r.ext_kind = Some(e.kind);
                ext_at.push(records.len());
                ext_rules.push(e);
            }
            What::Rule { rule, translated } => {
                if translated {
                    counts.translated += 1;
                    r.translated = true;
                }
                let t = rule.trim();
                match route(t) {
                    Route::Engine => {
                        let eng = eng.expect("engine rule evaluated");
                        let owner = eng.origin.filter(|o| *o != me);
                        if let Some(o) = owner {
                            r.kind = Kind::Duplicate;
                            r.other = o;
                            counts.duplicate += 1;
                        } else if !seen_engine.insert(line_hash(&rule)) {
                            r.kind = Kind::Duplicate;
                            r.other = me;
                            counts.duplicate += 1;
                        } else {
                            match eng.parsed.expect("owned rule parsed") {
                                Parsed::Network => {
                                    r.kind = Kind::Network;
                                    counts.network += 1;
                                }
                                Parsed::Cosmetic => {
                                    r.kind = Kind::Cosmetic;
                                    counts.cosmetic += 1;
                                }
                                Parsed::Ext(mut e) => {
                                    e.raw = e.raw.trim().to_string();
                                    r.kind = Kind::Extended;
                                    r.ext_kind = Some(e.kind);
                                    ext_at.push(records.len());
                                    ext_rules.push(e);
                                }
                                Parsed::Invalid(reason) => {
                                    r.kind = Kind::Invalid;
                                    r.stage = Stage::Compile;
                                    r.reason = intern(&reason);
                                    counts.invalid_compile += 1;
                                }
                            }
                        }
                    }
                    Route::BadSuffix(_) | Route::BadExact(..) => {
                        r.kind = Kind::Network;
                        counts.network += 1;
                    }
                    Route::Suffix(h) => {
                        let key = suffix_key(h);
                        let verdict = match live {
                            Some(l) => match l
                                .domains
                                .lookup(h, Scheme::Https)
                                .filter(|hit| hit.exact.is_none())
                            {
                                Some(hit) if hit.start > 0 => Dom::Covered(hit.list),
                                Some(hit) => Dom::Owned(hit.list),
                                None => Dom::Disabled,
                            },
                            None => {
                                let mut anc = Vec::new();
                                push_ancestors(h, &mut anc);
                                if anc.iter().any(|(_, a)| present.contains(a)) {
                                    Dom::Covered(me)
                                } else if removed.contains(&(key, 0)) {
                                    Dom::Disabled
                                } else {
                                    Dom::Owned(me)
                                }
                            }
                        };
                        dom_verdict(&mut r, &mut counts, &mut seen_dom, (key, 0), me, verdict);
                    }
                    Route::Exact(s, h) => {
                        let key = exact_key(h);
                        let verdict = match live {
                            Some(l) => match l.domains.lookup_exact(h, s) {
                                Some(hit) => Dom::Owned(hit.list),
                                None => Dom::Disabled,
                            },
                            None if removed.contains(&(key, s.bit())) => Dom::Disabled,
                            None => Dom::Owned(me),
                        };
                        dom_verdict(
                            &mut r,
                            &mut counts,
                            &mut seen_dom,
                            (key, s.bit()),
                            me,
                            verdict,
                        );
                    }
                }
            }
        }
        records.push(r);
    }

    // Stage D: the extended-rule index's verdicts.
    for e in &mut ext_rules {
        e.list = input.id.clone();
        e.trusted = input.trusted;
    }
    let verdicts = if ext_rules.is_empty() {
        Vec::new()
    } else {
        judge(&ext_rules)
    };
    for (k, at) in ext_at.iter().enumerate() {
        let v = verdicts
            .get(k)
            .cloned()
            .unwrap_or_else(ExtVerdict::enforced);
        let r = &mut records[*at];
        r.state = state_code(v.state);
        r.reason = v.reason.as_deref().map_or(NO_REASON, &mut intern);
        *counts.ext_states.entry(v.state.as_str()).or_default() += 1;
        match v.state {
            ExtState::ENFORCED => counts.ext_enforced += 1,
            ExtState::UNSUPPORTED => counts.ext_unsupported += 1,
            ExtState::INVALID => counts.ext_invalid += 1,
            ExtState::NEEDS_TRUST => counts.ext_needs_trust += 1,
            _ => {}
        }
    }

    let mut starts: Vec<u32> = Vec::with_capacity(counts.lines + 1);
    starts.push(0);
    starts.extend(content.match_indices('\n').map(|(i, _)| (i + 1) as u32));
    // A final line without a newline is a line; a trailing newline does not start one.
    if starts.last().is_some_and(|s| *s as usize >= content.len()) {
        starts.pop();
    }
    let filters = Filter::all();
    let mut filter_counts = vec![0usize; filters.len()];
    let groups: [Vec<Filter>; 3] = [
        filters.iter().copied().filter(Filter::is_issue).collect(),
        filters.iter().copied().filter(Filter::is_applied).collect(),
        filters.iter().copied().filter(Filter::is_ignored).collect(),
    ];
    let mut group_counts = [0usize; 3];
    for r in &records {
        for (k, f) in filters.iter().enumerate() {
            if f.matches(r) {
                filter_counts[k] += 1;
            }
        }
        for (g, fs) in groups.iter().enumerate() {
            if fs.iter().any(|f| f.matches(r)) {
                group_counts[g] += 1;
            }
        }
    }
    Classified {
        id: input.id.clone(),
        format,
        in_build: live.is_some(),
        digest: String::new(),
        records,
        counts,
        filter_counts,
        group_counts,
        names,
        reasons,
        text: Arc::from(content),
        starts,
        extras,
    }
}

enum Dom {
    /// A shorter domain rule of this list covers it.
    Covered(u16),
    /// The table holds the rule, attributed to this list.
    Owned(u16),
    /// Disabled by a `$badfilter` rule.
    Disabled,
}

fn dom_verdict(
    r: &mut Record,
    counts: &mut Counts,
    seen: &mut HashSet<(u64, u8)>,
    key: (u64, u8),
    me: u16,
    v: Dom,
) {
    match v {
        Dom::Covered(l) => {
            r.kind = Kind::Covered;
            r.other = l;
            counts.covered += 1;
        }
        Dom::Owned(owner) if owner != me => {
            r.kind = Kind::Duplicate;
            r.other = owner;
            counts.duplicate += 1;
        }
        Dom::Owned(_) if !seen.insert(key) => {
            r.kind = Kind::Duplicate;
            r.other = me;
            counts.duplicate += 1;
        }
        Dom::Disabled => {
            r.kind = Kind::Disabled;
            counts.disabled += 1;
        }
        Dom::Owned(_) => {
            r.kind = Kind::Network;
            counts.network += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::build_set;

    fn input(id: &str, content: &str) -> ListInput {
        ListInput {
            id: id.into(),
            content: content.into(),
            ..Default::default()
        }
    }

    fn enforce_all(r: &[ExtRule]) -> Vec<ExtVerdict> {
        r.iter().map(|_| ExtVerdict::enforced()).collect()
    }

    fn alone(content: &str) -> Classified {
        classify_list(&input("l", content), None, &enforce_all)
    }

    fn kinds(c: &Classified) -> Vec<(u32, Kind)> {
        c.records.iter().map(|r| (r.line, r.kind)).collect()
    }

    #[test]
    fn source_lines_survive_directives_includes_and_dropped_lines() {
        let mut i = input(
            "l",
            "! Title\n!#if ext_ublock\n||a.test^\n!#else\n||b.test^\n!#endif\n\n!#include inc.txt\n||c.test^\n",
        );
        i.includes
            .insert("inc.txt".into(), "||d.test^\n##.x\n".into());
        let c = classify_list(&i, None, &enforce_all);
        let mut seen = c
            .records
            .iter()
            .map(|r| (r.line, r.kind))
            .collect::<Vec<_>>();
        seen.sort_by_key(|(l, _)| *l);
        assert_eq!(
            kinds(&c),
            vec![
                (1, Kind::Comment),
                (2, Kind::Comment),
                (3, Kind::Network),
                (4, Kind::Comment),
                (5, Kind::Inactive),
                (6, Kind::Comment),
                (7, Kind::Comment),
                (8, Kind::Comment),
                (8, Kind::Network),
                (8, Kind::Cosmetic),
                (9, Kind::Network),
            ]
        );
        assert_eq!(c.line_text(5), "||b.test^");
        let included = c.records.iter().find(|r| r.kind == Kind::Cosmetic).unwrap();
        assert_eq!(c.rule(included), "##.x");
        assert_eq!(c.counts.lines, 9);
    }

    #[test]
    fn standalone_statuses_cover_every_kind() {
        let c = alone(
            "||ads.test^\n||ads.test^\n||sub.ads.test^\nexample.com##.x\n/ads/*$bogus-option\n||x.test^$replace=/a/b/\n||bad$$$\n##+js(set-constant, a, 1)\n",
        );
        let k = kinds(&c);
        assert_eq!(k[0].1, Kind::Network);
        assert_eq!(k[1].1, Kind::Duplicate);
        assert_eq!(k[2].1, Kind::Covered);
        assert_eq!(k[3].1, Kind::Cosmetic);
        assert_eq!(c.counts.duplicate, 1);
        assert_eq!(c.counts.covered, 1);
        assert!(c.counts.ext() >= 2, "{:?}", c.counts);
    }

    #[test]
    fn duplicate_attribution_follows_build_order() {
        let a = input(
            "a",
            "||x.test/ads^\n||both.test^\n||both2.test/y\nexample.com##.q\n",
        );
        let b = input(
            "b",
            "||both.test^\n||both2.test/y\nexample.com##.q\n||only-b.test^\n",
        );
        for inputs in [[a.clone(), b.clone()], [b.clone(), a.clone()]] {
            let built = build_set(&inputs);
            let live = Live {
                origins: &built.origins,
                domains: &built.domains,
            };
            let first = &inputs[0].id;
            let second = &inputs[1].id;
            let c1 = classify_list(&inputs[0], Some(live), &enforce_all);
            let c2 = classify_list(&inputs[1], Some(live), &enforce_all);
            assert!(c1.in_build && c2.in_build);
            assert_eq!(c1.counts.duplicate, 0, "{first} comes first");
            assert!(c2.counts.duplicate >= 3, "{second}: {:?}", c2.counts);
            let d = c2
                .records
                .iter()
                .find(|r| r.kind == Kind::Duplicate)
                .unwrap();
            assert_eq!(c2.list_name(d.other), Some(first.as_str()));
            for (c, rep) in [(&c1, &built.reports[0]), (&c2, &built.reports[1])] {
                assert_eq!(c.counts.network, rep.network);
                assert_eq!(c.counts.cosmetic, rep.cosmetic);
                assert_eq!(c.counts.duplicate, rep.duplicates);
                assert_eq!(c.counts.covered, rep.compressed);
            }
        }
    }

    #[test]
    fn covered_host_names_the_list_that_covers_it() {
        let a = input("a", "||example.com^\n");
        let b = input("b", "||ads.example.com^\n||example.com^\n");
        let built = build_set(&[a.clone(), b.clone()]);
        let live = Live {
            origins: &built.origins,
            domains: &built.domains,
        };
        let c = classify_list(&b, Some(live), &enforce_all);
        assert_eq!(c.records[0].kind, Kind::Covered);
        assert_eq!(c.list_name(c.records[0].other), Some("a"));
        assert_eq!(c.records[1].kind, Kind::Duplicate);
        assert_eq!(c.counts.covered, built.reports[1].compressed);
        assert_eq!(c.counts.duplicate, built.reports[1].duplicates);
    }

    #[test]
    fn untrusted_lists_keep_the_else_branch_and_trusted_take_the_if_branch() {
        let text = "!#if cap_html_filtering\n||a.test^\n!#else\n||b.test^\n!#endif\n";
        let c = alone(text);
        assert_eq!(c.records[1].kind, Kind::Inactive);
        assert_eq!(c.records[3].kind, Kind::Network);
        let mut t = input("l", text);
        t.trusted = true;
        let c = classify_list(&t, None, &enforce_all);
        assert_eq!(c.records[1].kind, Kind::Network);
        assert_eq!(c.records[3].kind, Kind::Inactive);
    }

    #[test]
    fn host_lists_attribute_every_rule_to_its_line() {
        let c = alone("# hosts\n127.0.0.1 localhost\n0.0.0.0 a.test b.test\n192.168.1.5 nas\n");
        assert_eq!(c.format, ListFormat::Hosts);
        assert_eq!(
            kinds(&c),
            vec![
                (1, Kind::Comment),
                (2, Kind::Unsupported),
                (3, Kind::Network),
                (3, Kind::Network),
                (4, Kind::Unsupported),
            ]
        );
        assert_eq!(c.rule(&c.records[2]), "0.0.0.0 a.test b.test");
    }

    #[test]
    fn filters_parse_and_group() {
        let issues = Filter::parse("issues").unwrap();
        for name in ["unsupported", "invalid", "needs_trust", "not_enforced"] {
            let f = Filter::parse(name).unwrap()[0];
            assert!(issues.contains(&f), "{name}");
        }
        assert!(!issues.contains(&Filter::parse("not_applicable").unwrap()[0]));
        assert!(Filter::parse("applied")
            .unwrap()
            .contains(&Filter::State(ExtState::ENFORCED)));
        assert!(Filter::parse("ignored")
            .unwrap()
            .contains(&Filter::parse("not_applicable").unwrap()[0]));
        assert_eq!(
            Filter::parse("needs_trust"),
            Some(vec![Filter::State(ExtState::NEEDS_TRUST)])
        );
        assert_eq!(Filter::parse("nope"), None);
        // A state the table does not list is carried by name and counts as a problem.
        assert_eq!(ExtState::named("future").class(), ExtClass::Problem);
        assert_eq!(
            ExtState::named("not_enforced").class(),
            ExtClass::NotApplied
        );
    }

    #[test]
    fn line_text_handles_crlf_bom_and_a_missing_final_newline() {
        let c = alone("\u{feff}||a.test^\r\n||b.test^");
        assert_eq!(c.line_text(1), "||a.test^");
        assert_eq!(c.line_text(2), "||b.test^");
        assert_eq!(c.line_text(3), "");
        assert_eq!(c.records.len(), 2);
    }
}

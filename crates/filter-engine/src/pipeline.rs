//! The build pipeline: per list `detect/convert -> dedupe -> compile`, converting lists in
//! parallel. Pure CPU, no I/O: call it from `spawn_blocking`.

use std::collections::{BTreeMap, HashMap, HashSet};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::compile::{compile_lists_checked, route_domain_rules};
use crate::domainset::DomainSet;
use crate::formats::{
    convert, dedupe, ConvertOptions, Converted, ExtRule, IpRange, ListFormat, ListMeta, MAX_ERRORS,
};
use crate::shared::IpFilter;

/// One list to build.
#[derive(Debug, Clone, Default)]
pub struct ListInput {
    pub id: String,
    pub content: String,
    /// Format override; `Auto` detects.
    pub format: ListFormat,
    pub allowlist: bool,
    /// The list may inject scriptlets that require trust (`trusted-*`), like uBO's trusted lists.
    pub trusted: bool,
    /// Resolved `!#include` targets (see [`crate::formats::find_includes`]).
    pub includes: HashMap<String, String>,
}

/// Where a problem arose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueStage {
    /// The line could not be converted into a rule.
    #[default]
    Conversion,
    /// The converted rule was rejected by the engine's compiler.
    Compile,
}

/// A conversion / compile problem on one line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportIssue {
    /// 1-based line number in the source text (the line of the `!#include` for an included
    /// rule); 0 when the rule could not be traced back to a line.
    pub line: usize,
    /// The rule as written in the source.
    #[serde(default)]
    pub rule: String,
    pub reason: String,
    #[serde(default)]
    pub stage: IssueStage,
}

/// A list is flagged for attention when its INVALID rules (conversion errors, compiler
/// rejections, malformed extended rules) reach this percentage of its rules, rounded up, at
/// least one rule. Unsupported, not-enforced and needs-trust rules are never attention: they
/// are counted apart.
pub const ATTENTION_PERCENT: usize = 1;

/// What building one list produced.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ListReport {
    /// The format used (detected when the override was `Auto`).
    pub format: ListFormat,
    pub format_override: ListFormat,
    pub allowlist: bool,
    pub total_lines: usize,
    /// Rules emitted by conversion.
    pub converted: usize,
    /// Recognised but inexpressible lines.
    pub skipped: usize,
    /// Rules dropped as duplicates of an earlier rule (this or an earlier list).
    pub duplicates: usize,
    /// Domain rules dropped because a shorter suffix rule (any list) already covers them.
    #[serde(default)]
    pub compressed: usize,
    /// Rules rewritten into supported syntax.
    pub translated: usize,
    /// Network rules accepted by the engine.
    pub network: usize,
    /// Cosmetic rules accepted by the engine.
    pub cosmetic: usize,
    /// Extended rules handed off (not run by the engine). The four fields below split this by
    /// what the extended-rule index made of them; they are filled in by the list service once
    /// the index is built (see [`ListReport::apply_ext_states`]).
    pub ext: usize,
    /// Extended rules that are enforced.
    #[serde(default)]
    pub ext_enforced: usize,
    /// Well-formed extended rules that are not implemented.
    #[serde(default)]
    pub ext_unsupported: usize,
    /// Malformed extended rules.
    #[serde(default)]
    pub ext_invalid: usize,
    /// Extended rules dropped because the list is not trusted.
    #[serde(default)]
    pub ext_needs_trust: usize,
    /// Extended rules per state, whatever the state (see [`crate::inspect::EXT_STATES`]); the
    /// four fields above are the same figures for the states the UI has always shown.
    #[serde(default)]
    pub ext_states: BTreeMap<String, usize>,
    /// `$redirect` rules naming a resource that is not loaded (they act as plain blocks).
    /// Only counted by [`build_set_checked`].
    #[serde(default)]
    pub redirect_missing: usize,
    /// First few distinct missing resource names.
    #[serde(default)]
    pub redirect_missing_names: Vec<String>,
    /// Rules the engine's compiler rejected.
    pub rejected: usize,
    /// Pure domain rules disabled by a `$badfilter` rule (not counted in `network`).
    #[serde(default)]
    pub disabled: usize,
    /// IP / CIDR ranges collected for the IP matcher.
    pub ip_ranges: usize,
    /// Lines that could not be converted (not counting [`Self::rejected`]).
    pub error_count: usize,
    /// First few errors (conversion, then compile).
    pub errors: Vec<ReportIssue>,
    /// Rules already provided by an earlier rule or a shorter domain rule
    /// (`duplicates + compressed`); a list whose every rule is redundant is flagged
    /// [`Self::redundant`].
    #[serde(default)]
    pub redundant_count: usize,
    /// The list contributes no rule of its own: everything in it is already provided elsewhere.
    #[serde(default)]
    pub redundant: bool,
    /// Invalid rules reach [`ATTENTION_PERCENT`] percent of the list, at least one (see
    /// [`Self::problems`]).
    #[serde(default)]
    pub attention: bool,
    pub ext_counts: BTreeMap<String, usize>,
    pub skipped_reasons: BTreeMap<String, usize>,
    pub meta: ListMeta,
}

impl ListReport {
    /// Invalid rules: conversion errors, compiler rejections and malformed (`invalid`)
    /// extended rules. These alone can flag a list for attention.
    pub fn problems(&self) -> usize {
        self.error_count + self.rejected + self.ext_states.get("invalid").copied().unwrap_or(0)
    }

    /// All rules the list holds, whatever became of them.
    pub fn total_rules(&self) -> usize {
        self.network
            + self.cosmetic
            + self.ext
            + self.skipped
            + self.duplicates
            + self.compressed
            + self.disabled
            + self.error_count
            + self.rejected
    }

    /// Record how the extended-rule index judged this list's extended rules (`states`: count per
    /// state name) and refresh the derived flags.
    pub fn apply_ext_states(&mut self, states: BTreeMap<String, usize>) {
        let get = |n: &str| states.get(n).copied().unwrap_or(0);
        self.ext_enforced = get("enforced");
        self.ext_unsupported = get("unsupported");
        self.ext_invalid = get("invalid");
        self.ext_needs_trust = get("needs_trust");
        self.ext_states = states;
        self.finalize();
    }

    /// Set [`Self::redundant`], [`Self::redundant_count`] and [`Self::attention`] from the counts.
    pub fn finalize(&mut self) {
        self.redundant_count = self.duplicates + self.compressed;
        self.redundant = self.redundant_count > 0
            && self.network + self.cosmetic + self.ext + self.ip_ranges == 0;
        let threshold = (self.total_rules() * ATTENTION_PERCENT)
            .div_ceil(100)
            .max(1);
        self.attention = self.problems() >= threshold;
    }
}

/// Output of [`build_set`].
pub struct BuiltSet {
    /// Serialized engine (everything except the pure domain rules in [`Self::domains`]).
    pub blob: Vec<u8>,
    /// Pure domain / exact-host block rules, kept out of the engine.
    pub domains: DomainSet,
    /// All extended rules, in list order.
    pub ext: Vec<ExtRule>,
    pub ip: IpFilter,
    /// One report per input, in order.
    pub reports: Vec<ListReport>,
    /// The list of each compiled engine rule, keyed by the converted rule text.
    pub origins: crate::origins::RuleOrigins,
}

impl BuiltSet {
    /// Build the live engine from the blob and install everything (engine, domain set, extended
    /// rules, IP filter) into `engine`. Returns the per-list reports. CPU-bound.
    pub fn install_into(self, engine: &crate::SharedEngine) -> Vec<ListReport> {
        let live = crate::build_engine(&self.blob, &engine.resources());
        engine.install_set_with(
            std::sync::Arc::new(self.blob),
            live,
            None,
            std::sync::Arc::new(self.ext),
            std::sync::Arc::new(self.ip),
            std::sync::Arc::new(self.domains),
            std::sync::Arc::new(self.origins),
        );
        self.reports
    }
}

/// Is this list AdGuard's: an `adguard-` id or an explicitly forced AdGuard format (never
/// auto-detected syntax)?
pub(crate) fn is_adguard_origin(i: &ListInput) -> bool {
    !i.allowlist && (i.format == ListFormat::Adguard || i.id.starts_with("adguard-"))
}

/// Skip reason of an AdGuard `$redirect-rule` stub (dropped, see [`strip_redirects`]).
pub(crate) const STRIPPED_REDIRECT: &str = "adguard-redirect-stub";
/// Skip reason of an AdGuard bare-host exception (dropped, see [`strip_host_only_exceptions`]).
pub(crate) const STRIPPED_HOST_ONLY: &str = "adguard-host-exception";

fn is_opt(o: &str, k: &str) -> bool {
    o.strip_prefix(k).is_some_and(|r| r.starts_with('='))
}

/// Drop the redirect stub of every blocking rule: `$redirect=x` is removed (the rule stays a
/// plain block with its other options) and a `$redirect-rule=x` rule, which only adds a stub, is
/// dropped. Exceptions and site-specific rules (`domain=` / `from=`) are kept untouched.
pub(crate) fn strip_redirects(rules: &str) -> String {
    let mut out = String::with_capacity(rules.len());
    for line in rules.lines() {
        if let Some(l) = strip_redirects_line(line) {
            out.push_str(&l);
            out.push('\n');
        }
    }
    out
}

/// One line of [`strip_redirects`]: the (possibly rewritten) line, or `None` when it is dropped.
pub(crate) fn strip_redirects_line(line: &str) -> Option<std::borrow::Cow<'_, str>> {
    use crate::formats::{split_option_tokens, split_options};
    use std::borrow::Cow;
    if !line.contains("redirect") || line.starts_with("@@") {
        return Some(Cow::Borrowed(line));
    }
    let (pat, Some(opts)) = split_options(line) else {
        return Some(Cow::Borrowed(line));
    };
    let toks = split_option_tokens(opts);
    if toks
        .iter()
        .any(|o| is_opt(o, "domain") || is_opt(o, "from"))
    {
        return Some(Cow::Borrowed(line));
    }
    if toks.iter().any(|o| is_opt(o, "redirect-rule")) {
        return None;
    }
    if !toks.iter().any(|o| is_opt(o, "redirect")) {
        return Some(Cow::Borrowed(line));
    }
    let kept: Vec<&str> = toks
        .into_iter()
        .filter(|o| !is_opt(o, "redirect"))
        .collect();
    let mut l = pat.to_string();
    if !kept.is_empty() {
        l.push('$');
        l.push_str(&kept.join(","));
    }
    Some(Cow::Owned(l))
}

/// Drop AdGuard's bare-host exceptions `@@://host^|` (no options). AdGuard ships them to keep
/// DNS-level / HTTPS-filtering-off setups from breaking hosts like googleadservices.com, where the
/// full URL is never seen. Here every URL is visible and matched, so such an exception would only
/// unblock the host's root URL (`https://host/`) while `||host^` blocks everything else.
pub(crate) fn strip_host_only_exceptions(rules: &str) -> String {
    let mut out = String::with_capacity(rules.len());
    for line in rules.lines().filter(|l| !is_host_only_exception(l)) {
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Whether `line` is a bare-host exception dropped by [`strip_host_only_exceptions`].
pub(crate) fn is_host_only_exception(line: &str) -> bool {
    line.strip_prefix("@@://")
        .and_then(|r| r.strip_suffix("^|"))
        .is_some_and(|h| {
            !h.is_empty()
                && h.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        })
}

/// Line `n` (1-based) of `content`, trimmed; empty when out of range.
fn source_line(content: &str, n: usize) -> String {
    content
        .lines()
        .nth(n.saturating_sub(1))
        .map(|l| l.trim().to_string())
        .unwrap_or_default()
}

/// Convert, dedupe and compile `inputs`.
pub fn build_set(inputs: &[ListInput]) -> BuiltSet {
    build_set_checked(inputs, None)
}

/// Like [`build_set`]; with `known_redirects` (see [`crate::known_redirect_names`]) rules whose
/// `$redirect` resource is not loaded are counted and logged per list.
pub fn build_set_checked(
    inputs: &[ListInput],
    known_redirects: Option<&HashSet<String>>,
) -> BuiltSet {
    let mut converted: Vec<Converted> = inputs
        .par_iter()
        .map(|i| {
            convert(
                &i.content,
                &ConvertOptions {
                    format: i.format,
                    allowlist: i.allowlist,
                    includes: i.includes.clone(),
                    trusted: i.trusted,
                    ..Default::default()
                },
            )
        })
        .collect();

    // AdGuard-origin lists: their `$redirect` stubs are AdGuard's resources, which uBO/uBOL never
    // serve (uBO's own lists block these requests outright), so a stub would load where uBO
    // blocks. Keep the block, drop the stub.
    for (c, i) in converted.iter_mut().zip(inputs) {
        if is_adguard_origin(i) {
            let count = |t: &str| t.lines().count();
            let before = count(&c.rules);
            let rules = strip_redirects(&c.rules);
            let after_redirects = count(&rules);
            c.rules = strip_host_only_exceptions(&rules);
            for (n, reason) in [
                (before - after_redirects, STRIPPED_REDIRECT),
                (after_redirects - count(&c.rules), STRIPPED_HOST_ONLY),
            ] {
                if n > 0 {
                    c.stats.skipped += n;
                    *c.stats.skipped_reasons.entry(reason.into()).or_default() += n;
                }
            }
        }
    }

    // Pure domain rules go to the compact domain set (deduplicated there); only the rest is
    // text-deduplicated and compiled into the engine.
    let list_ids: Vec<String> = inputs.iter().map(|i| i.id.clone()).collect();
    let rule_texts: Vec<&str> = converted.iter().map(|c| c.rules.as_str()).collect();
    let routed = route_domain_rules(&rule_texts, list_ids);
    drop(rule_texts);
    for c in &mut converted {
        c.rules = String::new();
    }

    // Sequential, cheap: a 64-bit hash set across all lists.
    let total: usize = routed.engine_text.iter().map(|t| t.len() / 24 + 1).sum();
    let mut seen: HashSet<u64> = HashSet::with_capacity(total);
    let mut deduped: Vec<(String, usize)> = Vec::with_capacity(converted.len());
    for t in &routed.engine_text {
        deduped.push(dedupe(t, &mut seen));
    }
    drop(seen);
    let origins = crate::origins::RuleOrigins::build(
        inputs.iter().map(|i| i.id.clone()).collect(),
        deduped
            .iter()
            .enumerate()
            .flat_map(|(li, (t, _))| t.lines().map(move |l| (li, l))),
    );
    let domain_routed = routed.routed;
    drop(routed.engine_text);

    let texts: Vec<&str> = deduped.iter().map(|(t, _)| t.as_str()).collect();
    let trusted: Vec<bool> = inputs.iter().map(|i| i.trusted).collect();
    let compiled = compile_lists_checked(&texts, &trusted, known_redirects);
    drop(texts);
    let engine_network = compiled.per_list.iter().any(|c| c.network > 0);
    let domain_build = routed
        .builder
        .finish(compiled.engine_overrides, engine_network);
    let domain_dups = domain_build.duplicates;
    let domain_comp = domain_build.compressed;
    let domain_disabled = domain_build.disabled;

    let (mut ext, mut ip_block, mut ip_allow) = (Vec::new(), Vec::new(), Vec::<IpRange>::new());
    let mut reports = Vec::with_capacity(inputs.len());
    for (li, (((input, c), (_, dups)), cs)) in inputs
        .iter()
        .zip(converted)
        .zip(&deduped)
        .zip(compiled.per_list)
        .enumerate()
    {
        if cs.redirect_missing > 0 {
            tracing::warn!(
                "List {}: {} $redirect rule(s) name a missing resource (served as plain blocks), e.g. {}",
                input.id,
                cs.redirect_missing,
                cs.redirect_missing_names.join(", ")
            );
        }
        let domain_dup = domain_dups.get(li).copied().unwrap_or(0);
        let domain_comp = domain_comp.get(li).copied().unwrap_or(0);
        let domain_off = domain_disabled.get(li).copied().unwrap_or(0);
        let domain_kept = domain_routed[li].saturating_sub(domain_dup + domain_comp + domain_off);
        let mut errors: Vec<ReportIssue> = c
            .stats
            .errors
            .iter()
            .enumerate()
            .map(|(k, (line, reason))| ReportIssue {
                line: *line,
                rule: c
                    .stats
                    .error_texts
                    .get(k)
                    .cloned()
                    .unwrap_or_else(|| source_line(&input.content, *line)),
                reason: reason.clone(),
                stage: IssueStage::Conversion,
            })
            .collect();
        if !cs.error_rules.is_empty() {
            // Compile errors know the converted rule; find the source line it came from.
            let wanted: HashSet<&str> = cs.error_rules.iter().map(String::as_str).collect();
            let found = crate::inspect::locate(input, &wanted);
            for ((_, reason), rule) in cs.errors.iter().zip(&cs.error_rules) {
                if errors.len() >= MAX_ERRORS {
                    break;
                }
                let (line, text) = found
                    .get(rule.as_str())
                    .cloned()
                    .unwrap_or((0, rule.clone()));
                errors.push(ReportIssue {
                    line,
                    rule: text,
                    reason: reason.clone(),
                    stage: IssueStage::Compile,
                });
            }
        }
        let mut ext_counts = c.stats.ext_counts.clone();
        for e in &cs.ext_rules {
            *ext_counts.entry(e.kind.as_str().to_string()).or_default() += 1;
        }
        let mut report = ListReport {
            format: c.format,
            format_override: input.format,
            allowlist: input.allowlist,
            total_lines: c.stats.total_lines,
            converted: c.stats.converted,
            skipped: c.stats.skipped,
            duplicates: *dups + domain_dup,
            compressed: domain_comp,
            disabled: domain_off,
            translated: c.stats.translated,
            network: cs.network + domain_kept,
            cosmetic: cs.cosmetic,
            ext: c.ext.len() + cs.ext,
            redirect_missing: cs.redirect_missing,
            redirect_missing_names: cs.redirect_missing_names.clone(),
            rejected: cs.rejected,
            ip_ranges: c.ip_block.len() + c.ip_allow.len(),
            error_count: c.stats.error_count,
            errors,
            ext_counts,
            skipped_reasons: c.stats.skipped_reasons.clone(),
            meta: c.meta.clone(),
            ..Default::default()
        };
        report.finalize();
        reports.push(report);
        let (from_conv, from_compile) = (c.ext, cs.ext_rules);
        ext.extend(from_conv.into_iter().chain(from_compile).map(|mut e| {
            e.list = input.id.clone();
            e
        }));
        ip_block.extend(c.ip_block);
        ip_allow.extend(c.ip_allow);
    }
    BuiltSet {
        blob: compiled.blob,
        domains: domain_build.set,
        ext,
        ip: IpFilter::from_ranges(&ip_block, &ip_allow),
        reports,
        origins,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(id: &str, content: &str, format: ListFormat, allowlist: bool) -> ListInput {
        ListInput {
            id: id.into(),
            content: content.into(),
            format,
            allowlist,
            trusted: false,
            includes: HashMap::new(),
        }
    }

    #[test]
    fn dedupes_across_lists_and_reports_counts() {
        let built = build_set(&[
            input(
                "hosts",
                "0.0.0.0 a.example.com\n0.0.0.0 b.example.com\n",
                ListFormat::Auto,
                false,
            ),
            input(
                "abp",
                "||a.example.com^\n||c.example.com^\nexample.com##.x\n",
                ListFormat::Auto,
                false,
            ),
        ]);
        assert_eq!(built.reports[0].format, ListFormat::Hosts);
        assert_eq!(
            (built.reports[0].network, built.reports[0].duplicates),
            (2, 0)
        );
        assert_eq!(built.reports[1].format, ListFormat::Abp);
        assert_eq!(
            (
                built.reports[1].network,
                built.reports[1].cosmetic,
                built.reports[1].duplicates
            ),
            (1, 1, 1)
        );
    }

    #[test]
    fn easylist_style_list_after_superset_reports_unique_and_duplicates() {
        // A broad list first (as AdGuard Base is), then an EasyList-style list that mostly
        // overlaps it: the overlap is attributed to the first list, not lost or mis-parsed.
        let easylist = "[Adblock Plus 2.0]\n! Title: EasyList\n||ads.example^\n||tracker.example^$third-party\n/banner/*/img^\n@@||good.example^\n##.ad-box\nexample.com##.sponsor\n";
        let base = format!("{easylist}||extra.example^\n");
        let built = build_set(&[
            input("base", &base, ListFormat::Auto, false),
            input("easylist", easylist, ListFormat::Auto, false),
        ]);
        let (b, e) = (&built.reports[0], &built.reports[1]);
        assert_eq!(e.format, ListFormat::Abp);
        assert_eq!(b.network + b.cosmetic, 7);
        assert_eq!(e.network + e.cosmetic, 0);
        assert_eq!(e.duplicates, 6);
        assert_eq!(e.rejected, 0);
    }

    #[test]
    fn domain_compression_is_counted_per_list_and_ip_and_wildcards_are_unaffected() {
        let parent = "||example.com^\n";
        let child = "||ads.example.com^\n||deep.ads.example.com^\n||other.net^\n||*.wild.org^\n";
        let built = build_set(&[
            input("p", parent, ListFormat::Auto, false),
            input("c", child, ListFormat::Auto, false),
            input("ip", "0.0.0.0/8\n", ListFormat::Auto, false),
        ]);
        let (p, c) = (&built.reports[0], &built.reports[1]);
        assert_eq!((p.compressed, c.compressed), (0, 2));
        assert_eq!(c.duplicates, 0);
        // The two absorbed rules still count in the list's total, not as network rules.
        assert_eq!(c.network, 2);
        assert_eq!(built.reports[2].compressed, 0);
        let hit = built
            .domains
            .lookup("x.deep.ads.example.com", crate::domainset::Scheme::Https)
            .unwrap();
        assert_eq!(built.domains.list_id(hit.list), Some("p"));
        assert!(built
            .domains
            .lookup("a.other.net", crate::domainset::Scheme::Https)
            .is_some());
    }

    #[test]
    fn engine_hits_name_their_list_even_when_the_rule_was_translated() {
        let built = build_set(&[
            input(
                "a",
                "||ads.test/x.js^$script\n||ok.test/y.js^$script\n",
                ListFormat::Abp,
                false,
            ),
            // The AdGuard stub is stripped at build time: the compiled text is not the source.
            input(
                "adguard-b",
                "||m.test/a.js$script,redirect=noop.js\n",
                ListFormat::Ubo,
                false,
            ),
            input("c", "@@||ok.test/y.js^$script\n", ListFormat::Abp, false),
        ]);
        let engine = crate::SharedEngine::default();
        built.install_into(&engine);
        let q = |u: &str| {
            engine
                .check_gen_deferred(u, "https://page.test/", "script")
                .0
        };
        let r = q("https://ads.test/x.js");
        assert!(r.blocked && r.list_id.as_deref() == Some("a"), "{r:?}");
        let r = q("https://m.test/a.js");
        assert!(
            r.blocked && r.list_id.as_deref() == Some("adguard-b"),
            "{r:?}"
        );
        let r = q("https://ok.test/y.js");
        assert!(!r.blocked && r.list_id.as_deref() == Some("c"), "{r:?}");
        assert_eq!(q("https://none.test/").list_id, None);
    }

    #[test]
    fn adguard_host_only_exceptions_do_not_unblock_the_host_root() {
        let rules = "||googleadservices.com^\n@@://googleadservices.com^|\n\
                     @@://www.googleadservices.com^|\n@@://ok.test/x^|\n@@||keep.test^\n";
        assert_eq!(
            strip_host_only_exceptions(rules),
            "||googleadservices.com^\n@@://ok.test/x^|\n@@||keep.test^\n"
        );
        let built = build_set(&[input("adguard-mobile", rules, ListFormat::Ubo, false)]);
        let engine = crate::SharedEngine::default();
        built.install_into(&engine);
        for ty in ["xhr", "other"] {
            let r = engine.check("https://googleadservices.com/", "https://page.test/", ty);
            assert!(r.blocked, "{ty}: {r:?}");
        }
    }

    #[test]
    fn redirect_stripping_is_regex_aware() {
        // A regex `$` in a `domain=` value must not hide the site restriction or the redirect.
        let kept = r"||x.test^$domain=/a$/,redirect=noop.js";
        assert_eq!(strip_redirects(&format!("{kept}\n")), format!("{kept}\n"));
        assert_eq!(
            strip_redirects("||x.test^$removeparam=/^a$/,redirect=noop.js\n"),
            "||x.test^$removeparam=/^a$/\n"
        );
        assert!(matches!(
            strip_redirects_line("||x.test^$script"),
            Some(std::borrow::Cow::Borrowed(_))
        ));
    }

    #[test]
    fn strips_redirect_stubs_from_blocking_rules_only() {
        let rules = "||mc.yandex.ru/metrika/tag.js$script,redirect=metrika-yandex-tag\n\
                     ||ads.test/a.js$xhr,redirect=googlesyndication_adsbygoogle.js,script\n\
                     ||ads.test^$redirect-rule=noop.js\n\
                     @@||ads.test/ok.js$redirect=noop.js\n\
                     ||site.test/a.js$script,redirect=noop.js,domain=x.com\n\
                     ||site.test/b.js$script,redirect-rule=noop.js,from=x.com\n";
        assert_eq!(
            strip_redirects(rules),
            "||mc.yandex.ru/metrika/tag.js$script\n||ads.test/a.js$xhr,script\n\
             @@||ads.test/ok.js$redirect=noop.js\n\
             ||site.test/a.js$script,redirect=noop.js,domain=x.com\n\
             ||site.test/b.js$script,redirect-rule=noop.js,from=x.com\n"
        );
        let l = |id: &str| input(id, "", ListFormat::Auto, false);
        assert!(is_adguard_origin(&l("adguard-base")));
        let forced = input("x", "", ListFormat::Adguard, false);
        assert!(is_adguard_origin(&forced));
        // Auto-detected AdGuard syntax does not count.
        assert!(!is_adguard_origin(&l("x")));
        assert!(!is_adguard_origin(&input(
            "ublock-filters",
            "",
            ListFormat::Ubo,
            false
        )));
    }

    #[test]
    fn attention_is_invalid_rules_reaching_one_percent_rounded_up() {
        let rep = |total_ok: usize, bad: usize| {
            let mut r = ListReport {
                network: total_ok,
                error_count: bad,
                ..Default::default()
            };
            r.finalize();
            r
        };
        // Small list: 1% rounds up to one rule, so a single problem flags it.
        assert!(rep(50, 1).attention);
        assert!(!rep(50, 0).attention);
        // Medium list (1000 rules): 1% is 10 problems.
        assert!(!rep(990, 9).attention);
        assert!(rep(990, 10).attention);
        // No cap: a million-rule list needs 10,000 invalid rules.
        assert!(!rep(990_000, 20).attention);
        assert!(!rep(990_001, 9_999).attention);
        assert!(rep(990_000, 10_000).attention);
        // Unsupported, needs-trust and not-enforced rules never flag a list.
        let states = |v: &[(&str, usize)]| -> BTreeMap<String, usize> {
            v.iter().map(|(n, c)| (n.to_string(), *c)).collect()
        };
        let mut r = ListReport {
            network: 1000,
            ext: 600,
            ..Default::default()
        };
        r.apply_ext_states(states(&[
            ("unsupported", 200),
            ("needs_trust", 200),
            ("not_enforced", 100),
            ("invalid", 5),
        ]));
        assert!(!r.attention, "5 invalid of 1600 rules");
        r.apply_ext_states(states(&[("unsupported", 200), ("invalid", 16)]));
        assert!(r.attention, "16 invalid reach 1% of 1616");
        r.apply_ext_states(states(&[
            ("enforced", 2),
            ("not_enforced", 8),
            ("not_applicable", 2),
        ]));
        assert!(!r.attention);
        assert_eq!((r.ext_enforced, r.ext_states["not_enforced"]), (2, 8));
    }

    #[test]
    fn a_list_of_only_duplicates_is_redundant_not_empty() {
        let built = build_set(&[
            input(
                "first",
                "||a.test^
||b.test/x^
##.q
",
                ListFormat::Auto,
                false,
            ),
            input(
                "copy",
                "||a.test^
||b.test/x^
##.q
",
                ListFormat::Auto,
                false,
            ),
            input(
                "sub",
                "||ads.a.test^
",
                ListFormat::Auto,
                false,
            ),
            input(
                "own",
                "||own.test^
||a.test^
",
                ListFormat::Auto,
                false,
            ),
        ]);
        let r = &built.reports;
        assert!(!r[0].redundant);
        assert_eq!((r[1].network + r[1].cosmetic, r[1].redundant_count), (0, 3));
        assert!(r[1].redundant);
        assert!(
            r[2].redundant,
            "covered by a shorter domain rule of another list"
        );
        assert_eq!(r[2].redundant_count, 1);
        assert!(!r[3].redundant, "it adds ||own.test^");
        assert_eq!(r[3].redundant_count, 1);
    }

    #[test]
    fn issues_carry_the_source_line_rule_text_reason_and_stage() {
        let src = "! head
!#if ext_ublock
||bad$$
!#endif
||ok.test^
||x.test^$bogus-option=1
||y.test^
";
        let built = build_set(&[input("l", src, ListFormat::Abp, false)]);
        let r = &built.reports[0];
        assert_eq!((r.error_count, r.rejected), (0, 1), "{r:?}");
        let e = &r.errors[0];
        assert_eq!(
            (e.line, e.rule.as_str(), e.stage),
            (3, "||bad$$", IssueStage::Compile)
        );
        // A line that is not a rule at all fails in conversion.
        let built = build_set(&[input("l", "! x\n||\n||ok.test^\n", ListFormat::Abp, false)]);
        let r = &built.reports[0];
        assert_eq!((r.error_count, r.rejected), (1, 0), "{r:?}");
        let e = &r.errors[0];
        assert_eq!(
            (e.line, e.rule.as_str(), e.stage),
            (2, "||", IssueStage::Conversion)
        );
        // A rule the engine rejects: reported at its source line, not its place in the
        // converted text.
        let src = "! head

||fine.test^
||ads.test^$redirect-rule
";
        let built = build_set(&[input("l", src, ListFormat::Abp, false)]);
        let r = &built.reports[0];
        for e in r.errors.iter().filter(|e| e.stage == IssueStage::Compile) {
            assert_eq!(e.line, 4, "{e:?}");
            assert_eq!(e.rule, "||ads.test^$redirect-rule");
        }
    }

    #[test]
    fn allowlist_and_ip_and_ext_flow_through() {
        let built = build_set(&[
            input("block", "||a.example.com^\n", ListFormat::Auto, false),
            input("allow", "a.example.com\n", ListFormat::Domains, true),
            input("ips", "192.0.2.0/24\n", ListFormat::IpList, false),
            input(
                "ag",
                "||x.example^$replace=/a/b/\n",
                ListFormat::Adguard,
                false,
            ),
        ]);
        assert_eq!(built.reports[1].network, 1);
        assert_eq!(built.ext.len(), 1);
        assert_eq!(built.reports[3].ext, 1);
        assert!(built.ip.block.contains("192.0.2.9".parse().unwrap()));
        assert_eq!(built.reports[2].ip_ranges, 1);
    }
}

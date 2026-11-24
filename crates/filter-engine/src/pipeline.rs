//! The build pipeline: per list `detect/convert -> dedupe -> compile`, converting lists in
//! parallel. Pure CPU, no I/O: call it from `spawn_blocking`.

use std::collections::{BTreeMap, HashMap, HashSet};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::compile::{compile_lists_with, route_domain_rules};
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

/// A conversion / compile problem on one line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportIssue {
    /// Line number (in the source for conversion errors, in the converted rules for compile
    /// errors).
    pub line: usize,
    pub reason: String,
}

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
    /// Rules rewritten into supported syntax.
    pub translated: usize,
    /// Network rules accepted by the engine.
    pub network: usize,
    /// Cosmetic rules accepted by the engine.
    pub cosmetic: usize,
    /// Extended rules handed off (not run by the engine).
    pub ext: usize,
    /// Rules the engine rejected.
    pub rejected: usize,
    /// IP / CIDR ranges collected for the IP matcher.
    pub ip_ranges: usize,
    pub error_count: usize,
    /// First few errors (conversion, then compile).
    pub errors: Vec<ReportIssue>,
    pub ext_counts: BTreeMap<String, usize>,
    pub skipped_reasons: BTreeMap<String, usize>,
    pub meta: ListMeta,
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
}

impl BuiltSet {
    /// Build the live engine from the blob and install everything (engine, domain set, extended
    /// rules, IP filter) into `engine`. Returns the per-list reports. CPU-bound.
    pub fn install_into(self, engine: &crate::SharedEngine) -> Vec<ListReport> {
        let live = crate::build_engine(&self.blob, &engine.resources());
        engine.install_set(
            std::sync::Arc::new(self.blob),
            live,
            std::sync::Arc::new(self.ext),
            std::sync::Arc::new(self.ip),
            std::sync::Arc::new(self.domains),
        );
        self.reports
    }
}

/// Convert, dedupe and compile `inputs`.
pub fn build_set(inputs: &[ListInput]) -> BuiltSet {
    let mut converted: Vec<Converted> = inputs
        .par_iter()
        .map(|i| {
            convert(
                &i.content,
                &ConvertOptions {
                    format: i.format,
                    allowlist: i.allowlist,
                    includes: i.includes.clone(),
                },
            )
        })
        .collect();

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
    let domain_routed = routed.routed;
    drop(routed.engine_text);

    let texts: Vec<&str> = deduped.iter().map(|(t, _)| t.as_str()).collect();
    let trusted: Vec<bool> = inputs.iter().map(|i| i.trusted).collect();
    let compiled = compile_lists_with(&texts, &trusted);
    drop(texts);
    let engine_network = compiled.per_list.iter().any(|c| c.network > 0);
    let domain_build = routed
        .builder
        .finish(compiled.engine_overrides, engine_network);
    let domain_dups = domain_build.duplicates;

    let (mut ext, mut ip_block, mut ip_allow) = (Vec::new(), Vec::new(), Vec::<IpRange>::new());
    let mut reports = Vec::with_capacity(inputs.len());
    for (li, (((input, c), (_, dups)), cs)) in inputs
        .iter()
        .zip(converted)
        .zip(&deduped)
        .zip(compiled.per_list)
        .enumerate()
    {
        let domain_dup = domain_dups.get(li).copied().unwrap_or(0);
        let domain_kept = domain_routed[li].saturating_sub(domain_dup);
        let mut errors: Vec<ReportIssue> = c
            .stats
            .errors
            .iter()
            .map(|(line, reason)| ReportIssue {
                line: *line,
                reason: reason.clone(),
            })
            .collect();
        for (line, reason) in &cs.errors {
            if errors.len() < MAX_ERRORS {
                errors.push(ReportIssue {
                    line: *line,
                    reason: reason.clone(),
                });
            }
        }
        let mut ext_counts = c.stats.ext_counts.clone();
        for e in &cs.ext_rules {
            *ext_counts.entry(e.kind.as_str().to_string()).or_default() += 1;
        }
        reports.push(ListReport {
            format: c.format,
            format_override: input.format,
            allowlist: input.allowlist,
            total_lines: c.stats.total_lines,
            converted: c.stats.converted,
            skipped: c.stats.skipped,
            duplicates: *dups + domain_dup,
            translated: c.stats.translated,
            network: cs.network + domain_kept,
            cosmetic: cs.cosmetic,
            ext: c.ext.len() + cs.ext,
            rejected: cs.rejected,
            ip_ranges: c.ip_block.len() + c.ip_allow.len(),
            error_count: c.stats.error_count + cs.rejected,
            errors,
            ext_counts,
            skipped_reasons: c.stats.skipped_reasons.clone(),
            meta: c.meta.clone(),
        });
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

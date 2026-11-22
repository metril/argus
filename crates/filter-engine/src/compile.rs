//! Parallel rule parsing and engine compilation with per-list accounting.
//!
//! Converted rule text (see [`crate::formats`]) is parsed with adblock-rust's `parse_filter` in
//! parallel chunks across all cores, so every list reports how many rules the engine accepted
//! (network / cosmetic), how many were diverted to the extended-rule side list, and how many were
//! rejected, with the first few reasons. The single-threaded part is the final index build.
//!
//! CPU-bound: call from `spawn_blocking`, never from an async worker.

use adblock::filters::cosmetic::CosmeticFilter;
use adblock::filters::network::{NetworkFilter, NetworkFilterMask};
use adblock::lists::{parse_filter, FilterParseError, FilterSet, ParseOptions, ParsedFilter};
use adblock::Engine;
use rayon::prelude::*;

use crate::domainset::{is_set_host, DomainSetBuilder, Entry, Scheme};
use crate::formats::{classify_rejected, ExtRule, MAX_ERRORS};

const CHUNK: usize = 16 * 1024;

/// What the engine made of one list's rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListCompileStats {
    pub network: usize,
    pub cosmetic: usize,
    /// Rejected by the engine but classified as an extended rule (see `ext_rules`).
    pub ext: usize,
    /// Rejected and not recoverable.
    pub rejected: usize,
    /// First [`MAX_ERRORS`] rejections as `(line in the converted rule text, reason)`.
    pub errors: Vec<(usize, String)>,
    pub ext_rules: Vec<ExtRule>,
}

/// A compiled engine.
pub struct Compiled {
    /// Serialized engine (feed to [`crate::SharedEngine::install`]).
    pub blob: Vec<u8>,
    /// The engine holds exception, `$important` or redirect rules (a domain-set hit must then
    /// still consult it; see [`crate::DomainSet::engine_overrides`]).
    pub engine_overrides: bool,
    /// One entry per input list, in order.
    pub per_list: Vec<ListCompileStats>,
}

struct ChunkOut {
    list: usize,
    net: Vec<NetworkFilter>,
    cos: Vec<CosmeticFilter>,
    stats: ListCompileStats,
    overrides: bool,
}

fn parse_chunk(list: usize, first_line: usize, lines: &[&str]) -> ChunkOut {
    let mut out = ChunkOut {
        list,
        net: Vec::new(),
        cos: Vec::new(),
        stats: ListCompileStats::default(),
        overrides: false,
    };
    for (i, line) in lines.iter().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') {
            continue;
        }
        match parse_filter(line, true, ParseOptions::default()) {
            Ok(ParsedFilter::Network(f)) => {
                out.overrides |= f.mask.intersects(
                    NetworkFilterMask::IS_EXCEPTION
                        | NetworkFilterMask::IS_IMPORTANT
                        | NetworkFilterMask::IS_REDIRECT,
                );
                out.net.push(f);
                out.stats.network += 1;
            }
            Ok(ParsedFilter::Cosmetic(f)) => {
                out.cos.push(f);
                out.stats.cosmetic += 1;
            }
            Err(FilterParseError::Empty) => {}
            Err(e) => match classify_rejected(line) {
                Some(ext) => {
                    out.stats.ext += 1;
                    out.stats.ext_rules.push(ext);
                }
                None => {
                    out.stats.rejected += 1;
                    if out.stats.errors.len() < MAX_ERRORS {
                        out.stats.errors.push((first_line + i + 1, e.to_string()));
                    }
                }
            },
        }
    }
    out
}

/// Parse and compile `lists` (each: converted rule text, one rule per line).
pub fn compile_lists(lists: &[&str]) -> Compiled {
    let line_vecs: Vec<Vec<&str>> = lists.iter().map(|t| t.lines().collect()).collect();
    let chunks: Vec<(usize, usize, &[&str])> = line_vecs
        .iter()
        .enumerate()
        .flat_map(|(li, ls)| {
            ls.chunks(CHUNK)
                .enumerate()
                .map(move |(ci, c)| (li, ci * CHUNK, c))
        })
        .collect();
    let outs: Vec<ChunkOut> = chunks
        .par_iter()
        .map(|(li, first, c)| parse_chunk(*li, *first, c))
        .collect();

    let mut per_list = vec![ListCompileStats::default(); lists.len()];
    let (mut net, mut cos) = (Vec::new(), Vec::new());
    let mut engine_overrides = false;
    for o in outs {
        engine_overrides |= o.overrides;
        let s = &mut per_list[o.list];
        s.network += o.stats.network;
        s.cosmetic += o.stats.cosmetic;
        s.ext += o.stats.ext;
        s.rejected += o.stats.rejected;
        s.ext_rules.extend(o.stats.ext_rules);
        for e in o.stats.errors {
            if s.errors.len() < MAX_ERRORS {
                s.errors.push(e);
            }
        }
        net.extend(o.net);
        cos.extend(o.cos);
    }
    // debug=true keeps rule text so block pages / logs can show the matched rule.
    let set = FilterSet::new_with_rules(net, cos, true);
    let engine = Engine::from_filter_set(set, true);
    Compiled {
        blob: engine.serialize(),
        engine_overrides,
        per_list,
    }
}

// ---- pure domain rules ---------------------------------------------------------------------------

/// Where a rule line goes.
#[derive(Debug, PartialEq, Eq)]
enum Route<'a> {
    Suffix(&'a str),
    Exact(Scheme, &'a str),
    BadSuffix(&'a str),
    BadExact(Scheme, &'a str),
    Engine,
}

/// `body` minus its trailing `^` (or `^$badfilter`, flagged).
fn split_tail(body: &str) -> Option<(&str, bool)> {
    match body.strip_suffix("^$badfilter") {
        Some(h) => Some((h, true)),
        None => body.strip_suffix('^').map(|h| (h, false)),
    }
}

/// Classify one trimmed rule line: `||host^` and `|scheme://host^` (optionally with only
/// `$badfilter`) go to the domain set; everything else, including anything with another option,
/// an exception, an uppercase or unusual host, stays with the engine.
fn route(line: &str) -> Route<'_> {
    let Some(rest) = line.strip_prefix('|') else {
        return Route::Engine;
    };
    if let Some(rest) = rest.strip_prefix('|') {
        return match split_tail(rest) {
            Some((h, bad)) if is_set_host(h) => {
                if bad {
                    Route::BadSuffix(h)
                } else {
                    Route::Suffix(h)
                }
            }
            _ => Route::Engine,
        };
    }
    let Some((scheme, tail)) = rest.split_once("://") else {
        return Route::Engine;
    };
    match (Scheme::parse(scheme), split_tail(tail)) {
        (Some(sch), Some((h, bad))) if is_set_host(h) => {
            if bad {
                Route::BadExact(sch, h)
            } else {
                Route::Exact(sch, h)
            }
        }
        _ => Route::Engine,
    }
}

/// Output of [`route_domain_rules`].
pub struct DomainRouted {
    pub builder: DomainSetBuilder,
    /// Per list: rules routed to the domain set (before deduplication; includes `$badfilter`).
    pub routed: Vec<usize>,
    /// Per list: the remaining rule text for the engine.
    pub engine_text: Vec<String>,
}

struct RouteChunk {
    list: usize,
    entries: Vec<Entry>,
    removals: Vec<(u64, u8)>,
    routed: usize,
    text: String,
}

/// Split `lists` (converted rule text) into pure domain rules, collected into a
/// [`DomainSetBuilder`], and the rest. Runs in parallel over byte chunks of every list.
/// `list_ids[i]` names list `i` in set hits.
pub fn route_domain_rules(lists: &[&str], list_ids: Vec<String>) -> DomainRouted {
    use crate::domainset::{exact_key, suffix_key, NO_LIST};
    let mut chunks: Vec<(usize, &str)> = Vec::new();
    for (li, text) in lists.iter().enumerate() {
        let target = (text.len() / (rayon::current_num_threads() * 4)).max(256 * 1024);
        let mut rest = *text;
        while !rest.is_empty() {
            let mut cut = target.min(rest.len());
            if cut < rest.len() {
                cut = rest[cut..].find('\n').map_or(rest.len(), |i| cut + i + 1);
            }
            chunks.push((li, &rest[..cut]));
            rest = &rest[cut..];
        }
    }
    let outs: Vec<RouteChunk> = chunks
        .par_iter()
        .map(|(li, text)| {
            let list = (*li).min(NO_LIST as usize) as u16;
            let mut o = RouteChunk {
                list: *li,
                entries: Vec::new(),
                removals: Vec::new(),
                routed: 0,
                text: String::new(),
            };
            for raw in text.lines() {
                match route(raw.trim()) {
                    Route::Suffix(h) => o.entries.push(Entry {
                        key: suffix_key(h),
                        bit: 0,
                        list,
                    }),
                    Route::Exact(s, h) => o.entries.push(Entry {
                        key: exact_key(h),
                        bit: s.bit(),
                        list,
                    }),
                    Route::BadSuffix(h) => o.removals.push((suffix_key(h), 0)),
                    Route::BadExact(s, h) => o.removals.push((exact_key(h), s.bit())),
                    Route::Engine => {
                        o.text.push_str(raw);
                        o.text.push('\n');
                        continue;
                    }
                }
                o.routed += 1;
            }
            o
        })
        .collect();
    let mut builder = DomainSetBuilder::new(list_ids);
    let mut routed = vec![0; lists.len()];
    let mut engine_text = vec![String::new(); lists.len()];
    for o in outs {
        routed[o.list] += o.routed;
        engine_text[o.list].push_str(&o.text);
        builder.merge(o.entries, o.removals);
    }
    DomainRouted {
        builder,
        routed,
        engine_text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_classifies_pure_domain_rules_only() {
        use Route::*;
        assert_eq!(route("||ads.test^"), Suffix("ads.test"));
        assert_eq!(route("||ads.test^$badfilter"), BadSuffix("ads.test"));
        assert_eq!(route("|https://h.test^"), Exact(Scheme::Https, "h.test"));
        assert_eq!(
            route("|wss://h.test^$badfilter"),
            BadExact(Scheme::Wss, "h.test")
        );
        for engine in [
            "@@||ads.test^",
            "||ads.test^$script",
            "||ads.test^$important",
            "||ads.test/x^",
            "||ads.test",
            "||Ads.test^",
            "||com^",
            "||1.2.3.4^",
            "|ftp://h.test^",
            "|https://h.test/x^",
            "|https://h.test^$image",
            "/ads/",
            "##.x",
            "||a.test^$badfilter,script",
        ] {
            assert_eq!(route(engine), Engine, "{engine}");
        }
    }

    #[test]
    fn counts_accepted_and_rejected_per_list() {
        let a = "||a.test^\n##.ad\nx.com##^script:has-text(a)\n||b.test^$nonsense-option\n";
        let b = "||c.test^\n";
        let c = compile_lists(&[a, b]);
        assert_eq!((c.per_list[0].network, c.per_list[0].cosmetic), (1, 1));
        assert_eq!(
            c.per_list[0].ext, 2,
            "html filter and unsupported option are handed off"
        );
        assert_eq!(c.per_list[1].network, 1);
        assert!(!c.blob.is_empty());
    }
}

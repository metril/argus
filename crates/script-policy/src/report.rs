//! "What was blocked on this page": a bounded aggregation of proxy-side network blocks and
//! browser `securitypolicyviolation` events.

use crate::caps::{CapSet, Capability};
use crate::scope::{parse_origin, Scope};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

/// How a block was observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// The proxy refused the request.
    Network,
    /// The browser reported a CSP violation.
    Csp,
}

/// A browser `securitypolicyviolation` event, as the in-page code forwards it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CspViolation {
    pub document_uri: String,
    pub effective_directive: String,
    /// `inline`, `eval`, `wasm-eval`, `data`, `blob`, `""` or a URL.
    pub blocked_uri: String,
    /// `enforce` or `report`; report-only violations are ignored.
    #[serde(default)]
    pub disposition: String,
}

/// One aggregated blocked thing on one page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedItem {
    pub cap: Capability,
    /// Host of the blocked source; `None` for inline/eval/data:/blob: (no host to allow).
    pub source: Option<String>,
    pub count: u32,
    pub first_seen: u64,
    pub last_seen: u64,
    pub via_network: bool,
    pub via_csp: bool,
    /// One example URL without query or fragment (truncated).
    pub sample: Option<String>,
}

impl BlockedItem {
    /// The one-click allow: a host-level source rule for sourced items. Inline/eval/wasm items
    /// have no source rule (they are page-level; change the preset).
    pub fn suggested_allow(&self) -> Option<(Scope, CapSet)> {
        let host = self.source.as_ref()?;
        self.cap
            .is_source_keyed()
            .then(|| (Scope::Host(host.clone()), CapSet::of(&[self.cap])))
    }
}

/// A page's aggregate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageReport {
    pub page: String,
    pub items: Vec<BlockedItem>,
    /// Distinct items discarded because the per-page bound was reached.
    pub dropped: u32,
    pub events: u64,
    pub last_seen: u64,
}

/// A block event to record.
#[derive(Clone, Debug)]
pub struct BlockEvent {
    pub cap: Capability,
    pub source: Option<String>,
    pub sample: Option<String>,
    pub via: Via,
}

/// Memory bounds.
#[derive(Clone, Copy, Debug)]
pub struct ReportLimits {
    pub max_pages: usize,
    pub max_items_per_page: usize,
    pub max_sample_len: usize,
}

impl Default for ReportLimits {
    fn default() -> Self {
        ReportLimits {
            max_pages: 256,
            max_items_per_page: 64,
            max_sample_len: 200,
        }
    }
}

struct PageAgg {
    items: Vec<BlockedItem>,
    dropped: u32,
    events: u64,
    last_seen: u64,
}

/// Bounded per-host aggregation. Not thread safe: wrap in a mutex.
pub struct ReportAggregator {
    limits: ReportLimits,
    pages: FxHashMap<String, PageAgg>,
}

impl Default for ReportAggregator {
    fn default() -> Self {
        Self::new(ReportLimits::default())
    }
}

impl ReportAggregator {
    pub fn new(limits: ReportLimits) -> Self {
        ReportAggregator {
            limits,
            pages: FxHashMap::default(),
        }
    }

    /// Record a block on `page_host` (normalised host of the document).
    pub fn record(&mut self, page_host: &str, ev: BlockEvent, now: u64) {
        if !self.pages.contains_key(page_host) && self.pages.len() >= self.limits.max_pages {
            if let Some(oldest) = self
                .pages
                .iter()
                .min_by_key(|(_, p)| p.last_seen)
                .map(|(k, _)| k.clone())
            {
                self.pages.remove(&oldest);
            }
        }
        let max_items = self.limits.max_items_per_page;
        let sample = ev.sample.map(|s| clip(&s, self.limits.max_sample_len));
        let page = self
            .pages
            .entry(page_host.to_string())
            .or_insert_with(|| PageAgg {
                items: Vec::new(),
                dropped: 0,
                events: 0,
                last_seen: now,
            });
        page.events += 1;
        page.last_seen = now;
        let (net, csp) = (ev.via == Via::Network, ev.via == Via::Csp);
        if let Some(it) = page
            .items
            .iter_mut()
            .find(|i| i.cap == ev.cap && i.source == ev.source)
        {
            it.count = it.count.saturating_add(1);
            it.last_seen = now;
            it.via_network |= net;
            it.via_csp |= csp;
            return;
        }
        if page.items.len() >= max_items {
            // Evict the least significant item: fewest hits, then oldest.
            if let Some(i) = page
                .items
                .iter()
                .enumerate()
                .min_by_key(|(_, i)| (i.count, i.last_seen))
                .map(|(i, _)| i)
            {
                page.items.swap_remove(i);
            }
            page.dropped = page.dropped.saturating_add(1);
        }
        page.items.push(BlockedItem {
            cap: ev.cap,
            source: ev.source,
            count: 1,
            first_seen: now,
            last_seen: now,
            via_network: net,
            via_csp: csp,
            sample,
        });
    }

    /// Record a browser violation. Returns false when it is ignored (report-only, unknown
    /// directive, or `document_uri` not http(s)).
    pub fn record_violation(&mut self, v: &CspViolation, now: u64) -> bool {
        let Some((page, ev)) = classify_violation(v) else {
            return false;
        };
        self.record(&page, ev, now);
        true
    }

    /// The aggregate for one page, items sorted by hits (descending).
    pub fn page(&self, page_host: &str) -> Option<PageReport> {
        self.pages.get(page_host).map(|p| report_of(page_host, p))
    }

    /// Pages seen, most recently active first.
    pub fn pages(&self) -> Vec<PageReport> {
        let mut v: Vec<_> = self.pages.iter().map(|(h, p)| report_of(h, p)).collect();
        v.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.page.cmp(&b.page)));
        v
    }

    pub fn clear(&mut self) {
        self.pages.clear();
    }
}

fn report_of(host: &str, p: &PageAgg) -> PageReport {
    let mut items = p.items.clone();
    items.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then(a.cap.cmp(&b.cap))
            .then(a.source.cmp(&b.source))
    });
    PageReport {
        page: host.to_string(),
        items,
        dropped: p.dropped,
        events: p.events,
        last_seen: p.last_seen,
    }
}

fn clip(s: &str, max: usize) -> String {
    let s = s.split(['?', '#']).next().unwrap_or(s);
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Map a violation to `(page host, event)`.
pub fn classify_violation(v: &CspViolation) -> Option<(String, BlockEvent)> {
    if v.disposition == "report" {
        return None;
    }
    let (_, page, _) = parse_origin(&v.document_uri)?;
    let blocked = v.blocked_uri.as_str();
    let inline = matches!(blocked, "inline" | "");
    let cap = match v.effective_directive.as_str() {
        "script-src" | "script-src-elem" => match blocked {
            "eval" => Capability::Eval,
            "wasm-eval" => Capability::Wasm,
            "inline" => Capability::InlineScript,
            _ => Capability::Script,
        },
        "script-src-attr" => Capability::InlineScript,
        "style-src" | "style-src-elem" => {
            if inline {
                Capability::InlineStyle
            } else {
                Capability::Style
            }
        }
        "style-src-attr" => Capability::InlineStyle,
        "worker-src" => Capability::Worker,
        "img-src" => Capability::Image,
        "font-src" => Capability::Font,
        "media-src" => Capability::Media,
        "object-src" => Capability::Object,
        "frame-src" | "child-src" => Capability::Frame,
        "connect-src" => Capability::Connect,
        "form-action" => Capability::FormAction,
        _ => return None,
    };
    let (source, sample) = match parse_origin(blocked) {
        Some((_, host, _)) => (Some(host), Some(blocked.to_string())),
        None => (None, None),
    };
    Some((
        page,
        BlockEvent {
            cap,
            source,
            sample,
            via: Via::Csp,
        },
    ))
}

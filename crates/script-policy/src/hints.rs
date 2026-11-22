//! Early, request-path enforcement of capability denials ("network hints").
//!
//! The proxy sees a subresource request, not the page. It can enforce a denial early only when
//! it knows which page the request belongs to; see [`PageContext`]. Whenever it does not, it does
//! nothing and the CSP on the page's document is the only enforcement.

use crate::caps::{CapSet, Capability};
use crate::compile::{PagePolicy, Source};
use crate::scope::Scheme;

/// `Sec-Fetch-Dest` of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchDest {
    Script,
    /// `audioworklet` / `paintworklet`.
    Worklet,
    /// `worker` / `sharedworker` / `serviceworker`.
    Worker,
    Style,
    Image,
    Font,
    /// `audio` / `video` / `track`.
    Media,
    /// `object` / `embed`.
    Object,
    /// `iframe` / `frame`.
    Frame,
    /// `fetch`, XHR, beacons, EventSource.
    Empty,
    Websocket,
    /// Top-level navigations and everything not classified.
    Other,
}

impl FetchDest {
    pub fn from_header(v: &str) -> FetchDest {
        match v {
            "script" => FetchDest::Script,
            "audioworklet" | "paintworklet" => FetchDest::Worklet,
            "worker" | "sharedworker" | "serviceworker" => FetchDest::Worker,
            "style" => FetchDest::Style,
            "image" => FetchDest::Image,
            "font" => FetchDest::Font,
            "audio" | "video" | "track" => FetchDest::Media,
            "object" | "embed" => FetchDest::Object,
            "iframe" | "frame" => FetchDest::Frame,
            "empty" => FetchDest::Empty,
            "websocket" => FetchDest::Websocket,
            _ => FetchDest::Other,
        }
    }

    /// The capability a request of this kind exercises.
    pub fn capability(self) -> Option<Capability> {
        Some(match self {
            FetchDest::Script | FetchDest::Worklet => Capability::Script,
            FetchDest::Worker => Capability::Worker,
            FetchDest::Style => Capability::Style,
            FetchDest::Image => Capability::Image,
            FetchDest::Font => Capability::Font,
            FetchDest::Media => Capability::Media,
            FetchDest::Object => Capability::Object,
            FetchDest::Frame => Capability::Frame,
            FetchDest::Empty | FetchDest::Websocket => Capability::Connect,
            FetchDest::Other => return None,
        })
    }
}

/// Why the initiating page is unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownReason {
    /// No `Referer` and no `Origin` (Referrer-Policy `no-referrer`/`same-origin`, or an old
    /// client).
    NoInitiator,
    /// `Origin: null` (sandboxed frame, `data:` document, redirected cross-origin request).
    OpaqueOrigin,
    /// `Sec-Fetch-Site: none`: user-initiated navigation, not a subresource.
    UserNavigation,
    /// The header was present but not an http(s) URL we can read.
    Unparsable,
}

/// The document a subresource request belongs to, as far as headers reveal it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageContext<'a> {
    Known {
        scheme: Scheme,
        host: &'a str,
        port: Option<u16>,
    },
    Unknown(UnknownReason),
}

impl<'a> PageContext<'a> {
    /// Derive the page from request headers, in this order: `Referer` (full URL or origin; the
    /// initiating *document* — a frame's own URL for requests it makes, a worker script's URL for
    /// requests a worker makes), then `Origin`, then `Sec-Fetch-Site: same-origin` (the page is
    /// the target's own origin). `target` is the request's own scheme/host/port.
    ///
    /// Returns `Unknown` when no header identifies the page. Referrer policies that strip the
    /// referrer (`no-referrer`, `same-origin` for cross-origin requests) land here, so the third
    /// party requests we most want to judge are exactly the ones we may not be able to attribute.
    pub fn from_headers(
        referer: Option<&'a str>,
        origin: Option<&'a str>,
        sec_fetch_site: Option<&str>,
        target: (Scheme, &'a str, Option<u16>),
    ) -> PageContext<'a> {
        if sec_fetch_site == Some("none") {
            return PageContext::Unknown(UnknownReason::UserNavigation);
        }
        if let Some(r) = referer {
            return parse_authority(r).unwrap_or(PageContext::Unknown(UnknownReason::Unparsable));
        }
        if let Some(o) = origin {
            if o == "null" {
                return PageContext::Unknown(UnknownReason::OpaqueOrigin);
            }
            return parse_authority(o).unwrap_or(PageContext::Unknown(UnknownReason::Unparsable));
        }
        if sec_fetch_site == Some("same-origin") {
            return PageContext::Known {
                scheme: target.0,
                host: target.1,
                port: target.2,
            };
        }
        PageContext::Unknown(UnknownReason::NoInitiator)
    }
}

/// Scheme, host and port from `scheme://[user@]host[:port][/...]` without allocating. Browsers
/// serialise hosts lowercase; anything else is treated as unparsable.
fn parse_authority(u: &str) -> Option<PageContext<'_>> {
    let (sc, rest) = u.split_once("://")?;
    let scheme = Scheme::parse(sc)?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let auth = &rest[..end];
    let auth = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    let (host, port) = if auth.starts_with('[') {
        let i = auth.find(']')?;
        (&auth[..=i], auth[i + 1..].strip_prefix(':'))
    } else {
        match auth.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (auth, None),
        }
    };
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let port = match port {
        Some(p) if !p.is_empty() => Some(p.parse().ok()?),
        _ => None,
    };
    Some(PageContext::Known { scheme, host, port })
}

/// A subresource request as the proxy sees it.
#[derive(Clone, Copy, Debug)]
pub struct SubRequest<'a> {
    pub dest: FetchDest,
    /// The request carries a `Ping-To` header (hyperlink auditing).
    pub ping: bool,
    pub target: Source<'a>,
}

/// Outcome of an early check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HintVerdict {
    Allow,
    /// Block with the typed script-policy response; `cap` is what was denied.
    Block {
        cap: Capability,
    },
}

/// Capabilities worth checking at the proxy for a page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkHints {
    /// Capabilities that this page denies for at least some source and that the request path
    /// can judge. Empty means "do nothing for this page".
    pub enforce: CapSet,
}

impl NetworkHints {
    pub fn is_empty(&self) -> bool {
        self.enforce.is_empty()
    }
}

/// Capabilities the request path may enforce by default. `connect` is excluded: `Sec-Fetch-Dest:
/// empty` also covers prefetches, service-worker fetches and other traffic whose initiator
/// cannot be attributed reliably; opt in with [`PagePolicy::network_hints_with`].
pub const DEFAULT_ENFORCEABLE: CapSet = CapSet::of_const(&[
    Capability::Script,
    Capability::Worker,
    Capability::Style,
    Capability::Image,
    Capability::Font,
    Capability::Media,
    Capability::Object,
    Capability::Frame,
    Capability::Ping,
]);

impl<'a> PagePolicy<'a> {
    pub fn network_hints(&self) -> NetworkHints {
        self.network_hints_with(DEFAULT_ENFORCEABLE)
    }

    pub fn network_hints_with(&self, enforceable: CapSet) -> NetworkHints {
        if !self.active || !self.c.settings().network_hints {
            return NetworkHints {
                enforce: CapSet::EMPTY,
            };
        }
        let enforce = enforceable
            .iter()
            .filter(|c| {
                !self.profile.first_party.contains(*c)
                    || !self.profile.third_party.contains(*c)
                    || self.rules_for(*c).iter().any(|(_, r)| r.deny)
            })
            .fold(CapSet::EMPTY, |s, c| s.with(c));
        NetworkHints { enforce }
    }

    /// Judge a subresource request from this page. `hints` is [`PagePolicy::network_hints`]
    /// (computed once per page and cached by the caller).
    pub fn check_request(&self, hints: &NetworkHints, req: &SubRequest<'_>) -> HintVerdict {
        let cap = if req.ping {
            Capability::Ping
        } else {
            match req.dest.capability() {
                Some(c) => c,
                None => return HintVerdict::Allow,
            }
        };
        if hints.enforce.contains(cap) && !self.allows(cap, req.target) {
            HintVerdict::Block { cap }
        } else {
            HintVerdict::Allow
        }
    }
}

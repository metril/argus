//! Admin settings: every runtime setting, with default/modified/unsaved state, per-field reset,
//! a sticky save bar, per-field results from the PUT response and the web UI move flow.

use std::net::IpAddr;

use leptos::prelude::*;

use crate::api::proxy::{ProxyConfigResponse, UpdateProxyConfigRequest};
use crate::api::{ApiClient, ApiError};
use crate::components::{Icon, Layout, RequireAdmin, Segmented, Switch, TagInput};
use crate::state::use_app_state;

#[derive(Clone, PartialEq)]
enum Val {
    B(bool),
    S(String),
    T(Vec<String>),
}

impl Val {
    fn s(&self) -> String {
        match self {
            Val::S(s) => s.clone(),
            Val::B(b) => b.to_string(),
            Val::T(t) => t.join(", "),
        }
    }
    fn b(&self) -> bool {
        matches!(self, Val::B(true))
    }
    fn t(&self) -> Vec<String> {
        match self {
            Val::T(t) => t.clone(),
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Text,
    Port,
    Num {
        unit: &'static str,
        min: u64,
        max: u64,
    },
    Switch,
    Cidr,
    /// Host names (`example.com`, `*.example.com`).
    Hosts,
    /// Free text, not validated here (the server checks it).
    Free,
    /// Write-only text: shown masked, never filled in from the server.
    Secret,
    Seg(&'static [(&'static str, &'static str)]),
}

#[derive(Clone, Copy)]
struct Def {
    key: &'static str,
    label: &'static str,
    desc: &'static str,
    kind: Kind,
    dep: Option<&'static str>,
}

#[derive(Clone, Copy)]
struct F {
    def: Def,
    cur: RwSignal<Val>,
    saved: RwSignal<Val>,
    default: RwSignal<Val>,
    msg: RwSignal<Option<(bool, String)>>,
}

const UPSTREAM_KINDS: &[(&str, &str)] = &[("http", "HTTP"), ("socks5", "SOCKS5")];

const BLOCK_RESPONSES: &[(&str, &str)] = &[("fail", "Fail"), ("synthetic", "Fake success")];

const HOURS: &[(&str, &str)] = &[("6", "6 h"), ("12", "12 h"), ("24", "24 h"), ("168", "7 d")];

struct Section {
    id: &'static str,
    title: &'static str,
    sub: &'static str,
    fields: &'static [Def],
}

const SECTIONS: &[Section] = &[
    Section {
        id: "listeners",
        title: "Listeners",
        sub: "Ports rebind live. Open connections finish on the old socket.",
        fields: &[
            Def {
                key: "explicit_host",
                label: "Explicit proxy host",
                desc: "Address to bind. 0.0.0.0 listens on all IPv4 interfaces, :: on all.",
                kind: Kind::Text,
                dep: None,
            },
            Def {
                key: "explicit_port",
                label: "Explicit proxy port",
                desc: "Clients set host:port as their HTTP(S) proxy.",
                kind: Kind::Port,
                dep: None,
            },
            Def {
                key: "transparent_on",
                label: "Transparent listener",
                desc: "Accepts traffic redirected by the firewall.",
                kind: Kind::Switch,
                dep: None,
            },
            Def {
                key: "transparent_port",
                label: "Transparent port",
                desc: "Must match the nftables redirect target.",
                kind: Kind::Port,
                dep: Some("transparent_on"),
            },
            Def {
                key: "ext_on",
                label: "Extension listener",
                desc: "Lets the Argus browser extension bind its browser to its session. Answers 407 to everything else.",
                kind: Kind::Switch,
                dep: None,
            },
            Def {
                key: "ext_port",
                label: "Extension port",
                desc: "Proxy port the extension sends its browser through (the extension learns it from Argus).",
                kind: Kind::Port,
                dep: Some("ext_on"),
            },
            Def {
                key: "webui_host",
                label: "Web UI host",
                desc: "Where this console is served.",
                kind: Kind::Text,
                dep: None,
            },
            Def {
                key: "webui_port",
                label: "Web UI port",
                desc: "Changing it moves this page. You confirm first.",
                kind: Kind::Port,
                dep: None,
            },
        ],
    },
    Section {
        id: "lists",
        title: "Signed lists source",
        sub: "Where the bypass lists, trusted roots and catalogues are fetched from. Applied at once.",
        fields: &[
            Def {
                key: "lists_url",
                label: "Base URL",
                desc: "Empty uses the official release. A mirror must not serve older releases than the ones already installed: those are refused. A mirror with its own key and lower serials stays on the built-in roots because of the downgrade floor.",
                kind: Kind::Free,
                dep: None,
            },
            Def {
                key: "lists_key",
                label: "Public key",
                desc: "Minisign key the lists must be signed with. Empty uses the built-in key. Changing it checks the installed lists against the new key and drops any that fail.",
                kind: Kind::Free,
                dep: None,
            },
        ],
    },
    Section {
        id: "timeouts",
        title: "Timeouts and limits",
        sub: "Apply to new connections.",
        fields: &[
            Def {
                key: "conn_timeout",
                label: "Connection timeout",
                desc: "TCP and TLS handshake with the upstream.",
                kind: Kind::Num {
                    unit: "s",
                    min: 1,
                    max: 300,
                },
                dep: None,
            },
            Def {
                key: "req_timeout",
                label: "Request timeout",
                desc: "Whole request, headers to last byte.",
                kind: Kind::Num {
                    unit: "s",
                    min: 1,
                    max: 3600,
                },
                dep: None,
            },
            Def {
                key: "block_response",
                label: "Blocked requests",
                desc: "Fail: a blocked script, fetch, stylesheet, ping, media, font or WebSocket fails like a network error, as with an extension blocker, so pages see the block. Documents still get the block page, frames a blank page and images a transparent pixel. Fake success answers every block with an empty success instead.",
                kind: Kind::Seg(BLOCK_RESPONSES),
                dep: None,
            },
            Def {
                key: "browser_like",
                label: "Browser-like connections",
                desc: "Connect to sites the way your browser does (same TLS and HTTP/2 fingerprint). Off uses the same client without the browser fingerprint.",
                kind: Kind::Switch,
                dep: None,
            },
            Def {
                key: "guard_sw",
                label: "Neutralise service workers",
                desc: "Off by default. On filtered sites, replace service-worker scripts with a no-op that unregisters itself, so pages are always served through Argus and get filtered. Trade-off: offline apps and push notifications stop working on those sites. Bypassed, exempt and unblocked sites are never touched.",
                kind: Kind::Switch,
                dep: None,
            },
            Def {
                key: "guard_sw_exempt",
                label: "Service-worker exempt hosts",
                desc: "Hosts left alone by the service-worker setting: example.com, or *.example.com for subdomains.",
                kind: Kind::Hosts,
                dep: Some("guard_sw"),
            },
            Def {
                key: "max_conns",
                label: "Max connections",
                desc: "Across both listeners. 0 means automatic.",
                kind: Kind::Num {
                    unit: "connections",
                    min: 0,
                    max: 1_000_000,
                },
                dep: None,
            },
            Def {
                key: "log_cap",
                label: "Request log size",
                desc: "Requests kept in the Logs page, and again for blocked-only. Applies at once; shrinking keeps the newest.",
                kind: Kind::Num {
                    unit: "entries",
                    min: 100,
                    max: 500_000,
                },
                dep: None,
            },
        ],
    },
    Section {
        id: "cname",
        title: "CNAME uncloaking",
        sub: "Catch trackers hidden behind a site's own sub-domain, as uBlock Origin does on Firefox. A request that is not blocked is checked again under the name its host really points to. Applied at once.",
        fields: &[
            Def {
                key: "cname_on",
                label: "Uncloak CNAMEs",
                desc: "Resolves each host once (the answer Argus connects with, so no extra lookup) and blocks the request when the name it is an alias of is blocked.",
                kind: Kind::Switch,
                dep: None,
            },
            Def {
                key: "cname_ignore",
                label: "Never uncloak these names",
                desc: "Canonical names left alone, with their subdomains: example.com or *.example.com.",
                kind: Kind::Hosts,
                dep: Some("cname_on"),
            },
            Def {
                key: "cname_1p",
                label: "Ignore same-site aliases",
                desc: "Skip an alias on the same site as the host (static.example.com pointing to cdn.example.com).",
                kind: Kind::Switch,
                dep: Some("cname_on"),
            },
            Def {
                key: "cname_exc",
                label: "Respect exceptions",
                desc: "Skip requests an exception rule (@@) already allows.",
                kind: Kind::Switch,
                dep: Some("cname_on"),
            },
            Def {
                key: "cname_root",
                label: "Ignore the page itself",
                desc: "Skip page loads and requests to the page's own host.",
                kind: Kind::Switch,
                dep: Some("cname_on"),
            },
            Def {
                key: "cname_ttl",
                label: "Remember aliases for",
                desc: "Longest time an alias is trusted. The DNS record's own lifetime still caps it.",
                kind: Kind::Num {
                    unit: "s",
                    min: 1,
                    max: 86_400,
                },
                dep: Some("cname_on"),
            },
            Def {
                key: "cname_full",
                label: "Check the full URL",
                desc: "Off checks only the scheme and host of the alias with a root path, as uBlock Origin does. On also tries the original path and query.",
                kind: Kind::Switch,
                dep: Some("cname_on"),
            },
        ],
    },
    Section {
        id: "upstream",
        title: "Upstream proxy",
        sub: "Send everything Argus connects to through another proxy. DNS lookups stay on Argus: it resolves and vets each address itself and gives the proxy only that address.",
        fields: &[
            Def {
                key: "up_on",
                label: "Enabled",
                desc: "When on, no connection leaves Argus directly. If the proxy is unreachable, connections fail.",
                kind: Kind::Switch,
                dep: None,
            },
            Def {
                key: "up_kind",
                label: "Type",
                desc: "HTTP uses CONNECT. SOCKS5 is sent the address, never a name.",
                kind: Kind::Seg(UPSTREAM_KINDS),
                dep: Some("up_on"),
            },
            Def {
                key: "up_host",
                label: "Host",
                desc: "Name or IP of the proxy. It may be on a private network, but never one of Argus's own listeners.",
                kind: Kind::Free,
                dep: Some("up_on"),
            },
            Def {
                key: "up_port",
                label: "Port",
                desc: "Port the proxy listens on.",
                kind: Kind::Port,
                dep: Some("up_on"),
            },
            Def {
                key: "up_user",
                label: "Username",
                desc: "Optional. Clearing it also clears the password.",
                kind: Kind::Free,
                dep: Some("up_on"),
            },
            Def {
                key: "up_pass",
                label: "Password",
                desc: "Write-only. Leave empty to keep the saved password. Changing the type, host or port drops it: enter it again.",
                kind: Kind::Secret,
                dep: Some("up_on"),
            },
        ],
    },
    Section {
        id: "access",
        title: "Network access",
        sub: "Who may use the proxy, and where it may connect.",
        fields: &[
            Def {
                key: "allow_clients",
                label: "Allowed clients",
                desc: "Source ranges. Others are refused.",
                kind: Kind::Cidr,
                dep: None,
            },
            Def {
                key: "allow_dest",
                label: "Allowed destinations",
                desc: "Destination ranges the proxy may reach. Empty means no restriction.",
                kind: Kind::Cidr,
                dep: None,
            },
            Def {
                key: "block_private",
                label: "Block private destinations",
                desc: "Refuse RFC 1918, loopback and link-local targets (SSRF guard).",
                kind: Kind::Switch,
                dep: None,
            },
        ],
    },
    Section {
        id: "stealth",
        title: "Stealth Mode",
        sub: "Limits what sites and trackers learn about you, after AdGuard's Stealth Mode. Off by default; the options below apply once it is on. Exceptions per site: @@||example.org^$stealth in a filter list or your rules turns every option off for requests to that site (add $domain=page.example to limit it to requests from a page, or a type such as $script), @@||example.org^$stealth=webrtc|3p-cookie only the listed ones (searchqueries, donottrack, 3p-cookie, 1p-cookie, 3p-cache, 3p-auth, webrtc, push, location, flash, java, referrer, useragent, ip, xclientdata, dpi). Hosts in full bypass and sites with blocking switched off are never touched.",
        fields: &[
            Def {
                key: "st_on",
                label: "Stealth Mode",
                desc: "Master switch. Applies to every device at once.",
                kind: Kind::Switch,
                dep: None,
            },
        ],
    },
    Section {
        id: "stealth_general",
        title: "Stealth Mode: general",
        sub: "",
        fields: &[
            Def {
                key: "st_search",
                label: "Hide search queries",
                desc: "When you open a site from a search engine's results, the site gets its own address as the Referer instead of the search page, so it cannot see your search words. Also applies to document.referrer.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
            Def {
                key: "st_dnt",
                label: "Ask websites not to track me",
                desc: "Sends Do Not Track and Global Privacy Control (DNT: 1, Sec-GPC: 1) and sets them in the page as well. Sites may ignore them.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
            Def {
                key: "st_params",
                label: "Remove tracking parameters from URLs",
                desc: "Off by default, as AdGuard does this with its URL Tracking filter. Strips utm_*, fbclid, gclid, yclid, mc_eid and similar from addresses, including in the address bar. Can break links that need them, such as some unsubscribe and email-login links.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
            Def {
                key: "st_referer",
                label: "Hide Referer from third parties",
                desc: "Requests to another site get that site's own address as the Referer instead of the page you were on. Form posts keep their Referer. May break sites that check the Referer, such as image hosts that block hotlinking.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
            Def {
                key: "st_referer_custom",
                label: "Custom Referer",
                desc: "Optional. Send this address instead. Empty uses the target site's own address.",
                kind: Kind::Free,
                dep: Some("st_referer"),
            },
            Def {
                key: "st_ua",
                label: "Hide User-Agent",
                desc: "Replaces the User-Agent with a generic one of the same browser (no exact version or system), and drops detailed client hints and extra languages. Sites that serve by browser or system may change or break; the page's own navigator.userAgent is not changed.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
            Def {
                key: "st_ua_custom",
                label: "Custom User-Agent",
                desc: "Optional. Send this instead. Must be a Chrome, Edge, Firefox or Safari User-Agent. The browser's own client hints are dropped and the connection to the site follows the browser this names, so use one close to yours; a very different one can break sites. Empty uses the generic one.",
                kind: Kind::Free,
                dep: Some("st_ua"),
            },
            Def {
                key: "st_xcd",
                label: "Remove X-Client-Data header",
                desc: "Stops Chrome from telling Google its version and experiments.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
            Def {
                key: "st_ip",
                label: "Mask IP address",
                desc: "Sends X-Forwarded-For with the address below. It cannot hide your real address: sites still see the connection's. Few sites read it, and some treat it as a proxy sign.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
            Def {
                key: "st_ip_addr",
                label: "IP address to send",
                desc: "Optional. Empty uses 203.0.113.1.",
                kind: Kind::Free,
                dep: Some("st_ip"),
            },
        ],
    },
    Section {
        id: "stealth_tracking",
        title: "Stealth Mode: tracking methods",
        sub: "",
        fields: &[
            Def {
                key: "st_c3p",
                label: "Delete third-party cookies",
                desc: "Cookies set by other sites expire after the time below. Can sign you out of social logins and embedded services.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
            Def {
                key: "st_c3p_min",
                label: "Third-party cookie lifetime",
                desc: "0 refuses them entirely. A cookie that already expires sooner keeps its shorter life.",
                kind: Kind::Num {
                    unit: "min",
                    min: 0,
                    max: 525_600,
                },
                dep: Some("st_c3p"),
            },
            Def {
                key: "st_c1p",
                label: "Delete first-party cookies (not recommended)",
                desc: "Cookies set by the site you are on expire after the time below. Signs you out of sites and loses settings.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
            Def {
                key: "st_c1p_min",
                label: "First-party cookie lifetime",
                desc: "0 refuses them entirely, which breaks logins.",
                kind: Kind::Num {
                    unit: "min",
                    min: 0,
                    max: 525_600,
                },
                dep: Some("st_c1p"),
            },
            Def {
                key: "st_etag",
                label: "Block ETag and If-None-Match headers",
                desc: "Third-party requests carry no cache validators, so a cache cannot be used to recognise you. Third-party files are downloaded every time.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
            Def {
                key: "st_auth",
                label: "Block third-party Authorization header",
                desc: "Stops saved credentials being sent to other sites. May break embedded services and extensions that authenticate that way.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
        ],
    },
    Section {
        id: "stealth_api",
        title: "Stealth Mode: browser API",
        sub: "Done by a script added to pages, so it needs ad blocking's page changes (HTML pages only) and does not run in pages that forbid scripts.",
        fields: &[
            Def {
                key: "st_webrtc",
                label: "Block WebRTC",
                desc: "Calls only go through TURN relays, so WebRTC cannot reveal your real address behind a proxy or VPN. Breaks video calls, messengers, streaming and games that connect directly.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
            Def {
                key: "st_push",
                label: "Block Push API",
                desc: "Sites cannot ask for or receive push notifications.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
            Def {
                key: "st_location",
                label: "Block Location API",
                desc: "Sites cannot read your location; they are told it was denied.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
            Def {
                key: "st_flash",
                label: "Block Flash",
                desc: "Kept for parity: browsers no longer run Flash, so this changes nothing.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
            Def {
                key: "st_java",
                label: "Block Java",
                desc: "Reports Java as unavailable to pages. Browsers no longer run Java plugins; JavaScript is not affected.",
                kind: Kind::Switch,
                dep: Some("st_on"),
            },
        ],
    },
    Section {
        id: "updates",
        title: "Filter list updates",
        sub: "Background fetch of all enabled lists.",
        fields: &[
            Def {
                key: "auto_update",
                label: "Auto-update",
                desc: "Lists recompile in the background.",
                kind: Kind::Switch,
                dep: None,
            },
            Def {
                key: "update_every",
                label: "Interval",
                desc: "Measured from the last successful fetch.",
                kind: Kind::Seg(HOURS),
                dep: Some("auto_update"),
            },
        ],
    },
];

fn defaults(key: &str) -> Val {
    match key {
        "explicit_host" => Val::S("::".into()),
        "explicit_port" => Val::S("8080".into()),
        "transparent_on" => Val::B(true),
        "transparent_port" => Val::S("3129".into()),
        "ext_on" => Val::B(false),
        "ext_port" => Val::S("3130".into()),
        "webui_host" => Val::S("0.0.0.0".into()),
        "webui_port" => Val::S("3000".into()),
        "conn_timeout" => Val::S("30".into()),
        "req_timeout" => Val::S("60".into()),
        "max_conns" => Val::S("0".into()),
        "log_cap" => Val::S("1000".into()),
        "allow_clients" => Val::T(
            [
                "127.0.0.0/8",
                "::1/128",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "100.64.0.0/10",
                "169.254.0.0/16",
                "fc00::/7",
                "fe80::/10",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        ),
        "allow_dest" => Val::T(Vec::new()),
        "block_private" => Val::B(false),
        "browser_like" => Val::B(true),
        "block_response" => Val::S("fail".into()),
        "guard_sw" => Val::B(false),
        "guard_sw_exempt" => Val::T(Vec::new()),
        "cname_on" | "cname_1p" | "cname_exc" | "cname_root" => Val::B(true),
        "cname_full" => Val::B(false),
        "cname_ignore" => Val::T(Vec::new()),
        "cname_ttl" => Val::S("600".into()),
        "up_on" => Val::B(false),
        "up_kind" => Val::S("http".into()),
        "up_host" | "up_user" | "up_pass" => Val::S(String::new()),
        "up_port" => Val::S("8080".into()),
        "auto_update" => Val::B(true),
        "lists_url" | "lists_key" => Val::S(String::new()),
        "st_on" | "st_c1p" | "st_ua" | "st_ip" | "st_auth" | "st_params" | "st_webrtc"
        | "st_push" | "st_location" => Val::B(false),
        "st_search" | "st_dnt" | "st_referer" | "st_xcd" | "st_c3p" | "st_etag" | "st_flash"
        | "st_java" => Val::B(true),
        "st_referer_custom" | "st_ua_custom" | "st_ip_addr" => Val::S(String::new()),
        "st_c3p_min" => Val::S("2880".into()),
        "st_c1p_min" => Val::S("4320".into()),
        _ => Val::S("24".into()),
    }
}

fn from_config(c: &ProxyConfigResponse) -> Vec<(&'static str, Val)> {
    vec![
        ("explicit_host", Val::S(c.host.clone())),
        ("explicit_port", Val::S(c.port.to_string())),
        ("transparent_on", Val::B(c.transparent_port.is_some())),
        (
            "transparent_port",
            Val::S(c.transparent_port.unwrap_or(3129).to_string()),
        ),
        ("ext_on", Val::B(c.ext_port.is_some())),
        ("ext_port", Val::S(c.ext_port.unwrap_or(3130).to_string())),
        ("webui_host", Val::S(c.webui_host.clone())),
        ("webui_port", Val::S(c.webui_port.to_string())),
        (
            "conn_timeout",
            Val::S(c.connection_timeout_secs.to_string()),
        ),
        ("req_timeout", Val::S(c.request_timeout_secs.to_string())),
        ("max_conns", Val::S(c.max_connections.to_string())),
        ("log_cap", Val::S(c.request_log_capacity.to_string())),
        ("allow_clients", Val::T(c.allowed_clients.clone())),
        ("allow_dest", Val::T(c.allowed_destinations.clone())),
        ("block_private", Val::B(c.block_private_destinations)),
        ("browser_like", Val::B(c.browser_like_upstream)),
        ("block_response", Val::S(c.block_response.clone())),
        ("guard_sw", Val::B(c.guard_service_workers)),
        (
            "guard_sw_exempt",
            Val::T(c.guard_service_workers_exempt.clone()),
        ),
        ("cname_on", Val::B(c.cname.enabled)),
        ("cname_ignore", Val::T(c.cname.ignore_list.clone())),
        ("cname_1p", Val::B(c.cname.ignore_first_party)),
        ("cname_exc", Val::B(c.cname.ignore_exceptions)),
        ("cname_root", Val::B(c.cname.ignore_root_document)),
        ("cname_ttl", Val::S(c.cname.max_ttl_secs.to_string())),
        ("cname_full", Val::B(c.cname.replay_full_url)),
        ("up_on", Val::B(c.upstream_proxy.enabled)),
        (
            "up_kind",
            Val::S(
                match c.upstream_proxy.kind {
                    api_types::UpstreamProxyKind::Http => "http",
                    api_types::UpstreamProxyKind::Socks5 => "socks5",
                }
                .into(),
            ),
        ),
        ("up_host", Val::S(c.upstream_proxy.host.clone())),
        ("up_port", Val::S(c.upstream_proxy.port.to_string())),
        ("up_user", Val::S(c.upstream_proxy.username.clone())),
        // Never filled in: the server does not send it.
        ("up_pass", Val::S(String::new())),
        ("auto_update", Val::B(c.auto_update)),
        ("update_every", Val::S(c.update_interval_hours.to_string())),
        ("lists_url", Val::S(c.bypass.lists_base_url.clone())),
        ("lists_key", Val::S(c.bypass.lists_public_key.clone())),
        ("st_on", Val::B(c.stealth.enabled)),
        ("st_search", Val::B(c.stealth.hide_search_queries)),
        ("st_dnt", Val::B(c.stealth.send_dnt)),
        ("st_params", Val::B(c.stealth.strip_tracking_params)),
        ("st_referer", Val::B(c.stealth.hide_referer)),
        (
            "st_referer_custom",
            Val::S(c.stealth.referer_custom.clone()),
        ),
        ("st_ua", Val::B(c.stealth.hide_user_agent)),
        ("st_ua_custom", Val::S(c.stealth.user_agent_custom.clone())),
        ("st_ip", Val::B(c.stealth.mask_ip)),
        ("st_ip_addr", Val::S(c.stealth.mask_ip_address.clone())),
        ("st_xcd", Val::B(c.stealth.remove_x_client_data)),
        ("st_c3p", Val::B(c.stealth.third_party_cookies)),
        (
            "st_c3p_min",
            Val::S(c.stealth.third_party_cookie_minutes.to_string()),
        ),
        ("st_c1p", Val::B(c.stealth.first_party_cookies)),
        (
            "st_c1p_min",
            Val::S(c.stealth.first_party_cookie_minutes.to_string()),
        ),
        ("st_etag", Val::B(c.stealth.block_etag)),
        ("st_auth", Val::B(c.stealth.block_third_party_auth)),
        ("st_webrtc", Val::B(c.stealth.block_webrtc)),
        ("st_push", Val::B(c.stealth.block_push)),
        ("st_location", Val::B(c.stealth.block_location)),
        ("st_flash", Val::B(c.stealth.block_flash)),
        ("st_java", Val::B(c.stealth.block_java)),
    ]
}

/// Backend field names a settings key maps to (as listed in `applied` / `restart_required`).
fn backend_names(key: &str) -> &'static [&'static str] {
    match key {
        "explicit_host" => &["host"],
        "explicit_port" => &["port"],
        "transparent_on" | "transparent_port" => &["transparent_port"],
        "ext_on" | "ext_port" => &["ext_port"],
        "webui_host" => &["webui_host"],
        "webui_port" => &["webui_port"],
        "conn_timeout" => &["connection_timeout_secs"],
        "req_timeout" => &["request_timeout_secs"],
        "max_conns" => &["max_connections"],
        "log_cap" => &["request_log_capacity"],
        "allow_clients" => &["allowed_clients"],
        "allow_dest" => &["allowed_destinations"],
        "block_private" => &["block_private_destinations"],
        "browser_like" => &["browser_like_upstream"],
        "block_response" => &["block_response"],
        "guard_sw" => &["guard_service_workers"],
        "guard_sw_exempt" => &["guard_service_workers_exempt"],
        "up_on" | "up_kind" | "up_host" | "up_port" | "up_user" | "up_pass" => &["upstream_proxy"],
        "auto_update" => &["auto_update"],
        "lists_url" | "lists_key" => &["bypass"],
        k if k.starts_with("st_") => &["stealth"],
        k if k.starts_with("cname_") => &["cname"],
        _ => &["update_interval_hours"],
    }
}

/// Memory hint for the request-log size: about 1 KB per entry in each of the two rings.
fn log_cap_hint(v: &str) -> String {
    match v.trim().parse::<u64>() {
        Ok(n) if (100..=500_000).contains(&n) => {
            let kb = n * 2;
            if kb >= 1024 {
                format!(" About {:.1} MB of memory.", kb as f64 / 1024.0)
            } else {
                format!(" About {kb} KB of memory.")
            }
        }
        _ => " About 1 KB of memory per entry, in each of two lists.".into(),
    }
}

fn host_ok(s: &str) -> bool {
    s == "localhost" || s.parse::<IpAddr>().is_ok()
}

fn cidr_ok(s: &str) -> bool {
    match s.split_once('/') {
        Some((ip, bits)) => match (ip.parse::<IpAddr>(), bits.parse::<u8>()) {
            (Ok(IpAddr::V4(_)), Ok(b)) => b <= 32,
            (Ok(IpAddr::V6(_)), Ok(b)) => b <= 128,
            _ => false,
        },
        None => s.parse::<IpAddr>().is_ok(),
    }
}

/// Validation of the upstream proxy fields (`get` reads the current value of a field).
fn upstream_error(key: &str, get: &dyn Fn(&str) -> String) -> Option<String> {
    match key {
        "up_host" if get("up_host").trim().is_empty() => {
            Some("Enter the proxy's host name or IP.".into())
        }
        "up_host" if get("up_host").trim().contains(char::is_whitespace) => {
            Some("A host has no spaces.".into())
        }
        "up_pass" if get("up_user").trim().is_empty() && !get("up_pass").is_empty() => {
            Some("A password needs a username.".into())
        }
        // The server never sends the saved password to another address.
        "up_pass"
            if get("up_ep_changed") == "true"
                && !get("up_user").trim().is_empty()
                && get("up_pass").is_empty() =>
        {
            Some("The address changed: enter the password again, or clear the username.".into())
        }
        _ => None,
    }
}

/// Whether the proxy's type, host or port differ from the saved ones.
fn endpoint_changed(all: &[F]) -> bool {
    all.iter().any(|f| {
        matches!(f.def.key, "up_kind" | "up_host" | "up_port")
            && f.cur.get_untracked() != f.saved.get_untracked()
    })
}

/// The upstream proxy part of a save (`None` when nothing of it changed). `dirty` says whether
/// a field changed; an empty password is left out, so the saved one is kept (the server drops it
/// when the type, host or port changed, so then the username is sent along too).
fn upstream_update(
    get: &dyn Fn(&str) -> String,
    dirty: &dyn Fn(&str) -> bool,
) -> Option<api_types::UpstreamProxyUpdate> {
    let keys = [
        "up_on", "up_kind", "up_host", "up_port", "up_user", "up_pass",
    ];
    if !keys.iter().any(|k| dirty(k)) {
        return None;
    }
    let ep = dirty("up_kind") || dirty("up_host") || dirty("up_port");
    Some(api_types::UpstreamProxyUpdate {
        enabled: dirty("up_on").then(|| get("up_on") == "true"),
        kind: (ep || dirty("up_kind")).then(|| match get("up_kind").as_str() {
            "socks5" => api_types::UpstreamProxyKind::Socks5,
            _ => api_types::UpstreamProxyKind::Http,
        }),
        host: (ep || dirty("up_host")).then(|| get("up_host").trim().to_string()),
        port: (ep || dirty("up_port")).then(|| get("up_port").trim().parse().unwrap_or(0)),
        username: (ep || dirty("up_user")).then(|| get("up_user").trim().to_string()),
        password: Some(get("up_pass")).filter(|p| (dirty("up_pass") || ep) && !p.is_empty()),
    })
}

fn is_on(all: &[F], key: &str) -> bool {
    all.iter()
        .find(|f| f.def.key == key)
        .map(|f| f.cur.read().b())
        .unwrap_or(true)
}

/// Validation message for a field, given the current values of all fields.
fn error_of(f: &F, all: &[F]) -> Option<String> {
    if let Some(dep) = f.def.dep {
        if !is_on(all, dep) {
            return None;
        }
    }
    let v = f.cur.read();
    let get = |k: &str| {
        if k == "up_ep_changed" {
            return endpoint_changed(all).to_string();
        }
        all.iter()
            .find(|x| x.def.key == k)
            .map(|x| x.cur.read().s())
            .unwrap_or_default()
    };
    if f.def.key.starts_with("up_") {
        if let Some(e) = upstream_error(f.def.key, &get) {
            return Some(e);
        }
    }
    match f.def.key {
        "st_ip_addr" if !v.s().trim().is_empty() && v.s().trim().parse::<IpAddr>().is_err() => {
            return Some("Enter an IP address, or leave empty.".into());
        }
        "st_ua_custom"
            if {
                let t = v.s();
                let t = t.trim();
                let known = ["Firefox/", "FxiOS/", "CriOS/", "Chrome/", "Edg/"]
                    .iter()
                    .any(|m| t.contains(m))
                    || (t.contains("Safari/") && t.contains("Version/"));
                !t.is_empty() && !known
            } =>
        {
            return Some(
                "Use a Chrome, Edge, Firefox or Safari User-Agent, or leave empty.".into(),
            );
        }
        "st_referer_custom"
            if {
                let t = v.s();
                let t = t.trim();
                !t.is_empty() && !t.starts_with("https://") && !t.starts_with("http://")
            } =>
        {
            return Some("Enter a URL such as https://example.org/, or leave empty.".into());
        }
        _ => {}
    }
    match f.def.kind {
        Kind::Port | Kind::Num { .. } => {
            let s = v.s();
            let Ok(n) = s.trim().parse::<u64>() else {
                return Some("Enter a whole number.".into());
            };
            if let Kind::Num { min, max, .. } = f.def.kind {
                if n < min || n > max {
                    return Some(format!("Use {min} to {max}."));
                }
            } else {
                if !(1..=65535).contains(&n) {
                    return Some("Use a port from 1 to 65535.".into());
                }
                // The upstream proxy is another machine's port, not one of ours.
                if f.def.key == "up_port" {
                    return None;
                }
                let others = [
                    ("explicit_port", "explicit proxy"),
                    ("transparent_port", "transparent listener"),
                    ("ext_port", "extension listener"),
                    ("webui_port", "web UI"),
                ];
                for (k, name) in others {
                    if k == f.def.key
                        || (k == "transparent_port" && !is_on(all, "transparent_on"))
                        || (k == "ext_port" && !is_on(all, "ext_on"))
                    {
                        continue;
                    }
                    if get(k).trim().parse::<u64>() == Ok(n) {
                        return Some(format!("Port {n} is already used by the {name}."));
                    }
                }
            }
            None
        }
        Kind::Text if !host_ok(v.s().trim()) => {
            Some("Enter an IP address such as 0.0.0.0 or ::.".into())
        }
        Kind::Cidr if f.def.key == "allow_clients" && v.t().is_empty() => {
            Some("Add at least one range, or every client is refused.".into())
        }
        _ => None,
    }
}

#[derive(Clone, PartialEq)]
enum Bar {
    Edit,
    Confirm,
    Redirect(u32, String),
}

fn build_request(all: &[F]) -> UpdateProxyConfigRequest {
    let dirty = |k: &str| {
        all.iter()
            .any(|f| f.def.key == k && f.cur.get_untracked() != f.saved.get_untracked())
    };
    let val = |k: &str| {
        all.iter()
            .find(|f| f.def.key == k)
            .map(|f| f.cur.get_untracked())
            .unwrap_or(Val::S(String::new()))
    };
    let num = |k: &str| val(k).s().trim().parse::<u64>().unwrap_or(0);
    let mut r = UpdateProxyConfigRequest::default();
    if dirty("explicit_host") {
        r.host = Some(val("explicit_host").s().trim().to_string());
    }
    if dirty("explicit_port") {
        r.port = Some(num("explicit_port") as u16);
    }
    if dirty("transparent_on") || dirty("transparent_port") {
        r.transparent_port = Some(if val("transparent_on").b() {
            num("transparent_port") as u16
        } else {
            0
        });
    }
    if dirty("ext_on") || dirty("ext_port") {
        r.ext_port = Some(if val("ext_on").b() {
            num("ext_port") as u16
        } else {
            0
        });
    }
    if dirty("webui_host") {
        r.webui_host = Some(val("webui_host").s().trim().to_string());
    }
    if dirty("webui_port") {
        r.webui_port = Some(num("webui_port") as u16);
    }
    if dirty("conn_timeout") {
        r.connection_timeout_secs = Some(num("conn_timeout"));
    }
    if dirty("req_timeout") {
        r.request_timeout_secs = Some(num("req_timeout"));
    }
    if dirty("max_conns") {
        r.max_connections = Some(num("max_conns") as u32);
    }
    if dirty("log_cap") {
        r.request_log_capacity = Some(num("log_cap") as u32);
    }
    if dirty("allow_clients") {
        r.allowed_clients = Some(val("allow_clients").t());
    }
    if dirty("allow_dest") {
        r.allowed_destinations = Some(val("allow_dest").t());
    }
    if dirty("block_private") {
        r.block_private_destinations = Some(val("block_private").b());
    }
    if dirty("browser_like") {
        r.browser_like_upstream = Some(val("browser_like").b());
    }
    if dirty("block_response") {
        r.block_response = Some(val("block_response").s());
    }
    if dirty("guard_sw_exempt") {
        r.guard_service_workers_exempt = Some(val("guard_sw_exempt").t());
    }
    if dirty("guard_sw") {
        r.guard_service_workers = Some(val("guard_sw").b());
    }
    if [
        "cname_on",
        "cname_ignore",
        "cname_1p",
        "cname_exc",
        "cname_root",
        "cname_ttl",
        "cname_full",
    ]
    .iter()
    .any(|k| dirty(k))
    {
        r.cname = Some(api_types::CnameUpdate {
            enabled: dirty("cname_on").then(|| val("cname_on").b()),
            ignore_list: dirty("cname_ignore").then(|| val("cname_ignore").t()),
            ignore_first_party: dirty("cname_1p").then(|| val("cname_1p").b()),
            ignore_exceptions: dirty("cname_exc").then(|| val("cname_exc").b()),
            ignore_root_document: dirty("cname_root").then(|| val("cname_root").b()),
            max_ttl_secs: dirty("cname_ttl").then(|| num("cname_ttl")),
            replay_full_url: dirty("cname_full").then(|| val("cname_full").b()),
        });
    }
    r.upstream_proxy = upstream_update(&|k| val(k).s(), &dirty);
    if dirty("auto_update") {
        r.auto_update = Some(val("auto_update").b());
    }
    if dirty("update_every") {
        r.update_interval_hours = Some(num("update_every"));
    }
    if dirty("lists_url") || dirty("lists_key") {
        r.bypass = Some(api_types::BypassSourceUpdate {
            lists_base_url: dirty("lists_url").then(|| val("lists_url").s()),
            lists_public_key: dirty("lists_key").then(|| val("lists_key").s()),
        });
    }
    if [
        "st_on",
        "st_search",
        "st_dnt",
        "st_params",
        "st_referer",
        "st_referer_custom",
        "st_ua",
        "st_ua_custom",
        "st_ip",
        "st_ip_addr",
        "st_xcd",
        "st_c3p",
        "st_c3p_min",
        "st_c1p",
        "st_c1p_min",
        "st_etag",
        "st_auth",
        "st_webrtc",
        "st_push",
        "st_location",
        "st_flash",
        "st_java",
    ]
    .iter()
    .any(|k| dirty(k))
    {
        r.stealth = Some(api_types::StealthUpdate {
            enabled: dirty("st_on").then(|| val("st_on").b()),
            hide_search_queries: dirty("st_search").then(|| val("st_search").b()),
            send_dnt: dirty("st_dnt").then(|| val("st_dnt").b()),
            strip_tracking_params: dirty("st_params").then(|| val("st_params").b()),
            hide_referer: dirty("st_referer").then(|| val("st_referer").b()),
            referer_custom: dirty("st_referer_custom")
                .then(|| val("st_referer_custom").s().trim().to_string()),
            hide_user_agent: dirty("st_ua").then(|| val("st_ua").b()),
            user_agent_custom: dirty("st_ua_custom")
                .then(|| val("st_ua_custom").s().trim().to_string()),
            mask_ip: dirty("st_ip").then(|| val("st_ip").b()),
            mask_ip_address: dirty("st_ip_addr").then(|| val("st_ip_addr").s().trim().to_string()),
            remove_x_client_data: dirty("st_xcd").then(|| val("st_xcd").b()),
            third_party_cookies: dirty("st_c3p").then(|| val("st_c3p").b()),
            third_party_cookie_minutes: dirty("st_c3p_min").then(|| num("st_c3p_min") as u32),
            first_party_cookies: dirty("st_c1p").then(|| val("st_c1p").b()),
            first_party_cookie_minutes: dirty("st_c1p_min").then(|| num("st_c1p_min") as u32),
            block_etag: dirty("st_etag").then(|| val("st_etag").b()),
            block_third_party_auth: dirty("st_auth").then(|| val("st_auth").b()),
            block_webrtc: dirty("st_webrtc").then(|| val("st_webrtc").b()),
            block_push: dirty("st_push").then(|| val("st_push").b()),
            block_location: dirty("st_location").then(|| val("st_location").b()),
            block_flash: dirty("st_flash").then(|| val("st_flash").b()),
            block_java: dirty("st_java").then(|| val("st_java").b()),
        });
    }
    r
}

#[component]
pub fn SettingsPage() -> impl IntoView {
    view! { <Layout class="settings-screen"><RequireAdmin><SettingsInner /></RequireAdmin></Layout> }
}

#[component]
fn SettingsInner() -> impl IntoView {
    let app = use_app_state();
    let all: Vec<F> = SECTIONS
        .iter()
        .flat_map(|s| s.fields.iter())
        .map(|d| F {
            def: *d,
            cur: RwSignal::new(defaults(d.key)),
            saved: RwSignal::new(defaults(d.key)),
            default: RwSignal::new(defaults(d.key)),
            msg: RwSignal::new(None),
        })
        .collect();
    let loaded = RwSignal::new(false);
    let bar = RwSignal::new(Bar::Edit);
    let busy = RwSignal::new(false);
    let cancel_redirect = StoredValue::new(false);

    let apply_values = {
        let all = all.clone();
        move |c: &ProxyConfigResponse, only_clean: bool| {
            if let Some(b) = &c.bind {
                if let (Some(a), Some(f)) = (
                    &b.webui_moved_to,
                    all.iter().find(|f| f.def.key == "webui_port"),
                ) {
                    f.msg.set(Some((
                        true,
                        format!("Web UI is on {a} because the configured port is in use. Change the port here."),
                    )));
                }
                for (down, keys) in [
                    (b.proxy_down, ["explicit_host", "explicit_port"]),
                    (b.transparent_down, ["transparent_on", "transparent_port"]),
                    (b.webui_down, ["webui_host", "webui_port"]),
                ] {
                    if down {
                        for k in keys {
                            if let Some(f) = all.iter().find(|f| f.def.key == k) {
                                f.msg.set(Some((
                                    true,
                                    "Listener is down. Save again to retry.".into(),
                                )));
                            }
                        }
                    }
                }
            }
            for (k, v) in from_config(c) {
                if let Some(f) = all.iter().find(|f| f.def.key == k) {
                    let was_dirty = f.cur.get_untracked() != f.saved.get_untracked();
                    f.saved.set(v.clone());
                    if !only_clean || !was_dirty {
                        f.cur.set(v);
                    }
                }
            }
        }
    };
    {
        let app = app.clone();
        let apply_values = apply_values.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match ApiClient::new().get_proxy_config().await {
                Ok(c) => {
                    apply_values(&c, false);
                    loaded.set(true);
                }
                Err(e) => app.error(format!("Failed to load settings: {e}")),
            }
        });
    }

    {
        let all = all.clone();
        wasm_bindgen_futures::spawn_local(async move {
            if let Ok(d) = ApiClient::new()
                .get::<ProxyConfigResponse>("/config/defaults")
                .await
            {
                for (k, v) in from_config(&d) {
                    if let Some(f) = all.iter().find(|f| f.def.key == k) {
                        f.default.set(v);
                    }
                }
            }
        });
    }

    let dirty_fields = {
        let all = all.clone();
        move || {
            all.iter()
                .filter(|f| f.cur.get() != f.saved.get())
                .copied()
                .collect::<Vec<F>>()
        }
    };
    let error_count = {
        let all = all.clone();
        move || all.iter().filter(|f| error_of(f, &all).is_some()).count()
    };

    let apply = {
        let all = all.clone();
        let app = app.clone();
        let apply_values = apply_values.clone();
        move || {
            let req = build_request(&all);
            let dirty: Vec<F> = all
                .iter()
                .filter(|f| f.cur.get_untracked() != f.saved.get_untracked())
                .copied()
                .collect();
            let moved = dirty
                .iter()
                .any(|f| matches!(f.def.key, "webui_host" | "webui_port"));
            let new_port = all
                .iter()
                .find(|f| f.def.key == "webui_port")
                .map(|f| f.cur.get_untracked().s())
                .unwrap_or_default();
            busy.set(true);
            let (all, app, apply_values) = (all.clone(), app.clone(), apply_values.clone());
            wasm_bindgen_futures::spawn_local(async move {
                match ApiClient::new().update_proxy_config_full(&req).await {
                    Ok(r) => {
                        apply_values(&r.config, false);
                        let mut live = 0;
                        for f in &dirty {
                            let names = backend_names(f.def.key);
                            let msg = if names
                                .iter()
                                .any(|n| r.restart_required.iter().any(|x| x == n))
                            {
                                "Saved. Applies after a restart."
                            } else {
                                live += 1;
                                "Applied live"
                            };
                            f.msg.set(Some((false, msg.to_string())));
                        }
                        app.success(format!(
                            "{} setting{} saved",
                            dirty.len(),
                            if dirty.len() == 1 { "" } else { "s" }
                        ));
                        let _ = live;
                        let all2 = all.clone();
                        gloo_timers::callback::Timeout::new(5000, move || {
                            for f in &all2 {
                                if matches!(f.msg.get_untracked(), Some((false, _))) {
                                    f.msg.set(None);
                                }
                            }
                        })
                        .forget();
                        if moved {
                            let loc = web_sys::window().map(|w| w.location());
                            let proto = loc
                                .as_ref()
                                .and_then(|l| l.protocol().ok())
                                .unwrap_or_else(|| "http:".into());
                            let host = loc
                                .as_ref()
                                .and_then(|l| l.hostname().ok())
                                .unwrap_or_default();
                            let port = r.config.webui_port.to_string();
                            let port = if port.is_empty() { new_port } else { port };
                            let url = format!("{proto}//{host}:{port}/settings");
                            cancel_redirect.set_value(false);
                            bar.set(Bar::Redirect(5, url.clone()));
                            for left in (0..5).rev() {
                                gloo_timers::future::TimeoutFuture::new(1000).await;
                                if cancel_redirect.get_value() {
                                    return;
                                }
                                if left == 0 {
                                    if let Some(w) = web_sys::window() {
                                        let _ = w.location().set_href(&url);
                                    }
                                } else {
                                    bar.set(Bar::Redirect(left, url.clone()));
                                }
                            }
                        } else {
                            bar.set(Bar::Edit);
                        }
                    }
                    Err(e) => {
                        let (txt, bind) = match &e {
                            ApiError::Conflict(m) => (m.clone(), true),
                            other => (other.to_string(), false),
                        };
                        for f in &dirty {
                            let listener = matches!(
                                f.def.key,
                                "explicit_host"
                                    | "explicit_port"
                                    | "transparent_port"
                                    | "transparent_on"
                                    | "ext_port"
                                    | "ext_on"
                                    | "webui_host"
                                    | "webui_port"
                            );
                            if bind && listener {
                                let old = f.saved.get_untracked().s();
                                f.cur.set(f.saved.get_untracked());
                                f.msg.set(Some((true, format!("{txt}. Kept {old}."))));
                            } else if !bind {
                                f.msg.set(Some((true, txt.clone())));
                            }
                        }
                        app.error(if bind {
                            "A listener could not bind. See the highlighted field.".to_string()
                        } else {
                            format!("Failed to save: {txt}")
                        });
                        bar.set(Bar::Edit);
                    }
                }
                busy.set(false);
            });
        }
    };

    let on_save = {
        let all = all.clone();
        let apply = apply.clone();
        move |_: web_sys::MouseEvent| {
            if all.iter().any(|f| error_of(f, &all).is_some()) {
                return;
            }
            let moving = all.iter().any(|f| {
                matches!(f.def.key, "webui_host" | "webui_port")
                    && f.cur.get_untracked() != f.saved.get_untracked()
            });
            let key_changed = all.iter().any(|f| {
                f.def.key == "lists_key" && f.cur.get_untracked() != f.saved.get_untracked()
            });
            if moving || key_changed {
                bar.set(Bar::Confirm);
            } else {
                apply();
            }
        }
    };
    let on_discard = {
        let all = all.clone();
        move |_: web_sys::MouseEvent| {
            for f in &all {
                f.cur.set(f.saved.get_untracked());
                f.msg.set(None);
            }
            app.info("Changes discarded");
        }
    };

    let jump = |id: &'static str| {
        if let Some(el) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id(&format!("set-{id}")))
        {
            el.scroll_into_view();
        }
    };

    let rows_for = {
        let all = all.clone();
        move |s: &'static Section| {
            let fields: Vec<F> = all
                .iter()
                .filter(|f| s.fields.iter().any(|d| d.key == f.def.key))
                .copied()
                .collect();
            fields
                .into_iter()
                .map(|f| row(f, all.clone()))
                .collect_view()
        }
    };

    let dirty_n = dirty_fields.clone();
    let all_t = all.clone();
    view! {
        <div class="set-intro">
            <p class="muted">"Every setting lives here. Changes apply live when you save, with no restart and no config file to edit."</p>
            <nav class="chips" aria-label="Settings sections">
                {SECTIONS.iter().map(|s| { let id = s.id; view! {
                    <a class="chip link" href=format!("#set-{id}") on:click=move |ev| { ev.prevent_default(); jump(id); }>{s.title}</a>
                } }).collect_view()}
                <a class="chip link" href="#set-https" on:click=move |ev| { ev.prevent_default(); jump("https"); }>"HTTPS"</a>
            </nav>
        </div>
        <Show when=move || loaded.get() fallback=|| view! { <div class="empty"><span class="spin"></span></div> }>
            <div class="set-cards">
                {SECTIONS.iter().map(|s| view! {
                    <div class="card" id=format!("set-{}", s.id)>
                        <div class="card-h"><h3>{s.title}</h3><span class="sub">{s.sub}</span></div>
                        <div>{rows_for(s)}</div>
                        {(s.id == "upstream").then(|| view! { <UpstreamTest all=all_t.clone() /> })}
                    </div>
                }).collect_view()}
                <super::settings_https::HttpsCard />
            </div>
        </Show>
        <Show when=move || !dirty_n().is_empty() || matches!(bar.get(), Bar::Redirect(..))>
            <div
                class=move || match bar.get() { Bar::Confirm => "savebar warn", Bar::Redirect(..) => "savebar go", _ => "savebar" }
                role="region"
                aria-label="Unsaved settings"
            >
                {
                    let dirty_fields = dirty_fields.clone();
                    let error_count = error_count.clone();
                    let (on_save, on_discard, apply) = (on_save.clone(), on_discard.clone(), apply.clone());
                    move || match bar.get() {
                        Bar::Redirect(n, url) => {
                            let u2 = url.clone();
                            view! {
                                <div class="sb-msg" aria-live="polite">
                                    <span class="countdown">{format!("{n}s")}</span>
                                    <span>"Web UI applied. Redirecting to "<b class="mono">{url.clone()}</b>"."</span>
                                </div>
                                <div class="sb-act">
                                    <button class="btn" type="button" on:click=move |_| { cancel_redirect.set_value(true); bar.set(Bar::Edit); }>"Stay on this page"</button>
                                    <button class="btn primary" type="button" on:click=move |_| { cancel_redirect.set_value(true); if let Some(w) = web_sys::window() { let _ = w.location().set_href(&u2); } }>"Go now"</button>
                                </div>
                            }.into_any()
                        }
                        Bar::Confirm => {
                            let apply = apply.clone();
                            let key_changed = dirty_fields().iter().any(|f| f.def.key == "lists_key");
                            let (msg, label) = if key_changed {
                                ("Changing the lists key: installed lists, trusted roots and catalogues signed with the old key are dropped until the new source verifies. Until then HTTPS is tunnelled, not decrypted.", "Change key and save")
                            } else {
                                ("The web UI will move. This page reconnects at the new address; other open sessions must reload.", "Move web UI and save")
                            };
                            view! {
                                <div class="sb-msg" aria-live="polite"><span>{msg}</span></div>
                                <div class="sb-act">
                                    <button class="btn" type="button" on:click=move |_| bar.set(Bar::Edit)>"Back"</button>
                                    <button class="btn primary" type="button" disabled=move || busy.get() on:click=move |_| apply()>{label}</button>
                                </div>
                            }.into_any()
                        }
                        Bar::Edit => {
                            let d = dirty_fields();
                            let errs = error_count();
                            let names: Vec<&str> = d.iter().map(|f| f.def.label).take(3).collect();
                            let more = d.len().saturating_sub(3);
                            let (on_save, on_discard) = (on_save.clone(), on_discard.clone());
                            view! {
                                <div class="sb-msg" aria-live="polite">
                                    <span class="sb-count">{d.len()}</span>
                                    <span>
                                        <b>{if d.len() == 1 { "Unsaved change" } else { "Unsaved changes" }}</b>
                                        <span class="dim">{format!(" · {}{}", names.join(", "), if more > 0 { format!(" and {more} more") } else { String::new() })}</span>
                                    </span>
                                    {(errs > 0).then(|| view! { <span class="err">{format!(" · fix {errs} error{} to save", if errs == 1 { "" } else { "s" })}</span> })}
                                </div>
                                <div class="sb-act">
                                    <button class="btn ghost" type="button" on:click=on_discard>"Discard"</button>
                                    <button class="btn primary" type="button" disabled={move || errs > 0 || busy.get()} on:click=on_save>"Save and apply"</button>
                                </div>
                            }.into_any()
                        }
                    }
                }
            </div>
        </Show>
    }
}

/// Tests the upstream proxy with the values on screen (saved or not).
#[component]
fn UpstreamTest(all: Vec<F>) -> impl IntoView {
    let result = RwSignal::new(Option::<(bool, String)>::None);
    let busy = RwSignal::new(false);
    let on_click = move |_| {
        let get = |k: &str| {
            if k == "up_ep_changed" {
                return endpoint_changed(&all).to_string();
            }
            all.iter()
                .find(|f| f.def.key == k)
                .map(|f| f.cur.get_untracked().s())
                .unwrap_or_default()
        };
        if let Some(e) = ["up_host", "up_pass"]
            .iter()
            .find_map(|k| upstream_error(k, &get))
        {
            result.set(Some((true, e)));
            return;
        }
        let req = upstream_update(&get, &|_| true).unwrap_or_default();
        busy.set(true);
        result.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            let r = ApiClient::new()
                .post::<api_types::UpstreamProxyTestResult, _>("/config/upstream-proxy/test", &req)
                .await;
            result.set(Some(match r {
                Ok(v) if v.ok => (
                    false,
                    format!(
                        "Reached {} through the proxy in {} ms.",
                        v.target,
                        v.latency_ms.unwrap_or(0)
                    ),
                ),
                Ok(v) => (true, v.error.unwrap_or_else(|| "The test failed.".into())),
                Err(e) => (true, e.to_string()),
            }));
            busy.set(false);
        });
    };
    view! {
        <div class="frow">
            <div class="fl">
                <span class="lname">"Test"</span>
                <small>"Argus connects to a well-known HTTPS site through the proxy. Uses the values above, saved or not."</small>
            </div>
            <div class="fc">
                <button class="btn" type="button" disabled=move || busy.get() on:click=on_click>
                    {move || if busy.get() { "Testing…" } else { "Test proxy" }}
                </button>
                <span
                    class=move || match result.get() { Some((true, _)) => "fmsg bad", Some((false, _)) => "fmsg ok", None => "fmsg" }
                    role="status"
                    aria-live="polite"
                >
                    {move || result.get().map(|(_, m)| m).unwrap_or_default()}
                </span>
            </div>
        </div>
    }
}

fn row(f: F, all: Vec<F>) -> impl IntoView {
    let id = format!("set-f-{}", f.def.key);
    let label_id = format!("{id}-l");
    let msg_id = format!("{id}-m");
    let d = f.def;
    let all_e = all.clone();
    let all_o = all.clone();
    let dirty = move || f.cur.get() != f.saved.get();
    let modified = move || f.cur.get() != f.default.get();
    let off = Signal::derive(move || d.dep.map(|k| !is_on(&all_o, k)).unwrap_or(false));
    let err = Signal::derive(move || error_of(&f, &all_e));
    let is_label = matches!(
        d.kind,
        Kind::Text | Kind::Free | Kind::Secret | Kind::Port | Kind::Num { .. }
    );
    let default_txt = move || {
        let v = f.default.get();
        match d.kind {
            Kind::Switch => {
                if v.b() {
                    "on".to_string()
                } else {
                    "off".to_string()
                }
            }
            _ => v.s(),
        }
    };

    let control = match d.kind {
        Kind::Switch => view! {
            <Switch
                checked=Signal::derive(move || f.cur.get().b())
                label=d.label
                text=Signal::derive(move || if f.cur.get().b() { "On".to_string() } else { "Off".to_string() })
                on_change=Callback::new(move |v| { f.cur.set(Val::B(v)); f.msg.set(None); })
            />
        }.into_any(),
        Kind::Seg(opts) => view! {
            <Segmented
                label=d.label
                options=opts.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
                value=Signal::derive(move || f.cur.get().s())
                disabled=off
                on_change=Callback::new(move |v: String| { f.cur.set(Val::S(v)); f.msg.set(None); })
            />
        }.into_any(),
        Kind::Cidr | Kind::Hosts => {
            let is_hosts = d.kind == Kind::Hosts;
            let tags = RwSignal::new(f.cur.get_untracked().t());
            Effect::new(move |_| { let t = f.cur.get().t(); if tags.get_untracked() != t { tags.set(t); } });
            let terr = RwSignal::new(Option::<String>::None);
            view! {
                <TagInput
                    tags=tags
                    label=d.label
                    placeholder=if is_hosts { "example.com, then Enter" } else { "192.168.1.0/24, then Enter" }
                    validate=Callback::new(move |v: String| if is_hosts {
                        let b = v.trim().strip_prefix("*.").unwrap_or(v.trim());
                        if !b.is_empty() && !b.contains(|c: char| c.is_whitespace() || matches!(c, '/' | '*' | ':')) { None } else { Some(format!("\"{v}\" is not a host. Use example.com or *.example.com.")) }
                    } else if cidr_ok(&v) { None } else { Some(format!("\"{v}\" is not a CIDR range. Use a form like 192.168.1.0/24.")) })
                    on_change=Callback::new(move |t: Vec<String>| { f.cur.set(Val::T(t)); f.msg.set(None); })
                    error=terr
                />
                {move || terr.get().map(|e| view! { <span class="fmsg bad" role="alert">{e}</span> })}
            }.into_any()
        }
        Kind::Text | Kind::Free | Kind::Secret | Kind::Port | Kind::Num { .. } => {
            let unit = if let Kind::Num { unit, .. } = d.kind { Some(unit) } else { None };
            let cls = match d.kind { Kind::Text | Kind::Free | Kind::Secret => "input mono mid", _ => "input mono short num" };
            let secret = d.kind == Kind::Secret;
            let input = view! {
                <input
                    class=cls
                    id=id.clone()
                    type=if secret { "password" } else { "text" }
                    inputmode=if matches!(d.kind, Kind::Text | Kind::Free | Kind::Secret) { "text" } else { "numeric" }
                    autocomplete=if secret { "new-password" } else { "off" }
                    aria-describedby=msg_id.clone()
                    aria-invalid=move || if err.get().is_some() { "true" } else { "false" }
                    disabled=move || off.get()
                    prop:value=move || f.cur.get().s()
                    on:input=move |ev| { f.cur.set(Val::S(event_target_value(&ev))); f.msg.set(None); }
                />
            };
            match unit {
                Some(u) => view! { <div class="unit">{input}<span>{u}</span></div> }.into_any(),
                None => input.into_any(),
            }
        }
    };

    view! {
        <div class=move || format!("frow {} {}", if dirty() { "dirty" } else { "" }, if off.get() { "off" } else { "" })>
            <div class="fl">
                {if is_label {
                    view! { <label for=id.clone() id=label_id.clone()>{d.label}</label> }.into_any()
                } else {
                    view! { <span class="lname" id=label_id.clone()>{d.label}</span> }.into_any()
                }}
                <small>{d.desc}{move || (d.key == "log_cap").then(|| log_cap_hint(&f.cur.get().s()))}</small>
                <span class="fstate">
                    {move || if modified() { view! { <span class="st st-mod">"modified"</span> }.into_any() } else { view! { <span class="st st-def">"default"</span> }.into_any() }}
                    {move || dirty().then(|| view! { <span class="st st-dirty">"unsaved"</span> })}
                </span>
            </div>
            <div class="fc">
                {control}
                <span id=msg_id class=move || match (err.get(), f.msg.get()) {
                    (Some(_), _) | (_, Some((true, _))) => "fmsg bad",
                    (None, Some((false, _))) => "fmsg ok",
                    _ => "fmsg",
                } aria-live="polite">
                    {move || match (err.get(), f.msg.get()) {
                        (Some(e), _) => e,
                        (None, Some((_, m))) => m,
                        _ => String::new(),
                    }}
                </span>
            </div>
            <button
                class="btn sm ghost freset"
                type="button"
                hidden=move || !modified()
                title=move || format!("Reset to {}", default_txt())
                aria-label=move || format!("Reset {} to default {}", d.label, default_txt())
                on:click=move |_| { f.cur.set(f.default.get()); f.msg.set(Some((false, "Default restored. Save to apply.".into()))); }
            >
                <Icon name="reset" />"Reset"
            </button>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_size_hint_counts_two_rings() {
        assert_eq!(log_cap_hint("1000"), " About 2.0 MB of memory.");
        assert_eq!(log_cap_hint("100"), " About 200 KB of memory.");
        assert!(log_cap_hint("abc").contains("per entry"));
    }
    use api_types::UpstreamProxyKind;

    fn vals(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> String {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
                .unwrap_or_default()
        }
    }

    #[test]
    fn upstream_proxy_fields_are_validated() {
        let get = vals(&[("up_host", " "), ("up_user", ""), ("up_pass", "x")]);
        assert!(upstream_error("up_host", &get).unwrap().contains("host"));
        assert!(upstream_error("up_pass", &get)
            .unwrap()
            .contains("needs a username"));
        let ok = vals(&[("up_host", "proxy.lan"), ("up_user", "a"), ("up_pass", "x")]);
        assert_eq!(upstream_error("up_host", &ok), None);
        assert_eq!(upstream_error("up_pass", &ok), None);
        let spaced = vals(&[("up_host", "a b")]);
        assert!(upstream_error("up_host", &spaced).is_some());
    }

    #[test]
    fn only_changed_fields_are_sent_and_an_empty_password_is_left_out() {
        let get = vals(&[
            ("up_on", "true"),
            ("up_kind", "socks5"),
            ("up_host", " proxy.lan "),
            ("up_port", "1080"),
            ("up_user", "alice"),
            ("up_pass", ""),
        ]);
        assert!(upstream_update(&get, &|_| false).is_none());
        let u = upstream_update(&get, &|k| k == "up_on" || k == "up_pass").unwrap();
        assert_eq!(u.enabled, Some(true));
        assert_eq!((u.kind, u.host.as_deref(), u.port), (None, None, None));
        let u = upstream_update(&get, &|k| k == "up_kind" || k == "up_host").unwrap();
        assert_eq!(u.kind, Some(UpstreamProxyKind::Socks5));
        assert_eq!(u.host.as_deref(), Some("proxy.lan"));
        assert_eq!(u.enabled, None);
        assert_eq!(u.password, None, "empty keeps the saved password");

        let typed = vals(&[("up_pass", "s3cret")]);
        let u = upstream_update(&typed, &|k| k == "up_pass").unwrap();
        assert_eq!(u.password.as_deref(), Some("s3cret"));
        // The test button sends everything on screen.
        let u = upstream_update(&get, &|_| true).unwrap();
        assert_eq!(u.port, Some(1080));
        assert_eq!(u.username.as_deref(), Some("alice"));
        // A changed address sends type, host, port and username so the server can tell.
        let u = upstream_update(&get, &|k| k == "up_host").unwrap();
        assert_eq!(u.kind, Some(UpstreamProxyKind::Socks5));
        assert_eq!(u.port, Some(1080));
        assert_eq!(u.username.as_deref(), Some("alice"));
    }

    #[test]
    fn a_changed_address_asks_for_the_password_again() {
        let ask = vals(&[("up_ep_changed", "true"), ("up_user", "a"), ("up_pass", "")]);
        assert!(upstream_error("up_pass", &ask).unwrap().contains("again"));
        let same = vals(&[
            ("up_ep_changed", "false"),
            ("up_user", "a"),
            ("up_pass", ""),
        ]);
        assert_eq!(upstream_error("up_pass", &same), None);
        let anon = vals(&[("up_ep_changed", "true"), ("up_user", ""), ("up_pass", "")]);
        assert_eq!(upstream_error("up_pass", &anon), None);
    }
}

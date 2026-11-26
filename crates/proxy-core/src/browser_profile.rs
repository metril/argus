//! Which browser a request comes from, mapped to the nearest `wreq-util` emulation, so the
//! upstream connection (TLS and HTTP/2 fingerprint) matches the browser behind it.
//!
//! The browser's own headers (User-Agent, client hints, ...) are forwarded untouched; only the
//! transport fingerprint comes from the profile.

use hyper::header::{HeaderMap, HeaderName};
use wreq::header::OrigHeaderMap;
use wreq_util::Profile;

/// Browser family of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Chrome,
    Edge,
    Firefox,
    Safari,
}

/// A classified browser and the emulation profile chosen for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserProfile {
    pub family: Family,
    pub profile: Profile,
}

impl Default for BrowserProfile {
    /// The latest Chrome `wreq-util` knows.
    fn default() -> Self {
        Self {
            family: Family::Chrome,
            profile: Profile::Chrome149,
        }
    }
}

const CHROME: &[(u32, Profile)] = &[
    (100, Profile::Chrome100),
    (101, Profile::Chrome101),
    (104, Profile::Chrome104),
    (105, Profile::Chrome105),
    (106, Profile::Chrome106),
    (107, Profile::Chrome107),
    (108, Profile::Chrome108),
    (109, Profile::Chrome109),
    (110, Profile::Chrome110),
    (114, Profile::Chrome114),
    (116, Profile::Chrome116),
    (117, Profile::Chrome117),
    (118, Profile::Chrome118),
    (119, Profile::Chrome119),
    (120, Profile::Chrome120),
    (123, Profile::Chrome123),
    (124, Profile::Chrome124),
    (126, Profile::Chrome126),
    (127, Profile::Chrome127),
    (128, Profile::Chrome128),
    (129, Profile::Chrome129),
    (130, Profile::Chrome130),
    (131, Profile::Chrome131),
    (132, Profile::Chrome132),
    (133, Profile::Chrome133),
    (134, Profile::Chrome134),
    (135, Profile::Chrome135),
    (136, Profile::Chrome136),
    (137, Profile::Chrome137),
    (138, Profile::Chrome138),
    (139, Profile::Chrome139),
    (140, Profile::Chrome140),
    (141, Profile::Chrome141),
    (142, Profile::Chrome142),
    (143, Profile::Chrome143),
    (144, Profile::Chrome144),
    (145, Profile::Chrome145),
    (146, Profile::Chrome146),
    (147, Profile::Chrome147),
    (148, Profile::Chrome148),
    (149, Profile::Chrome149),
];

const EDGE: &[(u32, Profile)] = &[
    (101, Profile::Edge101),
    (122, Profile::Edge122),
    (127, Profile::Edge127),
    (131, Profile::Edge131),
    (134, Profile::Edge134),
    (135, Profile::Edge135),
    (136, Profile::Edge136),
    (137, Profile::Edge137),
    (138, Profile::Edge138),
    (139, Profile::Edge139),
    (140, Profile::Edge140),
    (141, Profile::Edge141),
    (142, Profile::Edge142),
    (143, Profile::Edge143),
    (144, Profile::Edge144),
    (145, Profile::Edge145),
    (146, Profile::Edge146),
    (147, Profile::Edge147),
    (148, Profile::Edge148),
];

const FIREFOX: &[(u32, Profile)] = &[
    (109, Profile::Firefox109),
    (117, Profile::Firefox117),
    (128, Profile::Firefox128),
    (133, Profile::Firefox133),
    (135, Profile::Firefox135),
    (136, Profile::Firefox136),
    (139, Profile::Firefox139),
    (142, Profile::Firefox142),
    (143, Profile::Firefox143),
    (144, Profile::Firefox144),
    (145, Profile::Firefox145),
    (146, Profile::Firefox146),
    (147, Profile::Firefox147),
    (148, Profile::Firefox148),
    (149, Profile::Firefox149),
    (150, Profile::Firefox150),
    (151, Profile::Firefox151),
];

/// Desktop Safari by `(major, minor)`.
const SAFARI: &[((u32, u32), Profile)] = &[
    ((15, 3), Profile::Safari15_3),
    ((15, 5), Profile::Safari15_5),
    ((15, 6), Profile::Safari15_6_1),
    ((16, 0), Profile::Safari16),
    ((16, 5), Profile::Safari16_5),
    ((17, 0), Profile::Safari17_0),
    ((17, 2), Profile::Safari17_2_1),
    ((17, 4), Profile::Safari17_4_1),
    ((17, 5), Profile::Safari17_5),
    ((17, 6), Profile::Safari17_6),
    ((18, 0), Profile::Safari18),
    ((18, 2), Profile::Safari18_2),
    ((18, 3), Profile::Safari18_3_1),
    ((18, 5), Profile::Safari18_5),
    ((26, 0), Profile::Safari26),
    ((26, 1), Profile::Safari26_1),
    ((26, 2), Profile::Safari26_2),
    ((26, 3), Profile::Safari26_3),
    ((26, 4), Profile::Safari26_4),
];

/// iOS Safari by `(major, minor)`.
const SAFARI_IOS: &[((u32, u32), Profile)] = &[
    ((16, 5), Profile::SafariIos16_5),
    ((17, 2), Profile::SafariIos17_2),
    ((17, 4), Profile::SafariIos17_4_1),
    ((18, 1), Profile::SafariIos18_1_1),
    ((26, 0), Profile::SafariIos26),
    ((26, 2), Profile::SafariIos26_2),
];

/// The newest entry not above `want`, else the oldest one.
fn nearest<K: Ord + Copy>(table: &[(K, Profile)], want: K) -> Profile {
    table
        .iter()
        .rev()
        .find(|(k, _)| *k <= want)
        .unwrap_or(&table[0])
        .1
}

/// Major version of the brand `name` in a `Sec-CH-UA` value (`"Chromium";v="146", ...`).
fn brand_version(sec_ch_ua: &str, name: &str) -> Option<u32> {
    sec_ch_ua.split(',').find_map(|part| {
        let (brand, rest) = part.trim().split_once(';')?;
        if brand.trim().trim_matches('"') != name {
            return None;
        }
        let v = rest.trim().strip_prefix("v=")?.trim_matches('"');
        v.split('.').next()?.parse().ok()
    })
}

/// The number after `marker` in `ua` (`Chrome/146.0.0.0` with `Chrome/` gives 146).
fn ua_major(ua: &str, marker: &str) -> Option<u32> {
    let rest = &ua[ua.find(marker)? + marker.len()..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn safari_version(ua: &str) -> Option<(u32, u32)> {
    let rest = &ua[ua.find("Version/")? + "Version/".len()..];
    let mut it = rest.split(|c: char| !c.is_ascii_digit() && c != '.');
    let mut parts = it.next()?.split('.');
    let major = parts.next()?.parse().ok()?;
    Some((
        major,
        parts.next().and_then(|m| m.parse().ok()).unwrap_or(0),
    ))
}

impl BrowserProfile {
    /// Classify by `Sec-CH-UA` first, then the `User-Agent`; anything unrecognised gets the
    /// default (latest Chrome).
    pub fn classify(headers: &HeaderMap) -> Self {
        let text = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
        if let Some(hints) = text("sec-ch-ua") {
            if let Some(v) = brand_version(hints, "Microsoft Edge") {
                return Self::edge(v);
            }
            if let Some(v) =
                brand_version(hints, "Google Chrome").or_else(|| brand_version(hints, "Chromium"))
            {
                return Self::chrome(v);
            }
        }
        match text("user-agent") {
            Some(ua) => Self::from_user_agent(ua),
            None => Self::default(),
        }
    }

    fn from_user_agent(ua: &str) -> Self {
        if let Some(v) = ua_major(ua, "Edg/") {
            return Self::edge(v);
        }
        if let Some(v) = ua_major(ua, "Firefox/").or_else(|| ua_major(ua, "FxiOS/")) {
            return Self::firefox(v);
        }
        if let Some(v) = ua_major(ua, "CriOS/").or_else(|| ua_major(ua, "Chrome/")) {
            return Self::chrome(v);
        }
        if ua.contains("Safari/") {
            if let Some(v) = safari_version(ua) {
                let ios = ["iPhone", "iPad", "iPod"].iter().any(|d| ua.contains(d));
                return Self::safari(v, ios);
            }
        }
        Self::default()
    }

    fn chrome(v: u32) -> Self {
        Self {
            family: Family::Chrome,
            profile: nearest(CHROME, v),
        }
    }

    fn edge(v: u32) -> Self {
        Self {
            family: Family::Edge,
            profile: nearest(EDGE, v),
        }
    }

    fn firefox(v: u32) -> Self {
        Self {
            family: Family::Firefox,
            profile: nearest(FIREFOX, v),
        }
    }

    fn safari(v: (u32, u32), ios: bool) -> Self {
        Self {
            family: Family::Safari,
            profile: nearest(if ios { SAFARI_IOS } else { SAFARI }, v),
        }
    }

    /// The transport emulation of the profile with its default headers removed: the browser's
    /// own headers are forwarded as they came. Built once per profile.
    pub fn emulation(&self) -> wreq::Emulation {
        cached(self.profile).emulation.clone()
    }
}

/// A profile's emulation (headers stripped) and its header spellings, built once.
struct Cached {
    emulation: wreq::Emulation,
    spellings: std::collections::HashMap<HeaderName, String>,
}

fn cached(profile: Profile) -> std::sync::Arc<Cached> {
    use std::sync::{Arc, Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<std::collections::HashMap<Profile, Arc<Cached>>>> =
        OnceLock::new();
    let mut map = CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    map.entry(profile)
        .or_insert_with(|| {
            let mut e = wreq::IntoEmulation::into_emulation(profile);
            let spellings = e
                .orig_headers
                .iter()
                .map(|(n, c)| (n.clone(), String::from_utf8_lossy(c.as_ref()).into_owned()))
                .collect();
            e.headers.clear();
            e.orig_headers = OrigHeaderMap::new();
            Arc::new(Cached {
                emulation: e,
                spellings,
            })
        })
        .clone()
}

/// How browsers spell a header on HTTP/1: Title-Case, except the client hints, which Chrome
/// sends lowercase.
fn title_case(name: &str) -> String {
    if name.starts_with("sec-ch-") {
        return name.to_string();
    }
    // The WebSocket handshake headers carry a capital `S` in `WebSocket` (RFC 6455).
    if let Some(rest) = name.strip_prefix("sec-websocket-") {
        return format!("Sec-WebSocket-{}", title_case(rest));
    }
    let mut out = String::with_capacity(name.len());
    let mut up = true;
    for c in name.chars() {
        out.push(if up { c.to_ascii_uppercase() } else { c });
        up = c == '-';
    }
    out
}

/// The order of the request's headers (each name once, in first-seen order) with spellings for
/// an HTTP/1 upstream, so the origin sees them the way the browser sent them.
pub fn orig_headers<'a>(
    profile: &BrowserProfile,
    names: impl Iterator<Item = &'a HeaderName>,
) -> OrigHeaderMap {
    let full = cached(profile.profile);
    let mut seen = std::collections::HashSet::new();
    let mut out = OrigHeaderMap::new();
    for n in names {
        if !seen.insert(n.clone()) {
            continue;
        }
        match full.spellings.get(n) {
            Some(c) => out.insert(c.clone()),
            None => out.insert(title_case(n.as_str())),
        };
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn classification_table() {
        use Family::*;
        use Profile as P;
        let ch = |brands: &str| ("sec-ch-ua", brands.to_string());
        type Case = (&'static str, Vec<(&'static str, String)>, Family, Profile);
        let cases: Vec<Case> = vec![
            (
                "client hints name Chrome",
                vec![ch(
                    r#""Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146""#,
                )],
                Chrome,
                P::Chrome146,
            ),
            (
                "hints win over a Firefox-looking UA",
                vec![
                    ch(r#""Google Chrome";v="140""#),
                    ("user-agent", "Firefox/130.0".into()),
                ],
                Chrome,
                P::Chrome140,
            ),
            (
                "Edge by hints",
                vec![ch(
                    r#""Chromium";v="147", "Microsoft Edge";v="147", "Not.A/Brand";v="8""#,
                )],
                Edge,
                P::Edge147,
            ),
            (
                "Chromium-only brands (Brave, Opera) are Chrome",
                vec![ch(r#""Brave";v="141", "Chromium";v="141""#)],
                Chrome,
                P::Chrome141,
            ),
            (
                "version between two profiles rounds down",
                vec![ch(r#""Google Chrome";v="125""#)],
                Chrome,
                P::Chrome124,
            ),
            (
                "version below the oldest rounds up to it",
                vec![ch(r#""Google Chrome";v="80""#)],
                Chrome,
                P::Chrome100,
            ),
            (
                "version above the newest uses the newest",
                vec![ch(r#""Google Chrome";v="200""#)],
                Chrome,
                P::Chrome149,
            ),
            ("Chrome by UA", vec![("user-agent", CHROME_UA.into())], Chrome, P::Chrome146),
            (
                "Edge by UA",
                vec![("user-agent", format!("{CHROME_UA} Edg/131.0.2903.51"))],
                Edge,
                P::Edge131,
            ),
            (
                "Firefox by UA",
                vec![(
                    "user-agent",
                    "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/143.0".into(),
                )],
                Firefox,
                P::Firefox143,
            ),
            (
                "Firefox between versions",
                vec![("user-agent", "Mozilla/5.0 Gecko/20100101 Firefox/141.0".into())],
                Firefox,
                P::Firefox139,
            ),
            (
                "Safari on macOS",
                vec![(
                    "user-agent",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15".into(),
                )],
                Safari,
                P::Safari18_3_1,
            ),
            (
                "Safari 26.4",
                vec![(
                    "user-agent",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Safari/605.1.15".into(),
                )],
                Safari,
                P::Safari26_4,
            ),
            (
                "Safari on iOS",
                vec![(
                    "user-agent",
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1".into(),
                )],
                Safari,
                P::SafariIos17_4_1,
            ),
            (
                "Chrome on iOS",
                vec![("user-agent", "Mozilla/5.0 (iPhone) AppleWebKit/605 Mobile/15E148 CriOS/139.0.0.0 Safari/604.1".into())],
                Chrome,
                P::Chrome139,
            ),
            ("no hints, no UA", vec![], Chrome, P::Chrome149),
            ("curl is the default", vec![("user-agent", "curl/8.5.0".into())], Chrome, P::Chrome149),
            (
                "unrecognised hints fall back to the UA",
                vec![ch(r#""Not A;Brand";v="99""#), ("user-agent", CHROME_UA.into())],
                Chrome,
                P::Chrome146,
            ),
        ];
        for (name, hs, family, profile) in cases {
            let pairs: Vec<(&str, &str)> = hs.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let got = BrowserProfile::classify(&headers(&pairs));
            assert_eq!((got.family, got.profile), (family, profile), "{name}");
        }
    }

    #[test]
    fn default_is_the_latest_chrome() {
        assert_eq!(CHROME.last().unwrap().1, BrowserProfile::default().profile);
        assert!(CHROME.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(EDGE.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(FIREFOX.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(SAFARI.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(SAFARI_IOS.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn emulation_carries_no_headers() {
        let e = BrowserProfile::default().emulation();
        assert!(e.headers.is_empty());
        assert!(e.orig_headers.is_empty());
    }

    #[test]
    fn spellings_and_order_follow_the_request() {
        let p = BrowserProfile::default();
        let h = headers(&[
            ("user-agent", "x"),
            ("sec-ch-ua", "y"),
            ("x-custom-thing", "1"),
            ("user-agent", "again"),
        ]);
        let o = orig_headers(&p, h.keys());
        let got: Vec<String> = o
            .iter()
            .map(|(_, c)| String::from_utf8_lossy(c.as_ref()).into_owned())
            .collect();
        assert_eq!(got.len(), 3, "each name once: {got:?}");
        assert!(got.contains(&"User-Agent".to_string()), "{got:?}");
        assert!(
            got.iter().any(|g| g.eq_ignore_ascii_case("sec-ch-ua")),
            "{got:?}"
        );
        assert!(got.contains(&"X-Custom-Thing".to_string()), "{got:?}");
    }
}

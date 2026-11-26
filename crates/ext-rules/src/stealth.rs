//! `$stealth` options (AdGuard syntax): `@@||site^$stealth[=opt1|opt2]` turns the listed Stealth
//! Mode options off for pages matching the rule, or all of them without a value.

pub const SEARCH_QUERIES: u32 = 1;
pub const DNT: u32 = 1 << 1;
pub const COOKIES_3P: u32 = 1 << 2;
pub const COOKIES_1P: u32 = 1 << 3;
pub const CACHE_3P: u32 = 1 << 4;
pub const AUTH_3P: u32 = 1 << 5;
pub const WEBRTC: u32 = 1 << 6;
pub const PUSH: u32 = 1 << 7;
pub const LOCATION: u32 = 1 << 8;
pub const FLASH: u32 = 1 << 9;
pub const JAVA: u32 = 1 << 10;
pub const REFERRER: u32 = 1 << 11;
pub const USER_AGENT: u32 = 1 << 12;
pub const IP: u32 = 1 << 13;
pub const X_CLIENT_DATA: u32 = 1 << 14;
/// Tracking-parameter removal has no AdGuard name; only a bare `$stealth` turns it off.
pub const TRACKING_PARAMS: u32 = 1 << 15;
/// Every option.
pub const ALL: u32 = (1 << 16) - 1;

/// Bit of one option name (`$stealth=` spelling); `fingerprinting` is accepted and ignored.
pub fn option_bit(name: &str) -> Option<u32> {
    Some(match name {
        "searchqueries" => SEARCH_QUERIES,
        "donottrack" => DNT,
        "3p-cookie" | "3p-cookies" => COOKIES_3P,
        "1p-cookie" | "1p-cookies" => COOKIES_1P,
        "3p-cache" => CACHE_3P,
        "3p-auth" => AUTH_3P,
        "webrtc" => WEBRTC,
        "push" => PUSH,
        "location" => LOCATION,
        "flash" => FLASH,
        "java" => JAVA,
        "referrer" => REFERRER,
        "useragent" => USER_AGENT,
        "ip" => IP,
        "xclientdata" => X_CLIENT_DATA,
        // Accepted, nothing to switch: fingerprinting and DPI protection are not implemented.
        "fingerprinting" | "dpi" => 0,
        _ => return None,
    })
}

/// The options a `$stealth` value lists (`""` = all). `None` on an unknown name.
pub fn parse_value(v: &str) -> Option<u32> {
    if v.trim().is_empty() {
        return Some(ALL);
    }
    v.split('|')
        .try_fold(0u32, |m, n| Some(m | option_bit(n.trim())?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExtIndex, ExtKind, ExtRule, RequestInfo, ResourceType};

    fn idx(rules: &[&str]) -> ExtIndex {
        let r: Vec<ExtRule> = rules
            .iter()
            .map(|r| ExtRule::new(ExtKind::UnsupportedOption, r))
            .collect();
        ExtIndex::build(&r)
    }

    #[test]
    fn value_parsing() {
        assert_eq!(parse_value(""), Some(ALL));
        assert_eq!(parse_value("webrtc|push"), Some(WEBRTC | PUSH));
        assert_eq!(parse_value("fingerprinting"), Some(0));
        assert_eq!(parse_value("nope"), None);
    }

    fn req<'a>(url: &'a str, src: Option<&'a str>, t: ResourceType) -> RequestInfo<'a> {
        let mut r = RequestInfo::new(url, "GET", t);
        r.source_url = src;
        r
    }

    #[test]
    fn exceptions_judge_the_request_like_any_network_rule() {
        use ResourceType::*;
        let i = idx(&[
            "@@||a.test^$stealth=webrtc|3p-cookie",
            "@@||b.test^$stealth",
            "@@||c.test^$stealth=useragent,domain=page.test",
            "@@||s.test^$script,stealth=ip",
            "||d.test^$stealth",
            "@@||e.test^$stealth=bogus",
            "@@||f.test^$stealth=1p-cookies|dpi",
        ]);
        let doc = |u| i.stealth_off(&req(u, None, Document));
        assert_eq!(doc("https://a.test/x"), WEBRTC | COOKIES_3P);
        assert_eq!(doc("https://sub.b.test/"), ALL);
        assert_eq!(doc("https://d.test/"), 0, "only exceptions count");
        assert_eq!(doc("https://e.test/"), 0, "unknown option is invalid");
        assert_eq!(
            doc("https://f.test/"),
            COOKIES_1P,
            "plural alias, dpi no-op"
        );
        // A request to the excepted host from any other site.
        assert_eq!(
            i.stealth_off(&req(
                "https://b.test/a.js",
                Some("https://other.test/"),
                Script
            )),
            ALL
        );
        // `$domain=` is judged against the initiator.
        let c = |src| i.stealth_off(&req("https://c.test/a.js", src, Script));
        assert_eq!(c(Some("https://www.page.test/p")), USER_AGENT);
        assert_eq!(c(Some("https://other.test/")), 0);
        // The request type is honoured.
        let s = |t| i.stealth_off(&req("https://s.test/a", Some("https://x.test/"), t));
        assert_eq!(s(Script), IP);
        assert_eq!(s(Image), 0);
        // A `$document` exception does not touch Stealth Mode.
        assert_eq!(
            idx(&["@@||a.test^$document"]).stealth_off(&req("https://a.test/", None, Document)),
            0
        );
    }
}

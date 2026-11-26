//! Stealth Mode (AdGuard parity): privacy edits to requests, responses and pages.
//!
//! Everything here is pure: [`mask`] turns the settings into a bit set of options that apply (the
//! caller removes the ones a `$stealth` exception or a bypass turned off), the `apply_*`
//! functions edit header maps, and [`script`] builds the in-page shim.
//!
//! Deviations from AdGuard, by design: cookie self-destruction is done by capping the lifetime the
//! server asks for (Argus cannot reach into the browser's jar; session cookies stay session
//! cookies), and "hide IP" can only set `X-Forwarded-For`; it cannot hide the real address.
//! The in-page shim covers the page and the same-origin frames it can reach through
//! `contentWindow` / `contentDocument` (including `about:blank` and `srcdoc` ones); a frame
//! reached only through `window.frames` or `parent.frames` is not patched.

use std::time::SystemTime;

use common::config::StealthSettings;
use ext_rules::stealth as o;
use hyper::header::{HeaderMap, HeaderName, HeaderValue, REFERER, SET_COOKIE, USER_AGENT};

/// The options that apply under `s` (0 when the master switch is off).
pub fn mask(s: &StealthSettings) -> u32 {
    if !s.enabled {
        return 0;
    }
    [
        (s.hide_search_queries, o::SEARCH_QUERIES),
        (s.send_dnt, o::DNT),
        (s.strip_tracking_params, o::TRACKING_PARAMS),
        (s.hide_referer, o::REFERRER),
        (s.hide_user_agent, o::USER_AGENT),
        (s.mask_ip, o::IP),
        (s.remove_x_client_data, o::X_CLIENT_DATA),
        (s.third_party_cookies, o::COOKIES_3P),
        (s.first_party_cookies, o::COOKIES_1P),
        (s.block_etag, o::CACHE_3P),
        (s.block_third_party_auth, o::AUTH_3P),
        (s.block_webrtc, o::WEBRTC),
        (s.block_push, o::PUSH),
        (s.block_location, o::LOCATION),
        (s.block_flash, o::FLASH),
        (s.block_java, o::JAVA),
    ]
    .into_iter()
    .fold(0, |m, (on, b)| if on { m | b } else { m })
}

/// Registrable domain of a host (the host itself for IPs and unknown suffixes).
pub fn site(host: &str) -> &str {
    psl::domain_str(host).unwrap_or(host)
}

fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
}

/// Whether a request for `host` issued by the page at `source` is third-party. `source` is what
/// [`crate::request_type::source_url`] returns: empty means a cross-site request whose page is
/// unknown (third-party).
pub fn is_third_party(host: &str, source: &str) -> bool {
    if source.is_empty() {
        return true;
    }
    match host_of(source) {
        Some(sh) => site(&sh) != site(&host.to_ascii_lowercase()),
        None => false,
    }
}

/// Tracking parameters (AdGuard URL Tracking filter, abridged), matched on the exact name.
const PARAMS: &[&str] = &[
    "fbclid",
    "gclid",
    "gclsrc",
    "dclid",
    "gbraid",
    "wbraid",
    "yclid",
    "ymclid",
    "_openstat",
    "mc_eid",
    "mc_cid",
    "igshid",
    "msclkid",
    "twclid",
    "ttclid",
    "li_fat_id",
    "mkt_tok",
    "oly_anon_id",
    "oly_enc_id",
    "vero_id",
    "vero_conv",
    "_hsenc",
    "_hsmi",
    "__s",
    "ml_subscriber",
    "ml_subscriber_hash",
    "rb_clickid",
    "s_cid",
    "fb_ref",
    "fb_source",
    "ref_src",
    "ref_url",
    "srsltid",
    "wickedid",
    "gad_source",
    "mibextid",
    "_ga",
    "yclid",
    "cmpid",
    "icid",
    "sb_referer_host",
];
/// Parameter name prefixes.
const PREFIXES: &[&str] = &["utm_", "hsa_", "pk_", "mtm_", "piwik_", "stm_"];

fn is_tracking(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    PARAMS.contains(&n.as_str()) || PREFIXES.iter().any(|p| n.starts_with(p))
}

/// `url` without tracking parameters; `None` when it has none.
pub fn strip_tracking(url: &str) -> Option<String> {
    let (base, rest) = url.split_once('?')?;
    let (query, frag) = match rest.split_once('#') {
        Some((q, f)) => (q, Some(f)),
        None => (rest, None),
    };
    let mut changed = false;
    let kept: Vec<&str> = query
        .split('&')
        .filter(|p| {
            let name = p.split_once('=').map_or(*p, |(n, _)| n);
            let drop = !name.is_empty() && is_tracking(name);
            changed |= drop;
            !drop
        })
        .collect();
    if !changed {
        return None;
    }
    let mut out = base.to_string();
    if !kept.is_empty() {
        out.push('?');
        out.push_str(&kept.join("&"));
    }
    if let Some(f) = frag {
        out.push('#');
        out.push_str(f);
    }
    Some(out)
}

/// Whether `host` is a search engine's results site (first label of its registrable domain).
fn is_search_engine(host: &str) -> bool {
    const NAMES: &[&str] = &[
        "google",
        "bing",
        "duckduckgo",
        "yahoo",
        "yandex",
        "baidu",
        "ecosia",
        "startpage",
        "qwant",
        "ask",
        "naver",
        "seznam",
        "kagi",
        "mojeek",
        "sogou",
        "searx",
    ];
    let reg = site(host);
    let label = reg.split('.').next().unwrap_or("");
    if host == "search.brave.com" {
        return true;
    }
    if !NAMES.contains(&label) {
        return false;
    }
    host == reg
        || host
            .strip_suffix(reg)
            .is_some_and(|p| matches!(p, "www." | "search." | "html." | "lite." | "images." | "m."))
}

fn origin_slash(u: &url::Url) -> String {
    format!("{}/", u.origin().ascii_serialization())
}

/// What a request is, for the edits that depend on it.
#[derive(Clone, Copy)]
pub struct ReqKind {
    /// The request is a main-frame navigation.
    pub document: bool,
    /// POST, PUT, PATCH or DELETE.
    pub unsafe_method: bool,
}

/// Replace the Referer per the options. Returns the original Referer when it was changed. Never
/// on unsafe methods: servers check the Referer of form posts.
fn edit_referer(
    s: &StealthSettings,
    m: u32,
    headers: &mut HeaderMap,
    url: &str,
    kind: ReqKind,
) -> Option<String> {
    let want_ref = m & o::REFERRER != 0;
    let want_search = m & o::SEARCH_QUERIES != 0 && kind.document;
    if (!want_ref && !want_search) || kind.unsafe_method {
        return None;
    }
    let orig = headers.get(REFERER)?.to_str().ok()?.to_string();
    let ru = url::Url::parse(&orig).ok()?;
    let tu = url::Url::parse(url).ok()?;
    let (rh, th) = (ru.host_str()?.to_ascii_lowercase(), tu.host_str()?);
    if site(&rh) == site(&th.to_ascii_lowercase()) {
        return None;
    }
    let new = if want_ref {
        if s.referer_custom.is_empty() {
            origin_slash(&tu)
        } else {
            s.referer_custom.clone()
        }
    } else if is_search_engine(&rh) {
        // A navigation from a search engine's results: the site gets its own origin, not the
        // engine's address with the query.
        origin_slash(&tu)
    } else {
        return None;
    };
    let v = HeaderValue::from_str(&new).ok()?;
    headers.insert(REFERER, v);
    Some(orig)
}

fn major(ua: &str, marker: &str) -> Option<u32> {
    let i = ua.find(marker)? + marker.len();
    let d: String = ua[i..].chars().take_while(char::is_ascii_digit).collect();
    d.parse().ok()
}

/// A generic User-Agent of the same browser family, form factor and system family (major
/// version only, no device, build or OS version), or `None` when the family is not recognised.
pub fn reduce_ua(ua: &str) -> Option<String> {
    let ios = ["iPhone", "iPad", "iPod"]
        .into_iter()
        .find(|d| ua.contains(d));
    let android = ua.contains("Android");
    let mobile = ua.contains("Mobile");
    let desktop_os = if ua.contains("Windows") {
        "Windows NT 10.0; Win64; x64"
    } else if ua.contains("Macintosh") {
        "Macintosh; Intel Mac OS X 10_15_7"
    } else if ua.contains("CrOS") {
        "X11; CrOS x86_64 14541.0.0"
    } else {
        "X11; Linux x86_64"
    };
    if let Some(v) = major(ua, "FxiOS/") {
        let d = ios.unwrap_or("iPhone");
        return Some(format!(
            "Mozilla/5.0 ({d}; CPU {d} OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/{v}.0 Mobile/15E148 Safari/605.1.15"
        ));
    }
    if let Some(v) = major(ua, "Firefox/") {
        return Some(if android {
            format!(
                "Mozilla/5.0 (Android 10; {}rv:{v}.0) Gecko/{v}.0 Firefox/{v}.0",
                if mobile { "Mobile; " } else { "Tablet; " }
            )
        } else {
            let os = desktop_os.replace("X11; CrOS x86_64 14541.0.0", "X11; Linux x86_64");
            format!("Mozilla/5.0 ({os}; rv:{v}.0) Gecko/20100101 Firefox/{v}.0")
        });
    }
    if let Some(v) = major(ua, "CriOS/") {
        let d = ios.unwrap_or("iPhone");
        return Some(format!(
            "Mozilla/5.0 ({d}; CPU {d} OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/{v}.0.0.0 Mobile/15E148 Safari/604.1"
        ));
    }
    if let Some(c) = major(ua, "Chrome/") {
        let plat = if android {
            "Linux; Android 10; K"
        } else {
            desktop_os
        };
        let edge = major(ua, "Edg/")
            .or_else(|| major(ua, "EdgA/"))
            .map(|e| format!(" Edg/{e}.0.0.0"))
            .unwrap_or_default();
        return Some(format!(
            "Mozilla/5.0 ({plat}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{c}.0.0.0{} Safari/537.36{edge}",
            if mobile { " Mobile" } else { "" }
        ));
    }
    if ua.contains("Safari/") {
        let i = ua.find("Version/")? + "Version/".len();
        let v: String = ua[i..]
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if v.is_empty() {
            return None;
        }
        return Some(match ios {
            Some(d) => format!(
                "Mozilla/5.0 ({d}; CPU {} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{v} {}Safari/604.1",
                if d == "iPad" { "OS 17_0" } else { "iPhone OS 17_0" },
                if mobile { "Mobile/15E148 " } else { "" }
            ),
            None => format!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{v} Safari/605.1.15"
            ),
        });
    }
    None
}

const HIGH_ENTROPY_HINTS: &[&str] = &[
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-full-version",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-model",
    "sec-ch-ua-wow64",
    "sec-ch-ua-form-factors",
];

fn edit_user_agent(s: &StealthSettings, headers: &mut HeaderMap) {
    let Some(cur) = headers.get(USER_AGENT).and_then(|v| v.to_str().ok()) else {
        return;
    };
    let custom = !s.user_agent_custom.is_empty();
    let new = if custom {
        s.user_agent_custom.clone()
    } else {
        match reduce_ua(cur) {
            Some(n) => n,
            None => return,
        }
    };
    if let Ok(v) = HeaderValue::from_str(&new) {
        headers.insert(USER_AGENT, v);
    }
    if custom {
        // The browser's own hints describe the browser it really is: send none, so the upstream
        // TLS profile (chosen from the final headers) follows the User-Agent alone.
        let hints: Vec<HeaderName> = headers
            .keys()
            .filter(|k| k.as_str().starts_with("sec-ch-ua"))
            .cloned()
            .collect();
        for h in hints {
            headers.remove(h);
        }
    } else {
        // The reduced User-Agent keeps browser, version and system family, so the low-entropy
        // hints stay true; the detailed ones go.
        for h in HIGH_ENTROPY_HINTS {
            headers.remove(*h);
        }
    }
    // Language is an identifying detail too: keep the first tag only.
    if let Some(l) = headers
        .get(hyper::header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|t| t.split(';').next().unwrap_or("").trim().to_string())
        .filter(|t| !t.is_empty())
    {
        if let Ok(v) = HeaderValue::from_str(&l) {
            headers.insert(hyper::header::ACCEPT_LANGUAGE, v);
        }
    }
}

/// What the request edits did, for the caller's bookkeeping.
#[derive(Default)]
pub struct RequestOutcome {
    /// The Referer before it was replaced.
    pub orig_referer: Option<String>,
}

/// Apply the request-side header options. `third_party` is the request's party; `url` is the
/// URL actually sent.
pub fn apply_request(
    s: &StealthSettings,
    m: u32,
    headers: &mut HeaderMap,
    url: &str,
    third_party: bool,
    kind: ReqKind,
) -> RequestOutcome {
    let mut out = RequestOutcome::default();
    if m & o::DNT != 0 {
        headers.insert("dnt", HeaderValue::from_static("1"));
        headers.insert("sec-gpc", HeaderValue::from_static("1"));
    }
    if m & o::X_CLIENT_DATA != 0 {
        headers.remove("x-client-data");
    }
    out.orig_referer = edit_referer(s, m, headers, url, kind);
    if m & o::USER_AGENT != 0 {
        edit_user_agent(s, headers);
    }
    if m & o::IP != 0 {
        let ip = if s.mask_ip_address.is_empty() {
            "203.0.113.1"
        } else {
            &s.mask_ip_address
        };
        if let Ok(v) = HeaderValue::from_str(ip) {
            headers.insert("x-forwarded-for", v);
        }
    }
    if third_party {
        if m & o::CACHE_3P != 0 {
            headers.remove(hyper::header::IF_NONE_MATCH);
        }
        if m & o::AUTH_3P != 0 {
            headers.remove(hyper::header::AUTHORIZATION);
        }
    }
    out
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A cookie date as browsers read it (RFC 6265 section 5.1.1): any delimiters, day, month name,
/// year of 2 to 4 digits (two-digit years pivot at 70) and `h:m:s` in any order. Seconds since
/// the Unix epoch; negative before 1970.
pub fn parse_cookie_date(s: &str) -> Option<i64> {
    let delim = |c: char| matches!(c, '\x09' | '\x20'..='\x2F' | '\x3B'..='\x40' | '\x5B'..='\x60' | '\x7B'..='\x7E');
    let (mut time, mut day, mut month, mut year) = (None, None, None, None);
    for tok in s.split(delim).filter(|t| !t.is_empty()) {
        let digits = |t: &str, max: usize| -> Option<(u32, usize)> {
            let n = t.chars().take_while(char::is_ascii_digit).count();
            (1..=max)
                .contains(&n)
                .then(|| (t[..n].parse().unwrap_or(0), n))
        };
        if time.is_none() {
            let mut it = tok.splitn(3, ':');
            if let (Some(h), Some(m), Some(sec)) = (it.next(), it.next(), it.next()) {
                if let (Some((h, _)), Some((m, _)), Some((sec, _))) =
                    (digits(h, 2), digits(m, 2), digits(sec, 2))
                {
                    time = Some((h, m, sec));
                    continue;
                }
            }
        }
        if day.is_none() {
            if let Some((d, _)) = digits(tok, 2) {
                day = Some(d);
                continue;
            }
        }
        if month.is_none() && tok.len() >= 3 {
            const M: [&str; 12] = [
                "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
            ];
            let p = tok[..3].to_ascii_lowercase();
            if let Some(i) = M.iter().position(|m| *m == p) {
                month = Some(i as i64 + 1);
                continue;
            }
        }
        if year.is_none() {
            if let Some((y, _)) = digits(tok, 4).filter(|(_, n)| *n >= 2) {
                year = Some(match y {
                    70..=99 => y + 1900,
                    0..=69 => y + 2000,
                    _ => y,
                });
            }
        }
    }
    let ((h, mi, sec), d, mo, y) = (time?, day?, month?, year?);
    if !(1..=31).contains(&d) || y < 1601 || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    Some(
        days_from_civil(i64::from(y), mo, i64::from(d)) * 86_400
            + i64::from(h * 3600 + mi * 60 + sec),
    )
}

/// Cap one `Set-Cookie` to `max` seconds of life. `None`: leave it (a session cookie, already
/// shorter, or a deletion).
pub fn limit_set_cookie(v: &str, max: u64, now: SystemTime) -> Option<String> {
    let mut attrs: Vec<String> = v.split(';').map(|a| a.trim().to_string()).collect();
    let find = |attrs: &[String], n: &str| {
        attrs
            .iter()
            .skip(1)
            .position(|a| {
                a.split_once('=')
                    .map_or(a.as_str(), |(k, _)| k)
                    .trim()
                    .eq_ignore_ascii_case(n)
            })
            .map(|i| i + 1)
    };
    let val = |a: &str| {
        a.split_once('=')
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };
    let now_s = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    // Max-Age wins over Expires; an attribute a browser would ignore does not count.
    let max_age = find(&attrs, "max-age").and_then(|i| {
        let v = val(&attrs[i]);
        let ok = !v.is_empty()
            && v.strip_prefix('-')
                .unwrap_or(&v)
                .chars()
                .all(|c| c.is_ascii_digit())
            && v != "-";
        ok.then(|| v.parse::<i64>().unwrap_or(i64::MAX))
    });
    let expires = find(&attrs, "expires").and_then(|i| parse_cookie_date(&val(&attrs[i])));
    let life = match (max_age, expires) {
        (Some(a), _) => a,
        (None, Some(e)) => e - now_s,
        // A session cookie stays one.
        (None, None) => return None,
    };
    if life <= 0 || life as u64 <= max {
        return None;
    }
    if let Some(i) = find(&attrs, "expires") {
        attrs.remove(i);
    }
    match find(&attrs, "max-age") {
        Some(i) => attrs[i] = format!("Max-Age={max}"),
        None => attrs.push(format!("Max-Age={max}")),
    }
    Some(attrs.join("; "))
}

/// Apply the response-side options to a response's headers.
pub fn apply_response(s: &StealthSettings, m: u32, headers: &mut HeaderMap, third_party: bool) {
    if third_party && m & o::CACHE_3P != 0 {
        headers.remove(hyper::header::ETAG);
    }
    let minutes = if third_party && m & o::COOKIES_3P != 0 {
        s.third_party_cookie_minutes
    } else if !third_party && m & o::COOKIES_1P != 0 {
        s.first_party_cookie_minutes
    } else {
        return;
    };
    if !headers.contains_key(SET_COOKIE) {
        return;
    }
    let cookies: Vec<HeaderValue> = headers.get_all(SET_COOKIE).iter().cloned().collect();
    headers.remove(SET_COOKIE);
    let now = SystemTime::now();
    let max = u64::from(minutes) * 60;
    for c in cookies {
        if minutes == 0 {
            continue; // blocked
        }
        let new = c
            .to_str()
            .ok()
            .and_then(|t| limit_set_cookie(t, max, now))
            .and_then(|t| HeaderValue::from_str(&t).ok());
        headers.append(SET_COOKIE, new.unwrap_or(c));
    }
}

/// The in-page shim for the options in `m` (`None` when none needs one). Runs for the page and
/// for same-origin frames the page reaches through `contentWindow` / `contentDocument`.
pub fn script(s: &StealthSettings, m: u32) -> Option<String> {
    let mut js = String::new();
    let d = "var d=function(o,k,v){try{Object.defineProperty(o,k,{get:function(){return v},configurable:true})}catch(e){}};var N=w.Navigator&&w.Navigator.prototype;";
    if m & o::DNT != 0 {
        js.push_str("if(N){d(N,'doNotTrack','1');d(N,'globalPrivacyControl',true);}\n");
    }
    if m & (o::REFERRER | o::SEARCH_QUERIES) != 0 {
        // `document.referrer` follows what the header now says: a foreign referrer is replaced by
        // this page's origin (or the custom value); with only the search option, referrers from
        // search engines are. Sites are compared by their last two host labels.
        let custom = serde_json::to_string(&s.referer_custom).unwrap_or_else(|_| "\"\"".into());
        let all = if m & o::REFERRER != 0 {
            "true"
        } else {
            "false"
        };
        js.push_str(&format!(
            "try{{var D=w.Document.prototype,g=Object.getOwnPropertyDescriptor(D,'referrer').get;\
var site=function(h){{return h.split('.').slice(-2).join('.')}};\
var se=/^(www\\.|search\\.|html\\.|lite\\.|images\\.|m\\.)?(google|bing|duckduckgo|yahoo|yandex|baidu|ecosia|startpage|qwant|ask|naver|seznam|kagi|mojeek|sogou)\\.[a-z.]+$|^search\\.brave\\.com$/;\
Object.defineProperty(D,'referrer',{{get:function(){{var r=g.call(this);if(!r)return r;try{{var u=new URL(r),h=this.location.hostname;if(site(u.hostname)===site(h))return r;\
if(!({all}||se.test(u.hostname)))return r;return {custom}||this.location.origin+'/'}}catch(e){{return r}}}},configurable:true}})}}catch(e){{}}\n"
        ));
    }
    if m & o::WEBRTC != 0 {
        js.push_str(
            "['RTCPeerConnection','webkitRTCPeerConnection','mozRTCPeerConnection'].forEach(function(n){var O=w[n];if(typeof O!=='function')return;\
var P=new w.Proxy(O,{construct:function(t,a,nt){var c=Object.assign({},a[0]||{});c.iceTransportPolicy='relay';\
c.iceServers=(c.iceServers||[]).filter(function(s){var u=[].concat(s.urls||s.url||[]);return u.length>0&&u.every(function(x){return /^turns?:/i.test(x)})});\
return Reflect.construct(t,[c].concat([].slice.call(a,1)),nt)}});\
try{Object.defineProperty(w,n,{value:P,configurable:true,writable:true})}catch(e){}});\n",
        );
    }
    if m & o::PUSH != 0 {
        js.push_str(
            "try{if(w.PushManager)Object.defineProperty(w,'PushManager',{value:undefined,configurable:true,writable:true})}catch(e){}\
try{var R=w.ServiceWorkerRegistration&&w.ServiceWorkerRegistration.prototype;if(R)d(R,'pushManager',undefined)}catch(e){}\
try{if(w.Notification){w.Notification.requestPermission=function(cb){if(typeof cb==='function')cb('denied');return Promise.resolve('denied')};d(w.Notification,'permission','denied')}}catch(e){}\n",
        );
    }
    if m & o::LOCATION != 0 {
        js.push_str(
            "try{var G=w.Geolocation&&w.Geolocation.prototype;if(G){var deny=function(ok,err){if(typeof err==='function')setTimeout(function(){err({code:1,message:'User denied Geolocation',PERMISSION_DENIED:1,POSITION_UNAVAILABLE:2,TIMEOUT:3})},0);return 0};\
Object.defineProperty(G,'getCurrentPosition',{value:deny,configurable:true,writable:true});Object.defineProperty(G,'watchPosition',{value:deny,configurable:true,writable:true})}}catch(e){}\n",
        );
    }
    if m & o::JAVA != 0 {
        js.push_str("if(N){try{Object.defineProperty(N,'javaEnabled',{value:function(){return false},configurable:true,writable:true})}catch(e){}}\n");
    }
    if js.is_empty() {
        return None;
    }
    // `apply(w)` patches one window; frames the page reaches through `contentWindow` /
    // `contentDocument` (about:blank and srcdoc ones never load this script) are patched on
    // first access.
    Some(format!(
        "(function(){{'use strict';var done=new WeakSet();\
function apply(w){{if(done.has(w))return;done.add(w);try{{{d}\n{js}}}catch(e){{}}}}\n\
apply(window);\
try{{var P=HTMLIFrameElement.prototype,cw=Object.getOwnPropertyDescriptor(P,'contentWindow').get,cd=Object.getOwnPropertyDescriptor(P,'contentDocument').get;\
Object.defineProperty(P,'contentWindow',{{get:function(){{var w=cw.call(this);try{{if(w&&w.document)apply(w)}}catch(e){{}}return w}},configurable:true}});\
Object.defineProperty(P,'contentDocument',{{get:function(){{var x=cd.call(this);try{{if(x&&x.defaultView)apply(x.defaultView)}}catch(e){{}}return x}},configurable:true}})}}catch(e){{}}\
}})();"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_profile::{BrowserProfile, Family};
    use std::time::Duration;

    fn on() -> StealthSettings {
        StealthSettings {
            enabled: true,
            ..Default::default()
        }
    }

    const NAV: ReqKind = ReqKind {
        document: true,
        unsafe_method: false,
    };
    const SUB: ReqKind = ReqKind {
        document: false,
        unsafe_method: false,
    };

    #[test]
    fn master_switch_gates_everything_and_defaults_follow_adguard() {
        assert_eq!(mask(&StealthSettings::default()), 0);
        let m = mask(&on());
        for b in [
            o::SEARCH_QUERIES,
            o::DNT,
            o::REFERRER,
            o::X_CLIENT_DATA,
            o::COOKIES_3P,
            o::CACHE_3P,
            o::FLASH,
            o::JAVA,
        ] {
            assert_ne!(m & b, 0, "{b:#x} on by default");
        }
        for b in [
            o::USER_AGENT,
            o::IP,
            o::COOKIES_1P,
            o::AUTH_3P,
            o::WEBRTC,
            o::PUSH,
            o::LOCATION,
            o::TRACKING_PARAMS,
        ] {
            assert_eq!(m & b, 0, "{b:#x} off by default");
        }
        assert_eq!(on().third_party_cookie_minutes, 2880);
    }

    #[test]
    fn tracking_params_are_stripped_and_the_rest_kept() {
        assert_eq!(
            strip_tracking("https://a.test/p?x=1&utm_source=s&fbclid=9&y=2#f").as_deref(),
            Some("https://a.test/p?x=1&y=2#f")
        );
        assert_eq!(
            strip_tracking("https://a.test/p?UTM_Medium=1&gclid=2").as_deref(),
            Some("https://a.test/p")
        );
        assert_eq!(strip_tracking("https://a.test/p?x=1&utmx=2"), None);
        assert_eq!(strip_tracking("https://a.test/p"), None);
    }

    #[test]
    fn third_party_is_by_registrable_domain() {
        assert!(!is_third_party("cdn.a.test", "https://www.a.test/x"));
        assert!(is_third_party("b.test", "https://www.a.test/x"));
        assert!(is_third_party("b.test", ""));
        assert!(!is_third_party("x.co.uk", "https://y.x.co.uk/"));
        assert!(is_third_party("x.co.uk", "https://y.co.uk/"));
    }

    fn with_referer(r: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(REFERER, r.parse().unwrap());
        h
    }

    #[test]
    fn search_queries_are_hidden_on_navigations_with_the_targets_origin() {
        let mut s = on();
        s.hide_referer = false;
        let g = "https://www.google.com/search?q=secret";
        let mut h = with_referer(g);
        let out = apply_request(&s, mask(&s), &mut h, "https://site.test/p", true, NAV);
        assert_eq!(h[REFERER], "https://site.test/");
        assert_eq!(out.orig_referer.as_deref(), Some(g));
        // Subresources are not navigations: untouched by the search option.
        let mut h = with_referer(g);
        apply_request(&s, mask(&s), &mut h, "https://site.test/a.js", true, SUB);
        assert_eq!(h[REFERER], g);
        // Not a search engine.
        let mut h = with_referer("https://blog.test/a?b=1");
        apply_request(&s, mask(&s), &mut h, "https://site.test/p", true, NAV);
        assert_eq!(h[REFERER], "https://blog.test/a?b=1");
    }

    #[test]
    fn third_party_referer_is_replaced_but_not_on_unsafe_methods() {
        let s = on();
        let mut h = with_referer("https://blog.test/a?b=1");
        apply_request(&s, mask(&s), &mut h, "https://site.test/p", true, SUB);
        assert_eq!(h[REFERER], "https://site.test/");
        let mut s2 = on();
        s2.referer_custom = "https://example.org/".into();
        let mut h = with_referer("https://blog.test/a");
        apply_request(&s2, mask(&s2), &mut h, "https://site.test/p", true, SUB);
        assert_eq!(h[REFERER], "https://example.org/");
        // POST and friends keep what the browser sent.
        let post = ReqKind {
            document: false,
            unsafe_method: true,
        };
        let mut h = with_referer("https://blog.test/a?b=1");
        let out = apply_request(&s, mask(&s), &mut h, "https://site.test/p", true, post);
        assert_eq!(h[REFERER], "https://blog.test/a?b=1");
        assert!(out.orig_referer.is_none());
        // Same site: untouched.
        let mut h = with_referer("https://www.site.test/a?b=1");
        apply_request(&s, mask(&s), &mut h, "https://cdn.site.test/p", false, SUB);
        assert_eq!(h[REFERER], "https://www.site.test/a?b=1");
    }

    #[test]
    fn user_agent_keeps_family_form_factor_and_system() {
        let chrome = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.7339.12 Safari/537.36";
        assert_eq!(
            reduce_ua(chrome).unwrap(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
        );
        assert!(reduce_ua(&format!("{chrome} Edg/149.0.2.1"))
            .unwrap()
            .ends_with("Safari/537.36 Edg/149.0.0.0"));
        let win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.1.2 Safari/537.36";
        assert!(reduce_ua(win).unwrap().contains("Windows NT 10.0"));
        // Android stays mobile (and a tablet stays a tablet).
        let a = "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.1.2 Mobile Safari/537.36";
        let r = reduce_ua(a).unwrap();
        assert!(
            r.contains("Android 10") && r.contains("Chrome/149.0.0.0 Mobile Safari"),
            "{r}"
        );
        assert!(!reduce_ua(&a.replace(" Mobile", ""))
            .unwrap()
            .contains("Mobile"));
        let fa = "Mozilla/5.0 (Android 14; Mobile; rv:140.0) Gecko/140.0 Firefox/140.0";
        assert_eq!(
            reduce_ua(fa).unwrap(),
            "Mozilla/5.0 (Android 10; Mobile; rv:140.0) Gecko/140.0 Firefox/140.0"
        );
        assert!(reduce_ua(
            "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
        )
        .unwrap()
        .contains("X11; Linux x86_64; rv:140.0"));
        // iOS Safari stays iOS.
        let ios = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
        let r = reduce_ua(ios).unwrap();
        assert!(
            r.contains("iPhone; CPU iPhone OS")
                && r.contains("Version/17.5")
                && r.contains("Mobile/"),
            "{r}"
        );
        assert_eq!(
            BrowserProfile::classify(&ua_headers(&r)).family,
            Family::Safari
        );
        assert!(reduce_ua("curl/8").is_none());
    }

    fn ua_headers(ua: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(USER_AGENT, ua.parse().unwrap());
        h
    }

    #[test]
    fn user_agent_hints_and_tls_profile_agree() {
        let chrome = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.7339.12 Safari/537.36";
        let browser = |h: &mut HeaderMap| {
            h.insert(USER_AGENT, chrome.parse().unwrap());
            h.insert(
                "sec-ch-ua",
                "\"Google Chrome\";v=\"149\", \"Chromium\";v=\"149\""
                    .parse()
                    .unwrap(),
            );
            h.insert("sec-ch-ua-platform", "\"Linux\"".parse().unwrap());
            h.insert(
                "sec-ch-ua-full-version-list",
                "\"x\";v=\"149.0.1\"".parse().unwrap(),
            );
            h.insert(
                "accept-language",
                "de-DE,de;q=0.9,en;q=0.8".parse().unwrap(),
            );
        };
        let mut s = on();
        s.hide_user_agent = true;
        // Reduced: low-entropy hints stay (they stay true), detailed ones go, same family.
        let mut h = HeaderMap::new();
        browser(&mut h);
        apply_request(&s, mask(&s), &mut h, "https://t.test/", true, SUB);
        assert!(h.contains_key("sec-ch-ua") && h.contains_key("sec-ch-ua-platform"));
        assert!(!h.contains_key("sec-ch-ua-full-version-list"));
        assert_eq!(h["accept-language"], "de-DE");
        assert_eq!(BrowserProfile::classify(&h).family, Family::Chrome);
        // A custom Firefox User-Agent on a Chrome browser: every hint goes, and the TLS
        // profile follows the User-Agent that is sent.
        s.user_agent_custom =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"
                .into();
        let mut h = HeaderMap::new();
        browser(&mut h);
        apply_request(&s, mask(&s), &mut h, "https://t.test/", true, SUB);
        assert_eq!(h[USER_AGENT], s.user_agent_custom.as_str());
        assert!(h.keys().all(|k| !k.as_str().starts_with("sec-ch-ua")));
        assert_eq!(BrowserProfile::classify(&h).family, Family::Firefox);
        // And a custom Chrome one on a Firefox browser gets the Chrome profile.
        s.user_agent_custom = chrome.into();
        let mut h =
            ua_headers("Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0");
        apply_request(&s, mask(&s), &mut h, "https://t.test/", true, SUB);
        assert_eq!(BrowserProfile::classify(&h).family, Family::Chrome);
    }

    #[test]
    fn request_options_edit_headers() {
        let mut s = on();
        s.block_third_party_auth = true;
        s.mask_ip = true;
        s.mask_ip_address = "198.51.100.7".into();
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("x-client-data", "abc"),
            ("authorization", "Bearer t"),
            ("if-none-match", "\"e\""),
        ] {
            h.insert(HeaderName::from_static(k), v.parse().unwrap());
        }
        apply_request(&s, mask(&s), &mut h, "https://t.test/", true, SUB);
        assert_eq!(h["dnt"], "1");
        assert_eq!(h["sec-gpc"], "1");
        assert_eq!(h["x-forwarded-for"], "198.51.100.7");
        for k in ["x-client-data", "authorization", "if-none-match"] {
            assert!(!h.contains_key(k), "{k}");
        }
        let mut h = HeaderMap::new();
        h.insert("authorization", "x".parse().unwrap());
        h.insert("if-none-match", "\"e\"".parse().unwrap());
        apply_request(&s, mask(&s), &mut h, "https://t.test/", false, SUB);
        assert!(h.contains_key("authorization") && h.contains_key("if-none-match"));
    }

    #[test]
    fn cookie_dates_parse_like_browsers() {
        let epoch = Some(0);
        for d in [
            "Thu, 01 Jan 1970 00:00:00 GMT",
            "Thu, 01-Jan-1970 00:00:00 GMT",
            "Thursday, 01-Jan-70 00:00:00 GMT",
            "1 jan 1970 0:0:0",
            "Thu Jan  1 00:00:00 1970",
            "00:00:00 01 Jan 70",
        ] {
            assert_eq!(parse_cookie_date(d), epoch, "{d}");
        }
        assert_eq!(
            parse_cookie_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(
            parse_cookie_date("Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(
            parse_cookie_date("Wed, 09 Jun 2021 10:18:14 GMT"),
            Some(1_623_233_894)
        );
        // Two-digit years: 00-69 are 20xx.
        assert_eq!(
            parse_cookie_date("1 Jan 25 00:00:00"),
            parse_cookie_date("1 Jan 2025 00:00:00")
        );
        assert_eq!(parse_cookie_date("garbage"), None);
        assert_eq!(parse_cookie_date("32 Jan 2025 00:00:00"), None);
        assert_eq!(parse_cookie_date("1 Jan 1600 00:00:00"), None);
    }

    #[test]
    fn cookie_lifetimes_are_capped_never_extended_and_deletions_survive() {
        let now = SystemTime::now();
        let l = |v: &str| limit_set_cookie(v, 600, now);
        // Session cookies stay session cookies.
        assert_eq!(l("a=b; Path=/"), None);
        assert_eq!(l("a=b; Expires=garbage"), None);
        assert_eq!(l("a=b; Max-Age=abc; Secure"), None);
        assert_eq!(
            l("a=b; Max-Age=999999; Secure").unwrap(),
            "a=b; Max-Age=600; Secure"
        );
        assert_eq!(l("a=b; Max-Age=60"), None);
        // Deletions, whatever the date spelling.
        assert_eq!(l("a=; Max-Age=0"), None);
        assert_eq!(l("a=; Max-Age=-1"), None);
        for d in [
            "Thu, 01 Jan 1970 00:00:00 GMT",
            "Thu, 01-Jan-1970 00:00:00 GMT",
            "Thursday, 01-Jan-70 00:00:00 GMT",
            "Thu Jan  1 00:00:00 1970",
        ] {
            assert_eq!(l(&format!("a=; Expires={d}")), None, "{d}");
        }
        // Max-Age wins over Expires.
        let far = httpdate::fmt_http_date(now + Duration::from_secs(86400 * 30));
        assert_eq!(l(&format!("a=; Max-Age=0; Expires={far}")), None);
        assert_eq!(
            l(&format!("a=b; Expires={far}; HttpOnly")).unwrap(),
            "a=b; HttpOnly; Max-Age=600"
        );
        let soon = httpdate::fmt_http_date(now + Duration::from_secs(60));
        assert_eq!(l(&format!("a=b; Expires={soon}")), None);
    }

    #[test]
    fn response_cookies_and_etag() {
        let mut s = on();
        let mut h = HeaderMap::new();
        h.insert(hyper::header::ETAG, "\"x\"".parse().unwrap());
        h.append(SET_COOKIE, "a=1; Max-Age=999999".parse().unwrap());
        h.append(SET_COOKIE, "sess=1".parse().unwrap());
        apply_response(&s, mask(&s), &mut h, true);
        assert!(!h.contains_key(hyper::header::ETAG));
        let c: Vec<_> = h
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(c, ["a=1; Max-Age=172800", "sess=1"]);
        s.third_party_cookie_minutes = 0;
        apply_response(&s, mask(&s), &mut h, true);
        assert!(!h.contains_key(SET_COOKIE));
        let mut h = HeaderMap::new();
        h.insert(hyper::header::ETAG, "\"x\"".parse().unwrap());
        h.append(SET_COOKIE, "a=1; Max-Age=999999".parse().unwrap());
        apply_response(&s, mask(&s), &mut h, false);
        assert_eq!(h[SET_COOKIE], "a=1; Max-Age=999999");
        assert!(h.contains_key(hyper::header::ETAG));
        s.first_party_cookies = true;
        s.first_party_cookie_minutes = 5;
        apply_response(&s, mask(&s), &mut h, false);
        assert_eq!(h[SET_COOKIE], "a=1; Max-Age=300");
    }

    #[test]
    fn script_covers_exactly_the_enabled_api_options() {
        let s = on();
        assert!(script(&s, 0).is_none());
        assert!(script(&s, o::FLASH | o::IP).is_none());
        let js = script(&s, o::WEBRTC).unwrap();
        assert!(
            js.contains("RTCPeerConnection")
                && !js.contains("Geolocation")
                && !js.contains("referrer")
        );
        let all = StealthSettings {
            block_webrtc: true,
            block_push: true,
            block_location: true,
            ..on()
        };
        let js = script(&all, mask(&all)).unwrap();
        for k in [
            "globalPrivacyControl",
            "PushManager",
            "Geolocation",
            "iceTransportPolicy",
            "javaEnabled",
            "'referrer'",
            "contentWindow",
            "contentDocument",
        ] {
            assert!(js.contains(k), "{k}");
        }
        // The custom Referer reaches the script as a JSON string.
        let mut c = on();
        c.referer_custom = "https://example.org/\"x".into();
        assert!(script(&c, mask(&c))
            .unwrap()
            .contains(r#""https://example.org/\"x""#));
    }
}

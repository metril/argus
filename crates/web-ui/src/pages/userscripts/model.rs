//! Pure helpers of the userscripts pages (and their unit tests).

use wasm_bindgen::JsCast;

use crate::api::userscripts::{ImportUserscriptsResponse, Userscript, UserscriptCatalogueEntryDto};

/// Shown wherever a script has no update source.
pub const NO_SOURCE_HINT: &str = "This script has no @updateURL or @downloadURL, so Argus can't check for new versions. Reinstall from a URL to enable updates.";

/// A grant without its `GM_` / `GM.` prefix, lower-case (the server lower-cases them).
pub fn grant_key(grant: &str) -> String {
    let g = grant.trim().to_ascii_lowercase();
    g.strip_prefix("gm_")
        .or_else(|| g.strip_prefix("gm."))
        .unwrap_or(&g)
        .to_string()
}

/// Canonical spelling of a grant for display (`gm_getvalue` -> `GM_getValue`).
pub fn grant_display(grant: &str) -> String {
    const NAMES: [&str; 22] = [
        "getValue",
        "setValue",
        "deleteValue",
        "listValues",
        "addValueChangeListener",
        "removeValueChangeListener",
        "xmlhttpRequest",
        "setClipboard",
        "openInTab",
        "notification",
        "download",
        "cookie",
        "addStyle",
        "addElement",
        "registerMenuCommand",
        "unregisterMenuCommand",
        "getResourceText",
        "getResourceURL",
        "log",
        "info",
        "getTab",
        "saveTab",
    ];
    let key = grant_key(grant);
    let sep = if grant.to_ascii_lowercase().starts_with("gm.") {
        "GM."
    } else {
        "GM_"
    };
    NAMES
        .iter()
        .find(|n| n.to_ascii_lowercase() == key)
        .map_or_else(|| grant.to_string(), |n| format!("{sep}{n}"))
}

/// `document-end` from the server's `DocumentEnd`.
pub fn run_at_label(r: &str) -> String {
    let mut out = String::new();
    for (i, c) in r.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push('-');
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

/// Grants that deserve a warning highlight.
pub fn is_sensitive_grant(grant: &str) -> bool {
    matches!(
        grant_key(grant).as_str(),
        "xmlhttprequest" | "cookie" | "download" | "setclipboard" | "notification"
    )
}

/// Plain-language meaning of a grant.
pub fn grant_meaning(grant: &str) -> &'static str {
    match grant_key(grant).as_str() {
        "none" => "Does not use any Greasemonkey API",
        "xmlhttprequest" => "Send requests to other sites and read the replies",
        "getvalue" => "Read its saved settings",
        "setvalue" => "Save settings",
        "deletevalue" => "Delete saved settings",
        "listvalues" => "List its saved settings",
        "addvaluechangelistener" | "removevaluechangelistener" => "Watch its saved settings",
        "setclipboard" => "Write to your clipboard",
        "openintab" => "Open new tabs",
        "notification" => "Show desktop notifications",
        "download" => "Download files",
        "cookie" => "Read and change cookies",
        "addstyle" => "Add CSS to the page",
        "addelement" => "Add elements to the page",
        "registermenucommand" | "unregistermenucommand" => "Add commands to the Argus menu",
        "getresourcetext" | "getresourceurl" => "Read its bundled resources",
        "log" => "Write to the console",
        "info" => "Read script and browser details",
        "unsafewindow" => "Access the page's own scripts",
        _ => "Userscript API",
    }
}

/// What identifies a script URL for "already installed": Greasy Fork scripts by their numeric
/// id (the mirror host and file name vary), anything else by the URL itself. The host must be
/// greasyfork.org / sleazyfork.org or a subdomain of one, never a lookalike.
pub fn url_key(u: &str) -> String {
    let u = u.trim();
    let rest = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"));
    if let Some(rest) = rest {
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        if !authority.contains(['@', '\\', ' ']) {
            let host = authority
                .rsplit_once(':')
                .map_or(authority, |(h, port)| {
                    if port.chars().all(|c| c.is_ascii_digit()) {
                        h
                    } else {
                        authority
                    }
                })
                .to_ascii_lowercase();
            let ours = ["greasyfork.org", "sleazyfork.org"]
                .iter()
                .any(|d| host == *d || host.ends_with(&format!(".{d}")));
            if let (true, Some(tail)) = (ours, path.strip_prefix("/scripts/")) {
                let id: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
                let after = &tail[id.len()..];
                if !id.is_empty() && (after.is_empty() || after.starts_with(['/', '?', '#'])) {
                    return format!("gf:{id}");
                }
            }
        }
    }
    u.to_string()
}

/// Host part of a URL (no scheme, port, path); the input itself when it has no scheme.
pub fn url_host(u: &str) -> String {
    let rest = u.split_once("://").map_or(u, |(_, r)| r);
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    rest[..end].rsplit('@').next().unwrap_or("").to_string()
}

/// Host and the remainder of a URL, for a bold host in `.urlrow`.
pub fn split_url(u: &str) -> (String, String) {
    let (scheme, rest) = u.split_once("://").map_or(("", u), |(s, r)| (s, r));
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let head = if scheme.is_empty() {
        String::new()
    } else {
        format!("{scheme}://")
    };
    (format!("{head}{}", &rest[..end]), rest[end..].to_string())
}

pub fn fmt_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", n as f64 / 1048576.0)
    }
}

/// Counts of results by status, as `(ok, skipped, errors)`.
pub fn import_summary(r: &ImportUserscriptsResponse) -> (usize, usize, usize) {
    let mut t = (0, 0, 0);
    for x in &r.results {
        match x.status.as_str() {
            "installed" | "replaced" => t.0 += 1,
            "skipped" => t.1 += 1,
            _ => t.2 += 1,
        }
    }
    t
}

// ---------------------------------------------------------------------------
// Row state
// ---------------------------------------------------------------------------

/// What a script row or page header says about the script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateState {
    Ok,
    Off,
    /// Pending update to this version.
    Update(String),
    Error,
    /// Imported without approval and still disabled.
    NeedsApproval,
}

/// State of a script; `approval` is the ids imported without approval.
pub fn update_status(s: &Userscript, approval: &[String]) -> UpdateState {
    if !s.enabled && approval.contains(&s.id) {
        UpdateState::NeedsApproval
    } else if let Some(p) = &s.pending_update {
        UpdateState::Update(p.new_version.clone().unwrap_or_else(|| "?".into()))
    } else if s.error {
        UpdateState::Error
    } else if !s.enabled {
        UpdateState::Off
    } else {
        UpdateState::Ok
    }
}

/// `(pill class, text)` of a state, if it has a pill.
pub fn state_pill(st: &UpdateState) -> Option<(&'static str, String)> {
    match st {
        UpdateState::Ok => None,
        UpdateState::Off => Some(("p-neutral", "Off".into())),
        UpdateState::Update(v) => Some(("p-pass", format!("Update {v}"))),
        UpdateState::Error => Some(("p-block", "Error".into())),
        UpdateState::NeedsApproval => Some(("p-error", "Needs approval".into())),
    }
}

/// Whether the "Needs attention" filter lists the script.
pub fn needs_attention(s: &Userscript, approval: &[String]) -> bool {
    matches!(
        update_status(s, approval),
        UpdateState::Update(_) | UpdateState::Error | UpdateState::NeedsApproval
    ) || s.pending_update.is_some()
        || s.error
}

// ---------------------------------------------------------------------------
// Imported scripts awaiting approval (the server only says "disabled"; this remembers why)
// ---------------------------------------------------------------------------

const APPROVAL_KEY: &str = "us.approval";

pub fn approval_load() -> Vec<String> {
    use gloo_storage::Storage;
    gloo_storage::LocalStorage::get::<Vec<String>>(APPROVAL_KEY).unwrap_or_default()
}

pub fn approval_add(ids: impl IntoIterator<Item = String>) {
    use gloo_storage::Storage;
    let mut v = approval_load();
    for id in ids {
        if !v.contains(&id) {
            v.push(id);
        }
    }
    let _ = gloo_storage::LocalStorage::set(APPROVAL_KEY, v);
}

pub fn approval_remove(id: &str) {
    use gloo_storage::Storage;
    let mut v = approval_load();
    v.retain(|x| x != id);
    let _ = gloo_storage::LocalStorage::set(APPROVAL_KEY, v);
}

// ---------------------------------------------------------------------------
// Sites and permissions
// ---------------------------------------------------------------------------

/// Plain host of a `@match`/`@include` pattern; `None` for "every site".
pub fn site_name(p: &str) -> Option<String> {
    let p = p.trim();
    if matches!(
        p,
        "*" | "<all_urls>" | "*://*/*" | "http*://*/*" | "*://*" | "*://*/"
    ) {
        return None;
    }
    if p.starts_with('/') && p.ends_with('/') && p.len() > 2 {
        return Some(p.to_string()); // a regex include
    }
    let rest = p.split_once("://").map_or(p, |(_, r)| r);
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = rest[..end].trim_start_matches("*.").trim_end_matches(':');
    if host.is_empty() || host == "*" {
        None
    } else {
        Some(host.to_string())
    }
}

/// Distinct host names of `patterns` and whether any of them means every site.
pub fn site_list(patterns: &[String]) -> (Vec<String>, bool) {
    let mut hosts: Vec<String> = Vec::new();
    let mut every = false;
    for p in patterns {
        match site_name(p) {
            None => every = true,
            Some(h) => {
                if !hosts.contains(&h) {
                    hosts.push(h)
                }
            }
        }
    }
    (hosts, every)
}

/// The network line of a permission summary: the same words in the catalogue and in the review.
/// `None` when the script has no network grant.
pub fn connect_phrase(has_xhr: bool, connect: &[String]) -> Option<(String, bool)> {
    if !has_xhr {
        return None;
    }
    if connect.iter().any(|c| c == "*") {
        Some(("Can contact any site".into(), true))
    } else if connect.is_empty() {
        Some(("Can contact any site (approval required)".into(), true))
    } else {
        let n = connect.len();
        Some((
            format!("Can contact {n} site{}", if n == 1 { "" } else { "s" }),
            false,
        ))
    }
}

/// Plain-language permission lines `(icon, text, hot)`. Capabilities use the `bolt` icon,
/// stored settings and external code the `code` icon.
pub fn perm_items(
    grants: &[String],
    connect: &[String],
    n_require: usize,
    unhashed: bool,
) -> Vec<(&'static str, String, bool)> {
    let has = |name: &str| grants.iter().any(|g| grant_key(g) == name);
    let mut v = Vec::new();
    if let Some((t, hot)) = connect_phrase(has("xmlhttprequest"), connect) {
        v.push(("bolt", t, hot));
    }
    if has("setclipboard") {
        v.push(("bolt", "Can write to clipboard".into(), true));
    }
    if has("openintab") {
        v.push(("bolt", "Can open tabs".into(), false));
    }
    if has("cookie") {
        v.push(("bolt", "Can read cookies".into(), true));
    }
    if has("download") {
        v.push(("bolt", "Can download files".into(), true));
    }
    if has("notification") {
        v.push(("bolt", "Can show notifications".into(), false));
    }
    if has("getvalue") || has("setvalue") {
        v.push(("code", "Stores settings".into(), false));
    }
    if n_require > 0 {
        v.push((
            "code",
            format!(
                "Uses {n_require} external librar{}",
                if n_require == 1 { "y" } else { "ies" }
            ),
            unhashed,
        ));
    }
    if v.is_empty() {
        v.push(("bolt", "No special permissions".into(), false));
    }
    v
}

/// Permission summary of a catalogue entry (the catalogue only knows `none | basic | xhr`).
pub fn perm_summary(e: &UserscriptCatalogueEntryDto) -> Vec<(&'static str, String, bool)> {
    let grants: Vec<String> = match e.needs_gm.as_str() {
        "xhr" => vec!["GM_xmlhttpRequest".into(), "GM_getValue".into()],
        "basic" => vec!["GM_getValue".into(), "GM_setValue".into()],
        _ => Vec::new(),
    };
    let unhashed = e
        .requires
        .iter()
        .any(|u| !u.contains("#sha") && !u.contains("#md5"));
    perm_items(&grants, &e.connect, e.requires.len(), unhashed)
}

/// Offer a JSON file as a browser download.
pub(crate) fn download_text(filename: &str, text: &str) -> Result<(), String> {
    download_as(filename, text, "application/json")
}

/// Offer a text file as a browser download via Blob + anchor.
pub(crate) fn download_as(filename: &str, text: &str, mime: &str) -> Result<(), String> {
    let err = |e: wasm_bindgen::JsValue| format!("{:?}", e);
    let parts = js_sys::Array::new();
    parts.push(&wasm_bindgen::JsValue::from_str(text));
    let opts = web_sys::BlobPropertyBag::new();
    opts.set_type(mime);
    let blob = web_sys::Blob::new_with_str_sequence_and_options(&parts, &opts).map_err(err)?;
    let url = web_sys::Url::create_object_url_with_blob(&blob).map_err(err)?;
    let doc = web_sys::window()
        .and_then(|w| w.document())
        .ok_or("no document")?;
    let a: web_sys::HtmlAnchorElement = doc
        .create_element("a")
        .map_err(err)?
        .dyn_into()
        .map_err(|_| "anchor")?;
    a.set_href(&url);
    a.set_download(filename);
    a.click();
    let _ = web_sys::Url::revoke_object_url(&url);
    Ok(())
}

// ---------------------------------------------------------------------------
// Dates
// ---------------------------------------------------------------------------

/// "5 min ago", "2 h ago" from an age in seconds.
pub fn rel_from_secs(d: i64) -> String {
    let d = d.max(0);
    match d {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", d / 60),
        3600..=86399 => format!("{} h ago", d / 3600),
        86400..=2591999 => format!("{} d ago", d / 86400),
        _ => format!("{} mo ago", d / 2592000),
    }
}

/// Relative age of an RFC 3339 time.
pub fn rel_time(iso: &str) -> String {
    let t = js_sys::Date::parse(iso);
    if t.is_nan() {
        return iso.to_string();
    }
    rel_from_secs(((js_sys::Date::now() - t) / 1000.0) as i64)
}

/// "24 Nov 2026" from an RFC 3339 time (the date part, as written).
pub fn fmt_date(iso: &str) -> String {
    const M: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mut it = iso.get(..10).unwrap_or("").split('-');
    match (it.next(), it.next(), it.next()) {
        (Some(y), Some(m), Some(d)) => match m.parse::<usize>() {
            Ok(m) if (1..=12).contains(&m) => {
                format!("{} {} {y}", d.trim_start_matches('0'), M[m - 1])
            }
            _ => iso.to_string(),
        },
        _ => iso.to_string(),
    }
}

/// "2026-11-24 07:54" from an RFC 3339 time, for `title` attributes.
pub fn fmt_abs(iso: &str) -> String {
    iso.get(..16).unwrap_or(iso).replace('T', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use api_types::ImportResultDto;

    #[test]
    fn sensitive_grants() {
        assert!(is_sensitive_grant("GM_xmlhttpRequest"));
        assert!(is_sensitive_grant("GM.cookie"));
        assert!(is_sensitive_grant("GM_setClipboard"));
        assert!(!is_sensitive_grant("GM_getValue"));
        assert_eq!(grant_meaning("GM.setClipboard"), "Write to your clipboard");
        assert!(is_sensitive_grant("gm_xmlhttprequest"));
        assert_eq!(grant_display("gm_getvalue"), "GM_getValue");
        assert_eq!(grant_display("GM.xmlHttpRequest"), "GM.xmlhttpRequest");
        assert_eq!(grant_display("unsafeWindow"), "unsafeWindow");
        assert_eq!(run_at_label("DocumentEnd"), "document-end");
    }

    #[test]
    fn url_keys() {
        assert_eq!(
            url_key("https://update.greasyfork.org/scripts/584347/Some%20Name.user.js"),
            url_key("https://greasyfork.org/scripts/584347/code/x.user.js")
        );
        assert_eq!(
            url_key("https://x.test/a.user.js"),
            "https://x.test/a.user.js"
        );
        assert_eq!(url_host("https://a.test:8080/x?y"), "a.test:8080");
        assert_eq!(
            split_url("https://cdn.test/lib.js"),
            ("https://cdn.test".to_string(), "/lib.js".to_string())
        );
    }

    fn entry(needs: &str, connect: &[&str], requires: &[&str]) -> UserscriptCatalogueEntryDto {
        UserscriptCatalogueEntryDto {
            id: "a".into(),
            name: "a".into(),
            description: String::new(),
            install_url: String::new(),
            homepage: String::new(),
            sites: vec![],
            category: "ads".into(),
            licence: "MIT".into(),
            licence_note: None,
            needs_gm: needs.into(),
            connect: connect.iter().map(|s| s.to_string()).collect(),
            requires: requires.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn network_wording_is_shared() {
        // The catalogue and the review use the same phrase for the same facts.
        let any = perm_summary(&entry("xhr", &["*"], &["https://cdn.test/x.js"]));
        assert!(any.contains(&("bolt", "Can contact any site".to_string(), true)));
        assert!(any.contains(&("code", "Uses 1 external library".to_string(), true)));
        let none = perm_items(&["GM_xmlhttpRequest".into()], &[], 0, false);
        assert_eq!(
            none[0].1,
            "Can contact any site (approval required)".to_string()
        );
        assert!(none[0].2);
        let some = perm_items(&["GM.xmlHttpRequest".into()], &["a.test".into()], 0, false);
        assert_eq!(some[0], ("bolt", "Can contact 1 site".to_string(), false));
        assert_eq!(
            perm_summary(&entry("none", &[], &[])),
            vec![("bolt", "No special permissions".to_string(), false)]
        );
    }

    #[test]
    fn sites() {
        assert_eq!(
            site_name("*://*.stackoverflow.com/*").unwrap(),
            "stackoverflow.com"
        );
        assert_eq!(site_name("https://a.test/path/*").unwrap(), "a.test");
        assert_eq!(site_name("*://*/*"), None);
        assert_eq!(site_name("<all_urls>"), None);
        let (h, every) = site_list(&[
            "https://a.test/*".into(),
            "http://a.test/x".into(),
            "*://*/*".into(),
        ]);
        assert_eq!(h, vec!["a.test".to_string()]);
        assert!(every);
    }

    #[test]
    fn bytes_and_dates() {
        assert_eq!(fmt_bytes(10), "10 B");
        assert_eq!(fmt_bytes(2048), "2.0 KiB");
        assert_eq!(fmt_bytes(3 * 1048576), "3.0 MiB");
        assert_eq!(rel_from_secs(30), "just now");
        assert_eq!(rel_from_secs(7300), "2 h ago");
        assert_eq!(fmt_date("2026-11-24T07:54:58Z"), "24 Nov 2026");
        assert_eq!(fmt_abs("2026-11-24T07:54:58Z"), "2026-11-24 07:54");
    }

    #[test]
    fn summary() {
        let r = |s: &str| ImportResultDto {
            id: None,
            name: None,
            status: s.into(),
            error: None,
            pending_approval: false,
        };
        let resp = ImportUserscriptsResponse {
            results: vec![r("installed"), r("replaced"), r("skipped"), r("error")],
        };
        assert_eq!(import_summary(&resp), (2, 1, 1));
    }
}

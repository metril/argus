//! Install / update planning. The caller fetches; this crate plans, verifies and builds.
//!
//! Flow: `plan_install(source, origin)` lists what to download -> caller downloads ->
//! `finish_install(plan, fetched, approvals)` verifies SRI and returns a ready `Userscript`.
//! Updates: `plan_update` + [`UpdateDiff`]; an update that widens `@match`/`@include`,
//! `@connect` or `@grant` must be explicitly approved before `finish_update` will apply it.

use crate::{
    matcher::{Options, Rules},
    metadata::{Sri, UserscriptMetadata},
    script::{RequireBlob, ResourceBlob, ScriptAssets, Userscript},
    Error, Result,
};
use base64::Engine;
use chrono::Utc;
use md5::Md5;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{cmp::Ordering, collections::HashMap};
use url::Url;

pub const MAX_REQUIRES: usize = 32;
pub const MAX_RESOURCES: usize = 64;
pub const MAX_ASSET_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct FetchSpec {
    pub url: Url,
    pub sri: Vec<Sri>,
}

#[derive(Debug, Clone)]
pub struct ResourceFetch {
    pub name: String,
    pub url: Url,
    pub sri: Vec<Sri>,
}

/// What the user is being asked to approve.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantsSummary {
    /// Canonical grants (empty for `@grant none`).
    pub grants: Vec<String>,
    pub connect: Vec<String>,
    pub matches: Vec<String>,
    /// `@connect *`
    pub connect_all: bool,
    pub network: bool,
    pub cookies: bool,
    pub downloads: bool,
    pub clipboard: bool,
    pub notifications: bool,
    /// Directives requested but not achievable here.
    pub unsupported: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct InstallPlan {
    pub metadata: UserscriptMetadata,
    pub source: String,
    pub origin_url: Option<Url>,
    pub requires: Vec<FetchSpec>,
    pub resources: Vec<ResourceFetch>,
    pub warnings: Vec<String>,
    pub grants_summary: GrantsSummary,
}

/// Downloaded bodies, keyed by URL (requires) / resource name.
#[derive(Debug, Default)]
pub struct Fetched {
    pub requires: HashMap<String, Vec<u8>>,
    /// name -> (bytes, content-type)
    pub resources: HashMap<String, (Vec<u8>, Option<String>)>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Approvals {
    /// The user approved `@connect *`.
    pub allow_connect_all: bool,
}

fn resolve(base: Option<&Url>, raw: &str) -> std::result::Result<Url, String> {
    let r = match base {
        Some(b) => b.join(raw),
        None => Url::parse(raw),
    };
    let u = r.map_err(|e| format!("{raw}: {e}"))?;
    match u.scheme() {
        "http" | "https" => Ok(u),
        "data" => Ok(u),
        s => Err(format!("{raw}: unsupported scheme {s}")),
    }
}

pub fn summarize(meta: &UserscriptMetadata) -> GrantsSummary {
    let grants = meta.effective_grants();
    let has = |n: &str| grants.iter().any(|g| g == n);
    let mut matches: Vec<String> = meta.matches.iter().chain(&meta.includes).cloned().collect();
    matches.sort();
    let mut connect = meta.connect.clone();
    connect.sort();
    connect.dedup();
    GrantsSummary {
        connect_all: connect.iter().any(|c| c == "*"),
        network: has("gm_xmlhttprequest") || has("gm_download"),
        cookies: has("gm_cookie"),
        downloads: has("gm_download"),
        clipboard: has("gm_setclipboard"),
        notifications: has("gm_notification"),
        unsupported: meta
            .unsupported()
            .iter()
            .map(|w| w.message.clone())
            .collect(),
        grants,
        connect,
        matches,
    }
}

/// Parse `source` and list what must be downloaded. `origin_url` resolves relative URLs.
pub fn plan_install(source: &str, origin_url: Option<&Url>) -> Result<InstallPlan> {
    let metadata = UserscriptMetadata::parse(source)?;
    let mut warnings: Vec<String> = metadata
        .warnings
        .iter()
        .map(|w| w.message.clone())
        .collect();
    let (_, errs) = Rules::compile(&metadata, Options::default());
    warnings.extend(errs);
    if metadata.requires.len() > MAX_REQUIRES {
        return Err(Error::InvalidScript(format!(
            "too many @require ({} > {MAX_REQUIRES})",
            metadata.requires.len()
        )));
    }
    if metadata.resources.len() > MAX_RESOURCES {
        return Err(Error::InvalidScript(format!(
            "too many @resource ({} > {MAX_RESOURCES})",
            metadata.resources.len()
        )));
    }
    let mut requires = Vec::new();
    for r in &metadata.requires {
        match resolve(origin_url, &r.url) {
            Ok(url) => requires.push(FetchSpec {
                url,
                sri: r.sri.clone(),
            }),
            Err(e) => return Err(Error::InvalidScript(format!("@require {e}"))),
        }
    }
    let mut resources = Vec::new();
    for r in &metadata.resources {
        if r.name.contains(['/', '\\', '\0']) || r.name.contains("..") {
            return Err(Error::InvalidScript(format!(
                "invalid @resource name {:?}",
                r.name
            )));
        }
        match resolve(origin_url, &r.url) {
            Ok(url) => resources.push(ResourceFetch {
                name: r.name.clone(),
                url,
                sri: r.sri.clone(),
            }),
            Err(e) => return Err(Error::InvalidScript(format!("@resource {e}"))),
        }
    }
    for r in &requires {
        if r.sri.is_empty() && r.url.scheme() == "http" {
            warnings.push(format!(
                "@require {} is fetched over plain http without an integrity hash",
                r.url
            ));
        }
    }
    Ok(InstallPlan {
        grants_summary: summarize(&metadata),
        metadata,
        source: source.to_string(),
        origin_url: origin_url.cloned(),
        requires,
        resources,
        warnings,
    })
}

/// Check `data` against every hash in `sri` (all must match; an empty list passes).
pub fn verify_sri(data: &[u8], sri: &[Sri]) -> std::result::Result<(), String> {
    for s in sri {
        let got: Vec<u8> = match s.algo.as_str() {
            "md5" => Md5::digest(data).to_vec(),
            "sha256" => Sha256::digest(data).to_vec(),
            "sha384" => Sha384::digest(data).to_vec(),
            "sha512" => Sha512::digest(data).to_vec(),
            a => return Err(format!("unsupported hash {a}")),
        };
        if got != s.digest {
            return Err(format!("{} mismatch", s.algo));
        }
    }
    Ok(())
}

fn mime_guess(url: &Url, ct: Option<&str>) -> String {
    if let Some(c) = ct {
        let c = c.split(';').next().unwrap_or("").trim();
        if !c.is_empty() {
            return c.to_ascii_lowercase();
        }
    }
    let path = url.path().to_ascii_lowercase();
    match path.rsplit('.').next().unwrap_or("") {
        "css" => "text/css",
        "js" => "text/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "html" | "htm" => "text/html",
        "txt" => "text/plain",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Verify downloads and build the script. Every planned `@require`/`@resource` must be present.
pub fn finish_install(
    plan: InstallPlan,
    fetched: Fetched,
    approvals: Approvals,
) -> Result<Userscript> {
    let mut assets = ScriptAssets::default();
    for r in &plan.requires {
        let body = fetched.requires.get(r.url.as_str()).ok_or_else(|| {
            Error::InvalidScript(format!("@require {} was not downloaded", r.url))
        })?;
        if body.len() > MAX_ASSET_BYTES {
            return Err(Error::InvalidScript(format!(
                "@require {} is too large",
                r.url
            )));
        }
        verify_sri(body, &r.sri)
            .map_err(|e| Error::InvalidScript(format!("@require {}: {e}", r.url)))?;
        let content = String::from_utf8(body.clone())
            .map_err(|_| Error::InvalidScript(format!("@require {} is not UTF-8", r.url)))?;
        assets.requires.push(RequireBlob {
            url: r.url.to_string(),
            content: content.trim_start_matches('\u{feff}').to_string(),
        });
    }
    for r in &plan.resources {
        let (body, ct) = fetched.resources.get(&r.name).ok_or_else(|| {
            Error::InvalidScript(format!("@resource {} was not downloaded", r.name))
        })?;
        if body.len() > MAX_ASSET_BYTES {
            return Err(Error::InvalidScript(format!(
                "@resource {} is too large",
                r.name
            )));
        }
        verify_sri(body, &r.sri)
            .map_err(|e| Error::InvalidScript(format!("@resource {}: {e}", r.name)))?;
        assets.resources.push(ResourceBlob {
            name: r.name.clone(),
            url: r.url.to_string(),
            mime: mime_guess(&r.url, ct.as_deref()),
            data_b64: base64::engine::general_purpose::STANDARD.encode(body),
        });
    }
    if approvals.allow_connect_all && !plan.grants_summary.connect_all {
        return Err(Error::InvalidScript(
            "@connect * approved but not requested".into(),
        ));
    }
    let mut s = Userscript::new(plan.source)?;
    s.assets = assets;
    s.allow_connect_all = approvals.allow_connect_all;
    Ok(s)
}

/// Capability changes between two versions of a script.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdateDiff {
    pub added_matches: Vec<String>,
    pub added_connect: Vec<String>,
    pub added_grants: Vec<String>,
    pub removed_matches: Vec<String>,
    pub removed_connect: Vec<String>,
    pub removed_grants: Vec<String>,
}

impl UpdateDiff {
    /// An update that widens what the script may do needs explicit re-approval.
    pub fn needs_reapproval(&self) -> bool {
        !(self.added_matches.is_empty()
            && self.added_connect.is_empty()
            && self.added_grants.is_empty())
    }
}

fn set_diff(old: &[String], new: &[String]) -> (Vec<String>, Vec<String>) {
    let add = new.iter().filter(|x| !old.contains(x)).cloned().collect();
    let rem = old.iter().filter(|x| !new.contains(x)).cloned().collect();
    (add, rem)
}

pub fn diff(old: &UserscriptMetadata, new: &UserscriptMetadata) -> UpdateDiff {
    let pats = |m: &UserscriptMetadata| {
        let mut v: Vec<String> = m
            .matches
            .iter()
            .map(|s| format!("@match {s}"))
            .chain(m.includes.iter().map(|s| format!("@include {s}")))
            .collect();
        v.sort();
        v.dedup();
        v
    };
    let conn = |m: &UserscriptMetadata| {
        let mut v = m.connect.clone();
        v.sort();
        v.dedup();
        v
    };
    let gr = |m: &UserscriptMetadata| m.effective_grants();
    let (added_matches, removed_matches) = set_diff(&pats(old), &pats(new));
    let (added_connect, removed_connect) = set_diff(&conn(old), &conn(new));
    let (added_grants, removed_grants) = set_diff(&gr(old), &gr(new));
    // Dropping `@match` entirely turns a restricted script into match-everything.
    let mut d = UpdateDiff {
        added_matches,
        added_connect,
        added_grants,
        removed_matches,
        removed_connect,
        removed_grants,
    };
    let was_scoped = !(old.matches.is_empty() && old.includes.is_empty());
    if was_scoped && new.matches.is_empty() && new.includes.is_empty() {
        d.added_matches
            .push("(no @match/@include: runs everywhere)".into());
    }
    d
}

#[derive(Debug, Clone)]
pub struct UpdatePlan {
    pub plan: InstallPlan,
    pub diff: UpdateDiff,
    pub old_version: Option<String>,
    pub new_version: Option<String>,
    /// The new version is newer per [`is_newer`].
    pub is_newer: bool,
}

/// Plan an update of `installed` to `new_source`. The script identity (name+namespace) must match.
pub fn plan_update(
    installed: &Userscript,
    new_source: &str,
    origin_url: Option<&Url>,
) -> Result<UpdatePlan> {
    let plan = plan_install(new_source, origin_url)?;
    if plan.metadata.unique_id() != installed.metadata.unique_id() {
        return Err(Error::InvalidScript(
            "update has a different @name/@namespace".into(),
        ));
    }
    let diff = diff(&installed.metadata, &plan.metadata);
    let is_newer = match (&installed.metadata.version, &plan.metadata.version) {
        (Some(o), Some(n)) => self::is_newer(o, n),
        _ => false,
    };
    Ok(UpdatePlan {
        old_version: installed.metadata.version.clone(),
        new_version: plan.metadata.version.clone(),
        plan,
        diff,
        is_newer,
    })
}

/// Build the updated script. Refuses a widening update unless `approved`. Keeps identity,
/// enabled state and counters of `installed`; `@connect *` approval survives only if still
/// requested and previously approved (or newly approved).
pub fn finish_update(
    installed: &Userscript,
    up: UpdatePlan,
    fetched: Fetched,
    approved: bool,
    approve_connect_all: bool,
) -> Result<Userscript> {
    if up.diff.needs_reapproval() && !approved {
        return Err(Error::PermissionDenied(
            "update widens match/connect/grant; approval required".into(),
        ));
    }
    let now_connect_all = up.plan.grants_summary.connect_all;
    let keep = now_connect_all
        && (approve_connect_all
            || (installed.allow_connect_all && !up.diff.added_connect.iter().any(|c| c == "*")));
    let mut s = finish_install(
        up.plan,
        fetched,
        Approvals {
            allow_connect_all: keep,
        },
    )?;
    s.id = installed.id.clone();
    s.profile = installed.profile.clone();
    s.enabled = installed.enabled;
    s.installed_at = installed.installed_at;
    s.updated_at = Utc::now();
    s.last_executed = installed.last_executed;
    s.execution_count = installed.execution_count;
    Ok(s)
}

/// Where to check for a new version: the `@updateURL` (metadata-only `.meta.js` or full
/// script), else the `@downloadURL`. `None` when neither exists or a version is missing.
pub fn update_check_url(meta: &UserscriptMetadata) -> Option<Url> {
    meta.version.as_ref()?;
    let u = meta
        .update_url
        .as_deref()
        .or(meta.download_url.as_deref())?;
    Url::parse(u)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
}

/// Where to download the full script from.
pub fn update_download_url(meta: &UserscriptMetadata) -> Option<Url> {
    let u = meta
        .download_url
        .as_deref()
        .or(meta.update_url.as_deref())?;
    Url::parse(u)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
}

// ---- version comparison -------------------------------------------------------------------

/// One dot-separated part in Mozilla's toolkit version format:
/// `<num-a><str-b><num-c><str-d>`.
#[derive(Debug, Default)]
struct VPart {
    a: i64,
    b: String,
    c: i64,
    d: String,
}

fn parse_part(s: &str) -> VPart {
    let digits = |s: &str| -> (i64, usize) {
        let n = s.bytes().take_while(u8::is_ascii_digit).count();
        (s[..n].parse().unwrap_or(0), n)
    };
    let (a, n) = digits(s);
    let rest = &s[n..];
    let bn = rest.bytes().take_while(|c| !c.is_ascii_digit()).count();
    let b = rest[..bn].to_string();
    let rest = &rest[bn..];
    let (c, n) = digits(rest);
    VPart {
        a,
        b,
        c,
        d: rest[n..].to_string(),
    }
}

fn cmp_str(x: &str, y: &str) -> Ordering {
    // An empty string sorts after any non-empty one (1.0pre < 1.0), as in Mozilla's format.
    match (x.is_empty(), y.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        _ => x.cmp(y),
    }
}

/// Compare two `@version` strings. Missing trailing parts count as 0, so `1.0 == 1.0.0`;
/// `1.10 > 1.9`; `1.0pre1 < 1.0`. Tampermonkey documents this (Mozilla toolkit) comparison;
/// Violentmonkey ignores alphabetic characters, which agrees on purely numeric versions.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let (pa, pb): (Vec<VPart>, Vec<VPart>) = (
        a.trim().split('.').map(parse_part).collect(),
        b.trim().split('.').map(parse_part).collect(),
    );
    for i in 0..pa.len().max(pb.len()) {
        let zero = VPart::default();
        let (x, y) = (pa.get(i).unwrap_or(&zero), pb.get(i).unwrap_or(&zero));
        let o =
            x.a.cmp(&y.a)
                .then_with(|| cmp_str(&x.b, &y.b))
                .then_with(|| x.c.cmp(&y.c))
                .then_with(|| cmp_str(&x.d, &y.d));
        if o != Ordering::Equal {
            return o;
        }
    }
    Ordering::Equal
}

pub fn is_newer(installed: &str, candidate: &str) -> bool {
    compare_versions(candidate, installed) == Ordering::Greater
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(ver: &str, extra: &str) -> String {
        format!("// ==UserScript==\n// @name U\n// @namespace n\n// @version {ver}\n{extra}\n// ==/UserScript==\ncode();")
    }

    #[test]
    fn version_order() {
        use Ordering::*;
        for (a, b, o) in [
            ("1.0", "1.0.0", Equal),
            ("1.10", "1.9", Greater),
            ("1.0pre1", "1.0", Less),
            ("1.0a", "1.0b", Less),
            ("2", "10", Less),
            ("1.0.1", "1.0", Greater),
            ("0.9.9", "1.0", Less),
            ("1.0b1", "1.0b2", Less),
        ] {
            assert_eq!(compare_versions(a, b), o, "{a} vs {b}");
        }
        assert!(is_newer("1.0", "1.0.1"));
        assert!(!is_newer("1.0", "1.0.0"));
    }

    #[test]
    fn plan_resolves_and_reports() {
        let base = Url::parse("https://host.test/dir/s.user.js").unwrap();
        let hex = "00".repeat(32);
        let p = plan_install(&src("1", &format!("// @require lib.js#sha256={hex}\n// @require //cdn.test/x.js\n// @resource r ../r.css\n// @grant GM_xmlhttpRequest\n// @connect *\n// @run-at context-menu")), Some(&base)).unwrap();
        assert_eq!(p.requires[0].url.as_str(), "https://host.test/dir/lib.js");
        assert_eq!(p.requires[1].url.as_str(), "https://cdn.test/x.js");
        assert_eq!(p.resources[0].url.as_str(), "https://host.test/r.css");
        assert!(p.grants_summary.connect_all && p.grants_summary.network);
        assert_eq!(p.grants_summary.unsupported.len(), 1);
        assert!(plan_install(&src("1", "// @require javascript:alert(1)"), None).is_err());
        assert!(plan_install(&src("1", "// @resource ../x https://a/b"), None).is_err());
    }

    #[test]
    fn sri_verification() {
        let body = b"console.log(1)".to_vec();
        let good = hex(&Sha256::digest(&body));
        let bad = "11".repeat(32);
        let mk = |h: &str| {
            plan_install(
                &src("1", &format!("// @require https://a.test/l.js#sha256={h}")),
                None,
            )
            .unwrap()
        };
        let f = |b: &[u8]| Fetched {
            requires: [("https://a.test/l.js".to_string(), b.to_vec())].into(),
            ..Default::default()
        };
        let s = finish_install(mk(&good), f(&body), Approvals::default()).unwrap();
        assert_eq!(s.assets.requires[0].content, "console.log(1)");
        let e = finish_install(mk(&bad), f(&body), Approvals::default())
            .unwrap_err()
            .to_string();
        assert!(e.contains("mismatch"), "{e}");
        assert!(finish_install(mk(&good), Fetched::default(), Approvals::default()).is_err());
        // md5 and sha512 too
        assert!(verify_sri(
            &body,
            &[
                Sri {
                    algo: "md5".into(),
                    digest: Md5::digest(&body).to_vec()
                },
                Sri {
                    algo: "sha512".into(),
                    digest: Sha512::digest(&body).to_vec()
                }
            ]
        )
        .is_ok());
        assert!(verify_sri(
            &body,
            &[Sri {
                algo: "sha384".into(),
                digest: vec![0; 48]
            }]
        )
        .is_err());
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn connect_all_needs_request() {
        let p = plan_install(&src("1", "// @connect a.com"), None).unwrap();
        assert!(finish_install(
            p,
            Fetched::default(),
            Approvals {
                allow_connect_all: true
            }
        )
        .is_err());
    }

    #[test]
    fn update_diff_detection() {
        let old = finish_install(
            plan_install(
                &src(
                    "1",
                    "// @match https://a.com/*\n// @grant GM_getValue\n// @connect a.com",
                ),
                None,
            )
            .unwrap(),
            Fetched::default(),
            Approvals::default(),
        )
        .unwrap();
        let same = plan_update(
            &old,
            &src(
                "1.1",
                "// @match https://a.com/*\n// @grant GM.getValue\n// @connect a.com",
            ),
            None,
        )
        .unwrap();
        assert!(same.is_newer && !same.diff.needs_reapproval());
        let narrowed = plan_update(
            &old,
            &src("1.2", "// @match https://a.com/*\n// @grant none"),
            None,
        )
        .unwrap();
        assert!(
            !narrowed.diff.needs_reapproval() && narrowed.diff.removed_grants == ["gm_getvalue"]
        );
        for extra in ["// @match https://a.com/*\n// @match https://b.com/*\n// @grant GM_getValue\n// @connect a.com", "// @match https://a.com/*\n// @grant GM_getValue\n// @connect a.com\n// @connect evil.com", "// @match https://a.com/*\n// @grant GM_getValue\n// @grant GM_xmlhttpRequest\n// @connect a.com", "// @grant GM_getValue\n// @connect a.com"] {
            let up = plan_update(&old, &src("2", extra), None).unwrap();
            assert!(up.diff.needs_reapproval(), "{extra}");
            let e = finish_update(&old, up.clone(), Fetched::default(), false, false).unwrap_err();
            assert!(matches!(e, Error::PermissionDenied(_)));
            let s = finish_update(&old, up, Fetched::default(), true, false).unwrap();
            assert_eq!(s.id, old.id);
        }
        assert!(plan_update(
            &old,
            "// ==UserScript==\n// @name Other\n// ==/UserScript==",
            None
        )
        .is_err());
    }

    #[test]
    fn update_urls() {
        let m = UserscriptMetadata::parse(&src(
            "1",
            "// @updateURL https://a.test/m.meta.js\n// @downloadURL https://a.test/s.user.js",
        ))
        .unwrap();
        assert_eq!(update_check_url(&m).unwrap().path(), "/m.meta.js");
        assert_eq!(update_download_url(&m).unwrap().path(), "/s.user.js");
        let m = UserscriptMetadata::parse(
            "// ==UserScript==\n// @name x\n// @updateURL https://a.test/m\n// ==/UserScript==",
        )
        .unwrap();
        assert!(update_check_url(&m).is_none()); // no @version: never auto-updated
    }
}

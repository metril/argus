//! `// ==UserScript==` metadata block parser.
//!
//! Follows the public documentation of Tampermonkey, Violentmonkey and Greasemonkey 4.
//! Parsing never fails once a block is found; problems become [`MetaWarning`]s. Directives a
//! proxy cannot honour (`@run-at context-menu`, `@webRequest`, `@inject-into content`, ...) are
//! recorded *and* reported as [`WarnKind::Unsupported`].

use crate::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;

/// Execution timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RunAt {
    DocumentStart,
    /// `document-body`: as soon as `<body>` exists.
    DocumentBody,
    /// `DOMContentLoaded`. Default (Violentmonkey's documented default; Tampermonkey's is
    /// `document-idle`, which this runs slightly earlier than).
    #[default]
    DocumentEnd,
    /// After `load` (or shortly after DOMContentLoaded if `load` already fired).
    DocumentIdle,
    /// Menu-triggered: not achievable without a browser UI; reported as unsupported.
    ContextMenu,
}

impl RunAt {
    pub fn from_directive(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "document-start" => RunAt::DocumentStart,
            "document-body" => RunAt::DocumentBody,
            "document-end" => RunAt::DocumentEnd,
            "document-idle" => RunAt::DocumentIdle,
            "context-menu" => RunAt::ContextMenu,
            _ => return None,
        })
    }
}

/// `@inject-into`. Only `Page` is achievable for a proxy (no isolated world).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum InjectInto {
    #[default]
    Page,
    Content,
    Auto,
}

/// One `sha256=...` style integrity requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sri {
    /// `md5`, `sha256`, `sha384` or `sha512`.
    pub algo: String,
    /// Raw digest bytes.
    pub digest: Vec<u8>,
}

/// `@require url[#sha256=...]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Require {
    /// URL with the SRI fragment removed (may be relative / protocol-relative).
    pub url: String,
    pub sri: Vec<Sri>,
}

impl<'de> Deserialize<'de> for Require {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Plain(String),
            Full { url: String, sri: Vec<Sri> },
        }
        Ok(match Repr::deserialize(d)? {
            Repr::Plain(s) => split_sri(&s).0,
            Repr::Full { url, sri } => Require { url, sri },
        })
    }
}

/// `@resource name url[#sha256=...]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceDecl {
    pub name: String,
    pub url: String,
    pub sri: Vec<Sri>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WarnKind {
    /// A directive this proxy cannot honour; the script may misbehave.
    Unsupported,
    UnknownKey,
    UnknownGrant,
    Invalid,
    Duplicate,
    Structure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaWarning {
    /// 1-based line in the source (0 = n/a).
    pub line: usize,
    pub kind: WarnKind,
    pub message: String,
}

/// Parsed metadata. Field names that predate the rewrite are unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UserscriptMetadata {
    pub name: String,
    pub namespace: Option<String>,
    pub version: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
    /// `@homepage` / `@homepageURL` / `@website` / `@source`.
    pub homepage: Option<String>,
    pub icon: Option<String>,
    pub icon64: Option<String>,
    pub support_url: Option<String>,
    pub update_url: Option<String>,
    pub download_url: Option<String>,

    pub includes: Vec<String>,
    pub matches: Vec<String>,
    pub excludes: Vec<String>,
    pub exclude_matches: Vec<String>,

    pub run_at: RunAt,
    pub noframes: bool,
    pub inject_into: InjectInto,
    pub sandbox: Option<String>,
    pub unwrap: bool,
    pub top_level_await: bool,

    pub requires: Vec<Require>,
    pub resources: Vec<ResourceDecl>,
    /// As written (`GM_getValue`, `GM.getValue`, `none`, `unsafeWindow`, ...).
    pub grants: Vec<String>,
    pub connect: Vec<String>,

    pub antifeatures: Vec<String>,
    pub tags: Vec<String>,
    pub license: Option<String>,
    pub compatible: Vec<String>,
    pub run_in: Vec<String>,
    /// Raw `@webRequest` values (unsupported).
    pub web_request: Vec<String>,

    pub localized_names: BTreeMap<String, String>,
    pub localized_descriptions: BTreeMap<String, String>,
    /// Unrecognised keys, preserved in source order.
    pub unknown: Vec<(String, String)>,
    pub warnings: Vec<MetaWarning>,
    /// Raw lines of the block (without the `==UserScript==` fences).
    pub raw_metadata: Vec<String>,
}

/// Known API grant names, lowercase canonical form (`gm_*`; `GM.x` maps to `gm_x`).
pub const KNOWN_GRANTS: &[&str] = &[
    "none",
    "unsafewindow",
    "window.close",
    "window.focus",
    "window.onurlchange",
    "gm_info",
    "gm_getvalue",
    "gm_setvalue",
    "gm_deletevalue",
    "gm_listvalues",
    "gm_getvalues",
    "gm_setvalues",
    "gm_deletevalues",
    "gm_addvaluechangelistener",
    "gm_removevaluechangelistener",
    "gm_addstyle",
    "gm_addelement",
    "gm_getresourcetext",
    "gm_getresourceurl",
    "gm_xmlhttprequest",
    "gm_download",
    "gm_openintab",
    "gm_setclipboard",
    "gm_notification",
    "gm_registermenucommand",
    "gm_unregistermenucommand",
    "gm_log",
    "gm_gettab",
    "gm_savetab",
    "gm_gettabs",
    "gm_cookie",
    "gm_webrequest",
];

/// Canonical (comparison) form of a grant: `GM.getValue` and `GM_getValue` both become
/// `gm_getvalue`; case-insensitive (`GM_xmlhttpRequest` == `GM.xmlHttpRequest`).
pub fn canonical_grant(g: &str) -> String {
    let g = g.trim();
    let lower = g.to_ascii_lowercase();
    match lower.strip_prefix("gm.") {
        Some(rest) => format!("gm_{rest}"),
        None => lower,
    }
}

impl UserscriptMetadata {
    pub fn new(name: String) -> Self {
        Self {
            name,
            ..Default::default()
        }
    }

    /// Parse the first metadata block in `source`. Errors only when there is no block at all.
    pub fn parse(source: &str) -> Result<Self> {
        let source = source.strip_prefix('\u{feff}').unwrap_or(source);
        let mut m = Self::default();
        let mut in_block = false;
        let mut ended = false;
        let mut seen: Vec<String> = Vec::new();

        for (i, raw) in source.split('\n').enumerate() {
            let lineno = i + 1;
            let line = raw.trim();
            if !in_block {
                if is_fence(line, false) {
                    in_block = true;
                }
                continue;
            }
            if is_fence(line, true) {
                ended = true;
                break;
            }
            if !line.starts_with("//") {
                if line.is_empty() {
                    continue;
                }
                // Block ended implicitly by code.
                break;
            }
            m.raw_metadata.push(line.to_string());
            let body = line[2..].trim_start();
            let Some(body) = body.strip_prefix('@') else {
                continue;
            };
            let (key, value) = match body.find(char::is_whitespace) {
                Some(p) => (&body[..p], body[p..].trim()),
                None => (body, ""),
            };
            m.apply(key, value, lineno, &mut seen);
        }
        if !in_block {
            return Err(Error::MetadataParsing("No metadata block found".into()));
        }
        if !ended {
            m.warn(0, WarnKind::Structure, "metadata block is not terminated by ==/UserScript==");
        }
        if m.name.is_empty() {
            m.name = "Unnamed Script".into();
            m.warn(0, WarnKind::Structure, "missing @name; using a placeholder");
        }
        m.finish_checks();
        Ok(m)
    }

    fn warn(&mut self, line: usize, kind: WarnKind, msg: impl Into<String>) {
        self.warnings.push(MetaWarning {
            line,
            kind,
            message: msg.into(),
        });
    }

    fn single(&mut self, slot: fn(&mut Self) -> &mut Option<String>, key: &str, v: &str, line: usize, seen: &mut Vec<String>) {
        if v.is_empty() {
            self.warn(line, WarnKind::Invalid, format!("@{key} has no value"));
            return;
        }
        if slot(self).is_some() {
            self.warn(line, WarnKind::Duplicate, format!("duplicate @{key}; first one wins"));
            return;
        }
        seen.push(key.to_string());
        *slot(self) = Some(v.to_string());
    }

    fn apply(&mut self, key_raw: &str, v: &str, line: usize, seen: &mut Vec<String>) {
        let key_lc = key_raw.to_ascii_lowercase();
        // Locale suffix: @name:fr, @description:zh-CN
        if let Some((base, _)) = key_lc.split_once(':') {
            let loc = &key_raw[base.len() + 1..];
            match base {
                "name" if !loc.is_empty() => {
                    self.localized_names.insert(loc.to_string(), v.to_string());
                }
                "description" if !loc.is_empty() => {
                    self.localized_descriptions.insert(loc.to_string(), v.to_string());
                }
                _ => {
                    self.warn(line, WarnKind::UnknownKey, format!("unknown key @{key_raw}"));
                    self.unknown.push((key_raw.to_string(), v.to_string()));
                }
            }
            return;
        }
        match key_lc.as_str() {
            "name" => {
                if v.is_empty() {
                    self.warn(line, WarnKind::Invalid, "@name has no value");
                } else if self.name.is_empty() {
                    self.name = v.to_string();
                } else {
                    self.warn(line, WarnKind::Duplicate, "duplicate @name; first one wins");
                }
            }
            "namespace" => self.single(|s| &mut s.namespace, "namespace", v, line, seen),
            "version" => self.single(|s| &mut s.version, "version", v, line, seen),
            "author" => self.single(|s| &mut s.author, "author", v, line, seen),
            "description" => self.single(|s| &mut s.description, "description", v, line, seen),
            "homepage" | "homepageurl" | "website" | "source" => {
                self.single(|s| &mut s.homepage, "homepage", v, line, seen)
            }
            "icon" | "iconurl" | "defaulticon" => self.single(|s| &mut s.icon, "icon", v, line, seen),
            "icon64" | "icon64url" => self.single(|s| &mut s.icon64, "icon64", v, line, seen),
            "updateurl" => self.single(|s| &mut s.update_url, "updateURL", v, line, seen),
            "downloadurl" | "installurl" => {
                self.single(|s| &mut s.download_url, "downloadURL", v, line, seen)
            }
            "supporturl" => self.single(|s| &mut s.support_url, "supportURL", v, line, seen),
            "license" => self.single(|s| &mut s.license, "license", v, line, seen),
            "match" => self.push_nonempty(|s| &mut s.matches, "match", v, line),
            "include" => self.push_nonempty(|s| &mut s.includes, "include", v, line),
            "exclude" => self.push_nonempty(|s| &mut s.excludes, "exclude", v, line),
            "exclude-match" => self.push_nonempty(|s| &mut s.exclude_matches, "exclude-match", v, line),
            "require" => {
                if v.is_empty() {
                    self.warn(line, WarnKind::Invalid, "@require has no URL");
                } else {
                    let (r, bad) = split_sri(v);
                    for b in bad {
                        self.warn(line, WarnKind::Invalid, format!("@require: bad integrity '{b}'"));
                    }
                    self.requires.push(r);
                }
            }
            "resource" => {
                let mut it = v.splitn(2, char::is_whitespace);
                match (it.next().filter(|s| !s.is_empty()), it.next().map(str::trim)) {
                    (Some(name), Some(url)) if !url.is_empty() => {
                        let (r, bad) = split_sri(url);
                        for b in bad {
                            self.warn(line, WarnKind::Invalid, format!("@resource {name}: bad integrity '{b}'"));
                        }
                        if self.resources.iter().any(|x| x.name == name) {
                            self.warn(line, WarnKind::Duplicate, format!("duplicate @resource {name}; first wins"));
                        } else {
                            self.resources.push(ResourceDecl {
                                name: name.to_string(),
                                url: r.url,
                                sri: r.sri,
                            });
                        }
                    }
                    _ => self.warn(line, WarnKind::Invalid, "@resource needs a name and a URL"),
                }
            }
            "grant" => {
                for g in v.split_whitespace() {
                    if !self.grants.iter().any(|x| x == g) {
                        self.grants.push(g.to_string());
                    }
                }
                if v.is_empty() {
                    self.warn(line, WarnKind::Invalid, "@grant has no value");
                }
            }
            "connect" => {
                for c in v.split_whitespace() {
                    self.connect.push(c.to_ascii_lowercase());
                }
            }
            "run-at" => match RunAt::from_directive(v) {
                Some(RunAt::ContextMenu) => {
                    self.run_at = RunAt::ContextMenu;
                    self.warn(line, WarnKind::Unsupported, "@run-at context-menu needs a browser menu; the script will never run");
                }
                Some(r) => self.run_at = r,
                None => self.warn(line, WarnKind::Invalid, format!("unknown @run-at '{v}'; using document-end")),
            },
            "noframes" => self.noframes = true,
            "unwrap" => self.unwrap = true,
            "top-level-await" => self.top_level_await = true,
            "inject-into" => match v.to_ascii_lowercase().as_str() {
                "page" => self.inject_into = InjectInto::Page,
                "content" => {
                    self.inject_into = InjectInto::Content;
                    self.warn(line, WarnKind::Unsupported, "@inject-into content: no isolated world through a proxy; runs in the page world");
                }
                "auto" => {
                    self.inject_into = InjectInto::Auto;
                    self.warn(line, WarnKind::Unsupported, "@inject-into auto: always resolves to the page world here");
                }
                _ => self.warn(line, WarnKind::Invalid, format!("unknown @inject-into '{v}'")),
            },
            "sandbox" => {
                self.sandbox = Some(v.to_string());
                if !v.eq_ignore_ascii_case("raw") {
                    self.warn(line, WarnKind::Unsupported, format!("@sandbox {v}: scripts always run in the page world"));
                }
            }
            "antifeature" => self.push_nonempty(|s| &mut s.antifeatures, "antifeature", v, line),
            "tag" => {
                for t in v.split_whitespace() {
                    self.tags.push(t.to_string());
                }
            }
            "compatible" => self.push_nonempty(|s| &mut s.compatible, "compatible", v, line),
            "run-in" => {
                self.run_in.push(v.to_string());
                self.warn(line, WarnKind::Unsupported, "@run-in is browser-tab specific; ignored");
            }
            "webrequest" => {
                self.web_request.push(v.to_string());
                self.warn(line, WarnKind::Unsupported, "@webRequest rules cannot be applied; ignored");
            }
            "priority" | "require-ts" | "nocompat" | "contributionurl" | "contributionamount" | "copyright" | "contributors" | "contributor" | "updatedelay" | "downloadurl2" => {
                self.unknown.push((key_raw.to_string(), v.to_string()));
            }
            _ => {
                self.warn(line, WarnKind::UnknownKey, format!("unknown key @{key_raw}"));
                self.unknown.push((key_raw.to_string(), v.to_string()));
            }
        }
    }

    fn push_nonempty(&mut self, slot: fn(&mut Self) -> &mut Vec<String>, key: &str, v: &str, line: usize) {
        if v.is_empty() {
            self.warn(line, WarnKind::Invalid, format!("@{key} has no value"));
        } else {
            slot(self).push(v.to_string());
        }
    }

    fn finish_checks(&mut self) {
        let mut ws = Vec::new();
        let none = self.grants.iter().any(|g| canonical_grant(g) == "none");
        if none && self.grants.len() > 1 {
            ws.push("@grant none is combined with other grants; none wins".to_string());
        }
        for g in &self.grants {
            let c = canonical_grant(g);
            if !KNOWN_GRANTS.contains(&c.as_str()) {
                ws.push(format!("unknown @grant '{g}'"));
            }
            if c == "gm_webrequest" {
                ws.push("GM_webRequest is unsupported; calls will reject".to_string());
            }
        }
        for w in ws {
            let kind = if w.starts_with("unknown") { WarnKind::UnknownGrant } else { WarnKind::Unsupported };
            self.warn(0, kind, w);
        }
    }

    /// Canonical grants, sorted and de-duplicated; empty when `@grant none` (or nothing) is set.
    pub fn effective_grants(&self) -> Vec<String> {
        let mut v: Vec<String> = self.grants.iter().map(|g| canonical_grant(g)).collect();
        if v.iter().any(|g| g == "none") {
            return Vec::new();
        }
        v.sort();
        v.dedup();
        v
    }

    pub fn has_grant(&self, capability: &str) -> bool {
        let want = canonical_grant(capability);
        !self.grants.iter().any(|g| canonical_grant(g) == "none")
            && self.grants.iter().any(|g| canonical_grant(g) == want)
    }

    /// Name for a locale (`fr-CA` falls back to `fr`, then the default name).
    pub fn localized_name(&self, locale: &str) -> &str {
        lookup_locale(&self.localized_names, locale).unwrap_or(&self.name)
    }

    pub fn localized_description(&self, locale: &str) -> Option<&str> {
        lookup_locale(&self.localized_descriptions, locale).map(String::as_str).or(self.description.as_deref())
    }

    /// Unique id (namespace + name), as managers identify scripts.
    pub fn unique_id(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}:{}", ns, self.name),
            None => self.name.clone(),
        }
    }

    /// Features requested that this proxy cannot provide.
    pub fn unsupported(&self) -> Vec<&MetaWarning> {
        self.warnings.iter().filter(|w| w.kind == WarnKind::Unsupported).collect()
    }
}

fn lookup_locale<'a>(map: &'a BTreeMap<String, String>, locale: &str) -> Option<&'a String> {
    let l = locale.to_ascii_lowercase();
    let find = |want: &str| map.iter().find(|(k, _)| k.to_ascii_lowercase() == want).map(|(_, v)| v);
    find(&l).or_else(|| l.split(['-', '_']).next().and_then(find))
}

fn is_fence(line: &str, end: bool) -> bool {
    let Some(rest) = line.strip_prefix("//") else { return false };
    let rest = rest.trim().to_ascii_lowercase();
    if end {
        rest == "==/userscript=="
    } else {
        rest == "==userscript=="
    }
}

/// Split `url#sha256=...` into the URL and parsed digests. The second tuple lists bad specs.
pub fn split_sri(s: &str) -> (Require, Vec<String>) {
    let s = s.trim();
    let Some((url, frag)) = s.split_once('#') else {
        return (Require { url: s.to_string(), sri: vec![] }, vec![]);
    };
    let mut sri = Vec::new();
    let mut bad = Vec::new();
    let mut keep_frag = false;
    for part in frag.split([',', ';']).map(str::trim).filter(|p| !p.is_empty()) {
        let (algo, val) = match part.split_once(['=', '-']) {
            Some((a, v)) => (a.to_ascii_lowercase(), v),
            None => {
                keep_frag = true;
                continue;
            }
        };
        let want = match algo.as_str() {
            "md5" => 16,
            "sha256" => 32,
            "sha384" => 48,
            "sha512" => 64,
            _ => {
                keep_frag = true;
                continue;
            }
        };
        match decode_digest(val, want) {
            Some(digest) => sri.push(Sri { algo, digest }),
            None => bad.push(part.to_string()),
        }
    }
    // A fragment that is not integrity data belongs to the URL.
    let url = if keep_frag && sri.is_empty() && bad.is_empty() { s.to_string() } else { url.to_string() };
    (Require { url, sri }, bad)
}

fn decode_digest(v: &str, len: usize) -> Option<Vec<u8>> {
    use base64::Engine;
    let v = v.trim();
    if v.len() == len * 2 && v.bytes().all(|b| b.is_ascii_hexdigit()) {
        return (0..len).map(|i| u8::from_str_radix(&v[i * 2..i * 2 + 2], 16).ok()).collect();
    }
    let t = v.trim_end_matches('=');
    for e in [&base64::engine::general_purpose::STANDARD_NO_PAD, &base64::engine::general_purpose::URL_SAFE_NO_PAD] {
        if let Ok(b) = e.decode(t) {
            if b.len() == len {
                return Some(b);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> UserscriptMetadata {
        UserscriptMetadata::parse(s).unwrap()
    }

    #[test]
    fn full_block() {
        let m = p(r#"// ==UserScript==
// @name         Fancy
// @name:fr      Chic
// @name:zh-CN   花哨
// @namespace    https://example.org/
// @version      1.2.3
// @description  Does things
// @description:de Macht Dinge
// @author       Me
// @homepageURL  https://example.org/h
// @icon         https://example.org/i.png
// @icon64       https://example.org/i64.png
// @updateURL    https://example.org/u.meta.js
// @downloadURL  https://example.org/d.user.js
// @supportURL   https://example.org/s
// @match        https://*.example.org/*
// @include      /^https?:\/\/foo\.com\/.*$/
// @exclude      https://example.org/private*
// @exclude-match https://example.org/x/*
// @require      https://cdn.example/lib.js#sha256=0000000000000000000000000000000000000000000000000000000000000000
// @resource     css https://cdn.example/a.css
// @grant        GM_getValue
// @grant        GM.setValue
// @grant        unsafeWindow
// @connect      api.example.org
// @connect      self
// @run-at       document-start
// @noframes
// @inject-into  page
// @unwrap
// @top-level-await
// @antifeature  ads  we show ads
// @tag          a b
// @license      MIT
// @compatible   firefox
// @frobnicate   yes
// ==/UserScript==
code();"#);
        assert_eq!(m.name, "Fancy");
        assert_eq!(m.localized_names["fr"], "Chic");
        assert_eq!(m.localized_name("zh-cn"), "花哨");
        assert_eq!(m.localized_name("fr-CA"), "Chic");
        assert_eq!(m.localized_name("es"), "Fancy");
        assert_eq!(m.localized_description("de"), Some("Macht Dinge"));
        assert_eq!(m.homepage.as_deref(), Some("https://example.org/h"));
        assert_eq!(m.matches.len(), 1);
        assert_eq!(m.exclude_matches.len(), 1);
        assert_eq!(m.requires[0].url, "https://cdn.example/lib.js");
        assert_eq!(m.requires[0].sri[0].algo, "sha256");
        assert_eq!(m.resources[0].name, "css");
        assert_eq!(m.run_at, RunAt::DocumentStart);
        assert!(m.noframes && m.unwrap && m.top_level_await);
        assert_eq!(m.connect, ["api.example.org", "self"]);
        assert_eq!(m.tags, ["a", "b"]);
        assert_eq!(m.unknown, [("frobnicate".to_string(), "yes".to_string())]);
        assert!(m.has_grant("GM.getValue") && m.has_grant("GM_setValue") && !m.has_grant("GM_log"));
        assert!(m.unsupported().is_empty());
    }

    #[test]
    fn tolerant_input() {
        let m = p("\u{feff}\r\n  //   ==UserScript==  \r\n//@name\tTabbed\r\n//    @match   *://a/*\r\n// ==/UserScript==\r\n");
        assert_eq!(m.name, "Tabbed");
        assert_eq!(m.matches, ["*://a/*"]);
    }

    #[test]
    fn unsupported_reported() {
        let m = p("// ==UserScript==\n// @name x\n// @run-at context-menu\n// @webRequest {\"selector\":\"*\"}\n// @inject-into content\n// @sandbox DOM\n// @run-in incognito-tabs\n// @grant GM_webRequest\n// ==/UserScript==");
        let kinds: Vec<_> = m.unsupported().iter().map(|w| w.message.clone()).collect();
        assert!(kinds.len() >= 6, "{kinds:?}");
        assert_eq!(m.run_at, RunAt::ContextMenu);
        assert_eq!(m.inject_into, InjectInto::Content);
    }

    #[test]
    fn malformed_never_panics() {
        let m = p("// ==UserScript==\n// @name\n// @match\n// @resource lonely\n// @require\n// @run-at sometime\n// @require https://x/y.js#sha256=zz\n// @version 1\n// @version 2\n// @grant none GM_log\n// @inject-into elsewhere\n//\n// not a key\ncode");
        assert_eq!(m.name, "Unnamed Script");
        assert_eq!(m.version.as_deref(), Some("1"));
        assert!(m.warnings.len() >= 7);
        assert!(m.effective_grants().is_empty());
        assert!(!m.has_grant("GM_log"));
    }

    #[test]
    fn no_block_is_error_unterminated_is_warning() {
        assert!(UserscriptMetadata::parse("console.log(1)").is_err());
        let m = p("// ==UserScript==\n// @name A\nconsole.log(1)");
        assert_eq!(m.name, "A");
        assert!(m.warnings.iter().any(|w| w.kind == WarnKind::Structure));
    }

    #[test]
    fn sri_forms() {
        let hex = "ab".repeat(32);
        let (r, bad) = split_sri(&format!("https://x/a.js#sha256={hex},md5={}", "cd".repeat(16)));
        assert!(bad.is_empty());
        assert_eq!(r.sri.len(), 2);
        use base64::Engine;
        let b = base64::engine::general_purpose::STANDARD.encode([7u8; 48]);
        let (r, _) = split_sri(&format!("https://x/a.js#sha384-{b}"));
        assert_eq!(r.sri[0].digest, vec![7u8; 48]);
        // Non-integrity fragments stay in the URL.
        assert_eq!(split_sri("https://x/a.js#frag").0.url, "https://x/a.js#frag");
    }

    #[test]
    fn legacy_string_require_deserializes() {
        let r: Require = serde_json::from_str("\"https://x/a.js#md5=00000000000000000000000000000000\"").unwrap();
        assert_eq!(r.url, "https://x/a.js");
        assert_eq!(r.sri.len(), 1);
    }

    #[test]
    fn canonical_grants() {
        assert_eq!(canonical_grant("GM.xmlHttpRequest"), canonical_grant("GM_xmlhttpRequest"));
        assert_eq!(canonical_grant("GM.getResourceUrl"), "gm_getresourceurl");
    }
}

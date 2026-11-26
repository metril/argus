//! uBlock Origin `$redirect` resource library -> adblock-rust [`Resource`]s.
//!
//! uBO ships neutered replacement resources as files under `src/web_accessible_resources/` and a
//! name map (`src/js/redirect-resources.js`: file name, aliases, `requiresTrust`). The map is
//! parsed with a real JavaScript parser (`oxc_parser`), never scanned as text. Every file named
//! by the map becomes a MIME resource (binary ones carry their raw bytes, base64 encoded) under
//! its name and aliases, plus the AdGuard redirect names uBO does not alias itself
//! ([`ADGUARD_REDIRECT_ALIASES`]).
//!
//! GPLv3 content (uBlock Origin): fetched at runtime, with a pinned bundled snapshot (see
//! `docs/LICENSING.md`).

use std::collections::{HashMap, HashSet};

use adblock::resources::{MimeType, PermissionMask, Resource, ResourceType};
use base64::Engine as _;
use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, Expression, ObjectPropertyKind, Statement};
use oxc_parser::Parser;
use oxc_span::SourceType;

use crate::scriptlet_resources::{validate_resources, DroppedResource, ScriptletConversion};

/// AdGuard redirect names that uBO does not alias itself: `(adguard name, uBO resource name)`.
/// Applied only when the target exists and the name is free.
pub const ADGUARD_REDIRECT_ALIASES: &[(&str, &str)] = &[
    ("1x1-transparent.gif", "1x1.gif"),
    ("2x2-transparent.png", "2x2.png"),
    ("3x2-transparent.png", "3x2.png"),
    ("32x32-transparent.png", "32x32.png"),
    ("amazon-apstag", "amazon_apstag.js"),
    ("chartbeat", "chartbeat.js"),
    ("fingerprintjs2", "fingerprint2.js"),
    ("fingerprintjs3", "fingerprint3.js"),
    ("google-analytics", "google-analytics_analytics.js"),
    ("google-analytics-ga", "google-analytics_ga.js"),
    ("google-ima3", "google-ima.js"),
    (
        "googlesyndication-adsbygoogle",
        "googlesyndication_adsbygoogle.js",
    ),
    ("googletagmanager-gtm", "google-analytics_analytics.js"),
    ("googletagservices-gpt", "googletagservices_gpt.js"),
    ("noeval", "noeval.js"),
    ("noopcss", "noop.css"),
    ("noopframe", "noop.html"),
    ("noopjs", "noop.js"),
    ("noopjson", "noop.json"),
    ("noopmp3-0.1s", "noop-0.1s.mp3"),
    ("noopmp4-1s", "noop-1s.mp4"),
    ("nooptext", "noop.txt"),
    ("noopvast-2.0", "noop-vast2.xml"),
    ("noopvast-3.0", "noop-vast3.xml"),
    ("noopvast-4.0", "noop-vast4.xml"),
    ("noopvmap-1.0", "noop-vmap1.xml"),
    ("prebid-ads", "prebid-ads.js"),
    ("prevent-bab", "nobab2.js"),
    ("prevent-bab2", "nobab2.js"),
    ("prevent-fab-3.2.0", "nofab.js"),
    ("prevent-popads-net", "popads.js"),
    ("scorecardresearch-beacon", "scorecardresearch_beacon.js"),
    ("set-popads-dummy", "popads-dummy.js"),
    ("silent-noeval", "noeval-silent.js"),
];

/// One entry of uBO's redirect map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectEntry {
    /// Resource name, also the file name under `web_accessible_resources/`.
    pub name: String,
    pub aliases: Vec<String>,
    /// uBO marks a few resources as usable by trusted lists only. adblock-rust never serves a
    /// non-default-permission resource as a `$redirect`, so the redirect body is registered with
    /// the default permission (a `$redirect` is not code injection into the page by a list).
    pub requires_trust: bool,
}

fn str_of(e: &Expression) -> Option<String> {
    match e {
        Expression::StringLiteral(s) => Some(s.value.to_string()),
        _ => None,
    }
}

fn read_entry(e: &Expression) -> Option<RedirectEntry> {
    let Expression::ArrayExpression(pair) = e else {
        return None;
    };
    let name = pair.elements.first()?.as_expression().and_then(str_of)?;
    let Some(Expression::ObjectExpression(o)) = pair.elements.get(1)?.as_expression() else {
        return None;
    };
    let mut entry = RedirectEntry {
        name,
        aliases: vec![],
        requires_trust: false,
    };
    for p in &o.properties {
        let ObjectPropertyKind::ObjectProperty(p) = p else {
            continue;
        };
        match p.key.static_name().as_deref() {
            Some("alias") => match &p.value {
                Expression::ArrayExpression(a) => entry.aliases.extend(
                    a.elements
                        .iter()
                        .filter_map(|e| e.as_expression().and_then(str_of)),
                ),
                v => entry.aliases.extend(str_of(v)),
            },
            Some("requiresTrust") => {
                if let Expression::BooleanLiteral(b) = &p.value {
                    entry.requires_trust = b.value;
                }
            }
            _ => {}
        }
    }
    Some(entry)
}

/// Parse uBO's `redirect-resources.js` (`export default new Map([...])`).
pub fn parse_redirect_map(src: &str) -> Result<Vec<RedirectEntry>, String> {
    let alloc = Allocator::default();
    let ret = Parser::new(&alloc, src, SourceType::mjs()).parse();
    if ret.panicked || !ret.errors.is_empty() {
        let msg = ret.errors.first().map(|e| e.to_string());
        return Err(format!(
            "redirect map has a syntax error: {}",
            msg.unwrap_or_else(|| "parser gave up".into())
        ));
    }
    for st in &ret.program.body {
        let Statement::ExportDefaultDeclaration(d) = st else {
            continue;
        };
        let Some(Expression::NewExpression(n)) = d.declaration.as_expression() else {
            continue;
        };
        let Some(Argument::ArrayExpression(items)) = n.arguments.first() else {
            continue;
        };
        return Ok(items
            .elements
            .iter()
            .filter_map(|e| e.as_expression().and_then(read_entry))
            .collect());
    }
    Err("redirect map: no `export default new Map([...])` found".into())
}

/// MIME type of a resource file, from its extension (`empty` is plain text).
fn mime_of(name: &str) -> MimeType {
    match name.rsplit_once('.').map(|(_, e)| e) {
        Some("js") => MimeType::ApplicationJavascript,
        Some("html") => MimeType::TextHtml,
        Some("css") => MimeType::TextCss,
        Some("json") => MimeType::ApplicationJson,
        Some("xml") => MimeType::TextXml,
        Some("gif") => MimeType::ImageGif,
        Some("png") => MimeType::ImagePng,
        Some("mp3") => MimeType::AudioMp3,
        Some("mp4") => MimeType::VideoMp4,
        _ => MimeType::TextPlain,
    }
}

/// Check a resource file's content against its type: magic bytes for gif / png / mp3 / mp4,
/// well-formed XML for `.xml`, valid UTF-8 for text. (Scripts are parsed by
/// [`validate_resources`] afterwards.)
fn validate_file(name: &str, b: &[u8]) -> Result<(), String> {
    let ext = name.rsplit_once('.').map(|(_, e)| e);
    let ok = match ext {
        Some("gif") => b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a"),
        Some("png") => b.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]),
        Some("mp3") => {
            b.starts_with(b"ID3") || (b.len() > 2 && b[0] == 0xff && b[1] & 0xe0 == 0xe0)
        }
        Some("mp4") => b.len() > 8 && &b[4..8] == b"ftyp",
        Some("xml") => return xml_well_formed(b),
        _ => std::str::from_utf8(b).is_ok(),
    };
    if ok {
        Ok(())
    } else {
        Err("content does not match its file type".into())
    }
}

/// Minimal well-formedness check: tags nest and close, one root element, quoted attributes.
fn xml_well_formed(b: &[u8]) -> Result<(), String> {
    let s = std::str::from_utf8(b).map_err(|_| "XML is not UTF-8".to_string())?;
    let bad = |m: &str| Err(format!("XML not well-formed: {m}"));
    let (mut stack, mut roots, mut rest) = (Vec::<&str>::new(), 0, s);
    while let Some(i) = rest.find('<') {
        if !stack.is_empty() || roots == 0 {
            // text outside the root must be whitespace
            if stack.is_empty() && !rest[..i].trim().is_empty() {
                return bad("text outside the root element");
            }
        }
        rest = &rest[i..];
        if let Some(t) = rest.strip_prefix("<!--") {
            let Some(e) = t.find("-->") else {
                return bad("unterminated comment");
            };
            rest = &t[e + 3..];
            continue;
        }
        let end = if rest.starts_with("<?") {
            rest.find("?>").map(|e| e + 2)
        } else {
            // the first `>` outside quotes
            let mut q = None;
            rest.char_indices().find_map(|(i, c)| match (q, c) {
                (None, '"' | '\'') => {
                    q = Some(c);
                    None
                }
                (Some(x), c) if c == x => {
                    q = None;
                    None
                }
                (None, '>') => Some(i + 1),
                _ => None,
            })
        };
        let Some(end) = end else {
            return bad("unterminated tag");
        };
        let tag = &rest[..end];
        rest = &rest[end..];
        if tag.starts_with("<?") || tag.starts_with("<!") {
            continue;
        }
        let inner = tag[1..tag.len() - 1].trim_end_matches('/');
        let name = |t: &'_ str| t.split_whitespace().next().unwrap_or("").to_string();
        if let Some(close) = inner.strip_prefix('/') {
            match stack.pop() {
                Some(open) if open == name(close) => {}
                _ => return bad("mismatched closing tag"),
            }
        } else {
            let n = name(inner);
            if n.is_empty() {
                return bad("empty tag name");
            }
            if stack.is_empty() {
                roots += 1;
                if roots > 1 {
                    return bad("more than one root element");
                }
            }
            if !tag.ends_with("/>") {
                // leak-free: names live as long as `s`
                let start = s.len() - rest.len() - tag.len() + 1;
                let st = &s[start..start + n.len()];
                stack.push(st);
            }
        }
    }
    if !stack.is_empty() || roots != 1 || !rest.trim().is_empty() {
        return bad("unclosed or missing root element");
    }
    Ok(())
}

/// Convert uBO's redirect map plus the files (`name -> bytes`) it names into validated
/// resources. A listed file that is missing, or a script that does not parse, is dropped with a
/// reason; nothing aborts the conversion.
pub fn convert_ubo_redirects(
    map_js: &str,
    files: &HashMap<String, Vec<u8>>,
) -> Result<ScriptletConversion, String> {
    let entries = parse_redirect_map(map_js)?;
    let mut dropped: Vec<DroppedResource> = Vec::new();
    let mut resources: Vec<Resource> = Vec::new();
    let mut taken: HashSet<String> = HashSet::new();
    let mut by_name: HashMap<&str, usize> = HashMap::new();
    for e in &entries {
        let Some(bytes) = files.get(&e.name) else {
            dropped.push(DroppedResource {
                name: e.name.clone(),
                reason: "resource file not found".into(),
            });
            continue;
        };
        if let Err(reason) = validate_file(&e.name, bytes) {
            dropped.push(DroppedResource {
                name: e.name.clone(),
                reason,
            });
            continue;
        }
        let ids: Vec<&String> = std::iter::once(&e.name).chain(&e.aliases).collect();
        if let Some(dup) = ids.iter().find(|i| taken.contains(i.as_str())) {
            dropped.push(DroppedResource {
                name: e.name.clone(),
                reason: format!("name `{dup}` already registered"),
            });
            continue;
        }
        taken.extend(ids.into_iter().cloned());
        by_name.insert(&e.name, resources.len());
        resources.push(Resource {
            name: e.name.clone(),
            aliases: e.aliases.clone(),
            kind: ResourceType::Mime(mime_of(&e.name)),
            content: base64::engine::general_purpose::STANDARD.encode(bytes),
            dependencies: vec![],
            permission: PermissionMask::default(),
        });
    }
    for (ag, target) in ADGUARD_REDIRECT_ALIASES {
        if let Some(&i) = by_name.get(target) {
            if taken.insert((*ag).to_string()) {
                resources[i].aliases.push((*ag).to_string());
            }
        }
    }
    let v = validate_resources(resources);
    dropped.extend(v.dropped);
    Ok(ScriptletConversion {
        resources: v.resources,
        dropped,
    })
}

/// Names of the files a redirect map needs fetched.
pub fn redirect_file_names(map_js: &str) -> Result<Vec<String>, String> {
    Ok(parse_redirect_map(map_js)?
        .into_iter()
        .map(|e| e.name)
        .collect())
}

/// Convert to the JSON array [`crate::SharedEngine::set_resources_from_json`] expects.
pub fn ubo_redirects_to_json(
    map_js: &str,
    files: &HashMap<String, Vec<u8>>,
) -> Result<(String, Vec<DroppedResource>), String> {
    let c = convert_ubo_redirects(map_js, files)?;
    let json = serde_json::to_string(&c.resources).map_err(|e| e.to_string())?;
    Ok((json, c.dropped))
}

/// Append the resources of `extra` (a JSON array) that do not collide, by name or alias, with
/// one in `base`. The base wins; used to fill gaps with the bundled snapshot.
pub fn merge_resources_json(base: &str, extra: &str) -> Result<String, serde_json::Error> {
    let mut all: Vec<Resource> = serde_json::from_str(base)?;
    if extra.trim().is_empty() {
        return serde_json::to_string(&all);
    }
    let more: Vec<Resource> = serde_json::from_str(extra)?;
    let mut taken: HashSet<String> = all
        .iter()
        .flat_map(|r| std::iter::once(&r.name).chain(&r.aliases).cloned())
        .collect();
    for r in more {
        let ids: Vec<&String> = std::iter::once(&r.name).chain(&r.aliases).collect();
        if ids.iter().any(|i| taken.contains(i.as_str())) {
            continue;
        }
        taken.extend(ids.into_iter().cloned());
        all.push(r);
    }
    serde_json::to_string(&all)
}

/// Does this body look like a scriptlet (`function name(...) {...}`, the form adblock-rust
/// invokes with `+js(...)` arguments) rather than a redirect resource?
pub fn looks_like_scriptlet(body: &[u8]) -> bool {
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^function\s+[^\(\)\{\}\s]+\s*\(").expect("static regex")
    });
    RE.is_match(&String::from_utf8_lossy(&body[..body.len().min(256)]))
}

/// Scriptlets (and their helpers) share the resource store with redirect resources, and a
/// `$redirect=` would resolve a scriptlet alias (e.g. `nobab.js`) to the scriptlet's source.
fn is_scriptlet(r: &Resource) -> bool {
    match &r.kind {
        ResourceType::Template | ResourceType::Mime(MimeType::FnJavascript) => true,
        ResourceType::Mime(MimeType::ApplicationJavascript) => {
            !r.dependencies.is_empty()
                || base64::engine::general_purpose::STANDARD
                    .decode(&r.content)
                    .is_ok_and(|b| looks_like_scriptlet(&b))
        }
        _ => false,
    }
}

/// Every name and alias a `$redirect=` can really be served from: the redirect resources of the
/// library plus the built-in set. Scriptlets and non-default-permission resources are not
/// redirects (adblock-rust refuses the latter).
pub fn known_redirect_names(resources: &[Resource]) -> HashSet<String> {
    let builtin = crate::redirect_resources::builtin_redirect_resources();
    resources
        .iter()
        .filter(|r| !is_scriptlet(r) && r.permission.to_bits() == 0)
        .chain(&builtin)
        .flat_map(|r| std::iter::once(r.name.clone()).chain(r.aliases.iter().cloned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_parses_names_aliases_and_trust() {
        let m = parse_redirect_map(
            "export default new Map([['a.js',{alias:['x','y'],data:'text'}],['b.gif',{alias:'z',requiresTrust:true}],['c',{}]]);",
        )
        .unwrap();
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].aliases, ["x", "y"]);
        assert_eq!(m[1].aliases, ["z"]);
        assert!(m[1].requires_trust && !m[0].requires_trust);
        assert!(parse_redirect_map("export default 1;").is_err());
    }

    #[test]
    fn files_are_validated_against_their_type() {
        for (n, b, ok) in [
            ("a.gif", &b"GIF89a.."[..], true),
            ("a.gif", b"nope", false),
            ("a.png", b"\x89PNG\r\n\x1a\n", true),
            ("a.png", b"GIF89a", false),
            ("a.mp3", b"\xff\xfb\x90", true),
            ("a.mp3", b"text", false),
            ("a.mp4", b"\0\0\0\x18ftypmp42", true),
            ("a.mp4", b"abc", false),
            ("a.xml", b"<VAST version=\"2.0\"></VAST>", true),
            (
                "a.xml",
                b"<vmap:VMAP xmlns:vmap=\"u\" version=\"1.0\"/>",
                true,
            ),
            ("a.xml", b"<VAST><x></VAST>", false),
            ("a.xml", b"<a></a><b/>", false),
            ("a.xml", b"<a>", false),
            ("a.xml", b"", false),
        ] {
            assert_eq!(validate_file(n, b).is_ok(), ok, "{n} {b:?}");
        }
    }

    #[test]
    fn invalid_file_is_dropped_not_served() {
        let map = "export default new Map([['1x1.gif',{}],['noop.js',{}]]);";
        let files = HashMap::from([
            ("1x1.gif".to_string(), b"junk".to_vec()),
            ("noop.js".to_string(), b"(function(){".to_vec()),
        ]);
        let c = convert_ubo_redirects(map, &files).unwrap();
        assert!(c.resources.is_empty());
        assert_eq!(c.dropped.len(), 2);
    }

    #[test]
    fn trusted_redirects_use_the_default_permission_so_they_can_be_served() {
        let map = "export default new Map([['x.js',{requiresTrust:true}]]);";
        let files = HashMap::from([("x.js".to_string(), b"var a;".to_vec())]);
        let c = convert_ubo_redirects(map, &files).unwrap();
        assert!(c.resources[0].permission.to_bits() == 0);
        assert!(known_redirect_names(&c.resources).contains("x.js"));
    }

    #[test]
    fn scriptlets_are_not_redirects() {
        let sc = Resource {
            name: "prevent-bab.js".into(),
            aliases: vec!["nobab.js".into()],
            kind: ResourceType::Mime(MimeType::ApplicationJavascript),
            content: base64::engine::general_purpose::STANDARD.encode("function preventBab() {}"),
            dependencies: vec![],
            permission: PermissionMask::default(),
        };
        let k = known_redirect_names(&[sc]);
        assert!(!k.contains("nobab.js") && !k.contains("prevent-bab.js"));
        assert!(
            looks_like_scriptlet(b"function f(a) {}") && !looks_like_scriptlet(b"(function(){})()")
        );
    }

    #[test]
    fn missing_file_is_dropped_and_adguard_names_are_added() {
        let map = "export default new Map([['noop.js',{}],['gone.js',{}]]);";
        let files = HashMap::from([("noop.js".to_string(), b"(function(){})();".to_vec())]);
        let c = convert_ubo_redirects(map, &files).unwrap();
        assert_eq!(c.resources.len(), 1);
        assert_eq!(c.dropped.len(), 1);
        assert!(c.resources[0].aliases.contains(&"noopjs".to_string()));
    }

    #[test]
    fn merge_keeps_base_and_skips_clashes() {
        let r = |n: &str, a: &str| {
            format!(
                r#"{{"name":"{n}","aliases":["{a}"],"kind":{{"mime":"text/plain"}},"content":""}}"#
            )
        };
        let base = format!("[{}]", r("a", "x"));
        let extra = format!("[{},{}]", r("b", "x"), r("c", "y"));
        let m: Vec<Resource> =
            serde_json::from_str(&merge_resources_json(&base, &extra).unwrap()).unwrap();
        let names: Vec<_> = m.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["a", "c"]);
    }
}

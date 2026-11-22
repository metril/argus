//! Convert uBlock Origin scriptlet sources into adblock-rust [`Resource`]s, and validate any
//! resource library before it is served.
//!
//! uBO defines scriptlets as ES-module files under `src/js/resources/`:
//!
//! ```js
//! import { registerScriptlet } from './base.js';
//! export function setConstant(chain = '', value = '', extra = {}) { /* ... */ }
//! registerScriptlet(setConstant, {
//!     name: 'set-constant.js',
//!     aliases: ['set-constant'],
//!     dependencies: [safeSelf, validateConstantFn],
//!     requiresTrust: false,
//! });
//! ```
//!
//! (The older `builtinScriptlets.push({ name, fn, dependencies: ['x.fn'] })` form is read too.)
//! The sources are parsed with a real JavaScript parser (`oxc_parser`), never scanned as text:
//! top-level function declarations are cut out by their syntax spans and the registration calls
//! are read from the AST, so default parameters, template and regex literals, nested functions,
//! comments and destructuring cannot confuse the extraction.
//!
//! adblock-rust's own `resource-assembler` only understands the pre-2023 single-file `scriptlets.js`
//! layout (line based, deprecated), so it cannot be used for the current module layout.
//!
//! [`validate_resources`] is the gate every library passes through (freshly converted, cached or
//! bundled): each JavaScript resource must parse, every declared dependency must resolve, and the
//! assembled script (the resource plus its transitive dependencies) must parse. A resource that
//! fails is dropped with a reason and never served; dependents of a dropped resource are dropped
//! too.
//!
//! These scriptlets are GPLv3 (uBlock Origin) — they are fetched at runtime, never vendored
//! (the optional snapshot is feature-gated, see `docs/LICENSING.md`).

use std::collections::{HashMap, HashSet};

use adblock::resources::{MimeType, PermissionMask, Resource, ResourceType};
use base64::Engine as _;
use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, Declaration, Expression, ObjectPropertyKind, Statement};
use oxc_parser::Parser;
use oxc_span::SourceType;
use serde::{Deserialize, Serialize};

/// Permission bit carried by resources whose uBO registration says `requiresTrust: true`. Only
/// filters parsed from a trusted list are granted it (see `compile_lists_with`).
pub const TRUSTED_PERMISSION: PermissionMask = PermissionMask::from_bits(0b1);

/// A resource that was not served, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DroppedResource {
    pub name: String,
    pub reason: String,
}

/// Result of [`convert_ubo_sources`].
#[derive(Default)]
pub struct ScriptletConversion {
    /// Validated resources only.
    pub resources: Vec<Resource>,
    pub dropped: Vec<DroppedResource>,
}

fn drop_(dropped: &mut Vec<DroppedResource>, name: &str, reason: impl Into<String>) {
    dropped.push(DroppedResource {
        name: name.to_string(),
        reason: reason.into(),
    });
}

/// First syntax error of `src` parsed as a classic script, if any.
fn script_error(src: &str) -> Option<String> {
    let alloc = Allocator::default();
    let ret = Parser::new(&alloc, src, SourceType::script()).parse();
    if ret.panicked {
        return Some("parser gave up".into());
    }
    ret.errors.first().map(|e| e.to_string())
}

// ---- extraction ------------------------------------------------------------------------------------

/// A top-level declaration that registrations can refer to by identifier.
struct Decl {
    text: String,
    /// A non-async, non-generator `function name(...)`: the only form adblock-rust can invoke.
    plain_function: bool,
}

enum Dep {
    /// An identifier (`registerScriptlet` form): resolved through the registered function.
    Ident(String),
    /// A resource name (`builtinScriptlets.push` form).
    Name(String),
}

struct Reg {
    name: String,
    aliases: Vec<String>,
    fn_ref: String,
    deps: Vec<Dep>,
    requires_trust: bool,
}

#[derive(Default)]
struct Extracted {
    decls: HashMap<String, Decl>,
    regs: Vec<Reg>,
}

fn str_of(e: &Expression) -> Option<String> {
    match e {
        Expression::StringLiteral(s) => Some(s.value.to_string()),
        Expression::TemplateLiteral(t) if t.expressions.is_empty() && t.quasis.len() == 1 => {
            t.quasis[0].value.cooked.as_ref().map(|c| c.to_string())
        }
        _ => None,
    }
}

fn ident_of(e: &Expression) -> Option<String> {
    match e {
        Expression::Identifier(i) => Some(i.name.to_string()),
        _ => None,
    }
}

/// Read the registration object literal (`name`, `aliases`, `dependencies`, `requiresTrust`, `fn`).
fn read_details(obj: &Expression, reg: &mut Reg, fn_from_details: bool) -> bool {
    let Expression::ObjectExpression(o) = obj else {
        return false;
    };
    for p in &o.properties {
        let ObjectPropertyKind::ObjectProperty(p) = p else {
            continue;
        };
        let Some(key) = p.key.static_name() else {
            continue;
        };
        match key.as_ref() {
            "name" => {
                if let Some(s) = str_of(&p.value) {
                    reg.name = s;
                }
            }
            "fn" if fn_from_details => {
                if let Some(i) = ident_of(&p.value) {
                    reg.fn_ref = i;
                }
            }
            "aliases" => {
                if let Expression::ArrayExpression(a) = &p.value {
                    reg.aliases = a
                        .elements
                        .iter()
                        .filter_map(|e| e.as_expression().and_then(str_of))
                        .collect();
                }
            }
            "dependencies" => {
                if let Expression::ArrayExpression(a) = &p.value {
                    for e in a.elements.iter().filter_map(|e| e.as_expression()) {
                        if let Some(i) = ident_of(e) {
                            reg.deps.push(Dep::Ident(i));
                        } else if let Some(s) = str_of(e) {
                            reg.deps.push(Dep::Name(s));
                        }
                    }
                }
            }
            "requiresTrust" => {
                if let Expression::BooleanLiteral(b) = &p.value {
                    reg.requires_trust = b.value;
                }
            }
            _ => {}
        }
    }
    true
}

fn is_member_call(callee: &Expression, obj: &str, prop: &str) -> bool {
    match callee {
        Expression::StaticMemberExpression(m) => {
            m.property.name == prop && ident_of(&m.object).is_some_and(|o| o == obj)
        }
        _ => false,
    }
}

fn extract_one(src: &str, out: &mut Extracted, dropped: &mut Vec<DroppedResource>, label: &str) {
    // uBO files are ES modules; fall back to a classic script for the old single-file layout.
    let alloc = Allocator::default();
    let ret = Parser::new(&alloc, src, SourceType::mjs()).parse();
    if !ret.panicked && ret.errors.is_empty() {
        return extract_program(src, &ret.program.body, out);
    }
    let alloc2 = Allocator::default();
    let script = Parser::new(&alloc2, src, SourceType::script()).parse();
    if !script.panicked && script.errors.is_empty() {
        return extract_program(src, &script.program.body, out);
    }
    let msg = ret
        .errors
        .first()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "parser gave up".into());
    drop_(dropped, label, format!("source has a syntax error: {msg}"));
    // The parser recovers from most errors. Whatever is cut out of the recovered tree is
    // validated again on its own (see `validate_resources`), so a damaged region cannot be served.
    if !ret.panicked {
        extract_program(src, &ret.program.body, out);
    }
}

fn extract_program(src: &str, body: &[Statement], out: &mut Extracted) {
    let slice = |s: oxc_span::Span| src[s.start as usize..s.end as usize].to_string();
    for st in body {
        let decl = match st {
            Statement::ExportNamedDeclaration(e) => e.declaration.as_ref(),
            Statement::FunctionDeclaration(_)
            | Statement::ClassDeclaration(_)
            | Statement::VariableDeclaration(_) => st.as_declaration(),
            _ => None,
        };
        if let Some(d) = decl {
            match d {
                Declaration::FunctionDeclaration(f) => {
                    if let Some(id) = &f.id {
                        out.decls.insert(
                            id.name.to_string(),
                            Decl {
                                text: slice(f.span),
                                plain_function: !f.r#async && !f.generator,
                            },
                        );
                    }
                }
                Declaration::ClassDeclaration(c) => {
                    if let Some(id) = &c.id {
                        out.decls.insert(
                            id.name.to_string(),
                            Decl {
                                text: slice(c.span),
                                plain_function: false,
                            },
                        );
                    }
                }
                Declaration::VariableDeclaration(v) => {
                    if v.declarations.len() == 1 {
                        if let Some(name) = v.declarations[0].id.get_identifier_name() {
                            out.decls.insert(
                                name.to_string(),
                                Decl {
                                    text: slice(v.span),
                                    plain_function: false,
                                },
                            );
                        }
                    }
                }
                _ => {}
            }
            continue;
        }
        let Statement::ExpressionStatement(es) = st else {
            continue;
        };
        let Expression::CallExpression(call) = &es.expression else {
            continue;
        };
        let mut reg = Reg {
            name: String::new(),
            aliases: vec![],
            fn_ref: String::new(),
            deps: vec![],
            requires_trust: false,
        };
        let arg = |i: usize| call.arguments.get(i).and_then(Argument::as_expression);
        let ok = if ident_of(&call.callee).is_some_and(|c| c == "registerScriptlet") {
            match (arg(0).and_then(ident_of), arg(1)) {
                (Some(f), Some(details)) => {
                    reg.fn_ref = f;
                    read_details(details, &mut reg, false)
                }
                _ => false,
            }
        } else if is_member_call(&call.callee, "builtinScriptlets", "push") {
            arg(0).is_some_and(|d| read_details(d, &mut reg, true))
        } else {
            false
        };
        if ok && !reg.name.is_empty() && !reg.fn_ref.is_empty() {
            out.regs.push(reg);
        }
    }
}

/// Convert uBO scriptlet source files (each parsed separately, in the given order) into validated
/// resources. Problems never abort the conversion: they come back in [`Converted::dropped`].
pub fn convert_ubo_sources<S: AsRef<str>>(sources: &[S]) -> ScriptletConversion {
    let mut dropped = Vec::new();
    let mut ex = Extracted::default();
    for (i, s) in sources.iter().enumerate() {
        extract_one(s.as_ref(), &mut ex, &mut dropped, &format!("source #{i}"));
    }

    // identifier of the registered function -> the resource name it is registered under
    let mut ident_to_name: HashMap<&str, &str> = HashMap::new();
    for r in &ex.regs {
        ident_to_name.entry(&r.fn_ref).or_insert(&r.name);
    }

    let mut resources: Vec<Resource> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for r in &ex.regs {
        if !seen.insert(&r.name) {
            drop_(
                &mut dropped,
                &r.name,
                "registered more than once; first kept",
            );
            continue;
        }
        let Some(decl) = ex.decls.get(&r.fn_ref) else {
            drop_(
                &mut dropped,
                &r.name,
                format!("function `{}` not found at the top level", r.fn_ref),
            );
            continue;
        };
        let is_fn_dep = r.name.ends_with(".fn");
        if !is_fn_dep && !decl.plain_function {
            drop_(
                &mut dropped,
                &r.name,
                format!("`{}` is not a plain function declaration", r.fn_ref),
            );
            continue;
        }
        let mut deps = Vec::new();
        let mut unresolved = None;
        for d in &r.deps {
            match d {
                Dep::Ident(i) => match ident_to_name.get(i.as_str()) {
                    Some(n) => deps.push(n.to_string()),
                    None => {
                        unresolved = Some(i.clone());
                        break;
                    }
                },
                Dep::Name(n) => deps.push(n.clone()),
            }
        }
        if let Some(i) = unresolved {
            drop_(
                &mut dropped,
                &r.name,
                format!("dependency `{i}` is not a registered scriptlet"),
            );
            continue;
        }
        resources.push(Resource {
            name: r.name.clone(),
            aliases: r.aliases.clone(),
            kind: ResourceType::Mime(if is_fn_dep {
                MimeType::FnJavascript
            } else {
                MimeType::ApplicationJavascript
            }),
            content: base64::engine::general_purpose::STANDARD.encode(&decl.text),
            dependencies: deps,
            permission: if r.requires_trust {
                TRUSTED_PERMISSION
            } else {
                PermissionMask::default()
            },
        });
    }

    let v = validate_resources(resources);
    dropped.extend(v.dropped);
    ScriptletConversion {
        resources: v.resources,
        dropped,
    }
}

/// Convert a single (or already concatenated) source. See [`convert_ubo_sources`].
pub fn convert_ubo_scriptlets(js: &str) -> Vec<Resource> {
    convert_ubo_sources(&[js]).resources
}

/// Convert uBO source files into the JSON array [`crate::SharedEngine::set_resources_from_json`]
/// expects, plus what was dropped.
pub fn ubo_sources_to_json<S: AsRef<str>>(
    sources: &[S],
) -> Result<(String, Vec<DroppedResource>), serde_json::Error> {
    let c = convert_ubo_sources(sources);
    Ok((serde_json::to_string(&c.resources)?, c.dropped))
}

/// Convert one source into the resources JSON array.
pub fn ubo_scriptlets_to_json(js: &str) -> Result<String, serde_json::Error> {
    serde_json::to_string(&convert_ubo_scriptlets(js))
}

// ---- validation -------------------------------------------------------------------------------------

fn is_js(r: &Resource) -> bool {
    matches!(
        r.kind,
        ResourceType::Mime(MimeType::ApplicationJavascript | MimeType::FnJavascript)
    )
}

/// Does the script contain a `{{<digits>}}` argument placeholder?
fn has_placeholder(text: &str) -> bool {
    let mut rest = text;
    while let Some(i) = rest.find("{{") {
        let tail = &rest[i + 2..];
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 && tail[digits..].starts_with("}}") {
            return true;
        }
        rest = tail;
    }
    false
}

fn decoded(r: &Resource) -> Result<String, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&r.content)
        .map_err(|e| format!("content is not valid base64: {e}"))?;
    String::from_utf8(bytes).map_err(|_| "content is not UTF-8".to_string())
}

/// Result of [`validate_resources`].
#[derive(Default)]
pub struct Validated {
    pub resources: Vec<Resource>,
    pub dropped: Vec<DroppedResource>,
}

/// Keep only the resources that are safe to serve: JavaScript that parses, whose dependencies all
/// resolve to kept resources, and whose assembled script (dependencies first, then the resource)
/// parses. Non-JavaScript resources pass through untouched.
pub fn validate_resources(resources: Vec<Resource>) -> Validated {
    let mut dropped: Vec<DroppedResource> = Vec::new();
    let mut live: Vec<(Resource, Option<String>)> = Vec::new(); // (resource, decoded JS)
    for r in resources {
        // `{{1}}` templates paste the rule's raw argument into the script text, so a quote in
        // the argument would end the template's own string literal and run as code. Function-style
        // scriptlets (arguments passed as escaped string literals) are the only form served.
        if matches!(r.kind, ResourceType::Template) {
            drop_(
                &mut dropped,
                &r.name,
                "argument templates (`{{1}}`) are not served",
            );
            continue;
        }
        if !is_js(&r) {
            live.push((r, None));
            continue;
        }
        match decoded(&r) {
            Err(e) => drop_(&mut dropped, &r.name, e),
            Ok(text) if has_placeholder(&text) => drop_(
                &mut dropped,
                &r.name,
                "argument templates (`{{1}}`) are not served",
            ),
            Ok(text) => match script_error(&text) {
                Some(e) => drop_(&mut dropped, &r.name, format!("does not parse: {e}")),
                None => live.push((r, Some(text))),
            },
        }
    }

    // Dependency resolution to a fixpoint: a resource whose dependency is missing or dropped goes
    // too. Dependencies are canonical names (aliases are not allowed there, as in adblock-rust).
    loop {
        let names: HashSet<&str> = live.iter().map(|(r, _)| r.name.as_str()).collect();
        let bad: Vec<(usize, String)> = live
            .iter()
            .enumerate()
            .filter_map(|(i, (r, _))| {
                r.dependencies
                    .iter()
                    .find(|d| !names.contains(d.as_str()))
                    .map(|d| (i, d.clone()))
            })
            .collect();
        if bad.is_empty() {
            break;
        }
        for (i, d) in bad.iter().rev() {
            let (r, _) = live.remove(*i);
            drop_(
                &mut dropped,
                &r.name,
                format!("dependency `{d}` is missing or was dropped"),
            );
        }
    }

    // The script actually served: every transitive dependency, then the resource itself.
    let text_of: HashMap<&str, &str> = live
        .iter()
        .filter_map(|(r, t)| t.as_deref().map(|t| (r.name.as_str(), t)))
        .collect();
    let deps_of: HashMap<&str, &[String]> = live
        .iter()
        .map(|(r, _)| (r.name.as_str(), r.dependencies.as_slice()))
        .collect();
    let mut bundle_bad: Vec<(String, String)> = Vec::new();
    for (r, t) in &live {
        let Some(t) = t else { continue };
        let mut order: Vec<&str> = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        let mut stack: Vec<&str> = r.dependencies.iter().map(String::as_str).collect();
        while let Some(n) = stack.pop() {
            if seen.insert(n) {
                order.push(n);
                if let Some(ds) = deps_of.get(n) {
                    stack.extend(ds.iter().map(String::as_str));
                }
            }
        }
        let mut bundle = String::new();
        for n in order {
            if let Some(dt) = text_of.get(n) {
                bundle.push_str(dt);
                bundle.push('\n');
            }
        }
        bundle.push_str(t);
        if let Some(e) = script_error(&bundle) {
            bundle_bad.push((
                r.name.clone(),
                format!("assembled script does not parse: {e}"),
            ));
        }
    }
    if !bundle_bad.is_empty() {
        let bad: HashSet<&str> = bundle_bad.iter().map(|(n, _)| n.as_str()).collect();
        live.retain(|(r, _)| !bad.contains(r.name.as_str()));
        for (n, why) in &bundle_bad {
            drop_(&mut dropped, n, why.clone());
        }
    }

    Validated {
        resources: live.into_iter().map(|(r, _)| r).collect(),
        dropped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures in the *shape* of uBO's module files (written for these tests).
    const BASE: &str = r#"
export const registerScriptlet = (fn, details) => { /* ... */ };
"#;

    const HELPERS: &str = r#"
import { registerScriptlet } from './base.js';

// a comment with a stray { brace and a "quote
export function safeSelf() {
    if ( safeSelf.cache ) { return safeSelf.cache; }
    const re = /[{}]+\/\}/g;           // regex literal with braces
    const t = `tpl ${ '{' + 1 } } {`;   // template literal with braces
    safeSelf.cache = { t, re };
    return safeSelf.cache;
}
registerScriptlet(safeSelf, {
    name: 'safe-self.fn',
});

export function validateConstantFn(trusted, raw, extraArgs = {}) {
    const safe = safeSelf();
    const { a = {}, b: [c = '}'] = [] } = extraArgs;     // destructuring defaults
    function inner(x = { y: 1 }) { return `${x.y}}`; }  // nested function
    return [safe, a, c, inner(), trusted, raw];
}
registerScriptlet(validateConstantFn, {
    name: 'validate-constant.fn',
    dependencies: [
        safeSelf,
    ],
});
"#;

    const SCRIPTLETS: &str = r#"
import { registerScriptlet } from './base.js';
import { safeSelf } from './helpers.js';
import { validateConstantFn } from './helpers.js';

export function setConstant(chain = '', raw = '', extra = {}) {
    const safe = safeSelf();
    const v = validateConstantFn(false, raw, extra);
    Object.defineProperty(window, chain, { value: v[0] === safe ? 1 : 42 });
}
registerScriptlet(setConstant, {
    name: 'set-constant.js',
    aliases: [
        'set-constant',
        'set.js',
    ],
    dependencies: [
        validateConstantFn,
    ],
});

function trustedThing(a = {}) { return `}${a}`; }
registerScriptlet(trustedThing, {
    name: 'trusted-thing.js',
    requiresTrust: true,
    dependencies: [ safeSelf ],
});

function needsGhost() {}
registerScriptlet(needsGhost, { name: 'needs-ghost.js', dependencies: [ghostFn] });

function needsBroken() {}
registerScriptlet(needsBroken, { name: 'needs-broken.js', dependencies: ['broken.js'] });

registerScriptlet(missingFn, { name: 'missing.js' });
"#;

    // A damaged file: the parser cannot recover anything trustworthy from it.
    const BROKEN: &str = r#"
function broken( { return 1 }
registerScriptlet(broken, { name: 'broken.js' });
"#;

    fn convert() -> ScriptletConversion {
        convert_ubo_sources(&[BASE, HELPERS, SCRIPTLETS, BROKEN])
    }

    fn get<'a>(c: &'a ScriptletConversion, n: &str) -> &'a Resource {
        c.resources
            .iter()
            .find(|r| r.name == n)
            .unwrap_or_else(|| panic!("{n} not in {:?}; dropped {:?}", names(c), c.dropped))
    }

    fn names(c: &ScriptletConversion) -> Vec<&str> {
        c.resources.iter().map(|r| r.name.as_str()).collect()
    }

    fn content(r: &Resource) -> String {
        decoded(r).unwrap()
    }

    #[test]
    fn tricky_syntax_survives_extraction() {
        let c = convert();
        let v = get(&c, "validate-constant.fn");
        let text = content(v);
        assert!(text.starts_with("function validateConstantFn(trusted, raw, extraArgs = {})"));
        assert!(text.contains("function inner(x = { y: 1 })"));
        assert!(text.trim_end().ends_with('}'));
        assert!(script_error(&text).is_none());
        let s = content(get(&c, "safe-self.fn"));
        assert!(s.contains("/[{}]+\\/\\}/g") && s.contains("`tpl ${ '{' + 1 } } {`"));
        assert!(script_error(&s).is_none());
        // `export` is not part of the served function.
        assert!(!text.starts_with("export"));
        assert_eq!(
            get(&c, "safe-self.fn").kind,
            ResourceType::Mime(MimeType::FnJavascript)
        );
    }

    #[test]
    fn metadata_aliases_and_transitive_dependencies() {
        let c = convert();
        let sc = get(&c, "set-constant.js");
        assert_eq!(sc.aliases, vec!["set-constant", "set.js"]);
        assert_eq!(sc.dependencies, vec!["validate-constant.fn"]);
        assert_eq!(
            get(&c, "validate-constant.fn").dependencies,
            vec!["safe-self.fn"]
        );
    }

    #[test]
    fn requires_trust_sets_the_permission_bit() {
        let c = convert();
        assert_eq!(get(&c, "trusted-thing.js").permission.to_bits(), 1);
        assert_eq!(get(&c, "set-constant.js").permission.to_bits(), 0);
    }

    #[test]
    fn broken_and_unresolvable_resources_are_dropped_with_reasons() {
        let c = convert();
        let reason = |n: &str| {
            c.dropped
                .iter()
                .find(|d| d.name == n)
                .map(|d| d.reason.clone())
                .unwrap_or_else(|| panic!("{n} not dropped: {:?}", c.dropped))
        };
        assert!(!names(&c).contains(&"broken.js"), "{:?}", names(&c));
        assert!(reason("needs-broken.js").contains("broken.js"));
        assert!(
            c.dropped.iter().any(|d| d.name.starts_with("source #")),
            "the damaged source is reported: {:?}",
            c.dropped
        );
        assert!(reason("needs-ghost.js").contains("ghostFn"));
        assert!(reason("missing.js").contains("missingFn"));
        for r in &c.resources {
            if is_js(r) {
                assert!(script_error(&content(r)).is_none(), "{}", r.name);
            }
        }
    }

    #[test]
    fn dependents_of_a_dropped_resource_are_dropped() {
        let bad = Resource {
            name: "bad.js".into(),
            aliases: vec![],
            kind: ResourceType::Mime(MimeType::ApplicationJavascript),
            content: base64::engine::general_purpose::STANDARD.encode("function bad( {"),
            dependencies: vec![],
            permission: Default::default(),
        };
        let user = Resource {
            name: "user.js".into(),
            content: base64::engine::general_purpose::STANDARD.encode("function user() {}"),
            dependencies: vec!["bad.js".into()],
            ..bad.clone()
        };
        let ok = Resource {
            name: "ok.js".into(),
            content: base64::engine::general_purpose::STANDARD.encode("function ok() {}"),
            dependencies: vec![],
            ..bad.clone()
        };
        let v = validate_resources(vec![bad, user, ok]);
        assert_eq!(
            v.resources
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>(),
            vec!["ok.js"]
        );
        let mut dropped: Vec<&str> = v.dropped.iter().map(|d| d.name.as_str()).collect();
        dropped.sort();
        assert_eq!(dropped, vec!["bad.js", "user.js"]);
        assert!(v
            .dropped
            .iter()
            .any(|d| d.reason.contains("does not parse")));
    }

    #[test]
    fn non_javascript_resources_pass_through() {
        let png = Resource {
            name: "1x1.png".into(),
            aliases: vec![],
            kind: ResourceType::Mime(MimeType::ImagePng),
            content: "AAAA".into(),
            dependencies: vec![],
            permission: Default::default(),
        };
        let v = validate_resources(vec![png]);
        assert_eq!(v.resources.len(), 1);
        assert!(v.dropped.is_empty());
    }

    #[test]
    fn legacy_builtin_scriptlets_push_form() {
        const OLD: &str = r#"
builtinScriptlets.push({
    name: 'safe-self.fn',
    fn: safeSelf,
});
function safeSelf() { return { d: Object.defineProperty.bind(Object) }; }
builtinScriptlets.push({
    name: 'set-constant.js',
    aliases: ['set-constant', 'sc'],
    fn: setConstant,
    dependencies: ['safe-self.fn'],
});
function setConstant(...args) { safeSelf().d(window, args[0], { value: args[1] }); }
"#;
        let c = convert_ubo_sources(&[OLD]);
        assert_eq!(c.resources.len(), 2, "{:?}", c.dropped);
        assert_eq!(
            get(&c, "set-constant.js").dependencies,
            vec!["safe-self.fn"]
        );
    }

    #[test]
    fn converted_scriptlet_injects_via_engine_with_valid_script() {
        use adblock::lists::{FilterSet, ParseOptions};
        use adblock::Engine;

        let c = convert();
        let mut fs = FilterSet::new(false);
        fs.add_filter(
            "example.com##+js(set-constant, foo, 1)",
            ParseOptions::default(),
        )
        .unwrap();
        let mut engine = Engine::from_filter_set(fs, true);
        engine.use_resources(c.resources);
        let r = engine.url_cosmetic_resources("https://example.com/");
        assert!(!r.injected_script.is_empty());
        // The whole injected script parses as JavaScript.
        let wrapped = format!("(function(){{{}}})();", r.injected_script);
        assert!(
            script_error(&wrapped).is_none(),
            "{:?}",
            script_error(&wrapped)
        );
        assert!(r.injected_script.contains("function validateConstantFn"));
        assert!(r.injected_script.contains("function safeSelf"));
    }

    #[test]
    fn trusted_scriptlet_needs_a_trusted_list() {
        use adblock::lists::{FilterSet, ParseOptions};
        use adblock::Engine;

        let c = convert();
        let rule = "example.com##+js(trusted-thing, a)";
        let injected = |perm: PermissionMask| {
            let mut fs = FilterSet::new(false);
            fs.add_filter(
                rule,
                ParseOptions {
                    permissions: perm,
                    ..Default::default()
                },
            )
            .unwrap();
            let mut engine = Engine::from_filter_set(fs, true);
            engine.use_resources(c.resources.clone());
            engine
                .url_cosmetic_resources("https://example.com/")
                .injected_script
        };
        assert!(injected(PermissionMask::default()).is_empty());
        assert!(injected(TRUSTED_PERMISSION).contains("trustedThing"));
    }
}

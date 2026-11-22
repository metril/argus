//! Arguments of `##+js(name, arg, ...)` come from lists (untrusted ones included): whatever they
//! contain must stay a string argument of the one scriptlet call, never become code.

use filter_engine::{build_set, convert_ubo_sources, ListFormat, ListInput, SharedEngine};
use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, Expression, Statement};
use oxc_parser::Parser;
use oxc_span::SourceType;

const SRC: &str = r#"
import { registerScriptlet } from './base.js';
export function plain(a = '', b = '') { return `${a}${b}`; }
registerScriptlet(plain, { name: 'plain.js' });
"#;

fn injected(rule: &str) -> String {
    let e = SharedEngine::new();
    let json = serde_json::to_string(&convert_ubo_sources(&[SRC]).resources).unwrap();
    e.set_resources_from_json(&json).unwrap();
    build_set(&[ListInput {
        id: "l".into(),
        content: format!("{rule}\n"),
        format: ListFormat::Abp,
        allowlist: false,
        trusted: false,
        includes: Default::default(),
    }])
    .install_into(&e);
    e.cosmetic_for("https://site.test/").injected_script
}

/// The string values of every `plain(...)` call argument, asserting that nothing else in the
/// script (beyond the definition of `plain` itself) is executable top-level code.
fn call_args(js: &str) -> Vec<String> {
    let alloc = Allocator::default();
    let ret = Parser::new(&alloc, js, SourceType::default().with_script(true)).parse();
    assert!(
        ret.errors.is_empty(),
        "does not parse: {:?}\n{js}",
        ret.errors
    );
    let mut calls = Vec::new();
    let mut stmts = 0;
    let mut visit = |st: &Statement| {
        if let Statement::ExpressionStatement(e) = st {
            stmts += 1;
            let Expression::CallExpression(c) = &e.expression else {
                panic!("top-level statement is not a plain call: {js}");
            };
            let Expression::Identifier(id) = &c.callee else {
                panic!("callee is not an identifier: {js}");
            };
            assert_eq!(id.name, "plain", "{js}");
            for a in &c.arguments {
                match a {
                    Argument::StringLiteral(s) => calls.push(s.value.to_string()),
                    other => panic!("argument is not a string literal: {other:?}\n{js}"),
                }
            }
        }
    };
    for st in &ret.program.body {
        match st {
            Statement::FunctionDeclaration(_) => {}
            Statement::TryStatement(t) => t.block.body.iter().for_each(&mut visit),
            other => visit(other),
        }
    }
    assert_eq!(stmts, 1, "exactly one call statement expected: {js}");
    calls
}

#[test]
fn hostile_arguments_stay_string_arguments() {
    let hostile: &[&str] = &[
        r#"a"); alert(1); (""#,
        r#"a\"); alert(1); //"#,
        "back\\slash\\x",
        "x`${alert(1)}`y",
        "${alert(1)}",
        "</script><script>alert(1)</script>",
        "x'; alert(1); 'y",
        "line\u{2028}sep\u{2029}para",
        "tab\there",
        "nul\u{0}byte",
        "{{1}}{{2}}",
        "a\u{feff}b",
    ];
    for h in hostile {
        let escaped = h.replace(',', "\\,");
        let js = injected(&format!("site.test##+js(plain, {escaped}, second)"));
        let args = call_args(&js);
        assert_eq!(args, vec![h.to_string(), "second".to_string()], "{h:?}");
    }
}

/// Old-style `{{1}}` templates substitute the raw argument into the template, so a quote in the
/// argument ends the template's own string. Such resources must not be served.
#[test]
fn template_style_resources_are_not_served() {
    use base64::Engine as _;
    let e = SharedEngine::new();
    let content = base64::engine::general_purpose::STANDARD.encode("window.x = '{{1}}';");
    let json =
        format!(r#"[{{"name":"tpl.js","aliases":[],"kind":"template","content":"{content}"}}]"#);
    let n = e.set_resources_from_json(&json).unwrap();
    build_set(&[ListInput {
        id: "l".into(),
        content: "site.test##+js(tpl, x'; alert(1); 'y)\n".into(),
        format: ListFormat::Abp,
        allowlist: false,
        trusted: false,
        includes: Default::default(),
    }])
    .install_into(&e);
    let js = e.cosmetic_for("https://site.test/").injected_script;
    assert!(n == 0 && !js.contains("alert(1)"), "loaded={n}\n{js}");
}

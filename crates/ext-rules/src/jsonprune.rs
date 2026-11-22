//! `$jsonprune`: remove nodes from a JSON response selected by a JSONPath subset.
//!
//! Supported syntax (AdGuard KB "$jsonprune", uBO wiki "jsonprune="):
//! * `$` root; `.name`, `..name` (recursive descent), `.*`, `[*]`
//! * bracket selectors: `['a']`, `["a","b"]` (union), `[0]`, `[0,2]`, `[-1]`, `[?(<filter>)]`
//! * filters: `@.a.b`, `==`, `!=`, `<`, `<=`, `>`, `>=` against string / number / `true` /
//!   `false` / `null`, existence tests (`@.a`), `!`, `&&`, `||`, and parentheses
//! * uBO legacy form: space-separated dotted paths from the root (`a.b.[].c`, `*` and `[]` are
//!   wildcards), as used by the `json-prune` scriptlet
//!
//! Not supported (reported as unsupported at parse time): script expressions, slices, `$`-rooted
//! filter operands, regex filters. Parsing uses a small order- and number-preserving JSON model so
//! untouched parts of the document round-trip byte-for-byte equivalent in content.

use std::borrow::Cow;

pub const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_DEPTH: usize = 128;

// ---- JSON model --------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum J {
    Null,
    Bool(bool),
    /// Source text of the number (preserves precision and formatting).
    Num(String),
    /// Source text between the quotes (still escaped).
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

impl P<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn lit(&mut self, s: &str, v: J) -> Option<J> {
        if self.b[self.i..].starts_with(s.as_bytes()) {
            self.i += s.len();
            Some(v)
        } else {
            None
        }
    }
    fn string(&mut self) -> Option<String> {
        // at opening quote
        self.i += 1;
        let s = self.i;
        while self.i < self.b.len() {
            match self.b[self.i] {
                b'\\' => self.i += 2,
                b'"' => {
                    let out = std::str::from_utf8(&self.b[s..self.i]).ok()?.to_string();
                    self.i += 1;
                    return Some(out);
                }
                c if c < 0x20 => return None,
                _ => self.i += 1,
            }
        }
        None
    }
    fn value(&mut self, depth: usize) -> Option<J> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.ws();
        match *self.b.get(self.i)? {
            b'n' => self.lit("null", J::Null),
            b't' => self.lit("true", J::Bool(true)),
            b'f' => self.lit("false", J::Bool(false)),
            b'"' => self.string().map(J::Str),
            b'[' => {
                self.i += 1;
                let mut v = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Some(J::Arr(v));
                }
                loop {
                    v.push(self.value(depth + 1)?);
                    self.ws();
                    match *self.b.get(self.i)? {
                        b',' => self.i += 1,
                        b']' => {
                            self.i += 1;
                            return Some(J::Arr(v));
                        }
                        _ => return None,
                    }
                }
            }
            b'{' => {
                self.i += 1;
                let mut v = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Some(J::Obj(v));
                }
                loop {
                    self.ws();
                    if self.b.get(self.i) != Some(&b'"') {
                        return None;
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.b.get(self.i) != Some(&b':') {
                        return None;
                    }
                    self.i += 1;
                    v.push((k, self.value(depth + 1)?));
                    self.ws();
                    match *self.b.get(self.i)? {
                        b',' => self.i += 1,
                        b'}' => {
                            self.i += 1;
                            return Some(J::Obj(v));
                        }
                        _ => return None,
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let s = self.i;
                while self.i < self.b.len()
                    && matches!(
                        self.b[self.i],
                        b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'
                    )
                {
                    self.i += 1;
                }
                Some(J::Num(
                    std::str::from_utf8(&self.b[s..self.i]).ok()?.to_string(),
                ))
            }
            _ => None,
        }
    }
}

fn parse_json(b: &[u8]) -> Option<J> {
    let mut p = P { b, i: 0 };
    let v = p.value(0)?;
    p.ws();
    (p.i == b.len()).then_some(v)
}

fn write(v: &J, out: &mut Vec<u8>) {
    match v {
        J::Null => out.extend_from_slice(b"null"),
        J::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        J::Num(s) => out.extend_from_slice(s.as_bytes()),
        J::Str(s) => {
            out.push(b'"');
            out.extend_from_slice(s.as_bytes());
            out.push(b'"');
        }
        J::Arr(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(x, out);
            }
            out.push(b']');
        }
        J::Obj(o) => {
            out.push(b'{');
            for (i, (k, x)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.push(b'"');
                out.extend_from_slice(k.as_bytes());
                out.extend_from_slice(b"\":");
                write(x, out);
            }
            out.push(b'}');
        }
    }
}

/// Decode the escapes of a JSON string body (best effort: invalid escapes are kept verbatim).
fn unescape(s: &str) -> Cow<'_, str> {
    if !s.contains('\\') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('u') => {
                let hex: String = it.by_ref().take(4).collect();
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(ch) => out.push(ch),
                    None => {
                        out.push_str("\\u");
                        out.push_str(&hex)
                    }
                }
            }
            Some(o) => out.push(o),
            None => out.push('\\'),
        }
    }
    Cow::Owned(out)
}

// ---- path model --------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Lit {
    Str(String),
    Num(f64),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, PartialEq)]
enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    Exists(Vec<String>),
    Cmp(Vec<String>, Cmp, Lit),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
enum Sel {
    Names(Vec<String>),
    Indexes(Vec<i64>),
    Wild,
    Filter(Expr),
}

#[derive(Debug, Clone, PartialEq)]
struct Step {
    descend: bool,
    sel: Sel,
}

/// A parsed `$jsonprune` value: one or more prune paths.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonPrune {
    /// The option value as written.
    pub value: String,
    paths: Vec<Vec<Step>>,
}

struct Lex<'a> {
    s: &'a [u8],
    i: usize,
}

impl Lex<'_> {
    fn ws(&mut self) {
        while self.s.get(self.i).is_some_and(|c| c.is_ascii_whitespace()) {
            self.i += 1;
        }
    }
    fn eat(&mut self, t: &str) -> bool {
        self.ws();
        if self.s[self.i..].starts_with(t.as_bytes()) {
            self.i += t.len();
            true
        } else {
            false
        }
    }
    fn quoted(&mut self) -> Result<String, String> {
        let q = self.s[self.i];
        self.i += 1;
        let mut out = Vec::new();
        while let Some(&c) = self.s.get(self.i) {
            self.i += 1;
            if c == q {
                return String::from_utf8(out).map_err(|e| e.to_string());
            }
            if c == b'\\' {
                if let Some(&n) = self.s.get(self.i) {
                    self.i += 1;
                    out.push(n);
                }
            } else {
                out.push(c);
            }
        }
        Err("unterminated string".into())
    }
    fn ident(&mut self) -> String {
        let s = self.i;
        while self
            .s
            .get(self.i)
            .is_some_and(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'$' | b':'))
        {
            self.i += 1;
        }
        String::from_utf8_lossy(&self.s[s..self.i]).into_owned()
    }
    /// `@.a.b` / `@['a']` operand path (after `@`).
    fn operand(&mut self) -> Result<Vec<String>, String> {
        let mut path = Vec::new();
        loop {
            if self.s.get(self.i) == Some(&b'.') {
                self.i += 1;
                let id = self.ident();
                if id.is_empty() {
                    return Err("bad filter operand".into());
                }
                path.push(id);
            } else if self.s.get(self.i) == Some(&b'[') {
                self.i += 1;
                self.ws();
                if !matches!(self.s.get(self.i), Some(b'\'' | b'"')) {
                    return Err("bad filter operand".into());
                }
                path.push(self.quoted()?);
                if !self.eat("]") {
                    return Err("expected `]`".into());
                }
            } else {
                return Ok(path);
            }
        }
    }
    fn literal(&mut self) -> Result<Lit, String> {
        self.ws();
        match self.s.get(self.i) {
            Some(b'\'' | b'"') => Ok(Lit::Str(self.quoted()?)),
            _ => {
                let s = self.i;
                while self
                    .s
                    .get(self.i)
                    .is_some_and(|&c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'+' | b'.'))
                {
                    self.i += 1;
                }
                match std::str::from_utf8(&self.s[s..self.i]).unwrap_or("") {
                    "true" => Ok(Lit::Bool(true)),
                    "false" => Ok(Lit::Bool(false)),
                    "null" => Ok(Lit::Null),
                    n => n
                        .parse::<f64>()
                        .map(Lit::Num)
                        .map_err(|_| format!("bad literal `{n}`")),
                }
            }
        }
    }
    fn atom(&mut self, depth: usize) -> Result<Expr, String> {
        if depth > 16 {
            return Err("filter too deeply nested".into());
        }
        if self.eat("!") {
            return Ok(Expr::Not(Box::new(self.atom(depth + 1)?)));
        }
        if self.eat("(") {
            let e = self.or(depth + 1)?;
            return if self.eat(")") {
                Ok(e)
            } else {
                Err("expected `)`".into())
            };
        }
        if !self.eat("@") {
            return Err(
                "filter operands must start with `@` (script expressions unsupported)".into(),
            );
        }
        let path = self.operand()?;
        self.ws();
        for (t, c) in [
            ("==", Cmp::Eq),
            ("!=", Cmp::Ne),
            ("<=", Cmp::Le),
            (">=", Cmp::Ge),
            ("<", Cmp::Lt),
            (">", Cmp::Gt),
        ] {
            if self.eat(t) {
                return Ok(Expr::Cmp(path, c, self.literal()?));
            }
        }
        Ok(Expr::Exists(path))
    }
    fn and(&mut self, d: usize) -> Result<Expr, String> {
        let mut l = self.atom(d)?;
        while self.eat("&&") {
            l = Expr::And(Box::new(l), Box::new(self.atom(d)?));
        }
        Ok(l)
    }
    fn or(&mut self, d: usize) -> Result<Expr, String> {
        let mut l = self.and(d)?;
        while self.eat("||") {
            l = Expr::Or(Box::new(l), Box::new(self.and(d)?));
        }
        Ok(l)
    }
}

fn parse_jsonpath(s: &str) -> Result<Vec<Step>, String> {
    let mut lx = Lex {
        s: s.as_bytes(),
        i: 0,
    };
    lx.ws();
    if !lx.eat("$") {
        return Err("JSONPath must start with `$`".into());
    }
    let mut steps = Vec::new();
    loop {
        lx.ws();
        if lx.i >= lx.s.len() {
            break;
        }
        let descend = lx.s[lx.i..].starts_with(b"..");
        if descend {
            lx.i += 2;
        } else if lx.s[lx.i] == b'.' {
            lx.i += 1;
        } else if lx.s[lx.i] != b'[' {
            return Err(format!("unexpected `{}`", lx.s[lx.i] as char));
        }
        match lx.s.get(lx.i) {
            Some(b'*') => {
                lx.i += 1;
                steps.push(Step {
                    descend,
                    sel: Sel::Wild,
                });
            }
            Some(b'[') => {
                lx.i += 1;
                lx.ws();
                let sel = match lx.s.get(lx.i) {
                    Some(b'*') => {
                        lx.i += 1;
                        Sel::Wild
                    }
                    Some(b'?') => {
                        lx.i += 1;
                        if !lx.eat("(") {
                            return Err("expected `?(`".into());
                        }
                        let e = lx.or(0)?;
                        if !lx.eat(")") {
                            return Err("expected `)`".into());
                        }
                        Sel::Filter(e)
                    }
                    Some(b'\'' | b'"') => {
                        let mut names = vec![lx.quoted()?];
                        while lx.eat(",") {
                            lx.ws();
                            if !matches!(lx.s.get(lx.i), Some(b'\'' | b'"')) {
                                return Err("mixed union selectors unsupported".into());
                            }
                            names.push(lx.quoted()?);
                        }
                        Sel::Names(names)
                    }
                    Some(c) if c.is_ascii_digit() || *c == b'-' => {
                        let mut idx = Vec::new();
                        loop {
                            lx.ws();
                            let s0 = lx.i;
                            lx.i += 1;
                            while lx.s.get(lx.i).is_some_and(|c| c.is_ascii_digit()) {
                                lx.i += 1;
                            }
                            idx.push(
                                std::str::from_utf8(&lx.s[s0..lx.i])
                                    .unwrap_or("")
                                    .parse::<i64>()
                                    .map_err(|_| "bad index (slices are unsupported)")?,
                            );
                            if !lx.eat(",") {
                                break;
                            }
                        }
                        Sel::Indexes(idx)
                    }
                    _ => return Err("unsupported bracket selector".into()),
                };
                if !lx.eat("]") {
                    return Err("expected `]` (slices and expressions are unsupported)".into());
                }
                steps.push(Step { descend, sel });
            }
            _ => {
                let id = lx.ident();
                if id.is_empty() {
                    return Err("expected a property name".into());
                }
                steps.push(Step {
                    descend,
                    sel: Sel::Names(vec![id]),
                });
            }
        }
    }
    if steps.is_empty() {
        return Err("path selects only the root".into());
    }
    Ok(steps)
}

/// Legacy dotted path: `a.b.[].c`.
fn parse_legacy(s: &str) -> Result<Vec<Step>, String> {
    let steps: Vec<Step> = s
        .split('.')
        .map(|seg| {
            let sel = match seg {
                "*" | "[]" => Sel::Wild,
                "" => return Err("empty path segment".to_string()),
                n => Sel::Names(vec![n.to_string()]),
            };
            Ok(Step {
                descend: false,
                sel,
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(steps)
}

/// Split a value into whitespace-separated paths, keeping bracketed / quoted spans together.
fn split_paths(v: &str) -> Vec<&str> {
    let (mut out, mut depth, mut quote, mut start) = (Vec::new(), 0i32, None::<char>, None);
    for (i, c) in v.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, '[' | '(') => depth += 1,
            (None, ']' | ')') => depth -= 1,
            _ => {}
        }
        if c.is_whitespace() && quote.is_none() && depth <= 0 {
            if let Some(s) = start.take() {
                out.push(&v[s..i]);
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        out.push(&v[s..]);
    }
    out
}

impl JsonPrune {
    pub fn parse(value: &str) -> Result<Self, String> {
        let v = value.trim();
        if v.is_empty() {
            return Err("empty path".into());
        }
        let mut paths = Vec::new();
        for p in split_paths(v) {
            paths.push(if p.starts_with('$') {
                parse_jsonpath(p)?
            } else {
                parse_legacy(p)?
            });
        }
        Ok(Self {
            value: value.to_string(),
            paths,
        })
    }
}

// ---- evaluation --------------------------------------------------------------------------------

fn lookup<'a>(mut v: &'a J, path: &[String]) -> Option<&'a J> {
    for k in path {
        match v {
            J::Obj(o) => v = &o.iter().find(|(n, _)| unescape(n) == k.as_str())?.1,
            _ => return None,
        }
    }
    Some(v)
}

fn lit_cmp(v: &J, op: &Cmp, l: &Lit) -> bool {
    use std::cmp::Ordering::*;
    let ord = match (v, l) {
        (J::Str(s), Lit::Str(t)) => Some(unescape(s).as_ref().cmp(t.as_str())),
        (J::Num(n), Lit::Num(m)) => n.parse::<f64>().ok().and_then(|n| n.partial_cmp(m)),
        (J::Bool(a), Lit::Bool(b)) => Some(a.cmp(b)),
        (J::Null, Lit::Null) => Some(Equal),
        _ => None,
    };
    match (op, ord) {
        (Cmp::Eq, o) => o == Some(Equal),
        (Cmp::Ne, o) => o != Some(Equal),
        (_, None) => false,
        (Cmp::Lt, Some(o)) => o == Less,
        (Cmp::Le, Some(o)) => o != Greater,
        (Cmp::Gt, Some(o)) => o == Greater,
        (Cmp::Ge, Some(o)) => o != Less,
    }
}

fn eval(e: &Expr, v: &J) -> bool {
    match e {
        Expr::Exists(p) => lookup(v, p).is_some(),
        Expr::Cmp(p, op, l) => match lookup(v, p) {
            Some(x) => lit_cmp(x, op, l),
            None => matches!(op, Cmp::Ne),
        },
        Expr::Not(x) => !eval(x, v),
        Expr::And(a, b) => eval(a, v) && eval(b, v),
        Expr::Or(a, b) => eval(a, v) || eval(b, v),
    }
}

fn child_matches(sel: &Sel, key: Option<&str>, idx: usize, len: usize, v: &J) -> bool {
    match sel {
        Sel::Wild => true,
        Sel::Names(n) => key.is_some_and(|k| {
            let k = unescape(k);
            n.iter().any(|x| x.as_str() == k)
        }),
        Sel::Indexes(ix) => {
            key.is_none()
                && ix.iter().any(|&i| {
                    if i < 0 {
                        len as i64 + i == idx as i64
                    } else {
                        i == idx as i64
                    }
                })
        }
        Sel::Filter(e) => eval(e, v),
    }
}

fn apply_sel(node: &mut J, sel: &Sel, rest: &[Step], removed: &mut usize) {
    match node {
        J::Obj(o) => {
            let n = o.len();
            if rest.is_empty() {
                let mut idx = 0;
                o.retain(|(k, v)| {
                    let m = child_matches(sel, Some(k), idx, n, v);
                    idx += 1;
                    !m
                });
                *removed += n - o.len();
            } else {
                for (i, (k, v)) in o.iter_mut().enumerate() {
                    if child_matches(sel, Some(k), i, n, v) {
                        prune(v, rest, removed);
                    }
                }
            }
        }
        J::Arr(a) => {
            let n = a.len();
            if rest.is_empty() {
                let mut idx = 0;
                a.retain(|v| {
                    let m = child_matches(sel, None, idx, n, v);
                    idx += 1;
                    !m
                });
                *removed += n - a.len();
            } else {
                for (i, v) in a.iter_mut().enumerate() {
                    if child_matches(sel, None, i, n, v) {
                        prune(v, rest, removed);
                    }
                }
            }
        }
        _ => {}
    }
}

fn prune(node: &mut J, steps: &[Step], removed: &mut usize) {
    let Some((step, rest)) = steps.split_first() else {
        return;
    };
    apply_sel(node, &step.sel, rest, removed);
    if step.descend {
        match node {
            J::Obj(o) => o.iter_mut().for_each(|(_, v)| prune(v, steps, removed)),
            J::Arr(a) => a.iter_mut().for_each(|v| prune(v, steps, removed)),
            _ => {}
        }
    }
}

/// Apply `$jsonprune` specs to a JSON body. Returns the input untouched when the body is not valid
/// JSON, exceeds [`MAX_JSON_BYTES`] / the nesting limit, or nothing matched.
pub fn apply_jsonprune<'a>(body: &'a [u8], specs: &[&JsonPrune]) -> Cow<'a, [u8]> {
    if body.len() > MAX_JSON_BYTES || specs.is_empty() {
        return Cow::Borrowed(body);
    }
    // Tolerate a UTF-8 BOM.
    let (bom, rest) = match body.strip_prefix(&[0xEF, 0xBB, 0xBF][..]) {
        Some(r) => (&body[..3], r),
        None => (&body[..0], body),
    };
    let Some(mut doc) = parse_json(rest) else {
        return Cow::Borrowed(body);
    };
    let mut removed = 0;
    for s in specs {
        for path in &s.paths {
            prune(&mut doc, path, &mut removed);
        }
    }
    if removed == 0 {
        return Cow::Borrowed(body);
    }
    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(bom);
    write(&doc, &mut out);
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(path: &str, json: &str) -> String {
        let p = JsonPrune::parse(path).unwrap();
        String::from_utf8(apply_jsonprune(json.as_bytes(), &[&p]).into_owned()).unwrap()
    }

    #[test]
    fn conformance() {
        let doc = r#"{"a":{"ads":[1,2],"keep":1},"list":[{"id":1,"ad":true},{"id":2},{"id":3,"ad":false}],"ads":0}"#;
        assert_eq!(run("$.ads", doc).matches("\"ads\"").count(), 1);
        assert_eq!(
            run("$..ads", doc),
            r#"{"a":{"keep":1},"list":[{"id":1,"ad":true},{"id":2},{"id":3,"ad":false}]}"#
        );
        assert_eq!(
            run("$.a['ads','keep']", doc),
            r#"{"a":{},"list":[{"id":1,"ad":true},{"id":2},{"id":3,"ad":false}],"ads":0}"#
        );
        assert_eq!(
            run("$.list[?(@.ad==true)]", doc),
            r#"{"a":{"ads":[1,2],"keep":1},"list":[{"id":2},{"id":3,"ad":false}],"ads":0}"#
        );
        assert_eq!(run("$.list[?(@.ad)]", doc).matches("\"id\"").count(), 1);
        assert_eq!(
            run("$.list[?(@.id>=2 && @.ad!=true)]", doc),
            r#"{"a":{"ads":[1,2],"keep":1},"list":[{"id":1,"ad":true}],"ads":0}"#
        );
        assert_eq!(run("$.list[0]", doc).matches("\"id\"").count(), 2);
        assert_eq!(run("$.list[-1]", doc).matches("\"id\"").count(), 2);
        assert_eq!(run("$.a.ads[*]", doc), doc.replace("[1,2]", "[]"));
        assert_eq!(
            run("$.list.*.ad", doc),
            r#"{"a":{"ads":[1,2],"keep":1},"list":[{"id":1},{"id":2},{"id":3}],"ads":0}"#
        );
        assert_eq!(
            run("a.ads list.[].ad", doc),
            r#"{"a":{"keep":1},"list":[{"id":1},{"id":2},{"id":3}],"ads":0}"#
        );
        assert_eq!(
            run("$..[?(@.id==2)]", doc),
            r#"{"a":{"ads":[1,2],"keep":1},"list":[{"id":1,"ad":true},{"id":3,"ad":false}],"ads":0}"#
        );
        assert_eq!(run("$..[\"ads\", \"ad\"]", doc).matches("ad").count(), 0);
    }

    #[test]
    fn preserves_formatting_of_content() {
        let doc = r#"{ "n": 1.50e3, "s": "a\"bé", "x": 1 }"#;
        assert_eq!(run("$.x", doc), r#"{"n":1.50e3,"s":"a\"bé"}"#);
        assert_eq!(run("$.nope", doc), doc);
    }

    #[test]
    fn malformed_and_limits() {
        let p = JsonPrune::parse("$.a").unwrap();
        for bad in ["", "{", "{\"a\":1,}", "[1 2]", "{\"a\":1} x", "\u{0}"] {
            assert!(
                matches!(apply_jsonprune(bad.as_bytes(), &[&p]), Cow::Borrowed(_)),
                "{bad}"
            );
        }
        let deep = "[".repeat(1000) + &"]".repeat(1000);
        assert!(matches!(
            apply_jsonprune(deep.as_bytes(), &[&p]),
            Cow::Borrowed(_)
        ));
        let big = vec![b' '; MAX_JSON_BYTES + 1];
        assert!(matches!(apply_jsonprune(&big, &[&p]), Cow::Borrowed(_)));
    }

    #[test]
    fn parse_errors() {
        for bad in [
            "",
            "$",
            "$.a[1:2]",
            "$.a[?(foo)]",
            "$.a[?(@.x ==)]",
            "$.a[",
            "a..b",
        ] {
            assert!(JsonPrune::parse(bad).is_err(), "{bad}");
        }
    }
}

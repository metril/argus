//! `$xmlprune`: remove elements from an XML response selected by an XPath subset.
//!
//! Subset (AdGuard KB "$xmlprune", uBO wiki "xmlprune="): location steps joined by `/` and `//`
//! (a leading bare name means `//name`); name tests `name` and `*`; predicates `[@a]`,
//! `[@a='v']`, `[contains(@a,'v')]`, `[text()='v']`, `[contains(text(),'v')]`,
//! `[name()='v']`, `[N]` (1-based). The value may be wrapped in `xpath(...)`. Anything else is
//! rejected at parse time. The document is scanned tolerantly into an element tree and the
//! selected elements' byte ranges are cut out of the original text, so everything else is
//! preserved exactly.

use std::borrow::Cow;

pub const MAX_XML_BYTES: usize = 4 * 1024 * 1024;
const MAX_NODES: usize = 200_000;
const MAX_DEPTH: usize = 256;

#[derive(Debug, Clone, PartialEq)]
enum Pred {
    Attr(String),
    AttrEq(String, String),
    AttrContains(String, String),
    TextEq(String),
    TextContains(String),
    NameEq(String),
    Index(usize),
}

#[derive(Debug, Clone, PartialEq)]
struct Step {
    descendant: bool,
    name: Option<String>,
    preds: Vec<Pred>,
}

/// A parsed `$xmlprune` XPath.
#[derive(Debug, Clone, PartialEq)]
pub struct XmlPrune {
    /// The option value as written.
    pub value: String,
    steps: Vec<Step>,
}

fn unquote(s: &str) -> Option<String> {
    let s = s.trim();
    let q = s.chars().next()?;
    (matches!(q, '\'' | '"') && s.len() >= 2 && s.ends_with(q))
        .then(|| s[1..s.len() - 1].to_string())
}

fn parse_pred(p: &str) -> Result<Pred, String> {
    let p = p.trim();
    if let Ok(n) = p.parse::<usize>() {
        return if n >= 1 {
            Ok(Pred::Index(n))
        } else {
            Err("index must be >= 1".into())
        };
    }
    if let Some(inner) = p
        .strip_prefix("contains(")
        .and_then(|r| r.strip_suffix(')'))
    {
        let (a, b) = inner.split_once(',').ok_or("bad contains()")?;
        let val = unquote(b).ok_or("bad contains() value")?;
        return match a.trim() {
            "text()" | "." => Ok(Pred::TextContains(val)),
            x if x.starts_with('@') => Ok(Pred::AttrContains(x[1..].to_string(), val)),
            _ => Err("unsupported contains() subject".into()),
        };
    }
    if let Some((l, r)) = p.split_once('=') {
        let (l, v) = (l.trim(), unquote(r).ok_or("bad predicate value")?);
        return match l {
            "text()" | "." => Ok(Pred::TextEq(v)),
            "name()" | "local-name()" => Ok(Pred::NameEq(v)),
            x if x.starts_with('@') => Ok(Pred::AttrEq(x[1..].to_string(), v)),
            _ => Err("unsupported predicate".into()),
        };
    }
    if let Some(a) = p.strip_prefix('@') {
        if !a.is_empty()
            && a.chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | ':' | '.'))
        {
            return Ok(Pred::Attr(a.to_string()));
        }
    }
    Err(format!("unsupported predicate `{p}`"))
}

impl XmlPrune {
    pub fn parse(value: &str) -> Result<Self, String> {
        let v = value.trim();
        let v = v
            .strip_prefix("xpath(")
            .and_then(|r| r.strip_suffix(')'))
            .map(|x| x.trim())
            .unwrap_or(v);
        let b = v.as_bytes();
        if b.is_empty() {
            return Err("empty XPath".into());
        }
        let mut steps = Vec::new();
        let mut i = 0;
        let mut first = true;
        while i < b.len() {
            let mut descendant = false;
            if b[i..].starts_with(b"//") {
                descendant = true;
                i += 2;
            } else if b[i] == b'/' {
                i += 1;
            } else if first {
                descendant = true;
            } else {
                return Err("expected `/`".into());
            }
            first = false;
            let s = i;
            while i < b.len() && !matches!(b[i], b'/' | b'[') {
                i += 1;
            }
            let name = &v[s..i];
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, '*' | '_' | '-' | ':' | '.'))
            {
                return Err(format!("unsupported step `{name}`"));
            }
            let mut preds = Vec::new();
            while i < b.len() && b[i] == b'[' {
                let (mut depth, mut q, s2) = (0i32, None::<u8>, i + 1);
                let mut end = None;
                for (j, &c) in b.iter().enumerate().skip(i) {
                    match (q, c) {
                        (Some(qq), c) if c == qq => q = None,
                        (Some(_), _) => {}
                        (None, b'\'' | b'"') => q = Some(c),
                        (None, b'[') => depth += 1,
                        (None, b']') => {
                            depth -= 1;
                            if depth == 0 {
                                end = Some(j);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let end = end.ok_or("unterminated predicate")?;
                preds.push(parse_pred(&v[s2..end])?);
                i = end + 1;
            }
            steps.push(Step {
                descendant,
                name: (name != "*").then(|| name.to_string()),
                preds,
            });
        }
        Ok(Self {
            value: value.to_string(),
            steps,
        })
    }
}

// ---- tolerant element scanner -----------------------------------------------------------------

struct Node {
    name: String,
    attrs: Vec<(String, String)>,
    start: usize,
    end: usize,
    parent: usize,
    children: Vec<usize>,
    text: Vec<(usize, usize)>,
}

fn scan(src: &str) -> Option<Vec<Node>> {
    let b = src.as_bytes();
    let mut nodes = vec![Node {
        name: String::new(),
        attrs: vec![],
        start: 0,
        end: b.len(),
        parent: 0,
        children: vec![],
        text: vec![],
    }];
    let mut cur = 0usize;
    let mut depth = 0usize;
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'<' {
            let s = i;
            while i < b.len() && b[i] != b'<' {
                i += 1;
            }
            nodes[cur].text.push((s, i));
            continue;
        }
        let rest = &src[i..];
        if rest.starts_with("<!--") {
            i += rest.find("-->").map(|p| p + 3).unwrap_or(rest.len());
        } else if rest.starts_with("<![CDATA[") {
            let e = rest.find("]]>").map(|p| p + 3).unwrap_or(rest.len());
            nodes[cur]
                .text
                .push((i + 9, (i + e).saturating_sub(3).max(i + 9)));
            i += e;
        } else if rest.starts_with("<?") || rest.starts_with("<!") {
            i += rest.find('>').map(|p| p + 1).unwrap_or(rest.len());
        } else if let Some(close) = rest.strip_prefix("</") {
            let end = close.find('>')?;
            let name = close[..end].trim();
            // pop to the matching open element; ignore stray end tags
            let mut k = cur;
            while k != 0 && nodes[k].name != name {
                k = nodes[k].parent;
            }
            if k != 0 {
                let mut x = cur;
                loop {
                    nodes[x].end = i + 2 + end + 1;
                    if x == k {
                        break;
                    }
                    x = nodes[x].parent;
                }
                depth = depth.saturating_sub(
                    1 + {
                        let mut d = 0;
                        let mut y = cur;
                        while y != k {
                            y = nodes[y].parent;
                            d += 1;
                        }
                        d
                    },
                );
                cur = nodes[k].parent;
            }
            i += 2 + end + 1;
        } else {
            // start tag: find the closing '>' outside quotes
            let mut j = i + 1;
            let mut q = None::<u8>;
            while j < b.len() {
                match (q, b[j]) {
                    (Some(qq), c) if c == qq => q = None,
                    (Some(_), _) => {}
                    (None, b'"' | b'\'') => q = Some(b[j]),
                    (None, b'>') => break,
                    _ => {}
                }
                j += 1;
            }
            if j >= b.len() {
                return None;
            }
            let selfclose = b[j - 1] == b'/';
            let inner = &src[i + 1..if selfclose { j - 1 } else { j }];
            let name_end = inner
                .find(|c: char| c.is_whitespace())
                .unwrap_or(inner.len());
            let name = inner[..name_end].to_string();
            let attrs = parse_attrs(&inner[name_end..]);
            if nodes.len() >= MAX_NODES || depth >= MAX_DEPTH {
                return None;
            }
            let id = nodes.len();
            nodes.push(Node {
                name,
                attrs,
                start: i,
                end: j + 1,
                parent: cur,
                children: vec![],
                text: vec![],
            });
            nodes[cur].children.push(id);
            if !selfclose {
                cur = id;
                depth += 1;
            }
            i = j + 1;
        }
    }
    Some(nodes)
}

fn parse_attrs(s: &str) -> Vec<(String, String)> {
    let b = s.as_bytes();
    let (mut out, mut i) = (Vec::new(), 0);
    while i < b.len() {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let s0 = i;
        while i < b.len() && b[i] != b'=' && !b[i].is_ascii_whitespace() {
            i += 1;
        }
        let name = &s[s0..i];
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if name.is_empty() {
            break;
        }
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            let v0;
            if i < b.len() && matches!(b[i], b'"' | b'\'') {
                let q = b[i];
                i += 1;
                v0 = i;
                while i < b.len() && b[i] != q {
                    i += 1;
                }
                out.push((name.to_string(), s[v0..i].to_string()));
                i += 1;
            } else {
                v0 = i;
                while i < b.len() && !b[i].is_ascii_whitespace() {
                    i += 1;
                }
                out.push((name.to_string(), s[v0..i].to_string()));
            }
        } else {
            out.push((name.to_string(), String::new()));
        }
    }
    out
}

fn text_of(src: &str, n: &Node) -> String {
    n.text.iter().map(|&(a, b)| &src[a..b]).collect()
}

fn step_matches(src: &str, nodes: &[Node], id: usize, step: &Step, pos_among: usize) -> bool {
    let n = &nodes[id];
    if step.name.as_deref().is_some_and(|w| w != n.name) {
        return false;
    }
    step.preds.iter().all(|p| match p {
        Pred::Attr(a) => n.attrs.iter().any(|(k, _)| k == a),
        Pred::AttrEq(a, v) => n.attrs.iter().any(|(k, x)| k == a && x == v),
        Pred::AttrContains(a, v) => n
            .attrs
            .iter()
            .any(|(k, x)| k == a && x.contains(v.as_str())),
        Pred::TextEq(v) => text_of(src, n).trim() == v,
        Pred::TextContains(v) => text_of(src, n).contains(v.as_str()),
        Pred::NameEq(v) => &n.name == v,
        Pred::Index(i) => pos_among == *i,
    })
}

fn descendants(nodes: &[Node], id: usize, out: &mut Vec<usize>) {
    for &c in &nodes[id].children {
        out.push(c);
        descendants(nodes, c, out);
    }
}

/// Remove the elements selected by `specs`. Returns the input untouched when nothing matches, the
/// body is too large, or it is too deeply nested / malformed to scan.
pub fn apply_xmlprune<'a>(body: &'a [u8], specs: &[&XmlPrune]) -> Cow<'a, [u8]> {
    if body.len() > MAX_XML_BYTES || specs.is_empty() {
        return Cow::Borrowed(body);
    }
    let Ok(src) = std::str::from_utf8(body) else {
        return Cow::Borrowed(body);
    };
    let Some(nodes) = scan(src) else {
        return Cow::Borrowed(body);
    };
    let mut cut: Vec<(usize, usize)> = Vec::new();
    for spec in specs {
        let mut set = vec![0usize];
        for step in &spec.steps {
            let mut next = Vec::new();
            for &n in &set {
                let cands: Vec<usize> = if step.descendant {
                    let mut v = Vec::new();
                    descendants(&nodes, n, &mut v);
                    v
                } else {
                    nodes[n].children.clone()
                };
                for c in cands {
                    // 1-based position among same-parent siblings that pass the name test
                    let par = &nodes[nodes[c].parent];
                    let pos = par
                        .children
                        .iter()
                        .filter(|&&s| step.name.as_deref().is_none_or(|w| nodes[s].name == w))
                        .position(|&s| s == c)
                        .map_or(0, |p| p + 1);
                    if step_matches(src, &nodes, c, step, pos) && !next.contains(&c) {
                        next.push(c);
                    }
                }
            }
            set = next;
            if set.is_empty() {
                break;
            }
        }
        cut.extend(set.into_iter().map(|n| (nodes[n].start, nodes[n].end)));
    }
    if cut.is_empty() {
        return Cow::Borrowed(body);
    }
    cut.sort_unstable();
    let mut out = String::with_capacity(src.len());
    let mut at = 0;
    for (s, e) in cut {
        if s >= at {
            out.push_str(&src[at..s]);
            at = e;
        } else if e > at {
            at = e;
        }
    }
    out.push_str(&src[at.min(src.len())..]);
    Cow::Owned(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(x: &str, doc: &str) -> String {
        let p = XmlPrune::parse(x).unwrap();
        String::from_utf8(apply_xmlprune(doc.as_bytes(), &[&p]).into_owned()).unwrap()
    }

    #[test]
    fn xpath_subset() {
        let doc = r#"<?xml version="1.0"?><VAST><Ad id="1"><X/></Ad><Ad id="2" t="sponsor">z</Ad><Creative><Ad>q</Ad></Creative></VAST>"#;
        assert_eq!(
            run("//Ad[@id='1']", doc),
            r#"<?xml version="1.0"?><VAST><Ad id="2" t="sponsor">z</Ad><Creative><Ad>q</Ad></Creative></VAST>"#
        );
        assert_eq!(
            run("/VAST/Ad", doc),
            r#"<?xml version="1.0"?><VAST><Creative><Ad>q</Ad></Creative></VAST>"#
        );
        assert_eq!(
            run("//Ad[contains(@t,'spons')]", doc)
                .matches("<Ad")
                .count(),
            2
        );
        assert_eq!(
            run("//*[name()='Creative']", doc),
            r#"<?xml version="1.0"?><VAST><Ad id="1"><X/></Ad><Ad id="2" t="sponsor">z</Ad></VAST>"#
        );
        assert_eq!(
            run("xpath(//Ad[text()='q'])", doc).matches("<Ad").count(),
            2
        );
        assert_eq!(run("//Ad[2]", doc).matches("<Ad").count(), 2);
        assert_eq!(run("//Nope", doc), doc);
    }

    #[test]
    fn tolerant_and_bounded() {
        let p = XmlPrune::parse("//a").unwrap();
        for bad in [
            "",
            "<",
            "<a",
            "</a></a>",
            "<a><b></a>",
            "\u{0}<<>>",
            "<a x='>",
        ] {
            let _ = apply_xmlprune(bad.as_bytes(), &[&p]);
        }
        assert_eq!(run("//b", "<a><b>1</a>"), "<a>");
        assert!(matches!(
            apply_xmlprune(&[0xff, 0xfe], &[&p]),
            Cow::Borrowed(_)
        ));
        let deep = "<a>".repeat(MAX_DEPTH + 10);
        assert!(matches!(
            apply_xmlprune(deep.as_bytes(), &[&p]),
            Cow::Borrowed(_)
        ));
        for bad in ["", "//a[", "//a[foo()]", "//a/@b", "//a[0]"] {
            assert!(XmlPrune::parse(bad).is_err(), "{bad}");
        }
    }
}

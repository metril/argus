//! Content-Security-Policy parsing and the minimal additions our injected tags need.
//!
//! Policies are parsed into ordered directives (first occurrence wins, like browsers). For one
//! policy, [`adapt`] adds only what is required for (a) our same-origin external script, (b) our
//! inline `<style>`, (c) the `/__adblock__/` beacon and (d) a Trusted Types policy name. It never
//! removes a directive or source, and adds at most one source per need.
//!
//! The nonce pitfall: a `'nonce-…'` or hash in a source list makes browsers ignore
//! `'unsafe-inline'` in that list (so does `'strict-dynamic'` for scripts). Adding our nonce to a
//! list that relies on `'unsafe-inline'` would therefore break the page's own inline code; in that
//! case we add a host-source for `<origin>/__adblock__/` instead.

/// Path prefix of everything the proxy serves itself.
pub const INTERNAL_PREFIX: &str = "/__adblock__/";
/// Name of the Trusted Types policy created by `boot.js`.
pub const TT_POLICY: &str = "adblock-proxy";

/// Origin of the protected page (and so of our same-origin resources).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageOrigin {
    pub scheme: String,
    /// Lowercase host as written in a URL (IPv6 literals keep their brackets).
    pub host: String,
    pub port: u16,
}

impl PageOrigin {
    pub fn new(scheme: &str, host: &str, port: u16) -> Self {
        Self {
            scheme: scheme.to_ascii_lowercase(),
            host: host.to_ascii_lowercase(),
            port,
        }
    }

    fn default_port(&self) -> bool {
        scheme_default_port(&self.scheme) == Some(self.port)
    }

    /// `scheme://host[:port]`
    pub fn serialize(&self) -> String {
        if self.default_port() {
            format!("{}://{}", self.scheme, self.host)
        } else {
            format!("{}://{}:{}", self.scheme, self.host, self.port)
        }
    }
}

fn scheme_default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        _ => None,
    }
}

/// What the caller wants the policy to allow.
#[derive(Debug, Clone, Copy, Default)]
pub struct Needs {
    /// A parser-inserted external `<script src>` under [`INTERNAL_PREFIX`].
    pub script: bool,
    /// An inline `<style>` element.
    pub style: bool,
    /// `fetch()` to `/__adblock__/` from the page.
    pub connect: bool,
}

/// Header policies are fully adapted; `<meta>` policies only get the runtime allowances, because
/// our tags sit before any `<meta>` in the document and meta policies apply to what follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKind {
    Header,
    Meta,
}

/// A parsed policy: ordered `(name, values)` pairs, duplicates dropped (first wins).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Policy {
    directives: Vec<(String, Vec<String>)>,
}

impl Policy {
    pub fn parse(text: &str) -> Self {
        let mut directives: Vec<(String, Vec<String>)> = Vec::new();
        for part in text.split(';') {
            let mut toks = part.split_ascii_whitespace();
            let Some(name) = toks.next() else { continue };
            let name = name.to_ascii_lowercase();
            if directives.iter().any(|(n, _)| *n == name) {
                continue;
            }
            directives.push((name, toks.map(str::to_string).collect()));
        }
        Self { directives }
    }

    pub fn serialize(&self) -> String {
        self.directives
            .iter()
            .map(|(n, v)| {
                if v.is_empty() {
                    n.clone()
                } else {
                    format!("{n} {}", v.join(" "))
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn get(&self, name: &str) -> Option<&Vec<String>> {
        self.directives
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
    }

    fn get_mut(&mut self, name: &str) -> Option<&mut Vec<String>> {
        self.directives
            .iter_mut()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
    }

    /// Name of the directive that governs a request kind, following the fallback chain.
    fn effective(&self, chain: &[&'static str]) -> Option<&'static str> {
        chain.iter().copied().find(|d| self.get(d).is_some())
    }

    /// Whether `sandbox` is present and withholds `allow-scripts`.
    pub fn sandbox_blocks_scripts(&self) -> bool {
        self.get("sandbox")
            .is_some_and(|v| !v.iter().any(|t| t.eq_ignore_ascii_case("allow-scripts")))
    }

    /// Whether `sandbox` is present and withholds `allow-same-origin` (opaque origin).
    pub fn sandbox_opaque_origin(&self) -> bool {
        self.get("sandbox").is_some_and(|v| {
            !v.iter()
                .any(|t| t.eq_ignore_ascii_case("allow-same-origin"))
        })
    }
}

const SCRIPT_ELEM: &[&str] = &["script-src-elem", "script-src", "default-src"];
const STYLE_ELEM: &[&str] = &["style-src-elem", "style-src", "default-src"];
const CONNECT: &[&str] = &["connect-src", "default-src"];

fn is_kw(tok: &str, kw: &str) -> bool {
    tok.len() == kw.len() + 2
        && tok.starts_with('\'')
        && tok.ends_with('\'')
        && tok[1..tok.len() - 1].eq_ignore_ascii_case(kw)
}

fn is_nonce_or_hash(tok: &str) -> bool {
    let t = tok.to_ascii_lowercase();
    t.starts_with("'nonce-")
        || t.starts_with("'sha256-")
        || t.starts_with("'sha384-")
        || t.starts_with("'sha512-")
}

/// Whether a source list permits inline code of this kind.
fn allows_inline(list: &[String], script: bool, nonce: Option<&str>) -> bool {
    if let Some(n) = nonce {
        let want = format!("'nonce-{n}'");
        if list.contains(&want) {
            return true;
        }
    }
    let blockers = list.iter().any(|t| is_nonce_or_hash(t))
        || (script && list.iter().any(|t| is_kw(t, "strict-dynamic")));
    list.iter().any(|t| is_kw(t, "unsafe-inline")) && !blockers
}

/// Whether a source list permits a URL on the page's own origin and `path` without a nonce.
fn allows_url(list: &[String], origin: &PageOrigin, path: &str, script: bool) -> bool {
    if script && list.iter().any(|t| is_kw(t, "strict-dynamic")) {
        return false; // host/scheme/'self' are ignored; only nonce/hash count
    }
    list.iter().any(|t| source_matches(t, origin, path))
}

fn source_matches(tok: &str, origin: &PageOrigin, path: &str) -> bool {
    if tok.starts_with('\'') {
        return is_kw(tok, "self");
    }
    if tok == "*" {
        return matches!(origin.scheme.as_str(), "http" | "https" | "ws" | "wss");
    }
    // scheme-source: `https:`
    if let Some(s) = tok.strip_suffix(':') {
        if s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
            && !s.is_empty()
        {
            let s = s.to_ascii_lowercase();
            return s == origin.scheme
                || (s == "http" && origin.scheme == "https")
                || (s == "ws"
                    && matches!(origin.scheme.as_str(), "ws" | "wss" | "http" | "https"))
                || (s == "wss" && matches!(origin.scheme.as_str(), "wss" | "https"));
        }
    }
    // host-source: [scheme://]host[:port][/path]
    let (scheme, rest) = match tok.split_once("://") {
        Some((s, r)) => (Some(s.to_ascii_lowercase()), r),
        None => (None, tok),
    };
    if let Some(s) = &scheme {
        let ok = *s == origin.scheme || (s == "http" && origin.scheme == "https");
        if !ok {
            return false;
        }
    }
    let (authority, src_path) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(&rest[i..])),
        None => (rest, None),
    };
    let (host, port) = split_host_port(authority);
    let host = host.to_ascii_lowercase();
    let host_ok = if host == "*" {
        true
    } else if let Some(suffix) = host.strip_prefix("*.") {
        origin.host.len() > suffix.len() + 1
            && origin.host.ends_with(suffix)
            && origin.host.as_bytes()[origin.host.len() - suffix.len() - 1] == b'.'
    } else {
        host == origin.host
    };
    if !host_ok {
        return false;
    }
    let port_ok = match port {
        None => origin.default_port(),
        Some("*") => true,
        Some(p) => p.parse::<u16>().is_ok_and(|p| p == origin.port),
    };
    // A source without a port matches the scheme's default port only.
    if !port_ok {
        return false;
    }
    match src_path {
        None => true,
        Some(sp) => {
            if sp.ends_with('/') {
                path.starts_with(sp)
            } else {
                path == sp
            }
        }
    }
}

fn split_host_port(authority: &str) -> (&str, Option<&str>) {
    if authority.starts_with('[') {
        if let Some(end) = authority.find(']') {
            let host = &authority[..=end];
            let port = authority[end + 1..].strip_prefix(':');
            return (host, port);
        }
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    }
}

/// Result of [`adapt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adapted {
    /// The (possibly modified) policy text.
    pub text: String,
    pub changed: bool,
    /// `sandbox` forbids scripts: do not inject any.
    pub blocks_scripts: bool,
    /// `sandbox` without `allow-same-origin`: the document has an opaque origin, so the beacon
    /// cannot be authenticated as same-origin.
    pub opaque_origin: bool,
}

/// Add what `needs` requires to one policy. `nonce` is the base64 nonce on our tags.
pub fn adapt(
    policy: &str,
    kind: PolicyKind,
    origin: &PageOrigin,
    nonce: &str,
    needs: Needs,
) -> Adapted {
    let mut p = Policy::parse(policy);
    let before = p.clone();
    let blocks_scripts = kind == PolicyKind::Header && p.sandbox_blocks_scripts();
    let opaque_origin = kind == PolicyKind::Header && p.sandbox_opaque_origin();
    let our_path = format!("{INTERNAL_PREFIX}boot.js");
    let nonce_tok = format!("'nonce-{nonce}'");
    let host_tok = format!("{}{INTERNAL_PREFIX}", origin.serialize());

    if needs.script && kind == PolicyKind::Header && !blocks_scripts {
        if let Some(name) = p.effective(SCRIPT_ELEM) {
            let list = p.get(name).cloned().unwrap_or_default();
            if !allows_url(&list, origin, &our_path, true) {
                let unsafe_inline_relied = list.iter().any(|t| is_kw(t, "unsafe-inline"))
                    && !list.iter().any(|t| is_nonce_or_hash(t))
                    && !list.iter().any(|t| is_kw(t, "strict-dynamic"));
                let add = if unsafe_inline_relied {
                    &host_tok
                } else {
                    &nonce_tok
                };
                p.get_mut(name).expect("exists").push(add.clone());
            }
        }
        // Trusted Types: name our policy if the directive restricts names.
        let tt_required = p
            .get("require-trusted-types-for")
            .is_some_and(|v| v.iter().any(|t| is_kw(t, "script")));
        if tt_required {
            if let Some(v) = p.get_mut("trusted-types") {
                let restricts = !v.is_empty()
                    && !v
                        .iter()
                        .any(|t| is_kw(t, "none") || t == "*" || t == TT_POLICY);
                if restricts {
                    v.push(TT_POLICY.to_string());
                }
            }
        }
    }

    if needs.style && kind == PolicyKind::Header {
        if let Some(name) = p.effective(STYLE_ELEM) {
            let list = p.get(name).cloned().unwrap_or_default();
            if !allows_inline(&list, false, Some(nonce)) {
                // No `'unsafe-inline'` to preserve here (it would have allowed us), or it is
                // already ignored because of other nonces/hashes: our nonce is safe to add.
                p.get_mut(name).expect("exists").push(nonce_tok.clone());
            }
        }
    }

    if needs.connect && !blocks_scripts {
        let beacon = format!("{INTERNAL_PREFIX}cc");
        if let Some(name) = p.effective(CONNECT) {
            let list = p.get(name).cloned().unwrap_or_default();
            if !allows_url(&list, origin, &beacon, false) {
                p.get_mut(name).expect("exists").push(host_tok);
            }
        }
    }

    let changed = p != before;
    Adapted {
        text: if changed {
            p.serialize()
        } else {
            policy.to_string()
        },
        changed,
        blocks_scripts,
        opaque_origin,
    }
}

/// `(blocks_scripts, opaque_origin)` over all policies in a set of header values.
pub fn sandbox_facts(values: &[&str]) -> (bool, bool) {
    let mut f = (false, false);
    for v in values {
        for pol in split_policies(v) {
            let p = Policy::parse(pol);
            f.0 |= p.sandbox_blocks_scripts();
            f.1 |= p.sandbox_opaque_origin();
        }
    }
    f
}

/// Adapt every enforced policy in a set of `Content-Security-Policy` header values (each value may
/// hold several comma-separated policies). Returns the new values (same count and order, `None`
/// where unchanged) plus the combined facts.
pub fn adapt_headers(
    values: &[&str],
    origin: &PageOrigin,
    nonce: &str,
    needs: Needs,
) -> (Vec<Option<String>>, bool, bool) {
    let mut blocks = false;
    let mut opaque = false;
    // Sandbox facts first: they decide whether script needs apply to the other policies.
    for v in values {
        for pol in split_policies(v) {
            let parsed = Policy::parse(pol);
            blocks |= parsed.sandbox_blocks_scripts();
            opaque |= parsed.sandbox_opaque_origin();
        }
    }
    let mut needs = needs;
    if blocks {
        needs.script = false;
        needs.connect = false;
    }
    let out = values
        .iter()
        .map(|v| {
            let mut any = false;
            let adapted: Vec<String> = split_policies(v)
                .map(|pol| {
                    let a = adapt(pol, PolicyKind::Header, origin, nonce, needs);
                    any |= a.changed;
                    a.text
                })
                .collect();
            any.then(|| adapted.join(", "))
        })
        .collect();
    (out, blocks, opaque)
}

fn split_policies(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> PageOrigin {
        PageOrigin::new("https", "example.test", 443)
    }

    fn run(policy: &str, needs: Needs) -> Adapted {
        adapt(policy, PolicyKind::Header, &origin(), "N0nce", needs)
    }

    const ALL: Needs = Needs {
        script: true,
        style: true,
        connect: true,
    };

    #[test]
    fn table() {
        let cases: &[(&str, &str)] = &[
            // 'self' already allows our same-origin script/beacon; style needs a nonce.
            ("script-src 'self'", "script-src 'self'"),
            // nonce-only policy: add our nonce to script-src.
            (
                "script-src 'nonce-abc'",
                "script-src 'nonce-abc' 'nonce-N0nce'",
            ),
            // default-src fallback is used for script, style and connect.
            (
                "default-src 'none'",
                "default-src 'none' 'nonce-N0nce' https://example.test/__adblock__/",
            ),
            // script-src-elem wins over script-src.
            (
                "script-src 'self'; script-src-elem https://cdn.test",
                "script-src 'self'; script-src-elem https://cdn.test 'nonce-N0nce'",
            ),
            // unsafe-inline pitfall: no nonce, host-source instead.
            (
                "script-src https://cdn.test 'unsafe-inline'",
                "script-src https://cdn.test 'unsafe-inline' https://example.test/__adblock__/",
            ),
            // 'self' + unsafe-inline: nothing to add.
            (
                "script-src 'self' 'unsafe-inline'",
                "script-src 'self' 'unsafe-inline'",
            ),
            // strict-dynamic ignores 'self': nonce required.
            (
                "script-src 'self' 'strict-dynamic' 'nonce-abc'",
                "script-src 'self' 'strict-dynamic' 'nonce-abc' 'nonce-N0nce'",
            ),
            // style-src with unsafe-inline and no nonce: inline allowed already.
            ("style-src 'unsafe-inline'", "style-src 'unsafe-inline'"),
            // style-src with hash: unsafe-inline is already ignored, add nonce.
            (
                "style-src 'unsafe-inline' 'sha256-xyz'",
                "style-src 'unsafe-inline' 'sha256-xyz' 'nonce-N0nce'",
            ),
            // connect-src that does not allow us.
            (
                "connect-src https://api.test",
                "connect-src https://api.test https://example.test/__adblock__/",
            ),
            ("connect-src 'self'", "connect-src 'self'"),
            // wildcard host and scheme sources.
            ("script-src https:", "script-src https:"),
            ("script-src *.test", "script-src *.test"),
            ("script-src example.test", "script-src example.test"),
            (
                "script-src example.test:8443",
                "script-src example.test:8443 'nonce-N0nce'",
            ),
            // unrelated directives are untouched.
            (
                "img-src 'none'; frame-ancestors 'self'",
                "img-src 'none'; frame-ancestors 'self'",
            ),
            // duplicate directives: first wins, later ones dropped.
            (
                "script-src 'self'; script-src 'none'",
                "script-src 'self'; script-src 'none'",
            ),
        ];
        for (input, want) in cases {
            let got = run(input, ALL);
            // normalise: the table lists the expected serialization of changed policies only
            let want_text = Policy::parse(want).serialize();
            assert_eq!(
                Policy::parse(&got.text).serialize(),
                want_text,
                "input: {input}"
            );
        }
    }

    #[test]
    fn style_nonce_added_without_unsafe_inline() {
        let a = run(
            "style-src 'self'",
            Needs {
                style: true,
                ..Needs::default()
            },
        );
        assert_eq!(a.text, "style-src 'self' 'nonce-N0nce'");
    }

    #[test]
    fn unsafe_inline_never_gets_a_nonce() {
        for p in [
            "script-src https://cdn.test 'unsafe-inline'",
            "default-src https://cdn.test 'unsafe-inline'",
            "style-src 'unsafe-inline'",
        ] {
            let a = run(p, ALL);
            assert!(!a.text.contains("nonce-"), "{p} -> {}", a.text);
        }
    }

    #[test]
    fn sandbox_without_allow_scripts_blocks_script() {
        let a = run("sandbox allow-forms; script-src 'none'", ALL);
        assert!(a.blocks_scripts);
        assert!(a.opaque_origin);
        assert!(
            !a.text.contains("nonce-N0nce 'nonce"),
            "no script nonce: {}",
            a.text
        );
        let a = run("sandbox allow-scripts allow-same-origin", ALL);
        assert!(!a.blocks_scripts && !a.opaque_origin);
    }

    #[test]
    fn trusted_types_name_added_only_when_restricting() {
        let a = run(
            "require-trusted-types-for 'script'; trusted-types foo bar; script-src 'self'",
            ALL,
        );
        assert!(
            a.text.contains("trusted-types foo bar adblock-proxy"),
            "{}",
            a.text
        );
        for p in [
            "require-trusted-types-for 'script'; trusted-types *",
            "require-trusted-types-for 'script'; trusted-types 'none'",
            "require-trusted-types-for 'script'",
            "trusted-types foo",
        ] {
            let a = run(p, ALL);
            assert!(!a.text.contains("adblock-proxy"), "{p}: {}", a.text);
        }
    }

    #[test]
    fn multiple_policies_each_adapted() {
        let (out, blocks, _) = adapt_headers(
            &[
                "script-src 'self'",
                "script-src 'nonce-abc', default-src 'self'",
            ],
            &origin(),
            "N0nce",
            Needs {
                script: true,
                ..Needs::default()
            },
        );
        assert!(!blocks);
        assert_eq!(out[0], None, "first policy already allows us");
        assert_eq!(
            out[1].as_deref(),
            Some("script-src 'nonce-abc' 'nonce-N0nce', default-src 'self'")
        );
    }

    #[test]
    fn sandbox_in_any_policy_disables_script_for_all() {
        let (out, blocks, _) = adapt_headers(
            &["script-src 'nonce-a'", "sandbox"],
            &origin(),
            "N0nce",
            Needs {
                script: true,
                ..Needs::default()
            },
        );
        assert!(blocks);
        assert_eq!(out, vec![None, None]);
    }

    #[test]
    fn meta_only_gets_runtime_allowances() {
        let a = adapt(
            "script-src 'none'; connect-src https://api.test",
            PolicyKind::Meta,
            &origin(),
            "N0nce",
            ALL,
        );
        assert_eq!(
            a.text,
            "script-src 'none'; connect-src https://api.test https://example.test/__adblock__/"
        );
    }

    #[test]
    fn no_policy_means_no_change() {
        let a = run("", ALL);
        assert!(!a.changed);
        let a = run("frame-ancestors 'none'", ALL);
        assert!(!a.changed);
    }

    #[test]
    fn nonstandard_port_origin() {
        let o = PageOrigin::new("https", "example.test", 8443);
        let a = adapt("script-src 'self'", PolicyKind::Header, &o, "N", ALL);
        assert!(!a.changed);
        let a = adapt("script-src example.test", PolicyKind::Header, &o, "N", ALL);
        assert!(
            a.changed,
            "host-source without port means default port only"
        );
        assert_eq!(o.serialize(), "https://example.test:8443");
    }

    #[test]
    fn path_sources() {
        let o = origin();
        assert!(source_matches(
            "https://example.test/__adblock__/",
            &o,
            "/__adblock__/boot.js"
        ));
        assert!(!source_matches(
            "https://example.test/js/",
            &o,
            "/__adblock__/boot.js"
        ));
        assert!(source_matches(
            "example.test/__adblock__/boot.js",
            &o,
            "/__adblock__/boot.js"
        ));
    }
}

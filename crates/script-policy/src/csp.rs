//! Content-Security-Policy and Permissions-Policy generation.
//!
//! The generated policy is a *separate* `Content-Security-Policy` header: browsers intersect
//! multiple policies, so it can only restrict, never relax, the site's own policy.

use crate::caps::{CapSet, Capability};
use crate::compile::PagePolicy;
use crate::scope::{is_ip, Scheme, Scope};

/// One CSP directive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CspDirective {
    pub name: &'static str,
    pub sources: Vec<String>,
}

impl CspDirective {
    fn new(name: &'static str, sources: Vec<String>) -> Self {
        // `'none'` is only valid on its own.
        let sources = if sources.is_empty() {
            vec!["'none'".to_string()]
        } else {
            sources
        };
        CspDirective { name, sources }
    }
    pub fn render(&self) -> String {
        format!("{} {}", self.name, self.sources.join(" "))
    }
}

/// Join directives into a header value.
pub fn render_header(d: &[CspDirective]) -> String {
    d.iter()
        .map(CspDirective::render)
        .collect::<Vec<_>>()
        .join("; ")
}

/// What the proxy injects into the page and therefore must stay allowed.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProxyInject<'a> {
    /// Nonce of the injected `<script>`/`<style>` elements.
    pub nonce: Option<&'a str>,
    /// Path prefix of the proxy's own resources, e.g. `/__adblock__/`.
    pub path: Option<&'a str>,
}

/// Directives plus the intents CSP could not express for this page.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CspOutput {
    pub directives: Vec<CspDirective>,
    /// Human-readable list of denials this CSP does not enforce (see docs/SCRIPT-POLICY.md).
    pub notes: Vec<String>,
}

enum SrcList {
    /// No restriction from this policy: the directive is omitted (or widened to `*`).
    Unrestricted,
    List(Vec<String>),
}

const SELF: &str = "'self'";

impl<'a> PagePolicy<'a> {
    /// Directives to add as an extra `Content-Security-Policy` header. Empty when the page is
    /// unrestricted or the master switch is off.
    pub fn csp(&self, proxy: Option<&ProxyInject<'_>>) -> Vec<CspDirective> {
        self.csp_with_notes(proxy).directives
    }

    /// The header value, or `None` when there is nothing to add.
    pub fn csp_header(&self, proxy: Option<&ProxyInject<'_>>) -> Option<String> {
        let d = self.csp(proxy);
        (!d.is_empty()).then(|| render_header(&d))
    }

    /// Like [`PagePolicy::csp`], also reporting what CSP cannot express here.
    pub fn csp_with_notes(&self, proxy: Option<&ProxyInject<'_>>) -> CspOutput {
        let mut out = CspOutput::default();
        if !self.active {
            return out;
        }
        let px = proxy.copied().unwrap_or_default();
        let path_tok = px.path.map(|p| self.path_source(p));
        let nonce_tok = px.nonce.map(|n| format!("'nonce-{n}'"));
        let notes = &mut out.notes;

        let inline_script = self.profile.page.contains(Capability::InlineScript);
        let eval = self.profile.page.contains(Capability::Eval);
        let wasm = self.profile.page.contains(Capability::Wasm);
        let inline_style = self.profile.page.contains(Capability::InlineStyle);

        let script = self.source_list(Capability::Script, notes);
        let script_restricted = matches!(script, SrcList::List(_));
        let mut ds = Vec::new();

        // script-src (+ script-src-attr)
        if script_restricted || !inline_script || !eval {
            let mut t = match &script {
                SrcList::List(l) => l.clone(),
                SrcList::Unrestricted => vec!["*".into(), "data:".into(), "blob:".into()],
            };
            if script_restricted && !t.iter().any(|s| s == SELF) {
                t.extend(path_tok.clone());
            }
            if inline_script {
                t.push("'unsafe-inline'".into());
            } else {
                t.extend(nonce_tok.clone());
            }
            if eval {
                t.push("'unsafe-eval'".into());
            } else if wasm {
                t.push("'wasm-unsafe-eval'".into());
            }
            ds.push(CspDirective::new("script-src", t));
            if !inline_script {
                ds.push(CspDirective::new("script-src-attr", vec![]));
            }
        }

        if eval && !wasm {
            notes.push(
                "wasm denied but eval allowed: 'unsafe-eval' also permits WebAssembly".into(),
            );
        }

        // worker-src: explicit whenever it differs from what script-src would imply.
        let worker = self.source_list(Capability::Worker, notes);
        match (&worker, &script) {
            (SrcList::List(l), _) => {
                let mut t = l.clone();
                if !t.is_empty() {
                    t.push("blob:".into());
                }
                ds.push(CspDirective::new("worker-src", t));
            }
            (SrcList::Unrestricted, SrcList::List(_)) => ds.push(CspDirective::new(
                "worker-src",
                vec!["*".into(), "data:".into(), "blob:".into()],
            )),
            _ => {}
        }

        // style-src
        let style = self.source_list(Capability::Style, notes);
        if matches!(style, SrcList::List(_)) || !inline_style {
            let restricted = matches!(style, SrcList::List(_));
            let mut t = match style {
                SrcList::List(l) => l,
                SrcList::Unrestricted => vec!["*".into(), "data:".into(), "blob:".into()],
            };
            if restricted && !t.iter().any(|s| s == SELF) {
                t.extend(path_tok.clone());
            }
            if inline_style {
                t.push("'unsafe-inline'".into());
            } else {
                t.extend(nonce_tok.clone());
            }
            ds.push(CspDirective::new("style-src", t));
        }

        // Plain source-list directives: (capability, directive, tokens that ride along when any
        // source is allowed, add the proxy path source when 'self' is not allowed).
        let simple: [(Capability, &'static str, &[&str], bool); 7] = [
            (Capability::Image, "img-src", &["data:", "blob:"], false),
            (Capability::Font, "font-src", &["data:"], false),
            (Capability::Media, "media-src", &["blob:", "data:"], false),
            (Capability::Object, "object-src", &[], false),
            (Capability::Frame, "frame-src", &[], false),
            (
                Capability::Connect,
                "connect-src",
                &["data:", "blob:"],
                true,
            ),
            (Capability::FormAction, "form-action", &[], false),
        ];
        for (cap, name, extra, with_path) in simple {
            if let SrcList::List(mut t) = self.source_list(cap, notes) {
                let any_allowed = !t.is_empty();
                if with_path && !t.iter().any(|s| s == SELF) {
                    t.extend(path_tok.clone());
                }
                if any_allowed {
                    t.extend(extra.iter().map(|s| s.to_string()));
                }
                ds.push(CspDirective::new(name, t));
            }
        }

        if !self.profile.first_party.contains(Capability::Ping)
            || !self.profile.third_party.contains(Capability::Ping)
            || !self.rules_for(Capability::Ping).is_empty()
        {
            notes.push(
                "ping: not a CSP concept; enforced by stripping `ping` attributes and blocking Ping-To requests (beacons are governed by connect-src)".into(),
            );
        }
        out.directives = ds;
        out
    }

    /// `Permissions-Policy` header value for denied browser features, if any.
    pub fn permissions_policy(&self) -> Option<String> {
        if !self.active {
            return None;
        }
        let denied: Vec<String> = CapSet::PAGE_LEVEL
            .iter()
            .filter_map(|c| c.permissions_feature().map(|f| (c, f)))
            .filter(|(c, _)| !self.profile.page.contains(*c))
            .map(|(_, f)| format!("{f}=()"))
            .collect();
        (!denied.is_empty()).then(|| denied.join(", "))
    }

    /// `scheme://host[:port]/path/` of a proxy resource prefix on this page's origin.
    fn path_source(&self, path: &str) -> String {
        let scheme = self.scheme.unwrap_or(Scheme::Https);
        let port = match self.port {
            Some(p) if p != scheme.default_port() => format!(":{p}"),
            _ => String::new(),
        };
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        format!("{}://{}{}{}", scheme.as_str(), self.host, port, path)
    }

    /// Resolve the sources allowed for a source-keyed capability.
    fn source_list(&self, cap: Capability, notes: &mut Vec<String>) -> SrcList {
        struct Cand {
            rank: i16,
            scope: Scope,
        }
        let page_site = Scope::Site(self.site.to_string());
        let rules = self.rules_for(cap);
        let mut cands: Vec<Cand> = Vec::new();
        if self.profile.first_party.contains(cap) {
            cands.push(Cand {
                rank: -1,
                scope: page_site.clone(),
            });
        }
        if self.profile.third_party.contains(cap) {
            cands.push(Cand {
                rank: -1,
                scope: Scope::Global,
            });
        }
        let mut denies = Vec::new();
        for (rk, r) in &rules {
            if r.deny {
                denies.push((*rk as i16, &r.source));
            } else {
                cands.push(Cand {
                    rank: *rk as i16,
                    scope: r.source.clone(),
                });
            }
        }
        let survivors: Vec<&Cand> = cands
            .iter()
            .filter(|c| {
                !denies
                    .iter()
                    .any(|(dr, ds)| *dr > c.rank && ds.covers(&c.scope))
            })
            .collect();
        // Carve-outs CSP cannot express: a surviving broader allow with a narrower deny.
        for (dr, ds) in &denies {
            if survivors
                .iter()
                .any(|c| c.rank < *dr && c.scope != **ds && c.scope.covers(ds))
            {
                notes.push(format!(
                    "{}: deny of {ds} is a carve-out CSP cannot express (enforced by network hints only)",
                    cap.as_str()
                ));
            }
        }
        if survivors.iter().any(|c| c.scope == Scope::Global) {
            if !self.profile.first_party.contains(cap) {
                notes.push(format!(
                    "{}: allowed for third parties but denied for first party; CSP cannot express that",
                    cap.as_str()
                ));
            }
            return SrcList::Unrestricted;
        }
        let mut toks: Vec<String> = Vec::new();
        for c in &survivors {
            match &c.scope {
                Scope::Global => {}
                Scope::Site(s) => {
                    if *s == self.site {
                        toks.push(SELF.into());
                    }
                    toks.push(s.clone());
                    if s.contains('.') && !is_ip(s) {
                        toks.push(format!("*.{s}"));
                    }
                }
                Scope::Host(h) => toks.push(h.clone()),
                Scope::HostScheme(sc, h) => toks.push(format!("{}://{h}", sc.as_str())),
            }
        }
        toks.sort();
        toks.dedup();
        if let Some(i) = toks.iter().position(|t| t == SELF) {
            toks.remove(i);
            toks.insert(0, SELF.into());
        }
        SrcList::List(toks)
    }
}

//! Immutable per-profile script index for the per-document hot path.
//!
//! Built once from a profile's scripts, shared in an `Arc`, swapped wholesale on edits.
//! `candidates` buckets by exact host, by domain suffix (walking the host's label suffixes) and
//! an any-host bucket, then runs the path/regex checks on the few survivors only.

use crate::{
    matcher::{HostKey, Options, Rules, UrlParts},
    metadata::RunAt,
    script::Userscript,
};
use smallvec::SmallVec;
use std::collections::HashMap;

/// A script plus everything precompiled for matching.
#[derive(Debug)]
pub struct CompiledScript {
    /// Position in install order (stable sort key).
    pub order: u32,
    pub script: Userscript,
    rules: Rules,
    pub noframes: bool,
    pub run_at: RunAt,
}

impl CompiledScript {
    pub fn id(&self) -> &str {
        &self.script.id
    }
    /// Full URL rule check (excludes included).
    pub fn matches_url(&self, url: &str) -> bool {
        self.rules.is_match_url(url)
    }
}

/// Result of building: the index plus per-script pattern problems.
pub struct BuildReport {
    pub index: ScriptIndex,
    /// `(script id, message)` for each unparsable pattern or skipped script.
    pub problems: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub struct ScriptIndex {
    profile: String,
    scripts: Vec<CompiledScript>,
    exact: HashMap<Box<str>, Vec<u32>>,
    suffix: HashMap<Box<str>, Vec<u32>>,
    any: Vec<u32>,
}

/// Matched scripts for one document, in install order.
pub type Candidates<'a> = SmallVec<[&'a CompiledScript; 4]>;

impl ScriptIndex {
    /// Index the enabled, runnable scripts of `profile`. Disabled scripts and `context-menu`
    /// scripts (never auto-run) are left out.
    pub fn build(profile: &str, scripts: &[Userscript], opts: Options) -> BuildReport {
        let mut idx = ScriptIndex {
            profile: profile.to_string(),
            ..Default::default()
        };
        let mut problems = Vec::new();
        for s in scripts.iter().filter(|s| s.enabled) {
            if s.metadata.run_at == RunAt::ContextMenu {
                problems.push((
                    s.id.clone(),
                    "@run-at context-menu is unsupported; script skipped".into(),
                ));
                continue;
            }
            let (rules, errs) = Rules::compile(&s.metadata, opts);
            problems.extend(errs.into_iter().map(|e| (s.id.clone(), e)));
            let n = idx.scripts.len() as u32;
            for k in rules.host_keys() {
                match k {
                    HostKey::Any => idx.any.push(n),
                    HostKey::Exact(h) => idx.exact.entry(h.into()).or_default().push(n),
                    HostKey::Suffix(h) => idx.suffix.entry(h.into()).or_default().push(n),
                }
            }
            idx.scripts.push(CompiledScript {
                order: n,
                noframes: s.metadata.noframes,
                run_at: s.metadata.run_at,
                script: s.clone(),
                rules,
            });
        }
        for v in idx.exact.values_mut().chain(idx.suffix.values_mut()) {
            v.dedup();
        }
        idx.any.dedup();
        BuildReport {
            index: idx,
            problems,
        }
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn len(&self) -> usize {
        self.scripts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &CompiledScript> {
        self.scripts.iter()
    }

    pub fn get(&self, id: &str) -> Option<&CompiledScript> {
        self.scripts.iter().find(|s| s.script.id == id)
    }

    /// Scripts that run on this document. `host` is the document's hostname, `url` its full
    /// URL (normalised form). Allocation-free unless candidates are found (or `host` has
    /// uppercase letters).
    pub fn candidates(&self, host: &str, url: &str, is_top_frame: bool) -> Candidates<'_> {
        let mut out = Candidates::new();
        if self.scripts.is_empty() {
            return out;
        }
        let lowered;
        let host = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            lowered = host.to_ascii_lowercase();
            lowered.as_str()
        } else {
            host
        };
        let mut ids: SmallVec<[u32; 16]> = SmallVec::new();
        if !self.exact.is_empty() {
            if let Some(v) = self.exact.get(host) {
                ids.extend_from_slice(v);
            }
        }
        if !self.suffix.is_empty() {
            let mut rest = host;
            loop {
                if let Some(v) = self.suffix.get(rest) {
                    ids.extend_from_slice(v);
                }
                match rest.find('.') {
                    Some(p) => rest = &rest[p + 1..],
                    None => break,
                }
            }
        }
        ids.extend_from_slice(&self.any);
        if ids.is_empty() {
            return out;
        }
        ids.sort_unstable();
        ids.dedup();
        let Some(parts) = UrlParts::parse(url) else {
            return out;
        };
        for id in ids {
            let s = &self.scripts[id as usize];
            if (is_top_frame || !s.noframes) && s.rules.is_match(&parts) {
                out.push(s);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};

    fn script(name: &str, hdr: &str) -> Userscript {
        Userscript::new(format!(
            "// ==UserScript==\n// @name {name}\n{hdr}\n// ==/UserScript==\n"
        ))
        .unwrap()
    }

    #[test]
    fn basic_buckets() {
        let scripts = vec![
            script("a", "// @match https://example.com/*"),
            script("b", "// @match https://*.example.org/*"),
            script("c", "// @include /foo/"),
            script("d", "// @match https://example.com/*\n// @noframes"),
            script("e", "// @match *://*/*\n// @exclude https://example.com/*"),
        ];
        let idx = ScriptIndex::build("default", &scripts, Options::default()).index;
        let names = |h: &str, u: &str, top: bool| {
            idx.candidates(h, u, top)
                .iter()
                .map(|s| s.script.name().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names("example.com", "https://example.com/x", true),
            ["a", "d"]
        );
        assert_eq!(names("example.com", "https://example.com/x", false), ["a"]);
        assert_eq!(
            names("www.example.org", "https://www.example.org/", true),
            ["b", "e"]
        );
        assert_eq!(
            names("EXAMPLE.org", "https://example.org/", true),
            ["b", "e"]
        );
        assert_eq!(names("zzz.net", "https://zzz.net/foo", true), ["c", "e"]);
        assert!(names("zzz.net", "ftp://zzz.net/", true).is_empty());
        assert!(ScriptIndex::default()
            .candidates("a", "https://a/", true)
            .is_empty());
    }

    #[test]
    fn disabled_and_context_menu_skipped() {
        let mut off = script("off", "// @match *://*/*");
        off.enabled = false;
        let cm = script("cm", "// @match *://*/*\n// @run-at context-menu");
        let r = ScriptIndex::build("p", &[off, cm], Options::default());
        assert!(r.index.is_empty());
        assert_eq!(r.problems.len(), 1);
    }

    /// The index must agree with a brute-force scan over every script.
    #[test]
    fn matches_brute_force() {
        let mut rng = StdRng::seed_from_u64(0xad);
        let hosts = [
            "example.com",
            "a.example.com",
            "example.org",
            "x.y.example.org",
            "foo.net",
            "localhost",
            "google.co.uk",
            "google.com",
        ];
        let paths = ["/", "/a", "/a/b", "/foo?x=1", "/Edit/1"];
        let schemes = ["http", "https"];
        let patterns = |rng: &mut StdRng| -> String {
            let h = *hosts.choose(rng).unwrap();
            let p = *paths.choose(rng).unwrap();
            match rng.gen_range(0..11) {
                0 => format!("// @match *://{h}/*"),
                1 => format!("// @match https://*.{h}/*"),
                2 => format!("// @match {}://{h}{p}", schemes.choose(rng).unwrap()),
                3 => format!("// @include http*://{h}/*"),
                4 => format!("// @include *{h}*"),
                5 => format!("// @include /{}/", h.replace('.', "\\.")),
                6 => "// @include google.tld".to_string(),
                7 => "// @match *://google.tld/*".to_string(),
                8 => format!("// @include /^https?:\\/\\/{}\\//", h.replace('.', "\\.")),
                9 => format!("// @include /^https:\\/\\/{}\\/a/", h.replace('.', "\\.")),
                _ => "// @match <all_urls>".to_string(),
            }
        };
        for round in 0..8 {
            let mut scripts = Vec::new();
            for i in 0..rng.gen_range(0..25) {
                let mut hdr = String::new();
                for _ in 0..rng.gen_range(0..4) {
                    hdr += &patterns(&mut rng);
                    hdr.push('\n');
                }
                if rng.gen_bool(0.3) {
                    hdr += &format!("// @exclude *{}*\n", hosts.choose(&mut rng).unwrap());
                }
                if rng.gen_bool(0.2) {
                    hdr += "// @exclude-match *://*/a*\n";
                }
                if rng.gen_bool(0.2) {
                    hdr += "// @noframes\n";
                }
                let mut s = script(&format!("s{round}-{i}"), &hdr);
                s.enabled = rng.gen_bool(0.9);
                scripts.push(s);
            }
            let idx = ScriptIndex::build("p", &scripts, Options::default()).index;
            for _ in 0..60 {
                let h = *hosts.choose(&mut rng).unwrap();
                let url = format!(
                    "{}://{h}{}",
                    schemes.choose(&mut rng).unwrap(),
                    paths.choose(&mut rng).unwrap()
                );
                let top = rng.gen_bool(0.5);
                let got: Vec<_> = idx
                    .candidates(h, &url, top)
                    .iter()
                    .map(|s| s.script.id.clone())
                    .collect();
                let want: Vec<_> = scripts
                    .iter()
                    .filter(|s| s.enabled && (top || !s.metadata.noframes))
                    .filter(|s| {
                        let (r, _) = Rules::compile(&s.metadata, Options::default());
                        r.is_match_url(&url)
                    })
                    .map(|s| s.id.clone())
                    .collect();
                assert_eq!(got, want, "round {round} {url} top={top}");
            }
        }
    }

    #[test]
    fn index_is_send_sync() {
        fn ok<T: Send + Sync>() {}
        ok::<ScriptIndex>();
    }
}

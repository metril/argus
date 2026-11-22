//! The in-page panel in real Chromium: delivery, isolation, the allow flow through the
//! proxy-owned confirmation origin, and what a hostile page cannot do.

use std::collections::HashSet;
use std::sync::Arc;

use chromiumoxide::cdp::browser_protocol::input::{DispatchKeyEventParams, DispatchKeyEventType};
use e2e_browser::{eval_on, run_known, MockResponse, Session};
use proxy_core::panel::{PanelConfig, SiteBlocking};
use script_policy::panel::{hash_pin, PanelAuth, PanelSettings};
use script_policy::{Scope, DEFAULT_PROFILE as P};
use serde_json::Value;
use std::sync::Mutex;

const PIN: &str = "4711";

/// Records which sites have ad blocking off (the production backend edits the custom rules).
#[derive(Default)]
struct Sites(Mutex<HashSet<String>>);
impl SiteBlocking for Sites {
    fn disabled(&self, site: &str) -> bool {
        self.0.lock().unwrap().contains(site)
    }
    fn set_disabled(&self, site: &str, d: bool) -> Result<(), String> {
        let mut g = self.0.lock().unwrap();
        if d {
            g.insert(site.into());
        } else {
            g.remove(site);
        }
        Ok(())
    }
}

macro_rules! panel_test {
    ($name:ident, $auth:expr, |$s:ident, $sites:ident| $body:block) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            let Some($s) = Session::start(&["sp.test##.ad", "/ad.png^$image,domain=sp.test"]).await else {
                return;
            };
            let $sites = setup(&$s, $auth).await;
            run_known(stringify!($name), async move {
                $body
                $s.finish().await;
            })
            .await;
        }
    };
}

/// Policy on, panel on for the profile, a test spy that keeps a handle to every shadow root the
/// page creates (the root stays closed: `host.shadowRoot` is still null).
async fn setup(s: &Session, auth: PanelAuth) -> Arc<Sites> {
    let (store, control) = s.proxy.script_control();
    let mut st = store.rules(P).unwrap().settings;
    st.enabled = true;
    store.set_settings(P, st).unwrap();
    store
        .set_panel_settings(
            P,
            &PanelSettings {
                enabled: true,
                auth,
                pin_hash: Some(hash_pin(PIN, "salt").unwrap()),
                ..Default::default()
            },
        )
        .unwrap();
    control.refresh();
    let sites = Arc::new(Sites::default());
    s.proxy.ctx.configure_panel(
        PanelConfig {
            enabled: true,
            host: "adblock.invalid".into(),
            dashboard_url: "http://127.0.0.1:3000".into(),
        },
        Some(sites.clone()),
    );
    s.page
        .evaluate_on_new_document(
            "(() => { const o = Element.prototype.attachShadow; Element.prototype.attachShadow = function (i) { const r = o.call(this, i); (window.__spy = window.__spy || []).push(r); return r; }; })();",
        )
        .await
        .unwrap();
    sites
}

fn doc(extra_body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=utf-8><title>t</title>\
         <script>window.__inline=1</script><script src=\"/own.js\"></script>\
         <script src=\"CDN\"></script></head><body><input id=first><div class=ad>ad</div><img src=\"/ad.png\">{extra_body}</body></html>"
    )
}

fn routes(s: &Session, body: &str) {
    s.origin.route(
        "/own.js",
        MockResponse::ok("window.__own=1").header("content-type", "text/javascript"),
    );
    s.origin.route(
        "/x.js",
        MockResponse::ok("window.__cdn=1").header("content-type", "text/javascript"),
    );
    let cdn = s.url("cdn.test", "/x.js");
    s.origin
        .route("/", MockResponse::html(doc(body).replace("CDN", &cdn)));
}

async fn key(s: &Session, k: &str, code: &str, vk: i64, modifiers: i64) {
    for t in [
        DispatchKeyEventType::RawKeyDown,
        DispatchKeyEventType::KeyUp,
    ] {
        // Enter activates a focused button only through its character event.
        let enter_down = k == "Enter" && t == DispatchKeyEventType::RawKeyDown;
        let ty = if enter_down {
            DispatchKeyEventType::KeyDown
        } else {
            t
        };
        let mut b = DispatchKeyEventParams::builder()
            .r#type(ty)
            .key(k)
            .code(code)
            .windows_virtual_key_code(vk)
            .modifiers(modifiers);
        if enter_down {
            b = b.text("\r");
        }
        s.page.execute(b.build().unwrap()).await.unwrap();
    }
}

async fn hotkey(s: &Session) {
    key(s, "A", "KeyA", 65, 1 | 8).await; // Alt+Shift
}

async fn panel_text(s: &Session) -> String {
    s.eval("(() => { const r = (window.__spy || []).at(-1); return r && r.host.isConnected ? r.textContent : ''; })()")
        .await
        .as_str()
        .unwrap_or("")
        .to_string()
}

async fn wait_text(s: &Session, what: &str, needle: &str) {
    for _ in 0..400 {
        if panel_text(s).await.contains(needle) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!(
        "panel never showed {what} ({needle:?}): {:?}\n{}",
        panel_text(s).await,
        s.dump()
    );
}

async fn panel_click(s: &Session, sel: &str) {
    let ok = s
        .eval(&format!("(() => {{ const r = window.__spy.at(-1); const e = r.querySelector({sel:?}); if (!e) return false; e.click(); return true; }})()"))
        .await;
    assert_eq!(ok, true, "no {sel} in the panel: {}", panel_text(s).await);
}

async fn blocked_reported(s: &Session) {
    let (store, _) = s.proxy.script_control();
    for _ in 0..400 {
        if store.report_for(P, "sp.test").is_some_and(|r| {
            r.items
                .iter()
                .any(|i| i.source.as_deref() == Some("cdn.test"))
        }) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("cdn.test never reported");
}

panel_test!(
    panel_opens_on_the_hotkey_in_a_closed_shadow_root_and_lists_the_blocked_source,
    PanelAuth::Pin,
    |s, _sites| {
        routes(&s, "");
        s.goto(&s.url("sp.test", "/")).await;
        assert_eq!(s.eval("typeof window.__cdn").await, "undefined");
        blocked_reported(&s).await;
        // Nothing visible and nothing fetched before the hotkey.
        assert_eq!(s.eval("(window.__spy || []).length").await, 0);
        assert!(
            !s.internal_loads()
                .await
                .iter()
                .any(|(p, _)| p.contains("panel.")),
            "panel script is lazy"
        );
        // A page cannot open it with synthetic key events.
        s.eval("document.dispatchEvent(new KeyboardEvent('keydown', {altKey: true, shiftKey: true, code: 'KeyA', bubbles: true}))").await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            s.eval("(window.__spy || []).length").await,
            0,
            "untrusted events are ignored"
        );
        hotkey(&s).await;
        wait_text(&s, "the blocked source", "cdn.test").await;
        let t = panel_text(&s).await;
        assert!(
            t.contains("Script control: sp.test")
                && t.contains("Untrusted")
                && t.contains("script"),
            "{t}"
        );
        let shape = s
        .eval("(() => { const h = window.__spy.at(-1).host; return [h.shadowRoot === null, h.parentElement === document.documentElement, getComputedStyle(h).display, document.querySelectorAll('#p, .p').length]; })()")
        .await;
        assert_eq!(shape[0], true, "closed shadow root: {shape}");
        assert_eq!(shape[3], 0, "no panel markup in the page's own DOM");
        // Esc closes it; the hotkey toggles it again.
        key(&s, "Escape", "Escape", 27, 0).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(panel_text(&s).await, "");
        // The ad-blocker's own work is untouched and nothing of ours violated the page's policy.
        assert_eq!(s.display(".ad").await, "none");
        let v = s.violations().await;
        assert!(
            v.iter().all(|v| {
                let u = v["uri"].as_str().unwrap_or("");
                !u.contains("__adblock__")
                    && !v["eff"].as_str().unwrap_or("").starts_with("connect-src")
            }),
            "{v:?}"
        );
    }
);

panel_test!(
    allow_flow_through_the_confirmation_origin_ends_with_the_script_running,
    PanelAuth::Pin,
    |s, _sites| {
        routes(&s, "");
        let url = s.url("sp.test", "/");
        s.goto(&url).await;
        blocked_reported(&s).await;
        hotkey(&s).await;
        wait_text(&s, "the source", "cdn.test").await;
        panel_click(&s, "[data-k=\"s-cdn.test|script\"]").await;
        wait_text(&s, "a pending change", "Review and apply (1)").await;
        let href = s
            .eval("window.__spy.at(-1).querySelector('[data-k=apply]').getAttribute('href')")
            .await
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            href.starts_with("https://adblock.invalid/confirm?p="),
            "{href}"
        );
        let rel = s
            .eval("window.__spy.at(-1).querySelector('[data-k=apply]').rel")
            .await;
        assert!(rel.as_str().unwrap().contains("noopener"), "{rel}");
        // The panel alone changed nothing.
        let (store, _) = s.proxy.script_control();
        assert!(store.rules(P).unwrap().temps.is_empty());
        // The user opens the confirmation page (a separate tab), reads it and enters the PIN.
        let tab = s.new_tab().await;
        tab.goto(href.as_str()).await.unwrap();
        let body = eval_on(&tab, "document.body.innerText").await;
        assert!(
            body.as_str()
                .unwrap()
                .contains("Allow script from cdn.test on sp.test for 1 hour"),
            "{body}"
        );
        let top = eval_on(
            &tab,
            "[window.top === window, window.opener === null, location.origin]",
        )
        .await;
        assert_eq!(top[0], true);
        assert_eq!(top[1], true, "opened without an opener");
        assert_eq!(top[2], "https://adblock.invalid");
        assert!(
            s.origin
                .requests()
                .iter()
                .all(|r| !r.host.contains("adblock.invalid")),
            "never forwarded"
        );
        // The page cannot frame it: the proxy refuses to render it as anything but a top-level page.
        s.eval(&format!("(() => {{ const f = document.createElement('iframe'); f.src = {href:?}; document.body.appendChild(f); }})()")).await;
        let mut framed = None;
        for _ in 0..200 {
            framed = s
                .responses()
                .into_iter()
                .find(|r| r.url.contains("adblock.invalid/confirm"));
            if framed.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let framed = framed.expect("iframe request seen");
        assert_eq!(framed.status, 403, "framed request refused");
        assert!(framed
            .header("content-security-policy")
            .unwrap()
            .contains("frame-ancestors 'none'"));
        assert_eq!(framed.header("x-frame-options").as_deref(), Some("DENY"));
        tab.find_element("input[name=pin]")
            .await
            .unwrap()
            .click()
            .await
            .unwrap()
            .type_str(PIN)
            .await
            .unwrap();
        tab.find_element("button[type=submit]")
            .await
            .unwrap()
            .click()
            .await
            .unwrap();
        for _ in 0..400 {
            if !store.rules(P).unwrap().temps.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let done = eval_on(&tab, "document.body.innerText").await;
        assert!(done.as_str().unwrap().contains("done"), "{done}");
        assert_eq!(store.rules(P).unwrap().temps.len(), 1, "applied");
        // Back on the page: the panel offers a reload, the reload runs the script.
        s.eval("window.dispatchEvent(new Event('focus'))").await;
        wait_text(&s, "the reload prompt", "Reload to apply").await;
        s.goto(&url).await;
        assert_eq!(s.eval("window.__cdn").await, 1, "allowed after reload");
    }
);

panel_test!(
    hostile_page_cannot_change_policy_blocking_or_userscripts,
    PanelAuth::None,
    |s, sites| {
        let us = s.proxy.install_userscript(
        "// ==UserScript==\n// @name victim\n// @namespace sp\n// @version 1\n// @match *://sp.test/*\n// @grant none\n// ==/UserScript==\nwindow.__us = 1;\n",
    );
        let proposal = proxy_core::panel::encode_proposal(&[
            proxy_core::panel::PanelOp::Preset {
                page: "sp.test".into(),
                preset: "trusted".into(),
            },
            proxy_core::panel::PanelOp::Adblock {
                site: "sp.test".into(),
                enabled: false,
            },
            proxy_core::panel::PanelOp::Userscript {
                id: us.clone(),
                enabled: false,
            },
            proxy_core::panel::PanelOp::AllowAll {
                page: "sp.test".into(),
                ttl: proxy_core::panel::Ttl::Day1,
            },
        ]);
        let attack = format!(
            r#"<script>
(async () => {{
  const out = {{ steps: [] }}; window.__out = out;
  const p = {proposal:?};
  // 1. synthesised hotkeys, then look for our element anywhere
  for (const t of ['keydown', 'keyup']) for (const tg of [document, window, document.body]) tg.dispatchEvent(new KeyboardEvent(t, {{altKey: true, shiftKey: true, code: 'KeyA', key: 'A', bubbles: true, composed: true}}));
  out.hostFound = [...document.querySelectorAll('*')].some(e => e.shadowRoot) || document.documentElement.children.length > 2;
  // 2. everything the panel can call, with the page's own token
  const cfg = JSON.parse(document.getElementById('__ab_cfg').textContent);
  const st = await fetch('/__adblock__/panel/state', {{method: 'POST', credentials: 'omit', headers: {{'Content-Type': 'application/json', 'X-Adblock-Token': cfg.t}}, body: JSON.stringify({{url: location.href}})}}).then(r => r.json()).catch(e => null);
  out.state = !!st;
  // 3. cross-site fetches to the confirmation origin (opaque, but they are sent)
  const form = 'p=' + p + '&n=ffffffffff.AAAA&pin=' + {PIN:?};
  for (const mode of ['no-cors']) {{
    await fetch('https://adblock.invalid/apply', {{method: 'POST', mode, credentials: 'include', headers: {{'Content-Type': 'application/x-www-form-urlencoded'}}, body: form}}).catch(e => out.steps.push('fetch: ' + e.message));
    await fetch('https://adblock.invalid/confirm?p=' + p, {{mode, credentials: 'include'}}).catch(e => out.steps.push('get: ' + e.message));
  }}
  // 4. a form post into a hidden frame, and a top-level style navigation attempt
  const f = document.createElement('iframe'); f.name = 'hf'; document.body.appendChild(f);
  const fm = document.createElement('form'); fm.method = 'POST'; fm.action = 'https://adblock.invalid/apply'; fm.target = 'hf';
  for (const [k, v] of [['p', p], ['n', 'ffffffffff.AAAA'], ['pin', {PIN:?}]]) {{ const i = document.createElement('input'); i.name = k; i.value = v; fm.appendChild(i); }}
  document.body.appendChild(fm); fm.submit();
  // 5. the proxy's own endpoints with guesses
  for (const path of ['/__adblock__/panel/apply', '/__adblock__/gm/v1/values/set', '/__adblock__/pv?d=1.2.3']) await fetch(path, {{method: 'POST', credentials: 'omit', headers: {{'Content-Type': 'application/json'}}, body: '{{}}'}}).catch(() => 0);
  await new Promise(r => setTimeout(r, 500));
  out.done = true;
}})();
</script>"#
        );
        s.origin.route("/", MockResponse::html(format!("<!doctype html><html><head><meta charset=utf-8><title>h</title></head><body>{attack}</body></html>")));
        s.goto(&s.url("sp.test", "/")).await;
        s.wait_for(
            "the attack to finish",
            "window.__out && window.__out.done === true",
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let (store, _) = s.proxy.script_control();
        let rules = store.rules(P).unwrap();
        assert!(rules.site_rules.is_empty(), "no preset change: {rules:?}");
        assert!(
            rules.temps.is_empty() && rules.source_rules.is_empty(),
            "no grants"
        );
        assert!(!sites.disabled("sp.test"), "ad blocking still on");
        assert!(
            s.proxy.userscripts().get(&us).unwrap().enabled,
            "userscript still enabled"
        );
        assert_eq!(
            s.eval("(window.__spy || []).length").await,
            0,
            "the hotkey was not honoured"
        );
        // The attacker could read what the panel reads, and no more than that.
        assert_eq!(s.eval("window.__out.state").await, true);
        let _: Value = s.eval("window.__out").await;
    }
);

panel_test!(
    panel_works_under_default_src_none_and_trusted_types,
    PanelAuth::Pin,
    |s, _sites| {
        s.origin.route("/", MockResponse::html("<!doctype html><html><head><meta charset=utf-8><title>t</title></head><body><button id=b>x</button><div class=ad>ad</div></body></html>")
        .header("content-security-policy", "default-src 'none'; require-trusted-types-for 'script'"));
        s.goto(&s.url("sp.test", "/")).await;
        hotkey(&s).await;
        wait_text(&s, "the panel", "Script control: sp.test").await;
        let v = s.violations().await;
        assert!(
            v.iter()
                .all(|v| !v["uri"].as_str().unwrap_or("").contains("__adblock__")
                    && !v["sample"].as_str().unwrap_or("").contains("adblock")),
            "no violation from our resources: {v:?}"
        );
        let p = s.problems_sync(&v);
        assert!(p.is_empty(), "{p:?}");
        // A second case: a Trusted Types allow-list that does not know our policy.
        s.origin.route("/tt", MockResponse::html("<!doctype html><html><head><meta charset=utf-8><title>t</title></head><body>x</body></html>")
        .header("content-security-policy", "script-src 'self' 'nonce-N0'; require-trusted-types-for 'script'; trusted-types mypolicy"));
        s.goto(&s.url("sp.test", "/tt")).await;
        hotkey(&s).await;
        wait_text(&s, "the panel", "Script control: sp.test").await;
        let p = s.problems_sync(&s.violations().await);
        assert!(p.is_empty(), "{p:?}");
    }
);

panel_test!(
    menu_commands_of_two_scripts_appear_and_fire,
    PanelAuth::Pin,
    |s, _sites| {
        for (n, g) in [("One", "__c1"), ("Two", "__c2")] {
            s.proxy.install_userscript(&format!(
            "// ==UserScript==\n// @name {n}\n// @namespace sp\n// @version 1\n// @match *://sp.test/*\n// @grant GM_registerMenuCommand\n// ==/UserScript==\nGM_registerMenuCommand('{n} command', () => {{ window.{g} = (window.{g} || 0) + 1; }});\n"
        ));
        }
        routes(&s, "");
        s.goto(&s.url("sp.test", "/")).await;
        hotkey(&s).await;
        wait_text(&s, "both commands", "Two command").await;
        let t = panel_text(&s).await;
        assert!(
            t.contains("One command") && t.contains("Two command"),
            "{t}"
        );
        for (label, g) in [("One command", "__c1"), ("Two command", "__c2")] {
            s.eval(&format!(
            "(() => {{ const b = [...window.__spy.at(-1).querySelectorAll('button')].find(b => b.textContent === {label:?}); b.click(); }})()"
        ))
        .await;
            s.wait_for(label, &format!("window.{g} === 1")).await;
        }
    }
);

panel_test!(keyboard_only_operation, PanelAuth::Pin, |s, _sites| {
    routes(&s, "");
    s.goto(&s.url("sp.test", "/")).await;
    s.eval("document.getElementById('first').focus()").await;
    hotkey(&s).await;
    wait_text(&s, "the panel", "Script control").await;
    let focus = "(() => { const h = window.__spy.at(-1).host; return [document.activeElement === h, window.__spy.at(-1).activeElement && (window.__spy.at(-1).activeElement.getAttribute('data-k') || window.__spy.at(-1).activeElement.tagName)]; })()";
    // Tab many times: focus never leaves the panel (trap), and wraps.
    let mut seen = HashSet::new();
    for _ in 0..30 {
        key(&s, "Tab", "Tab", 9, 0).await;
        let f = s.eval(focus).await;
        assert_eq!(f[0], true, "focus escaped the panel: {f}");
        seen.insert(f[1].to_string());
    }
    assert!(seen.len() >= 4, "tab visits several controls: {seen:?}");
    // Shift+Tab goes backwards through the same ring.
    key(&s, "Tab", "Tab", 9, 8).await;
    assert_eq!(s.eval(focus).await[0], true);
    // Activate "Untrusted" with the keyboard alone.
    let mut hit = false;
    for _ in 0..30 {
        let f = s.eval(focus).await;
        if f[1] == "preset-untrusted" {
            key(&s, "Enter", "Enter", 13, 0).await;
            hit = true;
            break;
        }
        key(&s, "Tab", "Tab", 9, 0).await;
    }
    assert!(hit, "reached the preset button by keyboard");
    wait_text(&s, "the staged change", "Review and apply (1)").await;
    // Esc closes and focus returns to where it was.
    key(&s, "Escape", "Escape", 27, 0).await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(panel_text(&s).await, "");
    assert_eq!(
        s.eval("document.activeElement && document.activeElement.id")
            .await,
        "first"
    );
    let _ = Scope::Global;
});

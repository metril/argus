/* In-page control panel. Loaded only when the hotkey is first pressed (boot.js).
   It runs in the page's JavaScript world, so it is READ-ONLY: it shows state and builds links to
   the proxy-owned confirmation host, where the user approves changes. See docs/SCRIPT-POLICY.md.
   No innerHTML, no inline handlers, no eval; styles live in a constructed stylesheet inside a
   closed shadow root. */
(function () {
"use strict";
var W = window, D = document, KEY = Symbol.for("adblock.panel");
if (W[KEY]) { W[KEY](); return; }
var cfg = {};
try { cfg = JSON.parse(D.getElementById("__ab_cfg").textContent) || {}; } catch (e) { /* ignore */ }
var TTLS = [["5m", "5 minutes"], ["1h", "1 hour"], ["1d", "1 day"], ["restart", "Until restart"], ["forever", "Permanent"]];
var PRESETS = [["default", "Default"], ["trusted", "Trusted"], ["untrusted", "Untrusted"]];
var CSS = ":host{all:initial}*{box-sizing:border-box}" +
  ".w{all:initial;position:fixed;inset:0;z-index:2147483647;display:flex;justify-content:flex-end;font:14px/1.45 system-ui,sans-serif;color:var(--fg);" +
  "--bg:#fff;--fg:#1c1b1f;--mut:#5c5b61;--bd:#d0d0d6;--ac:#0b57d0;--acf:#fff;--bad:#b3261e;--sf:#f3f3f7}" +
  "@media(prefers-color-scheme:dark){.w{--bg:#1e1e22;--fg:#e6e6ea;--mut:#a0a0a8;--bd:#3a3a42;--ac:#8ab4f8;--acf:#101014;--bad:#f2b8b5;--sf:#28282e}}" +
  ".s{position:absolute;inset:0;background:rgba(0,0,0,.35)}" +
  ".p{position:relative;width:min(34rem,100vw);height:100%;overflow:auto;background:var(--bg);border-left:1px solid var(--bd);padding:1rem}" +
  "h2{font-size:1.1rem;margin:0 0 .5rem}h3{font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);margin:1rem 0 .4rem}" +
  ".r{display:flex;flex-wrap:wrap;gap:.4rem;align-items:center;margin:.25rem 0}.g{margin:.5rem 0;padding:.5rem;border:1px solid var(--bd);border-radius:.5rem;background:var(--sf)}" +
  "button,select,a.b{font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--bd);border-radius:.4rem;padding:.3rem .7rem;cursor:pointer;text-decoration:none;display:inline-block}" +
  "button[aria-pressed=true],a.pri{background:var(--ac);color:var(--acf);border-color:var(--ac)}a[aria-disabled=true]{opacity:.5;pointer-events:none}" +
  "button:focus-visible,select:focus-visible,a:focus-visible,input:focus-visible{outline:2px solid var(--ac);outline-offset:2px}" +
  ".m{color:var(--mut)}.e{color:var(--bad)}.x{margin-left:auto}label{display:inline-flex;gap:.3rem;align-items:center}" +
  "@media(max-width:480px){.p{padding:.75rem}}";
var host, shadow, wrap, panelEl, st = null, openedGen = null, prevFocus = null, timer = null, err = "";
var staged = {}, stagedPreset = null, stagedAdblock = null, stagedUs = {}, allowAll = false, revoke = false, ttl = "1h";
var viol = {};

function h(tag, props, kids) {
  var e = D.createElement(tag);
  for (var k in props || {}) {
    if (k === "text") { e.textContent = props[k]; }
    else if (k === "on") { for (var ev in props.on) { e.addEventListener(ev, props.on[ev]); } }
    else { e.setAttribute(k, props[k]); }
  }
  (kids || []).forEach(function (c) { if (c) { e.appendChild(typeof c === "string" ? D.createTextNode(c) : c); } });
  return e;
}
function b64url(s) { return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function fetchState() {
  return fetch("/__adblock__/panel/state", { method: "POST", credentials: "omit", cache: "no-store",
    headers: { "Content-Type": "application/json", "X-Adblock-Token": cfg.t || "" }, body: JSON.stringify({ url: location.href }) })
    .then(function (r) { if (!r.ok) { throw new Error("HTTP " + r.status); } return r.json(); });
}
var lastJ = "";
function refresh() {
  fetchState().then(function (s) {
    var j = JSON.stringify(s);
    if (j === lastJ && !err) { return; }
    lastJ = j; err = ""; st = s; if (openedGen === null) { openedGen = s.gen; } render(); },
    function (e) { err = "Could not load state (" + e.message + ")"; render(); });
}
function ops() {
  var out = [], by = {};
  if (stagedPreset) { out.push({ op: "preset", page: st.site, preset: stagedPreset }); }
  Object.keys(staged).forEach(function (k) {
    var i = k.indexOf("|"), src = k.slice(0, i), cap = k.slice(i + 1), allow = staged[k], g = src + (allow ? "+" : "-");
    if (!by[g]) { by[g] = { op: "source", page: st.site, source: src, caps: [], allow: allow, ttl: allow ? ttl : "forever" }; out.push(by[g]); }
    by[g].caps.push(cap);
  });
  if (allowAll) { out.push({ op: "allow_all", page: st.site, ttl: ttl === "forever" ? "1d" : ttl }); }
  if (revoke) { out.push({ op: "revoke_temps" }); }
  if (stagedAdblock !== null) { out.push({ op: "adblock", site: st.site, enabled: stagedAdblock }); }
  Object.keys(stagedUs).forEach(function (id) { out.push({ op: "userscript", id: id, enabled: stagedUs[id] }); });
  return out;
}
function sources() {
  var rows = (st.sources || []).filter(function (i) { return i.source && i.sourced; });
  var seen = {};
  rows.forEach(function (i) { seen[i.cap + "|" + i.source] = 1; });
  Object.keys(viol).forEach(function (k) { if (!seen[k]) { var i = k.indexOf("|"); rows.push({ cap: k.slice(0, i), source: k.slice(i + 1), site: viol[k], count: 1, allowed: false, via: "browser" }); } });
  var groups = {};
  rows.forEach(function (r) { var g = r.site || r.source; (groups[g] = groups[g] || {}); (groups[g][r.source] = groups[g][r.source] || []).push(r); });
  return groups;
}
function btn(label, pressed, fn, key) {
  return h("button", { type: "button", "aria-pressed": pressed ? "true" : "false", "data-k": key || label, on: { click: fn } }, [label]);
}
function section(title, kids) { return h("div", {}, [h("h3", { text: title })].concat(kids)); }
function render() {
  var focusKey = shadow && shadow.activeElement && shadow.activeElement.getAttribute("data-k");
  var p = h("div", { class: "p", role: "dialog", "aria-modal": "true", "aria-label": "Script control" });
  p.appendChild(h("div", { class: "r" }, [h("h2", { text: "Script control: " + (st ? st.site : "") }),
    h("button", { type: "button", class: "x", "data-k": "close", "aria-label": "Close", on: { click: close } }, ["Close"])]));
  if (err) { p.appendChild(h("p", { class: "e", role: "alert", text: err })); }
  if (st) {
    if (openedGen !== null && st.gen !== openedGen) {
      p.appendChild(h("div", { class: "g", role: "status" }, ["Settings changed. ", h("button", { type: "button", "data-k": "reload", on: { click: function () { location.reload(); } } }, ["Reload to apply"])]));
    }
    if (!st.enabled) { p.appendChild(h("p", { class: "m", text: "Script policy is switched off, so presets and sources have no effect yet." })); }
    var cur = stagedPreset || st.preset;
    p.appendChild(section("Preset for " + st.site, [h("div", { class: "r", role: "group", "aria-label": "Preset" },
      PRESETS.map(function (x) { return btn(x[1], cur === x[0], function () { stagedPreset = x[0] === st.preset ? null : x[0]; render(); }, "preset-" + x[0]); })
        .concat(st.preset === "custom" && !stagedPreset ? [h("span", { class: "m", text: "Custom (set in the dashboard)" })] : []))]));
    var groups = sources(), gk = Object.keys(groups), kids = [];
    var ttlSel = h("select", { "aria-label": "How long to allow", "data-k": "ttl", on: { change: function (e) { ttl = e.target.value; render(); } } },
      TTLS.map(function (t) { var o = h("option", { value: t[0], text: t[1] }); if (t[0] === ttl) { o.selected = true; } return o; }));
    kids.push(h("div", { class: "r" }, [h("span", { text: "Allow" }), ttlSel]));
    if (!gk.length) { kids.push(h("p", { class: "m", text: "Nothing blocked on this page so far." })); }
    gk.forEach(function (g) {
      var box = h("div", { class: "g" }, [h("strong", { text: g })]);
      Object.keys(groups[g]).forEach(function (src) {
        box.appendChild(h("div", { class: "r" }, [h("span", { text: src })].concat(groups[g][src].map(function (r) {
          var k = src + "|" + r.cap, want = k in staged ? staged[k] : r.allowed;
          return btn(r.cap + (r.count > 1 ? " ×" + r.count : ""), want, function () { if (k in staged) { delete staged[k]; } else { staged[k] = !r.allowed; } render(); }, "s-" + k);
        }))));
      });
      kids.push(box);
    });
    var inl = (st.sources || []).filter(function (i) { return !i.sourced; });
    if (inl.length) { kids.push(h("p", { class: "m", text: "Page-level blocks: " + inl.map(function (i) { return i.cap + " ×" + i.count; }).join(", ") + ". Change the preset to allow these." })); }
    kids.push(h("div", { class: "r" }, [btn("Temporarily allow all on this page", allowAll, function () { allowAll = !allowAll; render(); }, "allow-all"),
      btn("Revoke temporary permissions", revoke, function () { revoke = !revoke; render(); }, "revoke")]));
    (st.temps || []).forEach(function (t) { kids.push(h("p", { class: "m", text: "Temporary: " + t.what + (t.expires_at ? " until " + new Date(t.expires_at * 1000).toLocaleTimeString() : " until restart") })); });
    p.appendChild(section("Blocked on this page", kids));
    p.appendChild(section("Ad blocking", [h("div", { class: "r" }, [
      btn("On for " + st.site, (stagedAdblock === null ? !st.adblock_off : stagedAdblock), function () { var cur2 = stagedAdblock === null ? !st.adblock_off : stagedAdblock; stagedAdblock = !cur2 === !st.adblock_off ? null : !cur2; render(); }, "adblock"),
      h("span", { class: "m", text: st.blocked + " blocked on this page" })])]));
    var reg = null;
    try { reg = W[Symbol.for("adblock.userscript.menu")]; } catch (e) { /* ignore */ }
    var cmds = reg ? reg.commands() : [];
    var uk = (st.userscripts || []).map(function (u) {
      var on = u.id in stagedUs ? stagedUs[u.id] : u.enabled;
      var row = [btn(u.name + (on ? ": on" : ": off"), on, function () { if (u.id in stagedUs) { delete stagedUs[u.id]; } else { stagedUs[u.id] = !u.enabled; } render(); }, "u-" + u.id)];
      cmds.filter(function (c) { return c.script === u.id; }).forEach(function (c) {
        row.push(h("button", { type: "button", "data-k": "c-" + c.id, on: { click: function () { reg.invoke(c.script, c.id); } } }, [c.caption]));
      });
      return h("div", { class: "r" }, row);
    });
    p.appendChild(section("Userscripts", uk.length ? uk : [h("p", { class: "m", text: "No userscript matches this page." })]));
    var n = ops().length, can = st.auth !== "session" && n > 0 && !(st.auth === "pin" && !st.pin_set);
    var foot = [];
    if (can) { foot.push(h("a", { class: "b pri", "data-k": "apply", href: st.panel_origin + "/confirm?p=" + b64url(JSON.stringify(ops())), target: "_blank", rel: "noopener noreferrer" }, ["Review and apply (" + n + ")"])); }
    else { foot.push(h("a", { class: "b", "data-k": "apply", "aria-disabled": "true", role: "link", text: n ? "Cannot apply from here" : "No changes" })); }
    if (st.dashboard) { foot.push(h("a", { class: "b", "data-k": "dash", href: st.dashboard, target: "_blank", rel: "noopener noreferrer" }, ["Open dashboard"])); }
    p.appendChild(h("div", { class: "r" }, foot));
    if (st.auth === "session") { p.appendChild(h("p", { class: "m", text: "Changes are made in the dashboard for this profile." })); }
    else if (st.auth === "pin" && !st.pin_set) { p.appendChild(h("p", { class: "m", text: "Set a panel PIN in the dashboard to apply changes from here." })); }
    else { p.appendChild(h("p", { class: "m", text: "Changes are confirmed on " + st.panel_origin.replace(/^https?:\/\//, "") + ", never on this page." })); }
  }
  if (panelEl) { wrap.replaceChild(p, panelEl); } else { wrap.appendChild(p); }
  panelEl = p;
  var f = focusKey && p.querySelector("[data-k=\"" + focusKey.replace(/"/g, "") + "\"]");
  if (f) { f.focus(); } else if (!shadow.activeElement) { var c = p.querySelector("button"); if (c) { c.focus(); } }
}
function onKey(e) {
  if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(); return; }
  if (e.key !== "Tab" || !panelEl) { return; }
  var f = [].slice.call(panelEl.querySelectorAll("button,select,a[href]")).filter(function (x) { return !x.disabled; });
  if (!f.length) { return; }
  var i = f.indexOf(shadow.activeElement), last = f.length - 1;
  if (e.shiftKey && i <= 0) { e.preventDefault(); f[last].focus(); }
  else if (!e.shiftKey && i === last) { e.preventDefault(); f[0].focus(); }
}
function onViol(e) {
  var u = e.blockedURI || "", m = /^https?:\/\/([^\/:]+)/.exec(u), cap = (e.effectiveDirective || "").replace(/-src(-elem|-attr)?$/, "");
  if (m && cap) { viol[cap + "|" + m[1]] = m[1].split(".").slice(-2).join("."); if (host) { render(); } }
}
function open() {
  if (host) { return; }
  prevFocus = D.activeElement;
  host = D.createElement("div");
  shadow = host.attachShadow({ mode: "closed" });
  try { var sh = new CSSStyleSheet(); sh.replaceSync(CSS); shadow.adoptedStyleSheets = [sh]; }
  catch (e) { var s = D.createElement("style"); var n = D.querySelector("script[nonce]"); if (n && (n.nonce || n.getAttribute("nonce"))) { s.setAttribute("nonce", n.nonce || n.getAttribute("nonce")); } s.textContent = CSS; shadow.appendChild(s); }
  wrap = h("div", { class: "w" }, [h("div", { class: "s", on: { click: close } })]);
  shadow.appendChild(wrap);
  panelEl = null; st = null; lastJ = ""; openedGen = null; staged = {}; stagedPreset = null; stagedAdblock = null; stagedUs = {}; allowAll = false; revoke = false;
  shadow.addEventListener("keydown", onKey);
  D.documentElement.appendChild(host);
  render();
  refresh();
  timer = setInterval(refresh, 3000);
  W.addEventListener("focus", refresh);
  D.addEventListener("securitypolicyviolation", onViol, true);
  try { var reg = W[Symbol.for("adblock.userscript.menu")]; if (reg) { reg.subscribe(function () { if (host) { render(); } }); } } catch (e) { /* ignore */ }
}
function close() {
  if (!host) { return; }
  clearInterval(timer);
  W.removeEventListener("focus", refresh);
  D.removeEventListener("securitypolicyviolation", onViol, true);
  host.remove(); host = null; shadow = null; panelEl = null;
  try { if (prevFocus && prevFocus.focus) { prevFocus.focus(); } } catch (e) { /* ignore */ }
}
function toggle() { if (host) { close(); } else { open(); } }
try { Object.defineProperty(W, KEY, { value: toggle, enumerable: false, configurable: false, writable: false }); } catch (e) { /* ignore */ }
open();
})();

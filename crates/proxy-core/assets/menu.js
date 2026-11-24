/* On-demand userscript menu button. Loaded after the userscript bundles when the profile's
   `menu_button` is "on_demand" or "always" (data-m on this script tag). It shows a small corner
   badge that lists the GM_registerMenuCommand entries of the page's scripts, grouped by script.
   It uses only the registry the runtime already exposes (list, invoke, subscribe), accepts only
   trusted clicks, and renders inside a closed shadow root. No innerHTML, no inline handlers,
   no eval, no network. See docs/SCRIPT-POLICY.md. */
(function () {
"use strict";
var W = window, D = document, KEY = Symbol.for("adblock.menu");
try { if (Object.getOwnPropertyDescriptor(W, KEY)) { return; } Object.defineProperty(W, KEY, { value: 1, enumerable: false, configurable: false, writable: false }); } catch (e) { return; }
var me = D.currentScript, always = !!me && me.getAttribute("data-m") === "always", nonce = (me && (me.nonce || me.getAttribute("nonce"))) || "";
var reg = null;
try { reg = W[Symbol.for("adblock.userscript.menu")]; } catch (e) { /* ignore */ }
if (!reg || typeof reg.commands !== "function" || typeof reg.invoke !== "function" || typeof reg.subscribe !== "function") { return; }
var CSS = ":host{all:initial}*{box-sizing:border-box}" +
  ".w{all:initial;position:fixed;right:12px;bottom:12px;z-index:2147483647;display:flex;flex-direction:column;align-items:flex-end;gap:6px;font:13px/1.4 system-ui,sans-serif;color:var(--fg);" +
  "--bg:#fff;--fg:#1c1b1f;--mut:#5c5b61;--bd:#d0d0d6;--ac:#0b57d0}" +
  "@media(prefers-color-scheme:dark){.w{--bg:#1e1e22;--fg:#e6e6ea;--mut:#a0a0a8;--bd:#3a3a42;--ac:#8ab4f8}}" +
  ".b{font:600 12px/1 system-ui,sans-serif;width:28px;height:28px;border-radius:50%;border:1px solid var(--bd);background:var(--bg);color:var(--ac);cursor:pointer;opacity:.55;padding:0}" +
  ".b:hover,.b:focus-visible,.b[aria-expanded=true]{opacity:1}.b:focus-visible,.c:focus-visible{outline:2px solid var(--ac);outline-offset:2px}" +
  ".m{max-width:min(20rem,calc(100vw - 24px));max-height:60vh;overflow:auto;background:var(--bg);border:1px solid var(--bd);border-radius:8px;padding:6px;box-shadow:0 2px 12px rgba(0,0,0,.25)}" +
  ".t{margin:4px 6px 2px;color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.04em;overflow-wrap:anywhere}" +
  ".c{display:block;width:100%;text-align:left;font:inherit;color:var(--fg);background:none;border:0;border-radius:5px;padding:5px 8px;cursor:pointer}.c:hover{background:rgba(127,127,127,.18)}" +
  ".n{margin:4px 8px;color:var(--mut)}";
var host = null, root = null, wrap = null, badge = null, menuEl = null, open = false, vis = false;

function h(tag, props, kids) {
  var e = D.createElement(tag);
  for (var k in props || {}) {
    if (k === "text") { e.textContent = props[k]; }
    else if (k === "on") { for (var ev in props.on) { e.addEventListener(ev, props.on[ev]); } }
    else { e.setAttribute(k, props[k]); }
  }
  (kids || []).forEach(function (c) { if (c) { e.appendChild(c); } });
  return e;
}
function cmds() { try { var l = reg.commands(); return Array.isArray(l) ? l : []; } catch (e) { return []; } }
function build() {
  host = D.createElement("div");
  root = host.attachShadow({ mode: "closed" });
  try { var sh = new CSSStyleSheet(); sh.replaceSync(CSS); root.adoptedStyleSheets = [sh]; }
  catch (e) { var s = D.createElement("style"); if (nonce) { s.setAttribute("nonce", nonce); } s.textContent = CSS; root.appendChild(s); }
  badge = h("button", { type: "button", class: "b", "data-k": "badge", "aria-haspopup": "true", "aria-expanded": "false", on: { click: function (e) { if (e.isTrusted) { setOpen(!open); } } } }, []);
  badge.textContent = "A";
  wrap = h("div", { class: "w" }, [badge]);
  root.appendChild(wrap);
  root.addEventListener("keydown", function (e) { if (e.key === "Escape" && open) { setOpen(false); try { badge.focus(); } catch (x) { /* ignore */ } } });
}
function setOpen(v) { open = v; render(); }
function ensure() {
  var r = D.documentElement;
  if (host && r && host.parentNode !== r) { r.appendChild(host); }
}
function render() {
  var list = cmds(), show = always || list.length > 0;
  if (!show) {
    if (host && host.parentNode) { host.parentNode.removeChild(host); }
    open = false; vis = false;
    return;
  }
  if (!host) { build(); }
  vis = true; ensure();
  badge.setAttribute("aria-expanded", open ? "true" : "false");
  badge.setAttribute("aria-label", "Argus userscript commands (" + list.length + ")");
  if (menuEl) { wrap.removeChild(menuEl); menuEl = null; }
  if (!open) { return; }
  var kids = [], groups = {}, order = [];
  list.forEach(function (c) { var g = String(c.script); if (!groups[g]) { groups[g] = []; order.push(g); } groups[g].push(c); });
  if (!order.length) { kids.push(h("p", { class: "n", text: "No commands registered." })); }
  order.forEach(function (g) {
    kids.push(h("div", { class: "t", text: String(groups[g][0].scriptName || g) }));
    groups[g].forEach(function (c) {
      kids.push(h("button", { type: "button", class: "c", "data-k": "c-" + g + "-" + c.id, on: { click: function (e) {
        if (!e.isTrusted) { return; }
        setOpen(false);
        try { reg.invoke(c.script, c.id); } catch (x) { /* ignore */ }
      } } }, [h("span", { text: String(c.caption) })]));
    });
  });
  menuEl = h("div", { class: "m", role: "menu", "aria-label": "Userscript commands" }, kids);
  wrap.insertBefore(menuEl, badge);
}
reg.subscribe(render);
D.addEventListener("click", function (e) { if (open && e.target !== host) { setOpen(false); } }, true);
["DOMContentLoaded", "load"].forEach(function (n) { D.addEventListener(n, function () { if (vis) { ensure(); } }); });
["popstate", "hashchange", "pageshow"].forEach(function (n) { W.addEventListener(n, function () { render(); }); });
try { if (W.MutationObserver && D.documentElement) { new W.MutationObserver(function () { if (vis) { ensure(); } }).observe(D, { childList: true }); } } catch (e) { /* ignore */ }
render();
})();

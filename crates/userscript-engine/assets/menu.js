/* On-demand userscript menu button. Inlined into the shared runtime closure (gm_shared.js), so the
   command registry is never reachable from page code: `reg` is a closure variable handed to this
   function once. It shows a small corner badge listing the GM_registerMenuCommand entries of the
   page's scripts, grouped by script, in a closed shadow root (no innerHTML, no inline handlers, no
   eval, no network).
   Hostile-page defences: every built-in used is captured here, at document start, and only ever
   called through Reflect.apply (the page cannot hook addEventListener/attachShadow/
   getComputedStyle to capture handlers or fake the checks); no property of an object literal or
   array method is read that Object.prototype/Array.prototype pollution could change; clicks count
   only when a saved Event isTrusted getter says so; the host has inline !important styles; the
   badge and open menu are re-raised in the top layer before each click; a computed-style, geometry
   and hit-test check runs before each click; items ignore clicks for 400 ms after the menu opens.
   See docs/SCRIPT-POLICY.md. */
function (W, reg, mode, nonce) {
  "use strict";
  if (mode !== "always" && mode !== "on_demand") { return; }
  if (mode === "always") { try { if (W !== W.top) { mode = "on_demand"; } } catch (e) { mode = "on_demand"; } }
  var apply = Reflect.apply, gopd = Object.getOwnPropertyDescriptor, Str = String, pf = parseFloat, abs = Math.abs, dnow = Date.now, DateC = Date;
  var D = W.document, always = mode === "always";
  function pr(c) { try { return c && c.prototype; } catch (e) { return null; } }
  function fn(p, n) { var f; try { f = p && p[n]; } catch (e) { f = null; } return typeof f === "function" ? f : null; }
  function getter(p, n) {
    var d = null, g;
    try { d = p ? gopd(p, n) : null; } catch (e) { d = null; }
    g = d && d.get;
    return function (o) { return g ? apply(g, o, []) : o[n]; };
  }
  function setter(p, n) {
    var d = null, s;
    try { d = p ? gopd(p, n) : null; } catch (e) { d = null; }
    s = d && d.set;
    return function (o, v) { if (s) { apply(s, o, [v]); } else { o[n] = v; } };
  }
  var ETp = pr(W.EventTarget), NDp = pr(W.Node), ELp = pr(W.Element), HEp = pr(W.HTMLElement) || ELp, DOp = pr(W.Document), CSp = pr(W.CSSStyleDeclaration), MOp = pr(W.MutationObserver), RCp = pr(W.DOMRectReadOnly);
  var fAdd = fn(ETp, "addEventListener"), fCreate = fn(DOp, "createElement"), fAttach = fn(ELp, "attachShadow"), fRect = fn(ELp, "getBoundingClientRect"),
      fSetAttr = fn(ELp, "setAttribute"), fAppend = fn(NDp, "appendChild"), fInsB = fn(NDp, "insertBefore"), fRemove = fn(NDp, "removeChild"),
      fShow = fn(HEp, "showPopover"), fHide = fn(HEp, "hidePopover"), fFromPts = fn(DOp, "elementsFromPoint"),
      fSetProp = fn(CSp, "setProperty"), fGetProp = fn(CSp, "getPropertyValue"), fObs = fn(MOp, "observe"),
      gcs = W.getComputedStyle, setT = W.setTimeout, MO = W.MutationObserver, Sheet = W.CSSStyleSheet;
  var gStyle = getter(HEp, "style"), gParent = getter(NDp, "parentNode"), gDocEl = getter(DOp, "documentElement"),
      gCW = getter(ELp, "clientWidth"), gCH = getter(ELp, "clientHeight"), sText = setter(NDp, "textContent"), gText = getter(NDp, "textContent"),
      rW = getter(RCp, "width"), rH = getter(RCp, "height"), rL = getter(RCp, "left"), rT = getter(RCp, "top"), rR = getter(RCp, "right"), rB = getter(RCp, "bottom");
  // isTrusted lives on the instance (unforgeable) in browsers: save its getter from a fresh event.
  var getTrusted = null;
  try {
    var e0 = new W.Event("x"), d0 = gopd(e0, "isTrusted") || gopd(pr(W.Event), "isTrusted");
    getTrusted = d0 && d0.get;
  } catch (e) { getTrusted = null; }
  if (!fAdd || !fCreate || !fAttach || !fAppend || !fRemove || !fInsB || !fSetAttr || !getTrusted) { return; }
  function trusted(e) { try { return apply(getTrusted, e, []) === true; } catch (x) { return false; } }
  function now() { return apply(dnow, DateC, []); }
  function add(o, t, f) { apply(fAdd, o, [t, f]); }
  function setA(o, k, v) { apply(fSetAttr, o, [k, v]); }
  function append(p, c) { return apply(fAppend, p, [c]); }
  function remove(p, c) { return apply(fRemove, p, [c]); }
  function sp(o, k, v) { var s = gStyle(o); if (s && fSetProp) { try { apply(fSetProp, s, [k, v, "important"]); } catch (e) { /* ignore */ } } }
  function gp(cs, k) { return fGetProp ? Str(apply(fGetProp, cs, [k])) : Str(cs[k]); }

  var CSS = ":host{all:initial}*{box-sizing:border-box}" +
    ".w{all:initial;position:fixed;right:12px;bottom:12px;width:28px;height:28px;font:13px/1.4 system-ui,sans-serif;color:var(--fg);" +
    "--bg:#fff;--fg:#1c1b1f;--mut:#5c5b61;--bd:#d0d0d6;--ac:#0b57d0}" +
    "@media(prefers-color-scheme:dark){.w{--bg:#1e1e22;--fg:#e6e6ea;--mut:#a0a0a8;--bd:#3a3a42;--ac:#8ab4f8}}" +
    ".b{font:600 12px/1 system-ui,sans-serif;width:28px;height:28px;border-radius:50%;border:1px solid var(--bd);background:var(--bg);color:var(--ac);cursor:pointer;opacity:.55;padding:0;display:block}" +
    ".b:hover,.b:focus-visible,.b[aria-expanded=true]{opacity:1}.b:focus-visible,.c:focus-visible{outline:2px solid var(--ac);outline-offset:2px}" +
    ".m{all:initial;position:fixed;right:12px;bottom:46px;margin:0;font:13px/1.4 system-ui,sans-serif;color:var(--fg);max-width:min(20rem,calc(100vw - 24px));max-height:60vh;overflow:auto;background:var(--bg);border:1px solid var(--bd);border-radius:8px;padding:6px;box-shadow:0 2px 12px rgba(0,0,0,.25)}" +
    ".t{margin:4px 6px 2px;color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.04em;overflow-wrap:anywhere}" +
    ".c{display:block;width:100%;text-align:left;font:inherit;color:var(--fg);background:none;border:0;border-radius:5px;padding:5px 8px;cursor:pointer}.c:hover{background:rgba(127,127,127,.18)}" +
    ".n{margin:4px 8px;color:var(--mut)}";
  var HOST_STYLE = ["all", "initial", "display", "block", "position", "fixed", "right", "0", "bottom", "0", "width", "0", "height", "0",
    "overflow", "visible", "z-index", "2147483647", "opacity", "1", "visibility", "visible", "pointer-events", "auto", "transform", "none",
    "filter", "none", "clip-path", "none", "mask", "none", "mix-blend-mode", "normal", "contain", "none"];
  var host = null, wrap = null, badge = null, menuEl = null, open = false, vis = false, openedAt = 0;
  var attachN = 0, attachWin = 0, retry = false, mo = null, moRoot = null;

  // Positional builder: no object-literal property is read, so Object.prototype pollution is inert.
  function h(tag, attrs, text, evs, kids) {
    var e = apply(fCreate, D, [tag]), i;
    for (i = 0; i < attrs.length; i += 2) { setA(e, attrs[i], attrs[i + 1]); }
    if (text !== null) { sText(e, text); }
    for (i = 0; i < evs.length; i += 2) { add(e, evs[i], evs[i + 1]); }
    for (i = 0; i < kids.length; i++) { append(e, kids[i]); }
    return e;
  }
  function pin() { for (var i = 0; i < HOST_STYLE.length; i += 2) { sp(host, HOST_STYLE[i], HOST_STYLE[i + 1]); } }
  function raise() {
    if (!fShow) { return; }
    if (fHide) { try { apply(fHide, wrap, []); } catch (e) { /* not open */ } }
    try { apply(fShow, wrap, []); } catch (e) { /* ignore */ }
    if (menuEl) { try { apply(fShow, menuEl, []); } catch (e) { /* ignore */ } }
  }
  // False when the page hides, fades, moves or covers the badge (or an ancestor) with styles.
  function intact(el, isBadge) {
    pin(); raise();
    try {
      if (typeof gcs === "function") {
        var cs = apply(gcs, W, [host]);
        if (!(pf(gp(cs, "opacity")) >= 1) || gp(cs, "transform") !== "none" || gp(cs, "filter") !== "none" || gp(cs, "clip-path") !== "none" ||
            gp(cs, "visibility") !== "visible" || gp(cs, "display") === "none" || gp(cs, "pointer-events") === "none") { return false; }
        if (!fShow) {
          var de = apply(gcs, W, [gDocEl(D)]);
          if (!(pf(gp(de, "opacity")) >= 1) || gp(de, "filter") !== "none" || gp(de, "transform") !== "none") { return false; }
        }
      }
      if (fRect) {
        var r = apply(fRect, el, []), rt = gDocEl(D);
        if (isBadge) {
          var cw = gCW(rt), ch = gCH(rt);
          if (abs(rW(r) - 28) > 2 || abs(rH(r) - 28) > 2 || abs(cw - rR(r) - 12) > 4 || abs(ch - rB(r) - 12) > 4) { return false; }
        }
        if (fFromPts) {
          var hits = apply(fFromPts, D, [(rL(r) + rR(r)) / 2, (rT(r) + rB(r)) / 2]);
          if (!hits || hits[0] !== host) { return false; }
        }
      }
    } catch (e) { return false; }
    return true;
  }
  function build() {
    host = apply(fCreate, D, ["div"]);
    var root = apply(fAttach, host, [{ mode: "closed" }]);
    try { var sh = new Sheet(); sh.replaceSync(CSS); root.adoptedStyleSheets = [sh]; }
    catch (e) { var s = h("style", nonce ? ["nonce", nonce] : [], CSS, [], []); append(root, s); }
    badge = h("button", ["type", "button", "class", "b", "data-k", "badge", "aria-haspopup", "true", "aria-expanded", "false"], "A", ["click", function (e) {
      if (trusted(e) && intact(badge, true)) { setOpen(!open); }
    }], []);
    wrap = h("div", fShow ? ["class", "w", "popover", "manual"] : ["class", "w"], null, [], [badge]);
    append(root, wrap);
    add(root, "keydown", function (e) { if (trusted(e) && e.key === "Escape" && open) { setOpen(false); try { badge.focus(); } catch (x) { /* ignore */ } } });
    pin();
  }
  function setOpen(v) { open = v; openedAt = v ? now() : 0; render(); }
  // Re-attach after the page drops the host, at most 20 times a second; past the cap a retry is
  // scheduled for when the window ends, so a page that removes it in a burst cannot leave it gone.
  function ensure() {
    var r = gDocEl(D);
    if (!host || !r || gParent(host) === r) { return; }
    var t = now();
    if (t - attachWin >= 1000) { attachWin = t; attachN = 0; }
    if (++attachN > 20) {
      if (!retry && typeof setT === "function") {
        retry = true;
        apply(setT, W, [function () { retry = false; if (vis) { ensure(); } }, 1000 - (t - attachWin) + 5]);
      }
      return;
    }
    append(r, host);
    pin(); raise();
  }
  function render() {
    var list = [], show, i, j, g;
    try { list = reg.commands(); } catch (e) { list = []; }
    show = always || list.length > 0;
    if (!show) {
      if (host && gParent(host)) { remove(gParent(host), host); }
      open = false; vis = false;
      return;
    }
    if (!host) { build(); }
    vis = true; ensure();
    setA(badge, "aria-expanded", open ? "true" : "false");
    setA(badge, "aria-label", "Argus userscript commands (" + list.length + ")");
    if (menuEl) { remove(wrap, menuEl); menuEl = null; }
    if (fShow) { try { apply(fShow, wrap, []); } catch (e) { /* already open */ } }
    if (!open) { return; }
    var kids = [], ids = [], names = [], groups = [];
    for (i = 0; i < list.length; i++) {
      var c = list[i], sid = Str(c.script);
      for (j = 0; j < ids.length; j++) { if (ids[j] === sid) { break; } }
      if (j === ids.length) { ids[j] = sid; names[j] = Str(c.scriptName || sid); groups[j] = []; }
      groups[j][groups[j].length] = c;
    }
    if (!ids.length) { kids[kids.length] = h("p", ["class", "n"], "No commands registered.", [], []); }
    for (j = 0; j < ids.length; j++) {
      kids[kids.length] = h("div", ["class", "t"], names[j], [], []);
      for (g = 0; g < groups[j].length; g++) { kids[kids.length] = item(groups[j][g], ids[j]); }
    }
    menuEl = h("div", fShow ? ["class", "m", "role", "menu", "aria-label", "Userscript commands", "popover", "manual"] : ["class", "m", "role", "menu", "aria-label", "Userscript commands"], null, [], kids);
    apply(fInsB, wrap, [menuEl, badge]);
    if (fShow) { try { apply(fShow, menuEl, []); } catch (e) { /* ignore */ } }
  }
  function item(c, sid) {
    var btn = h("button", ["type", "button", "class", "c", "data-k", "c-" + sid + "-" + c.id], null, ["click", function (e) {
      if (!trusted(e) || now() - openedAt < 400 || !intact(btn, false)) { return; }
      setOpen(false);
      try { reg.invoke(c.script, c.id); } catch (x) { /* ignore */ }
    }], [h("span", [], Str(c.caption), [], [])]);
    return btn;
  }
  function watch() {
    try {
      if (typeof MO !== "function" || !fObs || !gDocEl(D)) { return; }
      if (!mo) { mo = new MO(function () { if (vis) { watch(); ensure(); } }); apply(fObs, mo, [D, { childList: true }]); }
      var r = gDocEl(D);
      if (moRoot !== r) { moRoot = r; apply(fObs, mo, [r, { childList: true }]); }
    } catch (e) { /* ignore */ }
  }
  reg.subscribe(render);
  add(D, "click", function (e) { if (open && e.target !== host) { setOpen(false); } });
  add(D, "DOMContentLoaded", function () { if (vis) { watch(); ensure(); } });
  add(W, "load", function () { if (vis) { watch(); ensure(); } });
  add(W, "popstate", render); add(W, "hashchange", render); add(W, "pageshow", render);
  watch();
  render();
}

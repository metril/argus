/* On-demand userscript menu button. Inlined into the shared runtime closure (gm_shared.js), so the
   command registry is never reachable from page code: `reg` is a closure variable handed to this
   function once. It shows a small corner badge listing the GM_registerMenuCommand entries of the
   page's scripts, grouped by script, in a closed shadow root (no innerHTML, no inline handlers, no
   eval, no network).
   Hostile-page defences. The runtime installs before any page script, but the UI is built later,
   after page code may have hooked anything. So: every built-in used is captured here, at install,
   and called only through Reflect.apply; dynamic lists are null-prototype objects with a counter
   (an index write or push on an array walks Array.prototype, which a page can fill with setters);
   dictionaries handed to the platform are null-prototype with every member explicit; no property
   of an object literal that could be missing is read; clicks count only when a saved Event
   isTrusted getter says so; the host has inline !important styles; the badge and open menu are
   re-raised in the top layer before each click; a computed-style, geometry and hit-test check
   runs before each click; items ignore clicks for 400 ms after the menu opens and the badge for 300 ms
   after it appears or is re-attached (a page cannot make a user click what has just been put under
   the pointer).
   See docs/SCRIPT-POLICY.md. */
function (W, reg, mode, nonce) {
  "use strict";
  if (mode !== "always" && mode !== "on_demand") { return; }
  if (mode === "always") { try { if (W !== W.top) { mode = "on_demand"; } } catch (e) { mode = "on_demand"; } }
  var apply = Reflect.apply, gopd = Object.getOwnPropertyDescriptor, ObjCreate = Object.create, Str = String,
      pf = parseFloat, abs = Math.abs, max = Math.max, min = Math.min, dnow = Date.now, DateC = Date;
  var D = W.document, always = mode === "always";
  function pr(c) { try { return c && c.prototype; } catch (e) { return null; } }
  function fn(p, n) { var f; try { f = p && p[n]; } catch (e) { f = null; } return typeof f === "function" ? f : null; }
  function getter(p, n) {
    var d = null, g;
    try { d = p ? gopd(p, n) : null; } catch (e) { d = null; }
    g = d && d.get;
    return function (o) { return g ? apply(g, o, []) : o[n]; };
  }
  function setterOf(p, n) {
    var d = null;
    try { d = p ? gopd(p, n) : null; } catch (e) { d = null; }
    return d && d.set ? d.set : null;
  }
  function lst() { var l = ObjCreate(null); l.length = 0; return l; }
  function push(l, v) { var n = l.length; l[n] = v; l.length = n + 1; }
  var ETp = pr(W.EventTarget), NDp = pr(W.Node), ELp = pr(W.Element), HEp = pr(W.HTMLElement) || ELp, DOp = pr(W.Document), CSp = pr(W.CSSStyleDeclaration),
      MOp = pr(W.MutationObserver), RCp = pr(W.DOMRectReadOnly), EVp = pr(W.Event), KEp = pr(W.KeyboardEvent);
  var fAdd = fn(ETp, "addEventListener"), fCreate = fn(DOp, "createElement"), fAttach = fn(ELp, "attachShadow"), fRect = fn(ELp, "getBoundingClientRect"),
      fSetAttr = fn(ELp, "setAttribute"), fAppend = fn(NDp, "appendChild"), fInsB = fn(NDp, "insertBefore"), fRemove = fn(NDp, "removeChild"),
      fShow = fn(HEp, "showPopover"), fHide = fn(HEp, "hidePopover"), fFocus = fn(HEp, "focus"), fFromPts = fn(DOp, "elementsFromPoint"),
      fSetProp = fn(CSp, "setProperty"), fGetProp = fn(CSp, "getPropertyValue"), fObs = fn(MOp, "observe"),
      gcs = W.getComputedStyle, setT = W.setTimeout, MO = W.MutationObserver;
  var gStyle = getter(HEp, "style"), gParent = getter(NDp, "parentNode"), gDocEl = getter(DOp, "documentElement"), gBody = getter(DOp, "body"),
      gCompat = getter(DOp, "compatMode"), gCW = getter(ELp, "clientWidth"), gCH = getter(ELp, "clientHeight"), gKey = getter(KEp, "key"), gTarget = getter(EVp, "target"),
      rW = getter(RCp, "width"), rH = getter(RCp, "height"), rL = getter(RCp, "left"), rT = getter(RCp, "top"), rR = getter(RCp, "right"), rB = getter(RCp, "bottom");
  var sText = setterOf(NDp, "textContent");
  var vv = null, gIW = getter(W, "innerWidth"), gIH = getter(W, "innerHeight"), gVW = getter(null, "width"), gVH = getter(null, "height");
  try {
    if (W.visualViewport) { vv = W.visualViewport; gVW = getter(pr(W.VisualViewport), "width"); gVH = getter(pr(W.VisualViewport), "height"); }
  } catch (e) { vv = null; }
  // isTrusted lives on the instance (unforgeable) in browsers: save its getter from a fresh event.
  var getTrusted = null;
  try {
    var e0 = new W.Event("x"), d0 = gopd(e0, "isTrusted") || gopd(EVp, "isTrusted");
    getTrusted = d0 && d0.get;
  } catch (e) { getTrusted = null; }
  if (!fAdd || !fCreate || !fAttach || !fAppend || !fRemove || !fInsB || !fSetAttr || !getTrusted) { return; }
  // Dictionaries for the platform: null prototype, every member explicit.
  var SHADOW_INIT = ObjCreate(null);
  SHADOW_INIT.mode = "closed"; SHADOW_INIT.serializable = false; SHADOW_INIT.clonable = false; SHADOW_INIT.delegatesFocus = false; SHADOW_INIT.slotAssignment = "named";
  var OBS_INIT = ObjCreate(null);
  OBS_INIT.childList = true; OBS_INIT.attributes = false; OBS_INIT.characterData = false; OBS_INIT.subtree = false;
  OBS_INIT.attributeOldValue = false; OBS_INIT.characterDataOldValue = false;
  var NOARGS = [];
  function trusted(e) { try { return apply(getTrusted, e, NOARGS) === true; } catch (x) { return false; } }
  function now() { return apply(dnow, DateC, NOARGS); }
  function add(o, t, f) { apply(fAdd, o, [t, f]); }
  function setA(o, k, v) { apply(fSetAttr, o, [k, v]); }
  function append(p, c) { return apply(fAppend, p, [c]); }
  function remove(p, c) { return apply(fRemove, p, [c]); }
  function setText(e, t) { if (sText) { apply(sText, e, [t]); } else { e.textContent = t; } }
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
  var attachN = 0, attachWin = 0, retry = false, mo = null, moRoot = null, shownAt = 0;

  // Positional builder (`attrs`, `evs` are literal arrays, `kids` a literal array or a lst()).
  function h(tag, attrs, text, evs, kids) {
    var e = apply(fCreate, D, [tag]), i;
    for (i = 0; i < attrs.length; i += 2) { setA(e, attrs[i], attrs[i + 1]); }
    if (text !== null) { setText(e, text); }
    for (i = 0; i < evs.length; i += 2) { add(e, evs[i], evs[i + 1]); }
    for (i = 0; i < kids.length; i++) { append(e, kids[i]); }
    return e;
  }
  function pin() { for (var i = 0; i < HOST_STYLE.length; i += 2) { sp(host, HOST_STYLE[i], HOST_STYLE[i + 1]); } }
  function hideShow(el) {
    if (fHide) { try { apply(fHide, el, NOARGS); } catch (e) { /* not open */ } }
    try { apply(fShow, el, NOARGS); } catch (e) { /* ignore */ }
  }
  function raise() {
    if (!fShow) { return; }
    hideShow(wrap);
    if (menuEl) { hideShow(menuEl); }
  }
  // Candidate viewport sizes a fixed element may anchor to: the document's client size (excludes a
  // classic scrollbar; body in quirks mode), the window's inner size and, if present, the visual
  // viewport. On Chrome for Android, once the URL bar hides, fixed elements anchor to the larger
  // one. Each axis passes if any candidate matches; with no candidate it fails closed.
  function near(a, b) { return abs(a - b) <= 4; }
  function anchored(r) {
    var right = rR(r), bottom = rB(r), wOk = false, hOk = false, el = gCompat(D) === "BackCompat" ? gBody(D) : gDocEl(D);
    if (el) { wOk = near(gCW(el) - 12, right); hOk = near(gCH(el) - 12, bottom); }
    wOk = wOk || near(gIW(W) - 12, right); hOk = hOk || near(gIH(W) - 12, bottom);
    if (vv) { wOk = wOk || near(gVW(vv) - 12, right); hOk = hOk || near(gVH(vv) - 12, bottom); }
    return wOk && hOk;
  }
  // False when the page hides, fades, moves or covers the badge (or an ancestor) with styles.
  // Order matters: the page's state is READ first and judged, and only then do we pin our own
  // styles back (re-pinning first would erase a page's inline tampering before we looked at it).
  function intact(el, isBadge) {
    var ok = true;
    try {
      if (typeof gcs === "function") {
        var cs = apply(gcs, W, [host]);
        if (!(pf(gp(cs, "opacity")) >= 1) || gp(cs, "transform") !== "none" || gp(cs, "filter") !== "none" || gp(cs, "clip-path") !== "none" ||
            gp(cs, "visibility") !== "visible" || gp(cs, "display") === "none" || gp(cs, "pointer-events") === "none") { ok = false; }
        if (ok && !fShow) {
          var de = apply(gcs, W, [gDocEl(D)]);
          if (!(pf(gp(de, "opacity")) >= 1) || gp(de, "filter") !== "none" || gp(de, "transform") !== "none") { ok = false; }
        }
      }
      if (ok && isBadge && fRect) {
        var r0 = apply(fRect, el, NOARGS);
        if (abs(rW(r0) - 28) > 2 || abs(rH(r0) - 28) > 2 || !anchored(r0)) { ok = false; }
      }
    } catch (e) { ok = false; }
    pin();
    if (!ok) { return false; }
    raise();
    try {
      if (fRect) {
        var r = apply(fRect, el, NOARGS), l = rL(r), t = rT(r), rr = rR(r), b = rB(r);
        if (!isBadge && menuEl) {
          // The item may be scrolled partly out of the menu: test the visible part.
          var m = apply(fRect, menuEl, NOARGS);
          l = max(l, rL(m)); t = max(t, rT(m)); rr = min(rr, rR(m)); b = min(b, rB(m));
          if (!(rr > l) || !(b > t)) { return false; }
        }
        if (fFromPts) {
          var hits = apply(fFromPts, D, [(l + rr) / 2, (t + b) / 2]);
          if (!hits || !(hits.length > 0) || hits[0] !== host) { return false; }
        }
      }
    } catch (e) { return false; }
    return true;
  }
  function build() {
    host = apply(fCreate, D, ["div"]);
    var root = apply(fAttach, host, [SHADOW_INIT]);
    // A <style> in the closed root (nonce for CSP). Constructed stylesheets are not used: adopting
    // one converts a sequence through the page-hookable array iterator, which would hand it over.
    append(root, h("style", nonce ? ["nonce", nonce] : [], CSS, [], []));
    badge = h("button", ["type", "button", "class", "b", "data-k", "badge", "aria-haspopup", "true", "aria-expanded", "false"], "A", ["click", function (e) {
      if (trusted(e) && now() - shownAt >= 300 && intact(badge, true)) { setOpen(!open); }
    }], []);
    wrap = h("div", fShow ? ["class", "w", "popover", "manual"] : ["class", "w"], null, [], [badge]);
    append(root, wrap);
    add(root, "keydown", function (e) {
      if (trusted(e) && open && gKey(e) === "Escape") { setOpen(false); if (fFocus) { try { apply(fFocus, badge, NOARGS); } catch (x) { /* ignore */ } } }
    });
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
    shownAt = now();
    append(r, host);
    pin(); raise();
  }
  function render() {
    var list, show, i, j, g;
    try { list = reg.commands(); } catch (e) { list = null; }
    if (!list) { list = lst(); }
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
    if (fShow) { try { apply(fShow, wrap, NOARGS); } catch (e) { /* already open */ } }
    if (!open) { return; }
    var kids = lst(), ids = lst(), names = lst(), groups = lst();
    for (i = 0; i < list.length; i++) {
      var c = list[i], sid = Str(c.script);
      for (j = 0; j < ids.length; j++) { if (ids[j] === sid) { break; } }
      if (j === ids.length) { push(ids, sid); push(names, Str(c.scriptName || sid)); push(groups, lst()); }
      push(groups[j], c);
    }
    if (!ids.length) { push(kids, h("p", ["class", "n"], "No commands registered.", [], [])); }
    for (j = 0; j < ids.length; j++) {
      push(kids, h("div", ["class", "t"], names[j], [], []));
      for (g = 0; g < groups[j].length; g++) { push(kids, item(groups[j][g], ids[j])); }
    }
    menuEl = h("div", fShow ? ["class", "m", "role", "menu", "aria-label", "Userscript commands", "popover", "manual"] : ["class", "m", "role", "menu", "aria-label", "Userscript commands"], null, [], kids);
    apply(fInsB, wrap, [menuEl, badge]);
    if (fShow) { try { apply(fShow, menuEl, NOARGS); } catch (e) { /* ignore */ } }
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
      if (!mo) { mo = new MO(function () { if (vis) { watch(); ensure(); } }); apply(fObs, mo, [D, OBS_INIT]); }
      var r = gDocEl(D);
      if (moRoot !== r) { moRoot = r; apply(fObs, mo, [r, OBS_INIT]); }
    } catch (e) { /* ignore */ }
  }
  reg.subscribe(render);
  add(D, "click", function (e) { if (open && gTarget(e) !== host) { setOpen(false); } });
  add(D, "DOMContentLoaded", function () { if (vis) { watch(); ensure(); } });
  add(W, "load", function () { if (vis) { watch(); ensure(); } });
  add(W, "popstate", render); add(W, "hashchange", render); add(W, "pageshow", render);
  watch();
  render();
}

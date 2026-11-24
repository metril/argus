/* On-demand userscript menu button. Inlined into the shared runtime closure (gm_shared.js), so the
   command registry is never reachable from page code: `reg` is a closure variable handed to this
   function once. It shows a small corner badge listing the GM_registerMenuCommand entries of the
   page's scripts, grouped by script, in a closed shadow root (no innerHTML, no inline handlers, no
   eval, no network). Defences against a hostile page (clickjacking): inline !important styles on
   the host, top-layer rendering, a computed-style/geometry check before every click, trusted
   clicks only, and items ignored for 400 ms after the menu opens. See docs/SCRIPT-POLICY.md. */
function (W, reg, mode, nonce) {
  "use strict";
  var D = W.document;
  if (mode !== "always" && mode !== "on_demand") { return; }
  if (mode === "always") { try { if (W !== W.top) { mode = "on_demand"; } } catch (e) { mode = "on_demand"; } }
  var always = mode === "always", now = Date.now.bind(Date);
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
  var HOST_STYLE = [["all", "initial"], ["display", "block"], ["position", "fixed"], ["right", "0"], ["bottom", "0"], ["width", "0"], ["height", "0"],
    ["overflow", "visible"], ["z-index", "2147483647"], ["opacity", "1"], ["visibility", "visible"], ["pointer-events", "auto"], ["transform", "none"],
    ["filter", "none"], ["clip-path", "none"], ["mask", "none"], ["mix-blend-mode", "normal"], ["contain", "none"]];
  var host = null, root = null, wrap = null, badge = null, menuEl = null, open = false, vis = false, openedAt = 0;
  var attachN = 0, attachWin = 0, mo = null, moRoot = null;

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
  function pin() {
    if (!host || !host.style || !host.style.setProperty) { return; }
    for (var i = 0; i < HOST_STYLE.length; i++) { try { host.style.setProperty(HOST_STYLE[i][0], HOST_STYLE[i][1], "important"); } catch (e) { /* ignore */ } }
  }
  function top(el) {
    if (typeof el.showPopover === "function") {
      try { if (!el.matches || !el.matches(":popover-open")) { el.showPopover(); } } catch (e) { /* ignore */ }
    }
  }
  // False when the page hides, fades, moves or covers the badge (or an ancestor) with styles.
  function intact() {
    pin();
    if (typeof W.getComputedStyle !== "function") { return true; }
    try {
      var cs = W.getComputedStyle(host), de = D.documentElement && W.getComputedStyle(D.documentElement);
      var bad = function (s) { return !s || parseFloat(s.opacity) < 1 || (s.transform && s.transform !== "none") || (s.filter && s.filter !== "none") ||
        s.visibility === "hidden" || s.display === "none" || (s.clipPath && s.clipPath !== "none") || (s.pointerEvents && s.pointerEvents === "none"); };
      if (bad(cs) || (de && (parseFloat(de.opacity) < 1 || (de.filter && de.filter !== "none") || (de.transform && de.transform !== "none")))) { return false; }
      if (badge.getBoundingClientRect) {
        var r = badge.getBoundingClientRect(), iw = W.innerWidth, ih = W.innerHeight;
        if (iw && ih && (Math.abs(r.width - 28) > 2 || Math.abs(r.height - 28) > 2 || Math.abs(iw - r.right - 12) > 20 || Math.abs(ih - r.bottom - 12) > 20)) { return false; }
      }
    } catch (e) { return false; }
    return true;
  }
  function build() {
    host = D.createElement("div");
    root = host.attachShadow({ mode: "closed" });
    try { var sh = new W.CSSStyleSheet(); sh.replaceSync(CSS); root.adoptedStyleSheets = [sh]; }
    catch (e) { var s = D.createElement("style"); if (nonce) { s.setAttribute("nonce", nonce); } s.textContent = CSS; root.appendChild(s); }
    badge = h("button", { type: "button", class: "b", "data-k": "badge", "aria-haspopup": "true", "aria-expanded": "false", on: { click: function (e) {
      if (e.isTrusted && intact()) { setOpen(!open); }
    } } }, []);
    badge.textContent = "A";
    wrap = h("div", { class: "w" }, [badge]);
    if (typeof wrap.showPopover === "function") { wrap.setAttribute("popover", "manual"); }
    root.appendChild(wrap);
    root.addEventListener("keydown", function (e) { if (e.key === "Escape" && open) { setOpen(false); try { badge.focus(); } catch (x) { /* ignore */ } } });
    pin();
  }
  function setOpen(v) { open = v; openedAt = v ? now() : 0; render(); }
  // Re-attach after the page drops the host; at most about 20 times a second so a page that keeps
  // removing it cannot make us spin.
  function ensure() {
    var r = D.documentElement;
    if (!host || !r || host.parentNode === r) { return; }
    var t = now();
    if (t - attachWin >= 1000) { attachWin = t; attachN = 0; }
    if (++attachN > 20) { return; }
    r.appendChild(host);
    pin(); top(wrap); if (menuEl) { top(menuEl); }
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
    top(wrap);
    if (!open) { return; }
    var kids = [], groups = {}, order = [];
    list.forEach(function (c) { var g = String(c.script); if (!groups[g]) { groups[g] = []; order.push(g); } groups[g].push(c); });
    if (!order.length) { kids.push(h("p", { class: "n", text: "No commands registered." })); }
    order.forEach(function (g) {
      kids.push(h("div", { class: "t", text: String(groups[g][0].scriptName || g) }));
      groups[g].forEach(function (c) {
        kids.push(h("button", { type: "button", class: "c", "data-k": "c-" + g + "-" + c.id, on: { click: function (e) {
          if (!e.isTrusted || now() - openedAt < 400 || !intact()) { return; }
          setOpen(false);
          try { reg.invoke(c.script, c.id); } catch (x) { /* ignore */ }
        } } }, [h("span", { text: String(c.caption) })]));
      });
    });
    menuEl = h("div", { class: "m", role: "menu", "aria-label": "Userscript commands" }, kids);
    if (typeof menuEl.showPopover === "function") { menuEl.setAttribute("popover", "manual"); }
    wrap.insertBefore(menuEl, badge);
    top(menuEl);
  }
  function watch() {
    try {
      if (!W.MutationObserver || !D.documentElement) { return; }
      if (!mo) { mo = new W.MutationObserver(function () { if (vis) { watch(); ensure(); } }); mo.observe(D, { childList: true }); }
      if (moRoot !== D.documentElement) { moRoot = D.documentElement; mo.observe(moRoot, { childList: true }); }
    } catch (e) { /* ignore */ }
  }
  reg.subscribe(render);
  D.addEventListener("click", function (e) { if (open && e.target !== host) { setOpen(false); } }, true);
  ["DOMContentLoaded", "load"].forEach(function (n) { D.addEventListener(n, function () { if (vis) { watch(); ensure(); } }); });
  ["popstate", "hashchange", "pageshow"].forEach(function (n) { W.addEventListener(n, function () { render(); }); });
  watch();
  render();
}

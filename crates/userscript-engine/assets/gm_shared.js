/* Installs the GM runtime once per document. ONE function expression, called with `window`
 * by the shared runtime script (bundle::runtime_script), which substitutes the text of gm.js
 * for the placeholder below. Holds no secret: capability tokens arrive only in the per-document bundles. */
function (W) {
  "use strict";
  var S = W.Symbol, K = S.for("adblock.userscript.runtime"), D = Object.defineProperty;
  try { if (Object.getOwnPropertyDescriptor(W, K)) { return; } } catch (e) { /* ignore */ }
  var run = /*RUNTIME*/null;
  var mountMenu = /*MENU*/null;
  // The command registry every script of the page registers into.
  // Lists are null-prototype objects with a `length` counter, never arrays: an index write on an
  // array walks Array.prototype (a page can install setters there), and push is hookable too.
  var ObjCreate = Object.create, Str = String;
  function lst() { var l = ObjCreate(null); l.length = 0; return l; }
  var menu = lst(), subs = lst(), seq = 0;
  function at(i) {
    for (var k = i; k < menu.length - 1; k++) { menu[k] = menu[k + 1]; }
    menu[menu.length - 1] = undefined;
    menu.length = menu.length - 1;
  }
  function find(script, id) {
    for (var i = 0; i < menu.length; i++) { if (menu[i].script === script && menu[i].id === id) { return i; } }
    return -1;
  }
  var SH = {
    next: function () { return ++seq; },
    add: function (e, replace) {
      if (replace) { var i = find(e.script, e.id); if (i >= 0) { at(i); } }
      menu[menu.length] = e;
      menu.length = menu.length + 1;
    },
    remove: function (script, id) { var i = find(script, id); if (i < 0) { return false; } at(i); return true; },
    changed: function () { for (var i = 0; i < subs.length; i++) { try { subs[i](); } catch (e) { /* ignore */ } } },
    // Bound to a live browser-extension session: commands are synced to the proxy and triggered
    // from the extension's popup instead of an in-page button (see docs/USERSCRIPT-PROTOCOL.md 8).
    ext: false,
    // Mount the in-page button after all (the proxy says the extension is not serving this page).
    fallback: function () { },
    // This script's own commands as fresh null-prototype records (what menu/sync sends).
    list: function (script) {
      var o = lst();
      for (var i = 0; i < menu.length; i++) {
        var m = menu[i];
        if (m.script !== script) { continue; }
        var e = ObjCreate(null);
        e.id = Str(m.id); e.name = Str(m.caption); e.accessKey = Str(m.accessKey || ""); e.title = Str(m.title || ""); e.autoClose = m.autoClose !== false;
        o[o.length] = e; o.length = o.length + 1;
      }
      return o;
    },
    // Ids travel as text: match them as text (a generated id is a number).
    invoke: function (script, id) {
      for (var i = 0; i < menu.length; i++) {
        if (menu[i].script === script && Str(menu[i].id) === Str(id)) { menu[i].run(); return true; }
      }
      return false;
    }
  };
  // The registry is NOT published on the window: page code could list and invoke commands. It stays
  // in this closure and is handed once to the menu button below. commands() returns a fresh
  // null-prototype list of fresh objects (no run callbacks).
  var reg = {
    commands: function () {
      var o = lst();
      for (var i = 0; i < menu.length; i++) {
        var m = menu[i];
        o[i] = { script: m.script, scriptName: m.scriptName, id: m.id, caption: m.caption, accessKey: m.accessKey };
        o.length = i + 1;
      }
      return o;
    },
    invoke: function (s, id) { var i = find(s, id); if (i < 0) { return false; } menu[i].run(); return true; },
    subscribe: function (f) { if (typeof f === "function") { subs[subs.length] = f; subs.length = subs.length + 1; } }
  };
  var c = W.document && W.document.currentScript, mode = "off", nonce = "";
  try { if (c) { mode = c.getAttribute("data-m") || "off"; nonce = c.nonce || c.getAttribute("nonce") || ""; } } catch (e) { /* ignore */ }
  var mounted = false;
  function mount() {
    if (mounted) { return; }
    mounted = true;
    try { mountMenu(W, reg, mode, nonce); } catch (e) { /* the menu is optional */ }
  }
  // `ext:<mode>`: the document is served by a live extension session. No button unless the
  // proxy later says otherwise (a page that forges the attribute only hides its own button).
  if (mode.slice(0, 4) === "ext:") { SH.ext = true; mode = mode.slice(4); SH.fallback = mount; }
  else { mount(); }
  try {
    D(W, K, { value: function (cfg, entries) { return run(cfg, entries, W, SH); }, enumerable: false, configurable: false, writable: false });
  } catch (e) { /* ignore */ }
  if (c && c.parentNode) { try { c.parentNode.removeChild(c); } catch (e) { /* ignore */ } }
}

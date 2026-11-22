/* Installs the GM runtime once per document. ONE function expression, called with `window`
 * by the shared runtime script (bundle::runtime_script), which substitutes the text of gm.js
 * for the placeholder below. Holds no secret: capability tokens arrive only in the per-document bundles. */
function (W) {
  "use strict";
  var S = W.Symbol, K = S.for("adblock.userscript.runtime"), D = Object.defineProperty;
  try { if (Object.getOwnPropertyDescriptor(W, K)) { return; } } catch (e) { /* ignore */ }
  var run = /*RUNTIME*/null;
  // The command registry every script of the page registers into and the in-page panel reads.
  var menu = [], subs = [], seq = 0;
  var SH = {
    menu: menu,
    next: function () { return ++seq; },
    changed: function () { for (var i = 0; i < subs.length; i++) { try { subs[i](); } catch (e) { /* ignore */ } } }
  };
  try {
    D(W, S.for("adblock.userscript.menu"), {
      value: Object.freeze({
        commands: function () {
          var o = [];
          for (var i = 0; i < menu.length; i++) {
            var m = menu[i];
            o.push({ script: m.script, scriptName: m.scriptName, id: m.id, caption: m.caption, accessKey: m.accessKey });
          }
          return o;
        },
        invoke: function (s, id) {
          for (var i = 0; i < menu.length; i++) { if (menu[i].script === s && menu[i].id === id) { menu[i].run(); return true; } }
          return false;
        },
        subscribe: function (f) { if (typeof f === "function") { subs.push(f); } }
      }),
      enumerable: false, configurable: false, writable: false
    });
  } catch (e) { /* a hostile page may have claimed it; commands then just do not show */ }
  try {
    D(W, K, { value: function (cfg, entries) { return run(cfg, entries, W, SH); }, enumerable: false, configurable: false, writable: false });
  } catch (e) { /* ignore */ }
  var c = W.document && W.document.currentScript;
  if (c && c.parentNode) { try { c.parentNode.removeChild(c); } catch (e) { /* ignore */ } }
}

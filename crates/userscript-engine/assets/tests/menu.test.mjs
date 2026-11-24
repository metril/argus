// The on-demand menu button (assets/menu.js, inlined in the shared runtime closure) against the
// real GM registration path, with a prototype-based fake DOM. The fake is itself "trap clean": all
// of its state lives in null-prototype lists and it never calls an array method or reads a property
// that Object.prototype could supply, so the booby-trap test can tell runtime hits from fake hits.
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeEnv, runScript } from "./harness.mjs";

let off = 0;
const realNow = Date.now;
Date.now = () => realNow() + off;
const advance = (ms) => { off += ms; };

const ocreate = Object.create, okeys = Object.keys;
const nul = () => ocreate(null);
const nd = (o) => Object.assign(Object.create(null), o);
const mkList = () => { const l = nul(); l.length = 0; return l; };
const lpush = (l, v) => { const n = l.length; l[n] = v; l.length = n + 1; };
const TR = Symbol("trusted"), KY = Symbol("key");
function trustedGetter() { if (!(TR in this)) throw new TypeError("Illegal invocation"); return this[TR]; }
class TEvent {
  constructor(trusted) { Object.defineProperty(this, "isTrusted", nd({ get: trustedGetter })); this[TR] = trusted === true; }
  get target() { return this.tg || null; }
}
class KEvent extends TEvent {
  constructor(trusted, key) { super(trusted); this[KY] = key; }
  get key() { if (!(KY in this)) throw new TypeError("Illegal invocation"); return this[KY]; }
}
class MEvent extends TEvent { get button() { return 0; } }
class CSD {
  constructor(v) { this.s = nul(); this.v = nul(); if (v) { const ks = okeys(v); for (let i = 0; i < ks.length; i++) this.v[ks[i]] = v[ks[i]]; } }
  setProperty(k, v, p) { this.s[k] = [v, p]; }
  getPropertyValue(k) { const x = this.v[k]; return x === undefined ? "" : x; }
}
class SS { replaceSync(c) { this.css = c; } }
class Rect {
  constructor(r) { this.r = r; }
  get width() { return this.r.width; } get height() { return this.r.height; }
  get left() { return this.r.left; } get top() { return this.r.top; }
  get right() { return this.r.right; } get bottom() { return this.r.bottom; }
}
class ET {
  addEventListener(t, f) { const m = this.l || (this.l = nul()); const a = m[t] || (m[t] = mkList()); lpush(a, f); }
}
function attach(p, c) { if (c.pn) detach(c.pn, c); lpush(p.ch, c); c.pn = p; p.appends = (p.appends || 0) + 1; }
function detach(p, c) {
  let i = 0;
  while (i < p.ch.length && p.ch[i] !== c) i++;
  if (i === p.ch.length) return;
  for (let k = i; k < p.ch.length - 1; k++) p.ch[k] = p.ch[k + 1];
  p.ch[p.ch.length - 1] = undefined; p.ch.length--; c.pn = null;
}
class Nd extends ET {
  constructor() { super(); this.ch = mkList(); this.pn = null; }
  get parentNode() { return this.pn; }
  get textContent() { return this.tx === undefined ? "" : this.tx; }
  set textContent(v) { this.tx = v; }
  appendChild(c) { attach(this, c); return c; }
  removeChild(c) { detach(this, c); return c; }
  insertBefore(c, ref) {
    if (c.pn) detach(c.pn, c);
    let i = 0;
    while (i < this.ch.length && this.ch[i] !== ref) i++;
    for (let k = this.ch.length; k > i; k--) this.ch[k] = this.ch[k - 1];
    this.ch[i] = c; this.ch.length = this.ch.length + 1; c.pn = this; this.appends = (this.appends || 0) + 1;
    return c;
  }
}
class SR extends Nd {
  get adoptedStyleSheets() { return this.ss; }
  set adoptedStyleSheets(v) { this.ss = v; }
}
class El extends Nd {
  get style() { return this.sx; }
  get clientWidth() { return this.cw; }
  get clientHeight() { return this.chh; }
  setAttribute(n, v) { this.at[n] = String(v); }
  getAttribute(n) { return n in this.at ? this.at[n] : null; }
  attachShadow(init) { this.shadowInit = init; this.shadow = new SR(); return this.shadow; }
  showPopover() { this.popped = (this.popped || 0) + 1; }
  hidePopover() { this.hid = (this.hid || 0) + 1; }
  focus() { this.focused = true; }
  getBoundingClientRect() { return new Rect(this.rect || { width: 28, height: 28, left: 984, top: 728, right: 1012, bottom: 756 }); }
}
class N extends El {
  constructor(tag) { super(); this.tag = tag; this.at = nul(); this.sx = new CSD(); this.popped = 0; this.cw = 0; this.chh = 0; }
  get attrs() { return this.at; }
  fire(t, ev) { const a = this.l && this.l[t]; if (a) for (let i = 0; i < a.length; i++) a[i](ev); }
}
const fire = (n, t, ev) => { const a = n.l && n.l[t]; if (a) for (let i = 0; i < a.length; i++) a[i](ev); };
const all = (n) => { const o = [n]; for (let i = 0; i < n.ch.length; i++) o.push(...all(n.ch[i])); return o; };
const kidsOf = (n) => { const o = []; for (let i = 0; i < n.ch.length; i++) o.push(n.ch[i]); return o; };
const kq = (n, key) => all(n).find((x) => x.at && x.at["data-k"] === key);
const cls = (n, c) => all(n).find((x) => x.at && x.at.class === c);

const run = (env, opts) => new Promise((resolve) => runScript(env, opts, function (api) { resolve(api); }));
const GR = ["gm_registermenucommand", "gm_unregistermenucommand"];
const GOOD = { opacity: "1", transform: "none", filter: "none", visibility: "visible", display: "block", "clip-path": "none", "pointer-events": "auto" };

function page(mode) {
  const env = makeEnv();
  const root = new N("html");
  root.cw = 1024; root.chh = 768;
  const W = env.W;
  Object.assign(W, { EventTarget: ET, Node: Nd, Element: El, HTMLElement: El, ShadowRoot: SR, CSSStyleDeclaration: CSD, CSSStyleSheet: SS, DOMRectReadOnly: Rect, Event: TEvent, KeyboardEvent: KEvent, MouseEvent: MEvent });
  W.Document.prototype.createElement = (t) => new N(t);
  W.Document.prototype.elementsFromPoint = () => env.hits();
  Object.defineProperty(W.Document.prototype, "documentElement", { get() { return this.__root; }, set() {}, configurable: true });
  Object.defineProperty(W.Document.prototype, "compatMode", { get() { return this.__compat || "CSS1Compat"; }, set() {}, configurable: true });
  Object.defineProperty(W.Document.prototype, "body", { get() { return this.__body; }, set() {}, configurable: true });
  env.document.__root = root;
  env.document.currentScript = { nonce: "n1", getAttribute: (n) => (n === "data-m" ? mode : null) };
  W.top = W;
  env.cs = new CSD(GOOD);
  W.getComputedStyle = (el) => {
    const c = new CSD(), v = env.cs.v, ks = okeys(v);
    for (let i = 0; i < ks.length; i++) c.v[ks[i]] = v[ks[i]];
    const s = el && el.sx && el.sx.s, is = s ? okeys(s) : [];
    for (let i = 0; i < is.length; i++) c.v[is[i]] = s[is[i]][0];
    return c;
  };
  env.tamper = (k, v) => { hostOf(env).sx.s[k] = [v, "important"]; };
  env.timers = [];
  W.setTimeout = (f, ms) => env.timers.push([f, ms]);
  const mos = [];
  env.MO = W.MutationObserver = class { constructor(cb) { this.cb = cb; this.targets = []; this.opts = []; mos.push(this); } observe(t, o) { this.targets.push(t); this.opts.push(o); } };
  env.hits = () => [root.ch[0]];
  env.fireW = (t) => { const a = W.l && W.l[t]; if (a) for (let i = 0; i < a.length; i++) a[i]({}); };
  env.mutate = () => mos.forEach((m) => m.cb([]));
  env.mos = mos;
  env.root = root;
  return env;
}
const T = () => new TEvent(true), U = () => new TEvent(false);
const hostOf = (env) => env.root.ch[0];

test("on_demand: nothing without commands; badge appears on first command and goes on unregister", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR, name: "S One" });
  assert.equal(env.root.ch.length, 0);
  const id = api.GM_registerMenuCommand("Do it", () => {});
  assert.equal(env.root.ch.length, 1);
  const sh = hostOf(env).shadow;
  assert.match(kq(sh, "badge").at["aria-label"], /\(1\)/);
  assert.ok(hostOf(env).sx.s.opacity[1] === "important" && hostOf(env).sx.s["pointer-events"][0] === "auto", "inline !important host styles");
  assert.ok(cls(sh, "w").popped > 0, "badge is in the top layer");
  assert.equal(Object.getPrototypeOf(hostOf(env).shadowInit), null);
  assert.deepEqual(Object.keys(hostOf(env).shadowInit).sort(), ["clonable", "delegatesFocus", "mode", "serializable", "slotAssignment"]);
  assert.equal(sh.ss, undefined, "no constructed stylesheet is adopted");
  const st0 = all(sh).find((n) => n.tag === "style");
  assert.ok(st0 && st0.at.nonce === "n1" && st0.textContent.includes(".w{"), "nonce'd <style> inside the closed root");
  assert.equal(env.mos[0].opts[0].childList, true);
  assert.equal(Object.getPrototypeOf(env.mos[0].opts[0]), null);
  api.GM_unregisterMenuCommand(id);
  assert.equal(env.root.ch.length, 0, "unregister removes the button");
  api.GM_registerMenuCommand("Again", () => {});
  assert.equal(env.root.ch.length, 1);
});

test("off (no data-m): nothing is ever shown", async () => {
  const env = page(null);
  const api = await run(env, { grants: GR });
  api.GM_registerMenuCommand("x", () => {});
  assert.equal(env.root.ch.length, 0);
});

test("grouped by script; synthetic/fake clicks, early clicks, tampered styles and covered badge are ignored", async () => {
  const env = page("on_demand");
  const a = await run(env, { grants: GR, id: "s1", name: "First" });
  const b = await run(env, { grants: GR, id: "s2", name: "Second" });
  const hits = [];
  a.GM_registerMenuCommand("A1", () => hits.push("a1"));
  b.GM_registerMenuCommand("B1", () => hits.push("b1"));
  const idB2 = b.GM_registerMenuCommand("B2", () => hits.push("b2"));
  const sh = hostOf(env).shadow;
  const badge = kq(sh, "badge");
  badge.fire("click", U());
  badge.fire("click", { isTrusted: true }); // a plain object: the saved getter refuses it
  assert.equal(badge.at["aria-expanded"], "false");
  env.tamper("opacity", "0.01");
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "false", "faded badge ignores clicks");
  env.hits = () => [{}, hostOf(env)];
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "false", "covered badge ignores clicks");
  env.hits = () => [hostOf(env)];
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "true");
  const menu = cls(sh, "m");
  assert.equal(menu.at.popover, "manual");
  assert.ok(menu.popped > 0, "open menu is in the top layer");
  assert.deepEqual(all(sh).filter((n) => n.at && n.at.class === "t").map((n) => n.textContent), ["First", "Second"]);
  const item = () => kq(sh, "c-s2-" + idB2);
  item().fire("click", T());
  assert.deepEqual(hits, [], "ignored within 400 ms of opening");
  advance(450);
  item().fire("click", U());
  item().fire("click", { isTrusted: true });
  assert.deepEqual(hits, []);
  env.tamper("transform", "scale(2)");
  item().fire("click", T());
  assert.deepEqual(hits, [], "transformed host ignored");
  // the item's visible part is what is hit-tested: scrolled fully out of the menu box it is ignored
  item().rect = { width: 28, height: 20, left: 984, top: 100, right: 1012, bottom: 120 };
  item().fire("click", T());
  assert.deepEqual(hits, [], "item outside the menu's visible box ignored");
  item().rect = undefined;
  item().fire("click", T());
  assert.deepEqual(hits, ["b2"]);
  assert.ok(menu.hid > 0, "re-raised (hide then show) before acting");
  assert.equal(badge.at["aria-expanded"], "false", "menu closes after a command");
});

test("badge moved or resized is not clickable; a classic scrollbar's width is tolerated; quirks mode uses body", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR });
  api.GM_registerMenuCommand("x", () => {});
  const badge = kq(hostOf(env).shadow, "badge");
  badge.rect = { width: 400, height: 400, left: 0, top: 0, right: 1012, bottom: 756 };
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "false");
  env.root.cw = 1009; // scrollbar: clientWidth is 15px narrower than innerWidth and the badge moves with it
  badge.rect = { width: 28, height: 28, left: 969, top: 728, right: 997, bottom: 756 };
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "true");
  badge.fire("click", T());
  badge.rect = { width: 28, height: 28, left: 984, top: 728, right: 1012, bottom: 756 };
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "false", "off by the scrollbar width: ignored");
  // BackCompat: the viewport is body.clientWidth/Height, not documentElement's
  env.root.cw = 5; env.root.chh = 5;
  const body = new N("body"); body.cw = 1024; body.chh = 768;
  env.document.__body = body; env.document.__compat = "BackCompat";
  badge.rect = { width: 28, height: 28, left: 984, top: 728, right: 1012, bottom: 756 };
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "true");
  // no viewport element at all: fail closed
  badge.fire("click", T()); // closes it
  env.document.__body = null;
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "false", "unknown viewport refuses the click");
  // an empty hit-test list is a failure, not a pass
  env.document.__compat = "CSS1Compat"; env.root.cw = 1024; env.root.chh = 768;
  env.hits = () => [];
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "false");
});

test("always: top frame shows with no commands; frames behave like on_demand", async () => {
  const env = page("always");
  await run(env, { grants: GR });
  assert.equal(env.root.ch.length, 1);
  kq(hostOf(env).shadow, "badge").fire("click", T());
  assert.ok(all(hostOf(env).shadow).some((n) => n.textContent === "No commands registered."));
  const fr = page("always");
  fr.W.top = {};
  const api = await run(fr, { grants: GR });
  assert.equal(fr.root.ch.length, 0);
  api.GM_registerMenuCommand("x", () => {});
  assert.equal(fr.root.ch.length, 1);
});

test("SPA: re-attached on history events and root replacement; capped at 20/s with a retry at the window end", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR });
  api.GM_registerMenuCommand("X", () => {});
  const host = hostOf(env);
  env.root.removeChild(host);
  env.fireW("popstate");
  assert.equal(hostOf(env), host);
  assert.ok(env.mos[0].targets.includes(env.root));
  const root2 = new N("html");
  env.document.__root = root2;
  env.mutate();
  assert.equal(host.parentNode, root2);
  assert.ok(env.mos[0].targets.includes(root2));
  advance(1100);
  root2.appends = 0;
  for (let i = 0; i < 100; i++) { if (host.parentNode) root2.removeChild(host); env.mutate(); }
  assert.ok(root2.appends <= 20, "appends " + root2.appends);
  assert.ok(root2.appends >= 10);
  assert.equal(host.parentNode, null, "capped: detached for now");
  assert.ok(env.timers.length >= 1, "retry scheduled");
  advance(1100);
  env.timers.forEach(([f]) => f());
  assert.equal(host.parentNode, root2, "the retry re-attaches it");
});

test("page code cannot list or invoke commands: no registry on the window", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR });
  let hit = 0;
  api.GM_registerMenuCommand("secret", () => hit++);
  assert.equal(env.W[env.W.Symbol.for("adblock.userscript.menu")], undefined);
  const seen = [];
  const walk = (o, d) => {
    if (!o || (typeof o !== "object" && typeof o !== "function") || d > 2) return;
    for (const k of Reflect.ownKeys(o)) {
      let v; try { v = o[k]; } catch { continue; }
      if (v && (typeof v === "object" || typeof v === "function")) {
        if (["commands", "invoke", "subscribe"].some((n) => typeof v[n] === "function")) seen.push(String(k));
        if (typeof v === "object") walk(v, d + 1);
      }
    }
  };
  walk(env.W, 0);
  walk(env.document, 0);
  assert.deepEqual(seen, []);
  assert.equal(hit, 0);
});

// ---- the acceptance gate: booby-trap everything the page could hook, then use the UI ------------

const rApply = Reflect.apply, rDefine = Object.defineProperty, origPush = Array.prototype.push;

function boobyTraps(st, extra) {
  const rec = (what) => { if (st.armed) { st.armed = false; rApply(origPush, st.hits, [what]); st.armed = true; } };
  const replace = (obj, key, desc) => {
    const old = Object.getOwnPropertyDescriptor(obj, key);
    rDefine(obj, key, nd({ ...desc, configurable: true }));
    st.undo.push(() => { if (old) rDefine(obj, key, nd(old)); else delete obj[key]; });
  };
  const wrapMember = (obj, key, label) => {
    const d = Object.getOwnPropertyDescriptor(obj, key);
    if (!d || key === "constructor") return;
    if (d.get || d.set) {
      replace(obj, key, {
        get: d.get ? function () { rec(label + "." + String(key) + " get"); return rApply(d.get, this, []); } : undefined,
        set: d.set ? function (v) { rec(label + "." + String(key) + " set"); rApply(d.set, this, [v]); } : undefined,
      });
    } else if (typeof d.value === "function") {
      replace(obj, key, { value: function (...a) { rec(label + "." + String(key)); return rApply(d.value, this, a); }, writable: true, enumerable: d.enumerable });
    }
  };
  // Object.prototype: names the runtime reads off dictionaries, descriptors and options.
  for (const name of ["mode", "serializable", "clonable", "delegatesFocus", "slotAssignment", "childList", "attributes", "characterData", "subtree",
    "attributeOldValue", "characterDataOldValue", "attributeFilter", "value", "writable", "enumerable", "configurable", "get", "set", "capture", "once",
    "passive", "signal", "text", "on", "popover", "class", "handleEvent", "then", "id", "caption", "script", "scriptName", "run", "accessKey", "key", "target"]) {
    replace(Object.prototype, name, {
      get() { rec("Object.prototype." + name + " get"); return undefined; },
      set(v) { rec("Object.prototype." + name + " set"); rDefine(this, name, nd({ value: v, writable: true, enumerable: true, configurable: true })); },
    });
  }
  for (const name of ["id", "accessKey"]) {
    replace(String.prototype, name, { get() { rec("String.prototype." + name + " get"); return undefined; }, set() { rec("String.prototype." + name + " set"); } });
  }
  // Array.prototype: indices 0-50 (getter and setter), every method, the iterator.
  for (let i = 0; i <= 50; i++) {
    replace(Array.prototype, String(i), {
      get() { rec("Array.prototype[" + i + "] get"); return undefined; },
      set(v) { rec("Array.prototype[" + i + "] set"); rDefine(this, String(i), nd({ value: v, writable: true, enumerable: true, configurable: true })); },
    });
  }
  for (const k of Reflect.ownKeys(Array.prototype)) if (k !== "constructor" && k !== "length") wrapMember(Array.prototype, k, "Array.prototype");
  // The fake DOM's classes stand for the platform's prototypes.
  const protos = { EventTarget: ET.prototype, Node: Nd.prototype, Element: El.prototype, ShadowRoot: SR.prototype, CSSStyleSheet: SS.prototype,
    CSSStyleDeclaration: CSD.prototype, DOMRectReadOnly: Rect.prototype, Document: Object.getPrototypeOf(extra.doc), MutationObserver: extra.mo, ArrayIterator: Object.getPrototypeOf([][Symbol.iterator]()), Event: TEvent.prototype, KeyboardEvent: KEvent.prototype, MouseEvent: MEvent.prototype };
  for (const [label, p] of Object.entries(protos)) for (const k of Reflect.ownKeys(p)) wrapMember(p, k, label);
  // Globals and statics the runtime must not look up late.
  for (const [obj, label] of [[Object.prototype, "Object.prototype"], [Object, "Object"], [Reflect, "Reflect"], [Math, "Math"], [Function.prototype, "Function.prototype"], [Date, "Date"], [String.prototype, "String.prototype"]]) {
    for (const k of ["create", "getOwnPropertyDescriptor", "keys", "apply", "defineProperty", "abs", "max", "min", "call", "bind", "now", "toString", "concat", "indexOf", "hasOwnProperty"]) wrapMember(obj, k, label);
  }
}

test("acceptance: with every hookable built-in booby-trapped, registering, opening, keys and clicking touch no trap", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR });
  // The page's own document-start code has run; now it sets its traps.
  const st = { armed: false, hits: [], undo: [] };
  try {
    boobyTraps(st, { mo: env.MO.prototype, doc: env.document });
    st.armed = true; const probe = []; probe[0] = 1; const pl = {}; pl.mode = 1; st.armed = false;
    assert.ok(st.hits.length >= 2, "control: the traps fire");
    st.hits.length = 0;
    let ran = 0;
    const fake = { isTrusted: true }, fakeKey = { isTrusted: true, key: "Escape" };
    const t1 = T(), t2 = T(), t3 = T(), kA = new KEvent(true, "a"), kEscU = new KEvent(false, "Escape"), kEscT = new KEvent(true, "Escape");
    st.armed = true;
    const id = api.GM_registerMenuCommand("Secret", () => { ran++; });
    api.GM_registerMenuCommand("Other", () => {});
    api.GM_registerMenuCommand("Str", () => {}, "k");
    api.GM_registerMenuCommand("NoId", () => {}, {});
    api.GM_registerMenuCommand("Key", () => {}, { accessKey: "x" });
    st.armed = false;
    assert.equal(env.root.ch.length, 1, "badge shown");
    const sh = hostOf(env).shadow, badge = kq(sh, "badge");
    st.armed = true;
    badge.fire("click", fake);
    badge.fire("click", t1);
    fire(sh, "keydown", kA);
    fire(sh, "keydown", kEscU);
    fire(sh, "keydown", fakeKey);
    st.armed = false;
    assert.equal(badge.at["aria-expanded"], "true", "untrusted Escape does not close");
    st.armed = true;
    fire(sh, "keydown", kEscT);
    st.armed = false;
    assert.equal(badge.at["aria-expanded"], "false", "trusted Escape closes");
    assert.ok(badge.focused, "focus returns to the badge");
    st.armed = true;
    badge.fire("click", t2);
    st.armed = false;
    advance(450);
    const item = kq(sh, "c-s1-" + id);
    st.armed = true;
    item.fire("click", fake);
    st.armed = false;
    assert.equal(ran, 0);
    st.armed = true;
    item.fire("click", t3);
    api.GM_unregisterMenuCommand(id);
    st.armed = false;
    assert.equal(ran, 1, "the command ran from a real click");
    assert.deepEqual(st.hits, [], "no trap was touched by the runtime");
    // and none of the platform dictionaries leaked a prototype
    assert.equal(Object.getPrototypeOf(hostOf(env).shadowInit), null);
  } finally {
    st.armed = false;
    for (let i = st.undo.length - 1; i >= 0; i--) st.undo[i]();
  }
});

test("a page that fades the badge and lies via a replaced getComputedStyle still cannot get a click through", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR });
  let hit = 0;
  api.GM_registerMenuCommand("secret", () => hit++);
  env.W.getComputedStyle = () => new CSD(GOOD);
  const badge = kq(hostOf(env).shadow, "badge");
  env.tamper("opacity", "0");
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "false");
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "true");
  assert.equal(hit, 0);
});

test("a page that re-tampers the host's inline style right before every click never gets one through", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR });
  let hit = 0;
  api.GM_registerMenuCommand("x", () => hit++);
  const badge = kq(hostOf(env).shadow, "badge");
  const bad = [["opacity", "0"], ["transform", "translate(-200px,-200px)"], ["visibility", "hidden"], ["display", "none"], ["pointer-events", "none"], ["filter", "blur(1px)"], ["clip-path", "inset(50%)"]];
  for (const [k, v] of bad) {
    for (let i = 0; i < 3; i++) {
      env.tamper(k, v); // what the page's 5 ms loop does, applied just before the user's click
      badge.fire("click", T());
      assert.equal(badge.at["aria-expanded"], "false", k + " tampering refused");
    }
  }
  // moved by a page transform: the rect check catches it as well
  env.tamper("transform", "translate(-200px,-200px)");
  badge.rect = { width: 28, height: 28, left: 784, top: 528, right: 812, bottom: 556 };
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "false");
  badge.rect = undefined;
  badge.fire("click", T()); // after the refusals the host was pinned back: a clean click works
  assert.equal(badge.at["aria-expanded"], "true");
  // the same for an item
  advance(450);
  const it = all(hostOf(env).shadow).find((n) => n.at && n.at.class === "c");
  for (const [k, v] of bad) {
    env.tamper(k, v);
    it.fire("click", T());
    assert.equal(hit, 0, k + " tampering refused for items");
  }
  it.fire("click", T());
  assert.equal(hit, 1);
});

test("Chrome for Android: after the URL bar hides, fixed elements anchor to the larger (inner) viewport", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR });
  api.GM_registerMenuCommand("x", () => {});
  const badge = kq(hostOf(env).shadow, "badge");
  // documentElement.clientHeight is still the smaller one; the window's inner height grew by 56px
  env.root.chh = 768;
  env.W.innerWidth = 1024; env.W.innerHeight = 824;
  badge.rect = { width: 28, height: 28, left: 984, top: 784, right: 1012, bottom: 812 };
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "true", "matches the inner viewport");
  badge.fire("click", T());
  // something that matches neither is still refused
  badge.rect = { width: 28, height: 28, left: 984, top: 700, right: 1012, bottom: 728 };
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "false");
  // the visual viewport is a candidate too
  env.W.innerHeight = 700;
  env.W.visualViewport = { width: 1024, height: 740 };
  badge.rect = { width: 28, height: 28, left: 984, top: 700, right: 1012, bottom: 728 };
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "false", "no visual viewport was captured at install, so it is not trusted later");
});

test("a visual viewport present at install is a candidate anchor", async () => {
  const env = page("on_demand");
  env.W.visualViewport = { width: 1024, height: 740 };
  const api = await run(env, { grants: GR });
  api.GM_registerMenuCommand("x", () => {});
  const badge = kq(hostOf(env).shadow, "badge");
  badge.rect = { width: 28, height: 28, left: 984, top: 700, right: 1012, bottom: 728 };
  badge.fire("click", T());
  assert.equal(badge.at["aria-expanded"], "true");
});

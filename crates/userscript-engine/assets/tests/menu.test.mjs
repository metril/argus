// The on-demand menu button (assets/menu.js, inlined in the shared runtime closure) against the
// real GM registration path, with a tiny prototype-based fake DOM (so tests can hook the "built-ins"
// the way a hostile page would, after the runtime has captured them).
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeEnv, runScript } from "./harness.mjs";

let off = 0;
const realNow = Date.now;
Date.now = () => realNow() + off;
const advance = (ms) => { off += ms; };

const TR = Symbol("trusted");
class TEvent {
  constructor(trusted) { this[TR] = trusted === true; }
  get isTrusted() { if (!(TR in this)) throw new TypeError("Illegal invocation"); return this[TR]; }
}
class CSD {
  constructor(v = {}) { this.s = {}; this.v = v; }
  setProperty(k, v, p) { this.s[k] = [v, p]; }
  getPropertyValue(k) { return this.v[k] ?? ""; }
}
class ET { addEventListener(t, f) { (this.l ||= {})[t] = [...((this.l ||= {})[t] || []), f]; } }
class Nd extends ET {
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.children.push(c); this.appends = (this.appends || 0) + 1; return c; }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); c.parentNode = null; return c; }
  insertBefore(c, ref) { this.appendChild(c); this.children.splice(this.children.indexOf(c), 1); this.children.splice(this.children.indexOf(ref), 0, c); return c; }
}
class El extends Nd {
  setAttribute(n, v) { this.attrs[n] = String(v); }
  getAttribute(n) { return n in this.attrs ? this.attrs[n] : null; }
  attachShadow() { this.shadow = new N("#shadow"); return this.shadow; }
  showPopover() { this.popped++; }
  hidePopover() {}
  getBoundingClientRect() { return this.rect || { width: 28, height: 28, left: 984, top: 728, right: 1012, bottom: 756 }; }
  focus() {}
}
class N extends El {
  constructor(tag) { super(); this.tag = tag; this.attrs = {}; this.children = []; this.parentNode = null; this.textContent = ""; this.popped = 0; this.style = new CSD(); }
  fire(t, ev) { ((this.l || {})[t] || []).forEach((f) => f(ev)); }
  all() { return [this, ...this.children.flatMap((c) => c.all())]; }
  k(key) { return this.all().find((n) => n.attrs["data-k"] === key); }
}

const run = (env, opts) => new Promise((resolve) => runScript(env, opts, function (api) { resolve(api); }));
const GR = ["gm_registermenucommand", "gm_unregistermenucommand"];
const GOOD = { opacity: "1", transform: "none", filter: "none", visibility: "visible", display: "block", "clip-path": "none", "pointer-events": "auto" };

function page(mode) {
  const env = makeEnv();
  const root = new N("html");
  root.clientWidth = 1024; root.clientHeight = 768;
  const W = env.W;
  W.EventTarget = ET; W.Node = Nd; W.Element = El; W.HTMLElement = El; W.CSSStyleDeclaration = CSD; W.Event = TEvent;
  W.Document.prototype.createElement = (t) => new N(t);
  W.Document.prototype.elementsFromPoint = () => env.hits();
  env.document.documentElement = root;
  env.document.currentScript = { nonce: "n1", getAttribute: (n) => (n === "data-m" ? mode : null) };
  W.top = W;
  env.cs = new CSD({ ...GOOD });
  W.getComputedStyle = () => env.cs;
  env.timers = [];
  W.setTimeout = (f, ms) => env.timers.push([f, ms]);
  const mos = [];
  W.MutationObserver = class { constructor(cb) { this.cb = cb; this.targets = []; mos.push(this); } observe(t) { this.targets.push(t); } };
  env.hits = () => [root.children[0]];
  env.fireW = (t) => ((W.l || {})[t] || []).forEach((f) => f({}));
  env.mutate = () => mos.forEach((m) => m.cb([]));
  env.mos = mos;
  env.root = root;
  return env;
}
const T = () => new TEvent(true), U = () => new TEvent(false);
const hostOf = (env) => env.root.children[0];

test("on_demand: nothing without commands; badge appears on first command and goes on unregister", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR, name: "S One" });
  assert.equal(env.root.children.length, 0);
  const id = api.GM_registerMenuCommand("Do it", () => {});
  assert.equal(env.root.children.length, 1);
  const sh = hostOf(env).shadow;
  assert.match(sh.k("badge").attrs["aria-label"], /\(1\)/);
  assert.ok(hostOf(env).style.s.opacity[1] === "important" && hostOf(env).style.s["pointer-events"][0] === "auto", "inline !important host styles");
  assert.ok(sh.all().find((n) => n.attrs.class === "w").popped > 0, "badge is in the top layer");
  api.GM_unregisterMenuCommand(id);
  assert.equal(env.root.children.length, 0, "unregister removes the button");
  api.GM_registerMenuCommand("Again", () => {});
  assert.equal(env.root.children.length, 1);
});

test("off (no data-m): nothing is ever shown", async () => {
  const env = page(null);
  const api = await run(env, { grants: GR });
  api.GM_registerMenuCommand("x", () => {});
  assert.equal(env.root.children.length, 0);
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
  const badge = sh.k("badge");
  badge.fire("click", U());
  badge.fire("click", { isTrusted: true }); // a plain object: the saved getter refuses it
  assert.equal(badge.attrs["aria-expanded"], "false");
  env.cs.v.opacity = "0.01";
  badge.fire("click", T());
  assert.equal(badge.attrs["aria-expanded"], "false", "faded badge ignores clicks");
  env.cs.v.opacity = "1";
  env.hits = () => [{}, hostOf(env)];
  badge.fire("click", T());
  assert.equal(badge.attrs["aria-expanded"], "false", "covered badge ignores clicks");
  env.hits = () => [hostOf(env)];
  badge.fire("click", T());
  assert.equal(badge.attrs["aria-expanded"], "true");
  const menu = sh.all().find((n) => n.attrs.class === "m");
  assert.equal(menu.attrs.popover, "manual");
  assert.ok(menu.popped > 0, "open menu is in the top layer");
  assert.deepEqual(sh.all().filter((n) => n.attrs.class === "t").map((n) => n.textContent), ["First", "Second"]);
  const item = () => sh.k("c-s2-" + idB2);
  item().fire("click", T());
  assert.deepEqual(hits, [], "ignored within 400 ms of opening");
  advance(450);
  item().fire("click", U());
  item().fire("click", { isTrusted: true });
  assert.deepEqual(hits, []);
  env.cs.v.transform = "scale(2)";
  item().fire("click", T());
  assert.deepEqual(hits, [], "transformed host ignored");
  env.cs.v.transform = "none";
  item().fire("click", T());
  assert.deepEqual(hits, ["b2"]);
  assert.equal(badge.attrs["aria-expanded"], "false", "menu closes after a command");
});

test("badge moved or resized is not clickable; a classic scrollbar's width is tolerated", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR });
  api.GM_registerMenuCommand("x", () => {});
  const badge = hostOf(env).shadow.k("badge");
  badge.rect = { width: 400, height: 400, left: 0, top: 0, right: 1012, bottom: 756 };
  badge.fire("click", T());
  assert.equal(badge.attrs["aria-expanded"], "false");
  // scrollbar: clientWidth is 15px narrower than innerWidth and the badge moves with it
  env.root.clientWidth = 1009;
  badge.rect = { width: 28, height: 28, left: 969, top: 728, right: 997, bottom: 756 };
  badge.fire("click", T());
  assert.equal(badge.attrs["aria-expanded"], "true");
  // but a badge parked where the scrollbar-less layout would put it is off by 15px
  badge.fire("click", T());
  badge.rect = { width: 28, height: 28, left: 984, top: 728, right: 1012, bottom: 756 };
  badge.fire("click", T());
  assert.equal(badge.attrs["aria-expanded"], "false");
});

test("always: top frame shows with no commands; frames behave like on_demand", async () => {
  const env = page("always");
  await run(env, { grants: GR });
  assert.equal(env.root.children.length, 1);
  hostOf(env).shadow.k("badge").fire("click", T());
  assert.ok(hostOf(env).shadow.all().some((n) => n.textContent === "No commands registered."));
  const fr = page("always");
  fr.W.top = {};
  const api = await run(fr, { grants: GR });
  assert.equal(fr.root.children.length, 0);
  api.GM_registerMenuCommand("x", () => {});
  assert.equal(fr.root.children.length, 1);
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
  env.document.documentElement = root2;
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

test("hostile page after mount: hooked built-ins, polluted prototypes and fake events get nothing", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR });
  const grabbed = { handlers: [], shadow: null, pushed: [] };
  const origPush = Array.prototype.push;
  const pol = ["style", "on", "text", "popover", "class", "children", "attrs"];
  try {
    // everything the page can do before the first command exists
    ET.prototype.addEventListener = function (t, f) { grabbed.handlers.push(f); };
    El.prototype.attachShadow = function () { grabbed.shadow = this; return {}; };
    for (const k of pol) Object.defineProperty(Object.prototype, k, { value: { setProperty() {}, get isTrusted() { return true; } }, configurable: true, writable: true });
    Array.prototype.push = function (...a) { for (const x of a) if (typeof x === "function") Reflect.apply(origPush, grabbed.pushed, [x]); return Reflect.apply(origPush, this, a); };
    env.cs.v.opacity = "0.01"; // page fades the badge, then lies about it
    env.W.getComputedStyle = () => new CSD({ ...GOOD });
    let hit = 0;
    api.GM_registerMenuCommand("secret", () => hit++);
    const badge = hostOf(env).shadow.k("badge");
    assert.equal(grabbed.handlers.length, 0, "page captured no handler");
    assert.equal(grabbed.shadow, null, "page captured no shadow root");
    assert.equal(grabbed.pushed.filter((f) => String(f).includes("trusted")).length, 0);
    badge.fire("click", { isTrusted: true });
    badge.fire("click", T()); // real trust, but the style check (saved getComputedStyle) says tampered
    assert.equal(badge.attrs["aria-expanded"], "false");
    env.cs.v.opacity = "1";
    badge.fire("click", T());
    assert.equal(badge.attrs["aria-expanded"], "true");
    advance(450);
    const it = badge.parentNode.children.find((c) => c.attrs.class === "m").all().find((n) => n.attrs.class === "c");
    it.fire("click", { isTrusted: true });
    assert.equal(hit, 0, "no command runs from a fake event");
    it.fire("click", T());
    assert.equal(hit, 1);
  } finally {
    Array.prototype.push = origPush;
    for (const k of pol) delete Object.prototype[k];
  }
});

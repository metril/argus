// The on-demand menu button (assets/menu.js, inlined in the shared runtime closure) against the
// real GM registration path, with a tiny fake DOM.
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeEnv, runScript } from "./harness.mjs";

let off = 0;
const realNow = Date.now;
Date.now = () => realNow() + off;
const advance = (ms) => { off += ms; };

class N {
  constructor(tag) { this.tag = tag; this.attrs = {}; this.children = []; this.parentNode = null; this.l = {}; this.textContent = ""; this.styles = {}; this.popped = 0; this.style = { setProperty: (k, v, p) => { this.styles[k] = [v, p]; } }; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.children.push(c); this.appends = (this.appends || 0) + 1; return c; }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); c.parentNode = null; return c; }
  insertBefore(c, ref) { this.appendChild(c); this.children.splice(this.children.indexOf(c), 1); this.children.splice(this.children.indexOf(ref), 0, c); return c; }
  setAttribute(n, v) { this.attrs[n] = String(v); }
  getAttribute(n) { return n in this.attrs ? this.attrs[n] : null; }
  addEventListener(t, f) { (this.l[t] ||= []).push(f); }
  attachShadow() { this.shadow = new N("#shadow"); return this.shadow; }
  showPopover() { this.popped++; }
  matches() { return false; }
  getBoundingClientRect() { return { width: 28, height: 28, right: 1012, bottom: 756 }; }
  focus() {}
  fire(t, ev) { (this.l[t] || []).forEach((f) => f(ev)); }
  all() { return [this, ...this.children.flatMap((c) => c.all())]; }
  k(key) { return this.all().find((n) => n.attrs["data-k"] === key); }
}

const run = (env, opts) => new Promise((resolve) => runScript(env, opts, function (api) { resolve(api); }));
const GR = ["gm_registermenucommand", "gm_unregistermenucommand"];

function page(mode) {
  const env = makeEnv();
  const root = new N("html");
  env.document.createElement = (t) => new N(t);
  env.document.documentElement = root;
  env.document.currentScript = { nonce: "n1", getAttribute: (n) => (n === "data-m" ? mode : null) };
  const wl = {}, mos = [];
  env.W.addEventListener = (t, f) => (wl[t] ||= []).push(f);
  env.W.top = env.W;
  env.W.innerWidth = 1024; env.W.innerHeight = 768;
  env.cs = { opacity: "1", transform: "none", filter: "none", visibility: "visible", display: "block", clipPath: "none", pointerEvents: "auto" };
  env.W.getComputedStyle = () => env.cs;
  env.W.MutationObserver = class { constructor(cb) { this.cb = cb; this.targets = []; mos.push(this); } observe(t) { this.targets.push(t); } disconnect() {} };
  env.fireW = (t) => (wl[t] || []).forEach((f) => f({}));
  env.mutate = () => mos.forEach((m) => m.cb([]));
  env.mos = mos;
  env.root = root;
  return env;
}
const T = { isTrusted: true }, U = { isTrusted: false };
const hostOf = (env) => env.root.children[0];

test("on_demand: nothing without commands; badge appears on first command and goes on unregister", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR, name: "S One" });
  assert.equal(env.root.children.length, 0);
  const id = api.GM_registerMenuCommand("Do it", () => {});
  assert.equal(env.root.children.length, 1);
  const sh = hostOf(env).shadow;
  assert.match(sh.k("badge").attrs["aria-label"], /\(1\)/);
  assert.ok(hostOf(env).styles.opacity[1] === "important" && hostOf(env).styles["pointer-events"][0] === "auto", "inline !important host styles");
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

test("grouped by script; synthetic clicks, early clicks and tampered styles are ignored", async () => {
  const env = page("on_demand");
  const a = await run(env, { grants: GR, id: "s1", name: "First" });
  const b = await run(env, { grants: GR, id: "s2", name: "Second" });
  const hits = [];
  a.GM_registerMenuCommand("A1", () => hits.push("a1"));
  b.GM_registerMenuCommand("B1", () => hits.push("b1"));
  const idB2 = b.GM_registerMenuCommand("B2", () => hits.push("b2"));
  const sh = hostOf(env).shadow;
  sh.k("badge").fire("click", U);
  assert.equal(sh.k("badge").attrs["aria-expanded"], "false", "synthetic click ignored");
  env.cs.opacity = "0.01"; // page fades the badge to bait a click
  sh.k("badge").fire("click", T);
  assert.equal(sh.k("badge").attrs["aria-expanded"], "false", "faded badge ignores clicks");
  env.cs.opacity = "1";
  sh.k("badge").fire("click", T);
  assert.equal(sh.k("badge").attrs["aria-expanded"], "true");
  const menu = sh.all().find((n) => n.attrs.class === "m");
  assert.equal(menu.attrs.popover, "manual");
  assert.ok(menu.popped > 0, "open menu is in the top layer");
  assert.deepEqual(sh.all().filter((n) => n.attrs.class === "t").map((n) => n.textContent), ["First", "Second"]);
  const item = () => sh.k("c-s2-" + idB2);
  item().fire("click", T);
  assert.deepEqual(hits, [], "ignored within 400 ms of opening");
  advance(450);
  item().fire("click", U);
  assert.deepEqual(hits, []);
  env.cs.transform = "scale(2)";
  item().fire("click", T);
  assert.deepEqual(hits, [], "transformed host ignored");
  env.cs.transform = "none";
  item().fire("click", T);
  assert.deepEqual(hits, ["b2"]);
  assert.equal(sh.k("badge").attrs["aria-expanded"], "false", "menu closes after a command");
});

test("badge moved or resized by the page is not clickable", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR });
  api.GM_registerMenuCommand("x", () => {});
  const badge = hostOf(env).shadow.k("badge");
  badge.getBoundingClientRect = () => ({ width: 400, height: 400, right: 1012, bottom: 756 });
  badge.fire("click", T);
  assert.equal(badge.attrs["aria-expanded"], "false");
});

test("always: shown with no commands in the top frame; in frames it behaves like on_demand", async () => {
  const env = page("always");
  await run(env, { grants: GR });
  assert.equal(env.root.children.length, 1);
  hostOf(env).shadow.k("badge").fire("click", T);
  assert.ok(hostOf(env).shadow.all().some((n) => n.textContent === "No commands registered."));
  const fr = page("always");
  fr.W.top = {}; // W !== W.top
  const api = await run(fr, { grants: GR });
  assert.equal(fr.root.children.length, 0, "no badge in a frame without commands");
  api.GM_registerMenuCommand("x", () => {});
  assert.equal(fr.root.children.length, 1, "but commands still show");
});

test("SPA: re-attached on history events, root replacement, and capped at ~20 per second", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR });
  api.GM_registerMenuCommand("X", () => {});
  const host = hostOf(env);
  env.root.removeChild(host);
  env.fireW("popstate");
  assert.equal(hostOf(env), host);
  // documentElement is observed, and a replaced documentElement is observed again
  assert.ok(env.mos[0].targets.includes(env.root));
  const root2 = new N("html");
  env.document.documentElement = root2;
  env.mutate();
  assert.equal(host.parentNode, root2);
  assert.ok(env.mos[0].targets.includes(root2));
  // a page that keeps removing the host cannot make us spin
  advance(1100);
  root2.appends = 0;
  for (let i = 0; i < 100; i++) { if (host.parentNode) root2.removeChild(host); env.mutate(); }
  assert.ok(root2.appends <= 20, "appends " + root2.appends);
  assert.ok(root2.appends >= 10);
  advance(1100);
  if (host.parentNode) root2.removeChild(host);
  env.mutate();
  assert.equal(host.parentNode, root2, "allowed again in the next second");
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

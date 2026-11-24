// On-demand menu button (proxy-core/assets/menu.js) against the real GM registry, with a tiny fake DOM.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { makeEnv, runScript } from "./harness.mjs";

const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "proxy-core", "assets", "menu.js"), "utf8");

class N {
  constructor(tag) { this.tag = tag; this.attrs = {}; this.children = []; this.parentNode = null; this.l = {}; this.textContent = ""; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.children.push(c); return c; }
  removeChild(c) { this.children.splice(this.children.indexOf(c), 1); c.parentNode = null; return c; }
  insertBefore(c, ref) { this.appendChild(c); this.children.splice(this.children.indexOf(c), 1); this.children.splice(this.children.indexOf(ref), 0, c); return c; }
  setAttribute(n, v) { this.attrs[n] = String(v); }
  getAttribute(n) { return n in this.attrs ? this.attrs[n] : null; }
  addEventListener(t, f) { (this.l[t] ||= []).push(f); }
  attachShadow() { this.shadow = new N("#shadow"); return this.shadow; }
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
  const wl = {};
  env.W.addEventListener = (t, f) => (wl[t] ||= []).push(f);
  env.fireW = (t) => (wl[t] || []).forEach((f) => f({}));
  env.root = root;
  env.load = () => new Function("window", "document", src)(env.W, env.document);
  return env;
}
const T = { isTrusted: true }, U = { isTrusted: false };
const hostOf = (env) => env.root.children[0];

test("on_demand: nothing without commands; badge appears on first command and goes on unregister", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR, name: "S One" });
  env.load();
  assert.equal(env.root.children.length, 0);
  const id = api.GM_registerMenuCommand("Do it", () => {});
  assert.equal(env.root.children.length, 1);
  const badge = hostOf(env).shadow.k("badge");
  assert.match(badge.attrs["aria-label"], /\(1\)/);
  api.GM_unregisterMenuCommand(id);
  assert.equal(env.root.children.length, 0, "unregister removes the button");
  api.GM_registerMenuCommand("Again", () => {});
  assert.equal(env.root.children.length, 1);
});

test("commands registered before menu.js loads show too; grouped by script; clicks need trust", async () => {
  const env = page("on_demand");
  const a = await run(env, { grants: GR, id: "s1", name: "First" });
  const b = await run(env, { grants: GR, id: "s2", name: "Second" });
  const hits = [];
  a.GM_registerMenuCommand("A1", () => hits.push("a1"));
  b.GM_registerMenuCommand("B1", () => hits.push("b1"));
  const idB2 = b.GM_registerMenuCommand("B2", () => hits.push("b2"));
  env.load();
  const sh = hostOf(env).shadow;
  sh.k("badge").fire("click", U);
  assert.equal(sh.k("badge").attrs["aria-expanded"], "false", "synthetic click ignored");
  sh.k("badge").fire("click", T);
  assert.equal(sh.k("badge").attrs["aria-expanded"], "true");
  const titles = sh.all().filter((n) => n.attrs.class === "t").map((n) => n.textContent);
  assert.deepEqual(titles, ["First", "Second"]);
  sh.k("c-s2-" + idB2).fire("click", U);
  assert.deepEqual(hits, []);
  sh.k("c-s2-" + idB2).fire("click", T);
  assert.deepEqual(hits, ["b2"]);
  assert.equal(sh.k("badge").attrs["aria-expanded"], "false", "menu closes after a command");
});

test("always: shown with no commands and says so; no registry is a no-op", async () => {
  const env = page("always");
  await run(env, { grants: GR });
  env.load();
  assert.equal(env.root.children.length, 1);
  hostOf(env).shadow.k("badge").fire("click", T);
  assert.ok(hostOf(env).shadow.all().some((n) => n.textContent === "No commands registered."));
  const bare = page("on_demand");
  bare.load(); // no GM runtime installed: no registry, nothing shown, no throw
  assert.equal(bare.root.children.length, 0);
});

test("SPA: button is re-attached after the page replaces its root children; duplicate load is ignored", async () => {
  const env = page("on_demand");
  const api = await run(env, { grants: GR });
  env.load();
  api.GM_registerMenuCommand("X", () => {});
  const host = hostOf(env);
  env.root.removeChild(host);
  env.fireW("popstate");
  assert.equal(hostOf(env), host);
  env.load();
  assert.equal(env.root.children.length, 1);
});

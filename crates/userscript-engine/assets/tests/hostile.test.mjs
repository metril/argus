// The runtime lives in its own realm (like a page's JS world); the "page" tampers with that
// realm's built-ins after the runtime captured them. The fake backend stays in the main realm.
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { makeEnv, runScript, headFrame, dataFrame, endFrame } from "./harness.mjs";

test("page tampering with built-ins after startup does not affect the runtime", async () => {
  const ctx = vm.createContext({});
  const env = makeEnv();
  env.backend.xhrHandler = () => [headFrame(200, [["content-type", "application/json"]]), dataFrame('{"ok":1}'), endFrame()];
  const api = await new Promise((resolve) =>
    runScript(env, { grants: ["gm_getvalue", "gm_setvalue", "gm_xmlhttprequest", "gm_addvaluechangelistener", "gm_log"], values: { a: 1 } }, function (a) { resolve(a); }, ctx));
  const page = [];
  env.W.fetch = () => { page.push("fetch"); throw new Error("hijacked fetch"); };
  env.W.setTimeout = () => { page.push("setTimeout"); throw new Error("hijacked setTimeout"); };
  vm.runInContext(`
    var boom = function (n) { return function () { throw new Error("hijacked " + n); }; };
    Promise.prototype.then = boom("then");
    JSON.parse = boom("JSON.parse"); JSON.stringify = boom("JSON.stringify");
    Array.prototype.push = boom("push"); Array.prototype.slice = boom("slice"); Array.prototype.concat = boom("concat");
    Array.prototype.splice = boom("splice"); Array.prototype.join = boom("join");
    String.prototype.split = boom("split"); String.prototype.indexOf = boom("indexOf"); String.prototype.toLowerCase = boom("toLowerCase");
    Object.keys = boom("keys"); Object.create = boom("create"); Object.freeze = boom("freeze"); Object.defineProperty = boom("defineProperty");
    Function.prototype.call = boom("call"); Function.prototype.apply = boom("apply"); Function.prototype.bind = boom("bind");
    Object.prototype.hasOwnProperty = boom("hasOwnProperty");
    Date.now = boom("Date.now"); Math.random = boom("Math.random");
  `, ctx);
  api.GM_setValue("b", 2);
  assert.equal(api.GM_getValue("a"), 1);
  assert.equal(api.GM_getValue("b"), 2);
  api.GM_log("still works");
  const r = await new Promise((resolve, reject) => api.GM_xmlhttpRequest({ url: "https://a.test/", responseType: "json", onload: resolve, onerror: reject }));
  assert.equal(r.response.ok, 1);
  api.GM_addValueChangeListener("a", () => {});
  await new Promise((r2) => setTimeout(r2, 30));
  assert.equal(env.backend.store.b, 2, "value write reached the backend");
  assert.deepEqual(page, [], "the page's replacement fetch/setTimeout were never used");
  assert.equal(env.consoleCalls.error.length, 0, JSON.stringify(env.consoleCalls.error.map(String)));
});

test("hand-over objects are frozen so scripts and the page cannot swap APIs", async () => {
  const ctx = vm.createContext({});
  const env = makeEnv();
  const api = await new Promise((resolve) => runScript(env, { grants: ["gm_getvalue", "gm_setvalue"], values: {} }, function (a) { resolve(a); }, ctx));
  assert.ok(Object.isFrozen(api.GM));
  assert.throws(() => { api.GM.getValue = () => "pwned"; }, TypeError);
  assert.throws(() => { api.GM_info.script = null; }, TypeError);
});

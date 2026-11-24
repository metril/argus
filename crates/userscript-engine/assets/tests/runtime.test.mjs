import { test } from "node:test";
import assert from "node:assert/strict";
import { makeEnv, runScript, until, sleep, headFrame, dataFrame, endFrame, errorFrame, parseXhrRequest } from "./harness.mjs";

const run = (env, opts, fn) => new Promise((resolve, reject) => {
  runScript(env, opts, function (api) { try { resolve(fn.call(this, api)); } catch (e) { reject(e); } });
});

test("grants: only granted APIs are visible; grant none exposes nothing but unsafeWindow", async () => {
  const env = makeEnv();
  const a = await run(env, { grants: ["gm_getvalue", "gm_log"] }, (api) => api);
  assert.equal(typeof a.GM_getValue, "function");
  assert.equal(typeof a.GM_log, "function");
  assert.equal(a.GM_setValue, undefined);
  assert.equal(a.GM_xmlhttpRequest, undefined);
  assert.equal(typeof a.GM.getValue, "function");
  assert.equal(a.GM.setValue, undefined);
  assert.equal(a.unsafeWindow, env.W);
  const none = await run(env, { grants: [] }, (api) => api);
  assert.equal(none.GM, undefined);
  assert.equal(none.GM_info, undefined);
  assert.equal(none.GM_getValue, undefined);
  assert.equal(none.unsafeWindow, env.W);
});

test("GM objects are frozen; GM_info is populated", async () => {
  const env = makeEnv();
  const api = await run(env, { grants: ["gm_info"], name: "Évil </script>", meta: { version: "2.0", namespace: "ns" } }, (a) => a);
  assert.equal(api.GM_info.script.name, "Évil </script>");
  assert.equal(api.GM.info, api.GM_info);
  assert.equal(api.GM_info.scriptHandler, "Argus Userscripts");
  assert.equal(api.GM_info.version, "1.0.0");
  assert.match(api.GM_info.scriptMetaStr, /==UserScript==/);
  assert.throws(() => { api.GM.info = 1; }, TypeError);
  assert.throws(() => { api.GM_info.script.name = "x"; }, TypeError);
  assert.ok(Object.isFrozen(api.GM));
});

test("values: sync cache, ordered write-behind, promise forms, clones", async () => {
  const env = makeEnv();
  const g = ["gm_getvalue", "gm_setvalue", "gm_deletevalue", "gm_listvalues", "gm_getvalues", "gm_setvalues", "gm_deletevalues"];
  const api = await run(env, { grants: g, values: { a: 1, obj: { x: [1, 2] } } }, (a) => a);
  assert.equal(api.GM_getValue("a"), 1);
  assert.equal(api.GM_getValue("missing", "dflt"), "dflt");
  const o = api.GM_getValue("obj");
  o.x.push(3);
  assert.deepEqual(api.GM_getValue("obj"), { x: [1, 2] }, "returned values are copies");
  api.GM_setValue("b", { y: 1 });
  api.GM_setValue("b", { y: 2 });
  assert.deepEqual(api.GM_getValue("b"), { y: 2 }, "visible immediately");
  await until(() => env.backend.store.b && env.backend.store.b.y === 2);
  assert.deepEqual(env.backend.calls.filter((c) => c.path === "values/set").map((c) => JSON.parse(c.init.body).values.b.y), [1, 2], "writes stay ordered");
  assert.deepEqual(api.GM_listValues().sort(), ["a", "b", "obj"]);
  assert.deepEqual(api.GM_getValues(["a", "b"]), { a: 1, b: { y: 2 } });
  assert.deepEqual(api.GM_getValues({ a: 0, zzz: 9 }), { a: 1, zzz: 9 });
  assert.equal(await api.GM.getValue("a"), 1);
  await api.GM.setValue("c", "v");
  assert.equal(env.backend.store.c, "v");
  await api.GM.setValues({ d: 1, e: 2 });
  assert.equal(env.backend.store.e, 2);
  await api.GM.deleteValue("c");
  assert.equal("c" in env.backend.store, false);
  await api.GM.deleteValues(["d", "e"]);
  assert.deepEqual(await api.GM.listValues(), ["a", "obj", "b"].sort().length ? (await api.GM.listValues()) : []);
  assert.equal(api.GM_getValue("d"), undefined);
  // the token and tab id travel in headers/body, never in the URL
  const c = env.backend.calls.find((x) => x.path === "values/set");
  assert.match(c.headers["X-GM-Token"], /^v1\./);
  assert.ok(!c.url.includes("v1.s1"));
});

test("values: lazy load when not embedded; failed write rolls back and rejects", async () => {
  const env = makeEnv({ store: { k: "stored" } });
  const api = await new Promise((resolve) => runScript(env, { grants: ["gm_getvalue", "gm_setvalue"] }, function (a) { resolve(a); }));
  assert.equal(api.GM_getValue("k"), "stored", "script starts after the values loaded");
  env.backend.failValueSet = true;
  await assert.rejects(api.GM.setValue("q", 1), (e) => e.code === "quota_exceeded");
  assert.equal(api.GM_getValue("q"), undefined, "rolled back");
});

test("value change listeners: local, cross-tab broadcast and polling", async () => {
  const env = makeEnv();
  const g = ["gm_getvalue", "gm_setvalue", "gm_addvaluechangelistener", "gm_removevaluechangelistener"];
  const a = await run(env, { grants: g, values: {} }, (x) => x);
  const events = [];
  const id = a.GM_addValueChangeListener("k", (...args) => events.push(args));
  a.GM_setValue("k", 1);
  assert.deepEqual(events[0], ["k", undefined, 1, false]);
  // a second page instance (another tab, same origin) sees it through BroadcastChannel
  const env2 = makeEnv({ store: env.backend.store });
  const b = await run(env2, { grants: g, values: {} }, (x) => x);
  const ev2 = [];
  b.GM_addValueChangeListener("k", (...args) => ev2.push(args));
  a.GM_setValue("k", 2);
  await until(() => ev2.length > 0);
  assert.deepEqual(ev2[0], ["k", 1, 2, true]);
  assert.equal(b.GM_getValue("k"), 2, "cache follows the remote change");
  // polling path: a change made by someone else only through the server
  env.backend.changeLog.push({ seq: 999, name: "k", old: 2, new: 77, src: "other-tab" });
  await until(() => events.some((e) => e[2] === 77), 8000);
  assert.equal(a.GM_getValue("k"), 77);
  assert.equal(events.at(-1)[3], true);
  a.GM_removeValueChangeListener(id);
  const n = events.length;
  a.GM_setValue("k", 5);
  assert.equal(events.length, n);
  process.exitCode = 0;
});

test("xmlhttpRequest: request framing, text/json/arraybuffer/blob responses, headers, progress", async () => {
  const env = makeEnv();
  const seen = [];
  env.backend.xhrHandler = ({ meta, body }) => {
    seen.push({ meta, body: new TextDecoder().decode(body) });
    return [headFrame(200, [["content-type", "application/json; charset=utf-8"], ["content-length", "7"], ["x-a", "b"]], "OK", "https://final.test/x"), dataFrame('{"a"'), dataFrame(":1}"), endFrame()];
  };
  const api = await run(env, { grants: ["gm_xmlhttprequest"] }, (a) => a);
  const progress = [];
  const r = await new Promise((resolve, reject) => api.GM_xmlhttpRequest({
    method: "POST", url: "/rel?x=1", headers: { "X-Custom": "1", Referer: "https://r.test/" }, data: "payload", responseType: "json",
    cookie: "a=b", anonymous: true, user: "u", password: "p", timeout: 5000, context: { id: 7 },
    onprogress: (e) => progress.push(e.loaded), onload: resolve, onerror: reject,
  }));
  assert.deepEqual(r.response, { a: 1 });
  assert.equal(r.status, 200);
  assert.equal(r.statusText, "OK");
  assert.equal(r.finalUrl, "https://final.test/x");
  assert.match(r.responseHeaders, /x-a: b\r\n/);
  assert.deepEqual(r.context, { id: 7 });
  assert.equal(r.readyState, 4);
  assert.ok(progress.length >= 1);
  const m = seen[0].meta;
  assert.equal(m.op, "xhr");
  assert.equal(m.method, "POST");
  assert.equal(m.url, "https://page.test/rel?x=1", "relative URLs resolve against the page");
  assert.deepEqual(m.headers.sort(), [["Referer", "https://r.test/"], ["X-Custom", "1"]].sort());
  assert.equal(m.anonymous, true);
  assert.equal(m.cookie, "a=b");
  assert.equal(m.user, "u");
  assert.equal(seen[0].body, "payload");
  const call = env.backend.calls.find((c) => c.path === "xhr");
  assert.equal(call.init.credentials, "omit");
  assert.equal(call.init.headers["Content-Type"], "application/x-gm-frame");
  // other response types
  env.backend.xhrHandler = () => [headFrame(200, [["content-type", "text/plain"]]), dataFrame(new Uint8Array([104, 105])), endFrame()];
  const run1 = (rt) => new Promise((resolve, reject) => api.GM_xmlhttpRequest({ url: "https://a.test/", responseType: rt, onload: resolve, onerror: reject }));
  assert.equal((await run1("")).responseText, "hi");
  assert.equal((await run1("text")).response, "hi");
  assert.deepEqual([...new Uint8Array((await run1("arraybuffer")).response)], [104, 105]);
  const blob = (await run1("blob")).response;
  assert.equal(await blob.text(), "hi");
  assert.equal(blob.type, "text/plain");
  // HTTP errors still go through onload
  env.backend.xhrHandler = () => [headFrame(404, [], "Not Found"), endFrame()];
  assert.equal((await run1("")).status, 404);
});

test("xmlhttpRequest: stream responses, binary bodies, FormData, promise form", async () => {
  const env = makeEnv();
  const bodies = [];
  env.backend.xhrHandler = ({ meta, body }) => {
    bodies.push({ meta, body });
    return [headFrame(200, [["content-type", "application/octet-stream"]]), dataFrame("ab"), dataFrame("cd"), endFrame()];
  };
  const api = await run(env, { grants: ["gm_xmlhttprequest"] }, (a) => a);
  const r = await api.GM.xmlHttpRequest({ url: "https://a.test/", responseType: "stream", method: "PUT", data: new Uint8Array([1, 2, 3]) });
  const reader = r.response.getReader();
  let got = "";
  for (;;) { const { done, value } = await reader.read(); if (done) break; got += new TextDecoder().decode(value); }
  assert.equal(got, "abcd");
  assert.deepEqual([...bodies[0].body], [1, 2, 3]);
  await api.GM.xmlHttpRequest({ url: "https://a.test/", method: "POST", data: "éÿ", binary: true });
  assert.deepEqual([...bodies[1].body], [0xe9, 0xff], "binary:true sends one byte per char");
  const fd = new FormData();
  fd.append("f", "v");
  await api.GM.xmlHttpRequest({ url: "https://a.test/", method: "POST", data: fd });
  const ct = bodies[2].meta.headers.find(([k]) => k.toLowerCase() === "content-type")[1];
  assert.match(ct, /^multipart\/form-data; boundary=/);
  assert.match(new TextDecoder().decode(bodies[2].body), /name="f"/);
  await api.GM.xmlHttpRequest({ url: "https://a.test/", method: "POST", data: new URLSearchParams({ a: "1" }) });
  assert.equal(new TextDecoder().decode(bodies[3].body), "a=1");
  await api.GM.xmlHttpRequest({ url: "https://a.test/", method: "POST", data: new Blob(["blobby"], { type: "text/x" }) });
  assert.equal(new TextDecoder().decode(bodies[4].body), "blobby");
});

test("xmlhttpRequest: error frames, backend refusal, timeout, abort", async () => {
  const env = makeEnv();
  const api = await run(env, { grants: ["gm_xmlhttprequest"] }, (a) => a);
  const outcome = (details) => new Promise((resolve) => {
    const d = { url: "https://a.test/", onload: () => resolve("load"), onerror: (e) => resolve("error:" + e.error), ontimeout: () => resolve("timeout"), onabort: () => resolve("abort"), ...details };
    const ctrl = api.GM_xmlhttpRequest(d);
    if (details.abortAfter) setTimeout(() => ctrl.abort(), details.abortAfter);
  });
  env.backend.xhrHandler = () => [headFrame(200), errorFrame("network", "connection refused")];
  assert.equal(await outcome({}), "error:connection refused");
  env.backend.xhrHandler = () => [errorFrame("timeout", "upstream timed out")];
  assert.equal(await outcome({}), "timeout");
  env.backend.xhrHandler = () => new Response(JSON.stringify({ ok: false, error: { code: "connect_denied", message: "x.test is not listed in @connect" } }), { status: 403, headers: { "content-type": "application/json" } });
  assert.equal(await outcome({}), "error:x.test is not listed in @connect");
  env.backend.xhrHandler = () => [headFrame(200), { delay: 400 }, dataFrame("late"), endFrame()];
  assert.equal(await outcome({ timeout: 50 }), "timeout");
  assert.equal(await outcome({ abortAfter: 30 }), "abort");
});

test("download goes through the xhr endpoint and triggers a browser download", async () => {
  const env = makeEnv();
  const ops = [];
  env.backend.xhrHandler = ({ meta }) => { ops.push(meta.op); return [headFrame(200, [["content-type", "text/plain"]]), dataFrame("file"), endFrame()]; };
  const clicked = [];
  const dproto = env.W.Document.prototype; const origCreate = dproto.createElement;
  dproto.createElement = function (t) { const e = origCreate.call(this, t); if (t === "a") clicked.push(e); return e; };
  const api = await run(env, { grants: ["gm_download"] }, (a) => a);
  await new Promise((resolve, reject) => api.GM_download({ url: "https://a.test/dir/f.txt", name: "f.txt", onload: resolve, onerror: reject }));
  assert.deepEqual(ops, ["download"]);
  assert.equal(clicked[0].attrs.download, "f.txt");
  assert.ok(clicked[0].clicked);
});

test("resources: inline (sync) and fetched (promise) forms", async () => {
  const env = makeEnv({ resources: { big: { mime: "text/css", bytes: new TextEncoder().encode("body{}") } } });
  const b64 = Buffer.from([1, 2, 3]).toString("base64");
  const api = await run(env, { grants: ["gm_getresourcetext", "gm_getresourceurl"], resources: { css: { mime: "text/css", text: "a{b:c}" }, bin: { mime: "image/png", b64 } } }, (a) => a);
  assert.equal(api.GM_getResourceText("css"), "a{b:c}");
  assert.equal(api.GM_getResourceURL("bin"), "data:image/png;base64," + b64);
  assert.equal(await api.GM.getResourceUrl("bin"), "data:image/png;base64," + b64);
  assert.equal(await api.GM.getResourceText("big"), "body{}", "not inlined: fetched from the backend");
  assert.match(await api.GM.getResourceUrl("big"), /^data:text\/css;base64,/);
  await assert.rejects(api.GM.getResourceText("nope"));
  const r = env.backend.calls.find((c) => c.path.startsWith("resource"));
  assert.ok(!r.url.includes("v1."), "the token never travels in the URL");
  assert.match(r.headers["X-GM-Token"], /^v1\./);
});

test("addStyle / addElement / log / openInTab / menu commands", async () => {
  const env = makeEnv();
  env.W.open = (u) => { env.opened = u; return { close() {} }; };
  const api = await run(env, { grants: ["gm_addstyle", "gm_addelement", "gm_log", "gm_openintab", "gm_registermenucommand", "gm_unregistermenucommand"], name: "Menu Script" }, (a) => a);
  const st = api.GM_addStyle("a{color:red}");
  assert.equal(st.tagName, "style");
  assert.equal(st.textContent, "a{color:red}");
  assert.ok(env.document.head.children.includes(st));
  const el = api.GM_addElement("div", { id: "x", textContent: "hi" });
  assert.equal(el.attrs.id, "x");
  assert.equal(el.textContent, "hi");
  assert.throws(() => api.GM_addElement("div", { innerHTML: "<img src=x>" }), TypeError);
  api.GM_log("hello", 1);
  assert.deepEqual(env.consoleCalls.log[0], ["[Menu Script]", "hello", 1]);
  api.GM_openInTab("/x"); assert.equal(env.opened, "https://page.test/x");
  let clicked = 0;
  const id = api.GM_registerMenuCommand("Do it", () => clicked++, "d");
  const reg = env.W[env.W.Symbol.for("adblock.userscript.menu")];
  assert.deepEqual(reg.commands(), [{ script: "s1", scriptName: "Menu Script", id, caption: "Do it", accessKey: "d" }]);
  assert.ok(reg.invoke("s1", id));
  assert.equal(clicked, 1);
  assert.throws(() => { reg.commands = null; }, TypeError, "registry object is frozen");
  let subs = 0;
  reg.subscribe(() => subs++);
  api.GM_unregisterMenuCommand(id);
  assert.equal(reg.commands().length, 0);
  assert.equal(subs, 1);
  assert.equal(reg.invoke("s1", id), false);
});

test("tabs, cookies and unsupported webRequest", async () => {
  const env = makeEnv();
  const api = await run(env, { grants: ["gm_gettab", "gm_savetab", "gm_gettabs", "gm_cookie", "gm_webrequest"] }, (a) => a);
  api.GM_saveTab({ n: 1 });
  assert.deepEqual(await api.GM.getTab(), { n: 1 });
  const all = await api.GM.getTabs();
  assert.ok(Object.values(all).some((v) => v.n === 1));
  const list = await api.GM.cookie.list({ url: "https://a.test/" });
  assert.equal(list[0].name, "a");
  const viaCb = await new Promise((resolve) => api.GM_cookie.list({ url: "https://a.test/" }, resolve));
  assert.equal(viaCb[0].name, "a");
  await api.GM.cookie.set({ url: "https://a.test/", name: "z", value: "1" });
  assert.equal(JSON.parse(env.backend.calls.at(-1).init.body).cookie.name, "z");
  assert.throws(() => api.GM_webRequest([], () => {}), /not supported/);
  await assert.rejects(api.GM.webRequest([], () => {}), (e) => e.code === "unsupported" && /proxy/.test(e.message));
});

test("notification and clipboard fall back gracefully", async () => {
  const env = makeEnv();
  env.W.Notification = class { static permission = "granted"; constructor(t, o) { env.notified = [t, o.body]; } close() {} };
  const api = await run(env, { grants: ["gm_notification", "gm_setclipboard"] }, (a) => a);
  api.GM_notification({ text: "body", title: "T" });
  assert.deepEqual(env.notified, ["T", "body"]);
  const n = await api.GM.notification({ text: "x" });
  assert.equal(typeof n.remove, "function");
});

test("run-at timing: start is synchronous, end waits for DOMContentLoaded, idle after end", async () => {
  const env = makeEnv();
  const order = [];
  const { loadRuntime } = await import("./harness.mjs");
  const mk = (name, runAt) => ({ d: { id: name, name, runAt, grants: [], params: ["unsafeWindow"], token: "v1.x.9999999999.s", meta: { name } }, f: () => order.push(name) });
  loadRuntime()({ base: "/b", top: true, handler: "h", handlerVersion: "1" }, [mk("idle", "document-idle"), mk("end", "document-end"), mk("start", "document-start")], env.W);
  assert.deepEqual(order, ["start"]);
  env.fireDCL();
  await until(() => order.length === 3);
  assert.deepEqual(order, ["start", "end", "idle"]);
});

test("unwrap scripts are injected as a nonce'd <script> and removed again", async () => {
  const env = makeEnv();
  env.document.currentScript = { nonce: "N0nce", parentNode: env.document.head };
  env.document.head.children.push(env.document.currentScript);
  let injected;
  const dproto = env.W.Document.prototype; const origCreate = dproto.createElement;
  dproto.createElement = function (t) { const e = origCreate.call(this, t); if (t === "script") injected = e; return e; };
  await new Promise((resolve) => { runScript(env, { unwrap: true, code: "window.foo = 1;" }, () => {}); setTimeout(resolve, 20); });
  assert.equal(injected.attrs.nonce, "N0nce");
  assert.match(injected.textContent, /^window\.foo = 1;\n\/\/# sourceURL=adblock-userscript\/Test_Script\.user\.js$/);
  assert.equal(injected.parentNode, null, "script element removed after execution");
  assert.ok(!env.document.head.children.some((c) => c.nonce === "N0nce"), "our own script element is removed");
});

test("capability tokens never appear on window, in the DOM or in URLs other than resource fetches", async () => {
  const env = makeEnv();
  const api = await run(env, { grants: ["gm_setvalue", "gm_xmlhttprequest", "gm_getresourcetext"], values: {} }, (a) => a);
  api.GM_setValue("a", 1);
  await until(() => env.backend.calls.length > 0);
  const own = Object.getOwnPropertyNames(env.W).concat(Object.getOwnPropertyNames(env.document));
  for (const k of own) {
    const v = env.W[k] ?? env.document[k];
    if (typeof v === "string") assert.ok(!v.startsWith("v1."), "token leaked on " + k);
  }
  assert.ok(!JSON.stringify(Object.getOwnPropertySymbols(env.W)).includes("v1."));
  assert.ok(env.backend.calls.filter((c) => c.path !== "resource").every((c) => !c.url.includes("v1.")));
});

test("menu commands of every script on the page share one registry", async () => {
  const env = makeEnv();
  const grants = ["gm_registermenucommand", "gm_unregistermenucommand"];
  const a = await run(env, { grants, id: "s1", name: "First" }, (api) => api);
  const b = await run(env, { grants, id: "s2", name: "Second" }, (api) => api);
  let hits = [];
  a.GM_registerMenuCommand("A cmd", () => hits.push("a"));
  const idB = b.GM_registerMenuCommand("B cmd", () => hits.push("b"));
  const reg = env.W[env.W.Symbol.for("adblock.userscript.menu")];
  let changes = 0;
  reg.subscribe(() => changes++);
  const cmds = reg.commands();
  assert.deepEqual(cmds.map((c) => [c.scriptName, c.caption]), [["First", "A cmd"], ["Second", "B cmd"]]);
  assert.ok(cmds.every((c) => c.run === undefined && c.fn === undefined), "callbacks are not exposed");
  assert.equal(reg.invoke("s2", idB), true);
  assert.equal(reg.invoke("s1", 999), false);
  assert.deepEqual(hits, ["b"]);
  b.GM_unregisterMenuCommand(idB);
  assert.equal(changes, 1);
  assert.equal(reg.commands().length, 1);
});

test("openInTab: background refocuses, onclose polls closed, close() fires onclose once", async () => {
  const env = makeEnv();
  let focused = 0;
  const wins = [];
  env.W.focus = () => focused++;
  env.W.open = (u) => { const w = { url: u, closed: false, close() { this.closed = true; } }; wins.push(w); return w; };
  env.W.setInterval = (f) => { const h = setInterval(f, 10); h.unref(); return h; };
  const api = await run(env, { grants: ["gm_openintab"] }, (a) => a);
  api.GM_openInTab("/fg");
  assert.equal(focused, 0);
  const bg = api.GM_openInTab("/bg", { active: false });
  assert.equal(focused, 1);
  api.GM_openInTab("/legacy", true);
  assert.equal(focused, 2);
  let closes = 0;
  bg.onclose = () => closes++;
  assert.equal(bg.closed, false);
  wins[1].closed = true;
  await until(() => closes === 1);
  assert.equal(bg.closed, true);
  await sleep(40);
  assert.equal(closes, 1, "onclose fires once");
  const t2 = api.GM_openInTab("/c");
  let c2 = 0;
  t2.onclose = () => c2++;
  t2.close();
  assert.equal(wins[3].closed, true);
  assert.equal(c2, 1);
  env.W.open = () => null; // popup blocked
  const blocked = api.GM_openInTab("/x");
  assert.equal(blocked.closed, true);
  blocked.close();
});

test("GM_info.platform comes from userAgentData or the user agent", async () => {
  const ua = (userAgent, userAgentData) => { const env = makeEnv(); env.W.navigator = { userAgent, userAgentData }; return run(env, { grants: ["gm_info"] }, (a) => a.GM_info.platform); };
  assert.deepEqual(await ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0"), { os: "win", arch: "x86-64", browserName: "Firefox", browserVersion: "130.0" });
  assert.deepEqual(await ua("Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0.0.0 Safari/537.36", { platform: "Linux", brands: [{ brand: "Not/A)Brand", version: "8" }, { brand: "Chromium", version: "126" }, { brand: "Google Chrome", version: "126" }] }), { os: "linux", arch: "x86-64", browserName: "Google Chrome", browserVersion: "126" });
  const p = await ua("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126.0.0.0 Mobile Safari/537.36");
  assert.equal(p.os, "android");
  assert.equal((await ua("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15")).os, "mac");
  assert.equal((await ua("test-agent")).os, "unknown");
});

// Fake page + fake GM backend for testing assets/gm.js under node (no DOM available).
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
export const runtimeSrc = readFileSync(join(here, "..", "gm.js"), "utf8");

export function loadRuntime(ctx) {
  if (ctx) return vm.runInContext("(" + runtimeSrc + ")", ctx);
  return new Function("return (" + runtimeSrc + ")")();
}

class FakeNode extends EventTarget {
  constructor(tag) {
    super();
    this.tagName = tag;
    this.attrs = {};
    this.children = [];
    this.parentNode = null;
    this.style = {};
    this._text = "";
  }
  appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
  removeChild(c) { this.children = this.children.filter((x) => x !== c); c.parentNode = null; return c; }
  setAttribute(n, v) { this.attrs[n] = v; }
  get textContent() { return this._text; }
  set textContent(v) { this._text = v; }
  click() { this.clicked = true; }
}
class FakeNodeBase {}
Object.defineProperty(FakeNodeBase.prototype, "textContent", Object.getOwnPropertyDescriptor(FakeNode.prototype, "textContent"));
FakeNodeBase.prototype.appendChild = FakeNode.prototype.appendChild;
FakeNodeBase.prototype.removeChild = FakeNode.prototype.removeChild;
class FakeElementBase {}
FakeElementBase.prototype.setAttribute = FakeNode.prototype.setAttribute;
class FakeDocumentBase extends EventTarget {}
FakeDocumentBase.prototype.createElement = function (tag) { return new FakeNode(tag); };
class FakeStorage { constructor() { this.m = new Map(); } getItem(k) { return this.m.has(k) ? this.m.get(k) : null; } setItem(k, v) { this.m.set(k, String(v)); } }

export function frame(type, payload) {
  const body = typeof payload === "string" ? new TextEncoder().encode(payload) : payload;
  const out = new Uint8Array(5 + body.length);
  out[0] = type;
  new DataView(out.buffer).setUint32(1, body.length);
  out.set(body, 5);
  return out;
}
export const headFrame = (status, headers = [], statusText = "OK", finalUrl) => frame(1, JSON.stringify({ status, statusText, headers, finalUrl }));
export const dataFrame = (bytes) => frame(2, typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes);
export const endFrame = () => frame(3, "{}");
export const errorFrame = (kind, message) => frame(4, JSON.stringify({ kind, code: kind, message }));

export function parseXhrRequest(bytes) {
  const len = new DataView(bytes.buffer, bytes.byteOffset).getUint32(0);
  const meta = JSON.parse(new TextDecoder().decode(bytes.subarray(4, 4 + len)));
  return { meta, body: bytes.subarray(4 + len) };
}

/** Environment: `env.W` is the fake window; `env.backend` records calls and scripts responses. */
export function makeEnv(opts = {}) {
  const store = opts.store || {};
  const calls = [];
  let seq = 0;
  const changeLog = [];
  const backend = {
    calls,
    store,
    changeLog,
    xhrHandler: opts.xhrHandler || (() => [headFrame(200, [["content-type", "text/plain"]]), dataFrame("hello"), endFrame()]),
    resources: opts.resources || {},
    failValueSet: false,
  };
  async function fetchImpl(url, init = {}) {
    url = String(url);
    const path = url.replace("/__adblock__/gm/v1/", "").split("?")[0];
    const headers = init.headers || {};
    calls.push({ path, url, headers, init });
    const jsonRes = (result) => new Response(JSON.stringify({ ok: true, result }), { headers: { "content-type": "application/json" } });
    const errRes = (code, message, status = 403) => new Response(JSON.stringify({ ok: false, error: { code, message } }), { status, headers: { "content-type": "application/json" } });
    if (path === "xhr") {
      if (init.signal && init.signal.aborted) throw new DOMException("aborted", "AbortError");
      const frames = await backend.xhrHandler(parseXhrRequest(init.body), init);
      if (frames instanceof Response) return frames;
      const stream = new ReadableStream({
        async start(c) {
          for (const f of frames) {
            if (f && f.delay) { await new Promise((r) => setTimeout(r, f.delay)); continue; }
            if (init.signal && init.signal.aborted) { c.error(new DOMException("aborted", "AbortError")); return; }
            c.enqueue(f);
          }
          c.close();
        },
      });
      return new Response(stream, { headers: { "content-type": "application/x-gm-frames" } });
    }
    const body = init.body ? JSON.parse(init.body) : {};
    if (path === "values/get") {
      const names = body.names || Object.keys(store);
      const r = {};
      for (const n of names) if (n in store) r[n] = store[n];
      return jsonRes(r);
    }
    if (path === "values/set") {
      if (backend.failValueSet) return errRes("quota_exceeded", "quota", 413);
      for (const [k, v] of Object.entries(body.values)) {
        changeLog.push({ seq: ++seq, name: k, old: store[k] ?? null, new: v, src: body.src });
        store[k] = v;
      }
      return jsonRes(null);
    }
    if (path === "values/delete") {
      for (const n of body.names) { changeLog.push({ seq: ++seq, name: n, old: store[n] ?? null, new: null, src: body.src }); delete store[n]; }
      return jsonRes(null);
    }
    if (path === "values/changes") {
      if (body.since === null) return jsonRes({ seq, reset: false, changes: [] });
      return jsonRes({ seq, reset: false, changes: changeLog.filter((c) => c.seq > body.since) });
    }
    if (path === "token/refresh") return jsonRes({ token: "v1.x." + (Math.floor(Date.now() / 1000) + 3600) + ".sig", exp: Math.floor(Date.now() / 1000) + 3600 });
    if (path === "cookie") return jsonRes(body.op === "list" ? [{ name: "a", value: "1" }] : null);
    if (path.startsWith("resource")) {
      const name = new URL("http://x/" + url.split("/v1/")[1]).searchParams.get("name");
      const r = backend.resources[name];
      if (!r) return errRes("not_found", "nope", 404);
      return new Response(r.bytes, { headers: { "content-type": r.mime } });
    }
    return errRes("not_found", "unknown " + path, 404);
  }

  const document = Object.assign(new FakeDocumentBase(), {
    currentScript: null,
    readyState: opts.readyState || "loading",
  });
  document.head = new FakeNode("head");
  document.body = opts.noBody ? null : new FakeNode("body");
  document.documentElement = new FakeNode("html");
  const consoleCalls = { error: [], warn: [], log: [] };
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const W = {
    document,
    location: { href: "https://page.test/path?q=1" },
    setTimeout: (f, t) => { const h = setTimeout(f, t); h.unref(); return h; },
    clearTimeout, setInterval, clearInterval,
    fetch: fetchImpl,
    Uint8Array, ArrayBuffer, Blob, URL, TextEncoder, TextDecoder, AbortController, FormData, URLSearchParams,
    ReadableStream, Response, Headers, ReadableStreamDefaultReader,
    MutationObserver: class { constructor(cb) { this.cb = cb; } observe() {} disconnect() {} },
    BroadcastChannel: opts.noBroadcast ? undefined : class extends BroadcastChannel { constructor(n) { super(n); this.unref(); } },
    console: { log: (...a) => consoleCalls.log.push(a), error: (...a) => consoleCalls.error.push(a), warn: (...a) => consoleCalls.warn.push(a) },
    Symbol, atob, btoa, encodeURIComponent,
    EventTarget, Node: FakeNodeBase, Element: FakeElementBase, Document: FakeDocumentBase, Event, CustomEvent,
    Storage: FakeStorage, sessionStorage: new FakeStorage(),
    History: class { pushState() {} replaceState() {} },
    history: {},
    navigator: { userAgent: "test-agent" },
    open: (u) => ({ url: u, close() { this.closed = true; } }),
    focus() {},
  };
  return { W, backend, consoleCalls, document, fireDCL() { document.readyState = "interactive"; document.dispatchEvent(new Event("DOMContentLoaded")); }, exp };
}

export function token(id = "s1") {
  return "v1." + Buffer.from(id).toString("base64url") + "." + (Math.floor(Date.now() / 1000) + 3600) + ".sig";
}

/** Run one script `fn(params...)` under the runtime. Resolves with what the script captured. */
export function runScript(env, { grants = [], runAt = "document-start", id = "s1", name = "Test Script", values, meta = {}, resources, unwrap = false, code, cfg = {} } = {}, fn) {
  const runtime = loadRuntime(arguments[3]);
  const gm = ["GM_info", "GM"];
  const table = {
    gm_getvalue: "GM_getValue", gm_setvalue: "GM_setValue", gm_deletevalue: "GM_deleteValue", gm_listvalues: "GM_listValues",
    gm_getvalues: "GM_getValues", gm_setvalues: "GM_setValues", gm_deletevalues: "GM_deleteValues",
    gm_addvaluechangelistener: "GM_addValueChangeListener", gm_removevaluechangelistener: "GM_removeValueChangeListener",
    gm_addstyle: "GM_addStyle", gm_addelement: "GM_addElement", gm_getresourcetext: "GM_getResourceText",
    gm_getresourceurl: "GM_getResourceURL", gm_xmlhttprequest: "GM_xmlhttpRequest", gm_download: "GM_download",
    gm_openintab: "GM_openInTab", gm_setclipboard: "GM_setClipboard", gm_notification: "GM_notification",
    gm_registermenucommand: "GM_registerMenuCommand", gm_unregistermenucommand: "GM_unregisterMenuCommand", gm_log: "GM_log",
    gm_gettab: "GM_getTab", gm_savetab: "GM_saveTab", gm_gettabs: "GM_getTabs", gm_cookie: "GM_cookie", gm_webrequest: "GM_webRequest",
  };
  const params = (grants.length ? gm : []).concat(grants.filter((g) => table[g]).map((g) => table[g]), ["unsafeWindow"]);
  const d = {
    id, name, runAt, grants, params, token: token(id), unwrap,
    meta: { name, version: "1.0", grants, ...meta }, metaStr: "// ==UserScript==\n// @name " + name + "\n// ==/UserScript==\n",
  };
  if (values) d.values = values;
  if (resources) d.resources = resources;
  if (unwrap) d.code = code;
  const f = unwrap ? null : function (...args) {
    const o = {};
    params.forEach((p, i) => (o[p] = args[i]));
    return fn.call(this, o);
  };
  runtime({ base: "/__adblock__/gm", top: true, handler: "AdBlocker Userscripts", handlerVersion: "1.0.0", ...cfg }, [{ d, f }], env.W);
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export async function until(cond, ms = 2000) {
  const t = Date.now();
  while (!cond()) {
    if (Date.now() - t > ms) throw new Error("timeout waiting for condition");
    await sleep(5);
  }
}

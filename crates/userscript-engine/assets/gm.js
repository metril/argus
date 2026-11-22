/* Userscript runtime for the ad-blocking proxy: original code written from the public
 * GM_* / GM.* API documentation. This file is ONE function expression:
 *     (function (cfg, entries, W, SH) { ... })
 * The generated bundle calls it with the config, the script entries and `window`.
 * It runs at document-start, before page scripts, and captures every built-in it needs
 * first; nothing below looks a built-in up on a global after that point.
 * Protocol: docs/USERSCRIPT-PROTOCOL.md. */
function (cfg, entries, W) {
  "use strict";

  // ---- 0. captured built-ins (never re-read from globals later) ---------------------------
  var bindFn = Function.prototype.bind;
  var uncurry = bindFn.bind(Function.prototype.call); // uncurry(f)(self, ...args)
  var fApply = uncurry(Function.prototype.apply);
  var hasOwn = uncurry(Object.prototype.hasOwnProperty);
  var Obj = Object, ObjDefine = Obj.defineProperty, ObjFreeze = Obj.freeze, ObjKeys = Obj.keys,
      ObjCreate = Obj.create, ObjDesc = Obj.getOwnPropertyDescriptor;
  var aPush = uncurry(Array.prototype.push), aSlice = uncurry(Array.prototype.slice), aConcat = uncurry(Array.prototype.concat),
      aSplice = uncurry(Array.prototype.splice), aJoin = uncurry(Array.prototype.join);
  var sIndexOf = uncurry(String.prototype.indexOf), sSlice = uncurry(String.prototype.slice),
      sLower = uncurry(String.prototype.toLowerCase), sSplit = uncurry(String.prototype.split),
      sTrim = uncurry(String.prototype.trim), sCharCode = uncurry(String.prototype.charCodeAt);
  var isArray = Array.isArray, StringFromCharCode = String.fromCharCode, Str = String, parseI = parseInt,
      encURI = encodeURIComponent;
  var atobF = bindFn.call(W.atob, W), btoaF = bindFn.call(W.btoa, W);
  var JSONparse = JSON.parse, JSONstringify = JSON.stringify;
  var P = Promise, pThen = uncurry(P.prototype.then);
  var Err = Error, TypeErr = TypeError;
  var NOW = Date.now, rand = Math.random, floor = Math.floor;
  var ErrorCtor = Err;
  var setT = bindFn.call(W.setTimeout, W), clearT = bindFn.call(W.clearTimeout, W),
      setI = bindFn.call(W.setInterval, W), clearI = bindFn.call(W.clearInterval, W);
  var _fetch = W.fetch ? bindFn.call(W.fetch, W) : null;
  var U8 = W.Uint8Array, AB = W.ArrayBuffer, BlobC = W.Blob, URLC = W.URL, TE = W.TextEncoder,
      TD = W.TextDecoder, AC = W.AbortController, FD = W.FormData, USP = W.URLSearchParams,
      RS = W.ReadableStream, Resp = W.Response, DP = W.DOMParser, MO = W.MutationObserver,
      BC = W.BroadcastChannel;
  var respJson = Resp ? uncurry(Resp.prototype.json) : null, respAB = Resp ? uncurry(Resp.prototype.arrayBuffer) : null;
  var hdrGet = W.Headers ? uncurry(W.Headers.prototype.get) : null;
  var bodyDesc = Resp ? ObjDesc(Resp.prototype, "body") : null;
  var getBody = bodyDesc && bodyDesc.get ? uncurry(bodyDesc.get) : null;
  var rsGetReader = RS ? uncurry(RS.prototype.getReader) : null;
  var rdRead = W.ReadableStreamDefaultReader ? uncurry(W.ReadableStreamDefaultReader.prototype.read) : null;
  var con = W.console || {};
  var conLog = con.log ? bindFn.call(con.log, con) : function () {};
  var conErr = con.error ? bindFn.call(con.error, con) : conLog;
  var conWarn = con.warn ? bindFn.call(con.warn, con) : conLog;
  var D = W.document, L = W.location;
  var protoOf = function (name) { return W[name] && W[name].prototype; };
  var evProto = protoOf("EventTarget"), nodeProto = protoOf("Node"), elProto = protoOf("Element"),
      docProto = protoOf("Document");
  var addEL = evProto ? uncurry(evProto.addEventListener) : function (t, n, f) { t.addEventListener(n, f); };
  var rmEL = evProto ? uncurry(evProto.removeEventListener) : function (t, n, f) { t.removeEventListener(n, f); };
  var dispatch = evProto ? uncurry(evProto.dispatchEvent) : function (t, e) { return t.dispatchEvent(e); };
  var mkEl = docProto ? uncurry(docProto.createElement) : function (d, t) { return d.createElement(t); };
  var appendC = nodeProto ? uncurry(nodeProto.appendChild) : function (p, c) { return p.appendChild(c); };
  var removeC = nodeProto ? uncurry(nodeProto.removeChild) : function (p, c) { return p.removeChild(c); };
  var setAttr = elProto ? uncurry(elProto.setAttribute) : function (e, n, v) { e.setAttribute(n, v); };
  var tcDesc = nodeProto && ObjDesc(nodeProto, "textContent");
  var setText = tcDesc && tcDesc.set ? uncurry(tcDesc.set) : function (n, t) { n.textContent = t; };
  var Ev = W.Event, CE = W.CustomEvent;
  var SS = null;
  try { SS = W.sessionStorage; } catch (e) { SS = null; }
  var ssGet = SS ? uncurry(W.Storage.prototype.getItem) : null,
      ssSet = SS ? uncurry(W.Storage.prototype.setItem) : null;
  var cur = D && D.currentScript;
  var nonce = cur ? (cur.nonce || "") : "";
  if (cur && cur.parentNode) { try { removeC(cur.parentNode, cur); } catch (e) { /* ignore */ } }

  // ---- 1. small helpers --------------------------------------------------------------------
  function dict() { return ObjCreate(null); }
  function clone(v) {
    if (v === undefined) { return undefined; }
    return JSONparse(JSONstringify(v));
  }
  var pResolve = bindFn.call(P.resolve, P), pReject = bindFn.call(P.reject, P), pAll = bindFn.call(P.all, P);
  var TAProto = Object.getPrototypeOf(U8.prototype);
  var u8set = uncurry(TAProto.set), u8slice = uncurry(TAProto.slice), u8sub = uncurry(TAProto.subarray);
  function newPromise(fn) { return new P(fn); }
  function resolved(v) { return pResolve(v); }
  function rejected(e) { return pReject(e); }
  function mkError(code, msg) { var e = new Err(msg); try { e.code = code; } catch (x) { /* ignore */ } return e; }
  function isFn(f) { return typeof f === "function"; }
  function safeCall(label, f, self, args) {
    try { return fApply(f, self, args || []); } catch (e) { conErr("[userscript " + label + "]", e); }
  }
  var encoder = TE ? new TE() : null;
  var tdDecode = TD ? uncurry(TD.prototype.decode) : null, tdEncode = TE ? uncurry(TE.prototype.encode) : null;
  function decodeUtf8(b) { return tdDecode(new TD(), b); }
  function utf8(s) { return tdEncode(encoder, s); }
  function latin1(s) {
    var out = new U8(s.length);
    for (var i = 0; i < s.length; i++) { out[i] = sCharCode(s, i) & 255; }
    return out;
  }
  function concatBytes(parts, total) {
    var out = new U8(total), off = 0;
    for (var i = 0; i < parts.length; i++) { u8set(out, parts[i], off); off += parts[i].length; }
    return out;
  }
  function b64OfBytes(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i += 0x8000) {
      s += StringFromCharCode.apply(null, aSlice(bytes, i, i + 0x8000));
    }
    return btoaF(s);
  }
  function randomId() { return floor(rand() * 4294967296).toString(36) + NOW().toString(36); }
  var tabId = randomId();
  function absUrl(u) { try { return new URLC(Str(u), L.href).href; } catch (e) { return Str(u); } }

  // ---- 2. backend client -----------------------------------------------------------------
  function exposeErr(env, status) {
    var er = env && env.error ? env.error : { code: "internal", message: "HTTP " + status };
    return mkError(er.code, er.message);
  }
  function makeClient(d) {
    var token = d.token;
    var tokenExp = parseI(sSplit(token, ".")[2], 10) || 0;
    function headers(extra) {
      var h = { "X-GM-Token": token };
      if (extra) { for (var k in extra) { h[k] = extra[k]; } }
      return h;
    }
    function json(path, body) {
      return pThen(_fetch(cfg.base + "/v1/" + path, {
        method: "POST", credentials: "omit", cache: "no-store", redirect: "error",
        headers: headers({ "Content-Type": "application/json" }), body: JSONstringify(body || {})
      }), function (res) {
        return pThen(respJson(res), function (env) {
          if (!env || env.ok !== true) { throw exposeErr(env, res.status); }
          return env.result;
        }, function () { throw mkError("internal", "bad response from " + path); });
      });
    }
    function refresh() {
      return pThen(json("token/refresh", {}), function (r) {
        if (r && r.token) { token = r.token; tokenExp = r.exp || 0; }
      });
    }
    function schedule() {
      if (!tokenExp) { return; }
      var life = tokenExp * 1000 - NOW();
      var t = setT(function () { pThen(refresh(), schedule, function () { setT(schedule, 30000); }); },
        life > 120000 ? life / 2 : 20000);
      if (t && t.unref) { t.unref(); }
    }
    schedule();
    return { json: json, headers: headers, token: function () { return token; } };
  }

  // ---- 3. per-script API ---------------------------------------------------------------------
  // The command registry is shared by every script of the document (and by the in-page panel):
  // it lives in SH, created once by the shared runtime script (see bundle::runtime_script).
  var menu = SH.menu;
  function menuChanged() { SH.changed(); }

  var urlListeners = null;
  function installUrlChange() {
    if (urlListeners) { return; }
    urlListeners = true;
    var last = L.href;
    function fire() {
      if (L.href === last) { return; }
      last = L.href;
      var e;
      try { e = new CE("urlchange", { detail: { url: last } }); } catch (x) { e = new Ev("urlchange"); e.url = last; }
      try { ObjDefine(e, "url", { value: last }); } catch (x) { /* ignore */ }
      var h = W.onurlchange;
      if (isFn(h)) { safeCall("onurlchange", h, W, [e]); }
      dispatch(W, e);
    }
    var hist = W.history, proto = W.History && W.History.prototype;
    var methods = ["pushState", "replaceState"];
    for (var mi = 0; mi < methods.length; mi++) {
      (function (m) {
        var orig = proto[m];
        proto[m] = function () { var r = fApply(orig, this, arguments); fire(); return r; };
      })(methods[mi]);
    }
    addEL(W, "popstate", fire); addEL(W, "hashchange", fire);
    if (!("onurlchange" in W)) { try { W.onurlchange = null; } catch (x) { /* ignore */ } }
  }

  function makeApi(d, valuesInit) {
    var granted = dict(), i;
    for (i = 0; i < d.grants.length; i++) { granted[d.grants[i]] = true; }
    var client = makeClient(d);
    var label = d.name;
    var api = dict(), gm = dict();
    function has(c) { return granted[c] === true; }
    function expose(canon, gmName, dot, fn, dotFn) {
      if (!has(canon)) { return; }
      api[gmName] = fn;
      if (dot) { gm[dot] = dotFn || fn; }
    }

    // GM_info
    var info = {
      script: clone(d.meta), scriptMetaStr: d.metaStr, scriptHandler: cfg.handler, version: cfg.handlerVersion,
      scriptWillUpdate: false, scriptUpdateURL: d.meta.updateURL || null, isIncognito: false, injectInto: "page",
      sandboxMode: "raw", platform: { os: "unknown", browserName: "unknown", browserVersion: "" },
      downloadMode: "browser", isFirstPartyIsolation: false, userAgent: W.navigator ? W.navigator.userAgent : ""
    };
    info.script.uuid = d.id; info.uuid = d.id;
    // ---- values (sync cache, ordered async write-behind)
    var vals = dict(), loaded = false, loadP = null;
    function seed(obj) { for (var k in obj) { vals[k] = obj[k]; } loaded = true; }
    if (valuesInit) { seed(valuesInit); }
    function ensureLoaded() {
      if (loaded) { return resolved(); }
      if (!loadP) {
        loadP = pThen(client.json("values/get", { names: null }), function (r) { seed(r || {}); }, function (e) {
          loaded = true; conErr("[userscript " + label + "] could not load values:", e);
        });
      }
      return loadP;
    }
    var chain = resolved();
    function enqueue(fn) {
      var p = pThen(chain, fn, fn);
      chain = pThen(p, function () {}, function () {});
      return p;
    }
    var changeListeners = dict(), listenerSeq = 0, listenerCount = 0, serverSeq = null, pollTimer = null;
    var chan = null;
    function fireChange(name, oldV, newV, remote) {
      var ids = ObjKeys(changeListeners);
      for (var j = 0; j < ids.length; j++) {
        var l = changeListeners[ids[j]];
        if (l && l.name === name) { safeCall(label, l.cb, W, [name, clone(oldV), clone(newV), remote]); }
      }
    }
    function applyRemote(name, newV, oldV, hasNew) {
      var prev = vals[name];
      if (hasNew) { vals[name] = newV; } else { delete vals[name]; }
      fireChange(name, oldV === undefined ? prev : oldV, hasNew ? newV : undefined, true);
    }
    function openChan() {
      if (chan || !BC) { return; }
      try {
        chan = new BC("adblock-gm:" + d.id);
        chan.onmessage = function (ev) {
          var m = ev && ev.data;
          if (!m || m.tab === tabId || m.t !== "set") { return; }
          applyRemote(m.name, m.new, m.old, m.has);
        };
      } catch (e) { chan = null; }
    }
    openChan();
    function poll() {
      pThen(client.json("values/changes", { since: serverSeq }), function (r) {
        if (!r) { return; }
        if (serverSeq === null) { serverSeq = r.seq; return; }
        if (r.reset) {
          serverSeq = r.seq;
          loaded = false; loadP = null; vals = dict(); ensureLoaded();
          return;
        }
        serverSeq = r.seq;
        for (var j = 0; j < r.changes.length; j++) {
          var c = r.changes[j];
          if (c.src === tabId) { continue; }
          var had = c.new !== null && c.new !== undefined;
          applyRemote(c.name, c.new, c.old, had);
        }
      }, function () { /* transient; try again next tick */ });
    }
    function startPolling() {
      if (pollTimer || !client) { return; }
      poll();
      pollTimer = setI(poll, 2500);
      if (pollTimer && pollTimer.unref) { pollTimer.unref(); }
    }
    function sendSet(name, v) {
      var vs = {}; vs[name] = v === undefined ? null : v;
      return enqueue(function () { return client.json("values/set", { values: vs, src: tabId }); });
    }
    function setValueNow(name, value) {
      name = Str(name);
      var had = name in vals, old = had ? vals[name] : undefined;
      var nv = value === undefined ? null : clone(value);
      vals[name] = nv;
      if (chan) { try { chan.postMessage({ t: "set", tab: tabId, name: name, new: nv, old: old, has: true }); } catch (e) { /* ignore */ } }
      if (JSONstringify(old) !== JSONstringify(nv)) { fireChange(name, old, nv, false); }
      return pThen(sendSet(name, nv), function () {}, function (e) {
        if (had) { vals[name] = old; } else { delete vals[name]; }
        throw e;
      });
    }
    function deleteValueNow(name) {
      name = Str(name);
      var had = name in vals, old = vals[name];
      delete vals[name];
      if (chan) { try { chan.postMessage({ t: "set", tab: tabId, name: name, old: old, has: false }); } catch (e) { /* ignore */ } }
      if (had) { fireChange(name, old, undefined, false); }
      return enqueue(function () { return client.json("values/delete", { names: [name], src: tabId }); });
    }
    function swallow(p, what) { pThen(p, function () {}, function (e) { conErr("[userscript " + label + "] " + what + " failed:", e); }); }
    function getValueSync(name, def) { name = Str(name); return name in vals ? clone(vals[name]) : def; }
    function listSync() { return ObjKeys(vals); }
    function getValuesSync(spec) {
      var out = {};
      if (isArray(spec)) { for (var j = 0; j < spec.length; j++) { out[spec[j]] = getValueSync(spec[j]); } }
      else if (spec && typeof spec === "object") { for (var k in spec) { out[k] = getValueSync(k, spec[k]); } }
      else { var all = listSync(); for (var m = 0; m < all.length; m++) { out[all[m]] = getValueSync(all[m]); } }
      return out;
    }
    function setValuesNow(obj) {
      var ps = [];
      for (var k in obj) { aPush(ps, setValueNow(k, obj[k])); }
      return pThen(pAll(ps), function () {});
    }
    function deleteValuesNow(names) {
      var ps = [];
      for (var j = 0; j < names.length; j++) { aPush(ps, deleteValueNow(names[j])); }
      return pThen(pAll(ps), function () {});
    }
    function addListener(name, cb) {
      if (!isFn(cb)) { throw new TypeErr("callback must be a function"); }
      var id = ++listenerSeq;
      changeListeners[id] = { name: Str(name), cb: cb };
      listenerCount++;
      startPolling();
      return id;
    }
    function removeListener(id) { if (changeListeners[id]) { delete changeListeners[id]; listenerCount--; } }
    var valueGate = function (fn) { return function () { var a = arguments; return pThen(ensureLoaded(), function () { return fApply(fn, null, a); }); }; };

    expose("gm_getvalue", "GM_getValue", "getValue", function (n, def) { return getValueSync(n, def); },
      valueGate(function (n, def) { return getValueSync(n, def); }));
    expose("gm_setvalue", "GM_setValue", "setValue", function (n, v) { swallow(setValueNow(n, v), "GM_setValue"); },
      valueGate(function (n, v) { return setValueNow(n, v); }));
    expose("gm_deletevalue", "GM_deleteValue", "deleteValue", function (n) { swallow(deleteValueNow(n), "GM_deleteValue"); },
      valueGate(function (n) { return deleteValueNow(n); }));
    expose("gm_listvalues", "GM_listValues", "listValues", listSync, valueGate(listSync));
    expose("gm_getvalues", "GM_getValues", "getValues", getValuesSync, valueGate(getValuesSync));
    expose("gm_setvalues", "GM_setValues", "setValues", function (o) { swallow(setValuesNow(o), "GM_setValues"); },
      valueGate(function (o) { return setValuesNow(o); }));
    expose("gm_deletevalues", "GM_deleteValues", "deleteValues", function (n) { swallow(deleteValuesNow(n), "GM_deleteValues"); },
      valueGate(function (n) { return deleteValuesNow(n); }));
    expose("gm_addvaluechangelistener", "GM_addValueChangeListener", "addValueChangeListener", addListener,
      function (n, cb) { return resolved(addListener(n, cb)); });
    expose("gm_removevaluechangelistener", "GM_removeValueChangeListener", "removeValueChangeListener", removeListener,
      function (id) { removeListener(id); return resolved(); });
    if (!has("gm_getvalue") && !has("gm_setvalue") && !has("gm_listvalues")) { /* no value access: nothing preloaded is used */ }

    // ---- DOM helpers
    function whenRoot(fn) {
      if (D.head || D.documentElement) { return fn(D.head || D.documentElement); }
      var mo = new MO(function () { if (D.documentElement) { mo.disconnect(); fn(D.head || D.documentElement); } });
      mo.observe(D, { childList: true });
    }
    function addStyle(css) {
      var el = mkEl(D, "style");
      setAttr(el, "type", "text/css");
      if (nonce) { setAttr(el, "nonce", nonce); }
      setText(el, Str(css));
      whenRoot(function (root) { appendC(root, el); });
      return el;
    }
    function addElement(a, b, c) {
      var parent, tag, attrs;
      if (typeof a === "string") { tag = a; attrs = b; parent = D.head || D.body || D.documentElement; }
      else { parent = a; tag = b; attrs = c; }
      var el = mkEl(D, Str(tag));
      attrs = attrs || {};
      for (var k in attrs) {
        if (k === "textContent") { setText(el, Str(attrs[k])); }
        else if (k === "innerHTML") { throw new TypeErr("addElement: innerHTML is not allowed; use textContent"); }
        else if (k === "on" || sIndexOf(sLower(k), "on") === 0 && sLower(k) === k && isFn(attrs[k])) { /* ignore handlers */ }
        else { setAttr(el, k, Str(attrs[k])); }
      }
      if (tag === "script" || tag === "style") { if (nonce) { setAttr(el, "nonce", nonce); } }
      if (parent) { appendC(parent, el); } else { whenRoot(function (root) { appendC(root, el); }); }
      return el;
    }
    expose("gm_addstyle", "GM_addStyle", "addStyle", addStyle, function (c) { return resolved(addStyle(c)); });
    expose("gm_addelement", "GM_addElement", "addElement", addElement, function (a, b, c) { return resolved(addElement(a, b, c)); });

    // ---- resources
    var resCache = dict();
    function inlineRes(name) { return d.resources && hasOwn(d.resources, name) ? d.resources[name] : null; }
    function fetchRes(name) {
      if (resCache[name]) { return resCache[name]; }
      return (resCache[name] = pThen(_fetch(cfg.base + "/v1/resource?name=" + encURI(name), {
        credentials: "omit", cache: "no-store", redirect: "error", headers: client.headers()
      }), function (res) {
        if (!res.ok) { throw mkError("not_found", "no such @resource: " + name); }
        var mime = hdrGet(res.headers, "content-type") || "application/octet-stream";
        return pThen(respAB(res), function (buf) { return { mime: mime, bytes: new U8(buf) }; });
      }));
    }
    function resText(name) {
      var r = inlineRes(name);
      if (r) { return r.text !== undefined ? r.text : decodeUtf8(bytesOfB64(r.b64)); }
      conWarn("[userscript " + label + "] @resource " + name + " is not inlined; use GM.getResourceText");
      return undefined;
    }
    function bytesOfB64(b) { var s = atobF(b), o = new U8(s.length); for (var j = 0; j < s.length; j++) { o[j] = sCharCode(s, j); } return o; }
    function dataUrl(mime, bytes) { return "data:" + mime + ";base64," + b64OfBytes(bytes); }
    function resUrlSync(name, blob) {
      var r = inlineRes(name);
      if (!r) { conWarn("[userscript " + label + "] @resource " + name + " is not inlined; use GM.getResourceUrl"); return undefined; }
      var bytes = r.text !== undefined ? utf8(r.text) : bytesOfB64(r.b64);
      return blob ? URLC.createObjectURL(new BlobC([bytes], { type: r.mime })) : dataUrl(r.mime, bytes);
    }
    expose("gm_getresourcetext", "GM_getResourceText", "getResourceText", resText, function (name) {
      var r = inlineRes(name);
      if (r) { return resolved(resText(name)); }
      return pThen(fetchRes(name), function (x) { return decodeUtf8(x.bytes); });
    });
    expose("gm_getresourceurl", "GM_getResourceURL", "getResourceUrl", resUrlSync, function (name, blob) {
      var r = inlineRes(name);
      if (r) { return resolved(resUrlSync(name, blob)); }
      return pThen(fetchRes(name), function (x) {
        return blob ? URLC.createObjectURL(new BlobC([x.bytes], { type: x.mime })) : dataUrl(x.mime, x.bytes);
      });
    });

    // ---- network: xmlhttpRequest / download over the framed endpoint
    function toBytes(data, binary, hdrs) {
      // resolves to Uint8Array | null; may set a Content-Type default in `hdrs`
      if (data === undefined || data === null) { return resolved(null); }
      if (typeof data === "string") { return resolved(binary ? latin1(data) : utf8(data)); }
      if (AB && data instanceof AB) { return resolved(new U8(data)); }
      if (AB && AB.isView && AB.isView(data)) { return resolved(new U8(data.buffer, data.byteOffset, data.byteLength)); }
      if (BlobC && data instanceof BlobC) {
        if (data.type && !hdrs.has("content-type")) { hdrs.set("content-type", data.type); }
        return pThen(data.arrayBuffer(), function (b) { return new U8(b); });
      }
      if (FD && data instanceof FD) {
        var r = new Resp(data);
        hdrs.set("content-type", r.headers.get("content-type"));
        return pThen(r.arrayBuffer(), function (b) { return new U8(b); });
      }
      if (USP && data instanceof USP) {
        if (!hdrs.has("content-type")) { hdrs.set("content-type", "application/x-www-form-urlencoded;charset=UTF-8"); }
        return resolved(utf8(data.toString()));
      }
      return resolved(utf8(Str(data)));
    }
    function hdrBag(obj) {
      var keys = [], vals2 = {}, idx = {};
      if (obj) { for (var k in obj) { var lk = sLower(k); aPush(keys, k); vals2[lk] = obj[k]; idx[lk] = k; } }
      return {
        has: function (n) { return hasOwn(vals2, n); },
        set: function (n, v) { if (!hasOwn(vals2, n)) { idx[n] = n; } vals2[n] = v; },
        list: function () { var out = []; for (var lk in vals2) { aPush(out, [idx[lk], Str(vals2[lk])]); } return out; }
      };
    }
    function frameRequest(meta, body) {
      var m = utf8(JSONstringify(meta)), total = 4 + m.length + (body ? body.length : 0);
      var out = new U8(total);
      out[0] = (m.length >>> 24) & 255; out[1] = (m.length >>> 16) & 255; out[2] = (m.length >>> 8) & 255; out[3] = m.length & 255;
      u8set(out, m, 4);
      if (body) { u8set(out, body, 4 + m.length); }
      return out;
    }
    function parseRawHeaders(list) {
      var s = "";
      for (var j = 0; j < list.length; j++) { s += list[j][0] + ": " + list[j][1] + "\r\n"; }
      return s;
    }
    function headerOf(list, name) {
      for (var j = 0; j < list.length; j++) { if (sLower(list[j][0]) === name) { return list[j][1]; } }
      return "";
    }
    function charsetOf(ct, override) {
      var src = override || ct || "", m = /charset\s*=\s*"?([^";\s]+)/i.exec(src);
      return m ? m[1] : "utf-8";
    }
    function decodeText(bytes, ct, override) {
      try { return tdDecode(new TD(charsetOf(ct, override)), bytes); } catch (e) { return decodeUtf8(bytes); }
    }

    function request(op, details) {
      var ctl = AC ? new AC() : null;
      var aborted = false, finished = false, timer = null;
      var ctrl = { abort: function () {
        if (finished || aborted) { return; }
        aborted = true;
        if (ctl) { ctl.abort(); }
        if (timer) { clearT(timer); }
        fire("onabort", state(0, 0, "", "", details.url, null, 0, 0, false));
      } };
      var rt = details.responseType || "";
      var cbs = details;
      var upload = details.upload || {};
      var url = absUrl(details.url);
      var hdrs = hdrBag(details.headers);
      var resp = { status: 0, statusText: "", headersList: [], finalUrl: url, parts: [], total: 0, loaded: 0, streamCtl: null, stream: null };
      function fire(name, ev) { if (isFn(cbs[name])) { safeCall(label, cbs[name], W, [ev]); } }
      function fireUp(name, ev) { if (isFn(upload[name])) { safeCall(label, upload[name], W, [ev]); } }
      function state(ready, status, statusText, rawHeaders, finalUrl, response, loaded, total, lengthComputable, text) {
        var ev = {
          readyState: ready, status: status, statusText: statusText, responseHeaders: rawHeaders, finalUrl: finalUrl,
          response: response, responseText: text === undefined ? (typeof response === "string" ? response : "") : text,
          responseXML: null, context: details.context, lengthComputable: !!lengthComputable, loaded: loaded, total: total
        };
        return ev;
      }
      function finalState(ready) {
        var bytes = concatBytes(resp.parts, resp.loaded), ct = headerOf(resp.headersList, "content-type");
        var response, text = "";
        if (rt === "arraybuffer") { response = bytes.buffer; }
        else if (rt === "blob") { response = new BlobC([bytes], { type: details.overrideMimeType || ct }); }
        else if (rt === "stream") { response = resp.stream; }
        else {
          text = decodeText(bytes, ct, details.overrideMimeType);
          response = text;
          if (rt === "json") { try { response = JSONparse(text); } catch (e) { response = null; } }
        }
        var ev = state(ready, resp.status, resp.statusText, parseRawHeaders(resp.headersList), resp.finalUrl, response, resp.loaded, resp.total, resp.total > 0, rt === "arraybuffer" || rt === "blob" || rt === "stream" ? "" : text);
        if (rt === "document" && DP) {
          try { ev.response = new DP().parseFromString(text, sSplit(details.overrideMimeType || ct || "text/html", ";")[0]); ev.responseXML = ev.response; } catch (e) { ev.response = null; }
        } else if (rt === "" || rt === "text") {
          if (/[/+]xml/i.test(ct) && DP) { try { ev.responseXML = new DP().parseFromString(text, "application/xml"); } catch (e) { /* ignore */ } }
        }
        return ev;
      }
      function fail(name, msg, status) {
        if (finished) { return; }
        finished = true;
        if (timer) { clearT(timer); }
        var ev = state(4, status || 0, "", "", url, null, resp.loaded, resp.total, false);
        ev.error = msg;
        fire(name, ev);
        fire("onloadend", ev);
      }
      function done() {
        if (finished) { return; }
        finished = true;
        if (timer) { clearT(timer); }
        if (resp.streamCtl) { try { resp.streamCtl.close(); } catch (e) { /* ignore */ } }
        var ev = finalState(4);
        fire("onreadystatechange", ev);
        fire("onload", ev);
        fire("onloadend", ev);
      }
      if (details.timeout > 0) {
        timer = setT(function () {
          if (finished || aborted) { return; }
          if (ctl) { ctl.abort(); }
          fail("ontimeout", "timeout");
        }, details.timeout);
      }
      if (!_fetch) { fail("onerror", "fetch is unavailable"); return ctrl; }
      pThen(pThen(toBytes(details.data, details.binary === true, hdrs), function (body) {
        var meta = {
          op: op, method: details.method || (body ? "POST" : "GET"), url: url, headers: hdrs.list(),
          anonymous: !!details.anonymous, cookie: details.cookie || null, user: details.user || null,
          password: details.password || null, timeout: details.timeout || 0,
          redirect: details.redirect === "error" || details.redirect === "manual" ? details.redirect : "follow"
        };
        var framed = frameRequest(meta, body);
        if (body) { var up = state(1, 0, "", "", url, null, 0, body.length, true); fireUp("onloadstart", up); }
        return pThen(_fetch(cfg.base + "/v1/xhr", {
          method: "POST", credentials: "omit", cache: "no-store", redirect: "error",
          headers: client.headers({ "Content-Type": "application/x-gm-frame" }), body: framed, signal: ctl ? ctl.signal : undefined
        }), function (res) {
          if (body) {
            var upe = state(1, 0, "", "", url, null, body.length, body.length, true);
            fireUp("onprogress", upe); fireUp("onload", upe); fireUp("onloadend", upe);
          }
          var ctype = hdrGet(res.headers, "content-type") || "";
          if (sIndexOf(ctype, "application/x-gm-frames") !== 0) {
            return pThen(respJson(res), function (env) { throw exposeErr(env, res.status); });
          }
          return readFrames(res);
        });
      }), null, function (e) {
        if (aborted) { return; }
        fail("onerror", e && e.message ? e.message : Str(e));
      });

      function handleFrame(type, payload) {
        if (finished || aborted) { return; }
        if (type === 1) {
          var h = JSONparse(decodeUtf8(payload));
          resp.status = h.status; resp.statusText = h.statusText || ""; resp.headersList = h.headers || [];
          resp.finalUrl = h.finalUrl || url;
          resp.total = parseI(headerOf(resp.headersList, "content-length"), 10) || 0;
          if (rt === "stream" && RS) {
            resp.stream = new RS({ start: function (c) { resp.streamCtl = c; } });
          }
          fire("onreadystatechange", state(2, resp.status, resp.statusText, parseRawHeaders(resp.headersList), resp.finalUrl, null, 0, resp.total, resp.total > 0));
          if (rt === "stream") { var se = state(3, resp.status, resp.statusText, parseRawHeaders(resp.headersList), resp.finalUrl, resp.stream, 0, resp.total, resp.total > 0); fire("onreadystatechange", se); }
        } else if (type === 2) {
          resp.loaded += payload.length;
          if (rt === "stream" && resp.streamCtl) { resp.streamCtl.enqueue(payload); }
          else { aPush(resp.parts, payload); }
          if (isFn(cbs.onprogress)) {
            fire("onprogress", state(3, resp.status, resp.statusText, parseRawHeaders(resp.headersList), resp.finalUrl, null, resp.loaded, resp.total, resp.total > 0));
          }
        } else if (type === 3) {
          done();
        } else if (type === 4) {
          var er = JSONparse(decodeUtf8(payload));
          fail(er.kind === "timeout" ? "ontimeout" : "onerror", er.message || er.code || "request failed", er.status);
        }
      }
      function readFrames(res) {
        var rbody = getBody ? getBody(res) : res.body;
        if (!rbody || !rsGetReader) {
          return pThen(respAB(res), function (b) { parseBuffer(new U8(b)); });
        }
        var reader = rsGetReader(rbody), buf = new U8(0);
        function pump() {
          return pThen(rdRead(reader), function (r) {
            if (r.done) { if (!finished && !aborted) { fail("onerror", "connection closed early"); } return; }
            buf = buf.length ? concatBytes([buf, r.value], buf.length + r.value.length) : r.value;
            buf = drain(buf);
            return pump();
          });
        }
        return pump();
      }
      function drain(buf) {
        var off = 0;
        while (buf.length - off >= 5) {
          var len = ((buf[off + 1] << 24) | (buf[off + 2] << 16) | (buf[off + 3] << 8) | buf[off + 4]) >>> 0;
          if (buf.length - off - 5 < len) { break; }
          handleFrame(buf[off], u8slice(buf, off + 5, off + 5 + len));
          off += 5 + len;
        }
        return off ? u8slice(buf, off) : buf;
      }
      function parseBuffer(buf) { drain(buf); }
      return ctrl;
    }

    function xhrCb(details) {
      if (!details || typeof details !== "object") { throw new TypeErr("GM_xmlhttpRequest needs a details object"); }
      if (!details.url) { throw new TypeErr("GM_xmlhttpRequest needs a url"); }
      return request("xhr", details);
    }
    function xhrPromise(details) {
      var ctrl, p = newPromise(function (res, rej) {
        var d2 = {}; for (var k in details) { d2[k] = details[k]; }
        var onload = details.onload, onerror = details.onerror, ontimeout = details.ontimeout, onabort = details.onabort;
        d2.onload = function (r) { if (isFn(onload)) { onload(r); } res(r); };
        d2.onerror = function (r) { if (isFn(onerror)) { onerror(r); } rej(r); };
        d2.ontimeout = function (r) { if (isFn(ontimeout)) { ontimeout(r); } rej(r); };
        d2.onabort = function (r) { if (isFn(onabort)) { onabort(r); } rej(r); };
        ctrl = xhrCb(d2);
      });
      p.abort = function () { ctrl.abort(); };
      return p;
    }
    expose("gm_xmlhttprequest", "GM_xmlhttpRequest", "xmlHttpRequest", xhrCb, xhrPromise);
    if (has("gm_xmlhttprequest")) { gm.xmlhttpRequest = xhrPromise; }

    function download(arg, name) {
      var det = typeof arg === "string" ? { url: arg, name: name } : (arg || {});
      if (!det.url) { throw new TypeErr("GM_download needs a url"); }
      var d2 = {};
      for (var k in det) { d2[k] = det[k]; }
      d2.responseType = "blob";
      d2.onload = function (r) {
        if (r.status >= 400) { if (isFn(det.onerror)) { safeCall(label, det.onerror, W, [{ error: "not_succeeded", details: "HTTP " + r.status }]); } return; }
        try {
          var a = mkEl(D, "a");
          var href = URLC.createObjectURL(r.response);
          setAttr(a, "href", href);
          setAttr(a, "download", det.name || fileNameOf(det.url));
          a.style.display = "none";
          appendC(D.body || D.documentElement, a);
          a.click();
          setT(function () { removeC(a.parentNode, a); URLC.revokeObjectURL(href); }, 1000);
          if (isFn(det.onload)) { safeCall(label, det.onload, W, [{ finalUrl: r.finalUrl }]); }
        } catch (e) { if (isFn(det.onerror)) { safeCall(label, det.onerror, W, [{ error: "not_permitted", details: Str(e) }]); } }
      };
      d2.onerror = function (r) { if (isFn(det.onerror)) { safeCall(label, det.onerror, W, [{ error: "not_succeeded", details: r.error }]); } };
      d2.ontimeout = function () { if (isFn(det.ontimeout)) { safeCall(label, det.ontimeout, W, [{}]); } };
      d2.onprogress = function (r) { if (isFn(det.onprogress)) { safeCall(label, det.onprogress, W, [{ loaded: r.loaded, total: r.total, lengthComputable: r.lengthComputable }]); } };
      return request("download", d2);
    }
    function fileNameOf(u) { try { var p = new URLC(u).pathname; return p.slice(p.lastIndexOf("/") + 1) || "download"; } catch (e) { return "download"; } }
    expose("gm_download", "GM_download", "download", download, function (a, n) {
      var ctrl; var p = newPromise(function (res, rej) {
        var det = typeof a === "string" ? { url: a, name: n } : (a || {});
        var d2 = {}; for (var k in det) { d2[k] = det[k]; }
        d2.onload = function (r) { if (isFn(det.onload)) { det.onload(r); } res(r); };
        d2.onerror = function (r) { if (isFn(det.onerror)) { det.onerror(r); } rej(r); };
        d2.ontimeout = function (r) { if (isFn(det.ontimeout)) { det.ontimeout(r); } rej(r); };
        ctrl = download(d2);
      });
      p.abort = function () { ctrl.abort(); };
      return p;
    });

    // ---- browser-side utilities
    function openInTab(url, opts) {
      var bg = typeof opts === "boolean" ? opts : (opts && opts.active === false);
      var w = W.open(absUrl(url), "_blank");
      if (bg && W.focus) { try { W.focus(); } catch (e) { /* ignore */ } }
      var tab = { closed: !w, close: function () { if (w) { w.close(); } tab.closed = true; }, onclose: null };
      return tab;
    }
    expose("gm_openintab", "GM_openInTab", "openInTab", openInTab, function (u, o) { return resolved(openInTab(u, o)); });
    function setClipboard(text, infoArg, cb) {
      var type = typeof infoArg === "string" ? infoArg : (infoArg && infoArg.type) || "text";
      var done = isFn(infoArg) ? infoArg : cb;
      var p;
      if (W.navigator && W.navigator.clipboard && W.navigator.clipboard.writeText && sIndexOf(type, "text") === 0) {
        p = W.navigator.clipboard.writeText(Str(text));
      } else {
        p = newPromise(function (res, rej) {
          try {
            var ta = mkEl(D, "textarea"); ta.value = Str(text); ta.style.position = "fixed"; ta.style.opacity = "0";
            appendC(D.body || D.documentElement, ta); ta.select();
            var ok = D.execCommand("copy"); removeC(ta.parentNode, ta);
            if (ok) { res(); } else { rej(mkError("not_permitted", "copy was refused")); }
          } catch (e) { rej(e); }
        });
      }
      pThen(p, function () { if (isFn(done)) { safeCall(label, done, W, []); } }, function (e) { conErr("[userscript " + label + "] clipboard:", e); });
      return p;
    }
    expose("gm_setclipboard", "GM_setClipboard", "setClipboard", function (t, i, c) { setClipboard(t, i, c); }, function (t, i) { return setClipboard(t, i); });
    function notification(a, b, c, d3) {
      var det = typeof a === "object" && a ? a : { text: a, title: b, image: c, onclick: d3 };
      var ondone = isFn(b) && typeof a === "object" ? b : det.ondone;
      var n = null, closed = false;
      function end(reason) { if (closed) { return; } closed = true; if (isFn(ondone)) { safeCall(label, ondone, W, [reason]); } }
      function show() {
        try {
          n = new W.Notification(det.title || label, { body: det.text || "", icon: det.image, silent: !!det.silent, requireInteraction: false });
          n.onclick = function () { if (isFn(det.onclick)) { safeCall(label, det.onclick, W, []); } if (det.url) { W.open(det.url, "_blank"); } end(true); };
          n.onclose = function () { end(false); };
          if (det.timeout > 0) { setT(function () { if (n) { n.close(); } end(false); }, det.timeout); }
        } catch (e) { conWarn("[userscript " + label + "] " + (det.title || "") + " " + (det.text || "")); end(false); }
      }
      if (W.Notification && W.Notification.permission === "granted") { show(); }
      else if (W.Notification && W.Notification.permission !== "denied") { pThen(W.Notification.requestPermission(), function (p) { if (p === "granted") { show(); } else { conWarn("[userscript " + label + "] " + (det.text || "")); end(false); } }); }
      else { conWarn("[userscript " + label + "] " + (det.text || "")); end(false); }
      return { remove: function () { if (n) { n.close(); } end(false); } };
    }
    expose("gm_notification", "GM_notification", "notification", notification, function (a, b, c, d3) { return resolved(notification(a, b, c, d3)); });
    function registerMenu(caption, fn, opt) {
      var id = SH.next(), key = typeof opt === "string" ? opt : (opt && opt.accessKey) || "";
      if (opt && opt.id) { id = opt.id; for (var j = 0; j < menu.length; j++) { if (menu[j].script === d.id && menu[j].id === id) { aSplice(menu, j, 1); break; } } }
      aPush(menu, { script: d.id, scriptName: label, id: id, caption: Str(caption), accessKey: key,
        run: function () { safeCall(label, fn, W, []); } });
      menuChanged();
      return id;
    }
    function unregisterMenu(id) {
      for (var j = 0; j < menu.length; j++) { if (menu[j].script === d.id && menu[j].id === id) { aSplice(menu, j, 1); menuChanged(); return; } }
    }
    expose("gm_registermenucommand", "GM_registerMenuCommand", "registerMenuCommand", registerMenu, function (c, f, o) { return resolved(registerMenu(c, f, o)); });
    expose("gm_unregistermenucommand", "GM_unregisterMenuCommand", "unregisterMenuCommand", unregisterMenu, function (id) { unregisterMenu(id); return resolved(); });
    function log() { var a = aSlice(arguments); a = aConcat(["[" + label + "]"], a); fApply(conLog, con, a); }
    expose("gm_log", "GM_log", "log", log);

    // ---- tabs (per-tab sessionStorage; getTabs asks same-origin tabs over BroadcastChannel)
    var tabKey = "adblock-gm-tab:" + d.id;
    function getTabObj() { try { return ssGet ? JSONparse(ssGet(SS, tabKey) || "{}") : {}; } catch (e) { return {}; } }
    function saveTabObj(o) { try { if (ssSet) { ssSet(SS, tabKey, JSONstringify(o === undefined ? {} : o)); } } catch (e) { conWarn("[userscript " + label + "] saveTab failed", e); } }
    function getTabs() {
      return newPromise(function (res) {
        var out = {}; out[tabId] = getTabObj();
        if (!BC) { res(out); return; }
        var c2;
        try { c2 = new BC("adblock-gm-tabs:" + d.id); } catch (e) { res(out); return; }
        c2.onmessage = function (ev) {
          var m = ev.data;
          if (m && m.t === "tab") { out[m.tab] = m.obj; }
          else if (m && m.t === "ask" && m.tab !== tabId) { c2.postMessage({ t: "tab", tab: tabId, obj: getTabObj() }); }
        };
        c2.postMessage({ t: "ask", tab: tabId });
        setT(function () { c2.close(); res(out); }, 150);
      });
    }
    var tabResponder = null;
    function ensureTabResponder() {
      if (tabResponder || !BC) { return; }
      try {
        tabResponder = new BC("adblock-gm-tabs:" + d.id);
        tabResponder.onmessage = function (ev) {
          var m = ev.data;
          if (m && m.t === "ask" && m.tab !== tabId) { tabResponder.postMessage({ t: "tab", tab: tabId, obj: getTabObj() }); }
        };
      } catch (e) { tabResponder = null; }
    }
    ensureTabResponder();
    expose("gm_gettab", "GM_getTab", "getTab", function (cb) { if (isFn(cb)) { cb(getTabObj()); } }, function () { return resolved(getTabObj()); });
    expose("gm_savetab", "GM_saveTab", "saveTab", function (o, cb) { saveTabObj(o); if (isFn(cb)) { cb(); } }, function (o) { saveTabObj(o); return resolved(); });
    expose("gm_gettabs", "GM_getTabs", "getTabs", function (cb) { pThen(getTabs(), cb); }, getTabs);

    // ---- cookies
    function cookieCall(op, details) {
      var body = { op: op, url: absUrl(details && details.url ? details.url : L.href) };
      if (op === "list") { body.name = details && details.name ? details.name : null; }
      else if (op === "set") { body.cookie = clone(details); delete body.cookie.url; }
      else { body.name = details && details.name; }
      return client.json("cookie", body);
    }
    function cookieFn(op) {
      return function (details, cb) {
        var p = cookieCall(op, details);
        if (isFn(cb)) { pThen(p, function (r) { cb(op === "list" ? r : undefined, undefined); }, function (e) { cb(undefined, e); }); }
        return p;
      };
    }
    if (has("gm_cookie")) {
      var ck = { list: cookieFn("list"), set: cookieFn("set"), "delete": cookieFn("delete") };
      api.GM_cookie = ObjFreeze(ck); gm.cookie = ObjFreeze({ list: function (d1) { return cookieCall("list", d1); }, set: function (d1) { return cookieCall("set", d1); }, "delete": function (d1) { return cookieCall("delete", d1); } });
    }
    // ---- unsupported
    if (has("gm_webrequest")) {
      var unsup = function () { return mkError("unsupported", "GM_webRequest is not supported: scripts run through a proxy, without access to the browser's request pipeline"); };
      api.GM_webRequest = function () { throw unsup(); };
      gm.webRequest = function () { return rejected(unsup()); };
    }
    if (has("window.onurlchange")) { installUrlChange(); }
    if (has("window.close") || has("window.focus")) { /* native window.close/focus are already reachable in the page world */ }

    // GM_info / GM.info, exposed whenever any API was granted
    var anyGrant = d.grants.length > 0;
    if (anyGrant) { api.GM_info = info; gm.info = info; api.GM = ObjFreeze(gm); }
    api.unsafeWindow = W;
    ObjFreeze(info); ObjFreeze(info.script);
    return { api: ObjFreeze(api), ensureLoaded: ensureLoaded, hasValues: loaded };
  }

  // ---- 4. running entries ---------------------------------------------------------------------
  function runEntry(e) {
    var d = e.d;
    try {
      var made = makeApi(d, d.values);
      var go = function () {
        if (d.unwrap) { injectRaw(d.code, d.name); return; }
        var args = [];
        for (var i = 0; i < d.params.length; i++) { aPush(args, made.api[d.params[i]]); }
        var r = fApply(e.f, W, args);
        if (r && isFn(r.then)) { pThen(r, null, function (err) { conErr("[userscript " + d.name + "]", err); }); }
      };
      if (!d.values && d.grants.length) { pThen(made.ensureLoaded(), function () { safeCall(d.name, go); }); }
      else { safeCall(d.name, go); }
    } catch (err) { conErr("[userscript " + d.name + "]", err); }
  }
  function injectRaw(code, name) {
    var s = mkEl(D, "script");
    if (nonce) { setAttr(s, "nonce", nonce); }
    setText(s, code + "\n//# sourceURL=adblock-userscript/" + Str(name).replace(/[^A-Za-z0-9._-]/g, "_") + ".user.js");
    appendC(D.documentElement || D.head, s);
    removeC(s.parentNode, s);
  }
  var groups = { "document-start": [], "document-body": [], "document-end": [], "document-idle": [] };
  for (var i = 0; i < entries.length; i++) {
    var g = groups[entries[i].d.runAt] || groups["document-end"];
    aPush(g, entries[i]);
  }
  function runAll(list) { for (var j = 0; j < list.length; j++) { runEntry(list[j]); } }
  function whenBody(fn) {
    if (D.body) { fn(); return; }
    var mo = new MO(function () { if (D.body) { mo.disconnect(); fn(); } });
    mo.observe(D.documentElement || D, { childList: true, subtree: true });
  }
  function whenReady(fn) {
    if (D.readyState !== "loading") { setT(fn, 0); return; }
    var once = false;
    addEL(D, "DOMContentLoaded", function () { if (!once) { once = true; fn(); } });
  }
  runAll(groups["document-start"]);
  if (groups["document-body"].length) { whenBody(function () { runAll(groups["document-body"]); }); }
  if (groups["document-end"].length || groups["document-idle"].length) {
    whenReady(function () {
      runAll(groups["document-end"]);
      if (groups["document-idle"].length) { setT(function () { runAll(groups["document-idle"]); }, 0); }
    });
  }
}

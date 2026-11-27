import { BridgeError, T, type ErrBody, type JobMeta, type ProxyMsg, type XhrMeta } from './bridge-types';
import { connectAllows, httpHost, isLocalTarget } from './connect';
import { cookieOp } from './cookies';
import { decodeFrame, encodeFrame, payloadJson } from './frames';
import { isGranted, reportedOrigins } from './grants';
import type { ProxyController } from './proxy';
import { JOB_HEADER, StoreRelay } from './storerelay';

export interface BridgeDeps {
  WebSocketCtor: new (url: string) => any;
  browser: any;
  getSettings: () => Promise<{ argusUrl: string; token: string }>;
  fetch?: typeof fetch;
  /** Sends the browser through Argus and answers its 407 (see `ProxyController`). */
  proxy?: ProxyController;
  /** Relays for non-default cookie stores (Firefox containers, private windows). */
  storeRelay?: StoreRelay;
  /** Content script for about:blank / srcdoc / blob: frames, present while connected. */
  frames?: { sync(connected: boolean): Promise<void> };
}

const MAX_JOBS = 8;
const MAX_REQ_BODY = 64 * 1024 * 1024;
const MAX_RES_BODY = 256 * 1024 * 1024;
const CHUNK = 64 * 1024;
const FORBIDDEN = new Set(['cookie', 'origin', 'host', 'content-length']);
const PING_MS = 20_000;

interface Job {
  abort: AbortController;
  cancelled: boolean;
  chunks: Uint8Array[];
  size: number;
  tooBig: boolean;
  bodyDone?: () => void;
  bodyPromise?: Promise<void>;
}

export function wsUrl(argusUrl: string): string {
  return argusUrl.replace(/^http/i, 'ws').replace(/\/+$/, '') + '/api/v1/ext/channel';
}

export class Bridge {
  private ws: any = null;
  private sid: string | null = null;
  private jobs = new Map<number, Job>();
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private backoff = 1000;
  private stopped = false;
  private gen = 0;

  constructor(private d: BridgeDeps) {}

  status(): { connected: boolean; sid?: string } {
    return this.sid ? { connected: true, sid: this.sid } : { connected: false };
  }

  /** Open the channel if configured and not already open/connecting. */
  async connect(): Promise<void> {
    this.stopped = false;
    if (this.ws) return;
    const s = await this.d.getSettings();
    if (this.ws || this.stopped) return;
    if (!s.argusUrl || !s.token) { await this.d.proxy?.release(); return; }
    let ws: any;
    try { ws = new this.d.WebSocketCtor(wsUrl(s.argusUrl)); } catch { this.scheduleRetry(); return; }
    const gen = ++this.gen;
    this.ws = ws;
    ws.binaryType = 'arraybuffer';
    // Ask for the previous session back (same sid): a restarted worker or a short outage keeps
    // the browser's tunnels valid. The server refuses it when it is gone or not this token's.
    const resume = this.d.proxy?.resumeSid?.() ?? null;
    ws.onopen = () => ws.send(JSON.stringify({ t: 'hello', token: s.token, v: 1, ...(resume ? { resume } : {}) }));
    ws.onmessage = (ev: { data: unknown }) => { if (gen === this.gen) void this.onMessage(ev.data); };
    ws.onerror = () => { /* close follows */ };
    ws.onclose = () => { if (gen === this.gen) void this.onClose(); };
  }

  /** Settings changed: drop the current socket and reconnect (or stay closed if unconfigured). */
  async reconnect(): Promise<void> {
    this.backoff = 1000;
    await this.teardown(true);
    await this.connect();
  }

  /** Sign-out: the session ends now (`bye`), and the browser stops using Argus. */
  async stop(): Promise<void> {
    this.stopped = true;
    try { if (this.sid) this.ws?.send('{"t":"bye"}'); } catch { /* ignore */ }
    await this.teardown(true);
    await this.d.proxy?.release();
  }

  private async teardown(closeSocket: boolean) {
    this.gen++;
    const ws = this.ws;
    this.ws = null;
    this.sid = null;
    if (this.pingTimer) clearInterval(this.pingTimer);
    this.pingTimer = null;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = null;
    for (const j of this.jobs.values()) { j.cancelled = true; j.abort.abort(); }
    this.jobs.clear();
    if (ws && closeSocket) { try { ws.close(); } catch { /* ignore */ } }
    // Disconnected: the proxy setting stays (fail closed) and the last sid is kept to resume.
    await this.d.proxy?.setSid(null);
    await this.d.frames?.sync(false);
  }

  private async onClose() {
    await this.teardown(false);
    if (!this.stopped) this.scheduleRetry();
  }

  private scheduleRetry() {
    if (this.retryTimer) return;
    const wait = this.backoff;
    this.backoff = Math.min(this.backoff * 2, 10_000);
    this.retryTimer = setTimeout(() => { this.retryTimer = null; void this.connect(); }, wait);
  }

  async sendPerms() {
    if (!this.sid || !this.ws) return;
    try {
      const origins = await reportedOrigins(this.d.browser);
      this.ws.send(JSON.stringify({ t: 'perms', origins }));
    } catch { /* ignore */ }
  }

  /**
   * A tab was opened by another one (`webNavigation.onCreatedNavigationTarget`): tell Argus the
   * target URL and the opener tab's URL, so `$popup` rules and the opener's `$domain` apply. The
   * proxy matches it to the navigation request of this session (consumed once, 30 s).
   */
  async reportPopup(target: string, sourceTabId: number): Promise<void> {
    if (!this.sid || !this.ws || !/^https?:/i.test(target)) return;
    try {
      const tab = await this.d.browser.tabs.get(sourceTabId);
      const opener: string | undefined = tab?.url;
      if (!opener || !/^https?:/i.test(opener) || !this.ws) return;
      this.ws.send(JSON.stringify({ t: 'popup', url: target, opener }));
    } catch { /* tab gone */ }
  }

  private async onMessage(data: unknown) {
    if (typeof data === 'string') {
      let m: any;
      try { m = JSON.parse(data); } catch { return; }
      if (m?.t === 'welcome' && typeof m.sid === 'string') {
        this.sid = m.sid;
        this.backoff = 1000;
        await this.d.proxy?.setSid(m.sid);
        void this.d.frames?.sync(true);
        this.pingTimer = setInterval(() => { try { this.ws?.send('{"t":"ping"}'); } catch { /* ignore */ } }, PING_MS);
        await this.sendPerms();
      } else if (m?.t === 'proxy' && this.sid) {
        const p = m as ProxyMsg;
        await this.d.proxy?.setServer(p.host, p.port);
      }
      return;
    }
    if (!this.sid) return;
    const f = decodeFrame(data as ArrayBuffer);
    if (f) this.onFrame(f.type, f.job, f.payload);
  }

  private send(type: number, job: number, payload?: Uint8Array | string | object) {
    try { this.ws?.send(encodeFrame(type, job, payload)); } catch { /* ignore */ }
  }

  private sendErr(job: number, e: ErrBody) { this.send(T.ERROR, job, e); }

  private onFrame(type: number, id: number, payload: Uint8Array) {
    if (type === T.META) {
      if (this.jobs.has(id)) return;
      if (this.jobs.size >= MAX_JOBS) {
        this.sendErr(id, { kind: 'network', code: 'network', message: 'too many concurrent jobs' });
        return;
      }
      let meta: JobMeta;
      try { meta = payloadJson<JobMeta>(payload); } catch {
        this.sendErr(id, { kind: 'denied', code: 'bad_request', message: 'bad job meta' });
        return;
      }
      const job: Job = { abort: new AbortController(), cancelled: false, chunks: [], size: 0, tooBig: false };
      if (meta.op === 'xhr' && meta.hasBody) job.bodyPromise = new Promise<void>((r) => { job.bodyDone = r; });
      this.jobs.set(id, job);
      void this.run(id, job, meta).finally(() => { if (this.jobs.get(id) === job) this.jobs.delete(id); });
      return;
    }
    const job = this.jobs.get(id);
    if (!job) return;
    if (type === T.DATA) {
      job.size += payload.length;
      if (job.size > MAX_REQ_BODY) { job.tooBig = true; job.chunks = []; }
      else if (!job.tooBig) job.chunks.push(payload.slice());
    } else if (type === T.END) {
      job.bodyDone?.();
    } else if (type === T.CANCEL) {
      job.cancelled = true;
      job.abort.abort();
      job.bodyDone?.();
    }
  }

  private async authorise(meta: JobMeta, url: string) {
    const h = httpHost(url);
    if (!h) throw new BridgeError('denied', 'bad_request', 'only http and https URLs are allowed');
    if (isLocalTarget(h.host)) throw new BridgeError('denied', 'connect_denied', 'local and private targets are not relayed');
    if (!connectAllows(meta.connect, h.host)) throw new BridgeError('denied', 'connect_denied', 'host not allowed by @connect');
    // Consent is the user's recorded per-host grant; the browser-level host access covers all sites.
    const ok = await isGranted(this.d.browser, h.scheme, h.host, new URL(url).port);
    if (!ok) throw new BridgeError('denied', 'permission', 'extension lacks host permission');
  }

  /** The real cookie store of a job's store token (`undefined`: the default store). */
  private storeOf(token: string | undefined): string | undefined {
    if (!token) return undefined;
    const id = this.d.proxy?.storeForToken(token);
    if (!id) throw new BridgeError('denied', 'store', 'unknown cookie store');
    return id;
  }

  private async run(id: number, job: Job, meta: JobMeta) {
    try {
      if (meta.op === 'cookie') {
        await this.authorise(meta, meta.cookie.url);
        const result = await cookieOp(this.d.browser, meta.cookie, this.storeOf(meta.store));
        if (job.cancelled) return;
        this.send(T.HEAD, id, { result });
        this.send(T.END, id, {});
      } else if (meta.op === 'xhr') {
        await this.xhr(id, job, meta);
      } else {
        throw new BridgeError('denied', 'bad_request', 'unknown op');
      }
    } catch (e) {
      if (job.cancelled) return;
      if (e instanceof BridgeError) this.sendErr(id, { kind: e.kind, code: e.code, message: e.message });
      else this.sendErr(id, { kind: 'network', code: 'network', message: 'request failed' });
    }
  }

  private async xhr(id: number, job: Job, meta: XhrMeta) {
    // A browser fetch cannot expose a redirect response (`manual` yields an opaque one), so
    // the proxy keeps those calls on its own jar; refuse if one arrives anyway.
    if (meta.redirect === 'manual') throw new BridgeError('denied', 'bad_request', 'manual redirects are not relayed');
    await this.authorise(meta, meta.url);
    let body: Uint8Array | undefined;
    if (meta.hasBody) {
      await job.bodyPromise;
      if (job.cancelled) return;
      if (job.tooBig) throw new BridgeError('too_large', 'too_large', 'request body too large');
      body = new Uint8Array(job.size);
      let o = 0;
      for (const c of job.chunks) { body.set(c, o); o += c.length; }
      job.chunks = [];
    }
    const headers = new Headers();
    for (const [k, v] of meta.headers ?? []) {
      if (FORBIDDEN.has(k.toLowerCase())) continue;
      try { headers.append(k, v); } catch { /* skip invalid header */ }
    }
    headers.set('X-Argus-Relay', meta.relay);
    // A non-default cookie store (container, private window): the fetch is made without the
    // default store's cookies; the store's own go in per hop and its Set-Cookie comes back to it.
    const storeId = this.storeOf(meta.store);
    let marker: string | null = null;
    if (storeId) {
      const sr = this.d.storeRelay;
      if (!sr || !sr.install()) throw new BridgeError('denied', 'store', 'this browser cannot relay for that cookie store');
      marker = crypto.randomUUID();
      headers.set(JOB_HEADER, marker);
      sr.register(marker, storeId);
    }
    let timedOut = false;
    const timer = meta.timeout && meta.timeout > 0
      ? setTimeout(() => { timedOut = true; job.abort.abort(); }, meta.timeout) : null;
    try {
      const f = this.d.fetch ?? fetch;
      let res: Response;
      try {
        res = await f(meta.url, {
          method: meta.method, headers, credentials: storeId ? 'omit' : 'include',
          redirect: meta.redirect,
          signal: job.abort.signal, body: body as BodyInit | undefined,
        });
      } catch {
        if (timedOut) throw new BridgeError('timeout', 'timeout', 'request timed out');
        throw new BridgeError('network', 'network', 'network error');
      }
      if (job.cancelled) return;
      // Every hop passed through the proxy, which checks it (live job, the session's host
      // permission, `@connect`, local targets) and answers a refused one with this marker.
      if (res.headers.get('x-adblock-note') === 'relayed request refused') {
        void res.body?.cancel();
        throw new BridgeError('denied', 'connect_denied', 'a redirect hop was refused');
      }
      // The browser followed redirects itself and the intermediate hops are not visible here,
      // but the final URL is: it must pass the job's @connect, the permission and the local check.
      if (res.url && res.url !== meta.url) {
        try { await this.authorise(meta, res.url); } catch (e) { void res.body?.cancel(); throw e; }
      }
      const hdrs: [string, string][] = [];
      res.headers.forEach((v, k) => { if (k.toLowerCase() !== 'set-cookie') hdrs.push([k, v]); });
      this.send(T.HEAD, id, { status: res.status, statusText: res.statusText, headers: hdrs, finalUrl: res.url, redirected: res.redirected });
      let total = 0;
      if (res.body) {
        const reader = res.body.getReader();
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            if (job.cancelled) { void reader.cancel(); return; }
            total += value.length;
            if (total > MAX_RES_BODY) { void reader.cancel(); throw new BridgeError('too_large', 'too_large', 'response too large'); }
            for (let o = 0; o < value.length; o += CHUNK) this.send(T.DATA, id, value.subarray(o, o + CHUNK));
          }
        } catch (e) {
          if (e instanceof BridgeError) throw e;
          if (timedOut) throw new BridgeError('timeout', 'timeout', 'request timed out');
          throw new BridgeError('network', 'network', 'network error');
        }
      }
      if (job.cancelled) return;
      this.send(T.END, id, {});
    } finally {
      if (timer) clearTimeout(timer);
      if (marker) this.d.storeRelay?.release(marker);
    }
  }
}

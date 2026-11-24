import { BridgeError, T, type ErrBody, type HostsMsg, type JobMeta, type XhrMeta } from './bridge-types';
import { connectAllows, httpHost } from './connect';
import { cookieOp } from './cookies';
import { buildRule, RULE_ID } from './dnr';
import { decodeFrame, encodeFrame, payloadJson } from './frames';

export interface BridgeDeps {
  WebSocketCtor: new (url: string) => any;
  browser: any;
  getSettings: () => Promise<{ argusUrl: string; token: string }>;
  fetch?: typeof fetch;
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
    if (!s.argusUrl || !s.token) { await this.removeRule(); return; }
    let ws: any;
    try { ws = new this.d.WebSocketCtor(wsUrl(s.argusUrl)); } catch { this.scheduleRetry(); return; }
    const gen = ++this.gen;
    this.ws = ws;
    ws.binaryType = 'arraybuffer';
    ws.onopen = () => ws.send(JSON.stringify({ t: 'hello', token: s.token, v: 1 }));
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

  async stop(): Promise<void> {
    this.stopped = true;
    await this.teardown(true);
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
    await this.removeRule();
  }

  private async onClose() {
    await this.teardown(false);
    if (!this.stopped) this.scheduleRetry();
  }

  private scheduleRetry() {
    if (this.retryTimer) return;
    const wait = this.backoff;
    this.backoff = Math.min(this.backoff * 2, 30_000);
    this.retryTimer = setTimeout(() => { this.retryTimer = null; void this.connect(); }, wait);
  }

  async removeRule() {
    try { await this.d.browser.declarativeNetRequest.updateSessionRules({ removeRuleIds: [RULE_ID] }); } catch { /* ignore */ }
  }

  async sendPerms() {
    if (!this.sid || !this.ws) return;
    try {
      const p = await this.d.browser.permissions.getAll();
      const origins = ((p?.origins ?? []) as string[]).filter((o) => /^(https?|\*):\/\//.test(o) || o === '<all_urls>');
      this.ws.send(JSON.stringify({ t: 'perms', origins }));
    } catch { /* ignore */ }
  }

  private async onMessage(data: unknown) {
    if (typeof data === 'string') {
      let m: any;
      try { m = JSON.parse(data); } catch { return; }
      if (m?.t === 'welcome' && typeof m.sid === 'string') {
        this.sid = m.sid;
        this.backoff = 1000;
        this.pingTimer = setInterval(() => { try { this.ws?.send('{"t":"ping"}'); } catch { /* ignore */ } }, PING_MS);
        await this.sendPerms();
      } else if (m?.t === 'hosts' && this.sid) {
        await this.applyHosts(m as HostsMsg);
      }
      return;
    }
    if (!this.sid) return;
    const f = decodeFrame(data as ArrayBuffer);
    if (f) this.onFrame(f.type, f.job, f.payload);
  }

  async applyHosts(msg: HostsMsg) {
    if (!this.sid) return;
    const rule = buildRule(this.sid, { wildcard: !!msg.wildcard, hosts: msg.hosts ?? [], exclude: msg.exclude });
    try {
      await this.d.browser.declarativeNetRequest.updateSessionRules({ removeRuleIds: [RULE_ID], addRules: rule ? [rule] : [] });
    } catch { /* ignore */ }
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
    if (!connectAllows(meta.connect, h.host)) throw new BridgeError('denied', 'connect_denied', 'host not allowed by @connect');
    const host = h.host.includes(':') ? `[${h.host}]` : h.host;
    const ok = await this.d.browser.permissions.contains({ origins: [`${h.scheme}://${host}/*`] });
    if (!ok) throw new BridgeError('denied', 'permission', 'extension lacks host permission');
  }

  private async run(id: number, job: Job, meta: JobMeta) {
    try {
      if (meta.op === 'cookie') {
        await this.authorise(meta, meta.cookie.url);
        const result = await cookieOp(this.d.browser, meta.cookie);
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
    let timedOut = false;
    const timer = meta.timeout && meta.timeout > 0
      ? setTimeout(() => { timedOut = true; job.abort.abort(); }, meta.timeout) : null;
    try {
      const f = this.d.fetch ?? fetch;
      let res: Response;
      try {
        res = await f(meta.url, {
          method: meta.method, headers, credentials: 'include',
          redirect: meta.redirect === 'manual' ? 'manual' : meta.redirect,
          signal: job.abort.signal, body: body as BodyInit | undefined,
        });
      } catch {
        if (timedOut) throw new BridgeError('timeout', 'timeout', 'request timed out');
        throw new BridgeError('network', 'network', 'network error');
      }
      if (job.cancelled) return;
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
    }
  }
}

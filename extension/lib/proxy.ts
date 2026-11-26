/** Realm of the extension listener's 407 (the only one this extension ever answers). */
export const REALM = 'argus-ext';

export const DEFAULT_STORE = 'firefox-default';
export const PRIVATE_STORE = 'firefox-private';

export interface ProxyState {
  /** "Use Argus in this browser". */
  enabled: boolean;
  /** Firefox: per cookie store switches (a store not listed is on). */
  stores: Record<string, boolean>;
}

/** What the server says about its extension listener (`proxy.ext_port`). */
export type Listener = 'pending' | 'none' | 'ready';
export type StatusKind = 'on' | 'off' | 'connecting' | 'unset' | 'blocked';

/**
 * The status line of the "Use Argus" switch. `blocked`: the toggle is on and the browser is
 * still sent through Argus (fail closed), but the channel to Argus is down: nothing loads.
 */
export function statusKind(enabled: boolean, active: boolean, listener: Listener, unreachable = false): StatusKind {
  if (enabled && unreachable && listener !== 'none') return 'blocked';
  if (active) return 'on';
  if (!enabled) return 'off';
  return listener === 'none' ? 'unset' : 'connecting';
}

const KEY = 'argusProxy';

export async function loadProxyState(br: any): Promise<ProxyState> {
  try {
    const r = (await br.storage.local.get(KEY))?.[KEY];
    return { enabled: !!r?.enabled, stores: r?.stores && typeof r.stores === 'object' ? r.stores : {} };
  } catch { return { enabled: false, stores: {} }; }
}

export async function saveProxyState(br: any, s: ProxyState): Promise<void> {
  await br.storage.local.set({ [KEY]: s });
}

function rand(n: number): string {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return Array.from(a, (b) => (b % 36).toString(36)).join('');
}

/** Hosts compare equal across case, a trailing dot and IPv6 brackets (`[::1]` vs `::1`). */
export function normHost(h: string | undefined | null): string {
  return (h ?? '').trim().toLowerCase().replace(/^\[(.*)\]$/, '$1').replace(/\.$/, '');
}

/** How long a 407 from our listener waits for the channel to (re)connect before it is cancelled. */
export const READY_WAIT_MS = 10_000;
/** The channel must be down this long before the popup and badge say Argus is unreachable. */
export const UNREACHABLE_AFTER_MS = 3_000;
/** Where the session survives a worker restart (cleared when the browser quits). */
const SESSION_KEY = 'argusSession';

interface Persisted { sid: string; server: { host: string | null; port: number } | null }

export interface ProxyDeps {
  browser: any; firefox: boolean; argusHost: () => Promise<string>; readyWaitMs?: number;
  /** The reachability (see `unreachable()`) may have changed: refresh the badge. */
  onStatus?: () => void;
}



/**
 * Sends the browser through Argus's extension listener while the toggle is on, and answers that
 * listener's 407 with the session secret (`ext:<sid>[:<store token>]`). Host, port and sid come
 * from the server over the channel (the host defaults to the Argus URL's) and are kept in
 * `storage.session`, so a restarted worker carries on at once. Fail closed: while the toggle is
 * on the proxy setting is never cleared because the channel is down or the worker just started
 * (the server keeps the session for a grace period, and the channel resumes it). It is cleared
 * only when the toggle goes off, on sign-out / unconfiguration, or when the server has no
 * extension listener.
 */
export class ProxyController {
  private sid: string | null = null;
  private server: { host: string | null; port: number } | null = null;
  /** The server has told this connection whether it has an extension listener. */
  private serverKnown = false;
  private state: ProxyState = { enabled: false, stores: {} };
  private tokens = new Map<string, string>();
  private byToken = new Map<string, string>();
  private answered = new Set<string>();
  private argus = '';
  private waiters: Array<() => void> = [];
  /** The channel to Argus is connected (the persisted sid is only "last known" while it is not). */
  private up = false;
  private downSince = Date.now();
  /** Signed out or not configured: nothing is routed, so nothing is blocked either. */
  private released = false;
  private downTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(private d: ProxyDeps) {}

  /** Settles once the stored state is read: a 407 that wakes a fresh worker must wait for it. */
  private ready: Promise<void> = Promise.resolve();

  init(): Promise<void> {
    this.ready = (async () => {
      this.state = await loadProxyState(this.d.browser);
      const p = await this.loadSession();
      if (p) {
        this.sid = p.sid;
        this.server = p.server;
        this.serverKnown = true;
      }
      this.armDown();
      await this.apply();
    })();
    return this.ready;
  }

  private store(): any { return this.d.browser?.storage?.session; }

  private async loadSession(): Promise<Persisted | null> {
    try {
      const r = (await this.store()?.get(SESSION_KEY))?.[SESSION_KEY];
      if (r && typeof r.sid === 'string' && r.sid) {
        const sv = r.server;
        const server = sv && Number.isInteger(sv.port) && sv.port > 0 && sv.port < 65536 ? { host: sv.host ?? null, port: sv.port as number } : null;
        return { sid: r.sid, server };
      }
    } catch { /* no session storage */ }
    return null;
  }

  private async saveSession() {
    try {
      if (this.sid) await this.store()?.set({ [SESSION_KEY]: { sid: this.sid, server: this.server } satisfies Persisted });
      else await this.store()?.remove(SESSION_KEY);
    } catch { /* memory only */ }
  }

  /** The session to ask the server to resume (it keeps it for a grace period after a drop). */
  resumeSid(): string | null { return this.sid; }

  /** The channel is down for long enough to tell the user: browsing is blocked, not direct. */
  unreachable(): boolean {
    return this.state.enabled && !this.released && !(this.serverKnown && !this.server) && !this.up && Date.now() - this.downSince >= UNREACHABLE_AFTER_MS;
  }

  private armDown() {
    if (this.downTimer) clearTimeout(this.downTimer);
    this.downTimer = null;
    if (this.up) return;
    this.downTimer = setTimeout(() => { this.downTimer = null; this.d.onStatus?.(); }, Math.max(0, UNREACHABLE_AFTER_MS - (Date.now() - this.downSince)) + 20);
  }

  /** Sign-out or no longer configured: forget the session and stop sending the browser through Argus. */
  async release() {
    this.released = true;
    this.sid = null;
    this.server = null;
    this.serverKnown = false;
    this.up = false;
    this.tokens.clear(); this.byToken.clear(); this.answered.clear();
    await this.saveSession();
    await this.clearProxy();
    this.d.onStatus?.();
  }

  /** The stored state changed elsewhere (storage): read it again. */
  async reload() {
    this.state = await loadProxyState(this.d.browser);
    await this.apply();
  }

  getState(): ProxyState { return this.state; }

  async setState(s: ProxyState) {
    this.state = s;
    await saveProxyState(this.d.browser, s);
    await this.apply();
  }

  /**
   * The channel's session. `null`: the channel dropped; the last sid is kept (the server keeps the
   * session for a grace period, the proxy setting stays) and the next hello resumes it. A
   * different sid (the resume was refused) replaces it: stale tokens and answers are dropped.
   */
  async setSid(sid: string | null) {
    if (sid === null) {
      if (this.up) { this.up = false; this.downSince = Date.now(); }
      this.armDown();
      this.d.onStatus?.();
      return;
    }
    if (sid !== this.sid) { this.tokens.clear(); this.byToken.clear(); this.answered.clear(); this.serverKnown = false; }
    this.sid = sid;
    this.released = false;
    this.up = true;
    this.armDown();
    await this.saveSession();
    await this.apply();
    this.wake();
    this.d.onStatus?.();
  }

  private wake() { if (this.active() || this.released) { const w = this.waiters; this.waiters = []; for (const f of w) f(); } }

  /** Resolves true once active (the channel is up), false after `ms`. */
  private whenActive(ms: number): Promise<boolean> {
    if (this.active()) return Promise.resolve(true);
    if (this.released) return Promise.resolve(false);
    return new Promise((res) => {
      const done = () => { clearTimeout(t); res(this.active()); };
      const t = setTimeout(() => { this.waiters = this.waiters.filter((f) => f !== done); res(false); }, ms);
      this.waiters.push(done);
    });
  }

  async setServer(host: string | null | undefined, port: number | null | undefined) {
    this.server = port && port > 0 && port < 65536 ? { host: host || null, port } : null;
    this.serverKnown = true;
    await this.saveSession();
    await this.apply();
    this.wake();
  }

  /** Whether the server has an extension listener: `pending` until it has said. */
  listener(): Listener {
    if (!this.serverKnown) return 'pending';
    return this.server ? 'ready' : 'none';
  }

  active(): boolean { return this.state.enabled && !!this.sid && !!this.server; }

  private async target(): Promise<{ host: string; port: number } | null> {
    if (!this.server) return null;
    if (!this.argus) this.argus = await this.d.argusHost();
    const host = this.server.host ?? this.argus;
    return host ? { host, port: this.server.port } : null;
  }

  private async clearProxy() {
    const br = this.d.browser;
    if (this.d.firefox || !br?.proxy?.settings) return;
    try { await br.proxy.settings.clear({ scope: 'regular' }); } catch { /* ignore */ }
  }

  /**
   * Chrome: write the proxy setting. Off, or the server has no extension listener: clear it.
   * On but the target is not known yet (fresh browser start): leave the setting as it is, so
   * nothing goes direct. (Firefox decides per request in `onRequest`.)
   */
  async apply() {
    const br = this.d.browser;
    if (this.d.firefox || !br?.proxy?.settings) return;
    try {
      if (!this.state.enabled || (this.serverKnown && !this.server)) { await this.clearProxy(); return; }
      const t = this.sid ? await this.target() : null;
      if (!t) return;
      const argus = await this.d.argusHost();
      const value = {
        mode: 'fixed_servers',
        rules: {
          singleProxy: { scheme: 'http', host: t.host, port: t.port },
          // Argus's own console and API (and local names) are never sent through itself.
          bypassList: ['<local>', ...(argus ? [argus] : [])],
        },
      };
      try {
        const cur: any = (await br.proxy.settings.get?.({}))?.value;
        const sp = cur?.rules?.singleProxy;
        const bl: string[] = cur?.rules?.bypassList ?? [];
        if (cur?.mode === 'fixed_servers' && sp?.host === t.host && sp?.port === t.port && (sp?.scheme ?? 'http') === 'http'
          && bl.length === value.rules.bypassList.length && bl.every((x, i) => x === value.rules.bypassList[i])) return;
      } catch { /* set it */ }
      await br.proxy.settings.set({ scope: 'regular', value });
    } catch { /* ignore */ }
  }

  /** Opaque token for a cookie store; the default store has none. */
  tokenFor(storeId: string | undefined): string {
    if (!storeId || storeId === DEFAULT_STORE || storeId === '0') return '';
    let t = this.tokens.get(storeId);
    if (!t) { t = rand(12); this.tokens.set(storeId, t); this.byToken.set(t, storeId); }
    return t;
  }

  /** The real store of a token the server echoed back (`undefined`: unknown token). */
  storeForToken(token: string | undefined): string | undefined {
    if (!token) return DEFAULT_STORE;
    return this.byToken.get(token);
  }

  storeEnabled(storeId: string | undefined): boolean {
    return this.state.stores[storeId ?? DEFAULT_STORE] !== false;
  }

  /** Firefox `proxy.onRequest`: our listener for enabled stores, direct otherwise. */
  async route(d: { cookieStoreId?: string; url?: string }): Promise<{ type: string; host?: string; port?: number; username?: string; password?: string; proxyDNS?: boolean }> {
    await this.ready;
    if (!this.state.enabled || this.released || !this.storeEnabled(d.cookieStoreId)) return { type: 'direct' };
    if (d.url) {
      try {
        const u = new URL(d.url);
        if (normHost(u.hostname) === normHost(await this.d.argusHost())) return { type: 'direct' };
      } catch { /* proxy it */ }
    }
    // Fresh browser start: nothing persisted yet. Never direct: wait for the channel's welcome,
    // and fail (a dead local port) if it does not come.
    if (!this.active() && !(await this.whenActive(this.d.readyWaitMs ?? READY_WAIT_MS))) {
      return this.released ? { type: 'direct' } : { type: 'socks', host: '127.0.0.1', port: 1, proxyDNS: true };
    }
    const t = await this.target();
    if (!t) return { type: 'socks', host: '127.0.0.1', port: 1, proxyDNS: true };
    // SOCKS5 with per-request credentials: `ext` / `sid[:store token]`. Firefox keeps one
    // proxy-credential cache for HTTP proxies that all containers share (the first container's
    // answer would bind every other one), and `proxyAuthorizationHeader` is ignored for HTTPS
    // tunnels; SOCKS user/password is sent per connection, and Firefox already keeps
    // containers' connections apart. Nothing travels inside the request itself.
    const tok = this.tokenFor(d.cookieStoreId);
    return { type: 'socks', host: t.host, port: t.port, username: 'ext', password: tok ? `${this.sid}:${tok}` : this.sid!, proxyDNS: true };
  }

  /**
   * `webRequest.onAuthRequired`: answer only our own listener (host, port, realm) and only while
   * active; each request id is answered once (a rejected secret ends there, no retry loop).
   */
  async auth(d: { isProxy?: boolean; realm?: string; challenger?: { host?: string; port?: number }; requestId?: string; cookieStoreId?: string }): Promise<{ authCredentials?: { username: string; password: string }; cancel?: boolean }> {
    if (!d.isProxy || d.realm !== REALM) return {};
    await this.ready;
    // Fresh browser start (nothing persisted yet) while Chrome keeps the proxy setting: wait for
    // the channel's welcome rather than let Chrome show its own prompt. With a persisted (or
    // grace-period) session there is nothing to wait for: it is answered at once.
    if (this.state.enabled && !this.active() && !(await this.whenActive(this.d.readyWaitMs ?? READY_WAIT_MS))) return { cancel: true };
    const t = this.server ? await this.target() : null;
    const ours = !!t && normHost(d.challenger?.host) === normHost(t.host) && d.challenger?.port === t.port;
    // Ours but unanswerable (just turned off, in-flight): end it, never a native prompt.
    if (!this.active() || !this.sid) return ours ? { cancel: true } : {};
    if (!ours) return {};
    if (d.requestId) {
      if (this.answered.has(d.requestId)) return { cancel: true };
      this.answered.add(d.requestId);
      if (this.answered.size > 2000) this.answered.clear();
    }
    if (!this.storeEnabled(d.cookieStoreId)) return { cancel: true };
    return { authCredentials: { username: 'ext', password: this.sid } };
  }
}

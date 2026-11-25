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
export type StatusKind = 'on' | 'off' | 'connecting' | 'unset';

/** The status line of the "Use Argus" switch. */
export function statusKind(enabled: boolean, active: boolean, listener: Listener): StatusKind {
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

export interface ProxyDeps { browser: any; firefox: boolean; argusHost: () => Promise<string> }

/**
 * Sends the browser through Argus's extension listener while the toggle is on and the channel is
 * connected, and answers that listener's 407 with this connection's session secret
 * (`ext:<sid>[:<store token>]`). Host and port come from the server over the channel (the host
 * defaults to the Argus URL's). Off, disconnected or unknown server: direct, and no auth answers.
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

  constructor(private d: ProxyDeps) {}

  async init() {
    this.state = await loadProxyState(this.d.browser);
    await this.apply();
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

  /** The channel's session (null on disconnect: a new connection gets a new secret and tokens). */
  async setSid(sid: string | null) {
    if (sid !== this.sid) { this.tokens.clear(); this.byToken.clear(); this.answered.clear(); this.serverKnown = false; }
    this.sid = sid;
    await this.apply();
  }

  async setServer(host: string | null | undefined, port: number | null | undefined) {
    this.server = port && port > 0 && port < 65536 ? { host: host || null, port } : null;
    this.serverKnown = true;
    await this.apply();
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

  /** Chrome: write or clear the proxy setting. (Firefox decides per request in `onRequest`.) */
  async apply() {
    const br = this.d.browser;
    if (this.d.firefox || !br?.proxy?.settings) return;
    try {
      const t = this.active() ? await this.target() : null;
      if (!t) { await br.proxy.settings.clear({ scope: 'regular' }); return; }
      const argus = await this.d.argusHost();
      await br.proxy.settings.set({
        scope: 'regular',
        value: {
          mode: 'fixed_servers',
          rules: {
            singleProxy: { scheme: 'http', host: t.host, port: t.port },
            // Argus's own console and API (and local names) are never sent through itself.
            bypassList: ['<local>', ...(argus ? [argus] : [])],
          },
        },
      });
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
    if (!this.active() || !this.storeEnabled(d.cookieStoreId)) return { type: 'direct' };
    const t = await this.target();
    if (!t) return { type: 'direct' };
    if (d.url) {
      try {
        const u = new URL(d.url);
        if (u.hostname === (await this.d.argusHost())) return { type: 'direct' };
      } catch { /* proxy it */ }
    }
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
    if (!d.isProxy || d.realm !== REALM || !this.active() || !this.sid) return {};
    const t = await this.target();
    if (!t || d.challenger?.host !== t.host || d.challenger?.port !== t.port) return {};
    if (d.requestId) {
      if (this.answered.has(d.requestId)) return { cancel: true };
      this.answered.add(d.requestId);
      if (this.answered.size > 2000) this.answered.clear();
    }
    if (!this.storeEnabled(d.cookieStoreId)) return {};
    return { authCredentials: { username: 'ext', password: this.sid } };
  }
}

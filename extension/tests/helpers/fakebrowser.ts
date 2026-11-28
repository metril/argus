import { hostUnder } from '../../lib/cookiejar/model';

/** A faithful-enough fake of the `browser.cookies` API (plus tabs, storage, alarms) for both flavours. */
export interface FakeOpts {
  flavor?: 'chrome' | 'firefox';
  /** Firefox: first-party isolation is on, so `firstPartyDomain` is mandatory in details. */
  fpi?: boolean;
  /** The browser does not know `partitionKey` (older versions): details with it throw. */
  noPartitioned?: boolean;
  stores?: { id: string; tabIds?: number[] }[];
  identities?: { cookieStoreId: string; name: string }[];
  now?: () => number;
}

const hostOf = (u: string) => new URL(u).hostname.toLowerCase();

export class FakeBrowser {
  readonly flavor: 'chrome' | 'firefox';
  readonly opts: FakeOpts;
  readonly jar = new Map<string, any>();
  readonly defaultStore: string;
  stores: { id: string; tabIds: number[] }[];
  readonly calls: { op: string; details: any }[] = [];
  /** Make an operation fail: return true to reject (or resolve null where the browser does). */
  failWhen?: (op: string, details: any) => boolean;
  private listeners = new Set<(c: any) => void>();
  tabList: any[] = [];

  constructor(o: FakeOpts = {}) {
    this.opts = o;
    this.flavor = o.flavor ?? 'chrome';
    this.defaultStore = this.flavor === 'firefox' ? 'firefox-default' : '0';
    this.stores = (o.stores ?? [{ id: this.defaultStore }]).map((s) => ({ id: s.id, tabIds: s.tabIds ?? [] }));
  }

  get cookies() {
    return {
      getAll: (d: any = {}) => this.getAll(d),
      get: (d: any) => this.getOne(d),
      set: (d: any) => this.set(d),
      remove: (d: any) => this.remove(d),
      getAllCookieStores: async () => this.stores.map((s) => ({ ...s })),
      onChanged: {
        addListener: (f: (c: any) => void) => { this.listeners.add(f); },
        removeListener: (f: (c: any) => void) => { this.listeners.delete(f); },
        hasListener: (f: (c: any) => void) => this.listeners.has(f),
      },
    };
  }

  get contextualIdentities() {
    if (this.flavor !== 'firefox') return undefined;
    return { query: async () => (this.opts.identities ?? []).map((i) => ({ ...i })) };
  }

  get tabs() {
    return {
      get: async (id: number) => { const t = this.tabList.find((x) => x.id === id); if (!t) throw new Error('No tab'); return t; },
      query: async () => this.tabList.map((t) => ({ ...t })),
    };
  }

  // -- test helpers -----------------------------------------------------------------------
  keyOf(c: any): string { return JSON.stringify([c.storeId, c.partitionKey ? [c.partitionKey.topLevelSite, c.partitionKey.hasCrossSiteAncestor ?? false] : '', c.firstPartyDomain ?? '', c.domain.replace(/^\./, ''), !!c.hostOnly, c.path, c.name]); }
  emit(info: any) { for (const l of [...this.listeners]) l(info); }
  /** Put a cookie straight into the jar (no event). */
  seed(p: any): any {
    const domain = p.domain ?? 'example.com';
    const hostOnly = p.hostOnly ?? !domain.startsWith('.');
    const c: any = {
      name: 'a', value: '1', path: '/', secure: false, httpOnly: false, sameSite: this.flavor === 'firefox' ? 'no_restriction' : 'unspecified', session: true,
      storeId: this.defaultStore, ...p, domain, hostOnly,
    };
    if (this.flavor === 'firefox') c.firstPartyDomain ??= '';
    if (c.expirationDate !== undefined) c.session = false;
    this.jar.set(this.keyOf(c), c);
    return c;
  }
  all(): any[] { return [...this.jar.values()]; }
  expire(c: any) { const k = this.keyOf(c); const had = this.jar.get(k); this.jar.delete(k); if (had) this.emit({ removed: true, cookie: had, cause: 'expired' }); }
  evict(c: any) { const k = this.keyOf(c); const had = this.jar.get(k); this.jar.delete(k); if (had) this.emit({ removed: true, cookie: had, cause: 'evicted' }); }

  // -- cookies API ------------------------------------------------------------------------
  private checkStore(id: string | undefined): string {
    const s = id ?? this.defaultStore;
    if (!this.stores.some((x) => x.id === s)) throw new Error(`Invalid cookie store id: "${s}"`);
    return s;
  }
  private checkKeys(d: any, op: string) {
    if (this.flavor === 'chrome' && 'firstPartyDomain' in d) throw new Error(`Error in invocation of cookies.${op}: Unexpected property: 'firstPartyDomain'.`);
    if (this.opts.noPartitioned && 'partitionKey' in d) throw new Error(`Error in invocation of cookies.${op}: Unexpected property: 'partitionKey'.`);
    if (this.flavor === 'firefox' && this.opts.fpi && op !== 'getAll' && d.firstPartyDomain === undefined) {
      throw new Error('First-Party Isolation is enabled, but the required \'firstPartyDomain\' attribute was not set.');
    }
    if (this.flavor === 'firefox' && this.opts.fpi && op === 'getAll' && d.firstPartyDomain === undefined) {
      throw new Error('First-Party Isolation is enabled, but the required \'firstPartyDomain\' attribute was not set.');
    }
  }
  private partitionOk(c: any, d: any): boolean {
    if (d.partitionKey === undefined) return !c.partitionKey;
    if (d.partitionKey.topLevelSite === undefined) return true;
    if (c.partitionKey?.topLevelSite !== d.partitionKey.topLevelSite) return false;
    return d.partitionKey.hasCrossSiteAncestor === undefined || (c.partitionKey.hasCrossSiteAncestor ?? false) === d.partitionKey.hasCrossSiteAncestor;
  }
  private fpdOk(c: any, d: any): boolean {
    if (this.flavor !== 'firefox') return true;
    if (d.firstPartyDomain === null) return true;
    return (c.firstPartyDomain ?? '') === (d.firstPartyDomain ?? '');
  }
  private urlOk(c: any, url: string): boolean {
    const u = new URL(url);
    const h = u.hostname.toLowerCase();
    const ch = c.domain.replace(/^\./, '').toLowerCase();
    if (c.hostOnly ? h !== ch : !hostUnder(h, ch)) return false;
    if (c.secure && u.protocol !== 'https:') return false;
    const p = u.pathname || '/';
    return p === c.path || (p.startsWith(c.path) && (c.path.endsWith('/') || p[c.path.length] === '/'));
  }

  private async getAll(d: any): Promise<any[]> {
    this.calls.push({ op: 'getAll', details: d });
    if (this.failWhen?.('getAll', d)) throw new Error('getAll failed');
    this.checkKeys(d, 'getAll');
    const store = this.checkStore(d.storeId);
    return this.all().filter((c) => {
      if (c.storeId !== store) return false;
      if (!this.partitionOk(c, d) || !this.fpdOk(c, d)) return false;
      if (d.name !== undefined && c.name !== d.name) return false;
      if (d.path !== undefined && c.path !== d.path) return false;
      if (d.secure !== undefined && c.secure !== d.secure) return false;
      if (d.session !== undefined && c.session !== d.session) return false;
      if (d.domain !== undefined && !hostUnder(c.domain.replace(/^\./, '').toLowerCase(), String(d.domain).replace(/^\./, '').toLowerCase())) return false;
      if (d.url !== undefined && !this.urlOk(c, d.url)) return false;
      return true;
    }).map((c) => ({ ...c }));
  }

  private async getOne(d: any): Promise<any | null> {
    this.calls.push({ op: 'get', details: d });
    if (this.failWhen?.('get', d)) throw new Error('get failed');
    this.checkKeys(d, 'get');
    const store = this.checkStore(d.storeId);
    const hit = this.all().filter((c) => c.storeId === store && c.name === d.name && this.partitionOk(c, d) && this.fpdOk(c, d) && this.urlOk(c, d.url))
      .sort((a, b) => b.path.length - a.path.length)[0];
    return hit ? { ...hit } : null;
  }

  private reject(op: string, why: string): null {
    if (this.flavor === 'chrome') return null; // chrome: resolves null and sets runtime.lastError
    throw new Error(`${op}: ${why}`);
  }

  private async set(d: any): Promise<any | null> {
    this.calls.push({ op: 'set', details: d });
    if (this.failWhen?.('set', d)) throw new Error('set failed');
    this.checkKeys(d, 'set');
    const store = this.checkStore(d.storeId);
    let u: URL;
    try { u = new URL(d.url); } catch { throw new Error('Invalid url'); }
    const host = u.hostname.toLowerCase();
    const name = d.name ?? '';
    const value = d.value ?? '';
    const secure = !!d.secure;
    const path = d.path ?? (u.pathname.slice(0, u.pathname.lastIndexOf('/') + 1) || '/');
    const hostOnly = d.domain === undefined;
    const domain = hostOnly ? host : '.' + String(d.domain).replace(/^\./, '').toLowerCase();
    if (!hostOnly && !hostUnder(host, domain.slice(1))) return this.reject('set', 'domain mismatch');
    if (secure && u.protocol !== 'https:') return this.reject('set', 'secure cookie from insecure url');
    if (new TextEncoder().encode(name + value).length > 4096) return this.reject('set', 'cookie too large');
    if (/[\x00-\x1f;]/.test(value) || /[\x00-\x20;=]/.test(name)) return this.reject('set', 'invalid characters');
    if (/^__Host-/i.test(name) && (!secure || path !== '/' || !hostOnly)) return this.reject('set', '__Host- rules');
    if (/^__Secure-/i.test(name) && !secure) return this.reject('set', '__Secure- rules');
    if (d.sameSite === 'no_restriction' && !secure) return this.reject('set', 'SameSite=None needs Secure');
    if (d.partitionKey && !secure) return this.reject('set', 'Partitioned needs Secure');
    const c: any = {
      name, value, domain, hostOnly, path, secure, httpOnly: !!d.httpOnly, sameSite: d.sameSite ?? (this.flavor === 'firefox' ? 'no_restriction' : 'unspecified'),
      session: d.expirationDate === undefined, storeId: store,
    };
    if (d.expirationDate !== undefined) c.expirationDate = d.expirationDate;
    if (d.partitionKey) c.partitionKey = { ...d.partitionKey };
    if (this.flavor === 'firefox') c.firstPartyDomain = d.firstPartyDomain ?? '';
    const k = this.keyOf(c);
    const old = this.jar.get(k);
    const now = (this.opts.now?.() ?? Date.now()) / 1000;
    if (c.expirationDate !== undefined && c.expirationDate <= now) {
      if (old) { this.jar.delete(k); this.emit({ removed: true, cookie: old, cause: 'expired_overwrite' }); }
      return this.reject('set', 'already expired');
    }
    if (old) this.emit({ removed: true, cookie: { ...old }, cause: 'overwrite' });
    this.jar.set(k, c);
    this.emit({ removed: false, cookie: { ...c }, cause: 'explicit' });
    return { ...c };
  }

  private async remove(d: any): Promise<any | null> {
    this.calls.push({ op: 'remove', details: d });
    if (this.failWhen?.('remove', d)) throw new Error('remove failed');
    this.checkKeys(d, 'remove');
    const store = this.checkStore(d.storeId);
    const hit = this.all().filter((c) => c.storeId === store && c.name === d.name && this.partitionOk(c, d) && this.fpdOk(c, d) && this.urlOk(c, d.url))
      .sort((a, b) => b.path.length - a.path.length)[0];
    if (!hit) return null;
    this.jar.delete(this.keyOf(hit));
    this.emit({ removed: true, cookie: { ...hit }, cause: 'explicit' });
    const out: any = { url: d.url, name: d.name, storeId: store };
    if (d.partitionKey) out.partitionKey = d.partitionKey;
    if (this.flavor === 'firefox') out.firstPartyDomain = d.firstPartyDomain ?? '';
    return out;
  }
}

/** A `storage` area with the `get/set/remove` surface used by the library. */
export class FakeStorageArea {
  data: Record<string, unknown> = {};
  failSet = false;
  async get(keys?: string | string[] | null): Promise<Record<string, unknown>> {
    if (keys == null) return structuredClone(this.data);
    const ks = typeof keys === 'string' ? [keys] : keys;
    const out: Record<string, unknown> = {};
    for (const k of ks) if (k in this.data) out[k] = structuredClone(this.data[k]);
    return out;
  }
  async set(items: Record<string, unknown>): Promise<void> {
    if (this.failSet) throw new Error('QUOTA_BYTES quota exceeded');
    for (const [k, v] of Object.entries(items)) this.data[k] = structuredClone(v);
  }
  async remove(keys: string | string[]): Promise<void> {
    for (const k of typeof keys === 'string' ? [keys] : keys) delete this.data[k];
  }
}

export interface Alarm { name: string; scheduledTime: number }

export class FakeAlarms {
  items = new Map<string, Alarm>();
  private ls = new Set<(a: Alarm) => void>();
  async create(name: string, info: { when?: number; delayInMinutes?: number }) {
    this.items.set(name, { name, scheduledTime: info.when ?? Date.now() + (info.delayInMinutes ?? 0) * 60000 });
  }
  async clear(name: string) { return this.items.delete(name); }
  async getAll() { return [...this.items.values()]; }
  onAlarm = { addListener: (f: (a: Alarm) => void) => { this.ls.add(f); } };
  /** Fire (and remove) one alarm, as the browser does when it is due. */
  async fire(name: string) { const a = this.items.get(name); if (!a) return; this.items.delete(name); for (const l of [...this.ls]) await l(a); }
}

/** A raw browser-shaped cookie for tests. */
export const raw = (p: Record<string, unknown> = {}) => ({ name: 'a', value: '1', domain: 'example.com', path: '/', ...p });

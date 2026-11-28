import { fromBrowser, identityKey, siteOf, toKeyDetails, toSetDetails, type Caps, type Cookie, hostOfCookie, byteSize } from './model';
import { firstProblem } from './validate';

export type CookieErrorCode = 'invalid' | 'set-failed' | 'remove-failed' | 'not-found' | 'store' | 'unsupported';

/** A failed jar operation, with a one-sentence reason the page can show as is. */
export class CookieError extends Error {
  constructor(readonly code: CookieErrorCode, message: string) {
    super(message);
    this.name = 'CookieError';
  }
}

export interface StoreInfo {
  id: string;
  label: string;
  kind: 'default' | 'private' | 'container' | 'other';
  tabIds: number[];
  color?: string;
  icon?: string;
}

export interface ListQuery {
  /** A host or URL; lists the site's registrable domain and every subdomain. */
  site?: string;
  /** One store; omitted means every store. */
  storeId?: string;
}

/** What copy/move does when the target store already holds the same cookie. */
export type ConflictMode = 'ask' | 'overwrite' | 'skip';

export interface BulkResult {
  /** Copy/move in `ask` mode: cookies left untouched because the target already has them. */
  conflicts?: { cookie: Cookie; existing: Cookie }[];
  done: Cookie[];
  failed: { cookie: Cookie; error: string }[];
  skipped: Cookie[];
}

export interface BulkOptions {
  /** Cookies this returns true for are never touched (they come back in `skipped`). */
  isProtected?: (c: Cookie) => boolean;
}

const msg = (e: unknown): string => String((e as Error)?.message ?? e).slice(0, 200);
const CHUNK = 20;
const SKIP = Symbol('skip');

/** `browser.cookies` for people: all stores, partitioned cookies, safe edit, bulk and copy/move. */
export class CookieJar {
  readonly caps: Caps & { partitioned: boolean };
  private identities?: Promise<{ cookieStoreId: string; name: string; color?: string; icon?: string }[]>;

  constructor(private readonly br: any, opts: { firefox?: boolean } = {}) {
    const firefox = opts.firefox ?? typeof br.contextualIdentities !== 'undefined';
    this.caps = { firstPartyDomain: firefox, partitioned: true };
  }

  // -- stores ----------------------------------------------------------------------------

  async stores(): Promise<StoreInfo[]> {
    let raw: { id: string; tabIds?: number[] }[];
    try { raw = (await this.br.cookies.getAllCookieStores()) ?? []; } catch (e) { throw new CookieError('store', `Could not list cookie stores: ${msg(e)}`); }
    const idents = await this.containerIdentities();
    const out: StoreInfo[] = [];
    for (const s of raw) {
      const tabIds = s.tabIds ?? [];
      const ci = idents.find((i) => i.cookieStoreId === s.id);
      if (s.id === 'firefox-default' || (!this.caps.firstPartyDomain && s.id === '0')) out.push({ id: s.id, label: 'Default', kind: 'default', tabIds });
      else if (s.id === 'firefox-private' || (!this.caps.firstPartyDomain && (await this.isPrivate(tabIds)))) out.push({ id: s.id, label: this.caps.firstPartyDomain ? 'Private' : 'Incognito', kind: 'private', tabIds });
      else if (ci) out.push({ id: s.id, label: ci.name, kind: 'container', tabIds, ...(ci.color ? { color: ci.color } : {}), ...(ci.icon ? { icon: ci.icon } : {}) });
      else if (/^firefox-container-/.test(s.id)) out.push({ id: s.id, label: `Container ${s.id.slice('firefox-container-'.length)}`, kind: 'container', tabIds });
      else out.push({ id: s.id, label: `Store ${s.id}`, kind: 'other', tabIds });
    }
    return out;
  }

  private containerIdentities() {
    const ci = this.br.contextualIdentities;
    if (!ci?.query) return Promise.resolve([] as { cookieStoreId: string; name: string; color?: string; icon?: string }[]);
    this.identities ??= Promise.resolve(ci.query({})).then((r: any[]) => r ?? [], () => []);
    return this.identities;
  }

  private async isPrivate(tabIds: number[]): Promise<boolean> {
    for (const id of tabIds.slice(0, 3)) {
      try { if ((await this.br.tabs.get(id))?.incognito) return true; } catch { /* tab gone */ }
    }
    return false;
  }

  // -- reading ---------------------------------------------------------------------------

  private async raw(call: 'getAll' | 'get' | 'set' | 'remove', details: Record<string, unknown>): Promise<any> {
    try {
      return await this.br.cookies[call](details);
    } catch (e) {
      // An older browser that does not know partitioned cookies: stop sending the key, once.
      if (this.caps.partitioned && 'partitionKey' in details && /partitionKey/i.test(msg(e))) {
        this.caps.partitioned = false;
        const { partitionKey: _p, ...rest } = details;
        return this.br.cookies[call](rest);
      }
      throw e;
    }
  }

  private async allIn(storeId: string | undefined, extra: Record<string, unknown>): Promise<Cookie[]> {
    const d: Record<string, unknown> = { ...extra };
    if (storeId) d.storeId = storeId;
    if (this.caps.firstPartyDomain) d.firstPartyDomain = null;
    if (this.caps.partitioned) d.partitionKey = {};
    return ((await this.raw('getAll', d)) as any[]).map(fromBrowser);
  }

  /** Cookies of a site, a store or everything, across partitions and (by default) every store. */
  async list(q: ListQuery = {}): Promise<Cookie[]> {
    const ids = q.storeId ? [q.storeId] : (await this.stores()).map((s) => s.id);
    const extra: Record<string, unknown> = q.site ? { domain: siteOf(q.site) } : {};
    const seen = new Map<string, Cookie>();
    for (const id of ids) {
      let cs: Cookie[];
      try { cs = await this.allIn(id, extra); } catch (e) { throw new CookieError('store', `Could not read cookies: ${msg(e)}`); }
      for (const c of cs) seen.set(identityKey(c), c);
    }
    return [...seen.values()].sort((a, b) => hostOfCookie(a).localeCompare(hostOfCookie(b)) || a.path.localeCompare(b.path) || a.name.localeCompare(b.name));
  }

  async get(c: Cookie): Promise<Cookie | null> {
    const r = await this.raw('get', toKeyDetails(c, this.caps));
    return r ? fromBrowser(r) : null;
  }

  // -- writing ---------------------------------------------------------------------------

  private details(c: Cookie): Record<string, unknown> {
    const d = toSetDetails(c, this.caps);
    if (!c.storeId) delete d.storeId;
    if (!this.caps.partitioned) delete d.partitionKey;
    return d;
  }

  private async setRaw(c: Cookie): Promise<Cookie> {
    let r: any;
    try { r = await this.raw('set', this.details(c)); } catch (e) { throw new CookieError('set-failed', `The browser refused this cookie: ${msg(e)}`); }
    if (!r) throw new CookieError('set-failed', 'The browser refused to store this cookie.');
    return fromBrowser(r);
  }

  private async removeRaw(c: Cookie): Promise<boolean> {
    const d = toKeyDetails(c, this.caps);
    if (!c.storeId) delete d.storeId;
    if (!this.caps.partitioned) delete d.partitionKey;
    let r: any;
    try { r = await this.raw('remove', d); } catch (e) { throw new CookieError('remove-failed', `Could not remove the cookie: ${msg(e)}`); }
    return !!r;
  }

  private check(c: Cookie) {
    const p = firstProblem(c, { url: `${c.secure ? 'https' : 'http'}://${hostOfCookie(c)}${c.path}` });
    if (p) throw new CookieError('invalid', p.reason);
  }

  /** Stores a new cookie (or overwrites the one with the same identity). */
  async create(c: Cookie): Promise<Cookie> {
    const next = { ...c, size: byteSize(c.name, c.value) };
    this.check(next);
    return this.setRaw(next);
  }

  /** Removes one cookie; false when it was already gone. */
  remove(c: Cookie): Promise<boolean> {
    return this.removeRaw(c);
  }

  /**
   * Edit = set the new cookie, then remove the old one if its identity changed. A failed set
   * leaves the old cookie in place (restored if the browser dropped it); a failed removal takes
   * the new cookie back out so no duplicate remains.
   */
  async edit(old: Cookie, next: Cookie): Promise<Cookie> {
    const n: Cookie = { ...next, storeId: next.storeId || old.storeId, size: byteSize(next.name, next.value) };
    this.check(n);
    let created: Cookie;
    try {
      created = await this.setRaw(n);
    } catch (e) {
      try { if (!(await this.get(old))) await this.setRaw(old); } catch { /* best effort */ }
      throw e;
    }
    if (identityKey(old) !== identityKey(n)) {
      try { await this.removeRaw(old); } catch (e) {
        try { await this.removeRaw(created); } catch { /* best effort */ }
        throw e;
      }
    }
    return created;
  }

  private async each(cs: Cookie[], opts: BulkOptions, op: (c: Cookie) => Promise<boolean | void | typeof SKIP>): Promise<BulkResult> {
    const res: BulkResult = { done: [], failed: [], skipped: [] };
    const todo = cs.filter((c) => { if (opts.isProtected?.(c)) { res.skipped.push(c); return false; } return true; });
    for (let i = 0; i < todo.length; i += CHUNK) {
      const part = todo.slice(i, i + CHUNK);
      const out = await Promise.allSettled(part.map(op));
      out.forEach((o, j) => {
        const c = part[j]!;
        if (o.status === 'fulfilled') (o.value === SKIP ? res.skipped : res.done).push(c);
        else res.failed.push({ cookie: c, error: msg(o.reason) });
      });
    }
    return res;
  }

  /** Removes many cookies; protected ones are skipped, failures are reported per cookie. */
  removeMany(cs: Cookie[], opts: BulkOptions = {}): Promise<BulkResult> {
    return this.each(cs, opts, (c) => this.removeRaw(c));
  }

  /**
   * Copies cookies into another store (`move`: and removes them from where they were). A cookie the
   * target already has is a conflict: `ask` (default) leaves both alone and returns it in
   * `conflicts`, `skip` leaves the target's, `overwrite` replaces it (and a failed move puts it back).
   */
  async copy(cs: Cookie[], toStoreId: string, opts: BulkOptions & { move?: boolean; conflict?: ConflictMode } = {}): Promise<BulkResult> {
    const mode = opts.conflict ?? 'ask';
    const conflicts: { cookie: Cookie; existing: Cookie }[] = [];
    const res = await this.each(cs.filter((c) => c.storeId !== toStoreId), opts, async (c) => {
      const copy: Cookie = { ...c, storeId: toStoreId };
      this.check(copy);
      const existing = await this.get(copy);
      if (existing && mode !== 'overwrite') {
        if (mode === 'ask') conflicts.push({ cookie: c, existing });
        return SKIP;
      }
      const created = await this.setRaw(copy);
      if (opts.move) {
        try { await this.removeRaw(c); } catch (e) {
          try { if (existing) await this.setRaw(existing); else await this.removeRaw(created); } catch { /* best effort */ }
          throw e;
        }
      }
    });
    res.skipped.push(...cs.filter((c) => c.storeId === toStoreId));
    if (conflicts.length) res.conflicts = conflicts;
    return res;
  }
  move(cs: Cookie[], toStoreId: string, opts: BulkOptions & { conflict?: ConflictMode } = {}): Promise<BulkResult> {
    return this.copy(cs, toStoreId, { ...opts, move: true });
  }
}

import { CookieError, type CookieJar } from './api';
import type { AtRestCipher, Sealed } from './crypto';
import { changedFields, identityKey, siteOfCookie, type Cookie } from './model';

export interface SnapshotMeta {
  id: string;
  name: string;
  createdAt: number;
  /** The site it was taken for; restoring then replaces that site's cookies. */
  site?: string;
  count: number;
}

export interface CookieDiff {
  /** In `to`, not in `from`. */
  added: Cookie[];
  /** In `from`, not in `to`. */
  removed: Cookie[];
  changed: { before: Cookie; after: Cookie; fields: string[] }[];
  unchanged: number;
}

export function diffCookies(from: Cookie[], to: Cookie[]): CookieDiff {
  const a = new Map(from.map((c) => [identityKey(c), c]));
  const b = new Map(to.map((c) => [identityKey(c), c]));
  const d: CookieDiff = { added: [], removed: [], changed: [], unchanged: 0 };
  for (const [k, c] of b) {
    const old = a.get(k);
    if (!old) { d.added.push(c); continue; }
    const fields = changedFields(old, c);
    if (fields.length) d.changed.push({ before: old, after: c, fields }); else d.unchanged++;
  }
  for (const [k, c] of a) if (!b.has(k)) d.removed.push(c);
  return d;
}

export interface RestoreResult {
  set: number;
  removed: number;
  skippedExpired: number;
  skippedProtected: number;
}

interface Stored {
  meta: SnapshotMeta;
  sealed: Sealed;
}

export const SNAPSHOT_KEY = 'cookiejar.snapshots';

/** Named cookie snapshots, encrypted at rest (cookie values are credentials). */
export class SnapshotStore {
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly area: { get(k: string): Promise<Record<string, unknown>>; set(i: Record<string, unknown>): Promise<void> },
    private readonly cipher: AtRestCipher,
    private readonly o: { now?: () => number; newId?: () => string } = {},
  ) {}

  private serial<T>(f: () => Promise<T>): Promise<T> {
    const r = this.queue.then(f, f);
    this.queue = r.catch(() => undefined);
    return r;
  }

  private async read(): Promise<Record<string, Stored>> {
    return ((await this.area.get(SNAPSHOT_KEY))[SNAPSHOT_KEY] as Record<string, Stored> | undefined) ?? {};
  }

  async save(name: string, cookies: Cookie[], opts: { site?: string } = {}): Promise<SnapshotMeta> {
    const sealed = await this.cipher.seal(cookies);
    return this.serial(async () => {
      const all = await this.read();
      const id = this.o.newId?.() ?? globalThis.crypto.randomUUID();
      const meta: SnapshotMeta = { id, name: name.trim() || 'Snapshot', createdAt: this.o.now?.() ?? Date.now(), count: cookies.length, ...(opts.site ? { site: opts.site } : {}) };
      all[id] = { meta, sealed };
      await this.area.set({ [SNAPSHOT_KEY]: all });
      return meta;
    });
  }

  async list(): Promise<SnapshotMeta[]> {
    return Object.values(await this.read()).map((s) => s.meta).sort((a, b) => b.createdAt - a.createdAt);
  }

  async load(id: string): Promise<Cookie[]> {
    const s = (await this.read())[id];
    if (!s) throw new CookieError('not-found', 'That snapshot no longer exists.');
    return this.cipher.open<Cookie[]>(s.sealed);
  }

  delete(id: string): Promise<boolean> {
    return this.serial(async () => {
      const all = await this.read();
      if (!all[id]) return false;
      delete all[id];
      await this.area.set({ [SNAPSHOT_KEY]: all });
      return true;
    });
  }

  /** What the live jar holds of what a snapshot covers: the site's cookies, or just the selection. */
  private async scope(jar: CookieJar, meta: SnapshotMeta, snap: Cookie[]): Promise<Cookie[]> {
    if (!meta.site) return [];
    const stores = new Set(snap.map((c) => c.storeId));
    return (await jar.list({ site: meta.site })).filter((c) => stores.has(c.storeId) && siteOfCookie(c) === meta.site);
  }

  async diffWithLive(id: string, jar: CookieJar): Promise<CookieDiff> {
    const meta = (await this.list()).find((m) => m.id === id);
    if (!meta) throw new CookieError('not-found', 'That snapshot no longer exists.');
    const snap = await this.load(id);
    const live = meta.site ? await this.scope(jar, meta, snap) : (await Promise.all(snap.map((c) => jar.get(c)))).filter((c): c is Cookie => !!c);
    return diffCookies(snap, live);
  }

  async diffSnapshots(a: string, b: string): Promise<CookieDiff> {
    return diffCookies(await this.load(a), await this.load(b));
  }

  /**
   * Makes the site's cookies match the snapshot (a selection snapshot only sets its cookies).
   * Nothing is half-applied: on any failure the earlier changes are undone and the error is thrown.
   */
  async restore(id: string, jar: CookieJar, o: { isProtected?: (c: Cookie) => boolean; now?: number } = {}): Promise<RestoreResult> {
    const meta = (await this.list()).find((m) => m.id === id);
    if (!meta) throw new CookieError('not-found', 'That snapshot no longer exists.');
    const snap = await this.load(id);
    const now = (o.now ?? this.o.now?.() ?? Date.now()) / 1000;
    const usable = snap.filter((c) => c.session || c.expirationDate === undefined || c.expirationDate > now);
    const res: RestoreResult = { set: 0, removed: 0, skippedExpired: snap.length - usable.length, skippedProtected: 0 };
    const current = await this.scope(jar, meta, snap);
    // Prior state of everything the restore will overwrite, also for a selection snapshot.
    const before = new Map(current.map((c) => [identityKey(c), c]));
    for (const c of usable) {
      if (before.has(identityKey(c))) continue;
      let live: Cookie | null = null;
      try { live = await jar.get(c); } catch { /* treated as absent */ }
      if (live) before.set(identityKey(c), live);
    }

    const applied: { cookie: Cookie; prior?: Cookie }[] = [];
    const undo = async (removed: Cookie[]) => {
      for (const c of removed) { try { await jar.create(c); } catch { /* best effort */ } }
      for (const a of applied.reverse()) {
        try { if (a.prior) await jar.create(a.prior); else await jar.remove(a.cookie); } catch { /* best effort */ }
      }
    };
    for (const c of usable) {
      try {
        await jar.create(c);
        applied.push({ cookie: c, ...(before.has(identityKey(c)) ? { prior: before.get(identityKey(c))! } : {}) });
      } catch (e) {
        await undo([]);
        throw new CookieError('set-failed', `Restoring stopped at ${c.name} (${(e as Error).message}); nothing was changed.`);
      }
    }
    res.set = applied.length;
    const keep = new Set(usable.map(identityKey));
    const extras = current.filter((c) => !keep.has(identityKey(c)));
    const out = await jar.removeMany(extras, o.isProtected ? { isProtected: o.isProtected } : {});
    res.skippedProtected = out.skipped.length;
    if (out.failed.length) {
      await undo(out.done);
      throw new CookieError('remove-failed', `Could not remove ${out.failed[0]!.cookie.name} (${out.failed[0]!.error}); nothing was changed.`);
    }
    res.removed = out.done.length;
    return res;
  }
}

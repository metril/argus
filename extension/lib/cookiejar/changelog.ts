import { fromBrowser, identityKey, type Cookie } from './model';

export type ChangeKind = 'set' | 'changed' | 'removed' | 'expired' | 'evicted';

export interface ChangeEntry {
  /** Increasing; an entry that is completed later (overwrite then set) keeps its id. */
  id: number;
  at: number;
  kind: ChangeKind;
  /** The browser's own cause (`explicit`, `overwrite`, `expired`, ...). */
  cause: string;
  /** The cookie after the change (before it, for removals). The value is never kept: it is always ''. */
  cookie: Cookie;
  key: string;
  /** For `changed`: which attributes differ from the cookie it replaced. */
  fields?: string[];
  /** Overwrite seen, the setting half not yet; an internal marker that is gone once coalesced. */
  awaiting?: boolean;
  /** Only while `awaiting`: a short hash of the replaced value, to tell whether the overwrite changed it. */
  vh?: number;
  /** Old expiry/flags for comparing; internal. */
  prev?: Pick<Cookie, 'secure' | 'httpOnly' | 'sameSite' | 'session' | 'expirationDate'>;
}

export const LOG_KEY = 'cookiejar.activity';
export const MAX_ENTRIES = 500;

interface State {
  seq: number;
  entries: ChangeEntry[];
}

const hash = (s: string): number => { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; };

const KINDS: Record<string, ChangeKind> = { explicit: 'removed', expired: 'expired', expired_overwrite: 'expired', evicted: 'evicted', overwrite: 'changed' };

export interface ChangeInfo {
  removed: boolean;
  cookie: unknown;
  cause?: string;
}

/** A storage area that lives only in memory, for browsers without `storage.session`. */
export function memoryArea() {
  const d: Record<string, unknown> = {};
  return {
    async get(k: string): Promise<Record<string, unknown>> { return k in d ? { [k]: structuredClone(d[k]) } : {}; },
    async set(i: Record<string, unknown>): Promise<void> { for (const [k, v] of Object.entries(i)) d[k] = structuredClone(v); },
    async remove(k: string): Promise<void> { delete d[k]; },
  };
}

/**
 * A bounded activity log fed by `cookies.onChanged`. It lives in `storage.session`, so it survives
 * the background worker sleeping; an overwrite and the set that follows it become one `changed`.
 */
export class ChangeLog {
  private queue: Promise<unknown> = Promise.resolve();
  private subs = new Set<(e: ChangeEntry) => void>();

  constructor(
    private readonly area: { get(k: string): Promise<Record<string, unknown>>; set(i: Record<string, unknown>): Promise<void>; remove(k: string): Promise<void> },
    private readonly o: { max?: number; now?: () => number } = {},
  ) {}

  subscribe(f: (e: ChangeEntry) => void): () => void {
    this.subs.add(f);
    return () => { this.subs.delete(f); };
  }

  private async load(): Promise<State> {
    return ((await this.area.get(LOG_KEY))[LOG_KEY] as State | undefined) ?? { seq: 0, entries: [] };
  }

  private async save(s: State): Promise<void> {
    const max = this.o.max ?? MAX_ENTRIES;
    if (s.entries.length > max) s.entries.splice(0, s.entries.length - max);
    try { await this.area.set({ [LOG_KEY]: s }); } catch {
      // Over the storage quota: keep the newer half.
      s.entries.splice(0, Math.ceil(s.entries.length / 2));
      await this.area.set({ [LOG_KEY]: s });
    }
  }

  /** Feeds one `onChanged` event. */
  record(info: ChangeInfo): Promise<ChangeEntry | undefined> {
    const f = () => this.apply(info);
    const r = this.queue.then(f, f);
    this.queue = r.catch(() => undefined);
    return r;
  }

  private async apply(info: ChangeInfo): Promise<ChangeEntry | undefined> {
    const full = fromBrowser(info.cookie);
    const key = identityKey(full);
    // Values are credentials: the log keeps names and attributes only.
    const cookie: Cookie = { ...full, value: '' };
    const st = await this.load();
    const at = this.o.now?.() ?? Date.now();
    let entry: ChangeEntry | undefined;

    if (info.removed) {
      const kind = KINDS[info.cause ?? 'explicit'] ?? 'removed';
      entry = { id: ++st.seq, at, kind, cause: info.cause ?? 'explicit', cookie, key };
      if (info.cause === 'overwrite') {
        entry.awaiting = true;
        entry.vh = hash(full.value);
        entry.prev = { secure: full.secure, httpOnly: full.httpOnly, sameSite: full.sameSite, session: full.session, ...(full.expirationDate !== undefined ? { expirationDate: full.expirationDate } : {}) };
      }
      st.entries.push(entry);
    } else {
      const wait = [...st.entries].reverse().slice(0, 8).find((e) => e.awaiting && e.key === key);
      if (wait) {
        const fields: string[] = [];
        if (wait.vh !== hash(full.value)) fields.push('value');
        const p = wait.prev!;
        for (const k of ['secure', 'httpOnly', 'sameSite'] as const) if (p[k] !== full[k]) fields.push(k);
        if (p.session !== full.session || (p.expirationDate ?? 0) !== (full.expirationDate ?? 0)) fields.push('expires');
        Object.assign(wait, { at, kind: 'changed', cookie, fields });
        delete wait.awaiting;
        delete wait.vh;
        delete wait.prev;
        entry = wait;
      } else {
        entry = { id: ++st.seq, at, kind: 'set', cause: info.cause ?? 'explicit', cookie, key };
        st.entries.push(entry);
      }
    }
    await this.save(st);
    for (const s of this.subs) { try { s(entry); } catch { /* subscriber gone */ } }
    return entry;
  }

  /** Entries newer than `since` (an entry id), oldest first. */
  async entries(since = 0): Promise<ChangeEntry[]> {
    await this.queue;
    return (await this.load()).entries.filter((e) => e.id > since);
  }

  async clear(): Promise<void> {
    const f = async () => { const s = await this.load(); await this.area.set({ [LOG_KEY]: { seq: s.seq, entries: [] } }); };
    const r = this.queue.then(f, f);
    this.queue = r.catch(() => undefined);
    return r;
  }
}

/** Registers the `onChanged` listener; call it at the top level of the background worker. */
export function listenForChanges(br: any, log: ChangeLog): void {
  br.cookies?.onChanged?.addListener((info: ChangeInfo) => { void log.record(info).catch(() => undefined); });
}

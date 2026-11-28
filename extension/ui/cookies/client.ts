import { createContext } from 'preact';
import { useContext } from 'preact/hooks';
import type { BulkResult, ConflictMode, StoreInfo } from '../../lib/cookiejar/api';
import type { ChangeEntry } from '../../lib/cookiejar/changelog';
import type { FormatId, SnippetId } from '../../lib/cookiejar/codecs';
import type { ApplyResult, ImportMode, ImportPlan } from '../../lib/cookiejar/detect';
import type { Cookie } from '../../lib/cookiejar/model';
import type { CookieRuleOptions } from '../../lib/cookiejar/rule';
import type { RuleSet } from '../../lib/cookiejar/rules';
import type { CookieDiff, RestoreResult, SnapshotMeta } from '../../lib/cookiejar/snapshots';
import type { Issue } from '../../lib/cookiejar/validate';

/** A cookie as the page lists it: the library's cookie plus whether a protect rule covers it. */
export type ListedCookie = Cookie & { isProtected?: boolean };

/** The service's requests, spelled out so the page is typed against the port (type-only import: the service is not bundled). */
export type Req =
  | { op: 'stores' }
  | { op: 'list'; site?: string; storeId?: string }
  | { op: 'validate'; cookie: Cookie; url?: string }
  | { op: 'create'; cookie: Cookie }
  | { op: 'edit'; old: Cookie; next: Cookie }
  | { op: 'remove'; cookies: Cookie[] }
  | { op: 'removeMany'; cookies: Cookie[] }
  | { op: 'copy'; cookies: Cookie[]; toStoreId: string; move?: boolean; conflict?: ConflictMode }
  | { op: 'export'; cookies: Cookie[]; format?: FormatId; snippet?: SnippetId; url?: string; passphrase?: string }
  | { op: 'import'; text: string; storeId: string; mode?: ImportMode; format?: FormatId; host?: string; passphrase?: string; dryRun?: boolean }
  | { op: 'snapshot.save'; name: string; site?: string; cookies?: Cookie[] }
  | { op: 'snapshot.list' }
  | { op: 'snapshot.delete'; id: string }
  | { op: 'snapshot.restore'; id: string }
  | { op: 'snapshot.diff'; id: string; other?: string }
  | { op: 'rules.get' }
  | { op: 'rules.set'; rules: Partial<RuleSet> }
  | { op: 'rules.protect'; cookies: Cookie[]; protect: boolean }
  | { op: 'activity.since'; since?: number }
  | { op: 'activity.clear' }
  | { op: 'rule.line'; cookie: Cookie; options: CookieRuleOptions };

export interface Results {
  stores: StoreInfo[];
  list: ListedCookie[];
  validate: Issue[];
  create: Cookie;
  edit: Cookie;
  remove: BulkResult;
  removeMany: BulkResult;
  copy: BulkResult;
  export: { text: string; mime: string; extension: string };
  import: { plan: ImportPlan; result?: ApplyResult };
  'snapshot.save': SnapshotMeta;
  'snapshot.list': SnapshotMeta[];
  'snapshot.delete': unknown;
  'snapshot.restore': RestoreResult;
  'snapshot.diff': CookieDiff;
  'rules.get': RuleSet;
  'rules.set': RuleSet;
  'rules.protect': RuleSet;
  'activity.since': ChangeEntry[];
  'activity.clear': unknown;
  'rule.line': string;
}

export class ClientError extends Error {
  constructor(readonly code: string, message: string) { super(message); this.name = 'ClientError'; }
}

export interface PortLike {
  postMessage(m: unknown): void;
  onMessage: { addListener(f: (m: any) => void): void };
  onDisconnect: { addListener(f: () => void): void };
  disconnect(): void;
}

/** The page's end of the background `cookies` port: request/reply by `rid`, pushed activity, and a reconnect when the worker sleeps. */
export class CookieClient {
  private port: PortLike | null = null;
  private rid = 0;
  private pending = new Map<number, { ok: (v: any) => void; fail: (e: Error) => void }>();
  private activity = new Set<(e: ChangeEntry) => void>();
  private resync = new Set<() => void>();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private attempts = 0;
  private lost = false;
  private closed = false;
  private dead = false;
  private deadFns = new Set<() => void>();

  /** `alive` says whether this extension context still exists: after an update or reload `runtime.id` is gone and no port can ever connect again. */
  constructor(private readonly connect: () => PortLike, private readonly o: { backoffMs?: number; maxBackoffMs?: number; alive?: () => boolean } = {}) {}

  private isAlive(): boolean { return (this.o.alive ?? (() => !!browser.runtime?.id))(); }

  private markDead(): void {
    if (this.dead) return;
    this.dead = true;
    clearTimeout(this.timer);
    for (const [, w] of this.pending) w.fail(new ClientError('stale', 'Argus was updated. Reload this page.'));
    this.pending.clear();
    for (const f of [...this.deadFns]) f();
  }

  /** Called once when the extension was reloaded or updated under this page. */
  onDead(f: () => void): () => void {
    this.deadFns.add(f);
    if (this.dead) queueMicrotask(f);
    return () => { this.deadFns.delete(f); };
  }

  private ensure(): PortLike {
    if (this.port) return this.port;
    if (this.dead || !this.isAlive()) { this.markDead(); throw new ClientError('stale', 'Argus was updated. Reload this page.'); }
    const p = this.connect();
    p.onMessage.addListener((m: any) => {
      this.attempts = 0;
      if (m?.t === 'activity') { for (const f of this.activity) f(m.entry); return; }
      const w = this.pending.get(m?.rid);
      if (!w) return;
      this.pending.delete(m.rid);
      if (m.ok) w.ok(m.result); else w.fail(new ClientError(m.error?.code ?? 'error', m.error?.message ?? 'The request failed.'));
    });
    p.onDisconnect.addListener(() => {
      if (this.port === p) this.port = null;
      for (const [, w] of this.pending) w.fail(new ClientError('disconnected', 'The extension was not reachable. Try again.'));
      this.pending.clear();
      if (this.closed) return;
      if (!this.isAlive()) { this.markDead(); return; }
      // The worker sleeps after about 30 s idle: open a new port with a backoff, then let the data hooks catch up.
      this.lost = true;
      if (this.activity.size > 0 || this.resync.size > 0) this.reconnectSoon();
    });
    this.port = p;
    if (this.lost) { this.lost = false; queueMicrotask(() => { for (const f of [...this.resync]) f(); }); }
    return p;
  }

  private reconnectSoon(): void {
    if (this.timer || this.closed) return;
    const base = this.o.backoffMs ?? 400, max = this.o.maxBackoffMs ?? 8000;
    const wait = Math.min(max, base * 2 ** this.attempts++);
    this.timer = setTimeout(() => {
      this.timer = undefined;
      try { this.ensure(); } catch { if (!this.dead) this.reconnectSoon(); }
    }, wait);
  }

  call<K extends Req['op']>(req: Extract<Req, { op: K }>): Promise<Results[K]> {
    return new Promise((ok, fail) => {
      const rid = ++this.rid;
      this.pending.set(rid, { ok, fail });
      try { this.ensure().postMessage({ ...req, rid }); } catch (e) { this.pending.delete(rid); fail(e as Error); }
    });
  }

  /** Live activity entries; also opens the port so the background starts pushing. */
  onActivity(f: (e: ChangeEntry) => void): () => void {
    this.activity.add(f);
    try { this.ensure(); } catch { if (!this.dead) this.reconnectSoon(); }
    return () => { this.activity.delete(f); };
  }

  /** Called after the port came back: whatever was cached may have missed changes. */
  onResync(f: () => void): () => void {
    this.resync.add(f);
    return () => { this.resync.delete(f); };
  }

  close(): void { this.closed = true; clearTimeout(this.timer); try { this.port?.disconnect(); } catch { /* gone */ } this.port = null; }
}

export const realClient = (): CookieClient => new CookieClient(() => browser.runtime.connect({ name: 'cookies' }));

export const ClientCtx = createContext<CookieClient | null>(null);
export function useClient(): CookieClient {
  const c = useContext(ClientCtx);
  if (!c) throw new Error('No cookie client');
  return c;
}

export const errText = (e: unknown): string => String((e as Error)?.message ?? e).slice(0, 200);

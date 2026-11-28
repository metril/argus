import type { BulkResult, CookieJar } from './api';
import { hostOfCookie, hostUnder, identityKey, siteOf, siteOfCookie, type Cookie } from './model';

export interface RuleSet {
  /** Identity keys of cookies that bulk delete and auto-delete never remove. */
  protected: string[];
  /** Sites (a domain or a host) whose cookies are never auto-deleted. */
  keep: string[];
  /** Sites cleaned only when the browser starts, not when their tabs close. */
  grey: string[];
  autoDelete: { enabled: boolean; delayMinutes: number };
}

export const RULES_KEY = 'cookiejar.rules';
export const MIN_DELAY_MINUTES = 0.5;
export const MAX_DELAY_MINUTES = 24 * 60;
export const ALARM_PREFIX = 'cookiejar-clean:';

export const defaultRules = (): RuleSet => ({ protected: [], keep: [], grey: [], autoDelete: { enabled: false, delayMinutes: 1 } });

type Area = { get(k: string): Promise<Record<string, unknown>>; set(i: Record<string, unknown>): Promise<void> };

const cleanSite = (s: string): string => s.trim().toLowerCase().replace(/^\*?\./, '');
const uniq = (xs: string[]): string[] => [...new Set(xs)];

/** Coerces stored or posted settings into a valid rule set. */
export function normalizeRules(v: Partial<RuleSet> | undefined): RuleSet {
  const d = defaultRules();
  const list = (x: unknown): string[] => (Array.isArray(x) ? x.filter((s): s is string => typeof s === 'string') : []);
  const delay = Number(v?.autoDelete?.delayMinutes);
  return {
    protected: uniq(list(v?.protected)),
    keep: uniq(list(v?.keep).map(cleanSite).filter(Boolean)),
    grey: uniq(list(v?.grey).map(cleanSite).filter(Boolean)),
    autoDelete: {
      enabled: !!v?.autoDelete?.enabled,
      delayMinutes: Number.isFinite(delay) ? Math.min(MAX_DELAY_MINUTES, Math.max(MIN_DELAY_MINUTES, delay)) : d.autoDelete.delayMinutes,
    },
  };
}

/** Protected cookies, keep list, greylist and auto-delete settings, persisted in `storage.local`. */
export class Rules {
  private queue: Promise<unknown> = Promise.resolve();
  constructor(private readonly area: Area) {}

  async get(): Promise<RuleSet> {
    return normalizeRules((await this.area.get(RULES_KEY))[RULES_KEY] as Partial<RuleSet> | undefined);
  }

  /** Changes settings; the lists given replace the stored ones. */
  update(patch: Partial<RuleSet>): Promise<RuleSet> {
    const f = async () => {
      const cur = await this.get();
      const next = normalizeRules({ ...cur, ...patch, autoDelete: { ...cur.autoDelete, ...(patch.autoDelete ?? {}) } });
      await this.area.set({ [RULES_KEY]: next });
      return next;
    };
    const r = this.queue.then(f, f);
    this.queue = r.catch(() => undefined);
    return r;
  }

  async protect(cs: Cookie[]): Promise<RuleSet> {
    const cur = await this.get();
    return this.update({ protected: [...cur.protected, ...cs.map(identityKey)] });
  }

  async unprotect(cs: Cookie[]): Promise<RuleSet> {
    const drop = new Set(cs.map(identityKey));
    const cur = await this.get();
    return this.update({ protected: cur.protected.filter((k) => !drop.has(k)) });
  }

  /** A synchronous predicate over the current rules, for bulk operations. */
  async guard(): Promise<(c: Cookie) => boolean> {
    const keys = new Set((await this.get()).protected);
    return (c) => keys.has(identityKey(c));
  }
}

export const isKept = (r: RuleSet, host: string): boolean => r.keep.some((e) => hostUnder(host, e));
export const isGrey = (r: RuleSet, host: string): boolean => r.grey.some((e) => hostUnder(host, e));

/** The registrable domain of an http(s) page URL; undefined for anything else. */
export function siteOfUrl(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try { const u = new URL(url); return u.protocol === 'http:' || u.protocol === 'https:' ? siteOf(u.hostname) : undefined; } catch { return undefined; }
}

interface AutoState {
  /** tabId -> site, kept because `tabs.onRemoved` only gives the id. */
  tabs: Record<string, string>;
  /** site -> due time (ms) of the pending cleanup. */
  due: Record<string, number>;
}

const STATE_KEY = 'cookiejar.autodelete';

/**
 * Removes cookies of sites the user does not keep, a delay after the last tab of the site closes.
 * Scheduling is `alarms` (they outlive the worker); state is in `storage.session`.
 */
export class AutoDelete {
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly br: { alarms?: any; tabs: any },
    private readonly jar: CookieJar,
    private readonly rules: Rules,
    private readonly session: Area & { remove?(k: string): Promise<void> },
    private readonly o: { now?: () => number } = {},
  ) {}

  private serial<T>(f: () => Promise<T>): Promise<T> {
    const r = this.queue.then(f, f);
    this.queue = r.catch(() => undefined);
    return r;
  }
  private async load(): Promise<AutoState> {
    return ((await this.session.get(STATE_KEY))[STATE_KEY] as AutoState | undefined) ?? { tabs: {}, due: {} };
  }
  private save(s: AutoState) { return this.session.set({ [STATE_KEY]: s }); }
  private now() { return this.o.now?.() ?? Date.now(); }

  /**
   * Worker start: merges the open tabs into the persisted map. A persisted tab that no longer
   * exists closed while the worker slept, so it gets the same treatment as `tabRemoved`.
   */
  init(): Promise<void> {
    return this.serial(async () => {
      const s = await this.load();
      const prev = s.tabs;
      s.tabs = {};
      for (const t of (await this.br.tabs.query({})) as { id?: number; url?: string; pendingUrl?: string }[]) {
        const site = siteOfUrl(t.url ?? t.pendingUrl);
        if (t.id !== undefined && site) s.tabs[String(t.id)] = site;
      }
      const r = await this.rules.get();
      for (const [id, site] of Object.entries(prev)) if (!(id in s.tabs)) await this.scheduleIfLast(s, site, r);
      await this.save(s);
    });
  }

  private async scheduleIfLast(s: AutoState, site: string, r: RuleSet): Promise<void> {
    if (!r.autoDelete.enabled || Object.values(s.tabs).includes(site) || isKept(r, site) || isGrey(r, site)) return;
    const when = this.now() + r.autoDelete.delayMinutes * 60_000;
    s.due[site] = when;
    await this.br.alarms?.create(ALARM_PREFIX + site, { when });
  }

  /** A tab loaded `url`: its site is open again, so a pending cleanup for it is cancelled. */
  noteTab(tabId: number, url: string | undefined): Promise<void> {
    return this.serial(async () => {
      const site = siteOfUrl(url);
      const s = await this.load();
      if (site) s.tabs[String(tabId)] = site; else delete s.tabs[String(tabId)];
      if (site && s.due[site] !== undefined) { delete s.due[site]; try { await this.br.alarms?.clear(ALARM_PREFIX + site); } catch { /* ignore */ } }
      await this.save(s);
    });
  }

  /** A tab closed: when it was the last one of its site, schedule the cleanup. */
  tabRemoved(tabId: number): Promise<void> {
    return this.serial(async () => {
      const s = await this.load();
      const site = s.tabs[String(tabId)];
      if (!site) return;
      delete s.tabs[String(tabId)];
      await this.scheduleIfLast(s, site, await this.rules.get());
      await this.save(s);
    });
  }

  /** An alarm fired; true when it was ours. */
  async alarm(name: string): Promise<boolean> {
    if (!name.startsWith(ALARM_PREFIX)) return false;
    const site = name.slice(ALARM_PREFIX.length);
    await this.serial(async () => {
      const s = await this.load();
      delete s.due[site];
      await this.save(s);
      const r = await this.rules.get();
      if (!r.autoDelete.enabled || isKept(r, site) || isGrey(r, site) || Object.values(s.tabs).includes(site)) return;
      await this.clean((c) => siteOfCookie(c) === site, r, site);
    });
    return true;
  }

  /** Browser start: clean every site that is not kept (greylisted ones included) and not open. */
  startup(): Promise<BulkResult | undefined> {
    return this.serial(async () => {
      const r = await this.rules.get();
      const s = await this.load();
      s.due = {};
      await this.save(s);
      if (!r.autoDelete.enabled) return undefined;
      try { for (const a of (await this.br.alarms?.getAll?.()) ?? []) if (a.name.startsWith(ALARM_PREFIX)) await this.br.alarms.clear(a.name); } catch { /* ignore */ }
      const open = new Set(Object.values(s.tabs));
      return this.clean((c) => !open.has(siteOfCookie(c)), r);
    });
  }

  private async clean(want: (c: Cookie) => boolean, r: RuleSet, site?: string): Promise<BulkResult> {
    const all = await this.jar.list(site ? { site } : {});
    const victims = all.filter((c) => want(c) && !isKept(r, hostOfCookie(c)));
    const keys = new Set(r.protected);
    return this.jar.removeMany(victims, { isProtected: (c) => keys.has(identityKey(c)) });
  }
}

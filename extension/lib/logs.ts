import type { LogEntry } from './api';
import type { Area } from './stats';

/** A logged request joined to the tab that made it (`tabId` -1: no tab could be matched). */
export interface LogRow extends LogEntry { tabId: number }
/** A request as the browser saw it start (`webRequest.onBeforeRequest`). `used` marks it joined. */
export interface ReqRec { tabId: number; url: string; at: number; used?: boolean }

export const MAX_ROWS_PER_TAB = 300;
export const MAX_REQS = 1500;
/** How far apart the proxy's and the browser's timestamps of one request may be. */
export const JOIN_WINDOW_MS = 30_000;

/** The proxy drops the query (and fragment) unless its request log keeps queries. */
const noQuery = (u: string) => u.split(/[?#]/)[0]!;

/**
 * Joins proxy log entries to tabs: the same URL (without query) seen by `webRequest`, nearest in
 * time, each browser request used once. Without a match the page host of a tab decides (when
 * exactly one tab shows that host); otherwise the row has no tab.
 */
export function joinEntries(entries: LogEntry[], reqs: ReqRec[], pages: Record<number, string>): LogRow[] {
  return entries.map((e) => {
    const at = Date.parse(e.time);
    const url = noQuery(e.url);
    let best: ReqRec | undefined;
    for (const r of reqs) {
      if (r.used || noQuery(r.url) !== url) continue;
      if (!Number.isNaN(at) && Math.abs(r.at - at) > JOIN_WINDOW_MS) continue;
      if (!best || Math.abs(r.at - at) < Math.abs(best.at - at)) best = r;
    }
    if (best) { best.used = true; return { ...e, tabId: best.tabId }; }
    const host = e.source_host.toLowerCase();
    const tabs = host ? Object.entries(pages).filter(([, h]) => h.toLowerCase() === host) : [];
    return { ...e, tabId: tabs.length === 1 ? Number(tabs[0]![0]) : -1 };
  });
}

export type LogBuffer = Record<number, LogRow[]>;

/** Appends rows to their tabs' buffers, each capped to its newest `cap` rows (pure). */
export function addRows(buf: LogBuffer, rows: LogRow[], cap = MAX_ROWS_PER_TAB): LogBuffer {
  if (rows.length === 0) return buf;
  const n: LogBuffer = { ...buf };
  for (const r of rows) {
    if (r.tabId < 0) continue;
    const cur = n[r.tabId] ?? [];
    n[r.tabId] = [...cur, r].slice(-cap);
  }
  return n;
}

const KEY = 'logRows';

/** Per-tab row buffers, kept in `storage.session` so the history survives the worker sleeping. */
export class LogStore {
  private m: LogBuffer = {};
  private timer: ReturnType<typeof setTimeout> | undefined;
  readonly ready: Promise<void>;
  constructor(private area: Area | undefined, private flushMs = 500) {
    this.ready = (async () => {
      try {
        const r = (await this.area?.get(KEY))?.[KEY];
        if (r && typeof r === 'object') this.m = { ...(r as LogBuffer), ...this.m };
      } catch { /* memory only */ }
    })();
  }
  async add(rows: LogRow[]) { await this.ready; this.m = addRows(this.m, rows); this.schedule(); }
  async rows(tabId: number): Promise<LogRow[]> { await this.ready; return this.m[tabId] ?? []; }
  async clear(tabId: number) { await this.ready; if (!(tabId in this.m)) return; const { [tabId]: _d, ...rest } = this.m; this.m = rest; this.schedule(); }
  async counts(): Promise<Record<number, number>> {
    await this.ready;
    return Object.fromEntries(Object.entries(this.m).map(([k, v]) => [k, v.length]));
  }
  private schedule() {
    if (this.timer) return;
    this.timer = setTimeout(() => { this.timer = undefined; void this.area?.set({ [KEY]: this.m }).catch(() => {}); }, this.flushMs);
  }
}

/** Remembers recent browser requests (bounded) for the join. */
export class ReqLog {
  private list: ReqRec[] = [];
  add(r: ReqRec) { this.list.push(r); if (this.list.length > MAX_REQS) this.list.splice(0, this.list.length - MAX_REQS); }
  all(): ReqRec[] { return this.list; }
}

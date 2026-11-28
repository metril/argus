import type { LogEntry } from './api';
import type { Area, LogRef } from './stats';

/** Entries kept for attributing network errors (the newest). */
export const MAX_RECENT = 500;
const KEY = 'logCursor';

export const entryKey = (sid: string, seq: number) => `${sid}:${seq}`;

/**
 * Position in the proxy's per-session log (`GET /ext/log`) and the entries seen so far. The proxy
 * numbers entries per session, so everything is keyed by `sid:seq`; a new session id starts over
 * (cursor, recent entries and consumed marks). The cursor lives in `storage.session` so a worker
 * restart resumes where it stopped instead of re-reading (and duplicating) the whole log.
 */
export class LogFeed {
  sid = '';
  cursor = 0;
  recent: LogRef[] = [];
  /** `sid:seq` of the entries that already explained a network error; pruned with `recent`. */
  readonly used = new Set<string>();
  private loaded: Promise<void>;
  constructor(private area: Area | undefined) {
    this.loaded = (async () => {
      try {
        const r = (await this.area?.get(KEY))?.[KEY] as { sid?: unknown; cursor?: unknown } | undefined;
        // A poll that already ran wins over the stored value.
        if (r && typeof r.sid === 'string' && typeof r.cursor === 'number' && this.sid === '') {
          this.sid = r.sid;
          this.cursor = r.cursor;
        }
      } catch { /* memory only */ }
    })();
  }

  /** The cursor to poll from for session `sid` (resetting everything when the session changed). */
  async begin(sid: string): Promise<number> {
    await this.loaded;
    if (sid !== this.sid) {
      this.sid = sid;
      this.cursor = 0;
      this.recent = [];
      this.used.clear();
      this.save();
    }
    return this.cursor;
  }

  /**
   * Take a poll answer for `sid`. Returns the entries that are new (none when the session changed
   * while the request was out, or the entries were already taken).
   */
  accept(sid: string, next: number, entries: LogEntry[]): LogEntry[] {
    if (sid !== this.sid) return [];
    const fresh = entries.filter((e) => e.seq > this.cursor);
    this.cursor = Math.max(this.cursor, next);
    if (fresh.length > 0) {
      this.recent.push(...fresh.map((e) => ({ key: entryKey(sid, e.seq), seq: e.seq, url: e.url, at: Date.parse(e.time), outcome: e.outcome, source: e.source_host })));
      if (this.recent.length > MAX_RECENT) this.recent.splice(0, this.recent.length - MAX_RECENT);
      const live = new Set(this.recent.map((r) => r.key));
      for (const k of this.used) if (!live.has(k)) this.used.delete(k);
    }
    this.save();
    return fresh;
  }

  private save() {
    void this.area?.set({ [KEY]: { sid: this.sid, cursor: this.cursor } }).catch(() => {});
  }
}

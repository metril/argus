import { getDomain } from 'tldts';

/**
 * Per-tab request counters for the popup and the badge.
 *
 * The proxy tags the responses it synthesises with `x-adblock` (`blocked`, `redirected`,
 * `rewritten`, `policy`). With `block_response = fail` (the default) most subresource blocks are
 * aborted instead: no response, so the browser reports a network error. Those are attributed by
 * asking the proxy (`GET /stats/blocked/recent`) whether it blocked the URL; see `reconcile`.
 * A real upstream failure also looks like an abort and stays "failed" when the proxy did not
 * block it. Not visible here: CONNECT-level blocks (no MITM: the tab only sees a failed
 * connection, counted only when the proxy logged the URL) and WebSocket handshakes (not reported
 * by webRequest on every browser).
 */
export interface HostCount { blocked: number; allowed: number }
export interface Pending { url: string; host: string; at: number; page?: string }
/** One entry of the proxy's recent-blocked ring: `at` is epoch ms (NaN when unparsable). */
export interface BlockedRef { url: string; at: number; source?: string | null }
export interface TabStats {
  blocked: number;
  redirected: number;
  allowed: number;
  failed: number;
  hosts: Record<string, HostCount>;
  pending: Pending[];
  /** Host of the main document (the proxy reports it as `source_host`). */
  pageHost?: string;
}

export const MAX_HOSTS = 300;
export const MAX_PENDING = 100;
/** How long an unexplained network error waits for the proxy's log before it counts as failed. */
export const PENDING_TTL_MS = 10_000;
/** A ring entry may predate the browser's error report by this much. */
export const MATCH_SLACK_MS = 2000;

export const emptyStats = (): TabStats => ({ blocked: 0, redirected: 0, allowed: 0, failed: 0, hosts: {}, pending: [] });

export type Kind = 'blocked' | 'redirected' | 'allowed' | 'other';

/** `x-adblock` of a response: block tags count as blocked, redirects as redirected, errors are neither. */
export function classify(headers: { name: string; value?: string }[] | undefined): Kind {
  const h = headers?.find((x) => x.name.toLowerCase() === 'x-adblock');
  if (!h) return 'allowed';
  switch ((h.value ?? '').toLowerCase()) {
    case 'blocked': case 'policy': return 'blocked';
    case 'redirected': case 'rewritten': return 'redirected';
    default: return 'other'; // cert-error, destination-refused, unresolved-upstream, ...
  }
}

export function hostnameOf(url: string): string {
  try { return new URL(url).hostname; } catch { return ''; }
}

/** What the page counts as blocked: blocks plus neutralised (redirected) requests. */
export const blockedTotal = (s: TabStats) => s.blocked + s.redirected;
export const totalRequests = (s: TabStats) => s.blocked + s.redirected + s.allowed;
export function percent(s: TabStats): number {
  const t = totalRequests(s);
  return t === 0 ? 0 : Math.round((blockedTotal(s) / t) * 100);
}

function bump(s: TabStats, host: string, field: 'blocked' | 'allowed') {
  if (!host) return;
  let h = s.hosts[host];
  if (!h) {
    if (Object.keys(s.hosts).length >= MAX_HOSTS) return;
    h = s.hosts[host] = { blocked: 0, allowed: 0 };
  }
  h[field]++;
}

/** Counts one answered request (pure: returns a new state). */
export function applyResponse(s: TabStats, kind: Kind, host: string): TabStats {
  const n: TabStats = { ...s, hosts: {} };
  for (const k of Object.keys(s.hosts)) n.hosts[k] = { ...s.hosts[k]! };
  if (kind === 'blocked') { n.blocked++; bump(n, host, 'blocked'); }
  else if (kind === 'redirected') { n.redirected++; bump(n, host, 'blocked'); }
  else if (kind === 'allowed') { n.allowed++; bump(n, host, 'allowed'); }
  return n;
}

/** Errors that are the page cancelling its own request, not a network failure. */
export const isCancel = (error?: string) => !error || /ERR_ABORTED|BINDING_ABORTED|ERR_BLOCKED_BY_CLIENT/i.test(error);

/** Remembers a failed request until the proxy's log tells whether it was a block. */
export function applyError(s: TabStats, url: string, now: number, error?: string): TabStats {
  if (isCancel(error)) return s;
  const pending = [...s.pending, { url, host: hostnameOf(url), at: now, ...(s.pageHost ? { page: s.pageHost } : {}) }].slice(-MAX_PENDING);
  return { ...s, pending };
}

/** The proxy stores blocked URLs without query string and fragment, so compare that way. */
const noFragment = (u: string) => u.split(/[?#]/)[0]!;

/** Just the fields of a `/ext/log` entry that attribution needs (`at` is epoch ms). */
export interface LogRef { key: string; seq: number; url: string; at: number; outcome: string; source?: string | null }

/**
 * Exact attribution: the proxy tagged each request of this session, so an unexplained network
 * error is a block when the log holds an `aborted` entry for the same URL (the proxy drops the
 * query unless its request log keeps queries, so it is not compared), not
 * older than the error minus a little slack, and for the same page host. Each entry explains at
 * most one error; `used` (`sid:seq` keys) is shared across calls and updated here.
 */
export function attribute(s: TabStats, entries: LogRef[], now: number, used: Set<string>): TabStats {
  if (s.pending.length === 0) return s;
  let n: TabStats = { ...s, pending: [] };
  for (const p of s.pending) {
    const e = entries.find((r) =>
      r.outcome === 'aborted' && !used.has(r.key) && noFragment(r.url) === noFragment(p.url)
      && (Number.isNaN(r.at) || r.at >= p.at - MATCH_SLACK_MS)
      && (!p.page || !r.source || r.source.toLowerCase() === p.page.toLowerCase()));
    if (e) { used.add(e.key); n = applyResponse(n, 'blocked', p.host); }
    else if (now - p.at >= PENDING_TTL_MS) n = { ...n, failed: n.failed + 1 };
    else n = { ...n, pending: [...n.pending, p] };
  }
  return n;
}

/**
 * Fallback for a proxy without `/ext/log`: resolves pending failures against the proxy's
 * recent-blocked ring. An entry matches by URL
 * (without query), not older than the failure minus a little slack, and for the same page host;
 * each entry is consumed by at most one failure.
 */
export function reconcile(s: TabStats, ring: BlockedRef[], now: number): TabStats {
  if (s.pending.length === 0) return s;
  const left = ring.map((r) => ({ ...r, key: noFragment(r.url) }));
  let n: TabStats = { ...s, pending: [] };
  for (const p of s.pending) {
    const i = left.findIndex((r) =>
      r.key === noFragment(p.url)
      && (Number.isNaN(r.at) || r.at >= p.at - MATCH_SLACK_MS)
      && (!p.page || (r.source ?? '').toLowerCase() === p.page.toLowerCase()));
    if (i >= 0) { left.splice(i, 1); n = applyResponse(n, 'blocked', p.host); }
    else if (now - p.at >= PENDING_TTL_MS) n = { ...n, failed: n.failed + 1 };
    else n = { ...n, pending: [...n.pending, p] };
  }
  return n;
}

export type StatsEvent =
  | { t: 'response'; tabId: number; main: boolean; kind: Kind; host: string }
  | { t: 'error'; tabId: number; main: boolean; url: string; now: number; error?: string }
  | { t: 'reconcile'; tabId: number; blocked: BlockedRef[]; now: number }
  | { t: 'attribute'; tabId: number; entries: LogRef[]; used: Set<string>; now: number }
  | { t: 'close'; tabId: number };

export type StatsMap = Record<number, TabStats>;

/** The reducer: a main-frame load starts a new page, a closed tab is dropped. */
export function reduce(m: StatsMap, e: StatsEvent): StatsMap {
  if (e.tabId < 0) return m;
  if (e.t === 'close') {
    if (!(e.tabId in m)) return m;
    const { [e.tabId]: _drop, ...rest } = m;
    return rest;
  }
  let cur = m[e.tabId] ?? emptyStats();
  if (e.t === 'attribute') return e.tabId in m ? { ...m, [e.tabId]: attribute(cur, e.entries, e.now, e.used) } : m;
  if (e.t === 'reconcile') return e.tabId in m ? { ...m, [e.tabId]: reconcile(cur, e.blocked, e.now) } : m;
  // A new page starts on a main-frame response or a real main-frame error, not on a cancel
  // (a download, a 204, a stopped navigation keeps the page it left).
  if (e.main && (e.t === 'response' || !isCancel(e.error))) cur = emptyStats();
  if (e.main && e.t === 'response') cur = { ...cur, pageHost: e.host };
  cur = e.t === 'response' ? applyResponse(cur, e.kind, e.host) : applyError(cur, e.url, e.now, e.error);
  return { ...m, [e.tabId]: cur };
}

const KEY = 'tabStats';
export interface Area { get(k: string): Promise<Record<string, unknown>>; set(o: Record<string, unknown>): Promise<void> }

/** The map, kept in `storage.session` so it survives the MV3 service worker sleeping. */
export class StatsStore {
  private m: StatsMap = {};
  private timer: ReturnType<typeof setTimeout> | undefined;
  readonly ready: Promise<void>;
  constructor(private area: Area | undefined, private onChange: (tabId: number) => void = () => {}, private flushMs = 300) {
    this.ready = (async () => {
      try {
        const r = (await this.area?.get(KEY))?.[KEY];
        if (r && typeof r === 'object') this.m = { ...(r as StatsMap), ...this.m };
      } catch { /* session storage unavailable: memory only */ }
    })();
  }
  async dispatch(e: StatsEvent) {
    await this.ready;
    const next = reduce(this.m, e);
    if (next === this.m) return;
    this.m = next;
    this.schedule();
    this.onChange(e.tabId);
  }
  async tab(tabId: number): Promise<TabStats> { await this.ready; return this.m[tabId] ?? emptyStats(); }
  private schedule() {
    if (this.timer) return;
    this.timer = setTimeout(() => { this.timer = undefined; void this.flush(); }, this.flushMs);
  }
  async flush() {
    try { await this.area?.set({ [KEY]: this.m }); } catch { /* ignore */ }
  }
}

/** Registrable domain by the public-suffix list (private suffixes such as herokuapp.com included); the full host when there is none (IP, localhost). */
export function registrableDomain(host: string): string {
  const h = host.toLowerCase().replace(/\.$/, '');
  return getDomain(h, { allowPrivateDomains: true }) ?? h;
}

import { call, type Settings } from '../api';
import { hostOfCookie, identityKey, type Cookie } from './model';

/** The attributes of a `Set-Cookie` header exactly as the server sent them. Never a value. */
export interface SentAttrs {
  domain?: string;
  path?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'none' | 'lax' | 'strict';
  /** Seconds. */
  maxAge?: number;
  /** Seconds since the epoch. */
  expires?: number;
  partitioned?: boolean;
}

export type ProvenanceEffect = 'changed' | 'stripped';

/** What the proxy saw when a response set (or a rule removed) one cookie. */
export interface ProvenanceRecord {
  /** Milliseconds since the epoch. */
  at: number;
  name: string;
  /** Host and path (no query string) of the request whose response set the cookie. */
  host: string;
  path: string;
  sent: SentAttrs;
  /** Present when a `$cookie` rule changed or removed the cookie. */
  effect?: ProvenanceEffect;
  rule?: string;
  listId?: string;
  listName?: string;
  line?: number;
}

export type Provenance =
  | { enabled: false; reason: 'disabled' | 'unavailable' | 'no-session' | 'scope' }
  | { enabled: true; records: ProvenanceRecord[] };

/** The wire record of `GET /ext/cookies/provenance` (snake_case; times as ISO strings or milliseconds). */
interface Wire {
  time?: string | number;
  name?: string;
  host?: string;
  path?: string;
  attrs?: { domain?: string; path?: string; secure?: boolean; http_only?: boolean; same_site?: string; max_age?: number; expires?: string | number; partitioned?: boolean };
  effect?: string;
  rule?: string;
  list_id?: string;
  list_name?: string;
  line?: number;
}

const ms = (v: unknown): number | undefined => {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') { const t = Date.parse(v); return Number.isNaN(t) ? undefined : t; }
  return undefined;
};

export function parseRecord(w: Wire): ProvenanceRecord | undefined {
  const at = ms(w.time);
  if (at === undefined || !w.name || !w.host) return undefined;
  const a = w.attrs ?? {};
  const sent: SentAttrs = {};
  if (a.domain) sent.domain = a.domain;
  if (a.path) sent.path = a.path;
  if (a.secure) sent.secure = true;
  if (a.http_only) sent.httpOnly = true;
  const ss = String(a.same_site ?? '').toLowerCase();
  if (ss === 'none' || ss === 'lax' || ss === 'strict') sent.sameSite = ss;
  if (typeof a.max_age === 'number') sent.maxAge = a.max_age;
  const ex = ms(a.expires);
  if (ex !== undefined) sent.expires = Math.floor(ex / 1000);
  if (a.partitioned) sent.partitioned = true;
  const r: ProvenanceRecord = { at, name: w.name, host: w.host.toLowerCase(), path: (w.path ?? '/').split('?')[0] || '/', sent };
  if (w.effect === 'changed' || w.effect === 'stripped') r.effect = w.effect;
  if (w.rule) r.rule = w.rule;
  if (w.list_id) r.listId = w.list_id;
  if (w.list_name) r.listName = w.list_name;
  if (typeof w.line === 'number') r.line = w.line;
  return r;
}

const isDisabled = (v: unknown): boolean =>
  v === 'disabled' || (typeof v === 'object' && v !== null && ((v as any).enabled === false || (v as any).status === 'disabled' || (v as any).disabled === true));

/**
 * `GET /ext/cookies/provenance?since&host` for the bridge session `sid` (header `X-Argus-Session`,
 * the same auth as `/ext/log`). The server answers `disabled` while the setting is off; a proxy
 * without the route answers 404. Both come back as `{ enabled: false }`.
 */
export async function fetchProvenance(s: Settings, sid: string, o: { since?: number; host?: string } = {}): Promise<Provenance> {
  if (!sid) return { enabled: false, reason: 'no-session' };
  const q = new URLSearchParams();
  q.set('since', String(o.since ?? 0));
  if (o.host) q.set('host', o.host);
  const r = await call<unknown>(s, 'GET', `/ext/cookies/provenance?${q}`, undefined, { headers: { 'X-Argus-Session': sid } });
  if (!r.ok) return { enabled: false, reason: r.status === 404 ? 'disabled' : r.scope ? 'scope' : 'unavailable' };
  if (isDisabled(r.value)) return { enabled: false, reason: 'disabled' };
  const list = Array.isArray(r.value) ? r.value : ((r.value as { records?: unknown[] })?.records ?? []);
  return { enabled: true, records: (list as Wire[]).map(parseRecord).filter((x): x is ProvenanceRecord => !!x) };
}

/** RFC 6265 default path of a request path. */
export function defaultPath(p: string): string {
  if (!p.startsWith('/')) return '/';
  const i = p.lastIndexOf('/');
  return i <= 0 ? '/' : p.slice(0, i);
}

const recHost = (r: ProvenanceRecord): string => (r.sent.domain ?? r.host).replace(/^\./, '').toLowerCase();
const recPath = (r: ProvenanceRecord): string => (r.sent.path?.startsWith('/') ? r.sent.path : defaultPath(r.path));
/** Host-only and domain cookies of one name, host and path are different cookies. */
const matchKey = (name: string, host: string, path: string, hostOnly: boolean): string => JSON.stringify([name, host, path, hostOnly]);
const recKey = (r: ProvenanceRecord): string => matchKey(r.name, recHost(r), recPath(r), !r.sent.domain);

export interface SentStored { label: string; sent: string; stored: string }

export interface ProvInfo {
  /** The setting response was seen; false means "not seen in transit". */
  seen: boolean;
  record?: ProvenanceRecord;
  effect?: ProvenanceEffect;
  diffs: SentStored[];
}

/** A cookie a rule removed before the browser stored it; it exists only in provenance. */
export interface StrippedCookie { key: string; record: ProvenanceRecord; domain: string; path: string }

export function humanSeconds(s: number): string {
  const n = Math.max(0, Math.round(s));
  const unit = (v: number, w: string) => `${v} ${w}${v === 1 ? '' : 's'}`;
  if (n < 60) return unit(n, 'second');
  if (n < 3600) return unit(Math.round(n / 60), 'minute');
  if (n < 86400) return unit(Math.round(n / 3600), 'hour');
  const d = Math.round(n / 86400);
  if (d < 365) return unit(d, 'day');
  return unit(Math.round(d / 365), 'year');
}

function lifetimeDiff(rec: ProvenanceRecord, c: Cookie): SentStored | undefined {
  const at = rec.at / 1000;
  const sentExp = rec.sent.maxAge !== undefined ? at + rec.sent.maxAge : rec.sent.expires;
  const storedExp = c.session ? undefined : c.expirationDate;
  if (sentExp === undefined && storedExp === undefined) return undefined;
  if (sentExp === undefined) return { label: 'Lifetime', sent: 'session', stored: `extended to ${humanSeconds(storedExp! - at)}` };
  const sentTxt = humanSeconds(sentExp - at);
  if (storedExp === undefined) return { label: 'Lifetime', sent: sentTxt, stored: 'session only' };
  if (Math.abs(storedExp - sentExp) <= 60) return undefined;
  const storedTxt = humanSeconds(storedExp - at);
  if (storedTxt === sentTxt) return undefined;
  return { label: 'Lifetime', sent: sentTxt, stored: storedExp < sentExp ? `capped to ${storedTxt}` : `extended to ${storedTxt}` };
}

const SS: Record<string, string> = { none: 'None', lax: 'Lax', strict: 'Strict', no_restriction: 'None', unspecified: 'Unspecified' };

/** The attributes as sent against as stored now; only those that differ. */
export function sentVsStored(rec: ProvenanceRecord, c: Cookie): SentStored[] {
  const out: SentStored[] = [];
  const life = lifetimeDiff(rec, c);
  if (life) out.push(life);
  if (rec.sent.sameSite && SS[rec.sent.sameSite] !== SS[c.sameSite]) out.push({ label: 'SameSite', sent: SS[rec.sent.sameSite]!, stored: SS[c.sameSite]! });
  if (rec.sent.secure && !c.secure) out.push({ label: 'Secure', sent: 'set', stored: 'not set' });
  if (rec.sent.httpOnly && !c.httpOnly) out.push({ label: 'HttpOnly', sent: 'set', stored: 'not set' });
  return out;
}

export interface Joined {
  info: Map<string, ProvInfo>;
  stripped: StrippedCookie[];
}

/**
 * Joins the browser's cookies with the proxy's records by name, domain and path. A cookie with no
 * record is "not seen in transit". Removed-by-rule records whose cookie is not in the browser come
 * back as `stripped` rows. Values never take part: records have none.
 */
export function joinProvenance(cookies: Cookie[], records: ProvenanceRecord[]): Joined {
  const latest = new Map<string, ProvenanceRecord>();
  const strippedLatest = new Map<string, ProvenanceRecord>();
  for (const r of [...records].sort((a, b) => a.at - b.at)) (r.effect === 'stripped' ? strippedLatest : latest).set(recKey(r), r);
  const info = new Map<string, ProvInfo>();
  const present = new Set<string>();
  for (const c of cookies) {
    const k = matchKey(c.name, hostOfCookie(c), c.path, c.hostOnly);
    present.add(k);
    const rec = latest.get(k);
    info.set(identityKey(c), rec ? { seen: true, record: rec, ...(rec.effect ? { effect: rec.effect } : {}), diffs: sentVsStored(rec, c) } : { seen: false, diffs: [] });
  }
  const stripped: StrippedCookie[] = [];
  for (const [k, r] of strippedLatest) {
    const later = latest.get(k);
    if (present.has(k) || (later && later.at > r.at)) continue;
    stripped.push({ key: k, record: r, domain: recHost(r), path: recPath(r) });
  }
  stripped.sort((a, b) => b.record.at - a.record.at);
  return { info, stripped };
}

export const sourceLabel = (p: ProvInfo | undefined): string => (p?.seen && p.record ? `Response from ${p.record.host}` : 'Not seen in transit');
export const NOT_SEEN_HINT = 'Set by a page script, before capture was on, or older than the retained window';
export const OFF_LINE = 'Turn on cookie provenance in Argus Settings to see where cookies come from';
export const HISTORY_NOTE = 'History covers recent activity in this browser session.';

/** `Today 12:02:11`, `Yesterday 21:12:03` or an ISO date and time. */
export function whenText(at: number, now = Date.now()): string {
  const d = new Date(at), n = new Date(now);
  const p = (v: number) => String(v).padStart(2, '0');
  const t = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  const day = (x: Date) => Math.floor(new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime() / 86400000);
  const diff = day(n) - day(d);
  if (diff === 0) return `Today ${t}`;
  if (diff === 1) return `Yesterday ${t}`;
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${t}`;
}

/** The label an activity entry shows: the response that set it, or why there is none. */
export function activitySource(kind: string, name: string, host: string, at: number, records: ProvenanceRecord[]): string {
  if (kind === 'expired') return 'Browser (expired)';
  if (kind === 'evicted') return 'Browser (storage limit)';
  if (kind === 'removed') return 'Page, extension or you';
  const hit = records.filter((r) => r.name === name && r.effect !== 'stripped' && recHost(r) === host && Math.abs(r.at - at) <= 10_000).sort((a, b) => Math.abs(a.at - at) - Math.abs(b.at - at))[0];
  return hit ? `Response from ${hit.host}` : 'Not seen in transit';
}

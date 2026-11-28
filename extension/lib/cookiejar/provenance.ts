import type { components } from '../api-schema';
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

/**
 * `set`: passed through unchanged. `changed`: a `$cookie` rule changed attributes. `stripped`: a rule
 * removed the `Set-Cookie`. `blocked_send`: a rule kept the cookie out of a request.
 */
export type ProvenanceEffect = 'set' | 'changed' | 'stripped' | 'blocked_send';

/** The rule behind a record or one change, and its list. */
export interface RuleRef { rule: string; listId?: string; listName?: string; userRule?: boolean }

/**
 * One attribute a rule changed: `from` and `to` are the sent and the new value (absent: none); `by` is
 * the rule whose value is the one applied (a later rule can win over an earlier one, per attribute).
 */
export interface AttrChange { attr: 'max_age' | 'expires' | 'same_site'; from?: string; to?: string; by?: RuleRef }

/** What the proxy saw of one cookie in transit (`GET /ext/cookies/provenance`); there is never a value. */
export interface ProvenanceRecord {
  /** Position in the session's records. */
  seq: number;
  /** Milliseconds since the epoch. */
  at: number;
  name: string;
  /** Host and path (no query string) of the request the response answered. */
  host: string;
  path: string;
  /** Host of the page that made the request; empty when unknown. */
  pageHost: string;
  thirdParty?: boolean;
  sent: SentAttrs;
  effect: ProvenanceEffect;
  changes: AttrChange[];
  prefix?: '__Host-' | '__Secure-';
  prefixValid?: boolean;
  /** The rule that changed, removed or blocked the cookie. */
  rule?: string;
  listId?: string;
  listName?: string;
  userRule?: boolean;
}

export type Provenance =
  | { enabled: false; reason: 'disabled' | 'unavailable' | 'no-session' | 'scope' }
  | { enabled: true; records: ProvenanceRecord[]; nextSince: number };

type Wire = components['schemas']['ExtCookieRecord'];
type WireAttrs = components['schemas']['ExtCookieAttrs'];

const EFFECTS: readonly string[] = ['set', 'changed', 'stripped', 'blocked_send'];
const CHANGE_ATTRS: readonly string[] = ['max_age', 'expires', 'same_site'];
const str = (v: unknown): string | undefined => (typeof v === 'string' && v ? v : undefined);

function parseAttrs(a: Partial<WireAttrs> | null | undefined): SentAttrs {
  const o: SentAttrs = {};
  if (!a) return o;
  if (a.domain) o.domain = a.domain;
  if (a.path) o.path = a.path;
  if (a.secure) o.secure = true;
  if (a.http_only) o.httpOnly = true;
  if (a.same_site === 'none' || a.same_site === 'lax' || a.same_site === 'strict') o.sameSite = a.same_site;
  if (typeof a.max_age === 'number') o.maxAge = a.max_age;
  if (typeof a.expires === 'number') o.expires = a.expires;
  if (a.partitioned) o.partitioned = true;
  return o;
}

/** A wire record as the page uses it; `undefined` for one that is malformed. */
export function parseRecord(w: Wire): ProvenanceRecord | undefined {
  const at = typeof w.time === 'string' ? Date.parse(w.time) : NaN;
  if (typeof w.seq !== 'number' || Number.isNaN(at) || typeof w.name !== 'string' || !w.host || !EFFECTS.includes(w.effect)) return undefined;
  const r: ProvenanceRecord = {
    seq: w.seq, at, name: w.name, host: w.host.toLowerCase(), path: (w.path ?? '/').split('?')[0] || '/', pageHost: (w.page_host ?? '').toLowerCase(),
    sent: parseAttrs(w.attrs), effect: w.effect as ProvenanceEffect,
    changes: (w.changes ?? []).filter((c) => CHANGE_ATTRS.includes(c.attr)).map((c) => ({
      attr: c.attr as AttrChange['attr'], ...(str(c.from) ? { from: c.from! } : {}), ...(str(c.to) ? { to: c.to! } : {}),
      ...(str(c.rule) ? { by: { rule: c.rule!, ...(str(c.list_id) ? { listId: c.list_id! } : {}), ...(str(c.list_name) ? { listName: c.list_name! } : {}), ...(c.user_rule ? { userRule: true } : {}) } } : {}),
    })),
  };
  if (typeof w.third_party === 'boolean') r.thirdParty = w.third_party;
  if (w.prefix === '__Host-' || w.prefix === '__Secure-') r.prefix = w.prefix;
  if (typeof w.prefix_valid === 'boolean') r.prefixValid = w.prefix_valid;
  if (str(w.rule)) r.rule = w.rule!;
  if (str(w.list_id)) r.listId = w.list_id!;
  if (str(w.list_name)) r.listName = w.list_name!;
  if (w.user_rule) r.userRule = true;
  return r;
}

/** Most pages one fetch follows (the server returns up to 500 records a page). */
const MAX_PAGES = 20;

/**
 * Records after the sequence `since` for the bridge session `sid` (header `X-Argus-Session`, the same
 * auth as `/ext/log`), following the server's pages. The server answers `{ enabled: false }` while the
 * setting is off; a proxy without the route answers 404. Both come back as `{ enabled: false }`.
 */
export async function fetchProvenance(s: Settings, sid: string, o: { since?: number; host?: string } = {}): Promise<Provenance> {
  if (!sid) return { enabled: false, reason: 'no-session' };
  const records: ProvenanceRecord[] = [];
  let since = o.since ?? 0;
  for (let page = 0; page < MAX_PAGES; page++) {
    const q = new URLSearchParams({ since: String(since) });
    if (o.host) q.set('host', o.host);
    const r = await call<components['schemas']['ExtCookieProvenance']>(s, 'GET', `/ext/cookies/provenance?${q}`, undefined, { headers: { 'X-Argus-Session': sid } });
    if (!r.ok) return { enabled: false, reason: r.status === 404 ? 'disabled' : r.scope ? 'scope' : 'unavailable' };
    const v = r.value;
    if (!v || typeof v !== 'object' || typeof v.enabled !== 'boolean') return { enabled: false, reason: 'unavailable' };
    if (!v.enabled) return { enabled: false, reason: 'disabled' };
    if (!Array.isArray(v.records)) return { enabled: false, reason: 'unavailable' };
    for (const w of v.records) { const p = parseRecord(w); if (p) records.push(p); }
    since = v.next_since;
    if (!v.more) break;
  }
  return { enabled: true, records, nextSince: since };
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
  /** Set when a rule changed or removed the cookie. */
  effect?: 'changed' | 'stripped';
  diffs: SentStored[];
  /** Requests a rule kept this cookie out of, oldest first. */
  blocked?: ProvenanceRecord[];
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
  const blockedByName = new Map<string, ProvenanceRecord[]>();
  for (const r of [...records].sort((a, b) => a.seq - b.seq)) {
    if (r.effect === 'blocked_send') blockedByName.set(r.name, [...(blockedByName.get(r.name) ?? []), r]);
    else (r.effect === 'stripped' ? strippedLatest : latest).set(recKey(r), r);
  }
  const info = new Map<string, ProvInfo>();
  const present = new Set<string>();
  for (const c of cookies) {
    const k = matchKey(c.name, hostOfCookie(c), c.path, c.hostOnly);
    present.add(k);
    const rec = latest.get(k);
    const host = hostOfCookie(c);
    const blocked = (blockedByName.get(c.name) ?? []).filter((b) => (c.hostOnly ? b.host === host : b.host === host || b.host.endsWith(`.${host}`)));
    const more = blocked.length ? { blocked } : {};
    info.set(identityKey(c), rec ? { seen: true, record: rec, ...(rec.effect === 'changed' ? { effect: 'changed' as const } : {}), diffs: sentVsStored(rec, c), ...more } : { seen: false, diffs: [], ...more });
  }
  const stripped: StrippedCookie[] = [];
  for (const [k, r] of strippedLatest) {
    const later = latest.get(k);
    if (present.has(k) || (later && later.seq > r.seq)) continue;
    stripped.push({ key: k, record: r, domain: recHost(r), path: recPath(r) });
  }
  stripped.sort((a, b) => b.record.at - a.record.at);
  return { info, stripped };
}

export const sourceLabel = (p: ProvInfo | undefined): string => (p?.seen && p.record ? `Response from ${p.record.host}` : 'Not seen in transit');
export const NOT_SEEN_HINT = 'Set by a page script, before capture was on, or older than the retained window';
export const OFF_LINE = 'Turn on cookie provenance in Argus Settings to see where cookies come from';
export const HISTORY_NOTE = 'History covers recent activity in this browser session.';

/** The web UI page of a rule in its list: the list's page with the rule text as the search. */
export function ruleUrl(argusUrl: string, listId: string, rule: string): string {
  return `${argusUrl}/filters/${encodeURIComponent(listId)}?q=${encodeURIComponent(rule)}`;
}

/** Changes grouped by the rule that made them, in order of first appearance. */
export function changesByRule(changes: AttrChange[], fallback?: RuleRef): { by?: RuleRef; changes: AttrChange[] }[] {
  const groups: { by?: RuleRef; changes: AttrChange[] }[] = [];
  for (const c of changes) {
    const by = c.by ?? fallback;
    const g = groups.find((x) => x.by?.rule === by?.rule && x.by?.listId === by?.listId);
    if (g) g.changes.push(c); else groups.push({ ...(by ? { by } : {}), changes: [c] });
  }
  return groups;
}

/** One rule change as a line: `Max-Age: 1 year → 1 hour`. */
export function changeText(c: AttrChange): string {
  const none = c.attr === 'expires' ? 'removed' : 'none';
  const show = (v: string | undefined): string => {
    if (v === undefined) return none;
    if (c.attr === 'max_age') return humanSeconds(Number(v));
    if (c.attr === 'expires') return new Date(Number(v) * 1000).toISOString().slice(0, 10);
    return SS[v] ?? v;
  };
  return `${c.attr === 'max_age' ? 'Max-Age' : c.attr === 'expires' ? 'Expires' : 'SameSite'}: ${show(c.from)} → ${show(c.to)}`;
}

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
  const hit = records.filter((r) => r.name === name && (r.effect === 'set' || r.effect === 'changed') && recHost(r) === host && Math.abs(r.at - at) <= 10_000).sort((a, b) => Math.abs(a.at - at) - Math.abs(b.at - at))[0];
  return hit ? `Response from ${hit.host}` : 'Not seen in transit';
}

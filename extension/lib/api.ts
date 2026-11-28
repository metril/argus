import type { components } from './api-schema';

export type CertInfo = components['schemas']['CertInfo'];

export interface Settings { argusUrl: string; token: string; tokenId?: string; user?: string; since?: string }

export type ErrorKind = 'badCredentials' | 'forbidden' | 'unreachable' | 'noHostPermission' | 'sessionExpired' | 'rateLimited';

export type Lookup =
  | { kind: 'unconfigured' }
  | { kind: 'unseen' }
  | { kind: 'error'; error: ErrorKind; refused?: boolean }
  | { kind: 'ok'; cert: CertInfo };

export async function getSettings(): Promise<Settings> {
  const r = await browser.storage.local.get(['argusUrl', 'token', 'tokenId', 'user', 'since']);
  return {
    argusUrl: String(r.argusUrl ?? '').replace(/\/+$/, ''),
    token: String(r.token ?? ''),
    ...(r.tokenId ? { tokenId: String(r.tokenId) } : {}),
    ...(r.user ? { user: String(r.user) } : {}),
    ...(r.since ? { since: String(r.since) } : {}),
  };
}

/** The proxy answered instead of Argus (the destination was refused): not an auth problem. */
export const isRefused = (res: Response) => res.headers.get('x-adblock') === 'destination-refused';
const isJson = (res: Response) => (res.headers.get('content-type') ?? '').includes('json');

/** Maps an API response to an error kind; null when it is not an error. */
export function errorForResponse(res: Response): { error: ErrorKind; refused?: boolean } | null {
  if (res.ok) return null;
  if (isRefused(res)) return { error: 'unreachable', refused: true };
  if (res.status === 401) return { error: 'sessionExpired' };
  if (res.status === 403) return isJson(res) ? { error: 'forbidden' } : { error: 'unreachable' };
  if (res.status === 429) return { error: 'rateLimited' };
  return { error: 'unreachable' };
}

/** A failed fetch: a revoked host permission looks like a network error, so check it first. */
export async function networkError(argusUrl: string): Promise<{ error: ErrorKind }> {
  try {
    const origin = new URL(argusUrl).origin + '/*';
    if (!(await browser.permissions.contains({ origins: [origin] }))) return { error: 'noHostPermission' };
  } catch { /* fall through */ }
  return { error: 'unreachable' };
}

export async function fetchCert(s: Settings, host: string): Promise<Lookup> {
  if (!s.argusUrl || !s.token) return { kind: 'unconfigured' };
  try {
    const res = await fetch(`${s.argusUrl}/api/v1/certs/by-host/${encodeURIComponent(host)}`, {
      headers: { Authorization: `Bearer ${s.token}` },
    });
    if (res.status === 404 && !isRefused(res)) return { kind: 'unseen' };
    const e = errorForResponse(res);
    if (e) return { kind: 'error', ...e };
    return { kind: 'ok', cert: (await res.json()) as CertInfo };
  } catch {
    return { kind: 'error', ...(await networkError(s.argusUrl)) };
  }
}

const TTL_MS = 60_000;
const cache = new Map<string, { at: number; v: Lookup }>();

export async function cachedLookup(host: string): Promise<Lookup> {
  const hit = cache.get(host);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.v;
  const v = await fetchCert(await getSettings(), host);
  if (v.kind !== 'error' || v.error === 'sessionExpired') cache.set(host, { at: Date.now(), v });
  return v;
}

export function clearCache() { cache.clear(); }

export function hostOf(url?: string): string | null {
  try {
    const u = new URL(url ?? '');
    // `host` keeps an explicit port (the lookup is per host:port) and IPv6 brackets.
    return u.protocol === 'https:' ? u.host : null;
  } catch { return null; }
}

export const CATEGORIES = ['ads', 'trackers', 'social', 'annoyances', 'security', 'other'] as const;
export type Category = (typeof CATEGORIES)[number];
export type CategoryCounts = Record<Category, number>;
export const CATEGORY_LABELS: Record<Category, string> = {
  ads: 'Ads', trackers: 'Trackers', social: 'Social', annoyances: 'Annoyances', security: 'Malware / Security', other: 'Other',
};

export type FilterStats = components['schemas']['FilterStatsResponse'] & {
  lifetime_blocked?: number; lifetime_total?: number; lifetime_by_category?: Partial<CategoryCounts>;
};
export type SeriesRange = 'd7' | 'd30' | 'm12';
export interface SeriesPoint { ts: number; requests: number; blocked: number; by_category?: Partial<CategoryCounts> }
export interface Series { range: string; bucket_secs: number; points: SeriesPoint[] }

/** One request the proxy logged for this extension session (`GET /ext/log`). */
export type Outcome = 'blocked' | 'allowed' | 'redirected' | 'modified' | 'aborted';
export interface LogEntry {
  seq: number; time: string; url: string; method: string; type: string; third_party: boolean | null;
  outcome: Outcome; rule: string | null; list_id: string | null; list_name: string | null; user_rule: boolean; source_host: string;
}

/** Result of an authenticated JSON call; `scope` means the token lacks a scope (an older extension token). */
/** `message` is the server's error text (the body of a JSON error), when it sent one. */
export type Call<T> = { ok: true; value: T } | { ok: false; scope: boolean; status: number; message?: string; restricted?: true };

export async function call<T>(s: Settings, method: string, path: string, signal?: AbortSignal, extra?: { headers?: Record<string, string>; body?: unknown }): Promise<Call<T>> {
  if (!s.argusUrl || !s.token) return { ok: false, scope: false, status: 0 };
  try {
    const headers: Record<string, string> = { Authorization: `Bearer ${s.token}`, ...extra?.headers };
    if (extra?.body !== undefined) headers['Content-Type'] = 'application/json';
    const res = await fetch(`${s.argusUrl}/api/v1${path}`, {
      method, headers, ...(extra?.body !== undefined ? { body: JSON.stringify(extra.body) } : {}), ...(signal ? { signal } : {}),
    });
    if (res.ok) return { ok: true, value: (await res.json()) as T };
    let scope = false;
    let restricted = false;
    let message: string | undefined;
    if (isJson(res) && !isRefused(res)) {
      // Read the body once: the envelope carries the scope code and the reason of a 400.
      try {
        const err = (await res.json())?.error;
        scope = res.status === 403 && err?.code === 'insufficient_scope';
        restricted = res.status === 403 && err?.code === 'profile_restricted';
        if (typeof err?.message === 'string' && err.message) message = err.message.slice(0, 300);
      } catch { /* not the envelope */ }
    }
    return { ok: false, scope, status: res.status, ...(message ? { message } : {}), ...(restricted ? { restricted: true as const } : {}) };
  } catch {
    return { ok: false, scope: false, status: 0 };
  }
}

export const fetchFilterStats = (s: Settings, signal?: AbortSignal) => call<FilterStats>(s, 'GET', '/stats/filter', signal);
export const fetchRecentBlocked = (s: Settings) => call<{ entries: { url: string; time: string; source_host?: string | null }[] }>(s, 'GET', '/stats/blocked/recent?limit=200');
const siteUrl = (site: string) => `/rules/site-exceptions/${encodeURIComponent(site)}`;
export const getSiteState = (s: Settings, site: string, signal?: AbortSignal) => call<{ site: string; disabled: boolean }>(s, 'GET', siteUrl(site), signal);
/** `off` switches ad blocking off for the site (PUT), otherwise back on (DELETE). */
export const setSiteOff = (s: Settings, site: string, off: boolean) => call<{ sites: string[] }>(s, off ? 'PUT' : 'DELETE', siteUrl(site));

/** Whether Argus leaves a host undecrypted, and why (`GET /bypass/sites/{host}`). */
export type SiteBypass = components['schemas']['SiteBypassState'];
const bypassSiteUrl = (host: string) => `/bypass/sites/${encodeURIComponent(host)}`;
/** A 403 with `scope: true` means the token predates `bypass:site`: offer to sign in again. */
export const getSiteBypass = (s: Settings, host: string, signal?: AbortSignal) => call<SiteBypass>(s, 'GET', bypassSiteUrl(host), signal);
/** Stop decrypting exactly this host; idempotent. */
export const setSiteBypass = (s: Settings, host: string) => call<SiteBypass>(s, 'PUT', bypassSiteUrl(host));
/** Decrypt the host again; only the extension's own entry is removed (409 for any other source). */
export const clearSiteBypass = (s: Settings, host: string) => call<SiteBypass>(s, 'DELETE', bypassSiteUrl(host));

export const fetchTimeseries = (s: Settings, range: SeriesRange, signal?: AbortSignal) => call<Series>(s, 'GET', `/stats/timeseries?range=${range}`, signal);

/** The proxy's log of this session's requests after `since`; `sid` is the bridge session. Unavailable (old proxy, no session) is `ok: false`. */
export const fetchExtLog = (s: Settings, sid: string, since: number) =>
  call<{ next: number; entries: LogEntry[] }>(s, 'GET', `/ext/log?since=${since}`, undefined, { headers: { 'X-Argus-Session': sid } });
export const postExtRule = (s: Settings, op: 'add' | 'remove', rule: string) =>
  call<{ rule_count: number; changed: boolean }>(s, 'POST', '/ext/rules', undefined, { body: { op, rule } });
export const fetchSiteRules = (s: Settings, site: string) =>
  call<{ site: string; rules: { rule: string; exclusive: boolean }[] }>(s, 'GET', `/ext/rules?site=${encodeURIComponent(site)}`);

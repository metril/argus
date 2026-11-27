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

export type FilterStats = components['schemas']['FilterStatsResponse'];

/** Result of an authenticated JSON call; `scope` means the token lacks a scope (an older extension token). */
export type Call<T> = { ok: true; value: T } | { ok: false; scope: boolean; status: number };

async function call<T>(s: Settings, method: string, path: string, signal?: AbortSignal): Promise<Call<T>> {
  if (!s.argusUrl || !s.token) return { ok: false, scope: false, status: 0 };
  try {
    const res = await fetch(`${s.argusUrl}/api/v1${path}`, { method, headers: { Authorization: `Bearer ${s.token}` }, ...(signal ? { signal } : {}) });
    if (res.ok) return { ok: true, value: (await res.json()) as T };
    let scope = false;
    if (res.status === 403 && isJson(res)) {
      try { scope = (await res.json())?.error?.code === 'insufficient_scope'; } catch { /* not the envelope */ }
    }
    return { ok: false, scope, status: res.status };
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


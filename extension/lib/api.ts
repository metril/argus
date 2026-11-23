import type { components } from './api-schema';

export type CertInfo = components['schemas']['CertInfo'];

export interface Settings { argusUrl: string; token: string }

export type Lookup =
  | { kind: 'unconfigured' }
  | { kind: 'auth'; status: number }
  | { kind: 'unseen' }
  | { kind: 'error'; message: string }
  | { kind: 'ok'; cert: CertInfo };

export async function getSettings(): Promise<Settings> {
  const r = await browser.storage.local.get(['argusUrl', 'token']);
  return { argusUrl: String(r.argusUrl ?? '').replace(/\/+$/, ''), token: String(r.token ?? '') };
}

export async function fetchCert(s: Settings, host: string): Promise<Lookup> {
  if (!s.argusUrl || !s.token) return { kind: 'unconfigured' };
  try {
    const res = await fetch(`${s.argusUrl}/api/v1/certs/by-host/${encodeURIComponent(host)}`, {
      headers: { Authorization: `Bearer ${s.token}` },
    });
    if (res.status === 401 || res.status === 403) return { kind: 'auth', status: res.status };
    if (res.status === 404) return { kind: 'unseen' };
    if (!res.ok) return { kind: 'error', message: `HTTP ${res.status}` };
    return { kind: 'ok', cert: (await res.json()) as CertInfo };
  } catch (e) {
    return { kind: 'error', message: e instanceof Error ? e.message : String(e) };
  }
}

const TTL_MS = 60_000;
const cache = new Map<string, { at: number; v: Lookup }>();

export async function cachedLookup(host: string): Promise<Lookup> {
  const hit = cache.get(host);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.v;
  const v = await fetchCert(await getSettings(), host);
  if (v.kind !== 'error') cache.set(host, { at: Date.now(), v });
  return v;
}

export function clearCache() { cache.clear(); }

export function hostOf(url?: string): string | null {
  try {
    const u = new URL(url ?? '');
    // `host` keeps an explicit port (the lookup is per host:port) and IPv6 brackets.
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.host : null;
  } catch { return null; }
}

export type Interception = 'intercepted' | 'direct' | 'unknown';

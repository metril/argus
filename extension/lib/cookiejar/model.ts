import { getDomain } from 'tldts';

export type SameSite = 'unspecified' | 'no_restriction' | 'lax' | 'strict';

export interface PartitionKey {
  /** The top-level site the cookie is partitioned under, e.g. `https://example.com`. */
  topLevelSite: string;
  /** Chrome only; undefined where the browser does not report it. */
  hasCrossSiteAncestor?: boolean;
}

/** One cookie, the same shape on Chrome and Firefox. */
export interface Cookie {
  storeId: string;
  partitionKey?: PartitionKey;
  /** Firefox first-party isolation; always `''` on Chrome. */
  firstPartyDomain: string;
  /** As the browser reports it: a leading dot for domain cookies, none for host-only ones. */
  domain: string;
  hostOnly: boolean;
  path: string;
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: SameSite;
  session: boolean;
  /** Seconds since the epoch; absent for session cookies. */
  expirationDate?: number;
  /** Bytes of name plus value. */
  size: number;
}

export const SAME_SITES: SameSite[] = ['unspecified', 'no_restriction', 'lax', 'strict'];

const enc = new TextEncoder();
export const byteSize = (name: string, value: string): number => enc.encode(name).length + enc.encode(value).length;

export function normalizeSameSite(v: unknown): SameSite {
  const s = String(v ?? '').toLowerCase().replace(/[\s-]/g, '_');
  if (s === 'no_restriction' || s === 'none') return 'no_restriction';
  if (s === 'lax' || s === 'strict') return s;
  return 'unspecified';
}

export function normalizePartition(p: unknown): PartitionKey | undefined {
  if (!p) return undefined;
  if (typeof p === 'string') return p ? { topLevelSite: p } : undefined;
  const o = p as { topLevelSite?: unknown; sourceOrigin?: unknown; hasCrossSiteAncestor?: unknown };
  const site = typeof o.topLevelSite === 'string' ? o.topLevelSite : typeof o.sourceOrigin === 'string' ? o.sourceOrigin : '';
  if (!site) return undefined;
  return typeof o.hasCrossSiteAncestor === 'boolean' ? { topLevelSite: site, hasCrossSiteAncestor: o.hasCrossSiteAncestor } : { topLevelSite: site };
}

/** Builds a complete cookie from a partial one (defaults: host-only session cookie on `/`). */
export function makeCookie(p: Partial<Cookie> & { name: string; domain: string }): Cookie {
  const value = p.value ?? '';
  const session = p.session ?? p.expirationDate === undefined;
  const c: Cookie = {
    storeId: p.storeId ?? '',
    firstPartyDomain: p.firstPartyDomain ?? '',
    domain: p.domain,
    hostOnly: p.hostOnly ?? !p.domain.startsWith('.'),
    path: p.path || '/',
    name: p.name,
    value,
    secure: !!p.secure,
    httpOnly: !!p.httpOnly,
    sameSite: p.sameSite ?? 'unspecified',
    session,
    size: byteSize(p.name, value),
  };
  const pk = normalizePartition(p.partitionKey);
  if (pk) c.partitionKey = pk;
  if (!session && p.expirationDate !== undefined) c.expirationDate = p.expirationDate;
  return c;
}

/** Normalises what `browser.cookies` returns on either browser. */
export function fromBrowser(raw: any): Cookie {
  const expirationDate = typeof raw.expirationDate === 'number' ? raw.expirationDate : undefined;
  const domain = String(raw.domain ?? '');
  return makeCookie({
    storeId: String(raw.storeId ?? ''),
    firstPartyDomain: typeof raw.firstPartyDomain === 'string' ? raw.firstPartyDomain : '',
    domain,
    hostOnly: typeof raw.hostOnly === 'boolean' ? raw.hostOnly : !domain.startsWith('.'),
    path: raw.path,
    name: String(raw.name ?? ''),
    value: String(raw.value ?? ''),
    secure: raw.secure,
    httpOnly: raw.httpOnly,
    sameSite: normalizeSameSite(raw.sameSite),
    session: typeof raw.session === 'boolean' ? raw.session : expirationDate === undefined,
    ...(expirationDate !== undefined ? { expirationDate } : {}),
    partitionKey: raw.partitionKey,
  });
}

/** The cookie's host without the leading dot. */
export const hostOfCookie = (c: { domain: string }): string => c.domain.replace(/^\./, '').toLowerCase();

/** A stable identity: store, partition (top-level site and cross-site ancestor; unknown counts as false), first-party domain, domain, hostOnly, path, name. */
export function identityKey(c: Pick<Cookie, 'storeId' | 'partitionKey' | 'firstPartyDomain' | 'domain' | 'hostOnly' | 'path' | 'name'>): string {
  return JSON.stringify([c.storeId, c.partitionKey ? [c.partitionKey.topLevelSite, c.partitionKey.hasCrossSiteAncestor ?? false] : '', c.firstPartyDomain, hostOfCookie(c), c.hostOnly, c.path, c.name]);
}

/** The URL that addresses this cookie for `cookies.set/remove/get`. */
export function cookieUrl(c: Pick<Cookie, 'domain' | 'path' | 'secure'>): string {
  return `${c.secure ? 'https' : 'http'}://${hostOfCookie(c)}${c.path.startsWith('/') ? c.path : '/' + c.path}`;
}

/** The registrable domain of a host or URL; the host itself for IPs, localhost and the like. */
export function siteOf(hostOrUrl: string): string {
  let h = hostOrUrl.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(h)) { try { h = new URL(h).hostname; } catch { /* keep */ } }
  h = h.replace(/^\./, '').replace(/^\[|\]$/g, '').toLowerCase();
  return getDomain(h) ?? h;
}

export const siteOfCookie = (c: Pick<Cookie, 'domain'>): string => siteOf(c.domain);

/** Whether `host` is `entry` or a subdomain of it. */
export const hostUnder = (host: string, entry: string): boolean => host === entry || host.endsWith('.' + entry);

export type Party = 'first' | 'third';

/** First party: the cookie's site is the page's site (same registrable domain). */
export function partyOf(c: Pick<Cookie, 'domain'>, pageSite: string): Party {
  return siteOfCookie(c) === siteOf(pageSite) ? 'first' : 'third';
}
export const isFirstParty = (c: Pick<Cookie, 'domain'>, pageSite: string): boolean => partyOf(c, pageSite) === 'first';

/** Domain-match + path-match + secure, as a request to `url` would send it. */
export function matchesUrl(c: Pick<Cookie, 'domain' | 'hostOnly' | 'path' | 'secure'>, url: string): boolean {
  let u: URL;
  try { u = new URL(url); } catch { return false; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
  const host = u.hostname.toLowerCase();
  const ch = hostOfCookie(c);
  if (c.hostOnly ? host !== ch : !hostUnder(host, ch)) return false;
  if (c.secure && u.protocol !== 'https:') return false;
  const p = u.pathname || '/';
  const cp = c.path || '/';
  return p === cp || (p.startsWith(cp) && (cp.endsWith('/') || p[cp.length] === '/'));
}

export interface Caps {
  /** Firefox: details carry `firstPartyDomain`. */
  firstPartyDomain: boolean;
}

/** Details for `cookies.set`; the cookie's own store, partition and first-party domain go back unchanged. */
export function toSetDetails(c: Cookie, caps: Caps): Record<string, unknown> {
  const d: Record<string, unknown> = {
    url: cookieUrl(c), name: c.name, value: c.value, path: c.path, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite,
    storeId: c.storeId,
  };
  if (!c.hostOnly) d.domain = c.domain.startsWith('.') ? c.domain : '.' + c.domain;
  if (!c.session && c.expirationDate !== undefined) d.expirationDate = c.expirationDate;
  if (c.partitionKey) d.partitionKey = c.partitionKey.hasCrossSiteAncestor === undefined ? { topLevelSite: c.partitionKey.topLevelSite } : { ...c.partitionKey };
  // Chrome rejects the property outright, so only a browser that knows it gets it.
  if (caps.firstPartyDomain) d.firstPartyDomain = c.firstPartyDomain;
  return d;
}

/** Details for `cookies.remove` / `cookies.get`. */
export function toKeyDetails(c: Cookie, caps: Caps): Record<string, unknown> {
  const { url, name, storeId, partitionKey, firstPartyDomain } = toSetDetails(c, caps) as any;
  return { url, name, storeId, ...(partitionKey ? { partitionKey } : {}), ...(firstPartyDomain !== undefined ? { firstPartyDomain } : {}) };
}

/** Field names whose values differ between two cookies of the same identity. */
export function changedFields(a: Cookie, b: Cookie): string[] {
  const out: string[] = [];
  for (const k of ['value', 'secure', 'httpOnly', 'sameSite'] as const) if (a[k] !== b[k]) out.push(k);
  if (a.session !== b.session || (a.expirationDate ?? 0) !== (b.expirationDate ?? 0)) out.push('expires');
  return out;
}

import { makeCookie, normalizePartition, normalizeSameSite, type Cookie } from '../model';
import type { ParsedRow } from './types';

const bool = (v: unknown): boolean => v === true || (typeof v === 'string' && /^(true|1|yes|y)$/i.test(v.trim())) || v === 1;
const pick = (o: Record<string, unknown>, ...keys: string[]): unknown => {
  for (const k of keys) {
    const hit = Object.keys(o).find((x) => x.toLowerCase().replace(/[_\s-]/g, '') === k.toLowerCase());
    if (hit !== undefined && o[hit] !== undefined && o[hit] !== null && o[hit] !== '') return o[hit];
  }
  return undefined;
};

/** Seconds since the epoch from the many ways exporters write an expiry; undefined = session. */
export function parseExpiry(v: unknown): number | undefined {
  if (v === undefined || v === null || v === '') return undefined;
  let n: number;
  if (typeof v === 'number') n = v;
  else if (/^-?\d+(\.\d+)?$/.test(String(v).trim())) n = Number(v);
  else { const t = Date.parse(String(v)); if (Number.isNaN(t)) return undefined; return t / 1000; }
  if (!(n > 0)) return undefined;
  if (n > 1e14) n /= 1e6; // microseconds
  else if (n > 1e11) n /= 1e3; // milliseconds
  return n;
}

/** Domain and hostOnly agree: domain cookies carry the leading dot, host-only ones do not. */
export function fixDomain(domain: string, hostOnly: boolean): string {
  const bare = domain.trim().replace(/^\./, '');
  return hostOnly ? bare : '.' + bare;
}

/** Reads one object in any of the JSON-ish shapes (EditThisCookie, Cookie-Editor, Playwright, Puppeteer). */
export function fromLoose(o: unknown, row: number): ParsedRow {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return { row, error: 'This entry is not a cookie object.' };
  const r = o as Record<string, unknown>;
  const name = pick(r, 'name');
  if (typeof name !== 'string' || name === '') return { row, error: 'This cookie has no name.' };
  let domain = pick(r, 'domain', 'host', 'hostkey');
  if (typeof domain !== 'string' || domain === '') {
    const url = pick(r, 'url');
    try { domain = typeof url === 'string' ? new URL(url).hostname : undefined; } catch { domain = undefined; }
  }
  if (typeof domain !== 'string' || domain === '') return { row, error: 'This cookie has no domain.' };
  const hoRaw = pick(r, 'hostOnly');
  const hostOnly = hoRaw !== undefined ? bool(hoRaw) : !domain.startsWith('.');
  const expRaw = pick(r, 'expirationDate', 'expires', 'expiry', 'expiresutc', 'expirytime');
  const exp = bool(pick(r, 'session')) ? undefined : parseExpiry(expRaw);
  const valueRaw = pick(r, 'value');
  const pk = pick(r, 'partitionKey');
  const fpd = pick(r, 'firstPartyDomain');
  const store = pick(r, 'storeId');
  const cookie = makeCookie({
    name,
    value: valueRaw === undefined ? '' : String(valueRaw),
    domain: fixDomain(domain, hostOnly),
    hostOnly,
    path: typeof pick(r, 'path') === 'string' ? (pick(r, 'path') as string) : '/',
    secure: bool(pick(r, 'secure')),
    httpOnly: bool(pick(r, 'httpOnly')),
    sameSite: normalizeSameSite(pick(r, 'sameSite')),
    session: exp === undefined,
    ...(exp !== undefined ? { expirationDate: exp } : {}),
    ...(typeof store === 'string' ? { storeId: store } : {}),
    ...(typeof fpd === 'string' ? { firstPartyDomain: fpd } : {}),
    ...(normalizePartition(pk) ? { partitionKey: normalizePartition(pk)! } : {}),
  });
  return { row, cookie };
}

/** The cookie list of a JSON document: an array, or an object holding one (`cookies`). */
export function jsonCookies(text: string): { items: unknown[] } | { error: string } {
  let v: unknown;
  try { v = JSON.parse(text); } catch (e) { return { error: `This is not valid JSON: ${String((e as Error).message).slice(0, 80)}` }; }
  if (Array.isArray(v)) return { items: v };
  if (v && typeof v === 'object' && Array.isArray((v as { cookies?: unknown }).cookies)) return { items: (v as { cookies: unknown[] }).cookies };
  return { error: 'This JSON has no list of cookies.' };
}

export const expiryOrUndefined = (c: Cookie): number | undefined => (c.session ? undefined : c.expirationDate);

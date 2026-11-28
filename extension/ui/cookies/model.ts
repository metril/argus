import type { StoreInfo } from '../../lib/cookiejar/api';
import { hostOfCookie, identityKey, makeCookie, partyOf, siteOf, type Cookie, type SameSite } from '../../lib/cookiejar/model';
import type { ProvInfo, StrippedCookie } from '../../lib/cookiejar/provenance';
import type { ListedCookie } from './client';

/** One line of the cookie table: a browser cookie, or (read-only) one a rule removed before storage. */
export interface Row {
  key: string;
  c: ListedCookie;
  info?: ProvInfo | undefined;
  stripped?: StrippedCookie | undefined;
}

export type ChipKey = 'secure' | 'httponly' | 'session' | 'partitioned' | 'third' | 'stripped';
export const CHIPS: { k: ChipKey; l: string }[] = [
  { k: 'secure', l: 'Secure' }, { k: 'httponly', l: 'HttpOnly' }, { k: 'session', l: 'Session' },
  { k: 'partitioned', l: 'Partitioned' }, { k: 'third', l: 'Third-party' }, { k: 'stripped', l: 'Stripped by Argus' },
];

export interface Filters { q: string; chips: ReadonlySet<ChipKey>; store: string }
export const noFilters = (): Filters => ({ q: '', chips: new Set(), store: 'all' });

export function strippedRow(s: StrippedCookie): Row {
  const r = s.record;
  const c = makeCookie({
    name: r.name, domain: s.domain, path: s.path, storeId: '', secure: !!r.sent.secure, httpOnly: !!r.sent.httpOnly,
    sameSite: r.sent.sameSite === 'none' ? 'no_restriction' : (r.sent.sameSite ?? 'unspecified'),
  });
  return { key: `stripped:${s.key}:${r.at}`, c, stripped: s, info: { seen: true, record: r, effect: 'stripped', diffs: [] } };
}

export const rowOf = (c: ListedCookie, info?: ProvInfo): Row => ({ key: identityKey(c), c, info });

/** Whether a row passes the search, the store and the chips. `page` is the site of the tab that opened the page. */
export function matches(r: Row, f: Filters, page: string): boolean {
  const stripOnly = f.chips.has('stripped');
  if (stripOnly !== !!r.stripped) return false;
  const c = r.c;
  if (f.store !== 'all' && !r.stripped && c.storeId !== f.store) return false;
  if (f.q) {
    const q = f.q.toLowerCase();
    if (!(c.name + '\n' + c.domain + '\n' + c.value).toLowerCase().includes(q)) return false;
  }
  if (f.chips.has('secure') && !c.secure) return false;
  if (f.chips.has('httponly') && !c.httpOnly) return false;
  if (f.chips.has('session') && !c.session) return false;
  if (f.chips.has('partitioned') && !c.partitionKey) return false;
  if (f.chips.has('third') && !(page && partyOf(c, page) === 'third')) return false;
  return true;
}

export interface FlagPill { kind: 'ok' | 'warn' | 'err' | 'info' | 'acc' | ''; label: string }

export function flagPills(r: Row, page: string): FlagPill[] {
  const c = r.c;
  const out: FlagPill[] = [];
  if (c.secure) out.push({ kind: 'ok', label: 'Secure' });
  if (c.httpOnly) out.push({ kind: 'info', label: 'HttpOnly' });
  if (c.sameSite === 'no_restriction' && c.secure) out.push({ kind: '', label: 'None' });
  else if (c.sameSite === 'strict') out.push({ kind: '', label: 'Strict' });
  if (c.partitionKey) out.push({ kind: 'acc', label: 'Partitioned' });
  if (page && partyOf(c, page) === 'third') out.push({ kind: 'warn', label: 'Third-party' });
  const lower = c.name.toLowerCase();
  if (lower.startsWith('__host-')) out.push({ kind: '', label: '__Host-' });
  else if (lower.startsWith('__secure-')) out.push({ kind: '', label: '__Secure-' });
  if (r.info?.effect === 'changed') out.push({ kind: 'warn', label: 'Changed by rule' });
  if (r.info?.effect === 'stripped') out.push({ kind: 'err', label: 'Stripped by rule' });
  return out;
}

const p2 = (n: number) => String(n).padStart(2, '0');

/** `Session`, or the expiry as a local date (with the time for cookies that live under a day). */
export function expiresText(c: Cookie, now = Date.now()): string {
  if (c.session || c.expirationDate === undefined) return 'Session';
  const d = new Date(c.expirationDate * 1000);
  const day = `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}`;
  return c.expirationDate * 1000 - now < 86_400_000 ? `${day} ${p2(d.getHours())}:${p2(d.getMinutes())}` : day;
}

export const dateInput = (sec: number): string => { const d = new Date(sec * 1000); return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}`; };

export const sizeText = (c: Cookie): string => `${c.size} B`;

export const SAME_SITE_LABELS: { v: SameSite; l: string }[] = [
  { v: 'lax', l: 'Lax' }, { v: 'strict', l: 'Strict' }, { v: 'no_restriction', l: 'None' }, { v: 'unspecified', l: 'Unspecified' },
];

export function storeLabel(stores: StoreInfo[], id: string): string {
  return stores.find((s) => s.id === id)?.label ?? id;
}

/** The domain and name of a protected-cookie identity key. */
export function parseIdentity(key: string): { name: string; host: string; storeId: string } | undefined {
  try {
    const a = JSON.parse(key) as unknown[];
    return { storeId: String(a[0]), host: String(a[3]), name: String(a[6]) };
  } catch { return undefined; }
}

/** A cookie carrying just the identity fields of `key`, for `rules.protect`. */
export function cookieFromIdentity(key: string): Cookie | undefined {
  try {
    const a = JSON.parse(key) as [string, unknown, string, string, boolean, string, string];
    const pk = Array.isArray(a[1]) ? { topLevelSite: String(a[1][0]), hasCrossSiteAncestor: !!a[1][1] } : undefined;
    return makeCookie({
      storeId: a[0], firstPartyDomain: a[2], domain: a[4] ? a[3] : '.' + a[3], hostOnly: !!a[4], path: a[5], name: a[6], ...(pk ? { partitionKey: pk } : {}),
    });
  } catch { return undefined; }
}

export { hostOfCookie, siteOf };

/** The tab id in `#tab=N`. */
export const tabFromHash = (hash = location.hash): number | undefined => { const m = /tab=(\d+)/.exec(hash); return m ? Number(m[1]) : undefined; };

/** Sorts newest information first where it matters: by domain, then name. */
export const byDomainName = (a: Row, b: Row): number => hostOfCookie(a.c).localeCompare(hostOfCookie(b.c)) || a.c.name.localeCompare(b.c.name);

/** This site's cookies: its own domain, and third-party cookies partitioned under it (CHIPS). */
export const inSite = (c: Cookie, site: string): boolean =>
  siteOf(c.domain) === site || (!!c.partitionKey && siteOf(c.partitionKey.topLevelSite) === site);

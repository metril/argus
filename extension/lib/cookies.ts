import { BridgeError, type CookieIn, type CookieOut, type CookieReq } from './bridge-types';

const fromBrowser: Record<string, string | undefined> = { no_restriction: 'none', lax: 'lax', strict: 'strict' };
const toBrowser: Record<string, string> = { none: 'no_restriction', lax: 'lax', strict: 'strict' };

export function mapCookie(c: any): CookieOut {
  return {
    name: c.name, value: c.value, domain: c.domain, path: c.path, secure: !!c.secure,
    http_only: !!c.httpOnly, same_site: fromBrowser[c.sameSite], expiration_date: c.expirationDate,
  };
}

const HTTP_ONLY = 'httpOnly cookies are not accessible';

/**
 * The job's cookie store (`storeId`; the default store when omitted). httpOnly cookies are never
 * read, written or deleted here.
 */
export async function cookieOp(br: any, req: CookieReq, storeId?: string): Promise<unknown> {
  const st = storeId ? { storeId } : {};
  if (req.op === 'list') {
    const all: any[] = await br.cookies.getAll({ url: req.url, ...(req.name ? { name: req.name } : {}), ...st });
    return all.filter((c) => !c.httpOnly).map(mapCookie);
  }
  if (req.op === 'set') {
    const c: CookieIn = req.cookie;
    if (c.http_only) throw new BridgeError('denied', 'bad_request', HTTP_ONLY);
    const existing: any[] = await br.cookies.getAll({ url: req.url, name: c.name, ...st });
    if (existing.some((e) => e.httpOnly)) throw new BridgeError('denied', 'bad_request', HTTP_ONLY);
    const d: Record<string, unknown> = { url: req.url, name: c.name, value: c.value };
    if (c.domain !== undefined) d.domain = c.domain;
    if (c.path !== undefined) d.path = c.path;
    if (c.secure !== undefined) d.secure = c.secure;
    if (c.same_site && toBrowser[c.same_site]) d.sameSite = toBrowser[c.same_site];
    if (c.expiration_date !== undefined) d.expirationDate = c.expiration_date;
    await br.cookies.set({ ...d, ...st });
    return null;
  }
  const existing: any[] = await br.cookies.getAll({ url: req.url, name: req.name, ...st });
  if (existing.some((e) => e.httpOnly)) throw new BridgeError('denied', 'bad_request', HTTP_ONLY);
  await br.cookies.remove({ url: req.url, name: req.name, ...st });
  return null;
}

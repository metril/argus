import type { Cookie, SameSite } from '../model';
import { fromLoose, jsonCookies } from './loose';
import { stripBom, type Codec, type ParsedRow } from './types';

const SS: Record<SameSite, string | undefined> = { no_restriction: 'None', lax: 'Lax', strict: 'Strict', unspecified: undefined };

/** The array `page.cookies()` / `browser.cookies()` returns, which `setCookie` takes back. */
export const puppeteer: Codec = {
  id: 'puppeteer',
  label: 'Puppeteer cookies',
  extension: 'json',
  mime: 'application/json',
  export(cs) {
    return JSON.stringify(cs.map((c) => ({
      name: c.name, value: c.value, domain: c.hostOnly ? c.domain.replace(/^\./, '') : '.' + c.domain.replace(/^\./, ''), path: c.path,
      expires: c.session || c.expirationDate === undefined ? -1 : c.expirationDate, size: c.size, httpOnly: c.httpOnly, secure: c.secure, session: c.session,
      ...(SS[c.sameSite] ? { sameSite: SS[c.sameSite] } : {}),
      ...(c.partitionKey ? { partitionKey: { sourceOrigin: c.partitionKey.topLevelSite, hasCrossSiteAncestor: c.partitionKey.hasCrossSiteAncestor ?? false } } : {}),
    })), null, 2);
  },
  parse(text): ParsedRow[] {
    const r = jsonCookies(stripBom(text));
    if ('error' in r) return [{ row: 1, error: r.error }];
    return r.items.map((o, i) => fromLoose(o, i + 1));
  },
};

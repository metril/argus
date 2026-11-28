import type { Cookie, SameSite } from '../model';
import { fromLoose, jsonCookies } from './loose';
import { stripBom, type Codec, type ParsedRow } from './types';

const SS: Record<SameSite, string | undefined> = { no_restriction: 'None', lax: 'Lax', strict: 'Strict', unspecified: undefined };

/** Does not round-trip: an unspecified SameSite comes back as lax. Playwright wants Strict/Lax/None; an unspecified SameSite is what browsers treat as Lax. */
const pwSameSite = (c: Cookie): string => SS[c.sameSite] ?? 'Lax';

export const playwright: Codec = {
  id: 'playwright',
  label: 'Playwright storage state',
  extension: 'json',
  mime: 'application/json',
  export(cs) {
    const cookies = cs.map((c) => ({
      name: c.name, value: c.value, domain: c.hostOnly ? c.domain.replace(/^\./, '') : '.' + c.domain.replace(/^\./, ''), path: c.path,
      expires: c.session || c.expirationDate === undefined ? -1 : c.expirationDate, httpOnly: c.httpOnly, secure: c.secure, sameSite: pwSameSite(c),
      ...(c.partitionKey ? { partitionKey: c.partitionKey.topLevelSite } : {}),
    }));
    return JSON.stringify({ cookies, origins: [] }, null, 2);
  },
  parse(text): ParsedRow[] {
    const r = jsonCookies(stripBom(text));
    if ('error' in r) return [{ row: 1, error: r.error }];
    return r.items.map((o, i) => fromLoose(o, i + 1));
  },
};

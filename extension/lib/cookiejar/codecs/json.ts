import type { Cookie } from '../model';
import { fromLoose, jsonCookies } from './loose';
import { stripBom, type Codec, type ParsedRow } from './types';

/** The EditThisCookie / Cookie-Editor shape. */
export function toEditThisCookie(c: Cookie, id: number): Record<string, unknown> {
  const o: Record<string, unknown> = {
    domain: c.domain, ...(c.session || c.expirationDate === undefined ? {} : { expirationDate: c.expirationDate }),
    hostOnly: c.hostOnly, httpOnly: c.httpOnly, name: c.name, path: c.path, sameSite: c.sameSite, secure: c.secure, session: c.session,
    storeId: c.storeId, value: c.value, id,
  };
  if (c.partitionKey) o.partitionKey = c.partitionKey;
  if (c.firstPartyDomain) o.firstPartyDomain = c.firstPartyDomain;
  return o;
}

export const json: Codec = {
  id: 'json',
  label: 'JSON (EditThisCookie / Cookie-Editor)',
  extension: 'json',
  mime: 'application/json',
  export: (cs) => JSON.stringify(cs.map((c, i) => toEditThisCookie(c, i + 1)), null, 2),
  parse(text): ParsedRow[] {
    const r = jsonCookies(stripBom(text));
    if ('error' in r) return [{ row: 1, error: r.error }];
    return r.items.map((o, i) => fromLoose(o, i + 1));
  },
};

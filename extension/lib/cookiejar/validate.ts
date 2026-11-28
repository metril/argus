import { byteSize, hostOfCookie, hostUnder, type Cookie } from './model';

export type IssueField = 'name' | 'value' | 'domain' | 'path' | 'secure' | 'sameSite' | 'expires' | 'partitionKey' | 'size';

/** One reason a browser would refuse (or silently drop) a cookie, as a sentence for the user. */
export interface Issue {
  field: IssueField;
  reason: string;
}

export type Draft = Pick<Cookie, 'name' | 'value' | 'domain' | 'hostOnly' | 'path' | 'secure' | 'sameSite' | 'session'> &
  Partial<Pick<Cookie, 'expirationDate' | 'partitionKey'>>;

export interface ValidateOptions {
  /** The URL the cookie is set from: its host must be the cookie's domain or a subdomain of it. */
  url?: string;
  /** Milliseconds since the epoch (tests). */
  now?: number;
}

export const MAX_COOKIE_BYTES = 4096;

const BAD_NAME = /[\x00-\x20\x7f;=]/;
const BAD_VALUE = /[\x00-\x08\x0a-\x1f\x7f;]/;

export function validateCookie(c: Draft, o: ValidateOptions = {}): Issue[] {
  const out: Issue[] = [];
  const add = (field: IssueField, reason: string) => out.push({ field, reason });
  const lower = c.name.toLowerCase();

  if (c.name === '') add('name', 'The cookie needs a name.');
  else if (BAD_NAME.test(c.name)) add('name', 'The name cannot contain spaces, control characters, semicolons or equals signs.');
  if (BAD_VALUE.test(c.value)) add('value', 'The value cannot contain semicolons or control characters.');
  if (byteSize(c.name, c.value) > MAX_COOKIE_BYTES) add('size', `The name and value together are over ${MAX_COOKIE_BYTES} bytes, which browsers refuse.`);

  if (!c.path.startsWith('/')) add('path', 'The path must start with a slash.');
  if (c.domain.replace(/^\./, '') === '') add('domain', 'The cookie needs a domain.');

  if (lower.startsWith('__host-')) {
    if (!c.secure) add('secure', 'A __Host- cookie must be Secure.');
    if (c.path !== '/') add('path', 'A __Host- cookie must have the path "/".');
    if (!c.hostOnly) add('domain', 'A __Host- cookie must not set a Domain, so it has to be host-only.');
  } else if (lower.startsWith('__secure-') && !c.secure) {
    add('secure', 'A __Secure- cookie must be Secure.');
  }
  if (c.sameSite === 'no_restriction' && !c.secure) add('sameSite', 'SameSite=None requires the Secure flag.');
  if (c.partitionKey && !c.secure) add('partitionKey', 'A partitioned cookie requires the Secure flag.');

  if (o.url) {
    let host = '';
    try { host = new URL(o.url).hostname.toLowerCase(); } catch { add('domain', 'The URL for this cookie is not valid.'); }
    if (host) {
      const d = hostOfCookie(c);
      if (c.hostOnly ? host !== d : !hostUnder(host, d)) add('domain', `The domain ${c.domain} is not ${host} or a parent of it.`);
    }
  }

  const now = (o.now ?? Date.now()) / 1000;
  if (!c.session && c.expirationDate !== undefined && c.expirationDate <= now) add('expires', 'The expiry is in the past, so the browser would delete this cookie at once.');
  return out;
}

export const firstProblem = (c: Draft, o?: ValidateOptions): Issue | undefined => validateCookie(c, o)[0];

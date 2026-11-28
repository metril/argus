import { rulePattern } from '../rulegen';
import { hostOfCookie, siteOfCookie, type Cookie } from './model';

export interface CookieRuleOptions {
  /** `remove` drops the cookie; `allow` is an exception; the others rewrite its attributes. */
  action: 'remove' | 'allow' | 'modify';
  /** `host`: only this cookie's host (and subdomains); `site`: the whole registrable domain. */
  scope?: 'host' | 'site';
  maxAge?: number;
  sameSite?: 'none' | 'lax' | 'strict';
  /** Only when the page is third-party to the host. */
  thirdParty?: boolean;
}

/** A name safe to write after `$cookie=`; anything else becomes an anchored regex. */
export function cookieNameOption(name: string): string {
  if (/^[\w.\-%]+$/.test(name)) return name;
  const esc = name.replace(/[\\^$.*+?()[\]{}|/]/g, '\\$&').replace(/,/g, '\\x2C').replace(/;/g, '\\x3B');
  return `/^${esc}$/`;
}

/**
 * One Argus `$cookie` rule line for a cookie, in the conventions of `lib/rulegen.ts`
 * (`||host^` patterns, `@@` exceptions). The value is never part of the rule.
 */
export function cookieRule(c: Cookie, o: CookieRuleOptions): string {
  const host = o.scope === 'site' ? siteOfCookie(c) : hostOfCookie(c);
  let value = cookieNameOption(c.name);
  if (o.action === 'modify') {
    if (o.maxAge !== undefined) value += `;maxAge=${Math.max(0, Math.floor(o.maxAge))}`;
    if (o.sameSite) value += `;sameSite=${o.sameSite}`;
  }
  const opts = [`cookie=${value}`];
  if (o.thirdParty) opts.push('third-party');
  return `${o.action === 'allow' ? '@@' : ''}${rulePattern(`https://${host}/`, 'host')}$${opts.join(',')}`;
}

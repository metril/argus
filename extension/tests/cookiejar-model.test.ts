import { describe, expect, it } from 'vitest';
import { changedFields, cookieUrl, fromBrowser, identityKey, isFirstParty, makeCookie, matchesUrl, normalizeSameSite, partyOf, siteOf, toKeyDetails, toSetDetails } from '../lib/cookiejar/model';
import { firstProblem, validateCookie } from '../lib/cookiejar/validate';

const c = (p: Record<string, unknown> = {}) => makeCookie({ name: 'a', value: '1', domain: 'example.com', storeId: '0', ...p } as never);

describe('model', () => {
  it('normalises chrome and firefox cookies to one shape', () => {
    const chrome = fromBrowser({ name: 'sid', value: 'x', domain: '.example.com', hostOnly: false, path: '/', secure: true, httpOnly: true, sameSite: 'no_restriction', session: false, expirationDate: 2e9, storeId: '0', partitionKey: { topLevelSite: 'https://top.test', hasCrossSiteAncestor: false } });
    expect(chrome).toMatchObject({ storeId: '0', firstPartyDomain: '', hostOnly: false, sameSite: 'no_restriction', partitionKey: { topLevelSite: 'https://top.test', hasCrossSiteAncestor: false }, size: 4 });
    const ff = fromBrowser({ name: 'a', value: 'é', domain: 'example.com', path: '/', secure: false, httpOnly: false, sameSite: 'unspecified', session: true, storeId: 'firefox-container-1', firstPartyDomain: 'example.com', partitionKey: { topLevelSite: 'https://top.test' } });
    expect(ff).toMatchObject({ hostOnly: true, firstPartyDomain: 'example.com', session: true, size: 3 });
    expect(ff.partitionKey).toEqual({ topLevelSite: 'https://top.test' });
    expect('expirationDate' in ff).toBe(false);
  });
  it('maps every SameSite spelling, including unspecified', () => {
    expect(['None', 'no_restriction', 'Lax', 'STRICT', 'unspecified', undefined, 'weird'].map(normalizeSameSite)).toEqual(['no_restriction', 'no_restriction', 'lax', 'strict', 'unspecified', 'unspecified', 'unspecified']);
  });
  it('identity covers store, partition, first-party domain, domain, hostOnly, path and name but not the value', () => {
    const base = c();
    expect(identityKey(c({ value: 'other', secure: true }))).toBe(identityKey(base));
    for (const diff of [{ storeId: '1' }, { partitionKey: { topLevelSite: 'https://t.test' } }, { firstPartyDomain: 'x.com' }, { domain: 'www.example.com' }, { hostOnly: false, domain: '.example.com' }, { path: '/p' }, { name: 'b' }]) {
      expect(identityKey(c(diff))).not.toBe(identityKey(base));
    }
    expect(identityKey(c({ domain: '.example.com', hostOnly: false }))).not.toBe(identityKey(c({ domain: 'example.com', hostOnly: true })));
    // hasCrossSiteAncestor is part of the identity; unknown counts as false
    const pk = (h?: boolean) => c({ partitionKey: { topLevelSite: 'https://t.test', ...(h === undefined ? {} : { hasCrossSiteAncestor: h }) } });
    expect(identityKey(pk(true))).not.toBe(identityKey(pk(false)));
    expect(identityKey(pk())).toBe(identityKey(pk(false)));
  });
  it('first and third party are relative to a site (registrable domain)', () => {
    expect(partyOf(c({ domain: '.cdn.example.com', hostOnly: false }), 'https://www.example.com/x')).toBe('first');
    expect(partyOf(c({ domain: '.tracker.net' }), 'www.example.com')).toBe('third');
    expect(isFirstParty(c({ domain: 'example.co.uk' }), 'shop.example.co.uk')).toBe(true);
    expect(isFirstParty(c({ domain: 'other.co.uk' }), 'shop.example.co.uk')).toBe(false);
    expect(siteOf('localhost')).toBe('localhost');
    expect(siteOf('http://192.168.1.2:80/')).toBe('192.168.1.2');
  });
  it('builds URLs and matches requests like a browser', () => {
    expect(cookieUrl(c({ domain: '.example.com', secure: true, path: '/a' }))).toBe('https://example.com/a');
    const sec = c({ secure: true, path: '/app' });
    expect(matchesUrl(sec, 'https://example.com/app/x')).toBe(true);
    expect(matchesUrl(sec, 'http://example.com/app/x')).toBe(false);
    expect(matchesUrl(sec, 'https://example.com/application')).toBe(false);
    expect(matchesUrl(c(), 'https://sub.example.com/')).toBe(false);
    expect(matchesUrl(c({ domain: '.example.com', hostOnly: false }), 'https://sub.example.com/')).toBe(true);
    expect(matchesUrl(c(), 'ftp://example.com/')).toBe(false);
  });
  it('passes the cookie its own store, partition and first-party domain back to the API', () => {
    const k = c({ storeId: 'firefox-container-2', firstPartyDomain: 'example.com', partitionKey: { topLevelSite: 'https://t.test', hasCrossSiteAncestor: true }, secure: true });
    expect(toKeyDetails(k, { firstPartyDomain: true })).toEqual({ url: 'https://example.com/', name: 'a', storeId: 'firefox-container-2', partitionKey: { topLevelSite: 'https://t.test', hasCrossSiteAncestor: true }, firstPartyDomain: 'example.com' });
    // chrome never receives firstPartyDomain for an unisolated cookie
    expect('firstPartyDomain' in toSetDetails(c(), { firstPartyDomain: false })).toBe(false);
    // a cookie that carries one (imported, or copied from Firefox) never sends it where unsupported
    expect('firstPartyDomain' in toSetDetails(c({ firstPartyDomain: 'example.com' }), { firstPartyDomain: false })).toBe(false);
    expect('firstPartyDomain' in toKeyDetails(c({ firstPartyDomain: 'example.com' }), { firstPartyDomain: false })).toBe(false);
    expect(toSetDetails(c(), { firstPartyDomain: true }).firstPartyDomain).toBe('');
    const d = toSetDetails(c({ domain: '.example.com', hostOnly: false, expirationDate: 2e9, session: false }), { firstPartyDomain: false });
    expect(d).toMatchObject({ domain: '.example.com', expirationDate: 2e9 });
    expect('domain' in toSetDetails(c(), { firstPartyDomain: false })).toBe(false);
  });
  it('lists the attributes that differ', () => {
    expect(changedFields(c(), c({ value: '2', secure: true, expirationDate: 5, session: false }))).toEqual(['value', 'secure', 'expires']);
    expect(changedFields(c(), c())).toEqual([]);
  });
});

describe('validate', () => {
  const reasons = (p: Record<string, unknown>, o = {}) => validateCookie(c(p), o).map((i) => i.reason);
  it('accepts a plain cookie', () => { expect(reasons({})).toEqual([]); });
  it('__Host- needs Secure, path / and no Domain', () => {
    expect(reasons({ name: '__Host-id' })).toEqual(['A __Host- cookie must be Secure.']);
    expect(reasons({ name: '__Host-id', secure: true, path: '/x' })).toEqual(['A __Host- cookie must have the path "/".']);
    expect(reasons({ name: '__Host-id', secure: true, domain: '.example.com', hostOnly: false })).toEqual(['A __Host- cookie must not set a Domain, so it has to be host-only.']);
    expect(reasons({ name: '__host-id', secure: true })).toEqual([]);
  });
  it('__Secure- needs Secure', () => {
    expect(reasons({ name: '__Secure-id' })).toEqual(['A __Secure- cookie must be Secure.']);
    expect(reasons({ name: '__Secure-id', secure: true })).toEqual([]);
  });
  it('SameSite=None and partitioned cookies need Secure', () => {
    expect(reasons({ sameSite: 'no_restriction' })).toEqual(['SameSite=None requires the Secure flag.']);
    expect(reasons({ sameSite: 'no_restriction', secure: true })).toEqual([]);
    expect(reasons({ partitionKey: { topLevelSite: 'https://t.test' } })).toEqual(['A partitioned cookie requires the Secure flag.']);
  });
  it('the domain must be the URL host or a parent of it', () => {
    expect(reasons({ domain: '.example.com', hostOnly: false }, { url: 'https://www.example.com/' })).toEqual([]);
    expect(reasons({ domain: 'example.com' }, { url: 'https://example.com/' })).toEqual([]);
    expect(reasons({ domain: '.other.com', hostOnly: false }, { url: 'https://www.example.com/' })[0]).toMatch(/not www.example.com or a parent/);
    expect(reasons({ domain: 'example.com' }, { url: 'https://www.example.com/' })[0]).toMatch(/not www.example.com/);
    expect(reasons({}, { url: 'nope' })[0]).toMatch(/URL/);
  });
  it('name plus value is limited to 4096 bytes (bytes, not characters)', () => {
    expect(reasons({ value: 'x'.repeat(4095) })).toEqual([]);
    expect(reasons({ value: 'x'.repeat(4096) })[0]).toMatch(/over 4096 bytes/);
    expect(reasons({ value: 'é'.repeat(2048) })[0]).toMatch(/over 4096 bytes/);
  });
  it('rejects invalid characters, empty names and bad paths', () => {
    expect(reasons({ name: 'a b' })[0]).toMatch(/name cannot contain/);
    expect(reasons({ name: 'a=b' })[0]).toMatch(/name cannot contain/);
    expect(reasons({ name: '' })).toContain('The cookie needs a name.');
    expect(reasons({ value: 'a;b' })[0]).toMatch(/value cannot contain/);
    expect(reasons({ value: 'a\nb' })[0]).toMatch(/value cannot contain/);
    expect(reasons({ value: 'a b' })).toEqual([]);
    expect(reasons({ path: 'x' })[0]).toMatch(/slash/);
  });
  it('an expiry in the past is refused; session cookies and the future are fine', () => {
    const now = 1_700_000_000_000;
    expect(reasons({ expirationDate: 1_699_999_999, session: false }, { now })[0]).toMatch(/in the past/);
    expect(reasons({ expirationDate: 1_700_000_100, session: false }, { now })).toEqual([]);
    expect(reasons({}, { now })).toEqual([]);
  });
  it('reports every problem, firstProblem the first', () => {
    const k = c({ name: '__Host-x', sameSite: 'no_restriction' });
    expect(validateCookie(k).length).toBe(2);
    expect(firstProblem(k)?.field).toBe('secure');
    expect(firstProblem(c())).toBeUndefined();
  });
});

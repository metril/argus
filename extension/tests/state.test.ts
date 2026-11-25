import { describe, expect, it } from 'vitest';
import { bannerCopy, daysUntil, issuerName, resolveState } from '../lib/state';
import type { CertInfo, Lookup } from '../lib/api';

const cert = { verdict: 'ok', issuer: 'C=US, CN=Sectigo ECC DV CA', not_after: '2027-03-01T00:00:00Z' } as unknown as CertInfo;
const r = (lookup?: Lookup, tabUrl = 'https://a.com/', configured = true) => resolveState({ configured, tabUrl, ...(lookup ? { lookup } : {}) });

describe('resolveState', () => {
  it('signed out shows sign-in', () => expect(r(undefined, 'https://a.com/', false)).toEqual({ view: 'signin' }));
  it('browser and http pages are not inspectable', () => {
    expect(r(undefined, 'chrome://extensions')).toEqual({ view: 'main', site: { kind: 'none', reason: 'browser' } });
    expect(r(undefined, 'http://a.com/')).toEqual({ view: 'main', site: { kind: 'none', reason: 'insecure' } });
  });
  it('loading until the lookup returns', () => expect(r()).toEqual({ view: 'main', site: { kind: 'loading' } }));
  it('ok, unseen', () => {
    expect(r({ kind: 'ok', cert })).toEqual({ view: 'main', site: { kind: 'cert', cert } });
    expect(r({ kind: 'unseen' })).toEqual({ view: 'main', site: { kind: 'unseen' } });
  });
  it('an expired session returns to sign-in', () => expect(r({ kind: 'error', error: 'sessionExpired' })).toEqual({ view: 'signin', reason: 'expired' }));
  it('other errors become a banner on the main view', () => {
    expect(r({ kind: 'error', error: 'unreachable', refused: true })).toEqual({ view: 'main', site: { kind: 'unknown' }, banner: { error: 'unreachable', refused: true } });
    expect(r({ kind: 'error', error: 'forbidden' })).toMatchObject({ view: 'main', banner: { error: 'forbidden' } });
  });
});

describe('copy', () => {
  it('has a title per error and no http codes', () => {
    for (const k of ['badCredentials', 'forbidden', 'unreachable', 'noHostPermission', 'sessionExpired', 'rateLimited'] as const) {
      const c = bannerCopy(k, 'argus.lan');
      expect(c.title.length).toBeGreaterThan(0);
      expect(JSON.stringify(c)).not.toMatch(/HTTP|\b40\d\b/);
    }
    expect(bannerCopy('unreachable', 'argus.lan').title).toBe("Can't reach argus.lan");
    expect(bannerCopy('unreachable', 'argus.lan', true).body).toBe("That's the proxy port. Use the web UI address.");
  });
  it('helpers', () => {
    expect(issuerName('C=US, CN=Sectigo ECC DV CA')).toBe('Sectigo ECC DV CA');
    expect(issuerName('Plain')).toBe('Plain');
    expect(daysUntil('2026-01-11T00:00:00Z', Date.parse('2026-01-01T00:00:00Z'))).toBe(10);
  });
});

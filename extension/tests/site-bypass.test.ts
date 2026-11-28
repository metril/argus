import { afterEach, describe, expect, it, vi } from 'vitest';
import { clearSiteBypass, getSiteBypass, setSiteBypass, type Settings } from '../lib/api';

const S: Settings = { argusUrl: 'https://argus.lan:8080', token: 'tok' };
const state = { host: 'a.test', bypassed: true, mode: 'no_decrypt', source: 'extension', name: 'a.test', removable: true, ev_auto_tunnel: true };
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

afterEach(() => vi.unstubAllGlobals());

describe('site bypass client', () => {
  it.each([
    ['GET', getSiteBypass], ['PUT', setSiteBypass], ['DELETE', clearSiteBypass],
  ] as const)('%s hits /bypass/sites/{host} with the bearer token and encodes the host', async (method, fn) => {
    const f = vi.fn(async () => json(200, state));
    vi.stubGlobal('fetch', f);
    const r = await fn(S, 'xn--a.test');
    expect(r).toEqual({ ok: true, value: state });
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://argus.lan:8080/api/v1/bypass/sites/xn--a.test');
    expect(init.method).toBe(method);
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer tok');
    await fn(S, '[::1]');
    expect((f.mock.calls[1] as unknown as [string])[0]).toBe('https://argus.lan:8080/api/v1/bypass/sites/%5B%3A%3A1%5D');
  });

  it('marks a 403 insufficient_scope so the popup can offer to sign in again', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(403, { error: { code: 'insufficient_scope', message: 'Missing required scope: one of bypass:site, config:write' } })));
    const r = await setSiteBypass(S, 'a.test');
    expect(r).toMatchObject({ ok: false, scope: true, status: 403 });
  });

  it('does not treat another 403 as a scope problem', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(403, { error: { code: 'profile_restricted', message: 'no' } })));
    expect(await getSiteBypass(S, 'a.test')).toMatchObject({ ok: false, scope: false, status: 403, restricted: true });
  });

  it('marks a profile-restricted token so the popup does not offer to sign in', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(403, { error: { code: 'profile_restricted', message: 'no' } })));
    expect(await setSiteBypass(S, 'a.test')).toEqual({ ok: false, scope: false, status: 403, message: 'no', restricted: true });
  });

  it('carries the 409 reason of a site bypassed by something else', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(409, { error: { code: 'not_extension_entry', message: 'a.test is bypassed by Banking' } })));
    expect(await clearSiteBypass(S, 'a.test')).toEqual({ ok: false, scope: false, status: 409, message: 'a.test is bypassed by Banking' });
  });

  it('is a failed call without settings or on a network error', async () => {
    expect(await getSiteBypass({ argusUrl: '', token: '' }, 'a.test')).toEqual({ ok: false, scope: false, status: 0 });
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('down'); }));
    expect(await setSiteBypass(S, 'a.test')).toEqual({ ok: false, scope: false, status: 0 });
  });
});

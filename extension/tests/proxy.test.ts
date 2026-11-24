import { describe, expect, it, vi } from 'vitest';
import { ProxyController, REALM } from '../lib/proxy';
import { parseSetCookie, storeSetCookies } from '../lib/setcookie';
import { JOB_HEADER, StoreRelay } from '../lib/storerelay';
import { isBroad } from '../lib/grants';

function mk(firefox: boolean, enabled = true) {
  const settings = { set: vi.fn(async () => {}), clear: vi.fn(async () => {}) };
  const store: Record<string, unknown> = { argusProxy: { enabled, stores: {} } };
  const br = {
    proxy: { settings },
    storage: { local: { get: vi.fn(async (k: string) => ({ [k]: store[k] })), set: vi.fn(async (o: object) => { Object.assign(store, o); }) } },
  };
  const c = new ProxyController({ browser: br, firefox, argusHost: async () => 'argus.local' });
  return { c, settings, br };
}
const ch = (host = 'argus.local', port = 3130) => ({ isProxy: true, realm: REALM, challenger: { host, port }, requestId: Math.random().toString() });

describe('ProxyController (Chrome)', () => {
  it('sets fixed_servers only while enabled and connected, clears otherwise', async () => {
    const { c, settings } = mk(false);
    await c.init();
    expect(settings.set).not.toHaveBeenCalled();
    await c.setServer(null, 3130);
    await c.setSid('s'.repeat(32));
    const v = (settings.set.mock.calls.at(-1) as any)[0];
    expect(v.scope).toBe('regular');
    expect(v.value.mode).toBe('fixed_servers');
    expect(v.value.rules.singleProxy).toEqual({ scheme: 'http', host: 'argus.local', port: 3130 });
    expect(v.value.rules.bypassList).toContain('argus.local');
    await c.setSid(null);
    expect((settings.clear.mock.calls.at(-1) as any)[0]).toEqual({ scope: 'regular' });
    await c.setSid('s'.repeat(32));
    await c.setState({ enabled: false, stores: {} });
    expect(settings.clear.mock.calls.length).toBeGreaterThan(1);
    expect(c.active()).toBe(false);
  });
  it('answers only its own realm, host and port, once per request', async () => {
    const { c } = mk(false);
    await c.init();
    await c.setServer(null, 3130);
    await c.setSid('a'.repeat(32));
    const ok = ch();
    expect(await c.auth(ok)).toEqual({ authCredentials: { username: 'ext', password: 'a'.repeat(32) } });
    expect(await c.auth(ok)).toEqual({ cancel: true });
    expect(await c.auth({ ...ch(), realm: 'other' })).toEqual({});
    expect(await c.auth({ ...ch('evil.test'), realm: REALM })).toEqual({});
    expect(await c.auth(ch('argus.local', 8080))).toEqual({});
    expect(await c.auth({ ...ch(), isProxy: false })).toEqual({});
  });
  it('does not answer when off or disconnected', async () => {
    const { c } = mk(false, false);
    await c.init();
    await c.setServer(null, 3130);
    await c.setSid('a'.repeat(32));
    expect(await c.auth(ch())).toEqual({});
    await c.setState({ enabled: true, stores: {} });
    await c.setSid(null);
    expect(await c.auth(ch())).toEqual({});
  });
});

describe('ProxyController (Firefox containers)', () => {
  it('routes only enabled stores to the listener; Argus itself stays direct', async () => {
    const { c } = mk(true);
    await c.init();
    await c.setServer('10.0.0.5', 3130);
    await c.setSid('a'.repeat(32));
    await c.setState({ enabled: true, stores: { 'firefox-container-2': false, 'firefox-private': false } });
    for (const store of ['firefox-default', 'firefox-container-1']) {
      expect(await c.route({ cookieStoreId: store, url: 'https://x.test/' })).toMatchObject({ type: 'socks', host: '10.0.0.5', port: 3130 });
    }
    expect(await c.route({ cookieStoreId: 'firefox-container-2', url: 'https://x.test/' })).toEqual({ type: 'direct' });
    expect(await c.route({ cookieStoreId: 'firefox-private', url: 'https://x.test/' })).toEqual({ type: 'direct' });
    expect(await c.route({ cookieStoreId: 'firefox-default', url: 'https://argus.local/api' })).toEqual({ type: 'direct' });
    await c.setSid(null);
    expect(await c.route({ cookieStoreId: 'firefox-default', url: 'https://x.test/' })).toEqual({ type: 'direct' });
  });
  it('routes through SOCKS5 with per-request credentials: the session, plus the store token for a container', async () => {
    const { c } = mk(true);
    await c.init();
    await c.setServer('10.0.0.5', 3130);
    await c.setSid('a'.repeat(32));
    const r = async (store: string) => c.route({ cookieStoreId: store, url: 'https://x.test/' });
    const d = await r('firefox-default');
    expect(d).toMatchObject({ type: 'socks', host: '10.0.0.5', port: 3130, username: 'ext', proxyDNS: true });
    expect(d.password).toBe('a'.repeat(32));
    const a = await r('firefox-container-1');
    const b = await r('firefox-container-2');
    const [sid, ta] = a.password!.split(':');
    expect(sid).toBe('a'.repeat(32));
    expect(ta).toMatch(/^[a-z0-9]{12}$/);
    expect(ta).not.toBe(b.password!.split(':')[1]);
    expect(a.password).not.toContain('container');
    expect(c.storeForToken(ta!)).toBe('firefox-container-1');
    expect(c.storeForToken('forged')).toBeUndefined();
    expect(c.storeForToken('')).toBe('firefox-default');
    await c.setSid('b'.repeat(32));
    expect(c.storeForToken(ta!)).toBeUndefined();
    // a switched-off store goes direct
    await c.setState({ enabled: true, stores: { 'firefox-container-1': false } });
    expect(await r('firefox-container-1')).toEqual({ type: 'direct' });
  });
});

describe('Set-Cookie', () => {
  it('parses attributes, max-age before expires, deletions', () => {
    const c = parseSetCookie('a=b; Domain=.Ex.com; Path=/p; Secure; HttpOnly; SameSite=None; Max-Age=60', 1000)!;
    expect(c).toMatchObject({ name: 'a', value: 'b', domain: 'ex.com', path: '/p', secure: true, httpOnly: true, sameSite: 'no_restriction', expires: 1060, delete: false });
    expect(parseSetCookie('a=b; Max-Age=0', 1000)!.delete).toBe(true);
    expect(parseSetCookie('a=b; Expires=Thu, 01 Jan 1970 00:00:00 GMT', 1000)!.delete).toBe(true);
    expect(parseSetCookie('a=b; Max-Age=10; Expires=Thu, 01 Jan 1970 00:00:00 GMT', 1000)!.delete).toBe(false);
    expect(parseSetCookie('novalue', 0)).toBeNull();
    expect(parseSetCookie('=x', 0)).toBeNull();
  });
  it('writes to the named store only', async () => {
    const br = { cookies: { set: vi.fn(async () => {}), remove: vi.fn(async () => {}) } };
    await storeSetCookies(br, 'https://ex.com/p', 'firefox-container-1', ['a=b; Path=/; HttpOnly', 'gone=1; Max-Age=0']);
    expect((br.cookies.set.mock.calls[0] as any)[0]).toMatchObject({ url: 'https://ex.com/p', name: 'a', value: 'b', httpOnly: true, storeId: 'firefox-container-1' });
    expect((br.cookies.remove.mock.calls[0] as any)[0]).toEqual({ url: 'https://ex.com/p', name: 'gone', storeId: 'firefox-container-1' });
  });
});

describe('StoreRelay', () => {
  function rig() {
    const jar: Record<string, { name: string; value: string }[]> = {
      'firefox-default': [{ name: 'dflt', value: 'D' }],
      'firefox-container-1': [{ name: 'c1', value: 'one' }, { name: 'sid', value: 'H' }],
      'firefox-container-2': [{ name: 'c2', value: 'two' }],
    };
    const br = {
      cookies: {
        getAll: vi.fn(async (q: { storeId?: string }) => jar[q.storeId ?? 'firefox-default']),
        set: vi.fn(async () => {}), remove: vi.fn(async () => {}),
      },
      webRequest: { onBeforeSendHeaders: { addListener: vi.fn() }, onHeadersReceived: { addListener: vi.fn() } },
    };
    return { br, sr: new StoreRelay(br) };
  }
  const hdrs = (m: string, extra: any[] = []) => [{ name: JOB_HEADER, value: m }, { name: 'X-Argus-Relay', value: 'r' }, ...extra];

  it('sends only the bound store cookies (HttpOnly included) and strips the marker, per hop', async () => {
    const { br, sr } = rig();
    expect(sr.install()).toBe(true);
    sr.register('m1', 'firefox-container-1');
    const r1: any = await sr.beforeSend({ requestId: '1', url: 'https://a.com/', requestHeaders: hdrs('m1', [{ name: 'Cookie', value: 'forged=1' }]) });
    const names = r1.requestHeaders.map((h: any) => h.name.toLowerCase());
    expect(names).not.toContain(JOB_HEADER.toLowerCase());
    expect(names).toContain('x-argus-relay');
    expect(r1.requestHeaders.find((h: any) => h.name === 'Cookie').value).toBe('c1=one; sid=H');
    // a redirect hop is a new request id with the marker still on it
    const r2: any = await sr.beforeSend({ requestId: '2', url: 'https://b.com/', requestHeaders: hdrs('m1') });
    expect(r2.requestHeaders.find((h: any) => h.name === 'Cookie').value).toBe('c1=one; sid=H');
    expect(br.cookies.getAll.mock.calls.every((c: any) => c[0].storeId === 'firefox-container-1')).toBe(true);
    // another container's job gets its own cookies, never the first one's
    sr.register('m2', 'firefox-container-2');
    const r3: any = await sr.beforeSend({ requestId: '3', url: 'https://a.com/', requestHeaders: hdrs('m2') });
    expect(r3.requestHeaders.find((h: any) => h.name === 'Cookie').value).toBe('c2=two');
    // the default store is never read
    expect(br.cookies.getAll.mock.calls.some((c: any) => c[0].storeId === 'firefox-default' || !c[0].storeId)).toBe(false);
  });

  it('a forged or released marker gets no cookies and is removed', async () => {
    const { sr } = rig();
    const r: any = await sr.beforeSend({ requestId: '1', url: 'https://a.com/', requestHeaders: hdrs('nope', [{ name: 'Cookie', value: 'x=1' }]) });
    expect(r.requestHeaders.some((h: any) => h.name.toLowerCase() === 'cookie')).toBe(false);
    expect(r.requestHeaders.some((h: any) => h.name === JOB_HEADER)).toBe(false);
    // requests without the marker are untouched
    expect(await sr.beforeSend({ requestId: '9', url: 'https://a.com/', requestHeaders: [{ name: 'Accept', value: '*/*' }] })).toEqual({});
  });

  it('Set-Cookie goes to the bound store and is removed from the response; the default store is untouched', async () => {
    const { br, sr } = rig();
    sr.register('m1', 'firefox-container-1');
    await sr.beforeSend({ requestId: '7', url: 'https://a.com/x', requestHeaders: hdrs('m1') });
    const out: any = await sr.received({ requestId: '7', url: 'https://a.com/x', responseHeaders: [{ name: 'Set-Cookie', value: 'n=v; Path=/; Secure' }, { name: 'Content-Type', value: 'text/plain' }] });
    expect(out.responseHeaders).toEqual([{ name: 'Content-Type', value: 'text/plain' }]);
    expect(br.cookies.set).toHaveBeenCalledTimes(1);
    expect((br.cookies.set.mock.calls[0] as any)[0]).toMatchObject({ name: 'n', value: 'v', storeId: 'firefox-container-1', secure: true });
    // a request that is not ours is not touched
    expect(await sr.received({ requestId: '8', url: 'https://a.com/', responseHeaders: [{ name: 'Set-Cookie', value: 'z=1' }] })).toEqual({});
    expect(br.cookies.set).toHaveBeenCalledTimes(1);
    sr.release('m1');
    expect(await sr.received({ requestId: '7', url: 'https://a.com/x', responseHeaders: [] })).toEqual({});
  });

  it('install reports a browser without blocking webRequest', () => {
    expect(new StoreRelay({}).install()).toBe(false);
  });
});

describe('grants', () => {
  it('broad patterns are never reported as per-host grants', () => {
    for (const o of ['<all_urls>', '*://*/*', 'https://*/*', 'http://*/*', 'https://a.com/path*']) expect(isBroad(o)).toBe(true);
    for (const o of ['https://a.com/*', '*://*.a.com/*', '*://localhost/*']) expect(isBroad(o)).toBe(false);
  });
});

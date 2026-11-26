import { describe, expect, it, vi } from 'vitest';
import { ProxyController, REALM, statusKind } from '../lib/proxy';
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

describe('ProxyController (worker restart)', () => {
  it('a 407 during the reconnect gap waits for the session instead of falling to the native prompt', async () => {
    const { c } = mk(false);
    await c.init(); // fresh worker: no sid, no server yet; Chrome still has the proxy setting
    const p = c.auth(ch());
    await new Promise((r) => setTimeout(r, 20));
    await c.setServer(null, 3130);
    await c.setSid('a'.repeat(32));
    expect(await p).toEqual({ authCredentials: { username: 'ext', password: 'a'.repeat(32) } });
  });
  it('a 407 that arrives before init has read the stored state still waits for it', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const settings = { set: vi.fn(async () => {}), clear: vi.fn(async () => {}) };
    const br = { proxy: { settings }, storage: { local: { get: vi.fn(async (k: string) => { await gate; return { [k]: { enabled: true, stores: {} } }; }), set: vi.fn() } } };
    const c = new ProxyController({ browser: br, firefox: false, argusHost: async () => 'argus.local', readyWaitMs: 2000 });
    const init = c.init();
    const p = c.auth(ch());
    release();
    await init;
    await c.setServer(null, 3130);
    await c.setSid('a'.repeat(32));
    expect(await p).toHaveProperty('authCredentials');
  });
  it('our own listener but unanswerable (just turned off, or a disabled store) is cancelled, a foreign one left alone', async () => {
    const { c } = mk(false);
    await c.init();
    await c.setServer(null, 3130);
    await c.setSid('a'.repeat(32));
    await c.setState({ enabled: false, stores: {} });
    expect(await c.auth(ch())).toEqual({ cancel: true });
    expect(await c.auth(ch('evil.test'))).toEqual({});
    await c.setState({ enabled: true, stores: { x: false } });
    expect(await c.auth({ ...ch(), cookieStoreId: 'x' })).toEqual({ cancel: true });
  });
  it('cancels (no native prompt) when the channel never comes back', async () => {
    const settings = { set: vi.fn(async () => {}), clear: vi.fn(async () => {}) };
    const br = { proxy: { settings }, storage: { local: { get: vi.fn(async (k: string) => ({ [k]: { enabled: true, stores: {} } })), set: vi.fn() } } };
    const c = new ProxyController({ browser: br, firefox: false, argusHost: async () => 'argus.local', readyWaitMs: 30 });
    await c.init();
    expect(await c.auth(ch())).toEqual({ cancel: true });
  });
  it('stays out of the way when the toggle is off', async () => {
    const { c } = mk(false, false);
    await c.init();
    expect(await c.auth(ch())).toEqual({});
  });
  it('compares hosts across case, trailing dot and IPv6 brackets', async () => {
    const { c } = mk(false);
    await c.init();
    await c.setServer('[::1]', 3130);
    await c.setSid('a'.repeat(32));
    expect(await c.auth(ch('::1'))).toHaveProperty('authCredentials');
    await c.setServer('Argus.Local.', 3130);
    expect(await c.auth(ch('argus.local'))).toHaveProperty('authCredentials');
  });
});

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
    await c.setSid(null); // channel lost: fail closed, the setting stays
    expect(settings.clear).not.toHaveBeenCalled();
    await c.setSid('s'.repeat(32));
    await c.setState({ enabled: false, stores: {} });
    expect((settings.clear.mock.calls.at(-1) as any)[0]).toEqual({ scope: 'regular' });
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
    expect(await c.auth(ch())).toEqual({ cancel: true }); // ours, but off: ended, not prompted
    await c.setState({ enabled: true, stores: {} });
    await c.release(); // signed out: nothing left to answer with
    c['d'].readyWaitMs = 20;
    expect(await c.auth(ch())).toEqual({ cancel: true });
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
    await c.release();
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

describe('listener status', () => {
  it('maps enabled, active and listener to the status line', () => {
    expect(statusKind(false, false, 'none')).toBe('off');
    expect(statusKind(true, true, 'ready')).toBe('on');
    expect(statusKind(true, false, 'pending')).toBe('connecting');
    expect(statusKind(true, false, 'ready')).toBe('connecting');
    expect(statusKind(true, false, 'none')).toBe('unset');
  });
  it('tells a missing listener from one still pending', async () => {
    const { c } = mk(false);
    await c.init();
    expect(c.listener()).toBe('pending');
    await c.setSid('s'.repeat(32));
    expect(c.listener()).toBe('pending');
    await c.setServer(null, null);
    expect(c.listener()).toBe('none');
    await c.setServer(null, 3130);
    expect(c.listener()).toBe('ready');
    await c.release();
    expect(c.listener()).toBe('pending');
  });
});

describe('ProxyController (fresh start, nothing persisted)', () => {
  function rig2(firefox: boolean, ms = 40) {
    const settings = { set: vi.fn(async () => {}), clear: vi.fn(async () => {}), get: vi.fn(async () => ({ value: undefined })) };
    const br = { proxy: { settings }, storage: { local: { get: vi.fn(async (k: string) => ({ [k]: { enabled: true, stores: {} } })), set: vi.fn() }, session: { get: vi.fn(async () => ({})), set: vi.fn(), remove: vi.fn() } } };
    return new ProxyController({ browser: br, firefox, argusHost: async () => 'argus.local', readyWaitMs: ms });
  }
  it('Firefox: waits for the welcome then routes to the listener, never direct', async () => {
    const c = rig2(true, 2000);
    await c.init();
    const p = c.route({ cookieStoreId: 'firefox-default', url: 'https://x.test/' });
    await new Promise((r) => setTimeout(r, 20));
    await c.setServer(null, 3130);
    await c.setSid('a'.repeat(32));
    expect(await p).toMatchObject({ type: 'socks', port: 3130 });
  });
  it('Firefox: no welcome in time fails closed (dead local port), Argus itself stays direct, sign-out is direct', async () => {
    const c = rig2(true);
    await c.init();
    expect(await c.route({ cookieStoreId: 'firefox-default', url: 'https://x.test/' })).toMatchObject({ type: 'socks', host: '127.0.0.1', port: 1 });
    expect(await c.route({ cookieStoreId: 'firefox-default', url: 'https://argus.local/api' })).toEqual({ type: 'direct' });
    await c.release();
    expect(await c.route({ cookieStoreId: 'firefox-default', url: 'https://x.test/' })).toEqual({ type: 'direct' });
  });
  it('is reported unreachable (popup and badge) 3s after a fresh start with no session, in both browsers', async () => {
    vi.useFakeTimers();
    try {
      for (const ff of [false, true]) {
        const c = rig2(ff);
        await c.init();
        expect(c.unreachable()).toBe(false);
        await vi.advanceTimersByTimeAsync(3500);
        expect(c.unreachable()).toBe(true);
        expect(statusKind(true, c.active(), c.listener(), c.unreachable())).toBe('blocked');
        await c.release();
        expect(c.unreachable()).toBe(false);
      }
    } finally { vi.useRealTimers(); }
  });
});

describe('ProxyController (fail closed, persisted session)', () => {
  function rig(opts: { enabled?: boolean; persisted?: unknown } = {}) {
    const settings = { set: vi.fn(async () => {}), clear: vi.fn(async () => {}), get: vi.fn(async () => ({ value: undefined })) };
    const local: Record<string, unknown> = { argusProxy: { enabled: opts.enabled ?? true, stores: {} } };
    const sess: Record<string, unknown> = opts.persisted ? { argusSession: opts.persisted } : {};
    const br = {
      proxy: { settings },
      storage: {
        local: { get: vi.fn(async (k: string) => ({ [k]: local[k] })), set: vi.fn(async (o: object) => { Object.assign(local, o); }) },
        session: { get: vi.fn(async (k: string) => ({ [k]: sess[k] })), set: vi.fn(async (o: object) => { Object.assign(sess, o); }), remove: vi.fn(async (k: string) => { delete sess[k]; }) },
      },
    };
    const onStatus = vi.fn();
    const c = new ProxyController({ browser: br, firefox: false, argusHost: async () => 'argus.local', readyWaitMs: 50, onStatus });
    return { c, settings, sess, onStatus };
  }
  const SID = 'a'.repeat(32);
  const persisted = { sid: SID, server: { host: null, port: 3130 } };

  it('persists the sid and server so a restarted worker has them', async () => {
    const { c, sess } = rig();
    await c.init();
    await c.setServer(null, 3130);
    await c.setSid(SID);
    expect(sess.argusSession).toEqual(persisted);
  });
  it('a worker start with a persisted session never clears the proxy, sets it, and answers at once', async () => {
    const { c, settings } = rig({ persisted });
    await c.init();
    expect(settings.clear).not.toHaveBeenCalled();
    expect((settings.set.mock.calls.at(-1) as any)[0].value.rules.singleProxy).toEqual({ scheme: 'http', host: 'argus.local', port: 3130 });
    expect(c.resumeSid()).toBe(SID);
    const t0 = Date.now();
    expect(await c.auth(ch())).toEqual({ authCredentials: { username: 'ext', password: SID } });
    expect(Date.now() - t0).toBeLessThan(40);
  });
  it('a worker start with nothing persisted and the toggle on leaves the proxy setting alone', async () => {
    const { c, settings } = rig();
    await c.init();
    expect(settings.clear).not.toHaveBeenCalled();
    expect(settings.set).not.toHaveBeenCalled();
  });
  it('does not rewrite an identical setting', async () => {
    const { c, settings } = rig({ persisted });
    settings.get.mockResolvedValue({ value: { mode: 'fixed_servers', rules: { singleProxy: { scheme: 'http', host: 'argus.local', port: 3130 }, bypassList: ['<local>', 'argus.local'] } } } as any);
    await c.init();
    expect(settings.set).not.toHaveBeenCalled();
  });
  it('a refused resume (new sid) replaces the sid; the next 407 is answered with it', async () => {
    const { c, sess } = rig({ persisted });
    await c.init();
    const first = ch();
    expect(await c.auth(first)).toMatchObject({ authCredentials: { password: SID } });
    expect(await c.auth(first)).toEqual({ cancel: true }); // once per request
    await c.setSid('b'.repeat(32));
    await c.setServer(null, 3130);
    expect((sess.argusSession as any).sid).toBe('b'.repeat(32));
    expect(await c.auth(first)).toEqual({ authCredentials: { username: 'ext', password: 'b'.repeat(32) } });
  });
  it('a resumed session (same sid) keeps the answered state and cookie-store tokens', async () => {
    const { c } = rig({ persisted });
    await c.init();
    const t = c.tokenFor('firefox-container-1');
    await c.setSid(SID);
    expect(c.storeForToken(t)).toBe('firefox-container-1');
  });
  it('a lost channel keeps the proxy, keeps answering with the grace sid, and reports unreachable after a while', async () => {
    vi.useFakeTimers();
    try {
      const { c, settings, onStatus } = rig();
      await c.init();
      await c.setServer(null, 3130);
      await c.setSid(SID);
      expect(c.unreachable()).toBe(false);
      await c.setSid(null);
      expect(settings.clear).not.toHaveBeenCalled();
      expect(c.active()).toBe(true);
      expect(c.unreachable()).toBe(false); // a worker restart gap is not shown
      expect(await c.auth(ch())).toEqual({ authCredentials: { username: 'ext', password: SID } });
      await vi.advanceTimersByTimeAsync(3500);
      expect(c.unreachable()).toBe(true);
      expect(onStatus).toHaveBeenCalled();
      expect(statusKind(true, c.active(), c.listener(), c.unreachable())).toBe('blocked');
      await c.setSid(SID); // back
      expect(c.unreachable()).toBe(false);
    } finally { vi.useRealTimers(); }
  });
  it('turning the toggle off clears the proxy; so does release (sign-out) and a server with no listener', async () => {
    const a = rig({ persisted });
    await a.c.init();
    await a.c.setState({ enabled: false, stores: {} });
    expect(a.settings.clear).toHaveBeenCalledTimes(1);
    const b = rig({ persisted });
    await b.c.init();
    await b.c.release();
    expect(b.settings.clear).toHaveBeenCalled();
    expect(b.sess.argusSession).toBeUndefined();
    expect(b.c.resumeSid()).toBeNull();
    const d = rig({ persisted });
    await d.c.init();
    await d.c.setServer(null, 0);
    expect(d.settings.clear).toHaveBeenCalled();
  });
});

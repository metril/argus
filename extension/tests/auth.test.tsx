import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import { render } from 'preact';
import { act } from 'preact/test-utils';
import { fetchCert } from '../lib/api';
import { normalizeUrl, signIn, signOut, signOutInBackground } from '../lib/auth';
import { CommandList, ErrorBanner, SignInForm } from '../ui/components';

const resp = (status: number, body: unknown = {}, headers: Record<string, string> = { 'content-type': 'application/json' }) =>
  new Response(JSON.stringify(body), { status, headers });
const refused = () => resp(403, '', { 'x-adblock': 'destination-refused' });

beforeEach(() => {
  (globalThis as any).browser = fakeBrowser;
  fakeBrowser.reset();
});
afterEach(() => vi.unstubAllGlobals());

describe('signIn', () => {
  it('stores settings (never the password) on success, replacing the old token', async () => {
    await fakeBrowser.storage.local.set({ argusUrl: 'https://a.lan', tokenId: 'old' });
    const f = vi.fn(async (..._a: unknown[]) => resp(200, { token: 'tok', token_id: 't1', user: { username: 'admin' } }));
    vi.stubGlobal('fetch', f);
    const r = await signIn('a.lan', 'admin', 'pw');
    expect(r.ok).toBe(true);
    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://a.lan/api/v1/auth/extension-token');
    expect(JSON.parse(String(init.body))).toMatchObject({ username: 'admin', browser: 'Chrome', replace_token_id: 'old' });
    const st = await fakeBrowser.storage.local.get();
    expect(st).toMatchObject({ argusUrl: 'https://a.lan', token: 'tok', tokenId: 't1', user: 'admin' });
    expect(JSON.stringify(st)).not.toContain('"pw"');
  });
  it.each([
    [401, () => resp(401), 'badCredentials'],
    [403, () => resp(403, { code: 'insufficient_scope' }), 'forbidden'],
    [429, () => resp(429), 'rateLimited'],
    [403, refused, 'unreachable'],
  ])('maps %i to %s', async (_s, res, kind) => {
    vi.stubGlobal('fetch', async () => res());
    expect(await signIn('https://a.lan', 'u', 'p')).toMatchObject({ ok: false, error: kind });
  });
  it('a refused destination is flagged, not an auth error', async () => {
    vi.stubGlobal('fetch', async () => refused());
    expect(await signIn('https://a.lan', 'u', 'p')).toMatchObject({ ok: false, error: 'unreachable', refused: true });
  });
  it('a network failure without host access is noHostPermission', async () => {
    vi.stubGlobal('fetch', async () => { throw new TypeError('x'); });
    (fakeBrowser as any).permissions = { contains: async () => false };
    expect(await signIn('https://a.lan', 'u', 'p')).toMatchObject({ ok: false, error: 'noHostPermission' });
  });
  it('normalizes addresses', () => {
    expect(normalizeUrl('argus.lan:8443/')).toBe('https://argus.lan:8443');
    expect(normalizeUrl('http://x.lan')).toBe('http://x.lan');
    expect(normalizeUrl('')).toBeNull();
  });
});

describe('signOut and 401', () => {
  it('revokes the token and clears storage but keeps the address', async () => {
    await fakeBrowser.storage.local.set({ argusUrl: 'https://a.lan', token: 'tok', tokenId: 't', user: 'u' });
    const f = vi.fn(async (..._a: unknown[]) => new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', f);
    await signOut();
    expect(f).toHaveBeenCalledWith('https://a.lan/api/v1/tokens/self', expect.objectContaining({ method: 'DELETE' }));
    expect(await fakeBrowser.storage.local.get()).toEqual({ argusUrl: 'https://a.lan' });
  });
  it('background sign-out removes the token before stopping, then revokes with the captured token', async () => {
    await fakeBrowser.storage.local.set({ argusUrl: 'https://a.lan', token: 'tok', tokenId: 't', user: 'u' });
    const order: string[] = [];
    const bridge = { stop: async () => { order.push('stop:' + JSON.stringify(await fakeBrowser.storage.local.get('token'))); } };
    const proxy = { apply: async () => { order.push('apply'); } };
    vi.stubGlobal('fetch', async (_u: string, init: any) => { order.push('revoke:' + init.headers.Authorization); return new Response(null, { status: 204 }); });
    await signOutInBackground({ bridge, proxy });
    expect(order).toEqual(['stop:{}', 'apply', 'revoke:Bearer tok']);
  });
  it('a hung revoke is cut off after 3s', async () => {
    vi.useFakeTimers();
    try {
      await fakeBrowser.storage.local.set({ argusUrl: 'https://a.lan', token: 'tok' });
      vi.stubGlobal('fetch', (_u: string, init: any) => new Promise((_r, rej) => init.signal.addEventListener('abort', () => rej(new Error('abort')))));
      const p = signOutInBackground({ bridge: { stop: async () => {} }, proxy: { apply: async () => {} } });
      await vi.advanceTimersByTimeAsync(3100);
      await p;
    } finally { vi.useRealTimers(); }
  });
  it('popup: worker asleep (sendMessage rejects) still removes the token and revokes', async () => {
    await fakeBrowser.storage.local.set({ argusUrl: 'https://a.lan', token: 'tok', tokenId: 't' });
    vi.spyOn((fakeBrowser as any).runtime, 'sendMessage').mockRejectedValue(new Error('no receiver'));
    const f = vi.fn(async (..._a: unknown[]) => new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', f);
    await signOut();
    expect(await fakeBrowser.storage.local.get()).toEqual({ argusUrl: 'https://a.lan' });
    expect(f).toHaveBeenCalled();
  });
  it('popup: a hanging background is abandoned after the wait, token removed regardless', async () => {
    vi.useFakeTimers();
    try {
      await fakeBrowser.storage.local.set({ argusUrl: 'https://a.lan', token: 'tok' });
      vi.spyOn((fakeBrowser as any).runtime, 'sendMessage').mockImplementation(() => new Promise(() => {}));
      vi.stubGlobal('fetch', async () => new Response(null, { status: 204 }));
      const p = signOut();
      await vi.advanceTimersByTimeAsync(1600);
      await p;
      expect(await fakeBrowser.storage.local.get()).toEqual({ argusUrl: 'https://a.lan' });
    } finally { vi.useRealTimers(); }
  });
  it('popup: when the background handled it, the popup does not repeat the revoke', async () => {
    await fakeBrowser.storage.local.set({ argusUrl: 'https://a.lan', token: 'tok' });
    vi.spyOn((fakeBrowser as any).runtime, 'sendMessage').mockResolvedValue(true);
    const f = vi.fn();
    vi.stubGlobal('fetch', f);
    await signOut();
    expect(f).not.toHaveBeenCalled();
  });
  it('a 401 on the API is a session error; a refused proxy is not', async () => {
    const s = { argusUrl: 'https://a.lan', token: 't' };
    vi.stubGlobal('fetch', async () => resp(401));
    expect(await fetchCert(s, 'x.com')).toEqual({ kind: 'error', error: 'sessionExpired' });
    vi.stubGlobal('fetch', async () => refused());
    expect(await fetchCert(s, 'x.com')).toEqual({ kind: 'error', error: 'unreachable', refused: true });
  });
});

describe('components', () => {
  it('sign-in form shows the expired banner', async () => {
    const root = document.createElement('div');
    await act(() => { render(<SignInForm expired />, root); });
    expect(root.querySelector('[role=alert]')?.textContent).toContain('Signed out');
    expect(root.querySelector('input[autocomplete=current-password]')).not.toBeNull();
  });
  it('a failed sign-in shows the error and a retry action', async () => {
    vi.stubGlobal('fetch', async () => { throw new TypeError('x'); });
    (fakeBrowser as any).permissions = { contains: async () => true };
    const root = document.createElement('div');
    document.body.append(root);
    await act(() => { render(<SignInForm />, root); });
    const set = (sel: string, v: string) => { const i = root.querySelector(sel) as HTMLInputElement; i.value = v; i.dispatchEvent(new Event('input', { bubbles: true })); };
    await act(() => { set('input[type=text]', 'argus.lan'); set('input[autocomplete=username]', 'u'); set('input[type=password]', 'p'); });
    await act(async () => { root.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); await new Promise((r) => setTimeout(r, 20)); });
    expect(root.querySelector('[role=alert]')?.textContent).toContain("Can't reach argus.lan");
    expect(root.textContent).toContain('Retry');
  });
  it('banners never show raw codes', () => {
    const root = document.createElement('div');
    render(<ErrorBanner error="forbidden" host="a.lan" />, root);
    expect(root.textContent).toBe('No extension accessAsk an admin.');
  });
  it('commands render as text and trigger', async () => {
    const root = document.createElement('div');
    const onTrigger = vi.fn();
    await act(() => { render(<CommandList commands={[{ script: 's', scriptName: '<i>S</i>', cmd: 'c', name: '<b>Go</b>', accessKey: 's' }]} onTrigger={onTrigger} />, root); });
    expect(root.querySelector('i,b')).toBeNull();
    const b = root.querySelector('button.cmd') as HTMLButtonElement;
    expect(b.textContent).toBe('<b>Go</b>');
    expect(b.dataset.key).toBe('S');
    b.click();
    expect(onTrigger).toHaveBeenCalled();
  });
});

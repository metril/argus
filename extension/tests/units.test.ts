import { describe, expect, it, vi } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import { decodeFrame, encodeFrame, payloadJson } from '../lib/frames';
import { connectAllows } from '../lib/connect';
import { cookieOp } from '../lib/cookies';
import { getSettings } from '../lib/api';

describe('frames', () => {
  it('round trips', () => {
    const f = decodeFrame(encodeFrame(2, 0xdeadbeef, new Uint8Array([1, 2, 3])))!;
    expect(f.type).toBe(2);
    expect(f.job).toBe(0xdeadbeef);
    expect(Array.from(f.payload)).toEqual([1, 2, 3]);
    const g = decodeFrame(encodeFrame(1, 7, { a: 'é' }))!;
    expect(payloadJson(g.payload)).toEqual({ a: 'é' });
    expect(decodeFrame(new Uint8Array(3))).toBeNull();
  });
});

describe('connectAllows', () => {
  const c = (list: string[], all = false) => ({ page: 'Page.com', list, all });
  const cases: [string[], boolean, string, boolean][] = [
    [[], false, 'page.com', true],
    [[], false, 'other.com', false],
    [['*'], false, 'other.com', false],
    [['a'], true, 'other.com', true],
    [['self'], false, 'page.com', true],
    [['localhost'], false, 'localhost', true],
    [['localhost'], false, 'localhost.evil.com', false],
    [['foo.*'], false, 'foo.com', true],
    [['foo.*'], false, 'x.foo.co.uk', true],
    [['foo.*'], false, 'foo', false],
    [['foo.*'], false, 'barfoo.com', false],
    [['*.b.com'], false, 'b.com', true],
    [['*.b.com'], false, 'a.B.com', true],
    [['b.com'], false, 'ab.com', false],
    [['b.com'], false, 'a.b.com', true],
    [['b.com'], false, 'b.com.evil.net', false],
    [['::1'], false, '[::1]', true],
  ];
  it.each(cases)('%j all=%s host=%s -> %s', (list, all, host, want) => {
    expect(connectAllows(c(list, all), host)).toBe(want);
  });
});

describe('cookies', () => {
  const store = [
    { name: 'a', value: '1', domain: 'x.com', path: '/', secure: true, httpOnly: false, sameSite: 'no_restriction', expirationDate: 5 },
    { name: 'h', value: 'secret', domain: 'x.com', path: '/', secure: true, httpOnly: true, sameSite: 'lax' },
  ];
  const br = () => ({
    cookies: {
      getAll: vi.fn(async ({ name }: any) => store.filter((c) => !name || c.name === name)),
      set: vi.fn(async () => ({})),
      remove: vi.fn(async () => ({})),
    },
  });
  it('list maps and filters httpOnly', async () => {
    const r = (await cookieOp(br(), { op: 'list', url: 'https://x.com/' })) as any[];
    expect(r).toEqual([{ name: 'a', value: '1', domain: 'x.com', path: '/', secure: true, http_only: false, same_site: 'none', expiration_date: 5 }]);
    expect(JSON.stringify(r)).not.toContain('secret');
  });
  it('set refuses httpOnly and overwrites of httpOnly', async () => {
    const b = br();
    await expect(cookieOp(b, { op: 'set', url: 'https://x.com/', cookie: { name: 'n', value: 'v', http_only: true } })).rejects.toMatchObject({ code: 'bad_request', message: 'httpOnly cookies are not accessible' });
    await expect(cookieOp(b, { op: 'set', url: 'https://x.com/', cookie: { name: 'h', value: 'v' } })).rejects.toMatchObject({ code: 'bad_request' });
    expect(b.cookies.set).not.toHaveBeenCalled();
    expect(await cookieOp(b, { op: 'set', url: 'https://x.com/', cookie: { name: 'a', value: 'v', same_site: 'none', expiration_date: 9 } })).toBeNull();
    expect(b.cookies.set).toHaveBeenCalledWith({ url: 'https://x.com/', name: 'a', value: 'v', sameSite: 'no_restriction', expirationDate: 9 });
  });
  it('delete refuses httpOnly', async () => {
    const b = br();
    await expect(cookieOp(b, { op: 'delete', url: 'https://x.com/', name: 'h' })).rejects.toMatchObject({ code: 'bad_request' });
    expect(await cookieOp(b, { op: 'delete', url: 'https://x.com/', name: 'a' })).toBeNull();
    expect(b.cookies.remove).toHaveBeenCalledWith({ url: 'https://x.com/', name: 'a' });
  });
});

describe('getSettings with fake browser', () => {
  it('reads storage', async () => {
    (globalThis as any).browser = fakeBrowser;
    await fakeBrowser.storage.local.set({ argusUrl: 'http://a:1/', token: 't' });
    expect(await getSettings()).toEqual({ argusUrl: 'http://a:1', token: 't' });
  });
});

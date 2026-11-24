import { describe, expect, it, vi } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import { decodeFrame, encodeFrame, payloadJson } from '../lib/frames';
import { connectAllows } from '../lib/connect';
import { buildRule } from '../lib/dnr';
import { cookieOp } from '../lib/cookies';
import { renderMenu } from '../lib/menu';
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

describe('buildRule', () => {
  it('null when no hosts', () => expect(buildRule('s', { wildcard: false, hosts: [] })).toBeNull());
  it('hosts rule', () => {
    const r = buildRule('sid1', { wildcard: false, hosts: ['a.com'], exclude: ['x.com'] })!;
    expect(r.id).toBe(1);
    expect(r.priority).toBe(1);
    expect(r.condition).toEqual({
      resourceTypes: ['main_frame', 'sub_frame'],
      requestDomains: ['a.com'],
      excludedRequestDomains: ['x.com'],
    });
    expect(r.action.requestHeaders).toEqual([{ header: 'X-Argus-Ext', operation: 'set', value: 'sid1' }]);
  });
  it('wildcard with exclude', () => {
    const r = buildRule('s', { wildcard: true, hosts: ['a.com'], exclude: ['x.com'] })!;
    expect(r.condition).toEqual({ resourceTypes: ['main_frame', 'sub_frame'], excludedRequestDomains: ['x.com'] });
    expect(buildRule('s', { wildcard: true, hosts: [] })!.condition).toEqual({ resourceTypes: ['main_frame', 'sub_frame'] });
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

describe('renderMenu', () => {
  it('inserts text, not html, and wires handlers', async () => {
    const root = document.createElement('div');
    const trigger = vi.fn(async () => true);
    const grant = vi.fn();
    const close = vi.fn();
    renderMenu(root, {
      commands: [{ script: 's1', scriptName: '<img src=x onerror=1>', cmd: 'c', name: '<b>Go</b>' }],
      grants: [{ script: 's1', scriptName: '<i>S</i>', host: 'a.com', patterns: ['*://a.com/*'] }],
    }, { trigger, grant, close });
    expect(root.querySelector('img,b,i')).toBeNull();
    expect(root.textContent).toContain('<b>Go</b>');
    expect(root.textContent).toContain('wants your logins for a.com');
    (root.querySelector('button.cmd') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 0));
    expect(trigger).toHaveBeenCalled();
    expect(close).toHaveBeenCalled();
    const gb = Array.from(root.querySelectorAll('button')).find((b) => b.textContent === 'Grant')!;
    gb.click();
    expect(grant).toHaveBeenCalled();
  });
  it('shows note when not delivered and keeps open', async () => {
    const root = document.createElement('div');
    const close = vi.fn();
    renderMenu(root, { commands: [{ script: 's', scriptName: 'S', cmd: 'c', name: 'N' }], grants: [] },
      { trigger: async () => false, grant: () => {}, close });
    (root.querySelector('button') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 0));
    expect(root.textContent).toContain('reload the page');
    expect(close).not.toHaveBeenCalled();
  });
});

describe('getSettings with fake browser', () => {
  it('reads storage', async () => {
    (globalThis as any).browser = fakeBrowser;
    await fakeBrowser.storage.local.set({ argusUrl: 'http://a:1/', token: 't' });
    expect(await getSettings()).toEqual({ argusUrl: 'http://a:1', token: 't' });
  });
});

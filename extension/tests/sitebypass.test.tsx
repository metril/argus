import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import { render } from 'preact';
import { act } from 'preact/test-utils';
import { clearCache } from '../lib/api';
import { emptyStats } from '../lib/stats';
import { App } from '../ui/popup';
import { settings } from '../ui/store';
import { reasonOf } from '../ui/sitebypass';

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const tick = () => act(async () => { await new Promise((r) => setTimeout(r, 0)); });
const st = (o: Record<string, unknown> = {}) => ({ host: 'a.example', bypassed: false, mode: null, source: 'none', name: null, removable: false, ev_auto_tunnel: true, ...o });
const EXT = st({ bypassed: true, mode: 'no_decrypt', source: 'extension', name: 'www.a.example', removable: true });

let root: HTMLElement;
let url: string;
let calls: string[];
/** The fake server: what GET returns, and what PUT / DELETE answer. */
let get: () => Response; let put: () => Response; let del: () => Response;
let hold: ((r: Response) => void) | undefined;

beforeEach(() => {
  (globalThis as any).browser = fakeBrowser;
  fakeBrowser.reset(); clearCache();
  root = document.createElement('div'); document.body.append(root);
  url = 'https://www.a.example/'; calls = []; hold = undefined;
  get = () => json(200, st()); put = () => json(200, EXT); del = () => json(200, st());
  settings.value = { argusUrl: 'https://argus.lan', token: 'tok' };
  const b: any = fakeBrowser;
  b.tabs.query = async () => [{ id: 7, url }];
  b.tabs.reload = vi.fn();
  b.runtime.sendMessage = async (m: { type: string }) => (m.type === 'tab-stats' ? { stats: emptyStats() } : m.type === 'interception' ? { route: 'argus' } : undefined);
  vi.stubGlobal('close', vi.fn());
  vi.stubGlobal('fetch', (u: string, init?: RequestInit) => {
    const path = new URL(u).pathname.replace('/api/v1', '');
    const method = init?.method ?? 'GET';
    if (path.startsWith('/bypass/sites/')) {
      calls.push(`${method} ${decodeURIComponent(path.slice('/bypass/sites/'.length))}`);
      if (hold && method === 'GET') return new Promise<Response>((r) => { hold = r; });
      return Promise.resolve(method === 'GET' ? get() : method === 'PUT' ? put() : del());
    }
    if (path.startsWith('/certs/by-host/')) return Promise.resolve(json(200, { verdict: 'valid', issuer: 'CN=CA', not_after: '2099-01-01T00:00:00Z', ev: false }));
    if (path.startsWith('/rules/site-exceptions/')) return Promise.resolve(json(200, { site: 'a.example', disabled: false }));
    return Promise.resolve(json(404, {}));
  });
});
afterEach(() => { render(null, root); root.remove(); vi.unstubAllGlobals(); });

const mount = async () => { await fakeBrowser.storage.local.set({ argusUrl: 'https://argus.lan', token: 'tok' }); await act(async () => { render(<App />, root); }); await tick(); await tick(); };
const q = (id: string) => root.querySelector<HTMLElement>(`[data-testid="${id}"]`);
const click = async (id: string) => { await act(async () => { q(id)!.click(); }); await tick(); await tick(); };
const row = () => q('site-bypass')!.textContent ?? '';

describe('Don\'t decrypt this site row', () => {
  it('sits in the slot under the grid and offers the action with its hint when the site is decrypted', async () => {
    await mount();
    expect(q('actions-slot')!.contains(q('site-bypass'))).toBe(true);
    expect(q('bypass-add')!.textContent).toBe("Don't decrypt this site");
    expect(q('bypass-add')!.getAttribute('title')).toBe('Argus stops inspecting and filtering this site.');
    expect(root.querySelector('#' + q('bypass-add')!.getAttribute('aria-describedby'))!.textContent).toBe('Argus stops inspecting and filtering this site.');
    expect(q('site-bypass')!.querySelector('.hint')).toBeNull();
    expect(calls).toEqual(['GET www.a.example']);
  });

  it('PUTs the active tab\'s host, shows the not-decrypted banner with Reload tab and Undo, and live status text', async () => {
    await mount();
    await click('bypass-add');
    expect(calls).toEqual(['GET www.a.example', 'PUT www.a.example']);
    expect(q('bypass-ext')).not.toBeNull();
    expect(row()).toContain('Not decrypted. Argus passes this site through unfiltered.');
    expect(row()).toContain('Reload tab to apply.');
    expect(q('bypass-ext')!.querySelector('[role=status]')).not.toBeNull();
    expect(q('bypass-add')).toBeNull();
  });

  it('Reload tab reloads the active tab and drops the reload hint but keeps the banner', async () => {
    await mount(); await click('bypass-add');
    await click('bypass-reload');
    expect((fakeBrowser.tabs as any).reload).toHaveBeenCalledWith(7);
    expect(q('bypass-ext')).not.toBeNull();
    expect(q('bypass-reload')).toBeNull();
    expect(row()).toContain('unfiltered.');
  });

  it('Undo removes the entry; the same reload hint applies, then the button is back after a reload', async () => {
    await mount(); await click('bypass-add');
    await click('bypass-undo');
    expect(calls.at(-1)).toBe('DELETE www.a.example');
    expect(q('bypass-undone')).not.toBeNull();
    expect(row()).toContain('Decrypting again.');
    await click('bypass-reload');
    expect((fakeBrowser.tabs as any).reload).toHaveBeenCalledWith(7);
    expect(q('bypass-add')).not.toBeNull();
  });

  it('an existing extension entry shows the banner with Undo and no reload hint', async () => {
    get = () => json(200, EXT);
    await mount();
    expect(q('bypass-ext')).not.toBeNull();
    expect(q('bypass-reload')).toBeNull();
    expect(q('bypass-undo')).not.toBeNull();
  });

  it.each([
    ['category', { source: 'category', name: 'Banking and finance' }, 'Not decrypted: Banking and finance category'],
    ['subscription', { source: 'subscription', name: 'My exclusions' }, 'Not decrypted: My exclusions list'],
    ['manual', { source: 'manual', name: 'a.example' }, 'Not decrypted: your Bypass list (a.example)'],
    ['failsafe', { source: 'failsafe', name: 'waiting for the Argus lists to load; HTTPS is tunnelled' }, 'Not decrypted: waiting for the Argus lists to load'],
  ])('a %s bypass is a read-only line naming the reason, with no button', async (_n, o, text) => {
    get = () => json(200, st({ bypassed: true, mode: 'no_decrypt', ...o }));
    await mount();
    expect(row()).toBe(text);
    expect(q('site-bypass')!.querySelector('button')).toBeNull();
  });

  it('reasonOf names the source', () => {
    expect(reasonOf(st({ source: 'category', name: 'Health' }) as any)).toBe('Health category');
  });

  it('a profile-restricted token says the profile does not allow it and never offers sign-in', async () => {
    get = () => json(403, { error: { code: 'profile_restricted', message: 'x' } });
    await mount();
    expect(row()).toBe("Your profile doesn't allow this.");
    expect(q('site-bypass')!.querySelector('button')).toBeNull();
  });

  it('a token without the scope says to sign in again and the link opens the sign-in form', async () => {
    get = () => json(403, { error: { code: 'insufficient_scope', message: 'x' } });
    await mount();
    expect(row()).toContain('Sign in again to use this.');
    await act(async () => { q('bypass-scope')!.querySelector('button')!.click(); }); await tick();
    expect(root.querySelector('form')).not.toBeNull();
  });

  it('a 403 on the change turns the row into the matching state', async () => {
    put = () => json(403, { error: { code: 'profile_restricted' } });
    await mount(); await click('bypass-add');
    expect(row()).toBe("Your profile doesn't allow this.");
    put = () => json(403, { error: { code: 'insufficient_scope' } });
    render(null, root); clearCache();
    await mount(); await click('bypass-add');
    expect(row()).toContain('Sign in again to use this.');
  });

  it('shows the server\'s reason when the limit is reached and keeps the button', async () => {
    put = () => json(409, { error: { code: 'site_bypass_limit', message: 'The extension already has 1000 sites that are not decrypted; remove some on the Bypass page' } });
    await mount(); await click('bypass-add');
    expect(q('bypass-note')!.textContent).toContain('remove some on the Bypass page');
    expect(q('bypass-add')).not.toBeNull();
  });

  it('a failed change without a message says to try again; Undo failing keeps the banner', async () => {
    put = () => json(500, {});
    await mount(); await click('bypass-add');
    expect(q('bypass-note')!.textContent).toBe('Could not change this site. Try again.');
    put = () => json(200, EXT); await click('bypass-add');
    del = () => json(409, { error: { code: 'not_extension_entry', message: 'a.example is bypassed by Banking' } });
    await click('bypass-undo');
    expect(q('bypass-note')!.textContent).toBe('a.example is bypassed by Banking');
    expect(q('bypass-ext')).not.toBeNull();
  });

  it('shows a placeholder of the row\'s height while loading, and a retry when the read fails', async () => {
    hold = () => {};
    await fakeBrowser.storage.local.set({ argusUrl: 'https://argus.lan', token: 'tok' });
    await act(async () => { render(<App />, root); }); await tick(); await tick();
    expect(q('bypass-loading')).not.toBeNull();
    render(null, root); hold = undefined; clearCache();
    get = () => json(500, {});
    await mount();
    expect(row()).toContain('Could not check this site.');
    get = () => json(200, st());
    await act(async () => { q('bypass-error')!.querySelector('button')!.click(); }); await tick(); await tick();
    expect(q('bypass-add')).not.toBeNull();
  });

  it('is absent on a page without a site', async () => {
    url = 'about:blank';
    await mount();
    expect(q('site-bypass')).toBeNull();
    expect(q('actions-slot')!.childElementCount).toBe(0);
    expect(calls).toEqual([]);
  });

  it('has no native checkbox or radio', async () => {
    await mount();
    expect(q('site-bypass')!.querySelector('input')).toBeNull();
  });
});

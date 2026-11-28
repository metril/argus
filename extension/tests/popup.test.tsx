import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import { render } from 'preact';
import { act } from 'preact/test-utils';
import { clearCache } from '../lib/api';
import { emptyStats, type TabStats } from '../lib/stats';
import { App } from '../ui/popup';
import { settings } from '../ui/store';

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const tick = () => act(async () => { await new Promise((r) => setTimeout(r, 0)); });
const cert = (issuer: string) => ({ verdict: 'valid', issuer: `CN=${issuer}`, not_after: '2099-01-01T00:00:00Z', ev: false });
const stat = (blocked: number, allowed: number, hosts: TabStats['hosts']): TabStats => ({ ...emptyStats(), blocked, allowed, hosts });

let root: HTMLElement;
let page: { id: number; url: string };
let tabStats: Record<number, TabStats>;
let exceptions: Set<string>;
let calls: { method: string; path: string }[];
let deferred: Record<string, (r: Response) => void>;
let hold: Set<string>;
let scopeless: boolean;
let extRules: string[];

beforeEach(() => {
  (globalThis as any).browser = fakeBrowser;
  fakeBrowser.reset();
  clearCache();
  root = document.createElement('div');
  document.body.append(root);
  page = { id: 1, url: 'https://www.a.example/' };
  tabStats = { 1: stat(3, 5, { 'ads.a.example': { blocked: 3, allowed: 0 }, 'www.a.example': { blocked: 0, allowed: 5 } }) };
  exceptions = new Set();
  extRules = []; calls = []; deferred = {}; hold = new Set(); scopeless = false;
  settings.value = { argusUrl: 'https://argus.lan', token: 'tok' };
  const b: any = fakeBrowser;
  b.tabs.query = async () => [{ id: page.id, url: page.url }];
  b.tabs.reload = vi.fn();
  b.runtime.sendMessage = async (m: { type: string; tabId?: number }) => {
    if (m.type === 'tab-stats') return { stats: tabStats[m.tabId!] };
    if (m.type === 'interception') return { route: 'argus' };
    return undefined;
  };
  vi.stubGlobal('close', vi.fn());
  vi.stubGlobal('fetch', (url: string, init?: RequestInit) => {
    const u = new URL(url);
    const path = u.pathname.replace('/api/v1', '');
    const method = init?.method ?? 'GET';
    calls.push({ method, path });
    if (path.startsWith('/certs/by-host/')) {
      const host = decodeURIComponent(path.split('/').pop()!);
      if (hold.has(host)) return new Promise<Response>((r) => { deferred[host] = r; });
      return Promise.resolve(json(200, cert(host.startsWith('www.a') ? 'A-CA' : 'B-CA')));
    }
    if (scopeless && (path.startsWith('/stats') || path.startsWith('/rules'))) return Promise.resolve(json(403, { error: { code: 'insufficient_scope' } }));
    if (path === '/stats/filter') return Promise.resolve(json(200, { total_requests: 12345, blocked_requests: 678, allowed_requests: 11667, lifetime_blocked: 900, lifetime_total: 20000, lifetime_by_category: { ads: 500, trackers: 300, social: 0, annoyances: 0, security: 0, other: 100 } }));
    if (path === '/stats/timeseries') return Promise.resolve(json(200, { range: 'd7', bucket_secs: 86400, points: [0, 1, 2].map((i) => ({ ts: 1_700_000_000 + i * 86400, requests: 10, blocked: i, by_category: { ads: i } })) }));
    if (path === '/ext/rules') {
      if (method === 'GET') return Promise.resolve(json(200, { site: u.searchParams.get('site'), rules: extRules.map((rule) => ({ rule, exclusive: true })) }));
      const b = JSON.parse(String(init?.body));
      const had = extRules.includes(b.rule);
      if (b.op === 'add' && !had) extRules.push(b.rule);
      if (b.op === 'remove') extRules = extRules.filter((r) => r !== b.rule);
      return Promise.resolve(json(200, { rule_count: extRules.length, changed: true }));
    }
    const m = path.match(/^\/rules\/site-exceptions\/(.+)$/);
    if (m) {
      const site = decodeURIComponent(m[1]!);
      if (method === 'PUT') exceptions.add(site);
      if (method === 'DELETE') exceptions.delete(site);
      return Promise.resolve(json(200, method === 'GET' ? { site, disabled: exceptions.has(site) } : { sites: [...exceptions] }));
    }
    return Promise.resolve(json(404, {}));
  });
});
afterEach(() => { render(null, root); root.remove(); vi.unstubAllGlobals(); });

const mount = async () => { await fakeBrowser.storage.local.set({ argusUrl: 'https://argus.lan', token: 'tok' }); await act(async () => { render(<App />, root); }); await tick(); await tick(); };
const text = (id: string) => root.querySelector(`[data-testid="${id}"]`)?.textContent ?? '';

describe('popup stats', () => {
  it('shows the page count, share, domains and the proxy totals alongside the existing cards', async () => {
    await mount();
    expect(text('page-blocked')).toBe('3');
    expect(text('page-percent')).toBe('38% of 8 requests');
    expect(root.querySelector('[data-host="ads.a.example"]')?.textContent).toContain('3');
    expect(root.querySelector('[data-host="www.a.example"] td:nth-child(3)')?.textContent).toBe('5');
    expect(text('domains-summary')).toBe('1 of 2 domains blocked');
    expect(root.textContent).toContain('This browser');
    expect(root.textContent).toContain('A-CA');
    expect(root.querySelector('[data-testid="open-logger"]')).not.toBeNull();
  });

  it('shows lifetime totals, categories and a chart under the Statistics toggle', async () => {
    await mount();
    const stats = [...root.querySelectorAll<HTMLButtonElement>('.seg button')].find((b) => b.textContent === 'Statistics')!;
    await act(async () => { stats.click(); });
    await tick(); await tick();
    expect(text('global-blocked')).toBe('900');
    expect(text('global-total')).toBe('of 20,000 requests');
    expect(root.querySelector('[data-cat="ads"]')?.textContent).toBe('500');
    expect(root.querySelector('[data-testid="chart"] path')?.getAttribute('d')).toMatch(/^M/);
    expect(root.querySelector('[data-testid="page-stats"]')).toBeNull();
  });
});

describe('per-site switch', () => {
  it('turns Argus off for the registrable domain with PUT, offers a reload, and back on with DELETE', async () => {
    await mount();
    const sw = root.querySelector<HTMLButtonElement>('[role=switch][aria-label="Argus on a.example"]')!;
    expect(sw.getAttribute('aria-checked')).toBe('true');
    await act(async () => { sw.click(); }); await tick();
    expect(calls).toContainEqual({ method: 'PUT', path: '/rules/site-exceptions/a.example' });
    expect(exceptions.has('a.example')).toBe(true);
    expect(sw.getAttribute('aria-checked')).toBe('false');
    const reload = [...root.querySelectorAll('button')].find((x) => x.textContent === 'Reload this page')!;
    await act(async () => { reload.click(); });
    expect((fakeBrowser.tabs as any).reload).toHaveBeenCalledWith(1);
    await act(async () => { sw.click(); }); await tick();
    expect(calls).toContainEqual({ method: 'DELETE', path: '/rules/site-exceptions/a.example' });
    expect(sw.getAttribute('aria-checked')).toBe('true');
  });
  it('reflects an exception that already exists', async () => {
    exceptions.add('a.example');
    await mount();
    expect(root.querySelector('[role=switch]')!.getAttribute('aria-checked')).toBe('false');
  });
  it('asks to sign in again when the token predates the scopes', async () => {
    scopeless = true;
    await mount();
    expect(root.textContent).toContain('Sign in again to enable page stats and the site switch');
    expect(root.querySelector('[role=switch]')).toBeNull();
  });
});

describe('following the active tab', () => {
  it('re-derives the site, cert and stats when the tab navigates, and drops a stale lookup', async () => {
    hold.add('www.a.example');
    await mount();
    // Navigate before page A's certificate lookup answers.
    tabStats[1] = stat(7, 1, { 'trk.b.example': { blocked: 7, allowed: 0 }, 'www.b.example': { blocked: 0, allowed: 1 } });
    page.url = 'https://www.b.example/';
    await act(async () => { (fakeBrowser.tabs.onUpdated as any).trigger(1, { url: page.url, status: 'loading' }, { id: 1, url: page.url }); });
    await tick(); await tick();
    expect(root.querySelector('.host')?.textContent).toBe('www.b.example');
    expect(root.textContent).toContain('B-CA');
    expect(text('page-blocked')).toBe('7');
    expect(root.querySelector('[data-host="trk.b.example"]')).not.toBeNull();
    expect(root.querySelector('[data-host="ads.a.example"]')).toBeNull();
    expect(root.querySelector('[role=switch]')?.getAttribute('aria-label')).toBe('Argus on b.example');
    // The late answer for page A must not overwrite page B.
    await act(async () => { deferred['www.a.example']!(json(200, cert('A-CA'))); });
    await tick();
    expect(root.textContent).toContain('B-CA');
    expect(root.textContent).not.toContain('A-CA');
  });
  it('also follows a switch to another tab', async () => {
    await mount();
    expect(root.querySelector('.host')?.textContent).toBe('www.a.example');
    page = { id: 2, url: 'https://www.b.example/' };
    tabStats[2] = stat(1, 0, { 'x.b.example': { blocked: 1, allowed: 0 } });
    await act(async () => { (fakeBrowser.tabs.onActivated as any).trigger({ tabId: 2, windowId: 1 }); });
    await tick(); await tick();
    expect(root.querySelector('.host')?.textContent).toBe('www.b.example');
    expect(text('page-blocked')).toBe('1');
  });
});

describe('per-domain grid and site rules', () => {
  beforeEach(() => { tabStats[1] = stat(4, 2, { 'ads.t.example': { blocked: 4, allowed: 0 }, 'cdn.u.example': { blocked: 0, allowed: 2 }, 'www.a.example': { blocked: 0, allowed: 0 } }); });
  const state = (h: string) => root.querySelector(`[data-host="${h}"] [aria-pressed="true"]`)?.getAttribute('data-state');
  const btn = (h: string, st: string) => root.querySelector<HTMLButtonElement>(`[data-host="${h}"] [data-state="${st}"]`)!;

  it('shows the state of existing rules, only for third-party hosts', async () => {
    extRules = ['||ads.t.example^$domain=a.example', '@@||cdn.u.example^$domain=a.example'];
    await mount();
    expect(state('ads.t.example')).toBe('block');
    expect(state('cdn.u.example')).toBe('allow');
    expect(root.querySelector('[data-host="www.a.example"] [data-testid="grid"]')).toBeNull();
  });

  it('writes block, allow and removes on default', async () => {
    await mount();
    expect(state('ads.t.example')).toBe('default');
    await act(async () => { btn('ads.t.example', 'block').click(); }); await tick();
    expect(extRules).toEqual(['||ads.t.example^$domain=a.example']);
    expect(state('ads.t.example')).toBe('block');
    await act(async () => { btn('ads.t.example', 'allow').click(); }); await tick(); await tick();
    expect(extRules).toEqual(['@@||ads.t.example^$domain=a.example']);
    await act(async () => { btn('ads.t.example', 'default').click(); }); await tick(); await tick();
    expect(extRules).toEqual([]);
    expect(state('ads.t.example')).toBe('default');
  });

  it('lists the site rules, removes one, and resets all', async () => {
    extRules = ['a.example##.promo', '||ads.t.example^$domain=a.example'];
    await mount();
    expect(root.querySelector('[data-testid="site-rules"]')?.textContent).toContain('a.example##.promo');
    await act(async () => { root.querySelector<HTMLButtonElement>('[aria-label="Remove a.example##.promo"]')!.click(); }); await tick();
    expect(extRules).toEqual(['||ads.t.example^$domain=a.example']);
    await act(async () => { root.querySelector<HTMLButtonElement>('[data-testid="reset-site"]')!.click(); });
    expect(extRules.length).toBe(1);
    await act(async () => { root.querySelector<HTMLButtonElement>('[data-testid="reset-yes"]')!.click(); }); await tick(); await tick();
    expect(extRules).toEqual([]);
    expect(root.querySelector('[data-testid="site-rules"]')).toBeNull();
  });

  it('arms the picker for the active tab', async () => {
    const sent: any[] = [];
    (fakeBrowser.runtime as any).sendMessage = async (m: any) => { sent.push(m); return m.type === 'picker-arm' ? { ok: true } : m.type === 'tab-stats' ? { stats: tabStats[1] } : { route: 'argus' }; };
    await mount();
    await act(async () => { root.querySelector<HTMLButtonElement>('[data-testid="pick"]')!.click(); }); await tick();
    expect(sent).toContainEqual({ type: 'picker-arm', tabId: 1, mode: 'picker' });
  });
});

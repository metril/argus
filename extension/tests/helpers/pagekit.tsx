import { render } from 'preact';
import { act } from 'preact/test-utils';
import { vi } from 'vitest';
import { clearToasts } from '../../ui/cookies/kit';
import { CookiesPage, type CmTab } from '../../ui/cookies/Page';
import { settings } from '../../ui/store';
import { cookieWorld, type World } from './cookiepage';
import { FIXTURE_URL, provenanceFetch, seedFixture, type ProvOpts } from './cookiefixture';

export const sleep = (ms = 0) => new Promise((r) => setTimeout(r, ms));
export const settle = (ms = 25) => act(async () => { await sleep(ms); });

export interface Page {
  w: World;
  root: HTMLElement;
  q<T extends HTMLElement = HTMLElement>(sel: string): T;
  qa<T extends HTMLElement = HTMLElement>(sel: string): T[];
  click(el: Element | null | undefined): Promise<void>;
  type(el: Element | null | undefined, v: string): Promise<void>;
  select(el: Element | null | undefined, v: string): Promise<void>;
  key(el: Element | null | undefined, key: string, o?: KeyboardEventInit): Promise<void>;
  text(sel?: string): string;
  button(label: string | RegExp, within?: ParentNode): HTMLButtonElement;
  waitFor(f: () => unknown, what?: string, ms?: number): Promise<void>;
  tab(name: string): Promise<void>;
  unmount(): void;
}

export interface MountOpts { prov?: ProvOpts['mode']; tab?: CmTab; tabs?: { id: number; url: string }[]; stores?: { id: string }[]; seed?: boolean; flavor?: 'chrome' | 'firefox'; hash?: string; records?: Record<string, unknown>[]; prepare?: (w: World) => void }

/** Mounts the real page on a fake browser, a real service behind an in-memory port, and a fetch that answers provenance. */
export async function mountPage(o: MountOpts = {}): Promise<Page> {
  const w = cookieWorld({ stores: o.stores ?? [{ id: '0' }, { id: '1' }, { id: '2' }], flavor: o.flavor ?? 'chrome', tabs: o.tabs ?? [{ id: 1, url: FIXTURE_URL }] });
  if (o.seed !== false) seedFixture(w.fb);
  o.prepare?.(w);
  (globalThis as any).browser = w.pageBrowser;
  location.hash = o.hash ?? '#tab=1';
  settings.value = { argusUrl: 'https://argus.lan', token: 'tok' };
  vi.stubGlobal('fetch', provenanceFetch({ mode: o.prov ?? 'on', ...(o.records ? { records: o.records } : {}) }));
  clearToasts();
  const root = document.createElement('div');
  document.body.append(root);
  await act(async () => { render(<CookiesPage client={w.client} {...(o.tab ? { tab: o.tab } : {})} />, root); });
  const p: Page = {
    w, root,
    q: (sel) => { const e = root.querySelector(sel); if (!e) throw new Error(`missing ${sel}`); return e as never; },
    qa: (sel) => [...root.querySelectorAll(sel)] as never,
    click: async (el) => { if (!el) throw new Error('click: no element'); await act(async () => { (el as HTMLElement).click(); }); await settle(); },
    type: async (el, v) => { if (!el) throw new Error('type: no element'); await act(async () => { (el as HTMLInputElement).value = v; el.dispatchEvent(new Event('input', { bubbles: true })); }); await settle(30); },
    select: async (el, v) => { if (!el) throw new Error('select: no element'); await act(async () => { (el as HTMLSelectElement).value = v; el.dispatchEvent(new Event('change', { bubbles: true })); }); await settle(); },
    key: async (el, key, init = {}) => { await act(async () => { (el ?? document.body).dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...init })); }); await settle(); },
    text: (sel) => (sel ? p.q(sel).textContent ?? '' : root.textContent ?? ''),
    button: (label, within = root) => {
      const b = [...within.querySelectorAll('button')].find((x) => (label instanceof RegExp ? label.test(x.textContent ?? '') : (x.textContent ?? '').trim() === label));
      if (!b) throw new Error(`no button ${label}`);
      return b as HTMLButtonElement;
    },
    waitFor: async (f, what = 'condition', ms = 1500) => {
      const end = Date.now() + ms;
      while (Date.now() < end) { try { if (f()) return; } catch { /* not yet */ } await settle(15); }
      throw new Error(`timed out: ${what}`);
    },
    tab: async (name) => { await p.click([...root.querySelectorAll('[role=tab]')].find((t) => t.textContent === name)); await settle(40); },
    unmount: () => { render(null, root); root.remove(); },
  };
  await p.waitFor(() => !root.textContent?.includes('Loading cookies'), 'cookies loaded');
  await settle(40);
  return p;
}

export const rowNames = (p: Page): string[] => p.qa('table[data-testid=cookie-table] tbody tr[data-row] td.nm .lnk').map((e) => e.textContent ?? '');

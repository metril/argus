import { render } from 'preact';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import '../ui/tokens.css';
import '../ui/ui.css';
import { App } from '../ui/popup';
import { settings } from '../ui/store';

// Dev-only: the real popup with a stubbed browser and Argus API. ?theme=dark|light &view=stats &site=https://www.stackoverflow.com/ &bypass=off|ext|category|restricted|scope|error|loading|none (none: a page without a site)
const q = new URLSearchParams(location.search);
document.documentElement.dataset.theme = q.get('theme') ?? 'light';
document.body.style.cssText = 'margin:16px auto;width:360px;background:var(--bg)';

const bypass = q.get('bypass') ?? 'off';
const url = (bypass === 'none' ? 'about:blank' : null) ?? q.get('site') ?? 'https://www.stackoverflow.com/questions/11227809';
const stats = { blocked: 17, redirected: 0, allowed: 41, failed: 0, pending: [], hosts: { 'ads.stackoverflow.com': { blocked: 12, allowed: 0 }, 'www.stackoverflow.com': { blocked: 0, allowed: 30 }, 'trk.example.net': { blocked: 5, allowed: 0 } } };
const b: any = fakeBrowser;
await b.storage.local.set({ argusUrl: 'https://argus.lan', token: 'tok', user: 'laptop' });
b.tabs.query = async () => [{ id: 1, url }];
b.tabs.create = async () => ({});
b.runtime.sendMessage = async (m: { type: string }) => {
  if (m.type === 'tab-stats') return { stats };
  if (m.type === 'interception') return { route: 'argus' };
  if (m.type === 'bridge-status') return { connected: true, sid: 's1' };
  if (m.type === 'proxy-get') return { state: { enabled: true, stores: {} }, active: true, listener: 'ready', firefox: false };
  return undefined;
};
(globalThis as any).browser = b;
settings.value = { argusUrl: 'https://argus.lan', token: 'tok', user: 'laptop' };
const json = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }));
const siteState = (o: Record<string, unknown>) => ({ host: 'www.stackoverflow.com', bypassed: false, mode: null, source: 'none', name: null, removable: false, ev_auto_tunnel: true, ...o });
const bypassNow: Record<string, () => Promise<Response>> = {
  off: () => json(siteState({})),
  ext: () => json(siteState({ bypassed: true, mode: 'no_decrypt', source: 'extension', name: 'www.stackoverflow.com', removable: true })),
  category: () => json(siteState({ bypassed: true, mode: 'no_decrypt', source: 'category', name: 'Banking and finance' })),
  restricted: () => json({ error: { code: 'profile_restricted', message: 'x' } }, 403),
  scope: () => json({ error: { code: 'insufficient_scope', message: 'x' } }, 403),
  error: () => json({}, 500),
  loading: () => new Promise<Response>(() => {}),
  none: () => json(siteState({})),
};
let ext = bypass === 'ext';
globalThis.fetch = ((u: string, init?: RequestInit) => {
  const path = new URL(u).pathname.replace('/api/v1', '');
  if (path.startsWith('/bypass/sites/')) {
    const m = init?.method ?? 'GET';
    if (m === 'PUT') ext = true; else if (m === 'DELETE') ext = false;
    if (m !== 'GET') return json(siteState(ext ? { bypassed: true, mode: 'no_decrypt', source: 'extension', name: 'www.stackoverflow.com', removable: true } : {}));
    return ext && bypass === 'off' ? json(siteState({ bypassed: true, mode: 'no_decrypt', source: 'extension', removable: true })) : bypassNow[bypass]!();
  }
  if (path.startsWith('/certs/by-host/')) return json({ verdict: 'valid', issuer: 'CN=Sectigo RSA DV', not_before: '2026-01-01T00:00:00Z', not_after: '2027-03-01T00:00:00Z', ev: false, fp: 'ab12cd34ef56', sans: ['stackoverflow.com'], subject: 'CN=stackoverflow.com' });
  if (path === '/stats/filter') return json({ total_requests: 12345, blocked_requests: 678, allowed_requests: 11667, lifetime_blocked: 1284, lifetime_total: 11056, lifetime_by_category: { ads: 700, trackers: 400, social: 80, annoyances: 60, security: 4, other: 40 } });
  if (path === '/stats/timeseries') return json({ range: 'd7', bucket_secs: 86400, points: Array.from({ length: 7 }, (_, i) => ({ ts: 1_790_000_000 + i * 86400, requests: 100, blocked: 10 + i * 3, by_category: { ads: i + 4 } })) });
  if (path === '/ext/rules') return json({ site: 'stackoverflow.com', rules: [] });
  if (path.startsWith('/rules/site-exceptions/')) return json({ site: 'stackoverflow.com', disabled: false });
  return json({}, 404);
}) as typeof fetch;

const app = document.getElementById('app')!;
render(<App />, app);
if (q.get('view') === 'stats') setTimeout(() => (app.querySelector('[role=radio]:last-child') as HTMLElement | null)?.click(), 300);
(window as any).__ready = true;

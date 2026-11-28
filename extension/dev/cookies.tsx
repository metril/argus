import { render } from 'preact';
import '../ui/tokens.css';
import '../ui/ui.css';
import '../ui/cookies.css';
import { CookiesPage, type CmTab } from '../ui/cookies/Page';
import { settings } from '../ui/store';
import { cookieWorld } from '../tests/helpers/cookiepage';
import { FIXTURE_URL, provenanceFetch, seedFixture } from '../tests/helpers/cookiefixture';

// Dev-only: the real page on a fake browser. ?theme=dark|light &prov=on|off|404 &tab=cookies|snaps|log|rules &n=extra cookies &live=1
const q = new URLSearchParams(location.search);
document.documentElement.dataset.theme = q.get('theme') ?? 'light';
const prov = (q.get('prov') ?? 'on') as 'on' | 'off' | '404';

const w = cookieWorld({
  flavor: 'firefox',
  stores: [{ id: 'firefox-default' }, { id: 'firefox-container-1' }, { id: 'firefox-container-2' }, { id: 'firefox-private' }],
  identities: [{ cookieStoreId: 'firefox-container-1', name: 'Work' }, { cookieStoreId: 'firefox-container-2', name: 'Personal' }],
  tabs: [{ id: 1, url: FIXTURE_URL }],
});
seedFixture(w.fb);
const extra = Number(q.get('n') ?? 0);
const t = Math.floor(Date.now() / 1000);
for (let i = 0; i < extra; i++) w.fb.seed({ name: `bulk_${String(i).padStart(5, '0')}`, value: `v${i}`, domain: `h${i % 80}.example.org`, secure: i % 3 === 0, expirationDate: t + 86400 * (1 + (i % 400)) });

(globalThis as any).browser = w.pageBrowser;
if (!location.hash) location.hash = '#tab=1';
settings.value = { argusUrl: 'https://argus.lan', token: 'tok' };
const real = provenanceFetch({ mode: prov });
globalThis.fetch = ((url: string, init?: RequestInit) => {
  if (new URL(url).pathname.endsWith('/ext/rules')) return Promise.resolve(new Response(JSON.stringify({ rule_count: 5, changed: true }), { status: 200, headers: { 'content-type': 'application/json' } }));
  return real(url, init);
}) as typeof fetch;

// Some history for the Activity tab.
async function history() {
  const c = w.br.cookies;
  const url = 'https://www.stackoverflow.com/';
  await c.set({ url, name: 'theme', value: 'dark', storeId: 'firefox-default', firstPartyDomain: '' });
  await c.set({ url, name: '_ga', value: 'GA1.2.1', domain: '.stackoverflow.com', expirationDate: t + 604800, storeId: 'firefox-default', firstPartyDomain: '' });
  await c.set({ url, name: 'theme', value: 'light', storeId: 'firefox-default', firstPartyDomain: '' });
  await c.remove({ url, name: 'theme', storeId: 'firefox-default', firstPartyDomain: '' });
  const probe = w.fb.seed({ name: 'autoplay', value: '1', domain: 'video.example.net', storeId: 'firefox-default' });
  w.fb.expire(probe);
  const ev = w.fb.seed({ name: 'old_cache', value: '1', domain: 'news.example.org', storeId: 'firefox-default' });
  w.fb.evict(ev);
  await c.set({ url: 'https://news.example.org/', name: 'paywall_count', value: '4', expirationDate: t + 86400 * 30, storeId: 'firefox-default', firstPartyDomain: '' });
}
void history().then(() => {
  render(<CookiesPage client={w.client} tab={(q.get('tab') ?? 'cookies') as CmTab} />, document.getElementById('app')!);
  (window as any).__ready = true;
});
(window as any).__world = w;

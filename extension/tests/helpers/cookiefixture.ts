import type { FakeBrowser } from './fakebrowser';

/** The sample browser the visual harness and the page tests share (the mockup's data, as real cookies). */
export const FIXTURE_SITE = 'stackoverflow.com';
export const FIXTURE_URL = `https://www.${FIXTURE_SITE}/questions/11227809`;

const DAY = 86400;

export function seedFixture(fb: FakeBrowser, now = Date.now()): void {
  const t = Math.floor(now / 1000);
  const store = fb.defaultStore;
  const s = (p: Record<string, unknown>) => fb.seed({ storeId: store, ...p });
  const secureNone = { secure: true, sameSite: 'no_restriction' };
  s({ name: '__Host-sosid', value: 'a1f9c0d4e8b2776f3a90', domain: 'stackoverflow.com', secure: true, httpOnly: true, sameSite: 'lax', expirationDate: t + 30 * DAY });
  s({ name: 'acct', value: 't=Xk29sQv&s=7Hq0pLm', domain: '.stackoverflow.com', secure: true, httpOnly: true, sameSite: 'lax' });
  s({ name: '_ga', value: 'GA1.2.1873245501.1790000000', domain: '.stackoverflow.com', expirationDate: t + 7 * DAY });
  s({ name: '_ga_9XK2LP', value: 'GS1.2.1790.s1.t1', domain: '.stackoverflow.com', expirationDate: t + 7 * DAY });
  s({ name: 'OptanonConsent', value: 'isGpcEnabled=0&datestamp=2026-11-28&version=6.10', domain: '.stackoverflow.com', sameSite: 'lax', expirationDate: t + 365 * DAY });
  s({ name: 'prefs', value: 'theme%3Dlight', domain: 'stackoverflow.com', secure: true, sameSite: 'lax' });
  s({ name: '__cf_bm', value: 'xYz81Qe0c_9a.Lk-1790', domain: '.stackoverflow.com', ...secureNone, httpOnly: true, expirationDate: t + 1800 });
  s({ name: '__Secure-tp-embed', value: 'w9a1c2e7', domain: '.embed-widgets.example.net', ...secureNone, expirationDate: t + 90 * DAY, partitionKey: { topLevelSite: 'https://stackoverflow.com' } });
  s({ name: 'session_id', value: '9c1e77aa0b4d5f', domain: 'news.example.org', secure: true, httpOnly: true, sameSite: 'lax' });
  s({ name: '__Secure-consent', value: 'v2.analytics=0', domain: '.news.example.org', secure: true, sameSite: 'lax', expirationDate: t + 180 * DAY });
  s({ name: 'paywall_count', value: '3', domain: 'news.example.org', sameSite: 'lax', expirationDate: t + 30 * DAY });
  s({ name: 'theme', value: 'dark', domain: 'news.example.org', sameSite: 'lax' });
  s({ name: '_ga', value: 'GA1.2.55012299.1788000000', domain: '.news.example.org', expirationDate: t + 7 * DAY });
  s({ name: 'PREF', value: 'f1=50000000&tz=UTC', domain: '.video.example.net', ...secureNone, expirationDate: t + 400 * DAY });
  s({ name: 'watch_hist', value: 'v=a81b2;v=c04d9'.replace(';', '|'), domain: 'video.example.net', sameSite: 'lax', expirationDate: t + 180 * DAY });
  s({ name: 'CONSENT', value: 'YES+cb.20261128', domain: '.video.example.net', ...secureNone });
  // Other stores, when the fake has them.
  const others = fb.stores.map((x) => x.id).filter((id) => id !== store);
  if (others[0]) fb.seed({ storeId: others[0], name: 'cart_id', value: 'c_77f0a9be12', domain: 'shop.example.com', secure: true, sameSite: 'lax', expirationDate: t + 14 * DAY });
  if (others[0]) fb.seed({ storeId: others[0], name: '__Host-csrf', value: 'q8Zm2kLw0p', domain: 'shop.example.com', secure: true, httpOnly: true, sameSite: 'strict' });
  if (others[1]) fb.seed({ storeId: others[1], name: 'autoplay', value: 'off', domain: 'video.example.net', sameSite: 'lax' });
}

/** The wire records of `GET /ext/cookies/provenance` that go with the fixture. */
export function fixtureWire(now = Date.now()): Record<string, unknown>[] {
  const at = (minAgo: number) => new Date(now - minAgo * 60_000).toISOString();
  const rec = (time: string, name: string, host: string, path: string, attrs: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) => ({ time, name, host, path, attrs, ...extra });
  return [
    rec(at(40), '__Host-sosid', 'stackoverflow.com', '/users/login', { path: '/', secure: true, http_only: true, same_site: 'lax', max_age: 30 * DAY }),
    rec(at(40), 'acct', 'stackoverflow.com', '/', { domain: '.stackoverflow.com', secure: true, http_only: true, same_site: 'lax' }),
    rec(at(40), '_ga', 'stackoverflow.com', '/', { domain: '.stackoverflow.com', max_age: 365 * DAY }, { effect: 'changed', rule: '||stackoverflow.com^$cookie=_ga;maxAge=604800', list_id: 'argus-base', list_name: 'Argus Base', line: 51 }),
    rec(at(40), '_ga_9XK2LP', 'stackoverflow.com', '/', { domain: '.stackoverflow.com', max_age: 2 * 365 * DAY }, { effect: 'changed', rule: '||stackoverflow.com^$cookie=/^_ga_/;maxAge=604800', list_id: 'argus-base', list_name: 'Argus Base', line: 52 }),
    rec(at(40), 'OptanonConsent', 'stackoverflow.com', '/', { domain: '.stackoverflow.com', same_site: 'lax', max_age: 365 * DAY }),
    rec(at(28), '__cf_bm', 'stackoverflow.com', '/questions/11227809', { domain: '.stackoverflow.com', path: '/', secure: true, http_only: true, same_site: 'none', max_age: 1800 }),
    rec(at(26), '__Secure-tp-embed', 'embed-widgets.example.net', '/widget/init', { domain: '.embed-widgets.example.net', path: '/', secure: true, same_site: 'none', max_age: 90 * DAY, partitioned: true }),
    rec(at(40), '_gid', 'stackoverflow.com', '/', { domain: '.stackoverflow.com', max_age: DAY }, { effect: 'stripped', rule: '||stackoverflow.com^$cookie=_gid', list_id: 'easyprivacy', list_name: 'EasyPrivacy', line: 1204 }),
    rec(at(27), '_pxid', 'pixel-sample.example', '/t.gif', { domain: '.pixel-sample.example', secure: true, same_site: 'none', max_age: 365 * DAY }, { effect: 'stripped', rule: '||pixel-sample.example^$cookie', list_id: 'adg-tracking', list_name: 'AdGuard Tracking Protection', line: 88211 }),
    rec(at(90), 'session_id', 'news.example.org', '/login', { secure: true, http_only: true, same_site: 'lax' }),
  ];
}

export interface ProvOpts { mode: 'on' | 'off' | '404'; records?: Record<string, unknown>[]; calls?: { path: string; sid: string | null; search: string }[] }

/** A `fetch` answering the provenance route (and 404 for anything else). */
export function provenanceFetch(o: ProvOpts) {
  return (url: string, init?: RequestInit): Promise<Response> => {
    const u = new URL(url);
    const j = (status: number, body: unknown) => Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }));
    if (u.pathname.endsWith('/ext/cookies/provenance')) {
      const h = new Headers(init?.headers as HeadersInit);
      o.calls?.push({ path: u.pathname, sid: h.get('x-argus-session'), search: u.search });
      if (o.mode === '404') return j(404, { error: { code: 'not_found' } });
      if (o.mode === 'off') return j(200, { status: 'disabled' });
      return j(200, { records: o.records ?? fixtureWire() });
    }
    return j(404, {});
  };
}

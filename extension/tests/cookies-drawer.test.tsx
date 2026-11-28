import { afterEach, describe, expect, it, vi } from 'vitest';
import { provenanceFetch } from './helpers/cookiefixture';
import { mountPage, rowNames, settle, type Page } from './helpers/pagekit';

let page: Page | undefined;
afterEach(() => { page?.unmount(); page = undefined; vi.unstubAllGlobals(); });
const mount: typeof mountPage = async (o) => (page = await mountPage(o));

const open = async (p: Page, name: string) => {
  await p.click(p.qa('td.nm .lnk').find((e) => e.textContent === name));
  await p.waitFor(() => document.querySelector('[data-testid=cookie-drawer]'), 'drawer');
  await settle(200);
};
const json = (status: number, body: unknown) => Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }));

describe('detail drawer', () => {
  it("shows the library's live validation reasons and blocks Save until they are fixed", async () => {
    const p = await mount();
    await open(p, '__Host-sosid');
    const save = () => p.q<HTMLButtonElement>('#dsave');
    await p.waitFor(() => p.text('#vmsg').includes('Looks valid'), 'valid');
    expect(save().disabled).toBe(false);
    await p.click(p.q('#dho'));
    await p.waitFor(() => p.text('#vmsg').includes('__Host-'), 'host rule reason');
    expect(p.text('#vmsg')).toContain('must not set a Domain');
    expect(save().disabled).toBe(true);
    await p.click(p.q('#dho'));
    await p.waitFor(() => save().disabled === false, 'fixed');
  });

  it('edits a cookie (set new, remove old) and closes with a confirmation', async () => {
    const p = await mount();
    await open(p, 'prefs');
    await p.type(p.q('#dv'), 'theme%3Ddark');
    await p.waitFor(() => !p.q<HTMLButtonElement>('#dsave').disabled, 'save enabled');
    await p.click(p.q('#dsave'));
    await p.waitFor(() => !document.querySelector('[data-testid=cookie-drawer]'), 'closed');
    expect(p.w.fb.all().find((c) => c.name === 'prefs')?.value).toBe('theme%3Ddark');
    expect(p.text('#toasts')).toContain('Cookie saved');
  });

  it('adds a cookie from the toolbar', async () => {
    const p = await mount();
    await p.click(p.button('Add cookie'));
    await p.type(p.q('#dn'), 'fresh');
    await p.type(p.q('#dv'), 'x');
    await p.waitFor(() => !p.q<HTMLButtonElement>('#dsave').disabled, 'valid');
    await p.click(p.q('#dsave'));
    await p.waitFor(() => p.w.fb.all().some((c) => c.name === 'fresh' && c.domain === 'stackoverflow.com'), 'created');
  });

  it('duplicates and deletes with an in-place two-step confirm, and Undo restores', async () => {
    const p = await mount();
    await open(p, 'OptanonConsent');
    await p.click(p.button('Duplicate'));
    await p.waitFor(() => p.w.fb.all().some((c) => c.name === 'OptanonConsent-copy'), 'duplicate');
    await open(p, 'OptanonConsent-copy');
    const del = p.q<HTMLButtonElement>('[data-testid=drawer-delete]');
    await p.click(del);
    expect(del.textContent).toBe('Delete?');
    expect(p.w.fb.all().some((c) => c.name === 'OptanonConsent-copy')).toBe(true);
    await p.click(del);
    await p.waitFor(() => !p.w.fb.all().some((c) => c.name === 'OptanonConsent-copy'), 'deleted');
    await p.click(p.button('Undo'));
    await p.waitFor(() => p.w.fb.all().some((c) => c.name === 'OptanonConsent-copy'), 'undone');
  });

  it('copies to another store and asks what to do when it already exists there', async () => {
    const p = await mount();
    await open(p, 'prefs');
    await p.select(p.q('select[aria-label="Target store"]'), '1');
    await p.click(p.button('Copy'));
    await p.waitFor(() => p.w.fb.all().some((c) => c.name === 'prefs' && c.storeId === '1'), 'copied');
    await open(p, 'prefs');
    await p.select(p.q('select[aria-label="Target store"]'), '1');
    await p.click(p.button('Copy'));
    await p.waitFor(() => p.root.textContent!.includes('already has this cookie'), 'conflict asked');
    await p.click(p.button('Skip'));
    expect(p.w.fb.all().filter((c) => c.name === 'prefs' && c.storeId === '1')).toHaveLength(1);
  });

  it('Esc closes the drawer and gives focus back to the row that opened it', async () => {
    const p = await mount();
    const link = p.qa('td.nm .lnk').find((e) => e.textContent === 'acct')!;
    link.focus();
    await open(p, 'acct');
    await p.key(p.q('[data-testid=cookie-drawer]'), 'Escape');
    expect(document.querySelector('[data-testid=cookie-drawer]')).toBeNull();
    expect(document.activeElement).toBe(link);
  });
});

describe('provenance', () => {
  it('on: Source column, Changed by rule pills, sent-vs-stored, rule line and list link', async () => {
    const p = await mount({ prov: 'on' });
    expect(p.qa('thead th').map((t) => t.textContent)).toContain('Source');
    const ga = p.qa('tr[data-row]').find((r) => r.querySelector('.nm')?.textContent === '_ga')!;
    expect(ga.textContent).toContain('Response from stackoverflow.com');
    expect(ga.textContent).toContain('Changed by rule');
    const prefs = p.qa('tr[data-row]').find((r) => r.querySelector('.nm')?.textContent === 'prefs')!;
    expect(prefs.textContent).toContain('Not seen in transit');
    await open(p, '_ga');
    const prov = p.text('#prov');
    expect(prov).toContain('stackoverflow.com/');
    expect(prov).toMatch(/Lifetime: 1 year → capped to 7 days/);
    expect(prov).toContain('||stackoverflow.com^$cookie=_ga;maxAge=604800');
    expect(prov).toContain('Argus Base');
    expect(prov).toContain('Max-Age: 1 year → 7 days');
    expect(p.q<HTMLAnchorElement>('#prov a').getAttribute('href')).toBe('https://argus.lan/filters/argus-base?q=%7C%7Cstackoverflow.com%5E%24cookie%3D_ga%3BmaxAge%3D604800');
    expect(prov).toContain('History covers recent activity in this browser session.');
  });

  it('on: a request a rule kept the cookie out of is listed under "Kept out of requests"', async () => {
    const p = await mount({ prov: 'on' });
    await p.click(p.q('[role=radio][aria-checked=false]'));
    await open(p, 'paywall_count');
    const prov = p.text('#prov');
    expect(prov).toContain('Kept out of requests');
    expect(prov).toContain('Once, last ');
    expect(prov).toContain('news.example.org');
    expect(prov).toContain('||news.example.org^$cookie=paywall_count');
    expect(prov).toContain('Your rules');
    // A cookie nothing was kept out of has no such line.
    await p.click(p.q('[data-testid=cookie-drawer] button[aria-label="Close"]'));
    await open(p, 'theme');
    expect(p.text('#prov')).not.toContain('Kept out of requests');
  });

  it('on: a cookie with no record says it was not seen in transit', async () => {
    const p = await mount({ prov: 'on' });
    await open(p, 'prefs');
    expect(p.text('#prov')).toContain('Not seen in transit.');
  });

  it('on: each changed attribute names the rule whose value won, with a link to that rule', async () => {
    const p = await mount({ prov: 'on' });
    await open(p, '_ga_9XK2LP');
    const prov = p.text('#prov');
    expect(prov).toContain('||stackoverflow.com^$cookie=/^_ga_/;maxAge=604800');
    expect(prov).toContain('||stackoverflow.com^$cookie=/^_ga_/;sameSite=lax');
    expect(prov).toContain('Max-Age: 2 years → 7 days');
    expect(prov).toContain('SameSite: None → Lax');
    expect(prov).toContain('Your rules');
    const hrefs = p.qa<HTMLAnchorElement>('#prov a').map((a) => a.getAttribute('href'));
    expect(hrefs).toEqual([
      'https://argus.lan/filters/argus-base?q=' + encodeURIComponent('||stackoverflow.com^$cookie=/^_ga_/;maxAge=604800'),
      'https://argus.lan/filters/custom?q=' + encodeURIComponent('||stackoverflow.com^$cookie=/^_ga_/;sameSite=lax'),
    ]);
  });

  it('on: Stripped by Argus lists cookies a rule removed, read-only', async () => {
    const p = await mount({ prov: 'on' });
    await p.click(p.button('Stripped by Argus'));
    expect(rowNames(p).sort()).toEqual(['_gid', '_pxid']);
    expect(p.qa('tr[data-row] button[role=checkbox]').every((b) => (b as HTMLButtonElement).disabled)).toBe(true);
    await open(p, '_gid');
    expect(p.text('[data-testid=cookie-drawer]')).toContain('cannot be edited');
    expect(p.q<HTMLInputElement>('#dn').disabled).toBe(true);
    expect(document.querySelector('#dsave')).toBeNull();
    expect(p.text('#prov')).toContain('Stripped by');
  });

  for (const mode of ['off', '404'] as const) {
    it(`${mode === 'off' ? 'disabled' : 'missing route'}: no Source column, chip disabled, one line in the detail panel`, async () => {
      const p = await mount({ prov: mode });
      expect(p.qa('thead th').map((t) => t.textContent)).not.toContain('Source');
      expect(p.button('Stripped by Argus').disabled).toBe(true);
      await open(p, '_ga');
      expect(p.text('#prov')).toBe('Turn on cookie provenance in Argus Settings to see where cookies come from');
    });
  }

  it('Block this cookie shows the generated $cookie rule and adds it through POST /ext/rules', async () => {
    const p = await mount({ prov: 'on' });
    const calls: { url: string; body?: string }[] = [];
    const base = provenanceFetch({ mode: 'on' });
    vi.stubGlobal('fetch', (url: string, init?: RequestInit) => {
      if (new URL(url).pathname.endsWith('/ext/rules')) { calls.push({ url, body: String(init?.body) }); return json(200, { rule_count: 3, changed: true }); }
      return base(url, init);
    });
    await open(p, '_ga');
    await p.click(p.q('#blockck'));
    await p.waitFor(() => p.q('[data-testid=rule-line]'), 'rule');
    expect(p.text('[data-testid=rule-line]')).toBe('||stackoverflow.com^$cookie=_ga');
    await p.click(p.button('Add to My rules'));
    await p.waitFor(() => calls.length === 1, 'posted');
    expect(JSON.parse(calls[0]!.body!)).toEqual({ op: 'add', rule: '||stackoverflow.com^$cookie=_ga' });
    expect(p.text('#blk')).toContain('Added to My rules');
  });

  it('Block this cookie explains a token without the rules scope', async () => {
    const p = await mount({ prov: 'on' });
    const base = provenanceFetch({ mode: 'on' });
    vi.stubGlobal('fetch', (url: string, init?: RequestInit) => (new URL(url).pathname.endsWith('/ext/rules') ? json(403, { error: { code: 'insufficient_scope' } }) : base(url, init)));
    await open(p, '_ga');
    await p.click(p.q('#blockck'));
    await p.waitFor(() => p.q('[data-testid=rule-line]'), 'rule');
    await p.click(p.button('Add to My rules'));
    await p.waitFor(() => p.text('#blk').includes('Sign in again'), 'scope message');
  });
});

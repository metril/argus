import { beforeEach, describe, expect, it } from 'vitest';
import { ARM_TTL_MS, Arming } from '../lib/arming';
import { candidates, cosmeticRule, resourceRule, resourceUrl, specificForAllSites } from '../lib/pickercore';
import { handlePickerMessage } from '../lib/pickerbg';
import { isTrustedClick, startPicker } from '../lib/pickerui';
import { dropSite, gridRule, gridState, resetSite, setGridState, type SiteRule } from '../lib/siterules';

const area = () => { const m: Record<string, unknown> = {}; return { get: async (k: string) => (k in m ? { [k]: m[k] } : {}), set: async (o: Record<string, unknown>) => { Object.assign(m, o); }, remove: async (k: string) => { delete m[k]; } }; };

describe('selector candidates', () => {
  beforeEach(() => {
    document.body.innerHTML = `<div id="main"><div class="ad banner css-12345"><a href="https://ads.x/p?q=1" data-ad="slot1"><img class="ad" src="https://cdn.x/i.png"></a></div><div class="ad"></div><p>t</p></div>`;
  });
  it('orders from specific to broad and every candidate matches the element', () => {
    const el = document.querySelector('a')!;
    const c = candidates(el);
    expect(c.length).toBeGreaterThan(2);
    for (let i = 1; i < c.length; i++) expect(c[i]!.count).toBeGreaterThanOrEqual(c[i - 1]!.count);
    for (const x of c) expect(Array.from(document.querySelectorAll(x.selector))).toContain(el);
    expect(c[0]!.selector).toBe('#main > div:nth-of-type(1) > a:nth-of-type(1)');
    expect(c[0]!.count).toBe(1);
    expect(c.some((x) => x.selector === 'a[data-ad="slot1"]')).toBe(true);
    expect(c.some((x) => x.selector === 'a[href^="https://ads.x/p"]')).toBe(true);
  });
  it('class candidates are broader and skip unstable classes, never a bare tag', () => {
    const el = document.querySelector('div.banner')!;
    const sel = candidates(el).map((x) => x.selector);
    expect(sel).toContain('div.ad.banner');
    expect(sel).toContain('.banner');
    expect(sel.some((s) => s.includes('css-12345'))).toBe(false);
    expect(sel).not.toContain('div');
    const ad = candidates(el).find((x) => x.selector === '.ad')!;
    expect(ad.count).toBe(3);
    expect(candidates(el).at(-1)!.count).toBeGreaterThanOrEqual(ad.count - 1);
  });
  it('uses an id and escapes odd characters', () => {
    document.body.innerHTML = '<div id="a:b"><span id="x.y">1</span></div>';
    const sel = candidates(document.querySelector('span')!).map((c) => c.selector);
    expect(sel).toContain('span#x\\.y');
    expect(sel[0]).toBe('#x\\.y');
  });
  it('resource url and rule', () => {
    expect(resourceUrl(document.querySelector('img')!)).toBe('https://cdn.x/i.png');
    expect(resourceUrl(document.querySelector('a')!)).toBeUndefined();
    expect(resourceRule('https://cdn.x/i.png', { scope: 'site', match: 'host', site: 's.test' })).toBe('||cdn.x^$domain=s.test');
    expect(resourceRule('https://cdn.x/i.png', { scope: 'everywhere', match: 'host', site: 's.test' })).toBe('||cdn.x^');
  });
});

describe('rule text', () => {
  it('site and all-sites', () => {
    expect(cosmeticRule('a.com', '.ad', 'site')).toBe('a.com##.ad');
    expect(cosmeticRule('a.com', '.ad', 'everywhere')).toBe('##.ad');
    expect(cosmeticRule('', '.ad', 'site')).toBe('##.ad');
  });
  it('all-sites needs an id, class or attribute value', () => {
    for (const ok of ['.ad', '#x', 'div.ad', 'a[href^="xyz"]', '.a, #b', 'div > .x:nth-child(2)']) expect(specificForAllSites(ok), ok).toBe(true);
    for (const bad of ['div', '*', 'body', '[class]', 'div:not(.x)', '.a, div', '.a *', 'div:nth-of-type(1)']) expect(specificForAllSites(bad), bad).toBe(false);
  });
  it('all-sites refuses selectors that can hide a whole page', () => {
    for (const bad of ['html.dark', 'body.x', '.a > body.x', ':root.x', '[data-x*="abcd"]', '[data-x~="abcd"]', '[data-x="ab"]', '[lang="en-US"]', '[dir="ltr"]', '[style="abc"]', '[class="abcd"]', '[id="abcd"]', '.x\\']) expect(specificForAllSites(bad), bad).toBe(false);
    for (const ok of ['.ad-slot', '[data-ad="slot1"]', 'a[href^="https://x.test/"]']) expect(specificForAllSites(ok), ok).toBe(true);
  });
});

describe('background guards', () => {
  const OWN = 'ext-id';
  let arming: Arming;
  let saved: string[];
  const deps = () => ({ arming, ownId: OWN, save: async (r: string) => { saved.push(r); return { ok: true }; } });
  const sender = (o: object = {}) => ({ id: OWN, tab: { id: 7, url: 'https://www.a.com/p' }, ...o });
  const save = { type: 'picker-save', rule: 'a.com##.ad', confirmed: true };
  beforeEach(async () => { arming = new Arming(area()); saved = []; await arming.arm(7, 'picker'); });

  it('accepts the armed tab', async () => {
    expect(await handlePickerMessage(deps(), save, sender())).toEqual({ ok: true });
    expect(saved).toEqual(['a.com##.ad']);
  });
  it('rejects a wrong tab', async () => {
    expect(await handlePickerMessage(deps(), save, sender({ tab: { id: 8, url: 'https://www.a.com/' } }))).toMatchObject({ ok: false });
    expect(await handlePickerMessage(deps(), save, { id: OWN })).toMatchObject({ ok: false });
    expect(saved).toEqual([]);
  });
  it('rejects a foreign sender', async () => {
    expect(await handlePickerMessage(deps(), save, sender({ id: 'other' }))).toMatchObject({ ok: false });
    expect(await handlePickerMessage(deps(), save, undefined as never)).toMatchObject({ ok: false });
    expect(saved).toEqual([]);
  });
  it('rejects once the arming expired', async () => {
    const a = new Arming(area());
    await a.arm(7, 'picker', Date.now() - ARM_TTL_MS - 1);
    expect(await handlePickerMessage({ ...deps(), arming: a }, save, sender())).toMatchObject({ ok: false });
    expect(saved).toEqual([]);
  });
  it('is disarmed by close and by an unarmed state', async () => {
    expect(await handlePickerMessage(deps(), { type: 'picker-close' }, sender())).toEqual({ ok: true });
    expect(await handlePickerMessage(deps(), save, sender())).toMatchObject({ ok: false });
  });
  it('needs the confirmation and a rule for the tab\'s own site', async () => {
    expect(await handlePickerMessage(deps(), { ...save, confirmed: false }, sender())).toMatchObject({ ok: false });
    expect(await handlePickerMessage(deps(), { ...save, rule: 'evil.com##.ad' }, sender())).toMatchObject({ ok: false, error: 'wrong site' });
    expect(await handlePickerMessage(deps(), { ...save, rule: 'a.com##.x\n||b.com^' }, sender())).toMatchObject({ ok: false });
    expect(await handlePickerMessage(deps(), { ...save, rule: '##.ad', allSites: true }, sender())).toEqual({ ok: true });
  });
  it('an all-sites rule needs the panel\'s flag, and a network rule the tab\'s site', async () => {
    expect(await handlePickerMessage(deps(), { ...save, rule: '##.ad' }, sender())).toMatchObject({ ok: false });
    expect(await handlePickerMessage(deps(), { ...save, rule: '##.ad', allSites: true }, sender())).toEqual({ ok: true });
    expect(await handlePickerMessage(deps(), { ...save, rule: '||cdn.x^' }, sender())).toMatchObject({ ok: false });
    expect(await handlePickerMessage(deps(), { ...save, rule: '||cdn.x^$domain=b.com' }, sender())).toMatchObject({ ok: false });
    expect(await handlePickerMessage(deps(), { ...save, rule: '||cdn.x^$domain=a.com|b.com' }, sender())).toMatchObject({ ok: false });
    expect(await handlePickerMessage(deps(), { ...save, rule: '||cdn.x^$image,domain=a.com' }, sender())).toEqual({ ok: true });
    expect(await handlePickerMessage(deps(), { ...save, rule: '||cdn.x^', allSites: true }, sender())).toEqual({ ok: true });
  });
  it('a zapper-armed tab cannot save', async () => {
    await arming.arm(7, 'zapper');
    expect(await handlePickerMessage(deps(), save, sender())).toMatchObject({ ok: false });
    expect(await arming.allows(sender(), OWN, 'picker')).toBe(false);
    expect(await arming.allows(sender(), OWN, 'zapper')).toBe(true);
    expect(saved).toEqual([]);
  });
  it('the picker aborts when the page restyles its host', async () => {
    let done = 0;
    const stop = startPicker({ mode: 'picker', site: 'a.com', send: async () => ({ ok: true }), onDone: () => { done++; } });
    const host = document.documentElement.lastElementChild as HTMLElement;
    host.style.setProperty('opacity', '0');
    await new Promise((r) => setTimeout(r, 20));
    expect(done).toBe(1);
    stop();
  });
  it('only a trusted click confirms', () => {
    const e = new Event('click');
    expect(isTrustedClick(e)).toBe(false);
  });
});

describe('grid state and reset', () => {
  const sr = (rule: string, exclusive = true): SiteRule => ({ rule, exclusive });
  const rules = [sr('||ads.x.com^$domain=a.com'), sr('@@||cdn.y.com^$domain=a.com'), sr('||other.com^$domain=b.com')];
  const strs = rules.map((r) => r.rule);
  it('reflects existing rules, ignoring other options and extra domains', () => {
    expect(gridState(strs, 'ads.x.com', 'a.com')).toBe('block');
    expect(gridState(strs, 'CDN.y.com', 'a.com')).toBe('allow');
    expect(gridState(strs, 'other.com', 'a.com')).toBe('default');
    expect(gridState(['||h.com^$third-party,domain=a.com'], 'h.com', 'a.com')).toBe('block');
    expect(gridState(['||h.com^$domain=b.com|a.com,script'], 'h.com', 'a.com')).toBe('block');
    expect(gridState(['||h.com^$domain=ba.com'], 'h.com', 'a.com')).toBe('default');
    expect(gridRule('Ads.X.com', 'a.com', 'block')).toBe('||ads.x.com^$domain=a.com');
  });
  it('drops a site from a rule', () => {
    expect(dropSite('||h.com^$domain=a.com|b.com', 'a.com')).toBe('||h.com^$domain=b.com');
    expect(dropSite('||h.com^$script,domain=b.com|a.com', 'a.com')).toBe('||h.com^$script,domain=b.com');
    expect(dropSite('a.com,b.com##.x', 'a.com')).toBe('b.com##.x');
    expect(dropSite('a.com##.x', 'a.com')).toBeNull();
    expect(dropSite('||h.com^$domain=a.com', 'a.com')).toBeNull();
    expect(dropSite('##.x', 'a.com')).toBe('##.x');
  });
  it('moves between states, removing the old rule', async () => {
    const calls: string[] = [];
    const post = async (op: 'add' | 'remove', r: string) => { calls.push(`${op} ${r}`); return { ok: true }; };
    const out = await setGridState(post, rules, 'ads.x.com', 'a.com', 'allow');
    expect(calls).toEqual(['remove ||ads.x.com^$domain=a.com', 'add @@||ads.x.com^$domain=a.com']);
    expect(gridState(out!.map((r) => r.rule), 'ads.x.com', 'a.com')).toBe('allow');
    calls.length = 0;
    const d = await setGridState(post, rules, 'ads.x.com', 'a.com', 'default');
    expect(calls).toEqual(['remove ||ads.x.com^$domain=a.com']);
    expect(gridState(d!.map((r) => r.rule), 'ads.x.com', 'a.com')).toBe('default');
    expect(await setGridState(async () => ({ ok: false }), rules, 'n.com', 'a.com', 'block')).toBeUndefined();
  });
  it('a toggle does not duplicate a rule that already says it', async () => {
    const calls: string[] = [];
    const post = async (op: 'add' | 'remove', r: string) => { calls.push(`${op} ${r}`); return { ok: true }; };
    const shared = [sr('||h.com^$third-party,domain=a.com|b.com', false)];
    expect((await setGridState(post, shared, 'h.com', 'a.com', 'block'))!.length).toBe(1);
    expect(calls).toEqual([]);
    const out = await setGridState(post, shared, 'h.com', 'a.com', 'allow');
    expect(calls).toEqual(['add ||h.com^$third-party,domain=b.com', 'remove ||h.com^$third-party,domain=a.com|b.com', 'add @@||h.com^$domain=a.com']);
    expect(out!.map((r) => r.rule)).toEqual(['@@||h.com^$domain=a.com']);
  });
  it('reset removes exclusive rules, rewrites shared ones and keeps what failed', async () => {
    const calls: string[] = [];
    const all = [sr('a.com##.only'), sr('a.com,b.com##.shared', false), sr('||x.com^$domain=a.com|b.com', false), sr('@@||cdn.y.com^$domain=a.com')];
    const left = await resetSite(async (o, r) => { calls.push(`${o} ${r}`); return { ok: !r.startsWith('@@') }; }, all, 'a.com');
    expect(calls).toEqual([
      'remove a.com##.only',
      'add b.com##.shared', 'remove a.com,b.com##.shared',
      'add ||x.com^$domain=b.com', 'remove ||x.com^$domain=a.com|b.com',
      'remove @@||cdn.y.com^$domain=a.com',
    ]);
    expect(left.map((r) => r.rule)).toEqual(['@@||cdn.y.com^$domain=a.com']);
  });
});

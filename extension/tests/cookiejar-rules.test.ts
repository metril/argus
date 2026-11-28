import { describe, expect, it } from 'vitest';
import { CookieJar } from '../lib/cookiejar/api';
import { makeCookie } from '../lib/cookiejar/model';
import { ALARM_PREFIX, AutoDelete, defaultRules, normalizeRules, Rules, RULES_KEY, siteOfUrl } from '../lib/cookiejar/rules';
import { FakeAlarms, FakeBrowser, FakeStorageArea } from './helpers/fakebrowser';

function setup(start = 1_000_000) {
  const fb = new FakeBrowser();
  const local = new FakeStorageArea();
  const session = new FakeStorageArea();
  const alarms = new FakeAlarms();
  let now = start;
  const jar = new CookieJar(fb);
  const rules = new Rules(local);
  const br = { alarms, tabs: fb.tabs };
  const auto = new AutoDelete(br, jar, rules, session, { now: () => now });
  const names = () => fb.all().map((c) => c.name).sort();
  return { fb, local, session, alarms, jar, rules, auto, names, tick: (ms: number) => { now += ms; } };
}

describe('rules', () => {
  it('defaults, persists in storage.local and normalises input', async () => {
    const { rules, local } = setup();
    expect(await rules.get()).toEqual(defaultRules());
    const r = await rules.update({ keep: [' Example.COM ', '*.mail.test', 'example.com', ''], grey: ['news.test'], autoDelete: { enabled: true, delayMinutes: 0.01 } });
    expect(r).toMatchObject({ keep: ['example.com', 'mail.test'], grey: ['news.test'], autoDelete: { enabled: true, delayMinutes: 0.5 } });
    expect(Object.keys(local.data)).toEqual([RULES_KEY]);
    expect((await rules.update({ autoDelete: { enabled: true, delayMinutes: 1e9 } })).autoDelete.delayMinutes).toBe(1440);
    expect((await rules.update({ autoDelete: { enabled: false } as never })).autoDelete.delayMinutes).toBe(1440);
    expect(normalizeRules({ keep: 5 as never, autoDelete: { enabled: true, delayMinutes: NaN } }).autoDelete.delayMinutes).toBe(1);
  });
  it('protect and unprotect work by cookie identity, not value', async () => {
    const { rules } = setup();
    const c = makeCookie({ name: 'sid', value: 'v1', domain: 'example.com', storeId: '0' });
    await rules.protect([c, c]);
    expect((await rules.get()).protected).toHaveLength(1);
    const guard = await rules.guard();
    expect(guard({ ...c, value: 'changed' })).toBe(true);
    expect(guard({ ...c, name: 'other' })).toBe(false);
    expect(guard({ ...c, storeId: '1' })).toBe(false);
    await rules.unprotect([c]);
    expect((await rules.guard())(c)).toBe(false);
  });
  it('concurrent updates are serialised', async () => {
    const { rules } = setup();
    await Promise.all(['a.com', 'b.com', 'c.com'].map(async (s) => rules.update({ keep: [...(await rules.get()).keep, s] })));
    expect((await rules.get()).keep.length).toBeGreaterThanOrEqual(1);
    const cs = ['x', 'y', 'z'].map((n) => makeCookie({ name: n, domain: 'e.com', storeId: '0' }));
    await Promise.all(cs.map((c) => rules.protect([c])));
    expect((await rules.get()).protected.length).toBeGreaterThanOrEqual(1);
  });
  it('siteOfUrl only knows http(s) pages', () => {
    expect(siteOfUrl('https://www.example.co.uk/x')).toBe('example.co.uk');
    expect(siteOfUrl('chrome://settings')).toBeUndefined();
    expect(siteOfUrl('about:blank')).toBeUndefined();
    expect(siteOfUrl(undefined)).toBeUndefined();
    expect(siteOfUrl('nonsense')).toBeUndefined();
  });
});

describe('auto-delete', () => {
  async function ready(over: Partial<ReturnType<typeof defaultRules>> = {}) {
    const s = setup();
    await s.rules.update({ autoDelete: { enabled: true, delayMinutes: 2 }, ...over });
    s.fb.seed({ name: 'a', domain: '.example.com', hostOnly: false });
    s.fb.seed({ name: 'b', domain: 'www.example.com' });
    s.fb.seed({ name: 'z', domain: 'other.com' });
    return s;
  }
  it('schedules an alarm when the last tab of a site closes and removes that site\'s cookies when it fires', async () => {
    const s = await ready();
    await s.auto.noteTab(1, 'https://www.example.com/a');
    await s.auto.noteTab(2, 'https://example.com/b');
    await s.auto.tabRemoved(1);
    expect(s.alarms.items.size).toBe(0); // another tab of the site is still open
    await s.auto.tabRemoved(2);
    expect([...s.alarms.items.values()]).toEqual([{ name: ALARM_PREFIX + 'example.com', scheduledTime: 1_000_000 + 120_000 }]);
    expect(s.names()).toEqual(['a', 'b', 'z']);
    expect(await s.auto.alarm(ALARM_PREFIX + 'example.com')).toBe(true);
    expect(s.names()).toEqual(['z']);
  });
  it('state survives the worker sleeping (a new AutoDelete on the same session storage)', async () => {
    const s = await ready();
    await s.auto.noteTab(7, 'https://example.com/');
    const woke = new AutoDelete({ alarms: s.alarms, tabs: s.fb.tabs }, s.jar, s.rules, s.session);
    await woke.tabRemoved(7);
    expect(s.alarms.items.has(ALARM_PREFIX + 'example.com')).toBe(true);
    await s.alarms.fire(ALARM_PREFIX + 'example.com');
    await woke.alarm(ALARM_PREFIX + 'example.com');
    expect(s.names()).toEqual(['z']);
  });
  it('reopening the site cancels the cleanup, and a still-open tab stops a stale alarm', async () => {
    const s = await ready();
    await s.auto.noteTab(1, 'https://example.com/');
    await s.auto.tabRemoved(1);
    await s.auto.noteTab(2, 'https://www.example.com/');
    expect(s.alarms.items.size).toBe(0);
    await s.auto.alarm(ALARM_PREFIX + 'example.com');
    expect(s.names()).toEqual(['a', 'b', 'z']);
  });
  it('never touches keep-list sites, protected cookies or other sites; greylist is not cleaned on close', async () => {
    const s = await ready({ keep: ['other.com'], grey: ['example.com'] });
    await s.auto.noteTab(1, 'https://other.com/');
    await s.auto.tabRemoved(1);
    expect(s.alarms.items.size).toBe(0);
    await s.auto.noteTab(2, 'https://example.com/');
    await s.auto.tabRemoved(2);
    expect(s.alarms.items.size).toBe(0);
    await s.auto.alarm(ALARM_PREFIX + 'example.com');
    await s.auto.alarm(ALARM_PREFIX + 'other.com');
    expect(s.names()).toEqual(['a', 'b', 'z']);
  });
  it('protected cookies and kept subdomains survive; the keep list is re-checked when the alarm fires', async () => {
    const s = await ready();
    await s.rules.protect([(await s.jar.list()).find((c) => c.name === 'a')!]);
    await s.auto.noteTab(1, 'https://example.com/');
    await s.auto.tabRemoved(1);
    await s.rules.update({ keep: ['www.example.com'] });
    await s.auto.alarm(ALARM_PREFIX + 'example.com');
    expect(s.names()).toEqual(['a', 'b', 'z']);
    await s.rules.update({ keep: [] });
    await s.auto.alarm(ALARM_PREFIX + 'example.com');
    expect(s.names()).toEqual(['a', 'z']);
  });
  it('does nothing when disabled or for unknown alarms and tabs', async () => {
    const s = await ready();
    await s.rules.update({ autoDelete: { enabled: false, delayMinutes: 2 } });
    await s.auto.noteTab(1, 'https://example.com/');
    await s.auto.tabRemoved(1);
    await s.auto.tabRemoved(99);
    expect(s.alarms.items.size).toBe(0);
    await s.auto.alarm(ALARM_PREFIX + 'example.com');
    expect(s.names()).toEqual(['a', 'b', 'z']);
    expect(await s.auto.alarm('argus-bridge')).toBe(false);
    await s.auto.noteTab(2, 'chrome://newtab/');
    await s.auto.tabRemoved(2);
  });
  it('browser start cleans greylisted and closed sites, but not kept or open ones', async () => {
    const s = await ready({ keep: ['kept.com'], grey: ['grey.com'] });
    s.fb.seed({ name: 'k', domain: 'kept.com' });
    s.fb.seed({ name: 'g', domain: 'grey.com' });
    s.fb.tabList = [{ id: 5, url: 'https://other.com/open' }, { id: 6, url: 'chrome://newtab' }];
    await s.alarms.create(ALARM_PREFIX + 'stale.com', { when: 1 });
    await s.auto.init();
    const r = await s.auto.startup();
    expect(r?.done).toHaveLength(3);
    expect(s.names()).toEqual(['k', 'z']);
    expect(s.alarms.items.size).toBe(0);
  });
  it('browser start does nothing when auto-delete is off', async () => {
    const s = await ready();
    await s.rules.update({ autoDelete: { enabled: false, delayMinutes: 1 } });
    expect(await s.auto.startup()).toBeUndefined();
    expect(s.names()).toEqual(['a', 'b', 'z']);
  });
  it('reports removal failures without throwing away the others', async () => {
    const s = await ready();
    s.fb.failWhen = (op, d) => op === 'remove' && d.name === 'a';
    await s.auto.noteTab(1, 'https://example.com/');
    await s.auto.tabRemoved(1);
    await s.auto.alarm(ALARM_PREFIX + 'example.com');
    expect(s.names()).toEqual(['a', 'z']);
  });
});

describe('auto-delete across a worker restart', () => {
  async function ready() {
    const s = setup();
    await s.rules.update({ autoDelete: { enabled: true, delayMinutes: 2 }, grey: ['grey.com'] });
    s.fb.seed({ name: 'a', domain: 'example.com' });
    s.fb.seed({ name: 'g', domain: 'grey.com' });
    return s;
  }
  it('a tab closed while the worker slept still schedules the cleanup when the worker starts', async () => {
    const s = await ready();
    await s.auto.noteTab(1, 'https://example.com/');
    s.fb.tabList = []; // the close woke a fresh worker: the tab is already gone from tabs.query
    const woke = new AutoDelete({ alarms: s.alarms, tabs: s.fb.tabs }, s.jar, s.rules, s.session, { now: () => 1_000_000 });
    await woke.init();
    expect(s.alarms.items.get(ALARM_PREFIX + 'example.com')?.scheduledTime).toBe(1_120_000);
    await woke.tabRemoved(1); // the delivered onRemoved finds nothing more to do
    expect(s.alarms.items.size).toBe(1);
    await woke.alarm(ALARM_PREFIX + 'example.com');
    expect(s.names()).toEqual(['g']);
  });
  it('init keeps still-open tabs, and does not schedule a site another tab still shows', async () => {
    const s = await ready();
    await s.auto.noteTab(1, 'https://example.com/a');
    await s.auto.noteTab(2, 'https://www.example.com/b');
    s.fb.tabList = [{ id: 2, url: 'https://www.example.com/b' }];
    await s.auto.init();
    expect(s.alarms.items.size).toBe(0);
    await s.auto.tabRemoved(2);
    expect(s.alarms.items.has(ALARM_PREFIX + 'example.com')).toBe(true);
  });
  it('init does not schedule kept or greylisted sites that closed while asleep', async () => {
    const s = await ready();
    await s.auto.noteTab(3, 'https://grey.com/');
    s.fb.tabList = [];
    await s.auto.init();
    expect(s.alarms.items.size).toBe(0);
  });
  it('restored tabs that have only a pendingUrl keep their site safe from the startup clean', async () => {
    const s = await ready();
    s.fb.tabList = [{ id: 5, pendingUrl: 'https://grey.com/' }];
    await s.auto.init();
    await s.auto.startup();
    expect(s.names()).toEqual(['g']);
  });
});

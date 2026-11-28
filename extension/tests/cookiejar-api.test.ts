import { describe, expect, it } from 'vitest';
import { CookieError, CookieJar } from '../lib/cookiejar/api';
import { identityKey, makeCookie, type Cookie } from '../lib/cookiejar/model';
import { FakeBrowser } from './helpers/fakebrowser';

const ck = (p: Record<string, unknown> = {}) => makeCookie({ name: 'a', value: '1', domain: 'example.com', storeId: '0', ...p } as never);

function chrome(o = {}) {
  const fb = new FakeBrowser({ flavor: 'chrome', ...o });
  return { fb, jar: new CookieJar(fb) };
}
function firefox(o = {}) {
  const fb = new FakeBrowser({ flavor: 'firefox', ...o });
  return { fb, jar: new CookieJar(fb) };
}

describe('stores', () => {
  it('labels chrome default and incognito stores', async () => {
    const { fb, jar } = chrome({ stores: [{ id: '0', tabIds: [1] }, { id: '1', tabIds: [7] }, { id: '2' }] });
    fb.tabList = [{ id: 1, incognito: false }, { id: 7, incognito: true }];
    expect((await jar.stores()).map((s) => [s.id, s.label, s.kind])).toEqual([['0', 'Default', 'default'], ['1', 'Incognito', 'private'], ['2', 'Store 2', 'other']]);
  });
  it('labels firefox default, private and containers via contextualIdentities', async () => {
    const { jar } = firefox({
      stores: [{ id: 'firefox-default' }, { id: 'firefox-private' }, { id: 'firefox-container-1' }, { id: 'firefox-container-9' }],
      identities: [{ cookieStoreId: 'firefox-container-1', name: 'Work' }],
    });
    expect((await jar.stores()).map((s) => [s.label, s.kind])).toEqual([['Default', 'default'], ['Private', 'private'], ['Work', 'container'], ['Container 9', 'container']]);
  });
  it('turns a store listing failure into a clean error', async () => {
    const bad = new CookieJar({ cookies: { getAllCookieStores: async () => { throw new Error('boom'); } } });
    await expect(bad.stores()).rejects.toMatchObject({ code: 'store' });
  });
});

describe('list', () => {
  it('lists a site across subdomains, partitioned cookies included, on chrome', async () => {
    const { fb, jar } = chrome();
    fb.seed({ name: 'a', domain: 'example.com' });
    fb.seed({ name: 'b', domain: '.www.example.com', hostOnly: false });
    fb.seed({ name: 'p', domain: 'example.com', secure: true, partitionKey: { topLevelSite: 'https://top.test', hasCrossSiteAncestor: true } });
    fb.seed({ name: 'x', domain: 'other.com' });
    const got = await jar.list({ site: 'https://www.example.com/path' });
    expect(got.map((c) => c.name)).toEqual(['a', 'p', 'b']);
    expect(got.find((c) => c.name === 'p')?.partitionKey).toEqual({ topLevelSite: 'https://top.test', hasCrossSiteAncestor: true });
    expect(fb.calls.find((c) => c.op === 'getAll')?.details).toMatchObject({ partitionKey: {}, domain: 'example.com' });
    expect('firstPartyDomain' in fb.calls[0]!.details).toBe(false);
  });
  it('asks firefox for every first-party domain and partition, even with first-party isolation on', async () => {
    const { fb, jar } = firefox({ fpi: true });
    fb.seed({ name: 'a', domain: 'example.com', firstPartyDomain: 'example.com' });
    fb.seed({ name: 'b', domain: 'example.com', firstPartyDomain: 'tracker.net' });
    fb.seed({ name: 'c', domain: 'example.com', secure: true, partitionKey: { topLevelSite: 'https://top.test' } });
    const got = await jar.list();
    expect(got.map((c) => c.name).sort()).toEqual(['a', 'b', 'c']);
    expect(fb.calls[0]!.details).toMatchObject({ firstPartyDomain: null, partitionKey: {} });
  });
  it('lists everything across stores, one store, and a site in a store', async () => {
    const { fb, jar } = chrome({ stores: [{ id: '0' }, { id: '1' }] });
    fb.seed({ name: 'a', domain: 'example.com', storeId: '0' });
    fb.seed({ name: 'a', domain: 'example.com', storeId: '1' });
    fb.seed({ name: 'z', domain: 'zzz.com', storeId: '1' });
    expect(await jar.list()).toHaveLength(3);
    expect((await jar.list({ storeId: '1' })).map((c) => c.name)).toEqual(['a', 'z']);
    expect(await jar.list({ site: 'example.com', storeId: '0' })).toHaveLength(1);
  });
  it('falls back once when the browser does not know partitioned cookies', async () => {
    const { fb, jar } = chrome({ noPartitioned: true });
    fb.seed({ name: 'a' });
    expect(await jar.list()).toHaveLength(1);
    expect(jar.caps.partitioned).toBe(false);
    expect('partitionKey' in fb.calls[fb.calls.length - 1]!.details).toBe(false);
    await jar.create(ck({ partitionKey: { topLevelSite: 'https://t.test' }, secure: true }));
    expect('partitionKey' in fb.calls[fb.calls.length - 1]!.details).toBe(false);
  });
  it('reports a read failure as a store error', async () => {
    const { fb, jar } = chrome();
    fb.failWhen = (op) => op === 'getAll';
    await expect(jar.list()).rejects.toMatchObject({ code: 'store' });
  });
});

describe('create / remove', () => {
  it('creates, with the partition and store it was given', async () => {
    const { fb, jar } = chrome({ stores: [{ id: '0' }, { id: '1' }] });
    const made = await jar.create(ck({ storeId: '1', secure: true, partitionKey: { topLevelSite: 'https://t.test', hasCrossSiteAncestor: false } }));
    expect(made).toMatchObject({ storeId: '1', partitionKey: { topLevelSite: 'https://t.test', hasCrossSiteAncestor: false } });
    expect(fb.all()).toHaveLength(1);
    expect(fb.calls[0]!.details).toMatchObject({ storeId: '1', partitionKey: { topLevelSite: 'https://t.test', hasCrossSiteAncestor: false } });
  });
  it('creates a domain cookie and a session cookie', async () => {
    const { fb, jar } = chrome();
    await jar.create(ck({ domain: '.example.com', hostOnly: false, expirationDate: 4e9, session: false }));
    expect(fb.all()[0]).toMatchObject({ domain: '.example.com', hostOnly: false, session: false, expirationDate: 4e9 });
  });
  it('refuses invalid cookies before calling the browser', async () => {
    const { fb, jar } = chrome();
    await expect(jar.create(ck({ name: '__Host-a' }))).rejects.toMatchObject({ code: 'invalid', message: 'A __Host- cookie must be Secure.' });
    expect(fb.calls).toHaveLength(0);
  });
  it('reports a null result (chrome) and a thrown error (firefox) as set-failed', async () => {
    const c = chrome(); c.fb.failWhen = (op) => op === 'set';
    await expect(c.jar.create(ck())).rejects.toBeInstanceOf(CookieError);
    const n = new CookieJar({ cookies: { set: async () => null } });
    await expect(n.create(ck())).rejects.toMatchObject({ code: 'set-failed', message: 'The browser refused to store this cookie.' });
  });
  it('removes a partitioned cookie only when given its partition key', async () => {
    const { fb, jar } = chrome();
    const k = fb.seed({ name: 'p', secure: true, partitionKey: { topLevelSite: 'https://t.test' } });
    const listed = (await jar.list())[0]!;
    expect(await jar.remove({ ...listed, partitionKey: undefined } as Cookie)).toBe(false);
    expect(fb.all()).toHaveLength(1);
    expect(await jar.remove(listed)).toBe(true);
    expect(fb.all()).toHaveLength(0);
    expect(k).toBeTruthy();
  });
  it('removes firefox cookies with their first-party domain when isolation is on', async () => {
    const { fb, jar } = firefox({ fpi: true });
    fb.seed({ name: 'a', domain: 'example.com', firstPartyDomain: 'example.com' });
    const [c] = await jar.list();
    expect(await jar.remove(c!)).toBe(true);
  });
});

describe('edit = set the new, then remove the old', () => {
  it('overwrites in place when the identity is unchanged', async () => {
    const { fb, jar } = chrome();
    fb.seed({ name: 'a', value: '1' });
    const [old] = await jar.list();
    const out = await jar.edit(old!, { ...old!, value: '2' });
    expect(out.value).toBe('2');
    expect(fb.all()).toHaveLength(1);
    expect(fb.calls.filter((c) => c.op === 'remove')).toHaveLength(0);
  });
  it('renaming sets the new cookie first and then removes the old one', async () => {
    const { fb, jar } = chrome();
    fb.seed({ name: 'old' });
    const [old] = await jar.list();
    await jar.edit(old!, { ...old!, name: 'new' });
    expect(fb.all().map((c) => c.name)).toEqual(['new']);
    expect(fb.calls.map((c) => c.op).filter((o) => o !== 'getAll')).toEqual(['set', 'remove']);
  });
  it('changing path, domain or partition moves the cookie', async () => {
    const { fb, jar } = chrome();
    fb.seed({ name: 'a', secure: true, partitionKey: { topLevelSite: 'https://t.test' } });
    const [old] = await jar.list();
    const out = await jar.edit(old!, { ...old!, partitionKey: { topLevelSite: 'https://u.test' }, path: '/x', hostOnly: true });
    expect(out.partitionKey?.topLevelSite).toBe('https://u.test');
    expect(fb.all()).toHaveLength(1);
    expect(fb.all()[0]).toMatchObject({ path: '/x' });
  });
  it('leaves the old cookie alone when the set fails', async () => {
    const { fb, jar } = chrome();
    fb.seed({ name: 'a', value: '1' });
    const [old] = await jar.list();
    fb.failWhen = (op, d) => op === 'set' && d.name === 'b';
    await expect(jar.edit(old!, { ...old!, name: 'b' })).rejects.toMatchObject({ code: 'set-failed' });
    expect(fb.all().map((c) => c.name)).toEqual(['a']);
  });
  it('restores the old cookie if the browser dropped it while refusing the new one', async () => {
    const fb = new FakeBrowser();
    fb.seed({ name: 'a', value: '1' });
    const base = fb.cookies;
    const jar = new CookieJar({ cookies: { ...base, set: async (d: any) => { if (d.value === 'bad') { fb.jar.clear(); return null; } return base.set(d); } } });
    const [old] = await jar.list();
    await expect(jar.edit(old!, { ...old!, value: 'bad' })).rejects.toMatchObject({ code: 'set-failed' });
    expect(fb.all().map((c) => c.value)).toEqual(['1']);
  });
  it('refuses an edit that would expire the cookie without touching it', async () => {
    const { fb, jar } = chrome();
    fb.seed({ name: 'a', value: '1', expirationDate: 4e9 });
    const [old] = await jar.list();
    await expect(jar.edit(old!, { ...old!, expirationDate: 1, session: false })).rejects.toMatchObject({ code: 'invalid' });
    expect(fb.calls.some((c) => c.op === 'set')).toBe(false);
    expect(fb.all()).toHaveLength(1);
  });
  it('removes the new cookie again when removing the old one fails (no duplicate)', async () => {
    const { fb, jar } = chrome();
    fb.seed({ name: 'a' });
    const [old] = await jar.list();
    fb.failWhen = (op, d) => op === 'remove' && d.name === 'a';
    await expect(jar.edit(old!, { ...old!, name: 'b' })).rejects.toMatchObject({ code: 'remove-failed' });
    expect(fb.all().map((c) => c.name)).toEqual(['a']);
  });
  it('validates the edit and keeps the store of the old cookie', async () => {
    const { fb, jar } = chrome({ stores: [{ id: '0' }, { id: '1' }] });
    fb.seed({ name: 'a', storeId: '1' });
    const [old] = await jar.list();
    await expect(jar.edit(old!, { ...old!, sameSite: 'no_restriction' })).rejects.toMatchObject({ code: 'invalid' });
    const out = await jar.edit(old!, { ...old!, storeId: '', value: 'z' });
    expect(out.storeId).toBe('1');
  });
});

describe('bulk, copy and move', () => {
  it('deletes many, skipping protected ones and reporting failures per cookie', async () => {
    const { fb, jar } = chrome();
    for (const n of ['a', 'b', 'c', 'd']) fb.seed({ name: n });
    fb.failWhen = (op, d) => op === 'remove' && d.name === 'd';
    const cs = await jar.list();
    const keep = identityKey(cs[0]!);
    const r = await jar.removeMany(cs, { isProtected: (c) => identityKey(c) === keep });
    expect(r.done.map((c) => c.name).sort()).toEqual(['b', 'c']);
    expect(r.skipped.map((c) => c.name)).toEqual(['a']);
    expect(r.failed.map((f) => f.cookie.name)).toEqual(['d']);
    expect(fb.all().map((c) => c.name).sort()).toEqual(['a', 'd']);
  });
  it('handles more cookies than one chunk', async () => {
    const { fb, jar } = chrome();
    for (let i = 0; i < 55; i++) fb.seed({ name: `n${i}` });
    const r = await jar.removeMany(await jar.list());
    expect(r.done).toHaveLength(55);
    expect(fb.all()).toHaveLength(0);
  });
  it('copies into another store, keeping partition and first-party domain', async () => {
    const { fb, jar } = firefox({ stores: [{ id: 'firefox-default' }, { id: 'firefox-container-1' }] });
    fb.seed({ name: 'a', secure: true, firstPartyDomain: 'example.com', partitionKey: { topLevelSite: 'https://t.test' } });
    const r = await jar.copy(await jar.list(), 'firefox-container-1');
    expect(r.done).toHaveLength(1);
    const all = fb.all();
    expect(all).toHaveLength(2);
    expect(all.find((c) => c.storeId === 'firefox-container-1')).toMatchObject({ firstPartyDomain: 'example.com', partitionKey: { topLevelSite: 'https://t.test' } });
  });
  it('moves: copy then remove; a failed removal takes the copy back; same-store is skipped', async () => {
    const { fb, jar } = chrome({ stores: [{ id: '0' }, { id: '1' }] });
    fb.seed({ name: 'a', storeId: '0' }); fb.seed({ name: 'b', storeId: '0' }); fb.seed({ name: 'c', storeId: '1' });
    fb.failWhen = (op, d) => op === 'remove' && d.name === 'b' && d.storeId === '0';
    const cs = await jar.list();
    const r = await jar.move(cs, '1');
    expect(r.done.map((c) => c.name)).toEqual(['a']);
    expect(r.failed.map((f) => f.cookie.name)).toEqual(['b']);
    expect(r.skipped.map((c) => c.name)).toEqual(['c']);
    expect(fb.all().map((c) => `${c.storeId}:${c.name}`).sort()).toEqual(['0:b', '1:a', '1:c']);
  });
  it('reports an unknown destination store per cookie', async () => {
    const { fb, jar } = chrome();
    fb.seed({ name: 'a' });
    const r = await jar.copy(await jar.list(), '99');
    expect(r.failed[0]!.error).toMatch(/Invalid cookie store/);
  });
});

describe('feature detection', () => {
  it('detects firefox from contextualIdentities, not from a user agent', () => {
    expect(new CookieJar(new FakeBrowser({ flavor: 'firefox' })).caps.firstPartyDomain).toBe(true);
    expect(new CookieJar(new FakeBrowser({ flavor: 'chrome' })).caps.firstPartyDomain).toBe(false);
    expect(new CookieJar({}, { firefox: true }).caps.firstPartyDomain).toBe(true);
  });
});

describe('first-party domain on Chrome', () => {
  it('a cookie carrying one (imported or from Firefox) is stored without sending the property', async () => {
    const { fb, jar } = chrome();
    const made = await jar.create(ck({ firstPartyDomain: 'example.com' }));
    expect(made.firstPartyDomain).toBe('');
    expect(fb.calls.every((c) => !('firstPartyDomain' in c.details))).toBe(true);
  });
});

describe('partition variants', () => {
  it('lists, removes and protects the two hasCrossSiteAncestor variants separately', async () => {
    const { fb, jar } = chrome();
    for (const h of [false, true]) fb.seed({ name: 'p', domain: 'example.com', secure: true, partitionKey: { topLevelSite: 'https://t.test', hasCrossSiteAncestor: h } });
    const cs = await jar.list();
    expect(cs.map((c) => c.partitionKey?.hasCrossSiteAncestor).sort()).toEqual([false, true]);
    expect(new Set(cs.map(identityKey)).size).toBe(2);
    const r = await jar.removeMany(cs, { isProtected: (c) => c.partitionKey?.hasCrossSiteAncestor === false });
    expect(r.done).toHaveLength(1);
    expect(fb.all().map((c) => c.partitionKey.hasCrossSiteAncestor)).toEqual([false]);
  });
});

describe('copy/move conflicts', () => {
  function two() {
    const t = chrome({ stores: [{ id: '0' }, { id: '1' }] });
    t.fb.seed({ name: 'a', value: 'src', domain: 'example.com', storeId: '0' });
    t.fb.seed({ name: 'a', value: 'target', domain: 'example.com', storeId: '1' });
    return t;
  }
  const valueIn = (fb: FakeBrowser, store: string) => fb.all().find((c) => c.storeId === store)?.value;
  it('asks by default: nothing is touched and the conflict is returned', async () => {
    const { fb, jar } = two();
    const r = await jar.move(await jar.list({ storeId: '0' }), '1');
    expect(r.conflicts?.map((c) => [c.cookie.value, c.existing.value])).toEqual([['src', 'target']]);
    expect(r.done).toEqual([]);
    expect(fb.all()).toHaveLength(2);
    expect(valueIn(fb, '1')).toBe('target');
  });
  it('skip keeps the target cookie', async () => {
    const { fb, jar } = two();
    const r = await jar.copy(await jar.list({ storeId: '0' }), '1', { conflict: 'skip' });
    expect(r.skipped).toHaveLength(1);
    expect(r.conflicts).toBeUndefined();
    expect(valueIn(fb, '1')).toBe('target');
  });
  it('overwrite replaces it; a move whose removal fails restores the target prior cookie', async () => {
    const a = two();
    await a.jar.copy(await a.jar.list({ storeId: '0' }), '1', { conflict: 'overwrite' });
    expect(valueIn(a.fb, '1')).toBe('src');
    const b = two();
    b.fb.failWhen = (op, d) => op === 'remove' && d.storeId === '0';
    const r = await b.jar.move(await b.jar.list({ storeId: '0' }), '1', { conflict: 'overwrite' });
    expect(r.failed).toHaveLength(1);
    expect(valueIn(b.fb, '1')).toBe('target');
    expect(valueIn(b.fb, '0')).toBe('src');
  });
});

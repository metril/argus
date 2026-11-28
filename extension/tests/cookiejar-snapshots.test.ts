import { describe, expect, it } from 'vitest';
import { CookieJar } from '../lib/cookiejar/api';
import { AtRestCipher, type KeyStore } from '../lib/cookiejar/crypto';
import { makeCookie } from '../lib/cookiejar/model';
import { diffCookies, SNAPSHOT_KEY, SnapshotStore } from '../lib/cookiejar/snapshots';
import { FakeBrowser, FakeStorageArea } from './helpers/fakebrowser';

const mem = (): KeyStore => { let k: CryptoKey | undefined; return { get: async () => k, put: async (x) => { k = x; } }; };
const mk = (p: Record<string, unknown>) => makeCookie({ storeId: '0', ...p } as never);

function setup() {
  const fb = new FakeBrowser();
  const area = new FakeStorageArea();
  let n = 0, t = 1000;
  const snaps = new SnapshotStore(area, new AtRestCipher(mem()), { now: () => (t += 1000), newId: () => `s${++n}` });
  return { fb, jar: new CookieJar(fb), area, snaps };
}

describe('snapshots', () => {
  it('saves, lists newest first, loads and deletes; cookie values are never stored in the clear', async () => {
    const { area, snaps } = setup();
    const a = await snaps.save('first', [mk({ name: 'sid', value: 'TOPSECRET', domain: 'example.com' })], { site: 'example.com' });
    const b = await snaps.save('  ', [mk({ name: 'x', domain: 'other.com' })]);
    expect(a).toMatchObject({ id: 's1', name: 'first', count: 1, site: 'example.com' });
    expect(b.name).toBe('Snapshot');
    expect((await snaps.list()).map((m) => m.id)).toEqual(['s2', 's1']);
    expect(JSON.stringify(area.data)).not.toContain('TOPSECRET');
    expect(JSON.stringify(area.data)).not.toContain('sid');
    expect((await snaps.load('s1'))[0]).toMatchObject({ name: 'sid', value: 'TOPSECRET' });
    expect(await snaps.delete('s1')).toBe(true);
    expect(await snaps.delete('s1')).toBe(false);
    await expect(snaps.load('s1')).rejects.toMatchObject({ code: 'not-found' });
  });
  it('concurrent saves do not lose each other', async () => {
    const { snaps } = setup();
    await Promise.all([1, 2, 3, 4, 5].map((i) => snaps.save(`n${i}`, [])));
    expect(await snaps.list()).toHaveLength(5);
  });
  it('surfaces a storage failure', async () => {
    const { area, snaps } = setup();
    area.failSet = true;
    await expect(snaps.save('x', [])).rejects.toThrow(/quota/);
    area.failSet = false;
    expect(await snaps.list()).toEqual([]);
  });
});

describe('restore', () => {
  async function site() {
    const s = setup();
    s.fb.seed({ name: 'sid', value: 'old', domain: '.example.com', hostOnly: false, secure: true });
    s.fb.seed({ name: 'keep', value: 'k', domain: 'example.com' });
    s.fb.seed({ name: 'other', value: 'o', domain: 'other.com' });
    const meta = await s.snaps.save('before', await s.jar.list({ site: 'example.com' }), { site: 'example.com' });
    return { ...s, id: meta.id };
  }
  it('replaces the site\'s cookies with the snapshot and leaves other sites alone', async () => {
    const { fb, jar, snaps, id } = await site();
    fb.seed({ name: 'sid', value: 'new', domain: '.example.com', hostOnly: false, secure: true });
    fb.seed({ name: 'added', value: 'a', domain: 'www.example.com' });
    fb.jar.delete(JSON.stringify(['0', '', '', 'example.com', true, '/', 'keep']));
    const r = await snaps.restore(id, jar);
    expect(r).toMatchObject({ set: 2, removed: 1 });
    const now = Object.fromEntries(fb.all().map((c) => [c.name, c.value]));
    expect(now).toEqual({ sid: 'old', keep: 'k', other: 'o' });
  });
  it('skips cookies that have expired since, and protected ones survive the replace', async () => {
    const { fb, jar, snaps, id } = await site();
    const extra = fb.seed({ name: 'prot', value: 'p', domain: 'example.com' });
    const r = await snaps.restore(id, jar, { isProtected: (c) => c.name === 'prot' });
    expect(r.skippedProtected).toBe(1);
    expect(fb.all().some((c) => c.name === 'prot')).toBe(true);
    expect(extra).toBeTruthy();
    const expiring = await snaps.save('exp', [mk({ name: 'e', domain: 'example.com', session: false, expirationDate: 1500 })], { site: 'example.com' });
    const r2 = await snaps.restore(expiring.id, jar, { now: 2_000_000 });
    expect(r2).toMatchObject({ set: 0, skippedExpired: 1 });
  });
  it('rolls back everything when a cookie cannot be set', async () => {
    const { fb, jar, snaps, id } = await site();
    fb.seed({ name: 'sid', value: 'live', domain: '.example.com', hostOnly: false, secure: true });
    fb.seed({ name: 'extra', value: 'x', domain: 'example.com' });
    const before = JSON.stringify(fb.all().map((c) => [c.name, c.value]).sort());
    fb.failWhen = (op, d) => op === 'set' && d.name === 'keep';
    await expect(snaps.restore(id, jar)).rejects.toMatchObject({ code: 'set-failed' });
    expect(JSON.stringify(fb.all().map((c) => [c.name, c.value]).sort())).toBe(before);
  });
  it('rolls back when a removal fails after the cookies were set', async () => {
    const { fb, jar, snaps, id } = await site();
    fb.seed({ name: 'sid', value: 'live', domain: '.example.com', hostOnly: false, secure: true });
    fb.seed({ name: 'extra', value: 'x', domain: 'example.com' });
    fb.seed({ name: 'extra2', value: 'y', domain: 'example.com' });
    const before = JSON.stringify(fb.all().map((c) => [c.name, c.value]).sort());
    fb.failWhen = (op, d) => op === 'remove' && d.name === 'extra2';
    await expect(snaps.restore(id, jar)).rejects.toMatchObject({ code: 'remove-failed' });
    expect(JSON.stringify(fb.all().map((c) => [c.name, c.value]).sort())).toBe(before);
  });
  it('a selection snapshot only sets its cookies', async () => {
    const { fb, jar, snaps } = setup();
    fb.seed({ name: 'other', domain: 'example.com' });
    const m = await snaps.save('sel', [mk({ name: 'a', value: '1', domain: 'example.com' })]);
    expect(await snaps.restore(m.id, jar)).toMatchObject({ set: 1, removed: 0 });
    expect(fb.all().map((c) => c.name).sort()).toEqual(['a', 'other']);
  });
  it('restores into a snapshot\'s own store, partitions included', async () => {
    const s = setup();
    const fb2 = new FakeBrowser({ stores: [{ id: '0' }, { id: '1' }] });
    const jar = new CookieJar(fb2);
    fb2.seed({ name: 'p', domain: 'example.com', storeId: '1', secure: true, partitionKey: { topLevelSite: 'https://t.test' } });
    const m = await s.snaps.save('x', await jar.list({ site: 'example.com' }), { site: 'example.com' });
    fb2.jar.clear();
    await s.snaps.restore(m.id, jar);
    expect(fb2.all()[0]).toMatchObject({ storeId: '1', partitionKey: { topLevelSite: 'https://t.test' } });
  });
  it('says so for an unknown snapshot', async () => {
    const { jar, snaps } = setup();
    await expect(snaps.restore('nope', jar)).rejects.toMatchObject({ code: 'not-found' });
  });
});

describe('diff', () => {
  const a = [mk({ name: 'a', value: '1', domain: 'x.com' }), mk({ name: 'b', value: '1', domain: 'x.com' }), mk({ name: 'c', value: '1', domain: 'x.com' })];
  it('lists added, removed and changed cookies with the changed attributes', () => {
    const b = [mk({ name: 'a', value: '1', domain: 'x.com' }), mk({ name: 'b', value: '2', domain: 'x.com', secure: true }), mk({ name: 'd', value: '1', domain: 'x.com' })];
    const d = diffCookies(a, b);
    expect(d.unchanged).toBe(1);
    expect(d.added.map((c) => c.name)).toEqual(['d']);
    expect(d.removed.map((c) => c.name)).toEqual(['c']);
    expect(d.changed.map((c) => [c.after.name, c.fields])).toEqual([['b', ['value', 'secure']]]);
  });
  it('diffs a snapshot against the live jar and two snapshots', async () => {
    const { fb, jar, snaps } = setup();
    fb.seed({ name: 'a', value: '1', domain: 'x.com' });
    fb.seed({ name: 'b', value: '1', domain: 'x.com' });
    const s1 = await snaps.save('one', await jar.list({ site: 'x.com' }), { site: 'x.com' });
    fb.seed({ name: 'a', value: '2', domain: 'x.com' });
    fb.seed({ name: 'n', value: '1', domain: 'x.com' });
    fb.jar.delete(JSON.stringify(['0', '', '', 'x.com', true, '/', 'b']));
    const live = await snaps.diffWithLive(s1.id, jar);
    expect([live.added.map((c) => c.name), live.removed.map((c) => c.name), live.changed.map((c) => c.after.name)]).toEqual([['n'], ['b'], ['a']]);
    const s2 = await snaps.save('two', await jar.list({ site: 'x.com' }), { site: 'x.com' });
    expect((await snaps.diffSnapshots(s1.id, s2.id)).added.map((c) => c.name)).toEqual(['n']);
    const sel = await snaps.save('sel', [mk({ name: 'a', value: '2', domain: 'x.com' }), mk({ name: 'gone', domain: 'x.com' })]);
    const selDiff = await snaps.diffWithLive(sel.id, jar);
    expect([selDiff.removed.map((c) => c.name), selDiff.unchanged]).toEqual([['gone'], 1]);
    await expect(snaps.diffWithLive('nope', jar)).rejects.toMatchObject({ code: 'not-found' });
  });
  it('uses the documented storage key', async () => {
    const { area, snaps } = setup();
    await snaps.save('x', []);
    expect(Object.keys(area.data)).toEqual([SNAPSHOT_KEY]);
  });
});

describe('restore rollback for a selection snapshot', () => {
  it('puts the live values back instead of deleting cookies it had overwritten', async () => {
    const { fb, jar, snaps } = setup();
    fb.seed({ name: 'a', value: 'live', domain: 'example.com' });
    const m = await snaps.save('sel', [mk({ name: 'a', value: 'snap', domain: 'example.com' }), mk({ name: 'b', value: 'new', domain: 'example.com' })]);
    fb.failWhen = (op, d) => op === 'set' && d.name === 'b';
    await expect(snaps.restore(m.id, jar)).rejects.toMatchObject({ code: 'set-failed' });
    expect(fb.all().map((c) => [c.name, c.value])).toEqual([['a', 'live']]);
  });
});

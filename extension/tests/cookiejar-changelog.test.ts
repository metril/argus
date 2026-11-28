import { describe, expect, it } from 'vitest';
import { ChangeLog, listenForChanges, LOG_KEY, MAX_ENTRIES, memoryArea } from '../lib/cookiejar/changelog';
import { CookieJar } from '../lib/cookiejar/api';
import { FakeBrowser, FakeStorageArea } from './helpers/fakebrowser';

function setup(max?: number) {
  const fb = new FakeBrowser();
  const area = new FakeStorageArea();
  let t = 0;
  const log = new ChangeLog(area, { ...(max ? { max } : {}), now: () => ++t });
  listenForChanges(fb, log);
  return { fb, area, log, jar: new CookieJar(fb) };
}
const flush = async (log: ChangeLog) => log.entries();

describe('activity log', () => {
  it('records set, removed, expired and evicted', async () => {
    const { fb, log, jar } = setup();
    const [c1] = [await jar.create({ ...(await mkc(jar)), name: 'a' })];
    fb.expire(fb.seed({ name: 'e', domain: 'example.com' }));
    fb.evict(fb.seed({ name: 'v', domain: 'example.com' }));
    await jar.remove(c1);
    const es = await flush(log);
    expect(es.map((e) => [e.kind, e.cause, e.cookie.name])).toEqual([['set', 'explicit', 'a'], ['expired', 'expired', 'e'], ['evicted', 'evicted', 'v'], ['removed', 'explicit', 'a']]);
    expect(es.map((e) => e.id)).toEqual([1, 2, 3, 4]);
  });
  it('coalesces an overwrite and the set that follows into one changed entry', async () => {
    const { log, jar } = setup();
    const c = await mkc(jar);
    await jar.create(c);
    await jar.create({ ...c, value: 'two', secure: false, session: false, expirationDate: 4e9 });
    await flush(log);
    const es = await log.entries();
    expect(es.map((e) => e.kind)).toEqual(['set', 'changed']);
    expect(es[1]).toMatchObject({ cause: 'overwrite', fields: ['value', 'secure', 'expires'], cookie: { value: '' } });
    expect(es.some((e) => e.awaiting)).toBe(false);
  });
  it('a rewrite with identical content is still one changed entry with no fields', async () => {
    const { log, jar } = setup();
    const c = await mkc(jar);
    await jar.create(c);
    await jar.create(c);
    const es = await log.entries();
    expect(es).toHaveLength(2);
    expect(es[1]).toMatchObject({ kind: 'changed', fields: [] });
  });
  it('an expired overwrite is an expiry, not a change', async () => {
    const { fb, log } = setup();
    const c = fb.seed({ name: 'a', domain: 'example.com', secure: true });
    await (fb.cookies.set({ url: 'https://example.com/', name: 'a', value: 'x', secure: true, expirationDate: 1 }) as Promise<unknown>);
    expect((await log.entries()).map((e) => [e.kind, e.cause])).toEqual([['expired', 'expired_overwrite']]);
    expect(c).toBeTruthy();
  });
  it('interleaved cookies coalesce independently', async () => {
    const { log } = setup();
    const raw = (name: string, cause: string, removed: boolean, value: string) => ({ removed, cause, cookie: { name, value, domain: 'x.com', path: '/', storeId: '0', hostOnly: true } });
    await log.record(raw('a', 'overwrite', true, '1'));
    await log.record(raw('b', 'overwrite', true, '1'));
    await log.record(raw('b', 'explicit', false, '2'));
    await log.record(raw('a', 'explicit', false, '1'));
    const es = await log.entries();
    expect(es.map((e) => [e.cookie.name, e.kind, e.fields])).toEqual([['a', 'changed', []], ['b', 'changed', ['value']]]);
  });
  it('is bounded and drops the oldest', async () => {
    const { fb, log } = setup(5);
    for (let i = 0; i < 12; i++) fb.emit({ removed: false, cause: 'explicit', cookie: fb.seed({ name: `n${i}`, domain: 'x.com' }) });
    await flush(log);
    const es = await log.entries();
    expect(es.map((e) => e.cookie.name)).toEqual(['n7', 'n8', 'n9', 'n10', 'n11']);
    expect(MAX_ENTRIES).toBeGreaterThan(100);
  });
  it('never stores a cookie value, yet still detects a changed value', async () => {
    const { log, area } = setup();
    const raw = (removed: boolean, v: string, cause: string) => ({ removed, cause, cookie: { name: 'big', value: v, domain: 'x.com', path: '/', storeId: '0', hostOnly: true } });
    await log.record(raw(false, 'SECRET-ONE', 'explicit'));
    await log.record(raw(true, 'SECRET-ONE', 'overwrite'));
    expect(JSON.stringify(area.data)).not.toMatch(/SECRET/); // not even while the overwrite waits for its set
    await log.record(raw(false, 'SECRET-TWO', 'explicit'));
    await log.record(raw(true, 'SECRET-TWO', 'explicit'));
    const es = await log.entries();
    expect(JSON.stringify(area.data)).not.toMatch(/SECRET/);
    expect(es.map((e) => e.cookie.value)).toEqual(['', '', '']);
    expect(es[1]).toMatchObject({ kind: 'changed', fields: ['value'] });
    expect('vh' in es[1]!).toBe(false);
  });
  it('without storage.session the service keeps the log in memory, never in storage.local', async () => {
    const { createCookieService, registerCookieListeners } = await import('../lib/cookiejar/service');
    const fb = new FakeBrowser();
    const local = new FakeStorageArea();
    const svc = createCookieService({ cookies: fb.cookies, tabs: fb.tabs, storage: { local } }, { keyStore: { get: async () => undefined, put: async () => undefined } });
    registerCookieListeners({ cookies: fb.cookies }, svc);
    await svc.d.log.record({ removed: false, cookie: { name: 'a', value: 'SECRET', domain: 'x.com', path: '/', storeId: '0' } });
    expect(JSON.stringify(local.data)).not.toMatch(/SECRET|x\.com/);
    expect(await svc.d.log.entries()).toHaveLength(1);
    const m = memoryArea();
    await m.set({ k: 1 }); expect(await m.get('k')).toEqual({ k: 1 }); await m.remove('k'); expect(await m.get('k')).toEqual({});
  });
  it('survives the worker sleeping: a new instance on the same session storage sees the history and continues ids', async () => {
    const { fb, area, log } = setup();
    fb.emit({ removed: false, cause: 'explicit', cookie: fb.seed({ name: 'a', domain: 'x.com' }) });
    await flush(log);
    const log2 = new ChangeLog(area);
    expect((await log2.entries()).map((e) => e.id)).toEqual([1]);
    await log2.record({ removed: true, cause: 'explicit', cookie: { name: 'a', domain: 'x.com', path: '/', storeId: '0' } });
    expect((await log2.entries(1)).map((e) => e.id)).toEqual([2]);
    expect(Object.keys(area.data)).toEqual([LOG_KEY]);
  });
  it('an overwrite recorded before the sleep is completed after it', async () => {
    const { area, log } = setup();
    const c = { name: 'a', value: '1', domain: 'x.com', path: '/', storeId: '0', hostOnly: true };
    await log.record({ removed: true, cause: 'overwrite', cookie: c });
    const woke = new ChangeLog(area);
    await woke.record({ removed: false, cause: 'explicit', cookie: { ...c, value: '2' } });
    expect((await woke.entries()).map((e) => [e.kind, e.fields])).toEqual([['changed', ['value']]]);
  });
  it('notifies subscribers, clear keeps ids rising, quota errors drop the oldest half', async () => {
    const { area, log } = setup();
    const seen: number[] = [];
    const off = log.subscribe((e) => seen.push(e.id));
    const c = (n: string) => ({ removed: false, cause: 'explicit', cookie: { name: n, value: '', domain: 'x.com', path: '/', storeId: '0' } });
    await log.record(c('a')); await log.record(c('b'));
    off();
    await log.record(c('c'));
    expect(seen).toEqual([1, 2]);
    await log.clear();
    expect(await log.entries()).toEqual([]);
    await log.record(c('d'));
    expect((await log.entries()).map((e) => e.id)).toEqual([4]);
    for (const n of ['e', 'f', 'g', 'h']) await log.record(c(n));
    let calls = 0;
    const real = area.set.bind(area);
    area.set = async (i) => { if (calls++ === 0) throw new Error('QUOTA_BYTES'); return real(i); };
    await log.record(c('i'));
    expect((await log.entries()).map((e) => e.cookie.name)).toEqual(['g', 'h', 'i']);
  });
  it('a failing subscriber does not stop recording', async () => {
    const { log } = setup();
    log.subscribe(() => { throw new Error('page gone'); });
    await expect(log.record({ removed: false, cookie: { name: 'a', domain: 'x.com', path: '/', storeId: '0' } })).resolves.toBeTruthy();
  });
});

async function mkc(jar: CookieJar) {
  void jar;
  const { makeCookie } = await import('../lib/cookiejar/model');
  return makeCookie({ name: 'a', value: 'one', domain: 'example.com', storeId: '0', secure: true });
}

import { describe, expect, it } from 'vitest';
import { CookieJar } from '../lib/cookiejar/api';
import { CODECS, FORMAT_IDS } from '../lib/cookiejar/codecs';
import { applyPlan, detectFormat, planImport } from '../lib/cookiejar/detect';
import { identityKey, makeCookie } from '../lib/cookiejar/model';
import { FakeBrowser } from './helpers/fakebrowser';

const mk = (p: Record<string, unknown>) => makeCookie({ storeId: '0', ...p } as never);
const base = [mk({ name: 'sid', value: 'v', domain: '.example.com', hostOnly: false, secure: true, httpOnly: true, sameSite: 'lax', session: false, expirationDate: 4e9 }), mk({ name: 'p', value: '1', domain: 'example.com' })];

describe('detectFormat', () => {
  it('recognises what every codec exports', () => {
    for (const id of FORMAT_IDS) {
      expect(detectFormat(CODECS[id].export(base)), id).toBe(id === 'header' ? 'header' : id);
    }
  });
  it('recognises real-world variations', () => {
    expect(detectFormat('﻿  [ {"name":"a","domain":"x.com","storeId":"0"} ]')).toBe('json');
    expect(detectFormat('{"cookies":[{"name":"a","domain":"x.com","expires":-1}],"origins":[]}')).toBe('playwright');
    expect(detectFormat('[{"name":"a","domain":"x.com","expires":-1,"size":2}]')).toBe('puppeteer');
    expect(detectFormat('#HttpOnly_.x.com\tTRUE\t/\tTRUE\t0\ta\tb')).toBe('netscape');
    expect(detectFormat('.x.com\tTRUE\t/\tTRUE\t0\ta\tb\n.y.com\tTRUE\t/\tTRUE\t0\ta\tb')).toBe('netscape');
    expect(detectFormat('Host,Name,Value\nx.com,a,1')).toBe('csv');
    expect(detectFormat('Cookie: a=1; b=2')).toBe('header');
    expect(detectFormat('a=1; b=2')).toBe('header');
    expect(detectFormat('Set-Cookie: a=1; Path=/')).toBe('header');
  });
  it('returns null for text that is no cookie format', () => {
    expect(detectFormat('')).toBeNull();
    expect(detectFormat('hello world')).toBeNull();
    expect(detectFormat('{"a":1}')).toBeNull();
    expect(detectFormat('[1,2]')).toBeNull();
    expect(detectFormat('{broken')).toBeNull();
  });
});

describe('planImport', () => {
  const text = JSON.stringify([
    { name: 'new', value: '1', domain: 'example.com', path: '/', secure: false },
    { name: 'sid', value: 'changed', domain: '.example.com', hostOnly: false, path: '/', secure: true },
    { name: '__Host-bad', value: '1', domain: 'example.com', path: '/', secure: false },
    { name: 'old', value: '1', domain: 'example.com', session: false, expirationDate: 1000 },
    { name: 'tooBig', value: 'x'.repeat(5000), domain: 'example.com' },
    { value: 'no name', domain: 'example.com' },
  ]);
  it('classifies each row with a reason for the rejected ones', () => {
    const plan = planImport(text, { storeId: '0', existing: base, now: 2e12 });
    expect(plan.format).toBe('json');
    expect(plan.rows.map((r) => [r.row, r.status])).toEqual([[1, 'import'], [2, 'replace'], [3, 'rejected'], [4, 'rejected'], [5, 'rejected'], [6, 'rejected']]);
    expect(plan.rows[1]!.existing?.name).toBe('sid');
    expect(plan.rows[2]!.reason).toBe('A __Host- cookie must be Secure.');
    expect(plan.rows[3]!.reason).toMatch(/in the past/);
    expect(plan.rows[4]!.reason).toMatch(/over 4096/);
    expect(plan.rows[5]!.reason).toBe('This cookie has no name.');
    expect(plan.counts).toEqual({ import: 1, replace: 1, rejected: 4 });
  });
  it('puts every cookie into the target store; only that store counts as existing', () => {
    const other = [mk({ name: 'new', domain: 'example.com', storeId: '1' })];
    const plan = planImport('[{"name":"new","domain":"example.com"}]', { storeId: '1', existing: [...base, ...other] });
    expect(plan.rows[0]).toMatchObject({ status: 'replace', cookie: { storeId: '1' } });
    expect(planImport('[{"name":"new","domain":"example.com"}]', { storeId: '5', existing: other }).rows[0]!.status).toBe('import');
  });
  it('a later duplicate row wins and the earlier one says so', () => {
    const plan = planImport('[{"name":"a","value":"1","domain":"x.com"},{"name":"a","value":"2","domain":"x.com"}]', { storeId: '0', existing: [] });
    expect(plan.rows.map((r) => r.status)).toEqual(['rejected', 'import']);
    expect(plan.rows[0]!.reason).toBe('A later row (2) sets the same cookie.');
  });
  it('says when the text is not a format or holds nothing', () => {
    expect(planImport('hello', { storeId: '0', existing: [] }).rows[0]!.reason).toMatch(/not a cookie format/);
    expect(planImport('[]', { storeId: '0', existing: [], format: 'json' }).rows[0]!.reason).toBe('There are no cookies in this text.');
  });
  it('a header paste needs the site; with it, it plans', () => {
    expect(planImport('a=1; b=2', { storeId: '0', existing: [] }).counts.rejected).toBe(2);
    expect(planImport('a=1; b=2', { storeId: '0', existing: [], host: 'example.com' }).counts.import).toBe(2);
  });
  it('warns when the import would exceed the per-domain limit (merge counts existing, replace does not)', () => {
    const existing = Array.from({ length: 150 }, (_, i) => mk({ name: `e${i}`, domain: 'example.com' }));
    const incoming = JSON.stringify(Array.from({ length: 40 }, (_, i) => ({ name: `n${i}`, domain: 'www.example.com' })));
    const merge = planImport(incoming, { storeId: '0', existing, mode: 'merge' });
    expect(merge.warnings).toEqual(['example.com would hold 190 cookies, but browsers keep about 180 per domain and drop the oldest.']);
    expect(planImport(incoming, { storeId: '0', existing, mode: 'replace' }).warnings).toEqual([]);
    expect(planImport(incoming, { storeId: '0', existing, mode: 'merge', limitPerDomain: 150 }).warnings).toHaveLength(1);
    expect(planImport(incoming, { storeId: '0', existing: [], mode: 'merge' }).warnings).toEqual([]);
  });
});

describe('applyPlan', () => {
  function setup() {
    const fb = new FakeBrowser();
    fb.seed({ name: 'sid', value: 'v', domain: '.example.com', hostOnly: false, secure: true });
    fb.seed({ name: 'stay', value: '1', domain: 'example.com' });
    fb.seed({ name: 'prot', value: '1', domain: 'example.com' });
    fb.seed({ name: 'elsewhere', value: '1', domain: 'other.com' });
    return { fb, jar: new CookieJar(fb) };
  }
  const incoming = JSON.stringify([{ name: 'sid', value: 'new', domain: '.example.com', hostOnly: false, secure: true }, { name: 'fresh', value: '1', domain: 'example.com' }, { name: '__Secure-x', value: '1', domain: 'example.com' }]);

  it('merge adds and overwrites, leaves the rest', async () => {
    const { fb, jar } = setup();
    const plan = planImport(incoming, { storeId: '0', existing: await jar.list() });
    const r = await applyPlan(jar, plan);
    expect(r).toMatchObject({ created: 1, replaced: 1, removed: 0, failed: [] });
    expect(fb.all().map((c) => c.name).sort()).toEqual(['elsewhere', 'fresh', 'prot', 'sid', 'stay']);
    expect(fb.all().find((c) => c.name === 'sid')!.value).toBe('new');
  });
  it('replace also removes the site\'s other cookies, but not protected ones or other sites', async () => {
    const { fb, jar } = setup();
    const existing = await jar.list();
    const prot = existing.find((c) => c.name === 'prot')!;
    const plan = planImport(incoming, { storeId: '0', existing, mode: 'replace' });
    const r = await applyPlan(jar, plan, { isProtected: (c) => identityKey(c) === identityKey(prot) });
    expect(r).toMatchObject({ created: 1, replaced: 1, removed: 1, skippedProtected: 1 });
    expect(fb.all().map((c) => c.name).sort()).toEqual(['elsewhere', 'fresh', 'prot', 'sid']);
  });
  it('reports browser failures per row and still imports the rest; no removal of what failed to import', async () => {
    const { fb, jar } = setup();
    fb.failWhen = (op, d) => op === 'set' && d.name === 'fresh';
    const plan = planImport(incoming, { storeId: '0', existing: await jar.list(), mode: 'replace' });
    const r = await applyPlan(jar, plan);
    expect(r.failed).toHaveLength(1);
    expect(r.failed[0]).toMatchObject({ row: 2 });
    expect(r.replaced).toBe(1);
    expect(fb.all().map((c) => c.name).sort()).toEqual(['elsewhere', 'sid']);
  });
});

describe('first-party isolation data on a browser without it', () => {
  const text = JSON.stringify([{ name: 'a', domain: 'example.com', firstPartyDomain: 'example.com' }]);
  it('still imports the row, drops the field and says so', () => {
    const plan = planImport(text, { storeId: '0', existing: [], firstPartyDomain: false });
    expect(plan.rows[0]).toMatchObject({ status: 'import', cookie: { firstPartyDomain: '' }, note: 'First-party isolation data was dropped because this browser does not support it.' });
    const keep = planImport(text, { storeId: '0', existing: [], firstPartyDomain: true });
    expect(keep.rows[0]).toMatchObject({ cookie: { firstPartyDomain: 'example.com' } });
    expect(keep.rows[0]!.note).toBeUndefined();
  });
  it('and it applies on Chrome', async () => {
    const fb = new FakeBrowser();
    const jar = new CookieJar(fb);
    const r = await applyPlan(jar, planImport(text, { storeId: '0', existing: [], firstPartyDomain: false }));
    expect(r).toMatchObject({ created: 1, failed: [] });
  });
});

import { IDBFactory } from 'fake-indexeddb';
import { describe, expect, it } from 'vitest';
import { idbKeyStore } from '../lib/cookiejar/crypto';
import { makeCookie } from '../lib/cookiejar/model';
import { cookieNameOption, cookieRule } from '../lib/cookiejar/rule';
import { ALARM_PREFIX } from '../lib/cookiejar/rules';
import { createCookieService, registerCookieListeners, servePort, type CookieRequest } from '../lib/cookiejar/service';
import { makeRule } from '../lib/rulegen';
import { FakeAlarms, FakeBrowser, FakeStorageArea } from './helpers/fakebrowser';

function browser(o = {}) {
  const fb = new FakeBrowser(o);
  const listeners: Record<string, ((...a: any[]) => void)[]> = { updated: [], removed: [], startup: [] };
  const alarms = new FakeAlarms();
  const br: any = {
    cookies: fb.cookies, tabs: { ...fb.tabs, onUpdated: { addListener: (f: any) => listeners.updated!.push(f) }, onRemoved: { addListener: (f: any) => listeners.removed!.push(f) } },
    alarms: Object.assign(alarms, {}), runtime: { onStartup: { addListener: (f: any) => listeners.startup!.push(f) } },
    storage: { local: new FakeStorageArea(), session: new FakeStorageArea() },
    contextualIdentities: fb.contextualIdentities,
  };
  return { fb, br, listeners, alarms };
}

class FakePort {
  sent: any[] = [];
  private onMsg: ((m: any) => unknown)[] = [];
  private onDis: (() => void)[] = [];
  onMessage = { addListener: (f: (m: any) => unknown) => this.onMsg.push(f) };
  onDisconnect = { addListener: (f: () => void) => this.onDis.push(f) };
  postMessage(m: any) { this.sent.push(m); }
  async send(m: any) { for (const f of this.onMsg) await f(m); }
  disconnect() { for (const f of this.onDis) f(); }
}

async function call(port: FakePort, req: CookieRequest, id = port.sent.length + 100) {
  await port.send({ ...req, rid: id });
  const r = port.sent.find((m) => m.rid === id);
  return r as { ok: boolean; result: any; error: { code: string; message: string } };
}

const keyStore = () => idbKeyStore({ factory: new IDBFactory() });

describe('cookies port', () => {
  function ready() {
    const b = browser();
    const svc = createCookieService(b.br, { keyStore: keyStore(), iterations: 1000 });
    registerCookieListeners(b.br, svc);
    const port = new FakePort();
    servePort(port, svc);
    return { ...b, svc, port };
  }

  it('lists stores and cookies, creates, edits and deletes through one request shape', async () => {
    const { fb, port } = ready();
    expect((await call(port, { op: 'stores' })).result.map((s: any) => s.label)).toEqual(['Default']);
    const c = makeCookie({ name: 'a', value: '1', domain: 'example.com', storeId: '0' });
    expect((await call(port, { op: 'create', cookie: c })).ok).toBe(true);
    const list = (await call(port, { op: 'list', site: 'example.com' })).result;
    expect(list).toHaveLength(1);
    const edited = await call(port, { op: 'edit', old: list[0], next: { ...list[0], name: 'b' } });
    expect(edited.result.name).toBe('b');
    expect(fb.all().map((x) => x.name)).toEqual(['b']);
    const del = await call(port, { op: 'remove', cookies: [edited.result] });
    expect(del.result.done).toHaveLength(1);
    expect(fb.all()).toEqual([]);
  });

  it('turns library errors into code + one-sentence message', async () => {
    const { port } = ready();
    const r = await call(port, { op: 'create', cookie: makeCookie({ name: '__Host-a', domain: 'example.com', storeId: '0' }) });
    expect(r).toMatchObject({ ok: false, error: { code: 'invalid', message: 'A __Host- cookie must be Secure.' } });
    const v = await call(port, { op: 'validate', cookie: makeCookie({ name: 'a b', domain: 'example.com' }) });
    expect(v.result[0].field).toBe('name');
    const boom = await call(port, { op: 'snapshot.restore', id: 'nope' });
    expect(boom.error.code).toBe('not-found');
  });

  it('bulk delete skips protected cookies; an explicit delete does not', async () => {
    const { fb, port } = ready();
    fb.seed({ name: 'keep', domain: 'example.com' }); fb.seed({ name: 'drop', domain: 'example.com' });
    const all = (await call(port, { op: 'list' })).result;
    await call(port, { op: 'rules.protect', cookies: [all.find((c: any) => c.name === 'keep')], protect: true });
    const bulk = await call(port, { op: 'removeMany', cookies: all });
    expect([bulk.result.done.length, bulk.result.skipped.length]).toEqual([1, 1]);
    expect(fb.all().map((c) => c.name)).toEqual(['keep']);
    const one = await call(port, { op: 'remove', cookies: all.filter((c: any) => c.name === 'keep') });
    expect(one.result.done).toHaveLength(1);
    expect(fb.all()).toEqual([]);
  });

  it('exports every format, snippets and encrypted exports, and imports them back with a dry run first', async () => {
    const { fb, port } = ready();
    fb.seed({ name: 'a', value: 'secret', domain: 'example.com', secure: true });
    const cookies = (await call(port, { op: 'list' })).result;
    expect((await call(port, { op: 'export', cookies, format: 'netscape' })).result).toMatchObject({ extension: 'txt', mime: 'text/plain' });
    expect((await call(port, { op: 'export', cookies, snippet: 'curl', url: 'https://example.com/' })).result.text).toBe("curl -b 'a=secret' 'https://example.com/'");
    const enc = (await call(port, { op: 'export', cookies, format: 'json', passphrase: 'pw' })).result;
    expect(enc.text).not.toContain('secret');
    expect(enc.extension).toBe('enc.json');
    fb.jar.clear();
    const noPass = await call(port, { op: 'import', text: enc.text, storeId: '0' });
    expect(noPass.error.code).toBe('wrong-passphrase');
    const wrong = await call(port, { op: 'import', text: enc.text, storeId: '0', passphrase: 'bad' });
    expect(wrong.error.code).toBe('wrong-passphrase');
    const dry = await call(port, { op: 'import', text: enc.text, storeId: '0', passphrase: 'pw', dryRun: true });
    expect(dry.result.plan.counts).toEqual({ import: 1, replace: 0, rejected: 0 });
    expect(dry.result.plan.existing).toEqual([]);
    expect(fb.all()).toEqual([]);
    const done = await call(port, { op: 'import', text: enc.text, storeId: '0', passphrase: 'pw' });
    expect(done.result.result).toMatchObject({ created: 1, failed: [] });
    expect(fb.all()[0]).toMatchObject({ name: 'a', value: 'secret' });
  });

  it('copies and moves between stores', async () => {
    const b = browser({ stores: [{ id: '0' }, { id: '1' }] });
    const svc = createCookieService(b.br, { keyStore: keyStore(), iterations: 1000 });
    const port = new FakePort(); servePort(port, svc);
    b.fb.seed({ name: 'a', domain: 'example.com' });
    const cs = (await call(port, { op: 'list' })).result;
    await call(port, { op: 'copy', cookies: cs, toStoreId: '1' });
    expect(b.fb.all()).toHaveLength(2);
    await call(port, { op: 'copy', cookies: cs, toStoreId: '1', move: true, conflict: 'overwrite' });
    expect(b.fb.all().map((c) => c.storeId)).toEqual(['1']);
  });

  it('saves, diffs and restores snapshots; the stored data is encrypted', async () => {
    const { fb, br, port } = ready();
    fb.seed({ name: 'sid', value: 'TOPSECRET', domain: 'example.com' });
    const meta = (await call(port, { op: 'snapshot.save', name: 'before', site: 'example.com' })).result;
    expect(JSON.stringify(br.storage.local.data)).not.toContain('TOPSECRET');
    fb.jar.clear();
    const d = await call(port, { op: 'snapshot.diff', id: meta.id });
    expect(d.error).toBeUndefined();
    expect(d.result.removed).toHaveLength(1);
    await call(port, { op: 'snapshot.restore', id: meta.id });
    expect(fb.all()[0]!.value).toBe('TOPSECRET');
    expect((await call(port, { op: 'snapshot.list' })).result).toHaveLength(1);
    expect((await call(port, { op: 'snapshot.delete', id: meta.id })).result).toBe(true);
  });

  it('rules round trip and the activity log streams to the page', async () => {
    const { fb, port } = ready();
    expect((await call(port, { op: 'rules.set', rules: { keep: ['Example.com'] } })).result.keep).toEqual(['example.com']);
    expect((await call(port, { op: 'rules.get' })).result.keep).toEqual(['example.com']);
    fb.emit({ removed: false, cause: 'explicit', cookie: fb.seed({ name: 'live', domain: 'example.com' }) });
    await new Promise((r) => setTimeout(r, 5));
    const streamed = port.sent.filter((m) => m.t === 'activity');
    expect(streamed[0].entry).toMatchObject({ kind: 'set', cookie: { name: 'live' } });
    const since = await call(port, { op: 'activity.since', since: 0 });
    expect(since.result).toHaveLength(1);
    await call(port, { op: 'activity.clear' });
    expect((await call(port, { op: 'activity.since' })).result).toEqual([]);
    port.disconnect();
    fb.emit({ removed: false, cause: 'explicit', cookie: fb.seed({ name: 'later', domain: 'example.com' }) });
    await new Promise((r) => setTimeout(r, 5));
    expect(port.sent.filter((m) => m.t === 'activity')).toHaveLength(1);
  });

  it('ignores malformed messages', async () => {
    const { port } = ready();
    await port.send(null);
    await port.send({ op: 'stores' });
    expect(port.sent).toEqual([]);
  });

  it('never sends a cookie value to a server: the library makes no network calls', async () => {
    const { fb, port } = ready();
    const real = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = (async () => { calls++; return new Response(''); }) as typeof fetch;
    try {
      fb.seed({ name: 'a', value: 'v', domain: 'example.com' });
      const cs = (await call(port, { op: 'list' })).result;
      await call(port, { op: 'rule.line', cookie: cs[0], options: { action: 'remove' } });
      await call(port, { op: 'export', cookies: cs, format: 'csv' });
    } finally { globalThis.fetch = real; }
    expect(calls).toBe(0);
  });
});

describe('background listeners', () => {
  it('registers the change log, tab, alarm and startup listeners', async () => {
    const b = browser();
    const svc = createCookieService(b.br, { keyStore: keyStore(), iterations: 1000 });
    registerCookieListeners(b.br, svc);
    await svc.d.rules.update({ autoDelete: { enabled: true, delayMinutes: 1 } });
    b.fb.seed({ name: 'a', domain: 'example.com' });
    b.listeners.updated![0]!(1, { url: 'https://example.com/' });
    b.listeners.updated![0]!(1, { status: 'loading' }); // no url: ignored
    await new Promise((r) => setTimeout(r, 10));
    b.listeners.removed![0]!(1);
    await new Promise((r) => setTimeout(r, 10));
    expect(b.alarms.items.has(ALARM_PREFIX + 'example.com')).toBe(true);
    await b.alarms.fire(ALARM_PREFIX + 'example.com');
    await new Promise((r) => setTimeout(r, 20));
    expect(b.fb.all()).toEqual([]);
    expect((await svc.d.log.entries()).map((e) => e.kind)).toEqual(['removed']); // the cleanup itself shows in the activity log
    b.fb.tabList = [];
    b.listeners.startup![0]!();
  });
  it('tolerates a browser without alarms, tabs or onChanged', () => {
    const svc = createCookieService({ cookies: {}, storage: { local: new FakeStorageArea() } });
    expect(() => registerCookieListeners({}, svc)).not.toThrow();
  });
});

describe('cookie to rule', () => {
  const c = (name: string, domain = 'www.example.com') => makeCookie({ name, domain, storeId: '0' });
  it('writes $cookie rules in the rulegen conventions, with no value', () => {
    expect(cookieRule(c('_ga'), { action: 'remove' })).toBe('||www.example.com^$cookie=_ga');
    expect(cookieRule(c('_ga', '.www.example.com'), { action: 'allow', scope: 'site' })).toBe('@@||example.com^$cookie=_ga');
    expect(cookieRule(c('_ga'), { action: 'remove', thirdParty: true })).toBe('||www.example.com^$cookie=_ga,third-party');
    expect(cookieRule(c('sid'), { action: 'modify', maxAge: 3600.9, sameSite: 'lax' })).toBe('||www.example.com^$cookie=sid;maxAge=3600;sameSite=lax');
    expect(cookieRule(c('sid'), { action: 'remove', maxAge: 5 })).toBe('||www.example.com^$cookie=sid');
    expect(cookieRule(makeCookie({ name: 'secretname', value: 'VALUE', domain: 'x.com' }), { action: 'remove' })).not.toContain('VALUE');
  });
  it('agrees with rulegen on the host pattern', () => {
    expect(cookieRule(c('a'), { action: 'remove' }).split('$')[0]).toBe(makeRule('https://www.example.com/', { action: 'block', scope: 'everywhere', match: 'host', thirdParty: false, important: false, site: '' }));
  });
  it('writes names that cannot appear verbatim as an anchored regex', () => {
    expect(cookieNameOption('a_b-c.d')).toBe('a_b-c.d');
    expect(cookieNameOption('a,b;c$d')).toBe('/^a\\x2Cb\\x3Bc\\$d$/');
    expect(cookieNameOption('/x')).toBe('/^\\/x$/');
    expect(new RegExp(cookieNameOption('a,b;c$d').slice(1, -1)).test('a,b;c$d')).toBe(true);
  });
});

describe('listed cookies', () => {
  it('carry an isProtected flag for the page to label', async () => {
    const b = browser();
    const svc = createCookieService(b.br, { keyStore: keyStore() });
    const port = new FakePort(); servePort(port, svc);
    b.fb.seed({ name: 'keep', domain: 'example.com' }); b.fb.seed({ name: 'other', domain: 'example.com' });
    const first = (await call(port, { op: 'list' })).result;
    expect(first.map((c: any) => c.isProtected)).toEqual([false, false]);
    await call(port, { op: 'rules.protect', cookies: [first.find((c: any) => c.name === 'keep')], protect: true });
    expect((await call(port, { op: 'list' })).result.map((c: any) => [c.name, c.isProtected])).toEqual([['keep', true], ['other', false]]);
  });
  it('import on a Chrome-like browser drops first-party isolation data with a note', async () => {
    const b = browser();
    const svc = createCookieService(b.br, { keyStore: keyStore() });
    const port = new FakePort(); servePort(port, svc);
    const r = await call(port, { op: 'import', text: '[{"name":"a","domain":"example.com","firstPartyDomain":"example.com"}]', storeId: '0', dryRun: true });
    expect(r.result.plan.rows[0].note).toMatch(/First-party isolation/);
  });
});

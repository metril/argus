import { afterEach, describe, expect, it, vi } from 'vitest';
import { ClientError, CookieClient } from '../ui/cookies/client';
import { cookieWorld, portPair } from './helpers/cookiepage';
import { provenanceFetch } from './helpers/cookiefixture';
import { mountPage, rowNames, settle, sleep, type Page } from './helpers/pagekit';
import { throttle } from '../ui/cookies/data';

let page: Page | undefined;
afterEach(() => { page?.unmount(); page = undefined; vi.unstubAllGlobals(); vi.useRealTimers(); });
const mount: typeof mountPage = async (o) => (page = await mountPage(o));

describe('port reconnect', () => {
  it('reconnects with a backoff after the background drops it, rejects what was pending, resyncs and receives activity again', async () => {
    const w = cookieWorld({ stores: [{ id: '0' }] });
    const { servePort } = await import('../lib/cookiejar/service');
    const pairs: ReturnType<typeof portPair>[] = [];
    const client = new CookieClient(() => { const p = portPair(); pairs.push(p); servePort(p.background, w.svc); return p.page; }, { backoffMs: 20, alive: () => true });
    const seen: string[] = [];
    let synced = 0;
    client.onActivity((e) => seen.push(e.cookie.name));
    client.onResync(() => { synced++; });
    expect(await client.call({ op: 'stores' })).toHaveLength(1);
    expect(pairs).toHaveLength(1);

    // a request in flight when the worker goes to sleep
    const inflight = client.call({ op: 'stores' });
    pairs[0]!.background.disconnect();
    await expect(inflight).rejects.toMatchObject({ code: 'disconnected' });
    expect(inflight).rejects.toBeInstanceOf(ClientError);

    await sleep(80);
    expect(pairs.length).toBeGreaterThanOrEqual(2);
    expect(synced).toBe(1);
    await w.br.cookies.set({ url: 'https://a.example/', name: 'after', value: '1' });
    await sleep(40);
    expect(seen).toContain('after');
    client.close();
  });

  it('keeps backing off while the connection keeps failing', async () => {
    let n = 0;
    const client = new CookieClient(() => { n++; throw new Error('no background'); }, { backoffMs: 10, maxBackoffMs: 40, alive: () => true });
    client.onActivity(() => {});
    await sleep(180);
    expect(n).toBeGreaterThan(2);
    expect(n).toBeLessThan(12);
    client.close();
  });

  it('the page reloads its data after a reconnect', async () => {
    const p = await mount();
    const before = rowNames(p).length;
    // a change the page never heard about (the worker was asleep)
    p.w.fb.seed({ name: 'missed', value: '1', domain: 'stackoverflow.com' });
    expect(rowNames(p)).not.toContain('missed');
    (p.w.client as any).port?.disconnect?.();
    (p.w.client as any).port = null;
    (p.w.client as any).lost = true;
    await p.w.client.call({ op: 'stores' });
    await p.waitFor(() => rowNames(p).includes('missed'), 'resynced');
    expect(rowNames(p).length).toBe(before + 1);
  });
});

describe('refresh cost and starvation', () => {
  it('throttle runs at the latest after maxWait however fast calls come', async () => {
    vi.useFakeTimers();
    let ran = 0;
    const t = throttle(() => { ran++; }, 350, 2000);
    for (let i = 0; i < 100; i++) { t.call(); vi.advanceTimersByTime(100); }
    expect(ran).toBeGreaterThanOrEqual(4);
    t.cancel();
  });

  it('under a continuous stream of activity the table still updates within the max wait', async () => {
    const p = await mount();
    let i = 0;
    const timer = setInterval(() => { void p.w.br.cookies.set({ url: 'https://www.stackoverflow.com/', name: `burst${i++}`, value: 'x' }); }, 100);
    const t0 = Date.now();
    try { await p.waitFor(() => rowNames(p).includes('burst0'), 'first burst cookie shown', 4000); } finally { clearInterval(timer); }
    expect(Date.now() - t0).toBeLessThan(2800);
  }, 10000);

  it('applies a removal from the activity entry itself, then only a throttled re-read of the cookies (never the stores)', async () => {
    const p = await mount();
    const ops: string[] = [];
    const call = p.w.client.call.bind(p.w.client);
    (p.w.client as any).call = (r: { op: string }) => { ops.push(r.op); return call(r as never); };
    const gone = p.w.fb.all().find((c) => c.name === 'acct')!;
    p.w.fb.expire(gone);
    await p.waitFor(() => !rowNames(p).includes('acct'), 'row dropped');
    expect(ops).not.toContain('list'); // dropped from the entry itself, before any read
    await settle(700);
    expect(ops).not.toContain('stores');
    // a set only re-reads the cookies, not the stores
    await p.w.br.cookies.set({ url: 'https://www.stackoverflow.com/', name: 'newone', value: '1' });
    await p.waitFor(() => rowNames(p).includes('newone'), 'new row');
    expect(ops).toContain('list');
    expect(ops).not.toContain('stores');
  });

  it('pauses while the page is hidden and catches up on visibilitychange', async () => {
    const p = await mount();
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => true });
    try {
      await p.w.br.cookies.set({ url: 'https://www.stackoverflow.com/', name: 'whilehidden', value: '1' });
      await settle(900);
      expect(rowNames(p)).not.toContain('whilehidden');
    } finally { Object.defineProperty(document, 'hidden', { configurable: true, get: () => false }); }
    document.dispatchEvent(new Event('visibilitychange'));
    await p.waitFor(() => rowNames(p).includes('whilehidden'), 'caught up');
  });

  it('asks the server only for provenance newer than the last record after the first read', async () => {
    const calls: { path: string; sid: string | null; search: string }[] = [];
    const p = await mount();
    vi.stubGlobal('fetch', provenanceFetch({ mode: 'on', calls }));
    await p.w.br.cookies.set({ url: 'https://www.stackoverflow.com/', name: 'prov-trigger', value: '1' });
    await p.waitFor(() => calls.length > 0, 'provenance refresh', 6000);
    const since = Number(new URLSearchParams(calls[0]!.search).get('since'));
    expect(since).toBeGreaterThan(0);
  }, 10000);

  it('a read that started before a removal cannot bring the removed cookie back', async () => {
    const p = await mount();
    const old = await p.w.client.call({ op: 'list' });
    expect(old.some((c) => c.name === 'acct')).toBe(true);
    let release: (() => void) | undefined;
    let held = false;
    const call = p.w.client.call.bind(p.w.client);
    (p.w.client as any).call = (r: { op: string }) => {
      if (r.op === 'list' && !held) { held = true; return new Promise((ok) => { release = () => ok(old); }); }
      return call(r as never);
    };
    // a set starts a (held) read, then a removal lands while it is in flight
    await p.w.br.cookies.set({ url: 'https://www.stackoverflow.com/', name: 'trigger', value: '1' });
    await p.waitFor(() => held, 'a read in flight', 4000);
    p.w.fb.expire(p.w.fb.all().find((c) => c.name === 'acct')!);
    await p.waitFor(() => !rowNames(p).includes('acct'), 'dropped locally');
    release!();
    await settle(100);
    expect(rowNames(p)).not.toContain('acct');
    await p.waitFor(() => rowNames(p).includes('trigger'), 'the fresh read shows the new cookie', 4000);
    expect(rowNames(p)).not.toContain('acct');
  }, 12000);
});

describe('extension updated under the page', () => {
  it('stops retrying when the extension context is gone, rejects calls and shows a notice with Reload', async () => {
    let alive = true;
    let connects = 0;
    const w = cookieWorld({ stores: [{ id: '0' }] });
    const { servePort } = await import('../lib/cookiejar/service');
    const pairs: ReturnType<typeof portPair>[] = [];
    const client = new CookieClient(() => { connects++; if (!alive) throw new Error('Extension context invalidated.'); const q = portPair(); pairs.push(q); servePort(q.background, w.svc); return q.page; }, { backoffMs: 10, alive: () => alive });
    let dead = 0;
    client.onDead(() => { dead++; });
    client.onActivity(() => {});
    expect(await client.call({ op: 'stores' })).toHaveLength(1);
    alive = false;
    pairs[0]!.background.disconnect();
    await sleep(150);
    const seen = connects;
    expect(dead).toBe(1);
    await sleep(150);
    expect(connects).toBe(seen);
    await expect(client.call({ op: 'stores' })).rejects.toMatchObject({ code: 'stale' });
  });

  it('the page says so in one line with a Reload button', async () => {
    const p = await mount();
    (p.w.client as any).markDead();
    await settle(30);
    expect(p.text('[data-testid=stale-notice]')).toBe('Argus was updated. Reload this page.Reload');
  });
});

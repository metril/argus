import { describe, expect, it, vi } from 'vitest';
import {
  applyError, classify, emptyStats, MAX_HOSTS, PENDING_TTL_MS, percent, reconcile, reduce, registrableDomain, StatsStore,
  type Area, type StatsMap,
} from '../lib/stats';

const hdr = (v?: string) => (v === undefined ? [{ name: 'content-type', value: 'x' }] : [{ name: 'X-Adblock', value: v }]);
const resp = (tabId: number, kind: 'blocked' | 'redirected' | 'allowed', host: string, main = false) => ({ t: 'response' as const, tabId, main, kind, host });

describe('classify', () => {
  it.each([
    ['blocked', 'blocked'], ['policy', 'blocked'], ['redirected', 'redirected'], ['rewritten', 'redirected'],
    ['cert-error', 'other'], ['destination-refused', 'other'], ['sinkholed-upstream', 'other'],
  ])('x-adblock %s is %s', (v, k) => expect(classify(hdr(v))).toBe(k));
  it('is allowed without the header, and case-insensitive on the name and value', () => {
    expect(classify(hdr())).toBe('allowed');
    expect(classify(undefined)).toBe('allowed');
    expect(classify([{ name: 'x-adblock', value: 'BLOCKED' }])).toBe('blocked');
  });
});

describe('reduce', () => {
  it('counts per tab and per host', () => {
    let m: StatsMap = {};
    for (const e of [resp(1, 'blocked', 'ads.x'), resp(1, 'blocked', 'ads.x'), resp(1, 'redirected', 'cdn.x'), resp(1, 'allowed', 'site.x'), resp(1, 'allowed', 'cdn.x'), resp(2, 'allowed', 'other.x')]) m = reduce(m, e);
    expect(m[1]).toMatchObject({ blocked: 2, redirected: 1, allowed: 2 });
    expect(m[1]!.hosts).toEqual({ 'ads.x': { blocked: 2, allowed: 0 }, 'cdn.x': { blocked: 1, allowed: 1 }, 'site.x': { blocked: 0, allowed: 1 } });
    expect(percent(m[1]!)).toBe(60);
    expect(m[2]!.allowed).toBe(1);
  });
  it('ignores other responses and tabs below zero', () => {
    const m = reduce({}, { t: 'response', tabId: 1, main: false, kind: 'other', host: 'h' });
    expect(m[1]).toMatchObject({ blocked: 0, allowed: 0, hosts: {} });
    expect(reduce({}, resp(-1, 'blocked', 'h'))).toEqual({});
  });
  it('resets on a top-frame navigation and counts the document itself in the new page', () => {
    let m = reduce({}, resp(1, 'blocked', 'ads.x'));
    m = reduce(m, resp(1, 'allowed', 'new.x', true));
    expect(m[1]).toMatchObject({ blocked: 0, allowed: 1, hosts: { 'new.x': { blocked: 0, allowed: 1 } } });
  });
  it('drops the entry when the tab closes, and tolerates an unknown tab', () => {
    let m = reduce({}, resp(1, 'blocked', 'a'));
    m = reduce(reduce(m, resp(2, 'allowed', 'b')), { t: 'close', tabId: 1 });
    expect(Object.keys(m)).toEqual(['2']);
    expect(reduce(m, { t: 'close', tabId: 9 })).toBe(m);
  });
  it('bounds the host map', () => {
    let m: StatsMap = {};
    for (let i = 0; i < MAX_HOSTS + 20; i++) m = reduce(m, resp(1, 'allowed', `h${i}.x`));
    expect(Object.keys(m[1]!.hosts)).toHaveLength(MAX_HOSTS);
    expect(m[1]!.allowed).toBe(MAX_HOSTS + 20);
  });
});

describe('aborted blocks', () => {
  it('ignores the page cancelling a request, keeps real network errors pending', () => {
    let s = applyError(emptyStats(), 'https://a/x', 0, 'net::ERR_ABORTED');
    expect(s.pending).toHaveLength(0);
    s = applyError(s, 'https://a/x', 0, 'NS_BINDING_ABORTED');
    expect(s.pending).toHaveLength(0);
    s = applyError(s, 'https://ads.x/p.js#frag', 0, 'net::ERR_FAILED');
    expect(s.pending).toEqual([{ url: 'https://ads.x/p.js#frag', host: 'ads.x', at: 0 }]);
  });
  it('matches a ring entry once, only if recent enough and from the same page', () => {
    let s = reduce({}, { t: 'response', tabId: 1, main: true, kind: 'allowed', host: 'page.x' })[1]!;
    for (const at of [10_000, 10_100]) s = applyError(s, 'https://ads.x/p.js', at, 'net::ERR_FAILED');
    const ring = (at: number, source: string) => ({ url: 'https://ads.x/p.js', at, source });
    // old entry and other page's entry never match
    let r = reconcile(s, [ring(1000, 'page.x'), ring(10_000, 'other.x')], 10_200);
    expect(r.blocked).toBe(0);
    // one matching entry is consumed by one failure only
    r = reconcile(s, [ring(9_000, 'page.x')], 10_200);
    expect(r.blocked).toBe(1);
    expect(r.pending).toHaveLength(1);
    r = reconcile(s, [ring(9_000, 'page.x'), ring(10_050, 'PAGE.x')], 10_200);
    expect(r.blocked).toBe(2);
  });
  it('attributes errors the proxy logged as blocked, expires the rest as failed, keeps the young', () => {
    let s = emptyStats();
    for (const [u, at] of [['https://ads.x/p.js?id=7', 0], ['https://down.x/api', 0], ['https://later.x/q', 9000]] as const) s = applyError(s, u, at, 'net::ERR_FAILED');
    const r = reconcile(s, [{ url: 'https://ads.x/p.js', at: 0 }], PENDING_TTL_MS + 1);
    expect(r).toMatchObject({ blocked: 1, failed: 1, hosts: { 'ads.x': { blocked: 1, allowed: 0 } } });
    expect(r.pending.map((p) => p.url)).toEqual(['https://later.x/q']);
    expect(reduce({ 1: s }, { t: 'reconcile', tabId: 1, blocked: [], now: 1 })[1]!.pending).toHaveLength(3);
  });
});

describe('page reset', () => {
  it('a main-frame cancel keeps the counts, a main-frame error or response resets them', () => {
    let m = reduce({}, resp(1, 'blocked', 'ads.x'));
    const err = (error: string) => ({ t: 'error' as const, tabId: 1, main: true, url: 'https://p.x/', now: 0, error });
    expect(reduce(m, err('net::ERR_ABORTED'))[1]!.blocked).toBe(1);
    expect(reduce(m, err('net::ERR_CONNECTION_REFUSED'))[1]!.blocked).toBe(0);
    m = reduce(m, resp(1, 'allowed', 'p.x', true));
    expect(m[1]!.blocked).toBe(0);
    expect(m[1]!.pageHost).toBe('p.x');
  });
});

describe('StatsStore', () => {
  const area = (init: Record<string, unknown> = {}): Area & { data: Record<string, unknown> } => {
    const data = { ...init };
    return { data, get: async (k) => ({ [k]: data[k] }), set: async (o) => { Object.assign(data, o); } };
  };
  it('persists to session storage and a fresh worker reloads it', async () => {
    const a = area();
    const changed = vi.fn();
    const s1 = new StatsStore(a, changed, 0);
    await s1.dispatch(resp(5, 'blocked', 'ads.x'));
    await s1.flush();
    expect(changed).toHaveBeenCalledWith(5);
    const s2 = new StatsStore(a, () => {}, 0);
    expect((await s2.tab(5)).blocked).toBe(1);
    await s2.dispatch({ t: 'close', tabId: 5 });
    await s2.flush();
    expect((a.data.tabStats as StatsMap)[5]).toBeUndefined();
  });
  it('works without session storage', async () => {
    const s = new StatsStore(undefined, () => {}, 0);
    await s.dispatch(resp(1, 'allowed', 'h'));
    expect((await s.tab(1)).allowed).toBe(1);
  });
});

describe('registrableDomain', () => {
  it.each([
    ['www.example.com', 'example.com'], ['a.b.example.co.uk', 'example.co.uk'], ['example.com', 'example.com'],
    ['localhost', 'localhost'], ['x.shop.com.pl', 'shop.com.pl'], ['a.x.gov.au', 'x.gov.au'], ['a.foo.herokuapp.com', 'foo.herokuapp.com'], ['[::1]', '[::1]'], ['192.168.1.5', '192.168.1.5'], ['EXAMPLE.org.', 'example.org'],
  ])('%s -> %s', (h, d) => expect(registrableDomain(h)).toBe(d));
});

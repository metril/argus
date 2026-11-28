import { describe, expect, it, vi } from 'vitest';
import type { LogEntry } from '../lib/api';
import { chartData, valueOf } from '../lib/chart';
import { applyFilters, exportText, matches, noFilters, statusKeys, typeKey } from '../lib/logfilter';
import { addRows, joinEntries, MAX_ROWS_PER_TAB, type LogRow } from '../lib/logs';
import { makeRule, type RuleOptions } from '../lib/rulegen';
import { attribute, emptyStats, reduce, type LogRef } from '../lib/stats';
import { LogFeed, MAX_RECENT } from '../lib/logfeed';
import { fromExtensionPage } from '../lib/messages';

const e = (o: Partial<LogEntry> = {}): LogEntry => ({
  seq: 1, time: '2026-01-01T00:00:00.000Z', url: 'https://ads.example/a/b.js?x=1', method: 'GET', type: 'script', third_party: true,
  outcome: 'blocked', rule: '||ads.example^', list_id: 'easylist', list_name: 'EasyList', user_rule: false, source_host: 'www.site.test', ...o,
});

describe('logger filters', () => {
  it('chips are empty = everything; groups OR within, AND across', () => {
    const rows = [e(), e({ seq: 2, outcome: 'allowed', third_party: false, type: 'image' }), e({ seq: 3, outcome: 'redirected', type: 'fetch' }), e({ seq: 4, outcome: 'aborted', user_rule: true, type: 'stylesheet' })];
    expect(applyFilters(rows, noFilters())).toHaveLength(4);
    expect(applyFilters(rows, { ...noFilters(), party: 'first' }).map((r) => r.seq)).toEqual([2]);
    expect(applyFilters(rows, { ...noFilters(), party: 'third' }).map((r) => r.seq)).toEqual([1, 3, 4]);
    expect(applyFilters(rows, { ...noFilters(), status: new Set(['blocked']) }).map((r) => r.seq)).toEqual([1, 4]);
    expect(applyFilters(rows, { ...noFilters(), status: new Set(['modified', 'allowed']) }).map((r) => r.seq)).toEqual([2, 3]);
    expect(applyFilters(rows, { ...noFilters(), status: new Set(['user']) }).map((r) => r.seq)).toEqual([4]);
    expect(applyFilters(rows, { ...noFilters(), types: new Set(['css', 'xhr']) }).map((r) => r.seq)).toEqual([3, 4]);
    expect(applyFilters(rows, { ...noFilters(), party: 'third', types: new Set(['css']) }).map((r) => r.seq)).toEqual([4]);
  });
  it('search matches url, rule, list and type case-insensitively', () => {
    const f = (q: string) => matches(e(), { ...noFilters(), search: q });
    expect(f('B.JS')).toBe(true); expect(f('||ads')).toBe(true); expect(f('easylist')).toBe(true); expect(f('script')).toBe(true); expect(f('nope')).toBe(false);
  });
  it('maps types and statuses', () => {
    expect(['document', 'subdocument', 'stylesheet', 'xmlhttprequest', 'fetch', 'imageset', 'ping', 'websocket', 'x'].map(typeKey))
      .toEqual(['document', 'document', 'css', 'xhr', 'xhr', 'image', 'other', 'websocket', 'other']);
    expect(statusKeys(e({ outcome: 'modified', user_rule: true }))).toEqual(['modified', 'user']);
  });
  it('exports tab separated text', () => {
    expect(exportText([e({ outcome: 'aborted' })])).toBe('2026-01-01T00:00:00.000Z\tblocked\tGET\thttps://ads.example/a/b.js?x=1\tscript\t||ads.example^\tEasyList');
  });
});

describe('rule text', () => {
  const base: RuleOptions = { action: 'block', scope: 'everywhere', match: 'host', thirdParty: false, important: false, site: 'site.test' };
  const url = 'https://ads.example:8443/a/b.js?x=1#f';
  it.each([
    ['host', '||ads.example^'],
    ['path', '||ads.example:8443/a/'],
    ['url', '|https://ads.example:8443/a/b.js?x=1|'],
  ] as const)('match %s', (match, pat) => {
    expect(makeRule(url, { ...base, match })).toBe(pat);
  });
  it('covers every action, scope, party and important combination', () => {
    for (const action of ['block', 'unblock'] as const) for (const scope of ['site', 'everywhere'] as const)
      for (const thirdParty of [false, true]) for (const important of [false, true]) {
        const o = [important && 'important', thirdParty && 'third-party', scope === 'site' && 'domain=site.test'].filter(Boolean).join(',');
        expect(makeRule(url, { ...base, action, scope, thirdParty, important })).toBe(`${action === 'unblock' ? '@@' : ''}||ads.example^${o ? '$' + o : ''}`);
      }
  });
  it('root path prefix and characters a pattern cannot carry', () => {
    expect(makeRule('https://h.test/', { ...base, match: 'path' })).toBe('||h.test/');
    expect(makeRule('https://h.test/a$b|c', { ...base, match: 'url' })).toBe('|https://h.test/a*b*c|');
  });
});

describe('join', () => {
  it('matches by url and time, uses each browser request once, falls back to the page host', () => {
    const reqs = [{ tabId: 1, url: 'https://ads.example/a/b.js?x=1', at: Date.parse('2026-01-01T00:00:00Z') }, { tabId: 2, url: 'https://ads.example/a/b.js?x=1', at: Date.parse('2026-01-01T00:00:01Z') }];
    const rows = joinEntries([e({ seq: 1 }), e({ seq: 2, time: '2026-01-01T00:00:01.100Z' }), e({ seq: 3, url: 'https://z.test/q' }), e({ seq: 4, url: 'https://z.test/r', source_host: 'nobody.test' })], reqs, { 9: 'www.site.test' });
    expect(rows.map((r) => r.tabId)).toEqual([1, 2, 9, -1]);
  });
  it('ignores a request too far away in time', () => {
    const rows = joinEntries([e()], [{ tabId: 1, url: e().url, at: Date.parse('2026-01-01T01:00:00Z') }], {});
    expect(rows[0]!.tabId).toBe(-1);
  });
  it('caps the buffer per tab and skips rows without a tab', () => {
    let b = {};
    const row = (seq: number, tabId: number): LogRow => ({ ...e({ seq }), tabId });
    b = addRows(b, Array.from({ length: MAX_ROWS_PER_TAB + 5 }, (_, i) => row(i, 1)));
    b = addRows(b, [row(999, -1)]);
    expect(Object.keys(b)).toEqual(['1']);
    expect((b as Record<number, LogRow[]>)[1]).toHaveLength(MAX_ROWS_PER_TAB);
    expect((b as Record<number, LogRow[]>)[1]![0]!.seq).toBe(5);
  });
});

describe('exact attribution', () => {
  const pend = (url: string, at: number, page = 'www.site.test') => ({ url, host: new URL(url).hostname, at, page });
  const ref = (seq: number, url: string, at: number, outcome = 'aborted', source = 'www.site.test'): LogRef => ({ key: `s1:${seq}`, seq, url, at, outcome, source });
  it('counts an aborted entry once per error, with the query, and expires the rest', () => {
    const s = { ...emptyStats(), pageHost: 'www.site.test', pending: [pend('https://t.test/p.js?a=1', 1000), pend('https://t.test/p.js?a=1', 1100), pend('https://t.test/p.js?a=2', 1200)] };
    const used = new Set<string>();
    const n = attribute(s, [ref(1, 'https://t.test/p.js?a=1', 1000), ref(2, 'https://t.test/other', 1000)], 2000, used);
    expect(n.blocked).toBe(1);
    expect(n.pending).toHaveLength(2);
    expect([...used]).toEqual(['s1:1']);
    const later = attribute(n, [], 20_000, used);
    expect(later).toMatchObject({ blocked: 1, failed: 2, pending: [] });
  });
  it('does not take a synthetic or another page\'s entry, nor reuse a consumed one', () => {
    const s = { ...emptyStats(), pending: [pend('https://t.test/p.js', 1000)] };
    expect(attribute(s, [ref(1, 'https://t.test/p.js', 1000, 'blocked')], 1500, new Set()).blocked).toBe(0);
    expect(attribute(s, [ref(1, 'https://t.test/p.js', 1000, 'aborted', 'other.test')], 1500, new Set()).blocked).toBe(0);
    expect(attribute(s, [ref(1, 'https://t.test/p.js', 1000)], 1500, new Set(['s1:1'])).blocked).toBe(0);
  });
  it('is reachable through the reducer', () => {
    const m = reduce({ 1: { ...emptyStats(), pending: [pend('https://t.test/p.js', 1000)] } }, { t: 'attribute', tabId: 1, entries: [ref(1, 'https://t.test/p.js', 1000)], used: new Set<string>(), now: 1500 });
    expect(m[1]).toMatchObject({ blocked: 1, pending: [] });
    expect(m[1]!.hosts['t.test']).toEqual({ blocked: 1, allowed: 0 });
  });
});

describe('log feed', () => {
  const entry = (seq: number, o: Partial<LogEntry> = {}) => e({ seq, outcome: 'aborted', ...o });
  const memory = () => {
    const m: Record<string, unknown> = {};
    return { m, area: { get: async (k: string) => (k in m ? { [k]: m[k] } : {}), set: async (o: Record<string, unknown>) => { Object.assign(m, o); } } };
  };
  it('starts over when the session id changes, so a reused seq is not taken for a consumed one', async () => {
    const f = new LogFeed(undefined);
    expect(await f.begin('a')).toBe(0);
    expect(f.accept('a', 2, [entry(1), entry(2)])).toHaveLength(2);
    f.used.add('a:1');
    expect(await f.begin('b')).toBe(0);
    expect(f.recent).toEqual([]);
    expect(f.used.size).toBe(0);
    // The new session numbers from 1 again: all fresh, and key 'b:1' is not 'a:1'.
    expect(f.accept('b', 1, [entry(1)]).map((x) => x.seq)).toEqual([1]);
    expect(f.recent[0]!.key).toBe('b:1');
    // An answer for the old session that arrives late is dropped.
    expect(f.accept('a', 3, [entry(3)])).toEqual([]);
  });
  it('resumes from the stored cursor after a worker restart without repeating entries', async () => {
    const { area } = memory();
    const f1 = new LogFeed(area);
    await f1.begin('s');
    f1.accept('s', 3, [entry(1), entry(2), entry(3)]);
    await Promise.resolve();
    const f2 = new LogFeed(area); // a new worker: empty memory, same storage
    expect(await f2.begin('s')).toBe(3);
    expect(f2.accept('s', 4, [entry(3), entry(4)]).map((x) => x.seq)).toEqual([4]);
    // A different session after the restart still resets.
    const f3 = new LogFeed(area);
    expect(await f3.begin('other')).toBe(0);
  });
  it('prunes consumed marks of entries that left the recent window', async () => {
    const f = new LogFeed(undefined);
    await f.begin('s');
    f.accept('s', 1, [entry(1)]);
    f.used.add('s:1');
    const many = Array.from({ length: MAX_RECENT }, (_, i) => entry(i + 2));
    f.accept('s', MAX_RECENT + 1, many);
    expect(f.recent).toHaveLength(MAX_RECENT);
    expect(f.used.has('s:1')).toBe(false);
  });
});

describe('chart data', () => {
  const pts = [{ ts: 1_700_000_000, requests: 9, blocked: 4, by_category: { ads: 3, trackers: 1 } }, { ts: 1_700_086_400, requests: 9, blocked: 0 }, { ts: 1_700_172_800, requests: 9, blocked: 8, by_category: { ads: 8 } }];
  it('picks the category, scales to the max and labels first, middle, last', () => {
    expect(valueOf(pts[0]!, 'all')).toBe(4); expect(valueOf(pts[0]!, 'trackers')).toBe(1); expect(valueOf(pts[1]!, 'ads')).toBe(0);
    const d = chartData(pts, 'all', 'd7', 100, 50, 0);
    expect(d.values).toEqual([4, 0, 8]); expect(d.max).toBe(8); expect(d.total).toBe(12);
    expect(d.points.map((p) => [p.x, p.y])).toEqual([[0, 25], [50, 50], [100, 0]]);
    expect(d.path).toBe('M0 25 L50 50 L100 0');
    expect(d.labels.map((l) => l.text)).toEqual(['Nov 14', 'Nov 15', 'Nov 16']);
    expect(chartData(pts, 'ads', 'd7').values).toEqual([3, 0, 8]);
    expect(chartData(pts, 'all', 'm12').labels[0]!.text).toBe('Nov');
  });
  it('is flat and finite with no data', () => {
    const d = chartData([], 'all', 'd7');
    expect(d.path).toBe(''); expect(d.max).toBe(1);
    expect(chartData([{ ts: 0, requests: 0, blocked: 0 }], 'all', 'd7').points[0]!.y).toBeGreaterThan(0);
  });
});

describe('sender check', () => {
  it('accepts only our own extension pages', () => {
    const base = 'chrome-extension://abc/';
    expect(fromExtensionPage({ id: 'abc', url: base + 'logger.html#tab=1' }, 'abc', base)).toBe(true);
    expect(fromExtensionPage({ id: 'abc', url: 'https://evil.test/' }, 'abc', base)).toBe(false);
    expect(fromExtensionPage({ id: 'x', url: base }, 'abc', base)).toBe(false);
    expect(fromExtensionPage({ id: 'abc' }, 'abc', base)).toBe(false);
    expect(fromExtensionPage(undefined, 'abc', base)).toBe(false);
  });
});

describe('api errors', () => {
  it('keeps the server message of a 400 and still detects a missing scope', async () => {
    const { postExtRule } = await import('../lib/api');
    const s = { argusUrl: 'https://argus.test', token: 't' };
    const body = (code: string, message: string) => JSON.stringify({ error: { code, message } });
    const json = { 'content-type': 'application/json' };
    vi.stubGlobal('fetch', async () => new Response(body('validation_error', 'The rule must start with ||host'), { status: 400, headers: json }));
    expect(await postExtRule(s, 'add', '*')).toEqual({ ok: false, scope: false, status: 400, message: 'The rule must start with ||host' });
    vi.stubGlobal('fetch', async () => new Response(body('insufficient_scope', 'no'), { status: 403, headers: json }));
    expect(await postExtRule(s, 'add', '*')).toMatchObject({ ok: false, scope: true, status: 403 });
    vi.stubGlobal('fetch', async () => new Response('nope', { status: 400 }));
    expect(await postExtRule(s, 'add', '*')).toEqual({ ok: false, scope: false, status: 400 });
    vi.unstubAllGlobals();
  });
});

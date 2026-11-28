import { afterEach, describe, expect, it, vi } from 'vitest';
import { identityKey, makeCookie } from '../lib/cookiejar/model';
import { activitySource, changeText, changesByRule, ruleUrl, defaultPath, fetchProvenance, joinProvenance, parseRecord, sentVsStored, whenText, type ProvenanceRecord } from '../lib/cookiejar/provenance';
import { fixtureWire, provenanceFetch } from './helpers/cookiefixture';

const NOW = Date.UTC(2026, 10, 28, 12, 0, 0);
let seq = 0;
const rec = (o: Partial<ProvenanceRecord> & { name: string }): ProvenanceRecord => ({ seq: ++seq, at: NOW - 60_000, host: 'a.example', path: '/', pageHost: '', sent: {}, effect: 'set', changes: [], ...o });
const ck = (o: Partial<Parameters<typeof makeCookie>[0]> & { name: string }) => makeCookie({ domain: 'a.example', storeId: '0', ...o });
const S = { argusUrl: 'https://argus.lan', token: 'tok' };

afterEach(() => vi.unstubAllGlobals());

describe('joinProvenance', () => {
  it('matches by name, domain and path; a cookie without a record was not seen in transit', () => {
    const a = ck({ name: 'sid', path: '/' }), b = ck({ name: 'other' }), c = ck({ name: 'sid', path: '/app' });
    const j = joinProvenance([a, b, c], [rec({ name: 'sid', host: 'a.example', path: '/login' })]);
    expect(j.info.get(identityKey(a))).toMatchObject({ seen: true, record: { host: 'a.example', path: '/login' } });
    expect(j.info.get(identityKey(b))).toEqual({ seen: false, diffs: [] });
    expect(j.info.get(identityKey(c))?.seen).toBe(false);
  });

  it('uses the Domain attribute over the request host, and the Path attribute over the default path', () => {
    const c = ck({ name: 't', domain: '.cdn.example', hostOnly: false, path: '/x' });
    const j = joinProvenance([c], [rec({ name: 't', host: 'www.cdn.example', path: '/a/b', sent: { domain: 'cdn.example', path: '/x' } })]);
    expect(j.info.get(identityKey(c))?.seen).toBe(true);
    expect(defaultPath('/a/b')).toBe('/a');
    expect(defaultPath('/a')).toBe('/');
    expect(defaultPath('')).toBe('/');
  });

  it('keeps the latest record and carries the rule effect', () => {
    const c = ck({ name: 'x' });
    const j = joinProvenance([c], [rec({ name: 'x', at: 1000, host: 'old.a.example' }), rec({ name: 'x', at: 5000, effect: 'changed', rule: '||a.example^$cookie=x;maxAge=60', listId: 'l', listName: 'L' })]);
    const i = j.info.get(identityKey(c))!;
    expect(i.record?.at).toBe(5000);
    expect(i.effect).toBe('changed');
    expect(i.record).toMatchObject({ rule: '||a.example^$cookie=x;maxAge=60', listId: 'l' });
  });

  it('returns stripped records that are not in the browser (and not set again later)', () => {
    const live = ck({ name: 'kept' });
    const j = joinProvenance([live], [
      rec({ name: 'gone', at: 1000, effect: 'stripped', rule: '||a.example^$cookie=gone' }),
      rec({ name: 'kept', at: 1000, effect: 'stripped' }),
      rec({ name: 'back', at: 1000, effect: 'stripped' }), rec({ name: 'back', at: 2000 }),
    ]);
    expect(j.stripped.map((s) => s.record.name)).toEqual(['gone']);
    expect(j.stripped[0]).toMatchObject({ domain: 'a.example', path: '/' });
  });

  it('collects what a rule kept out of requests by name and host, apart from the set records', () => {
    const own = ck({ name: 'n', domain: 'a.example' });
    const shared = ck({ name: 'n', domain: '.a.example', hostOnly: false });
    const other = ck({ name: 'n', domain: 'b.example' });
    const j = joinProvenance([own, shared, other], [
      rec({ name: 'n', host: 'a.example', effect: 'blocked_send', rule: '||a.example^$cookie=n' }),
      rec({ name: 'n', host: 'www.a.example', effect: 'blocked_send' }),
    ]);
    // A host-only cookie is sent to its own host only; a domain cookie to subdomains too.
    expect(j.info.get(identityKey(own))?.blocked?.map((b) => b.host)).toEqual(['a.example']);
    expect(j.info.get(identityKey(shared))?.blocked?.map((b) => b.host)).toEqual(['a.example', 'www.a.example']);
    expect(j.info.get(identityKey(other))?.blocked).toBeUndefined();
    // They are not "seen in transit" and never become a stripped row.
    expect(j.info.get(identityKey(own))?.seen).toBe(false);
    expect(j.stripped).toEqual([]);
  });

  it('a nameless request cookie (empty name) is attached to no named cookie', () => {
    const named = ck({ name: 'n', domain: 'a.example' });
    const j = joinProvenance([named], [rec({ name: '', host: 'a.example', effect: 'blocked_send', rule: '||a.example^$cookie' })]);
    expect(j.info.get(identityKey(named))?.blocked).toBeUndefined();
    expect(JSON.stringify([...j.info])).not.toContain('SECRETVALUE');
  });

  it('joins the fixture: changed, stripped and unseen', () => {
    const recs = fixtureWire(NOW).map((w) => parseRecord(w as never)!);
    const ga = ck({ name: '_ga', domain: '.stackoverflow.com', hostOnly: false, session: false, expirationDate: NOW / 1000 - 60 + 7 * 86400 });
    const prefs = ck({ name: 'prefs', domain: 'stackoverflow.com' });
    const j = joinProvenance([ga, prefs], recs);
    expect(j.info.get(identityKey(ga))?.effect).toBe('changed');
    expect(j.info.get(identityKey(ga))?.diffs).toEqual([{ label: 'Lifetime', sent: '1 year', stored: 'capped to 7 days' }]);
    expect(j.info.get(identityKey(prefs))?.seen).toBe(false);
    expect(j.stripped.map((s) => s.record.name).sort()).toEqual(['_gid', '_pxid']);
  });
});

describe('sentVsStored', () => {
  it('lists only what differs: lifetime, SameSite, Secure, HttpOnly', () => {
    const r = rec({ name: 'n', sent: { maxAge: 31536000, sameSite: 'none', secure: true, httpOnly: true } });
    const stored = ck({ name: 'n', session: false, expirationDate: NOW / 1000 - 60 + 3600, sameSite: 'lax', secure: false, httpOnly: false });
    expect(sentVsStored(r, stored)).toEqual([
      { label: 'Lifetime', sent: '1 year', stored: 'capped to 1 hour' },
      { label: 'SameSite', sent: 'None', stored: 'Lax' },
      { label: 'Secure', sent: 'set', stored: 'not set' },
      { label: 'HttpOnly', sent: 'set', stored: 'not set' },
    ]);
    const same = ck({ name: 'n', session: false, expirationDate: NOW / 1000 - 60 + 31536000, sameSite: 'no_restriction', secure: true, httpOnly: true });
    expect(sentVsStored(r, same)).toEqual([]);
  });
});

describe('labels', () => {
  it('names the source of an activity entry', () => {
    const recs = [rec({ name: 'a', at: NOW, host: 'www.a.example', sent: { domain: 'a.example' } })];
    expect(activitySource('set', 'a', 'a.example', NOW + 1000, recs)).toBe('Response from www.a.example');
    expect(activitySource('set', 'a', 'a.example', NOW + 60_000, recs)).toBe('Not seen in transit');
    expect(activitySource('expired', 'a', 'a.example', NOW, recs)).toBe('Browser (expired)');
    expect(activitySource('evicted', 'a', 'a.example', NOW, recs)).toBe('Browser (storage limit)');
    expect(activitySource('removed', 'a', 'a.example', NOW, recs)).toBe('Page, extension or you');
  });
  it('writes a time as Today, Yesterday or a date', () => {
    expect(whenText(NOW, NOW)).toMatch(/^Today \d\d:\d\d:\d\d$/);
    expect(whenText(NOW - 86_400_000, NOW)).toMatch(/^Yesterday /);
    expect(whenText(NOW - 5 * 86_400_000, NOW)).toMatch(/^2026-11-23 \d\d:\d\d:\d\d$/);
  });
});

describe('fetchProvenance', () => {
  it('sends the bridge session and the query, and parses records without values', async () => {
    const calls: { path: string; sid: string | null; search: string }[] = [];
    vi.stubGlobal('fetch', provenanceFetch({ mode: 'on', calls }));
    const r = await fetchProvenance(S, 'sid-9', { since: 5, host: 'example.com' });
    expect(calls).toEqual([{ path: '/api/v1/ext/cookies/provenance', sid: 'sid-9', search: '?since=5&host=example.com' }]);
    expect(r.enabled).toBe(true);
    if (r.enabled) {
      expect(r.records.length).toBe(fixtureWire().length - 5);
      expect(JSON.stringify(r.records)).not.toMatch(/"value"/);
      expect(r.records.find((x) => x.name === '_gid')).toMatchObject({ effect: 'stripped', listId: 'easyprivacy', listName: 'EasyPrivacy' });
      expect(r.nextSince).toBe(fixtureWire().length);
    }
  });
  it('polls by sequence: only records after nextSince come back, none twice', async () => {
    vi.stubGlobal('fetch', provenanceFetch({ mode: 'on' }));
    const first = await fetchProvenance(S, 's');
    if (!first.enabled) throw new Error('off');
    const again = await fetchProvenance(S, 's', { since: first.nextSince });
    expect(again).toEqual({ enabled: true, records: [], nextSince: first.nextSince });
    const mid = await fetchProvenance(S, 's', { since: 8 });
    if (mid.enabled) expect(mid.records.map((r) => r.seq)).toEqual([9, 10, 11]);
  });
  it('follows the server pages until it says nothing more follows', async () => {
    const urls: string[] = [];
    const page = (since: number) => ({ enabled: true, records: fixtureWire().filter((r) => (r['seq'] as number) > since).slice(0, 4), next_since: Math.min(since + 4, 11), more: since + 4 < 11 });
    vi.stubGlobal('fetch', (url: string) => { urls.push(url); const since = Number(new URL(url).searchParams.get('since')); return Promise.resolve(new Response(JSON.stringify(page(since)), { headers: { 'content-type': 'application/json' } })); });
    const r = await fetchProvenance(S, 's');
    expect(urls.map((u) => new URL(u).searchParams.get('since'))).toEqual(['0', '4', '8']);
    expect(r.enabled && r.records.map((x) => x.seq)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    expect(r.enabled && r.nextSince).toBe(11);
  });
  it('answers { enabled: false } when the server says disabled, when the route does not exist, and without a session', async () => {
    vi.stubGlobal('fetch', provenanceFetch({ mode: 'off' }));
    expect(await fetchProvenance(S, 's')).toEqual({ enabled: false, reason: 'disabled' });
    vi.stubGlobal('fetch', provenanceFetch({ mode: '404' }));
    expect(await fetchProvenance(S, 's')).toEqual({ enabled: false, reason: 'disabled' });
    expect(await fetchProvenance(S, '')).toEqual({ enabled: false, reason: 'no-session' });
  });
  it('reports an unreachable server, a refused scope and an unrecognised answer as unavailable or scope', async () => {
    vi.stubGlobal('fetch', () => Promise.reject(new Error('down')));
    expect(await fetchProvenance(S, 's')).toEqual({ enabled: false, reason: 'unavailable' });
    const body = (status: number, b: unknown) => () => Promise.resolve(new Response(JSON.stringify(b), { status, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', body(403, { error: { code: 'insufficient_scope' } }));
    expect(await fetchProvenance(S, 's')).toEqual({ enabled: false, reason: 'scope' });
    vi.stubGlobal('fetch', body(403, { error: { code: 'ext_session_required' } }));
    expect(await fetchProvenance(S, 's')).toEqual({ enabled: false, reason: 'unavailable' });
    vi.stubGlobal('fetch', body(200, 'disabled'));
    expect(await fetchProvenance(S, 's')).toEqual({ enabled: false, reason: 'unavailable' });
    vi.stubGlobal('fetch', body(200, { records: [] }));
    expect(await fetchProvenance(S, 's')).toEqual({ enabled: false, reason: 'unavailable' });
  });
});

describe('parseRecord', () => {
  const wire = () => fixtureWire(NOW).find((w) => w['name'] === '_ga')! as never;
  it('reads the server shape: attributes, rule changes and the list', () => {
    expect(parseRecord(wire())).toEqual({
      seq: 3, at: NOW - 40 * 60_000, name: '_ga', host: 'stackoverflow.com', path: '/', pageHost: 'www.stackoverflow.com',
      sent: { domain: 'stackoverflow.com', maxAge: 31536000 }, effect: 'changed',
      changes: [{ attr: 'max_age', from: '31536000', to: '604800', by: { rule: '||stackoverflow.com^$cookie=_ga;maxAge=604800', listId: 'argus-base', listName: 'Argus Base' } }],
      rule: '||stackoverflow.com^$cookie=_ga;maxAge=604800', listId: 'argus-base', listName: 'Argus Base',
    });
    const p = parseRecord(fixtureWire(NOW).find((w) => w['name'] === '__Secure-tp-embed')! as never)!;
    expect(p).toMatchObject({ thirdParty: true, prefix: '__Secure-', prefixValid: true, sent: { partitioned: true, sameSite: 'none', secure: true } });
  });
  it('keeps an empty name and drops what is malformed', () => {
    const w = wire() as Record<string, unknown>;
    expect(parseRecord({ ...w, name: '' } as never)?.name).toBe('');
    for (const bad of [{ seq: undefined }, { time: 'x' }, { host: '' }, { effect: 'weird' }, { name: undefined }]) expect(parseRecord({ ...w, ...bad } as never)).toBeUndefined();
    // unknown attribute names in a change are ignored
    expect(parseRecord({ ...w, changes: [{ attr: 'domain', from: 'a', to: 'b' }] } as never)?.changes).toEqual([]);
  });
  it('keeps the rule behind each changed attribute and groups changes by rule', () => {
    const p = parseRecord(fixtureWire(NOW).find((w) => w['name'] === '_ga_9XK2LP')! as never)!;
    expect(p.changes.map((c) => [c.attr, c.by?.rule, c.by?.listId, c.by?.userRule])).toEqual([
      ['max_age', '||stackoverflow.com^$cookie=/^_ga_/;maxAge=604800', 'argus-base', undefined],
      ['same_site', '||stackoverflow.com^$cookie=/^_ga_/;sameSite=lax', 'custom', true],
    ]);
    const g = changesByRule(p.changes);
    expect(g.map((x) => [x.by?.rule, x.changes.map((c) => c.attr)])).toEqual([
      ['||stackoverflow.com^$cookie=/^_ga_/;maxAge=604800', ['max_age']],
      ['||stackoverflow.com^$cookie=/^_ga_/;sameSite=lax', ['same_site']],
    ]);
    // A change without its own rule falls back to the record's.
    const fb = { rule: 'r', listId: 'l' };
    expect(changesByRule([{ attr: 'max_age' }, { attr: 'same_site', by: fb }], fb)).toHaveLength(1);
  });
  it('links a rule to its list page with the rule text as the search', () => {
    expect(ruleUrl('http://argus:8080', 'argus-base', '||a.test^$cookie=x;maxAge=60')).toBe('http://argus:8080/filters/argus-base?q=%7C%7Ca.test%5E%24cookie%3Dx%3BmaxAge%3D60');
  });
  it('writes a rule change as a line', () => {
    expect(changeText({ attr: 'max_age', from: '31536000', to: '3600' })).toBe('Max-Age: 1 year → 1 hour');
    expect(changeText({ attr: 'max_age', to: '60' })).toBe('Max-Age: none → 1 minute');
    expect(changeText({ attr: 'same_site', from: 'none', to: 'lax' })).toBe('SameSite: None → Lax');
    expect(changeText({ attr: 'expires', from: '4096250880' })).toBe('Expires: 2099-10-21 → removed');
  });
});

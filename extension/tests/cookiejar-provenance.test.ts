import { afterEach, describe, expect, it, vi } from 'vitest';
import { identityKey, makeCookie } from '../lib/cookiejar/model';
import { activitySource, defaultPath, fetchProvenance, joinProvenance, parseRecord, sentVsStored, whenText, type ProvenanceRecord } from '../lib/cookiejar/provenance';
import { fixtureWire, provenanceFetch } from './helpers/cookiefixture';

const NOW = Date.UTC(2026, 10, 28, 12, 0, 0);
const rec = (o: Partial<ProvenanceRecord> & { name: string }): ProvenanceRecord => ({ at: NOW - 60_000, host: 'a.example', path: '/', sent: {}, ...o });
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
    const j = joinProvenance([c], [rec({ name: 'x', at: 1000, host: 'old.a.example' }), rec({ name: 'x', at: 5000, effect: 'changed', rule: '||a.example^$cookie=x;maxAge=60', listId: 'l', listName: 'L', line: 3 })]);
    const i = j.info.get(identityKey(c))!;
    expect(i.record?.at).toBe(5000);
    expect(i.effect).toBe('changed');
    expect(i.record).toMatchObject({ rule: '||a.example^$cookie=x;maxAge=60', listId: 'l', line: 3 });
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
      expect(r.records.length).toBe(fixtureWire().length);
      expect(JSON.stringify(r.records)).not.toMatch(/"value"/);
      expect(r.records.find((x) => x.name === '_gid')).toMatchObject({ effect: 'stripped', listId: 'easyprivacy', line: 1204 });
    }
  });
  it('answers { enabled: false } when the server says disabled, when the route does not exist, and without a session', async () => {
    vi.stubGlobal('fetch', provenanceFetch({ mode: 'off' }));
    expect(await fetchProvenance(S, 's')).toEqual({ enabled: false, reason: 'disabled' });
    vi.stubGlobal('fetch', provenanceFetch({ mode: '404' }));
    expect(await fetchProvenance(S, 's')).toEqual({ enabled: false, reason: 'disabled' });
    expect(await fetchProvenance(S, '')).toEqual({ enabled: false, reason: 'no-session' });
  });
  it('accepts a bare "disabled" string and reports an unreachable server as unavailable', async () => {
    vi.stubGlobal('fetch', () => Promise.resolve(new Response('"disabled"', { status: 200, headers: { 'content-type': 'application/json' } })));
    expect(await fetchProvenance(S, 's')).toEqual({ enabled: false, reason: 'disabled' });
    vi.stubGlobal('fetch', () => Promise.reject(new Error('down')));
    expect(await fetchProvenance(S, 's')).toEqual({ enabled: false, reason: 'unavailable' });
  });
});

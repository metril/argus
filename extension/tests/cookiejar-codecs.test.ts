import { describe, expect, it } from 'vitest';
import { CODECS, FORMAT_IDS, shq, snippet, type FormatId } from '../lib/cookiejar/codecs';
import { parseCsv } from '../lib/cookiejar/codecs/csv';
import { makeCookie, type Cookie } from '../lib/cookiejar/model';

const mk = (p: Record<string, unknown>) => makeCookie({ storeId: '0', ...p } as never);
const sample: Cookie[] = [
  mk({ name: 'sid', value: 'abc123', domain: '.example.com', hostOnly: false, path: '/', secure: true, httpOnly: true, sameSite: 'lax', session: false, expirationDate: 1893456000 }),
  mk({ name: 'pref', value: 'dark mode, "yes"', domain: 'www.example.com', path: '/app', sameSite: 'strict' }),
  mk({ name: 'cmp', value: 'x=y=z', domain: '.tracker.net', hostOnly: false, secure: true, sameSite: 'no_restriction', session: false, expirationDate: 1893456123.5, partitionKey: { topLevelSite: 'https://example.com', hasCrossSiteAncestor: true } }),
];

/** What a format keeps; the rest is lost by design. */
const lossy: Record<FormatId, (c: Cookie) => unknown> = {
  json: (c) => ({ ...c, size: undefined }),
  netscape: (c) => [c.domain, c.hostOnly, c.path, c.secure, c.httpOnly, c.name, c.value, c.session, c.session ? 0 : Math.floor(c.expirationDate!)],
  csv: (c) => ({ ...c, size: undefined }),
  playwright: (c) => [c.domain, c.hostOnly, c.path, c.secure, c.httpOnly, c.name, c.value, c.sameSite === 'unspecified' ? 'lax' : c.sameSite, c.session, c.expirationDate, c.partitionKey?.topLevelSite],
  puppeteer: (c) => [c.domain, c.hostOnly, c.path, c.secure, c.httpOnly, c.name, c.value, c.sameSite, c.session, c.expirationDate, c.partitionKey],
  header: (c) => [c.name, c.value],
};

describe('round trips', () => {
  for (const id of FORMAT_IDS) {
    it(`${id}: export then import keeps what the format carries`, () => {
      const text = CODECS[id].export(sample);
      const back = CODECS[id].parse(text, { host: 'example.com' });
      expect(back.every((r) => r.cookie)).toBe(true);
      expect(back.map((r) => lossy[id](r.cookie!))).toEqual(sample.map(lossy[id]));
    });
  }
  it('json keeps the store, partition key and first-party domain', () => {
    const c = mk({ name: 'a', domain: 'example.com', storeId: 'firefox-container-3', firstPartyDomain: 'example.com', secure: true, partitionKey: { topLevelSite: 'https://t.test' } });
    expect(CODECS.json.parse(CODECS.json.export([c]))[0]!.cookie).toMatchObject({ storeId: 'firefox-container-3', firstPartyDomain: 'example.com', partitionKey: { topLevelSite: 'https://t.test' } });
  });
  it('empty exports parse to nothing', () => {
    for (const id of ['netscape', 'json', 'csv', 'playwright', 'puppeteer'] as const) expect(CODECS[id].parse(CODECS[id].export([]))).toEqual([]);
  });
});

describe('netscape', () => {
  it('writes #HttpOnly_ lines, tab separated, session = 0', () => {
    const t = CODECS.netscape.export(sample);
    expect(t.split('\n')[0]).toBe('# Netscape HTTP Cookie File');
    expect(t).toContain('#HttpOnly_.example.com\tTRUE\t/\tTRUE\t1893456000\tsid\tabc123');
    expect(t).toContain('www.example.com\tFALSE\t/app\tFALSE\t0\tpref\t');
  });
  it('reads curl/Firefox/Chrome-extension variations', () => {
    const text = '﻿# Netscape HTTP Cookie File\r\n# comment\r\n\r\n#HttpOnly_.a.com\tTRUE\t/\tTRUE\t1893456000\tsid\tv1\r\n'
      + 'a.com\tFALSE\t/x\tFALSE\t0\tempty\r\n'                      // six fields: empty value
      + '.b.com\tTRUE\t/\tFALSE\t1893456000123\tms\tv=2 x\r\n'       // milliseconds, value with = and space
      + 'c.com   FALSE   /   TRUE   0   spaces   still works\n';       // tabs turned into spaces
    const rows = CODECS.netscape.parse(text);
    expect(rows).toHaveLength(4);
    expect(rows[0]!.cookie).toMatchObject({ domain: '.a.com', hostOnly: false, httpOnly: true, secure: true, name: 'sid', value: 'v1', expirationDate: 1893456000 });
    expect(rows[1]!.cookie).toMatchObject({ domain: 'a.com', hostOnly: true, httpOnly: false, session: true, value: '' });
    expect(rows[2]!.cookie).toMatchObject({ expirationDate: 1893456000.123, value: 'v=2 x' });
    expect(rows[3]!.cookie).toMatchObject({ domain: 'c.com', secure: true, value: 'still works' });
  });
  it('gives a reason per bad line and keeps the good ones', () => {
    const rows = CODECS.netscape.parse('a.com\tMAYBE\t/\tFALSE\t0\tn\tv\njunk\na.com\tFALSE\t/\tFALSE\tsoon\tn\tv\na.com\tFALSE\t/\tFALSE\t0\tok\tv\n');
    expect(rows.map((r) => r.error ?? 'ok')).toEqual(['The subdomain and secure fields must be TRUE or FALSE.', 'A cookies.txt line needs seven tab-separated fields.', 'The expiry field must be a number of seconds.', 'ok']);
    expect(rows.map((r) => r.row)).toEqual([1, 2, 3, 4]);
  });
});

describe('json', () => {
  it('reads EditThisCookie and Cookie-Editor exports', () => {
    const etc = JSON.stringify([{ domain: '.example.com', expirationDate: 1893456000.5, hostOnly: false, httpOnly: true, name: 'sid', path: '/', sameSite: 'no_restriction', secure: true, session: false, storeId: '0', value: 'v', id: 1 }]);
    expect(CODECS.json.parse(etc)[0]!.cookie).toMatchObject({ domain: '.example.com', sameSite: 'no_restriction', expirationDate: 1893456000.5, httpOnly: true, storeId: '0' });
    const ce = JSON.stringify([{ name: 'a', value: '1', domain: 'example.com', path: '/', secure: false, httpOnly: false, sameSite: 'Lax', expires: '2030-01-01T00:00:00Z' }]);
    expect(CODECS.json.parse(ce)[0]!.cookie).toMatchObject({ hostOnly: true, sameSite: 'lax', expirationDate: 1893456000, session: false });
  });
  it('tolerates a wrapped list, snake_case, numeric strings and missing fields', () => {
    const t = JSON.stringify({ cookies: [{ name: 'a', domain: 'example.com', http_only: 'true', host_only: false, secure: 1, expires: '1893456000', session: false }, { name: 'b', domain: 'x.com', session: true, expirationDate: 5 }] });
    const [a, b] = CODECS.json.parse(t);
    expect(a!.cookie).toMatchObject({ httpOnly: true, hostOnly: false, domain: '.example.com', secure: true, value: '', path: '/', expirationDate: 1893456000 });
    expect(b!.cookie).toMatchObject({ session: true });
    expect('expirationDate' in b!.cookie!).toBe(false);
  });
  it('explains what is wrong', () => {
    expect(CODECS.json.parse('{nope')[0]!.error).toMatch(/not valid JSON/);
    expect(CODECS.json.parse('{"a":1}')[0]!.error).toBe('This JSON has no list of cookies.');
    const rows = CODECS.json.parse('[1, {"value":"x"}, {"name":"n"}, {"name":"ok","domain":"a.com"}]');
    expect(rows.map((r) => r.error ?? 'ok')).toEqual(['This entry is not a cookie object.', 'This cookie has no name.', 'This cookie has no domain.', 'ok']);
  });
});

describe('header', () => {
  it('reads a Cookie header for a given site', () => {
    const rows = CODECS.header.parse('Cookie: a=1; b=two=2;  c=; junk', { host: 'www.example.com' });
    expect(rows.map((r) => r.cookie?.name ?? r.error)).toEqual(['a', 'b', 'c', '"junk" is not name=value.']);
    expect(rows[1]!.cookie).toMatchObject({ value: 'two=2', domain: 'www.example.com', hostOnly: true, session: true });
    expect(rows[2]!.cookie!.value).toBe('');
  });
  it('needs a site because the header carries no domain', () => {
    expect(CODECS.header.parse('a=1', {})[0]!.error).toMatch(/choose the site/);
  });
  it('reads Set-Cookie lines with their attributes', () => {
    const rows = CODECS.header.parse('Set-Cookie: sid=1; Domain=.example.com; Path=/a; Secure; HttpOnly; SameSite=None; Partitioned; Max-Age=60\nset-cookie: e=2; Expires=Wed, 01 Jan 2031 00:00:00 GMT', { host: 'www.example.com', now: 1_000_000 });
    expect(rows[0]!.cookie).toMatchObject({ domain: '.example.com', hostOnly: false, path: '/a', secure: true, httpOnly: true, sameSite: 'no_restriction', expirationDate: 1060, partitionKey: { topLevelSite: 'https://www.example.com' } });
    expect(rows[1]!.cookie).toMatchObject({ domain: 'www.example.com', expirationDate: 1924992000 });
  });
  it('treats a bare attribute line as Set-Cookie', () => {
    expect(CODECS.header.parse('sid=1; Path=/; Secure', { host: 'a.com' })[0]!.cookie).toMatchObject({ secure: true, name: 'sid' });
  });
});

describe('csv', () => {
  it('quotes commas, quotes and newlines and reads them back', () => {
    const c = mk({ name: 'n', value: 'a,b\n"c"', domain: 'example.com' });
    const text = CODECS.csv.export([c]);
    expect(text.split('\r\n')[0]).toBe('name,value,domain,hostOnly,path,secure,httpOnly,sameSite,session,expirationDate,storeId,partitionKey,hasCrossSiteAncestor,firstPartyDomain');
    expect(CODECS.csv.parse(text)[0]!.cookie!.value).toBe('a,b\n"c"');
  });
  it('parses RFC 4180 corner cases', () => {
    expect(parseCsv('a,b\r\n"x,""y""",\n\n"multi\nline",z')).toEqual([['a', 'b'], ['x,"y"', ''], ['multi\nline', 'z']]);
  });
  it('is tolerant about header names and booleans', () => {
    const rows = CODECS.csv.parse('Host,Name,Value,HTTP_Only,Is_Secure,Expires,Path\nexample.com,a,1,TRUE,yes,1893456000,/x\n');
    expect(rows[0]!.cookie).toMatchObject({ domain: 'example.com', httpOnly: true, secure: true, expirationDate: 1893456000, path: '/x' });
  });
  it('rejects a file without name and domain columns', () => {
    expect(CODECS.csv.parse('foo,bar\n1,2')[0]!.error).toMatch(/name the columns/);
  });
});

describe('playwright and puppeteer', () => {
  it('playwright: storage state with origins, -1 for session, Lax for unspecified', () => {
    const out = JSON.parse(CODECS.playwright.export([mk({ name: 'a', domain: 'example.com' }), sample[2]!]));
    expect(out.origins).toEqual([]);
    expect(out.cookies[0]).toMatchObject({ expires: -1, sameSite: 'Lax', domain: 'example.com' });
    expect(out.cookies[1]).toMatchObject({ sameSite: 'None', domain: '.tracker.net', partitionKey: 'https://example.com' });
  });
  it('playwright: reads a real storage state (partition key as string or object)', () => {
    const t = JSON.stringify({ cookies: [{ name: 'a', value: '1', domain: '.example.com', path: '/', expires: -1, httpOnly: false, secure: true, sameSite: 'None', partitionKey: 'https://top.test' }], origins: [{ origin: 'https://x', localStorage: [] }] });
    expect(CODECS.playwright.parse(t)[0]!.cookie).toMatchObject({ session: true, hostOnly: false, partitionKey: { topLevelSite: 'https://top.test' } });
  });
  it('puppeteer: sourceOrigin partition keys and size, sameSite omitted when unspecified', () => {
    const out = JSON.parse(CODECS.puppeteer.export([mk({ name: 'a', value: 'x', domain: 'example.com' }), sample[2]!]));
    expect('sameSite' in out[0]).toBe(false);
    expect(out[0]).toMatchObject({ size: 2, session: true, expires: -1 });
    expect(out[1].partitionKey).toEqual({ sourceOrigin: 'https://example.com', hasCrossSiteAncestor: true });
    expect(CODECS.puppeteer.parse(JSON.stringify(out))[1]!.cookie!.partitionKey).toEqual({ topLevelSite: 'https://example.com', hasCrossSiteAncestor: true });
  });
});

describe('command snippets', () => {
  const cs = [mk({ name: 'a', value: '1', domain: 'example.com', path: '/' }), mk({ name: 'b', value: "it's", domain: '.example.com', hostOnly: false, secure: true }), mk({ name: 'other', value: '9', domain: 'other.com' }), mk({ name: 'deep', value: 'd', domain: 'example.com', path: '/deep' })];
  it('curl, wget and yt-dlp send only what the URL would receive, shell-quoted', () => {
    const url = 'https://example.com/page';
    expect(snippet('curl', cs, { url })).toBe(`curl -b 'a=1; b=it'\\''s' 'https://example.com/page'`);
    expect(snippet('wget', cs, { url })).toBe(`wget --header 'Cookie: a=1; b=it'\\''s' 'https://example.com/page'`);
    expect(snippet('ytdlp', cs, { url: 'https://example.com/deep/x' })).toBe(`yt-dlp --add-headers 'Cookie: a=1; b=it'\\''s; deep=d' 'https://example.com/deep/x'`);
  });
  it('drops secure cookies for http URLs, and header-injecting values; empty when nothing is sent', () => {
    expect(snippet('curl', cs, { url: 'http://example.com/' })).toBe(`curl -b 'a=1' 'http://example.com/'`);
    expect(snippet('curl', [mk({ name: 'x', value: 'a\r\nHost: evil', domain: 'example.com' })], { url: 'https://example.com/' })).toBe('');
    expect(snippet('curl', [], {})).toBe('');
  });
  it('defaults the URL to the first cookie host', () => {
    expect(snippet('curl', [cs[0]!])).toContain("'https://example.com/'");
    expect(shq("a'b")).toBe(`'a'\\''b'`);
  });
});

describe('csv formula guard', () => {
  const nasty = ['=1+1', '+SUM(A1)', '-2', '@cmd', '\tx', "'=already", "''@x", "'plain", 'ok'];
  it('prefixes a quote to cells a spreadsheet would run, and round-trips exactly', () => {
    const cs = nasty.map((v, i) => mk({ name: `n${i}`, value: v, domain: 'example.com' }));
    const text = CODECS.csv.export(cs);
    expect(text).toContain(",'=1+1,");
    expect(text).toContain(",'+SUM(A1),");
    expect(text).toContain(",'@cmd,");
    expect(text).toContain(",''=already,");
    expect(text).toContain(",'plain,");
    expect(text).not.toMatch(/,=1\+1/);
    expect(CODECS.csv.parse(text).map((r) => r.cookie!.value)).toEqual(nasty);
  });
  it('guards names and domains too', () => {
    const text = CODECS.csv.export([mk({ name: '=evil', value: 'v', domain: 'example.com' })]);
    expect(text).toContain("'=evil");
    expect(CODECS.csv.parse(text)[0]!.cookie!.name).toBe('=evil');
  });
});

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Bridge } from '../lib/bridge';
import { decodeFrame, encodeFrame, payloadJson } from '../lib/frames';

class FakeWS {
  static last: FakeWS;
  sent: (string | ArrayBuffer)[] = [];
  binaryType = '';
  onopen: any; onmessage: any; onclose: any; onerror: any;
  closed = false;
  constructor(public url: string) { FakeWS.last = this; }
  send(d: string | ArrayBuffer) { this.sent.push(d); }
  close() { this.closed = true; }
  open() { this.onopen?.(); }
  recv(data: string | ArrayBuffer) { this.onmessage?.({ data }); }
  drop() { this.onclose?.({ code: 1006 }); }
  frames() { return this.sent.filter((s) => typeof s !== 'string').map((s) => decodeFrame(s as ArrayBuffer)!); }
  texts() { return this.sent.filter((s) => typeof s === 'string').map((s) => JSON.parse(s as string)); }
}

const tick = () => new Promise((r) => setTimeout(r, 5));
const SID = 'a'.repeat(32);

function setup(opts: { perm?: boolean; fetch?: any } = {}) {
  const br = {
    declarativeNetRequest: { updateSessionRules: vi.fn(async () => {}) },
    permissions: {
      contains: vi.fn(async () => opts.perm ?? true),
      getAll: vi.fn(async () => ({ origins: ['https://a.com/*', 'chrome://x/*', '<all_urls>'] })),
    },
    cookies: { getAll: vi.fn(async () => []), set: vi.fn(), remove: vi.fn() },
  };
  const b = new Bridge({
    WebSocketCtor: FakeWS as any, browser: br, fetch: opts.fetch,
    getSettings: async () => ({ argusUrl: 'https://argus.local:8443', token: 'tok' }),
  });
  return { br, b };
}

async function welcome(b: Bridge) {
  await b.connect();
  const ws = FakeWS.last;
  ws.open();
  ws.recv(JSON.stringify({ t: 'welcome', sid: SID, v: 1 }));
  await tick();
  return ws;
}

const meta = (o: object) => ({
  op: 'xhr', script: 's', relay: 'abcd', connect: { page: 'p.com', list: ['a.com'], all: false },
  method: 'GET', url: 'https://a.com/x', headers: [['Accept', 'x'], ['Cookie', 'no']], redirect: 'follow', timeout: 5000, hasBody: false, ...o,
});

describe('Bridge', () => {
  beforeEach(() => { FakeWS.last = undefined as any; });

  it('sends hello first, then perms after welcome; token not in URL', async () => {
    const { b } = setup();
    await b.connect();
    const ws = FakeWS.last;
    expect(ws.url).toBe('wss://argus.local:8443/api/v1/ext/channel');
    expect(ws.url).not.toContain('tok');
    ws.open();
    expect(ws.sent[0]).toBe(JSON.stringify({ t: 'hello', token: 'tok', v: 1 }));
    ws.recv(JSON.stringify({ t: 'welcome', sid: SID, v: 1 }));
    await tick();
    expect(b.status()).toEqual({ connected: true, sid: SID });
    expect(ws.texts()[1]).toEqual({ t: 'perms', origins: ['https://a.com/*', '<all_urls>'] });
    await b.stop();
  });

  it('hosts installs the rule; disconnect removes it', async () => {
    const { b, br } = setup();
    const ws = await welcome(b);
    ws.recv(JSON.stringify({ t: 'hosts', wildcard: false, hosts: ['a.com'], exclude: [] }));
    await tick();
    const call = (br.declarativeNetRequest.updateSessionRules.mock.calls as any[]).at(-1)![0];
    expect(call.removeRuleIds).toEqual([1]);
    expect(call.addRules[0].condition.requestDomains).toEqual(['a.com']);
    expect(call.addRules[0].action.requestHeaders[0].value).toBe(SID);
    ws.recv(JSON.stringify({ t: 'hosts', wildcard: false, hosts: [] }));
    await tick();
    expect((br.declarativeNetRequest.updateSessionRules.mock.calls as any[]).at(-1)![0].addRules).toEqual([]);
    ws.drop();
    await tick();
    expect((br.declarativeNetRequest.updateSessionRules.mock.calls as any[]).at(-1)![0]).toEqual({ removeRuleIds: [1] });
    expect(b.status().connected).toBe(false);
    await b.stop();
  });

  it('job without host permission yields error frame', async () => {
    const { b } = setup({ perm: false });
    const ws = await welcome(b);
    ws.recv(encodeFrame(0, 9, meta({})));
    await tick();
    const f = ws.frames().at(-1)!;
    expect(f.type).toBe(4);
    expect(f.job).toBe(9);
    expect(payloadJson<any>(f.payload).code).toBe('permission');
    await b.stop();
  });

  it('job outside @connect yields connect_denied', async () => {
    const { b } = setup();
    const ws = await welcome(b);
    ws.recv(encodeFrame(0, 3, meta({ url: 'https://evil.com/' })));
    await tick();
    expect(payloadJson<any>(ws.frames().at(-1)!.payload).code).toBe('connect_denied');
    await b.stop();
  });

  it('xhr happy path streams head/data/end with relay header', async () => {
    const f = vi.fn(async (_u: string, init: any) => {
      expect(init.headers.get('X-Argus-Relay')).toBe('abcd');
      expect(init.headers.get('Cookie')).toBeNull();
      expect(init.headers.get('Accept')).toBe('x');
      expect(init.credentials).toBe('include');
      const res = new Response(new Uint8Array(70_000), { status: 200, headers: { 'x-a': 'b', 'set-cookie': 'z=1' } });
      return res;
    });
    const { b } = setup({ fetch: f });
    const ws = await welcome(b);
    ws.recv(encodeFrame(0, 5, meta({})));
    await tick(); await tick();
    const fr = ws.frames();
    expect(fr[0]!.type).toBe(1);
    const head = payloadJson<any>(fr[0]!.payload);
    expect(head.status).toBe(200);
    expect(head.headers.map((h: string[]) => h[0])).not.toContain('set-cookie');
    expect(head.headers).toContainEqual(['x-a', 'b']);
    const data = fr.filter((x) => x.type === 2);
    expect(data.reduce((n, x) => n + x.payload.length, 0)).toBe(70_000);
    expect(data.every((x) => x.payload.length <= 65536)).toBe(true);
    expect(fr.at(-1)!.type).toBe(3);
    await b.stop();
  });

  it('request body is collected before fetch; cancel aborts silently', async () => {
    let got: any;
    const f = vi.fn(async (_u: string, init: any) => { got = init; return new Response('ok'); });
    const { b } = setup({ fetch: f });
    const ws = await welcome(b);
    ws.recv(encodeFrame(0, 1, meta({ method: 'POST', hasBody: true })));
    ws.recv(encodeFrame(2, 1, new Uint8Array([1, 2])));
    ws.recv(encodeFrame(2, 1, new Uint8Array([3])));
    await tick();
    expect(f).not.toHaveBeenCalled();
    ws.recv(encodeFrame(3, 1));
    await tick(); await tick();
    expect(Array.from(got.body)).toEqual([1, 2, 3]);

    const before = ws.sent.length;
    ws.recv(encodeFrame(0, 2, meta({ hasBody: true })));
    ws.recv(encodeFrame(5, 2));
    await tick();
    expect(ws.sent.length).toBe(before);
    await b.stop();
  });

  it('cookie job lists without httpOnly', async () => {
    const { b, br } = setup();
    br.cookies.getAll.mockResolvedValue([
      { name: 'a', value: '1', domain: 'a.com', path: '/', secure: false, httpOnly: false },
      { name: 'h', value: 'S', domain: 'a.com', path: '/', secure: false, httpOnly: true },
    ] as any);
    const ws = await welcome(b);
    ws.recv(encodeFrame(0, 4, { op: 'cookie', script: 's', relay: 'r', connect: { page: 'a.com', list: [], all: false }, cookie: { op: 'list', url: 'https://a.com/' } }));
    await tick();
    const fr = ws.frames();
    const res = payloadJson<any>(fr[0]!.payload).result;
    expect(res).toHaveLength(1);
    expect(JSON.stringify(res)).not.toContain('"S"');
    expect(fr[1]!.type).toBe(3);
    await b.stop();
  });
});

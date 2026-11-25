import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Bridge } from '../lib/bridge';
import { StoreRelay } from '../lib/storerelay';
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

function setup(opts: { perm?: boolean; grants?: string[]; fetch?: any; proxy?: any; storeRelay?: any } = {}) {
  const br = {
    permissions: {
      contains: vi.fn(async () => opts.perm ?? true),
      getAll: vi.fn(async () => ({ origins: ['https://a.com/*', 'chrome://x/*', '<all_urls>'] })),
    },
    cookies: { getAll: vi.fn(async () => []), set: vi.fn(), remove: vi.fn() },
    storage: { local: { get: vi.fn(async () => ({ granted: opts.perm === false ? [] : (opts.grants ?? ['https://a.com/*']) })), set: vi.fn(async () => {}) } },
  };
  const b = new Bridge({
    WebSocketCtor: FakeWS as any, browser: br, fetch: opts.fetch, proxy: opts.proxy, storeRelay: opts.storeRelay,
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
    expect(ws.texts()[1]).toEqual({ t: 'perms', origins: ['https://a.com/*'] });
    await b.stop();
  });

  it('the proxy message configures the browser proxy; disconnect clears it', async () => {
    const proxy = { setSid: vi.fn(async () => {}), setServer: vi.fn(async () => {}) };
    const { b } = setup({ proxy });
    const ws = await welcome(b);
    expect(proxy.setSid).toHaveBeenLastCalledWith(SID);
    ws.recv(JSON.stringify({ t: 'proxy', host: null, port: 3130 }));
    await tick();
    expect(proxy.setServer).toHaveBeenLastCalledWith(null, 3130);
    ws.drop();
    await tick();
    expect(proxy.setSid).toHaveBeenLastCalledWith(null);
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

  it('refuses loopback and private targets even when @connect allows them', async () => {
    const { b } = setup();
    const ws = await welcome(b);
    for (const [i, host] of ['127.0.0.1', '10.0.0.5', '192.168.1.1', '169.254.169.254', '[::1]', 'localhost'].entries()) {
      ws.recv(encodeFrame(0, 20 + i, meta({ url: `https://${host}/`, connect: { page: 'p.com', list: [host.replace(/[\[\]]/g, '')], all: true } })));
    }
    await tick();
    const errs = ws.frames().filter((f) => f.type === 4);
    expect(errs).toHaveLength(6);
    expect(errs.every((f) => payloadJson<any>(f.payload).code === 'connect_denied')).toBe(true);
    await b.stop();
  });

  it('a redirect that ends outside @connect is an error, not a response', async () => {
    const f = vi.fn(async () => {
      const r = new Response('secret');
      Object.defineProperty(r, 'url', { value: 'https://evil.com/x' });
      return r;
    });
    const { b } = setup({ fetch: f });
    const ws = await welcome(b);
    ws.recv(encodeFrame(0, 5, meta({})));
    await tick(); await tick();
    const fr = ws.frames();
    expect(fr.some((x) => x.type === 1 || x.type === 2)).toBe(false);
    expect(payloadJson<any>(fr.at(-1)!.payload).code).toBe('connect_denied');
    await b.stop();
  });

  it('a hop the proxy refused (its marker header) is an error frame', async () => {
    const f = vi.fn(async () => new Response('', { status: 403, headers: { 'x-adblock-note': 'relayed request refused' } }));
    const { b } = setup({ fetch: f });
    const ws = await welcome(b);
    ws.recv(encodeFrame(0, 5, meta({})));
    await tick(); await tick();
    const fr = ws.frames();
    expect(fr.some((x) => x.type === 1)).toBe(false);
    expect(fr.at(-1)!.type).toBe(4);
    await b.stop();
  });

  it('manual redirects are not relayed (the proxy keeps them on the jar)', async () => {
    const f = vi.fn();
    const { b } = setup({ fetch: f });
    const ws = await welcome(b);
    ws.recv(encodeFrame(0, 5, meta({ redirect: 'manual' })));
    await tick();
    expect(f).not.toHaveBeenCalled();
    expect(ws.frames().at(-1)!.type).toBe(4);
    await b.stop();
  });

  it('reports recorded grants only, ignoring browser permissions', async () => {
    const { b, br } = setup({ grants: ['https://a.com/*', '*://*.b.com/*', '<all_urls>', 'https://*/*'] });
    br.permissions.getAll.mockResolvedValue({ origins: ['<all_urls>', 'https://z.com/*'] } as any);
    const ws = await welcome(b);
    expect(ws.texts()[1]).toEqual({ t: 'perms', origins: ['https://a.com/*', '*://*.b.com/*'] });
    await b.stop();
  });

  it('denies without a recorded grant even when the browser says it has access', async () => {
    const { b, br } = setup({ grants: [] });
    br.permissions.contains.mockResolvedValue(true);
    const ws = await welcome(b);
    ws.recv(encodeFrame(0, 5, meta({})));
    await tick(); await tick();
    expect(payloadJson<any>(ws.frames().at(-1)!.payload).code).toBe('permission');
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

  it('a container job fetches without the default cookies, with the marker, through the store relay', async () => {
    const proxy = { setSid: async () => {}, setServer: async () => {}, storeForToken: (t: string) => (t === 'tok1' ? 'firefox-container-1' : undefined) };
    let seen: any;
    const f = vi.fn(async (_u: string, init: any) => { seen = init; return new Response('ok'); });
    const { b, br } = setup({ fetch: f, proxy });
    const sr = new StoreRelay(br);
    (br as any).webRequest = { onBeforeSendHeaders: { addListener: vi.fn() }, onHeadersReceived: { addListener: vi.fn() } };
    const b2 = new Bridge({ WebSocketCtor: FakeWS as any, browser: br, fetch: f as any, proxy: proxy as any, storeRelay: sr, getSettings: async () => ({ argusUrl: 'https://argus.local:8443', token: 'tok' }) });
    await b2.connect();
    const ws = FakeWS.last; ws.open(); ws.recv(JSON.stringify({ t: 'welcome', sid: SID, v: 1 })); await tick();
    ws.recv(encodeFrame(0, 5, meta({ store: 'tok1' })));
    await tick(); await tick();
    expect(seen.credentials).toBe('omit');
    expect(seen.headers.get('X-Argus-Job')).toBeTruthy();
    expect(sr.active()).toBe(0); // released after the job
    // an unknown token is refused, nothing is fetched
    f.mockClear();
    ws.recv(encodeFrame(0, 6, meta({ store: 'forged' })));
    await tick();
    expect(f).not.toHaveBeenCalled();
    expect(payloadJson<any>(ws.frames().at(-1)!.payload).code).toBe('store');
    await b.stop(); await b2.stop();
  });

  it('a container cookie job reads and writes that store only', async () => {
    const proxy = { setSid: async () => {}, setServer: async () => {}, storeForToken: (t: string) => (t === 'tok1' ? 'firefox-container-1' : undefined) };
    const { b, br } = setup({ proxy });
    br.cookies.getAll.mockResolvedValue([{ name: 'a', value: '1', domain: 'a.com', path: '/', httpOnly: false }] as any);
    const ws = await welcome(b);
    ws.recv(encodeFrame(0, 4, { op: 'cookie', script: 's', relay: 'r', store: 'tok1', connect: { page: 'a.com', list: [], all: false }, cookie: { op: 'list', url: 'https://a.com/' } }));
    await tick();
    expect(br.cookies.getAll).toHaveBeenCalledWith({ url: 'https://a.com/', storeId: 'firefox-container-1' });
    await b.stop();
  });
});

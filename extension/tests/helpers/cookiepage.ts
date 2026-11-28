import { createCookieService, registerCookieListeners, servePort, type CookieService } from '../../lib/cookiejar/service';
import { IDBFactory } from 'fake-indexeddb';
import { idbKeyStore, type KeyStore } from '../../lib/cookiejar/crypto';
import { CookieClient, type PortLike } from '../../ui/cookies/client';
import { FakeAlarms, FakeBrowser, FakeStorageArea, type FakeOpts } from './fakebrowser';

/** Two ends of an in-memory `runtime.connect` port; messages are cloned and delivered asynchronously. */
export function portPair() {
  type L = (m: any) => void;
  const make = () => ({ msg: [] as L[], dis: [] as (() => void)[] });
  const a = make(), b = make();
  const end = (me: ReturnType<typeof make>, other: ReturnType<typeof make>): PortLike & { onMessage: any; onDisconnect: any } => ({
    postMessage: (m: unknown) => { const c = structuredClone(m); setTimeout(() => { for (const f of other.msg) f(c); }, 0); },
    onMessage: { addListener: (f: L) => me.msg.push(f) },
    onDisconnect: { addListener: (f: () => void) => me.dis.push(f) },
    disconnect: () => { for (const f of other.dis) f(); for (const f of me.dis) f(); },
  });
  return { page: end(a, b), background: end(b, a) };
}

export interface World {
  fb: FakeBrowser;
  br: any;
  svc: CookieService;
  client: CookieClient;
  /** The page's global `browser`: tabs and the bridge session. */
  pageBrowser: any;
  alarms: FakeAlarms;
}

/** The cookie library on a fake browser, served over an in-memory port to a real `CookieClient`. */
export function cookieWorld(o: FakeOpts & { keyStore?: KeyStore; sid?: string; tabs?: { id: number; url: string }[] } = {}): World {
  const fb = new FakeBrowser(o);
  fb.tabList = o.tabs ?? [];
  const alarms = new FakeAlarms();
  const noop = { addListener() {} };
  const br: any = {
    cookies: fb.cookies,
    tabs: { ...fb.tabs, onUpdated: noop, onRemoved: noop },
    alarms,
    runtime: { onStartup: noop },
    storage: { local: new FakeStorageArea(), session: new FakeStorageArea() },
    contextualIdentities: fb.contextualIdentities,
  };
  const svc = createCookieService(br, { keyStore: o.keyStore ?? (typeof indexedDB === 'undefined' ? idbKeyStore({ factory: new IDBFactory() }) : idbKeyStore()), iterations: 1000 });
  registerCookieListeners(br, svc);
  const client = new CookieClient(() => {
    const p = portPair();
    servePort(p.background, svc);
    return p.page;
  }, { alive: () => true });
  const pageBrowser = {
    tabs: { get: async (id: number) => { const t = fb.tabList.find((x) => x.id === id); if (!t) throw new Error('No tab'); return { ...t }; }, query: async () => fb.tabList.map((t) => ({ ...t })) },
    runtime: { sendMessage: async (m: { type: string }) => (m.type === 'bridge-status' ? { connected: true, sid: o.sid ?? 'sid-1' } : undefined) },
    storage: br.storage,
  };
  return { fb, br, svc, client, pageBrowser, alarms };
}

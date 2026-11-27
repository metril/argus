import { cachedLookup, clearCache, getSettings, hostOf, type Lookup } from '../lib/api';
import { signOutInBackground } from '../lib/auth';
import { Bridge } from '../lib/bridge';
import { onStorageChanged } from '../lib/changes';
import { respondAsync } from '../lib/messages';
import { ProxyController, type ProxyState } from '../lib/proxy';
import { RouteTracker } from '../lib/route';
import { StoreRelay } from '../lib/storerelay';

/** The toolbar badge is a colored dot for the site state; nothing when there is nothing to say. */
function badgeFor(v: Lookup): { text: string; color: string } {
  switch (v.kind) {
    case 'ok': return v.cert.verdict === 'invalid' ? { text: '!', color: '#f2695f' } : { text: '●', color: '#4fc48d' };
    case 'unseen': return { text: '●', color: '#4cc2d9' };
    case 'error': return { text: '?', color: '#e6a94c' };
    default: return { text: '', color: '#80868b' };
  }
}

export default defineBackground(() => {
  const action = browser.action;
  const routes = new RouteTracker();

  async function update(tabId: number, url?: string) {
    // Argus is on but unreachable: the browser is blocked (not direct); say so on every tab.
    if (proxy.unreachable()) {
      await action.setBadgeText({ tabId, text: '!' });
      await action.setBadgeBackgroundColor({ tabId, color: '#f2695f' });
      return;
    }
    const host = hostOf(url);
    if (!host) { await action.setBadgeText({ tabId, text: '' }); return; }
    const b = badgeFor(await cachedLookup(host));
    await action.setBadgeText({ tabId, text: b.text });
    await action.setBadgeBackgroundColor({ tabId, color: b.color });
    try { await (action as any).setBadgeTextColor?.({ tabId, color: '#0c0f13' }); } catch { /* optional */ }
  }

  async function refreshBadges() {
    try {
      for (const t of await browser.tabs.query({})) if (t.id !== undefined) await update(t.id, t.url);
    } catch { /* ignore */ }
  }

  // Userscript bridge: channel to the proxy for relayed requests, and the proxy settings that
  // bind this browser's documents to the channel's session (proxy authentication, never headers).
  const firefox = typeof (browser as any).contextualIdentities !== 'undefined' || /Firefox\//.test(navigator.userAgent);
  const argusHost = async () => { try { return new URL((await getSettings()).argusUrl).hostname; } catch { return ''; } };
  const proxy: ProxyController = new ProxyController({ browser, firefox, argusHost, onStatus: () => void refreshBadges() });
  const bridge = new Bridge({ WebSocketCtor: WebSocket, browser, getSettings, proxy, storeRelay: new StoreRelay(browser) });
  void proxy.init().then(() => bridge.connect());
  const b: any = browser;
  if (firefox && b.proxy?.onRequest) {
    b.proxy.onRequest.addListener((d: { cookieStoreId?: string; url?: string }) => proxy.route(d), { urls: ['<all_urls>'] });
  }
  // Only our own listener's realm is ever answered (see ProxyController.auth).
  b.webRequest?.onAuthRequired?.addListener(
    (d: any, cb?: (r: unknown) => void) => {
      const p = proxy.auth(d);
      // Chrome (asyncBlocking) answers through the callback; Firefox takes the promise.
      if (typeof cb === 'function') { void p.then(cb); return undefined; }
      return p;
    },
    { urls: ['<all_urls>'] },
    [firefox ? 'blocking' : 'asyncBlocking'],
  );
  // First run: open the setup page (sign in, turn on, pin).
  browser.runtime.onInstalled.addListener((d: { reason?: string }) => {
    if (d.reason === 'install') void browser.tabs.create({ url: browser.runtime.getURL('/options.html#setup' as any) });
  });
  const alarms = (browser as any).alarms;
  if (alarms) {
    void alarms.create('argus-bridge', { periodInMinutes: 0.5 });
    alarms.onAlarm.addListener((a: { name: string }) => {
      if (a.name === 'argus-bridge' && !bridge.status().connected) void bridge.connect();
    });
  }

  browser.tabs.onUpdated.addListener((tabId, info, tab) => {
    if (info.status === 'complete' || info.url) void update(tabId, tab.url);
  });
  browser.storage.onChanged.addListener((changes: Record<string, unknown>) => onStorageChanged(changes, { clearCache, bridge, proxy }));
  browser.tabs.onRemoved.addListener((id) => routes.forget(id));
  // New tabs / windows opened by a page: the proxy learns the opener (for `$popup`).
  b.webNavigation?.onCreatedNavigationTarget?.addListener((d: { url?: string; sourceTabId?: number }) => {
    if (d.url && d.sourceTabId !== undefined && d.sourceTabId >= 0) void bridge.reportPopup(d.url, d.sourceTabId);
  });

  // Whether a tab's document came through Argus: the proxy marks document responses it relays.
  const wr = (browser as any).webRequest;
  wr?.onHeadersReceived?.addListener(
    (d: { tabId: number; fromCache?: boolean; responseHeaders?: { name: string }[] }) => {
      if (!d.fromCache) routes.record(d.tabId, d.responseHeaders);
    },
    { urls: ['<all_urls>'], types: ['main_frame'] },
    ['responseHeaders'],
  );

  browser.runtime.onMessage.addListener(respondAsync((msg: { type?: string; tabId?: number }, sender: { id?: string }) => {
    if (msg?.type === 'interception' && msg.tabId !== undefined) {
      const enabled = proxy.getState().enabled;
      return Promise.resolve({ route: routes.route(msg.tabId, enabled), enabled });
    }
    if (msg?.type === 'proxy-get' || msg?.type === 'proxy-set' || msg?.type === 'store-token') {
      if (sender?.id !== browser.runtime.id) return undefined;
      const m = msg as { type: string; state?: ProxyState; storeId?: string };
      if (m.type === 'store-token') return Promise.resolve(proxy.tokenFor(m.storeId));
      if (m.type === 'proxy-set' && m.state) return proxy.setState(m.state).then(() => (routes.reset(), { state: proxy.getState(), active: proxy.active(), listener: proxy.listener(), unreachable: proxy.unreachable(), firefox }));
      return Promise.resolve({ state: proxy.getState(), active: proxy.active(), listener: proxy.listener(), unreachable: proxy.unreachable(), firefox });
    }
    if (msg?.type === 'bridge-reconnect') {
      if (sender?.id !== browser.runtime.id) return undefined;
      return bridge.connect().then(() => bridge.status());
    }
    if (msg?.type === 'sign-out') {
      if (sender?.id !== browser.runtime.id) return undefined;
      return signOutInBackground({ bridge, proxy }).then(() => true);
    }
    if (msg?.type === 'bridge-status') {
      if (sender?.id !== browser.runtime.id) return undefined;
      return Promise.resolve(bridge.status());
    }
    return undefined;
  }));
});

import { cachedLookup, clearCache, fetchExtLog, fetchRecentBlocked, getSettings, hostOf, type Lookup } from '../lib/api';
import { blockedTotal, classify, hostnameOf, StatsStore } from '../lib/stats';
import { joinEntries, LogStore, ReqLog, type LogRow } from '../lib/logs';
import { LogFeed } from '../lib/logfeed';
import { signOutInBackground } from '../lib/auth';
import { Bridge } from '../lib/bridge';
import { FriendlyFrames } from '../lib/friendly-frames';
import { onStorageChanged } from '../lib/changes';
import { fromExtensionPage, respondAsync } from '../lib/messages';
import { ProxyController, type ProxyState } from '../lib/proxy';
import { RouteTracker } from '../lib/route';
import { StoreRelay } from '../lib/storerelay';

/** The toolbar badge is a colored dot for the site state; nothing when there is nothing to say. */
/** Compact count for the badge (it holds about four characters). */
function badgeCount(n: number): string {
  return n < 1000 ? String(n) : n < 10000 ? `${(n / 1000).toFixed(1).replace(/\.0$/, '')}k` : `${Math.min(99, Math.floor(n / 1000))}k`;
}

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

  // Per-tab request counters, kept in storage.session so they survive the service worker sleeping.
  const stats = new StatsStore((browser.storage as any).session, (tabId) => refreshBadge(tabId));

  const badgeTimers = new Map<number, ReturnType<typeof setTimeout>>();
  /** Debounced per tab: a page can produce hundreds of counter changes a second. */
  function refreshBadge(tabId: number) {
    if (badgeTimers.has(tabId)) return;
    badgeTimers.set(tabId, setTimeout(() => { badgeTimers.delete(tabId); void refreshBadgeNow(tabId); }, 250));
  }
  async function refreshBadgeNow(tabId: number) {
    try { const t = await browser.tabs.get(tabId); await update(tabId, t.url); } catch { /* tab gone */ }
  }

  async function update(tabId: number, url?: string) {
    // Argus is on but unreachable: the browser is blocked (not direct); say so on every tab.
    if (proxy.unreachable()) {
      await action.setBadgeText({ tabId, text: '!' });
      await action.setBadgeBackgroundColor({ tabId, color: '#f2695f' });
      return;
    }
    // The text is this page's blocked count; the colour keeps the certificate state (a problem
    // still shows as `!`).
    const count = blockedTotal(await stats.tab(tabId));
    const host = hostOf(url);
    const b = host ? badgeFor(await cachedLookup(host)) : { text: '', color: '#80868b' };
    const text = b.text === '!' ? '!' : count > 0 ? badgeCount(count) : b.text;
    await action.setBadgeText({ tabId, text });
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
  const bridge = new Bridge({ WebSocketCtor: WebSocket, browser, getSettings, proxy, storeRelay: new StoreRelay(browser), frames: new FriendlyFrames(browser) });
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
  browser.tabs.onRemoved.addListener((id) => { routes.forget(id); void stats.dispatch({ t: 'close', tabId: id }); });
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

  // Counters: every response (the proxy's `x-adblock` tag marks blocks), cached completions, and
  // network errors (aborted blocks, attributed through the proxy's recent-blocked list).
  // Non-blocking, all request types; the same API on Chrome and Firefox.
  const seen = new Set<string>();
  const remember = (id: string) => { seen.add(id); if (seen.size > 2000) seen.delete(seen.values().next().value as string); };
  wr?.onHeadersReceived?.addListener(
    (d: { tabId: number; requestId: string; url: string; type: string; statusCode?: number; responseHeaders?: { name: string; value?: string }[] }) => {
      if (d.tabId < 0) return;
      remember(d.requestId);
      // Each redirect hop reports its own response; only the final one is a request of the page.
      if (d.statusCode !== undefined && d.statusCode >= 300 && d.statusCode <= 399) return;
      void stats.dispatch({ t: 'response', tabId: d.tabId, main: d.type === 'main_frame', kind: classify(d.responseHeaders), host: hostnameOf(d.url) });
      schedulePoll();
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders'],
  );
  wr?.onCompleted?.addListener(
    (d: { tabId: number; requestId: string; url: string; type: string; fromCache?: boolean }) => {
      // Served from cache without onHeadersReceived (Chrome): a cached response was never a block.
      if (d.tabId < 0 || !d.fromCache || seen.has(d.requestId)) return;
      void stats.dispatch({ t: 'response', tabId: d.tabId, main: d.type === 'main_frame', kind: 'allowed', host: hostnameOf(d.url) });
    },
    { urls: ['<all_urls>'] },
  );
  wr?.onErrorOccurred?.addListener(
    (d: { tabId: number; url: string; type: string; error?: string }) => {
      if (d.tabId < 0) return;
      void stats.dispatch({ t: 'error', tabId: d.tabId, main: d.type === 'main_frame', url: d.url, now: Date.now(), ...(d.error ? { error: d.error } : {}) });
      scheduleReconcile(d.tabId);
    },
    { urls: ['<all_urls>'] },
  );
  // The proxy's own log of this session's requests (`/ext/log`): exact attribution of aborted
  // blocks, and the rows of the logger page. Joined to tabs by URL and time (webRequest).
  const logs = new LogStore((browser.storage as any).session);
  const reqs = new ReqLog();
  wr?.onBeforeRequest?.addListener(
    (d: { tabId: number; url: string }) => { if (d.tabId >= 0) reqs.add({ tabId: d.tabId, url: d.url, at: Date.now() }); },
    { urls: ['<all_urls>'] },
  );
  const feed = new LogFeed((browser.storage as any).session);
  const ports = new Set<{ postMessage(m: unknown): void }>();
  let polling: Promise<boolean> = Promise.resolve(false);
  /** One poll at a time; true when the proxy answered (false: no session, older proxy, no scope). */
  function pollLog(): Promise<boolean> {
    polling = polling.then(pollOnce, pollOnce);
    return polling;
  }
  async function pollOnce(): Promise<boolean> {
    const sid = bridge.status().sid;
    if (!sid) return false;
    const from = await feed.begin(sid);
    const r = await fetchExtLog(await getSettings(), sid, from);
    if (!r.ok) return false;
    const entries = feed.accept(sid, r.value.next, r.value.entries ?? []);
    if (entries.length === 0) return true;
    const pages: Record<number, string> = {};
    try {
      for (const t of await browser.tabs.query({})) {
        const h = t.id !== undefined ? (await stats.tab(t.id)).pageHost : undefined;
        if (t.id !== undefined && h) pages[t.id] = h;
      }
    } catch { /* no tab hints */ }
    const rows = joinEntries(entries, reqs.all(), pages);
    await logs.add(rows);
    for (const p of ports) { try { p.postMessage({ t: 'rows', rows }); } catch { /* port gone */ } }
    return true;
  }
  let pollTimer: ReturnType<typeof setTimeout> | undefined;
  /** History for tabs without a logger page open: poll shortly after activity. */
  function schedulePoll() {
    if (pollTimer) return;
    pollTimer = setTimeout(() => { pollTimer = undefined; void pollLog(); }, 2000);
  }
  let liveTimer: ReturnType<typeof setInterval> | undefined;
  browser.runtime.onConnect.addListener((port: any) => {
    if (port.name !== 'logger' || !fromExtensionPage(port.sender, browser.runtime.id, browser.runtime.getURL('/' as any))) { try { port.disconnect(); } catch { /* ignore */ } return; }
    ports.add(port);
    if (!liveTimer) liveTimer = setInterval(() => void pollLog(), 1000);
    void pollLog();
    port.onDisconnect.addListener(() => {
      ports.delete(port);
      if (ports.size === 0 && liveTimer) { clearInterval(liveTimer); liveTimer = undefined; }
    });
  });

  const timers = new Map<number, ReturnType<typeof setTimeout>>();
  async function reconcileTab(tabId: number) {
    if ((await stats.tab(tabId)).pending.length === 0) return;
    // Exact: the proxy's log of this session. An older proxy (or no session): the heuristic.
    if (await pollLog()) {
      await stats.dispatch({ t: 'attribute', tabId, entries: feed.recent, used: feed.used, now: Date.now() });
      return;
    }
    const r = await fetchRecentBlocked(await getSettings());
    // Unreachable or without the scope: nothing is attributed, so the errors expire as "failed".
    await stats.dispatch({ t: 'reconcile', tabId, blocked: r.ok ? r.value.entries.map((e) => ({ url: e.url, at: Date.parse(e.time), source: e.source_host })) : [], now: Date.now() });
  }
  function scheduleReconcile(tabId: number) {
    if (timers.has(tabId)) return;
    timers.set(tabId, setTimeout(() => { timers.delete(tabId); void reconcileTab(tabId); }, 1500));
  }

  browser.runtime.onMessage.addListener(respondAsync((msg: { type?: string; tabId?: number }, sender: { id?: string; url?: string }) => {
    if (msg?.type === 'interception' && msg.tabId !== undefined) {
      const enabled = proxy.getState().enabled;
      return Promise.resolve({ route: routes.route(msg.tabId, enabled), enabled });
    }
    if (msg?.type === 'tab-stats' && msg.tabId !== undefined) {
      if (sender?.id !== browser.runtime.id) return undefined;
      const id = msg.tabId;
      return reconcileTab(id).then(() => stats.tab(id)).then((st) => ({ stats: { ...st, pending: [] } }));
    }
    if (msg?.type === 'log-rows' || msg?.type === 'log-clear' || msg?.type === 'log-counts') {
      if (!fromExtensionPage(sender, browser.runtime.id, browser.runtime.getURL('/' as any))) return undefined;
      const id = msg.tabId;
      if (msg.type === 'log-counts') return logs.counts().then((counts) => ({ counts }));
      if (id === undefined) return undefined;
      if (msg.type === 'log-clear') return logs.clear(id).then(() => true);
      return logs.rows(id).then((rows: LogRow[]) => ({ rows }));
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

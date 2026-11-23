import { cachedLookup, clearCache, hostOf, type Interception, type Lookup } from '../lib/api';

function badgeFor(v: Lookup): { text: string; color: string } {
  switch (v.kind) {
    case 'ok': return v.cert.verdict === 'invalid' ? { text: '!', color: '#d93025' } : { text: '', color: '#188038' };
    case 'unseen': return { text: '–', color: '#80868b' };
    case 'auth': return { text: '?', color: '#f9ab00' };
    default: return { text: '', color: '#80868b' };
  }
}

export default defineBackground(() => {
  const action = browser.action;
  const intercepted = new Map<number, Interception>();

  async function update(tabId: number, url?: string) {
    const host = hostOf(url);
    if (!host) { await action.setBadgeText({ tabId, text: '' }); return; }
    const b = badgeFor(await cachedLookup(host));
    await action.setBadgeText({ tabId, text: b.text });
    await action.setBadgeBackgroundColor({ tabId, color: b.color });
  }

  browser.tabs.onUpdated.addListener((tabId, info, tab) => {
    if (info.status === 'complete' || info.url) void update(tabId, tab.url);
  });
  browser.storage.onChanged.addListener(() => clearCache());
  browser.tabs.onRemoved.addListener((id) => intercepted.delete(id));

  // Firefox only: inspect the certificate the browser actually received.
  const wr = (browser as any).webRequest;
  if (wr && typeof wr.getSecurityInfo === 'function') {
    wr.onHeadersReceived.addListener(
      async (d: { requestId: string; tabId: number }) => {
        try {
          const info = await wr.getSecurityInfo(d.requestId, {});
          const issuer: string = info?.certificates?.[0]?.issuer ?? '';
          if (info?.state === 'insecure' || !issuer) return {};
          intercepted.set(d.tabId, issuer.includes('Argus Proxy CA') ? 'intercepted' : 'direct');
        } catch { /* ignore */ }
        return {};
      },
      { urls: ['<all_urls>'], types: ['main_frame'] },
      ['blocking'],
    );
  }

  browser.runtime.onMessage.addListener((msg: { type?: string; tabId?: number }) => {
    if (msg?.type === 'interception' && msg.tabId !== undefined) {
      return Promise.resolve((intercepted.get(msg.tabId) ?? 'unknown') as Interception);
    }
    return undefined;
  });
});

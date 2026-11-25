import { getSettings } from './api';
import { allGranted } from './grants';
import type { MenuCommand, MenuData, MenuGrant } from './bridge-types';

export interface Caller { trigger(c: MenuCommand): Promise<boolean> }

export type MenuState =
  | { kind: 'none' }
  | { kind: 'offline' }
  | { kind: 'note'; text: string }
  | { kind: 'ok'; commands: MenuCommand[]; grants: MenuGrant[]; call: Caller };

/** The page's userscript commands and pending login grants, via the connected bridge session. */
export async function loadMenu(tab: { id?: number; url?: string; cookieStoreId?: string } | undefined): Promise<MenuState> {
  if (tab?.id === undefined || !/^https?:/.test(tab.url ?? '')) return { kind: 'none' };
  let mdoc: string | null = null;
  try {
    const r = await browser.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [0] },
      func: () => {
        const e = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
        const s = e && e.serverTiming && Array.from(e.serverTiming).find((x) => x.name === 'argus');
        return s ? s.description : null;
      },
    });
    mdoc = (r?.[0]?.result as string | null | undefined) ?? null;
  } catch { return { kind: 'none' }; }
  if (!mdoc) return { kind: 'none' };
  const s = await getSettings();
  let sid: string | undefined; // held in memory only
  try {
    const st = (await browser.runtime.sendMessage({ type: 'bridge-status' })) as { connected?: boolean; sid?: string } | undefined;
    sid = st?.connected ? st.sid : undefined;
  } catch { /* ignore */ }
  if (!s.argusUrl || !sid) return { kind: 'offline' };
  const headers: Record<string, string> = { Authorization: `Bearer ${s.token}`, 'X-Argus-Session': sid };
  // A Firefox container's (or private window's) tab only sees its own documents: the opaque token
  // the extension used for that store in its proxy credentials names it to Argus.
  if (tab.cookieStoreId) {
    try {
      const t = (await browser.runtime.sendMessage({ type: 'store-token', storeId: tab.cookieStoreId })) as string | undefined;
      if (t) headers['X-Argus-Store'] = t;
    } catch { /* default store */ }
  }
  let data: MenuData;
  try {
    const res = await fetch(`${s.argusUrl}/api/v1/ext/menu?mdoc=${encodeURIComponent(mdoc)}`, { headers });
    if (res.status === 403 || res.status === 409) return { kind: 'note', text: 'Reload this page.' };
    if (!res.ok) return { kind: 'note', text: 'Commands unavailable.' };
    data = (await res.json()) as MenuData;
  } catch { return { kind: 'offline' }; }
  const grants: MenuGrant[] = [];
  for (const g of data.grants ?? []) {
    if (!(await allGranted(browser, g.patterns))) grants.push(g);
  }
  return {
    kind: 'ok', commands: data.commands ?? [], grants,
    call: {
      async trigger(c) {
        try {
          const res = await fetch(`${s.argusUrl}/api/v1/ext/menu/trigger`, {
            method: 'POST',
            headers: { ...headers, 'Content-Type': 'application/json' },
            body: JSON.stringify({ mdoc, script: c.script, cmd: c.cmd }),
          });
          if (!res.ok) return false;
          return ((await res.json()) as { delivered?: boolean }).delivered === true;
        } catch { return false; }
      },
    },
  };
}

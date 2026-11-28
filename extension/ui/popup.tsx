import { useEffect, useState } from 'preact/hooks';
import { cachedLookup, clearCache, hostOf, type Lookup } from '../lib/api';
import type { Route } from '../lib/route';
import { signOut } from '../lib/auth';
import { loadMenu, type MenuState } from '../lib/menudata';
import { registrableDomain, type TabStats } from '../lib/stats';
import { Scripts } from './scripts';
import { resolveState } from '../lib/state';
import { AccountBar, ErrorBanner, Header, Icon, SignInForm, SiteCard, Skeleton, BrowserCard } from './components';
import { PageStats, StatsView, ScopeNotice, SiteSwitch } from './pagestats';
import { hostLabel, isSignedIn, settings } from './store';

type Tab = { id?: number; url?: string; cookieStoreId?: string };

function Menu({ onSettings }: { onSettings: () => void }) {
  return (
    <div class="menu" role="menu">
      <button type="button" role="menuitem" class="row" onClick={onSettings}>Settings</button>
    </div>
  );
}

const plainHost = (url?: string) => { try { const u = new URL(url ?? ''); return /^https?:$/.test(u.protocol) ? u.hostname : ''; } catch { return ''; } };

export function App() {
  const s = settings.value;
  const [tab, setTab] = useState<Tab | null | undefined>(undefined);
  const [lookup, setLookup] = useState<Lookup>();
  const [inter, setInter] = useState<Route>();
  const [stats, setStats] = useState<TabStats>();
  const [menu, setMenu] = useState<MenuState>({ kind: 'none' });
  const [live, setLive] = useState(false);
  const [more, setMore] = useState(false);
  const [n, setN] = useState(0);
  const [switching, setSwitching] = useState(false);
  const [needScope, setNeedScope] = useState(false);
  const [view, setView] = useState<'actions' | 'stats'>('actions');

  // The popup follows the active tab: a navigation or a tab switch re-derives every card.
  useEffect(() => {
    let alive = true;
    const read = () => void browser.tabs.query({ active: true, currentWindow: true }).then(([t]) => {
      if (!alive) return;
      const next = (t as Tab | undefined) ?? null;
      setTab((prev) => (prev && next && prev.id === next.id && prev.url === next.url ? prev : next));
    });
    read();
    const onUpdated = (id: number, info: { url?: string; status?: string }) => { if (info.url || info.status === 'complete') { void id; read(); } };
    browser.tabs.onUpdated?.addListener(onUpdated as never);
    browser.tabs.onActivated?.addListener(read);
    return () => {
      alive = false;
      browser.tabs.onUpdated?.removeListener(onUpdated as never);
      browser.tabs.onActivated?.removeListener(read);
    };
  }, []);

  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') { if (more) setMore(false); else window.close(); } };
    addEventListener('keydown', esc);
    return () => removeEventListener('keydown', esc);
  }, [more]);

  const signed = isSignedIn(s);
  const tabId = tab?.id;
  const tabUrl = tab?.url;
  useEffect(() => {
    if (tab === undefined || !signed) return;
    // Everything below is for this tab and URL; a response for an earlier one is dropped.
    let cancelled = false;
    setLookup(undefined); setInter(undefined); setStats(undefined); setMenu({ kind: 'none' });
    let timer: ReturnType<typeof setInterval> | undefined;
    const host = hostOf(tabUrl);
    if (host) void cachedLookup(host).then((l) => { if (!cancelled) setLookup(l); });
    if (tabId !== undefined) {
      const ask = () => {
        void browser.runtime.sendMessage({ type: 'interception', tabId }).then((i) => { if (!cancelled) setInter((i as { route?: Route } | undefined)?.route); }, () => {});
        void browser.runtime.sendMessage({ type: 'tab-stats', tabId }).then((r) => { if (!cancelled) setStats((r as { stats?: TabStats } | undefined)?.stats); }, () => {});
      };
      ask();
      // The toggle can change while the popup is open: re-read this tab's routing and counts.
      timer = setInterval(ask, 2000);
    }
    void loadMenu(tab ?? undefined).then((m) => { if (!cancelled) setMenu(m); });
    void browser.runtime.sendMessage({ type: 'bridge-status' }).then((b) => { if (!cancelled) setLive(!!(b as { connected?: boolean } | undefined)?.connected); }, () => {});
    return () => { cancelled = true; if (timer) clearInterval(timer); };
  }, [tabId, tabUrl, signed, s?.token, n]);

  if (s === null || tab === undefined) return <div class="pop"><Header /><div class="main"><Skeleton /></div></div>;
  const r = resolveState({ configured: signed, ...(tabUrl ? { tabUrl } : {}), ...(lookup ? { lookup } : {}) });
  if (r.view === 'signin' || switching) {
    return <div class="pop"><Header /><SignInForm expired={r.view === 'signin' && r.reason === 'expired'} onDone={() => { setSwitching(false); setNeedScope(false); }} /></div>;
  }
  const host = hostOf(tabUrl) ?? '';
  const site = registrableDomain(plainHost(tabUrl));
  return (
    <div class="pop">
      <Header live={live}>
        <button type="button" class="ib" aria-label="More" aria-haspopup="menu" aria-expanded={more} onClick={() => setMore(!more)}><Icon n="dots" size={16} sw={3} /></button>
        {more && <Menu onSettings={() => void browser.runtime.openOptionsPage()} />}
      </Header>
      <main class="main">
        {r.banner && (
          <ErrorBanner error={r.banner.error} host={hostLabel(s.argusUrl)} refused={!!r.banner.refused} onAction={(a) => {
            if (a === 'switch') setSwitching(true);
            else if (a === 'allow') void browser.permissions.request({ origins: [new URL(s.argusUrl).origin + '/*'] }).finally(() => { clearCache(); setN(n + 1); });
            else { clearCache(); setN(n + 1); }
          }} />
        )}
        {needScope && <ScopeNotice onSignIn={() => setSwitching(true)} />}
        <div class="seg" role="group" aria-label="View">
          <button type="button" aria-pressed={view === 'actions'} onClick={() => setView('actions')}>Actions</button>
          <button type="button" aria-pressed={view === 'stats'} onClick={() => setView('stats')}>Statistics</button>
        </div>
        {view === 'stats' ? <StatsView key={s.token} settings={s} onScope={() => setNeedScope(true)} /> : <>
        <SiteCard host={host} site={r.site} route={inter} />
        <PageStats stats={stats} />
        {tabId !== undefined && <button type="button" class="btn" data-testid="open-logger" onClick={() => { void browser.tabs.create({ url: `${browser.runtime.getURL('/logger.html' as any)}#tab=${tabId}` }); window.close(); }}>Open logger</button>}
        {site && <SiteSwitch key={`${tabId}|${site}`} settings={s} site={site} onScope={() => setNeedScope(true)} reload={() => { if (tabId !== undefined) void browser.tabs.reload(tabId); window.close(); }} />}
        <Scripts state={menu} reload={() => setN(n + 1)} />
        <section class="sec">
          <div class="lbl">This browser</div>
          <BrowserCard />
        </section>
        </>}
      </main>
      <AccountBar user={s.user ?? ''} url={s.argusUrl} onSignOut={() => void signOut()} />
    </div>
  );
}

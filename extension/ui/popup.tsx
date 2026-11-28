import { useEffect, useState } from 'preact/hooks';
import { cachedLookup, clearCache, hostOf, type Lookup } from '../lib/api';
import type { Route } from '../lib/route';
import { signOut } from '../lib/auth';
import { loadMenu, type MenuState } from '../lib/menudata';
import { registrableDomain, type TabStats } from '../lib/stats';
import { Scripts } from './scripts';
import { resolveState } from '../lib/state';
import { AccountBar, ErrorBanner, Header, Icon, SignInForm, SiteCard, Skeleton, BrowserCard } from './components';
import { PageStats, StatsView, ScopeNotice, SiteNotes, SiteToggle, useSiteSwitch } from './pagestats';
import { Segmented } from './cookies/kit';
import { SiteBypassRow, useSiteBypass } from './sitebypass';
import { SiteRulesCard, useSiteRules } from './siterules';
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
  const [armErr, setArmErr] = useState(false);
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

  const arm = async (id: number, mode: 'picker' | 'zapper') => {
    setArmErr(false);
    const r = (await browser.runtime.sendMessage({ type: 'picker-arm', tabId: id, mode }).catch(() => undefined)) as { ok?: boolean } | undefined;
    if (r?.ok) window.close(); else setArmErr(true);
  };

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

  const siteKey = registrableDomain(plainHost(tabUrl));
  const sr = useSiteRules(signed ? s : null, siteKey, () => setNeedScope(true));
  const bp = useSiteBypass(s ?? { argusUrl: '', token: '' }, signed ? plainHost(tabUrl) : '');
  const sw = useSiteSwitch(s ?? { argusUrl: '', token: '' }, signed ? siteKey : '', () => setNeedScope(true));
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
        <Segmented<'actions' | 'stats'> label="View" cls="wide" value={view} onChange={setView} options={[{ v: 'actions', l: 'Actions' }, { v: 'stats', l: 'Statistics' }]} />
        {view === 'stats' ? <StatsView key={s.token} settings={s} onScope={() => setNeedScope(true)} /> : <>
        <SiteCard
          host={host} site={r.site} route={inter}
          right={site ? <SiteToggle site={site} st={sw} /> : undefined}
          foot={<SiteNotes st={sw} reload={() => { if (tabId !== undefined) void browser.tabs.reload(tabId); window.close(); }} />}
        >
          {r.site.kind !== 'none' && <PageStats stats={stats} site={site} sr={sr} bare />}
        </SiteCard>
        {r.site.kind === 'none' && <PageStats stats={stats} site={site} sr={sr} />}
        <div class="pgrid" data-testid="actions">
          <button type="button" class="btn" data-testid="open-logger" disabled={tabId === undefined} onClick={() => { if (tabId !== undefined) { void browser.tabs.create({ url: `${browser.runtime.getURL('/logger.html' as any)}#tab=${tabId}` }); window.close(); } }}>Open logger</button>
          <button type="button" class="btn" data-testid="open-cookies" disabled={tabId === undefined} onClick={() => { if (tabId !== undefined) { void browser.tabs.create({ url: `${browser.runtime.getURL('/cookies.html' as any)}#tab=${tabId}` }); window.close(); } }}><Icon n="cookie" size={14} />Cookies</button>
          <button type="button" class="btn" data-testid="pick" disabled={tabId === undefined || !site} onClick={() => { if (tabId !== undefined) void arm(tabId, 'picker'); }}>Block an element</button>
          <button type="button" class="btn" data-testid="zap" disabled={tabId === undefined || !site} onClick={() => { if (tabId !== undefined) void arm(tabId, 'zapper'); }}>Zap elements</button>
        </div>
        {/* Full-width rows that belong under the grid go here. */}
        <div class="pslot" data-testid="actions-slot">
          {site && <SiteBypassRow st={bp} reload={() => { if (tabId !== undefined) void browser.tabs.reload(tabId); }} onSignIn={() => setSwitching(true)} />}
        </div>
        {armErr && <div class="note" data-testid="arm-error">Could not start on this page.</div>}
        {site && <SiteRulesCard site={site} sr={sr} />}
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

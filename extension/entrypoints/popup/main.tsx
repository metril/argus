import { render } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import '../../ui/tokens.css';
import '../../ui/ui.css';
import { cachedLookup, clearCache, hostOf, type Lookup } from '../../lib/api';
import type { Route } from '../../lib/route';
import { signOut } from '../../lib/auth';
import { loadMenu, type MenuState } from '../../lib/menudata';
import { Scripts } from '../../ui/scripts';
import { resolveState } from '../../lib/state';
import { AccountBar, Banner, BrowserCard, ErrorBanner, Header, Icon, SignInForm, SiteCard, Skeleton } from '../../ui/components';
import { hostLabel, isSignedIn, settings, watchSettings } from '../../ui/store';

type Tab = { id?: number; url?: string; cookieStoreId?: string };

function Menu({ onSettings }: { onSettings: () => void }) {
  return (
    <div class="menu" role="menu">
      <button type="button" role="menuitem" class="row" onClick={onSettings}>Settings</button>
    </div>
  );
}

function App() {
  const s = settings.value;
  const [tab, setTab] = useState<Tab | null | undefined>(undefined);
  const [lookup, setLookup] = useState<Lookup>();
  const [inter, setInter] = useState<Route>();
  const [menu, setMenu] = useState<MenuState>({ kind: 'none' });
  const [live, setLive] = useState(false);
  const [more, setMore] = useState(false);
  const [n, setN] = useState(0);
  const [switching, setSwitching] = useState(false);

  useEffect(() => {
    void browser.tabs.query({ active: true, currentWindow: true }).then(([t]) => setTab((t as Tab | undefined) ?? null));
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') { if (more) setMore(false); else window.close(); } };
    addEventListener('keydown', esc);
    return () => removeEventListener('keydown', esc);
  }, [more]);

  const signed = isSignedIn(s);
  useEffect(() => {
    if (tab === undefined || !signed) return;
    setLookup(undefined);
    let timer: ReturnType<typeof setInterval> | undefined;
    const host = hostOf(tab?.url);
    if (host) void cachedLookup(host).then(setLookup);
    if (tab?.id !== undefined) {
      const ask = () => void browser.runtime.sendMessage({ type: 'interception', tabId: tab.id }).then((i) => setInter((i as { route?: Route } | undefined)?.route), () => {});
      ask();
      // The toggle can change while the popup is open: re-read this tab's routing.
      timer = setInterval(ask, 2000);
    }
    void loadMenu(tab ?? undefined).then(setMenu);
    void browser.runtime.sendMessage({ type: 'bridge-status' }).then((b) => setLive(!!(b as { connected?: boolean } | undefined)?.connected), () => {});
    return () => { if (timer) clearInterval(timer); };
  }, [tab, signed, s?.token, n]);

  if (s === null || tab === undefined) return <div class="pop"><Header /><div class="main"><Skeleton /></div></div>;
  const r = resolveState({ configured: signed, ...(tab?.url ? { tabUrl: tab.url } : {}), ...(lookup ? { lookup } : {}) });
  if (r.view === 'signin' || switching) {
    return <div class="pop"><Header /><SignInForm expired={r.view === 'signin' && r.reason === 'expired'} onDone={() => setSwitching(false)} /></div>;
  }
  const host = hostOf(tab?.url) ?? '';
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
        <SiteCard host={host} site={r.site} route={inter} />
        <Scripts state={menu} reload={() => setN(n + 1)} />
        <section class="sec">
          <div class="lbl">This browser</div>
          <BrowserCard />
        </section>
      </main>
      <AccountBar user={s.user ?? ''} url={s.argusUrl} onSignOut={() => void signOut()} />
    </div>
  );
}

watchSettings();
render(<App />, document.getElementById('app')!);

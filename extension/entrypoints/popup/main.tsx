import { render } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import '../../ui/tokens.css';
import '../../ui/ui.css';
import { cachedLookup, clearCache, hostOf, type Interception, type Lookup } from '../../lib/api';
import { signOut } from '../../lib/auth';
import type { MenuGrant } from '../../lib/bridge-types';
import { recordGrant } from '../../lib/grants';
import { loadMenu, type MenuState } from '../../lib/menudata';
import { resolveState } from '../../lib/state';
import { AccountBar, Banner, BrowserCard, CommandList, ErrorBanner, GrantRow, Header, Icon, SignInForm, SiteCard, Skeleton } from '../../ui/components';
import { hostLabel, isSignedIn, settings, watchSettings } from '../../ui/store';

type Tab = { id?: number; url?: string; cookieStoreId?: string };

function Menu({ onSettings }: { onSettings: () => void }) {
  return (
    <div class="menu" role="menu">
      <button type="button" role="menuitem" class="row" onClick={onSettings}>Settings</button>
    </div>
  );
}

function Scripts({ state, tab, reload }: { state: MenuState; tab?: Tab; reload: () => void }) {
  const [miss, setMiss] = useState(false);
  const [grants, setGrants] = useState<MenuGrant[]>(state.kind === 'ok' ? state.grants : []);
  if (state.kind === 'none') return null;
  if (state.kind === 'offline') {
    return <Banner tone="warn" slim title="Offline" body="Commands unavailable." action="Reconnect" onAction={() => { void browser.runtime.sendMessage({ type: 'bridge-reconnect' }).finally(reload); }} />;
  }
  if (state.kind === 'note') return <div class="note">{state.text}</div>;
  if (!state.commands.length && !grants.length) return null;
  void tab;
  return (
    <section class="sec">
      <div class="lbl">Userscripts</div>
      <CommandList commands={state.commands} onTrigger={async (c) => {
        if (await state.call.trigger(c)) { if (c.autoClose !== false) window.close(); } else setMiss(true);
      }} />
      {miss && <div class="note" role="status">Not delivered. Reload the page.</div>}
      {grants.map((g) => (
        <GrantRow key={g.script + g.host} grant={g} onAllow={(x) => {
          // Called straight from the click so the permission prompt keeps its user gesture.
          void browser.permissions.request({ origins: x.patterns }).then(async (ok) => {
            if (ok) { await recordGrant(browser, x.patterns); setGrants((cur) => cur.filter((y) => y !== x)); }
          });
        }} />
      ))}
    </section>
  );
}

function App() {
  const s = settings.value;
  const [tab, setTab] = useState<Tab | null | undefined>(undefined);
  const [lookup, setLookup] = useState<Lookup>();
  const [inter, setInter] = useState<Interception>();
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
    const host = hostOf(tab?.url);
    if (host) void cachedLookup(host).then(setLookup);
    if (tab?.id !== undefined) {
      void browser.runtime.sendMessage({ type: 'interception', tabId: tab.id }).then((i) => setInter(i as Interception), () => {});
    }
    void loadMenu(tab ?? undefined).then(setMenu);
    void browser.runtime.sendMessage({ type: 'bridge-status' }).then((b) => setLive(!!(b as { connected?: boolean } | undefined)?.connected), () => {});
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
        <SiteCard host={host} site={r.site} interception={inter} />
        <Scripts state={menu} {...(tab ? { tab } : {})} reload={() => setN(n + 1)} />
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

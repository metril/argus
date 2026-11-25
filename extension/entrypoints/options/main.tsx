import { render } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import '../../ui/tokens.css';
import '../../ui/ui.css';
import { signOut } from '../../lib/auth';
import { listGrants, revokeGrant } from '../../lib/grants';
import { BrowserCard, Icon, SignInForm } from '../../ui/components';
import { hostLabel, isSignedIn, settings, watchSettings } from '../../ui/store';

type Step = 'done' | 'cur' | '';

function Steps({ signed, on, pinned }: { signed: boolean; on: boolean; pinned: boolean }) {
  const flags = [signed, on, pinned];
  const cur = flags.indexOf(false);
  const names = ['Sign in', 'Turn on', 'Pin'];
  return (
    <ol class="steps" aria-label="Setup">
      {names.map((n, i) => {
        const st: Step = flags[i] ? 'done' : i === cur ? 'cur' : '';
        return <li key={n} class={st}><b>{st === 'done' ? '✓' : i + 1}</b>{n}</li>;
      })}
    </ol>
  );
}

function Permissions({ url }: { url: string }) {
  const [granted, setGranted] = useState(true);
  const [grants, setGrants] = useState<string[]>([]);
  const load = async () => {
    setGrants(await listGrants(browser));
    try { setGranted(await browser.permissions.contains({ origins: [new URL(url).origin + '/*'] })); } catch { /* keep */ }
  };
  useEffect(() => { void load(); }, [url]);
  return (
    <section class="card">
      <h2>Permissions</h2>
      <div class="perms">
        <span class="mono">{hostLabel(url)}</span>
        {granted
          ? <span class="t-allow" style="color:var(--c);font-size:12px;font-weight:500">✓ Granted</span>
          : <button type="button" class="btn" onClick={() => void browser.permissions.request({ origins: [new URL(url).origin + '/*'] }).then(load)}>Allow</button>}
        {grants.map((g) => (
          <>
            <span key={g} class="mono">{g}</span>
            <button type="button" class="btn" onClick={() => void revokeGrant(browser, g).then(load)}>Revoke</button>
          </>
        ))}
      </div>
    </section>
  );
}

function App() {
  const s = settings.value;
  const [on, setOn] = useState(false);
  const [pinned, setPinned] = useState(false);
  const setup = location.hash === '#setup';
  useEffect(() => {
    void browser.runtime.sendMessage({ type: 'proxy-get' }).then((r) => setOn(!!(r as { state?: { enabled?: boolean } } | undefined)?.state?.enabled), () => {});
    void (browser.action as any).getUserSettings?.().then((u: { isOnToolbar?: boolean }) => setPinned(!!u?.isOnToolbar), () => {});
  }, [s?.token]);
  if (s === null) return null;
  const signed = isSignedIn(s);
  return (
    <div class="opts">
      <header>
        <span class="logo" style="color:var(--accent)"><Icon n="eye" size={24} sw={1.8} /></span>
        <span class="brand">Argus</span>
        <span class="mono muted" style="margin-left:auto">v{browser.runtime.getManifest().version}</span>
      </header>
      {setup && <Steps signed={signed} on={on} pinned={pinned} />}
      <section class="card">
        <h2>Account</h2>
        {signed ? (
          <div class="acc">
            <span class="dot t-allow" style="width:8px;height:8px;color:var(--c)" />
            <div>
              <div>{s.user && <b>{s.user}</b>}{s.user && ' · '}<span class="mono">{hostLabel(s.argusUrl)}</span></div>
              {s.since && <div class="muted" style="font-size:12px">Since {s.since.slice(0, 10)}</div>}
            </div>
            <button type="button" class="btn" onClick={() => void signOut()}>Sign out</button>
          </div>
        ) : <SignInForm wide />}
      </section>
      {signed && (
        <>
          <section class="card">
            <h2>This browser</h2>
            <BrowserCard sub="Filter this browser." />
          </section>
          <Permissions url={s.argusUrl} />
        </>
      )}
    </div>
  );
}

watchSettings();
window.addEventListener('hashchange', () => location.reload());
render(<App />, document.getElementById('app')!);

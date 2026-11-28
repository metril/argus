import { useEffect, useState } from 'preact/hooks';
import { clearSiteBypass, getSiteBypass, setSiteBypass, type Call, type Settings, type SiteBypass } from '../lib/api';
import { Icon } from './components';

/** What the row shows. `error` is a failed read; a failed change keeps the state and sets `note`. */
export type BypassView =
  | { k: 'loading' }
  | { k: 'ready'; s: SiteBypass }
  | { k: 'restricted' }
  | { k: 'scope' }
  | { k: 'error' };

export interface SiteBypassState { view: BypassView; busy: boolean; changed: boolean; note: string | undefined; retry: () => void; add: () => void; undo: () => void; reloaded: () => void }

const FAIL = 'Could not change this site. Try again.';

/** "Don't decrypt this site" for one host: reads the server's state, changes it, and remembers that a reload is due. */
export function useSiteBypass(settings: Settings, host: string): SiteBypassState {
  const [view, setView] = useState<BypassView>({ k: 'loading' });
  const [busy, setBusy] = useState(false);
  const [changed, setChanged] = useState(false);
  const [note, setNote] = useState<string>();
  const [n, setN] = useState(0);
  useEffect(() => {
    setView({ k: 'loading' }); setChanged(false); setNote(undefined);
    if (!host) return;
    const ac = new AbortController();
    void getSiteBypass(settings, host, ac.signal).then((r) => { if (!ac.signal.aborted) setView(fromRead(r)); });
    return () => ac.abort();
  }, [settings.argusUrl, settings.token, host, n]);
  const change = async (fn: typeof setSiteBypass) => {
    if (busy) return;
    setBusy(true); setNote(undefined);
    const r = await fn(settings, host);
    setBusy(false);
    if (r.ok) { setView({ k: 'ready', s: r.value }); setChanged(true); return; }
    if (r.restricted) setView({ k: 'restricted' });
    else if (r.scope) setView({ k: 'scope' });
    else setNote(r.message ?? FAIL);
  };
  return {
    view, busy, changed, note,
    retry: () => setN((x) => x + 1),
    add: () => void change(setSiteBypass),
    undo: () => void change(clearSiteBypass),
    reloaded: () => setChanged(false),
  };
}

function fromRead(r: Call<SiteBypass>): BypassView {
  if (r.ok) return { k: 'ready', s: r.value };
  if (r.restricted) return { k: 'restricted' };
  if (r.scope) return { k: 'scope' };
  return { k: 'error' };
}

/** Why a host that is not the extension's own entry is left alone, in a few words. */
export function reasonOf(s: SiteBypass): string {
  switch (s.source) {
    case 'category': return `${s.name ?? 'Argus'} category`;
    case 'subscription': return `${s.name ?? 'a'} list`;
    case 'manual': return `your Bypass list${s.name ? ` (${s.name})` : ''}`;
    case 'failsafe': return 'waiting for the Argus lists to load';
    default: return 'another entry';
  }
}

/** The row under the popup's action grid. Each state keeps to the row's reserved height. */
export function SiteBypassRow({ st, reload, onSignIn }: { st: SiteBypassState; reload: () => void; onSignIn: () => void }) {
  const { view, busy, changed, note } = st;
  const doReload = () => { reload(); st.reloaded(); };
  const err = note && <div class="note" role="status" data-testid="bypass-note">{note}</div>;
  let body;
  if (view.k === 'loading') body = <div class="sbp-sk" aria-hidden="true" data-testid="bypass-loading" />;
  else if (view.k === 'error') {
    body = <div class="note sbp-line" role="status" data-testid="bypass-error">Could not check this site. <button type="button" class="lnk" onClick={st.retry}>Retry</button></div>;
  } else if (view.k === 'restricted') {
    body = <div class="note sbp-line" role="status" data-testid="bypass-restricted">Not available for this profile.</div>;
  } else if (view.k === 'scope') {
    body = (
      <div class="note sbp-line" data-testid="bypass-scope"><span role="status">Sign in again to use this.</span> <button type="button" class="lnk" onClick={onSignIn}>Sign in</button></div>
    );
  } else {
    const s = view.s;
    const ext = s.source === 'extension' && s.removable;
    if (ext) {
      body = (
        <div class="banner t-pass sbr" data-testid="bypass-ext">
          <Icon n="info" size={16} />
          <span class="sbt" role="status">Not decrypted: Argus tunnels this site untouched.{changed && <> <button type="button" class="lnk" data-testid="bypass-reload" onClick={doReload}>Reload tab</button> to apply.</>}</span>
          <button type="button" class="btn" data-testid="bypass-undo" disabled={busy} onClick={st.undo}>Undo</button>
        </div>
      );
    } else if (s.bypassed) {
      body = (
        <div class="banner t-pass sbr" data-testid="bypass-other" title={s.name ?? undefined}>
          <Icon n="info" size={16} />
          <span class="sbt" role="status">Not decrypted: {reasonOf(s)}</span>
        </div>
      );
    } else if (changed) {
      body = (
        <div class="banner t-pass sbr" data-testid="bypass-undone">
          <Icon n="info" size={16} />
          <span class="sbt" role="status">Decrypting again. <button type="button" class="lnk" data-testid="bypass-reload" onClick={doReload}>Reload tab</button> to apply.</span>
        </div>
      );
    } else {
      body = (
        <>
          <button type="button" class="btn" data-testid="bypass-add" disabled={busy} onClick={st.add}>Don't decrypt this site</button>
          <div class="hint">Argus stops inspecting and filtering this site.</div>
        </>
      );
    }
  }
  return <div class="sbp" data-testid="site-bypass">{body}{err}</div>;
}

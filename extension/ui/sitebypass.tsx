import type { ComponentChildren } from 'preact';
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
type Tone = 'info' | 'warn';

/** The row's one-line banner: icon, text, then an optional 32px action at the right. */
function Note({ tone, testid, title, children, action }: { tone: Tone; testid: string; title?: string | undefined; children: ComponentChildren; action?: ComponentChildren }) {
  return (
    <div class={`banner ${tone === 'warn' ? 't-warn' : 't-pass'} sbr`} data-testid={testid} title={title}>
      <Icon n={tone === 'warn' ? 'warn' : 'info'} size={16} />
      <span class="sbt" role="status">{children}</span>
      {action}
    </div>
  );
}

const WHY = 'Argus stops inspecting and filtering this site.';

/** The row under the popup's action grid. Each state keeps to the row's reserved height. */
export function SiteBypassRow({ st, reload, onSignIn }: { st: SiteBypassState; reload: () => void; onSignIn: () => void }) {
  const { view, busy, changed, note } = st;
  const doReload = () => { reload(); st.reloaded(); };
  const err = note && <div class="note" role="status" data-testid="bypass-note">{note}</div>;
  let body;
  if (view.k === 'loading') body = <div class="sbp-sk" aria-hidden="true" data-testid="bypass-loading" />;
  else if (view.k === 'error') {
    body = <Note tone="warn" testid="bypass-error" action={<button type="button" class="btn" onClick={st.retry}>Retry</button>}>Could not check this site.</Note>;
  } else if (view.k === 'restricted') {
    body = <Note tone="info" testid="bypass-restricted">Your profile doesn't allow this.</Note>;
  } else if (view.k === 'scope') {
    body = <Note tone="warn" testid="bypass-scope" action={<button type="button" class="btn" onClick={onSignIn}>Sign in</button>}>Sign in again to use this.</Note>;
  } else {
    const s = view.s;
    const ext = s.source === 'extension' && s.removable;
    if (ext) {
      body = (
        <Note tone="info" testid="bypass-ext" action={<button type="button" class="btn" data-testid="bypass-undo" disabled={busy} onClick={st.undo}>Undo</button>}>
          Not decrypted. Argus passes this site through unfiltered.{changed && <> <button type="button" class="lnk" data-testid="bypass-reload" onClick={doReload}>Reload tab</button> to apply.</>}
        </Note>
      );
    } else if (s.bypassed) {
      body = <Note tone="info" testid="bypass-other" title={s.name ?? undefined}>Not decrypted: {reasonOf(s)}</Note>;
    } else if (changed) {
      body = (
        <Note tone="info" testid="bypass-undone">Decrypting again. <button type="button" class="lnk" data-testid="bypass-reload" onClick={doReload}>Reload tab</button> to apply.</Note>
      );
    } else {
      body = (
        <>
          <button type="button" class="btn" data-testid="bypass-add" title={WHY} aria-describedby="bypass-why" disabled={busy} onClick={st.add}>Don't decrypt this site</button>
          <span id="bypass-why" class="sr">{WHY}</span>
        </>
      );
    }
  }
  return <div class="sbp" data-testid="site-bypass">{body}{err}</div>;
}

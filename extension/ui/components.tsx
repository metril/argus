import type { ComponentChildren } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import { type ErrorKind } from '../lib/api';
import type { Route } from '../lib/route';
import { bannerCopy, issuerName, daysUntil, invalidReason, type Site } from '../lib/state';
import { statusKind, type Listener } from '../lib/proxy';
import { bundledUrl, normalizeUrl, signIn, useToken } from '../lib/auth';
import { fetchCert } from '../lib/api';
import type { MenuCommand, MenuGrant } from '../lib/bridge-types';
import { Icon } from './icons';
export { Icon };
import { hostLabel } from './store';

type Tone = 'allow' | 'block' | 'pass' | 'warn';

export function Header({ live, children }: { live?: boolean; children?: ComponentChildren }) {
  return (
    <header class="hdr">
      <span class="logo"><Icon n="eye" size={20} sw={1.8} /></span>
      <span class="brand">Argus</span>
      <span class="sp" />
      {live && <Chip tone="allow"><span class="dot" />Live</Chip>}
      {children}
    </header>
  );
}

export function Chip({ tone, icon, children }: { tone: Tone; icon?: Parameters<typeof Icon>[0]['n']; children: ComponentChildren }) {
  return <span class={`chip t-${tone}`}>{icon && <Icon n={icon} size={13} />}{children}</span>;
}

export function Banner({ tone = 'warn', title, body, action, onAction, slim }: {
  tone?: Tone; title: string; body?: string; action?: string; onAction?: () => void; slim?: boolean;
}) {
  return (
    <div role="alert" class={`banner t-${tone}${slim ? ' slim' : ''}`}>
      <Icon n={slim ? 'plug' : 'warn'} size={16} />
      <div style="flex:1;min-width:0">
        <div class="bt">{title}</div>
        {body && <div class="bb">{body}</div>}
      </div>
      {action && <button type="button" class="btn" onClick={onAction}>{action}</button>}
    </div>
  );
}

export function ErrorBanner({ error, host, refused, onAction }: { error: ErrorKind; host: string; refused?: boolean; onAction?: (a: 'retry' | 'allow' | 'switch') => void }) {
  const c = bannerCopy(error, host, refused);
  const label = { retry: 'Retry', allow: 'Allow', switch: 'Switch' } as const;
  return <Banner title={c.title} {...(c.body ? { body: c.body } : {})} {...(c.action && onAction ? { action: label[c.action], onAction: () => onAction(c.action!) } : {})} />;
}

export function Skeleton() { return <div class="skel" aria-hidden="true" />; }

export function CopyText({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <span class="copy">
      <code>{text}</code>
      <button type="button" class="ib" style="width:24px;height:24px" aria-label="Copy" onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1200); }, () => {});
      }}><Icon n={done ? 'check' : 'copy'} size={13} /></button>
    </span>
  );
}

export function Switch({ on, label, onChange }: { on: boolean; label: string; onChange: (v: boolean) => void }) {
  return <button type="button" role="switch" class="sw" aria-checked={on} aria-label={label} onClick={() => onChange(!on)} />;
}

const day = (iso: string) => iso.slice(0, 10);

export function CertDetails({ cert }: { cert: NonNullable<Extract<Site, { kind: 'cert' }>['cert']> }) {
  return (
    <dl>
      <dt>Subject</dt><dd class="mono">{cert.subject}</dd>
      <dt>Issuer</dt><dd class="mono">{cert.issuer}</dd>
      <dt>Valid</dt><dd class="mono">{day(cert.not_before)} to {day(cert.not_after)}</dd>
      <dt>SHA-256</dt><dd><CopyText text={cert.fp} /></dd>
      {cert.sans.length > 0 && <><dt>Names</dt><dd><CopyText text={cert.sans.join(', ')} /></dd></>}
    </dl>
  );
}

export function SiteCard({ host, site, route }: { host: string; site: Site; route?: Route | undefined }) {
  const [open, setOpen] = useState(false);
  if (site.kind === 'loading') return <Skeleton />;
  if (site.kind === 'none') {
    return (
      <section class="card dashed">
        <Icon n="ban" size={18} />
        <div><div style="font-weight:500">Not inspectable</div><div class="muted" style="font-size:12px">{site.reason === 'insecure' ? 'Not HTTPS' : 'Browser page'}</div></div>
      </section>
    );
  }
  const cert = site.kind === 'cert' ? site.cert : null;
  const bad = cert?.verdict === 'invalid';
  // The certificate is what Argus saw for the host; it describes this tab only when the tab's
  // traffic really went through Argus (the proxy's marker header, observed per tab).
  const direct = route === 'direct';
  const routeChip =
    direct ? <Chip tone="pass" icon="arrow">Direct, not intercepted</Chip>
    : route === 'system' ? <Chip tone="pass" icon="shield">Extension off, still intercepted via system proxy</Chip>
    : route === 'argus' ? <Chip tone={bad ? 'block' : 'allow'} icon={bad ? 'shieldX' : 'shield'}>Intercepted</Chip>
    : site.kind === 'unseen' ? <Chip tone="pass" icon="arrow">Not filtered</Chip>
    : cert ? <Chip tone="pass" icon="arrow">Reload to check</Chip>
    : null;
  const showCert = !!cert && !direct;
  return (
    <section class={`card${bad ? ' t-block' : ''}`}>
      <div class="host">{host}</div>
      <div class="chips">
        {routeChip}
        {showCert && (bad
          ? <Chip tone="block" icon="shieldX">Cert invalid</Chip>
          : <Chip tone="allow" icon="lock">{cert.ev ? 'Cert valid · EV' : 'Cert valid'}</Chip>)}
      </div>
      {showCert && bad && <div style="font-size:12px">{invalidReason(cert)}</div>}
      {showCert && cert && (
        <>
          <dl>
            <dt>Issuer</dt><dd class="mono">{issuerName(cert.issuer)}</dd>
            <dt>Expires</dt><dd class="mono">{day(cert.not_after)} · {daysUntil(cert.not_after)} days</dd>
          </dl>
          <button type="button" class="lnk" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? '▾' : '▸'} Details</button>
          {open && <CertDetails cert={cert} />}
        </>
      )}
    </section>
  );
}

/** Roving-tabindex list of userscript commands, grouped by script. */
export function CommandList({ commands, onTrigger }: { commands: MenuCommand[]; onTrigger: (c: MenuCommand) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const groups = new Map<string, MenuCommand[]>();
  for (const c of commands) groups.set(c.scriptName, [...(groups.get(c.scriptName) ?? []), c]);
  const move = (e: KeyboardEvent) => {
    const k = e.key === 'ArrowDown' ? 1 : e.key === 'ArrowUp' ? -1 : 0;
    if (!k || !ref.current) return;
    const rows = [...ref.current.querySelectorAll<HTMLButtonElement>('button.cmd')];
    const i = rows.indexOf(document.activeElement as HTMLButtonElement);
    rows[(i + k + rows.length) % rows.length]?.focus();
    e.preventDefault();
  };
  let first = true;
  return (
    <div ref={ref} onKeyDown={move} role="group" aria-label="Userscript commands">
      {[...groups].map(([name, cmds]) => (
        <div key={name}>
          <div class="grp">{name}</div>
          {cmds.map((c) => {
            const tab = first ? 0 : -1;
            first = false;
            return (
              <button type="button" key={c.script + c.cmd} class="row cmd" tabIndex={tab} {...(c.title ? { title: c.title } : {})}
                {...(c.accessKey ? { accessKey: c.accessKey, 'data-key': c.accessKey.toUpperCase() } : {})}
                onClick={() => onTrigger(c)}>
                <Icon n="play" /><span>{c.name}</span>
              </button>
            );
          })}
        </div>
      ))}
    </div>
  );
}

export function GrantRow({ grant, onAllow }: { grant: MenuGrant; onAllow: (g: MenuGrant) => void }) {
  return (
    <div class="grant">
      <Icon n="key" size={16} sw={1.8} />
      <span><b>{grant.scriptName}</b> wants your login for <span class="mono">{grant.host}</span></span>
      <button type="button" class="btn pri" onClick={() => onAllow(grant)}>Allow</button>
    </div>
  );
}

export function AccountBar({ user, url, onSignOut }: { user: string; url: string; onSignOut: () => void }) {
  return (
    <footer class="ftr">
      <span class="muted"><Icon n="user" /></span>
      <span class="muted">{user ? `${user} · ` : ''}<span class="mono">{hostLabel(url)}</span></span>
      <a class="sp" href={`${url}/`} target="_blank" rel="noreferrer" style="font-weight:500">Open ↗</a>
      <button type="button" class="ib" aria-label="Sign out" onClick={onSignOut}><Icon n="out" size={16} sw={1.8} /></button>
    </footer>
  );
}

type PState = { enabled: boolean; stores: Record<string, boolean> };
type PInfo = { state: PState; active: boolean; listener?: Listener; unreachable?: boolean; firefox: boolean };

/** "Use Argus" switch with a live status line; Firefox also lists containers. */
export function BrowserCard({ sub }: { sub?: string }) {
  const [info, setInfo] = useState<PInfo>();
  const [names, setNames] = useState<{ id: string; name: string }[]>([]);
  const [argus, setArgus] = useState('');
  useEffect(() => {
    void (async () => {
      try {
        setArgus(String((await browser.storage.local.get('argusUrl')).argusUrl ?? '').replace(/\/+$/, ''));
        const r = (await browser.runtime.sendMessage({ type: 'proxy-get' })) as PInfo | undefined;
        if (!r) return;
        setInfo(r);
        if (r.firefox) {
          const ids = (await (browser as any).contextualIdentities.query({})) as { cookieStoreId: string; name: string }[];
          setNames([{ id: 'firefox-default', name: 'No container' }, ...ids.map((c) => ({ id: c.cookieStoreId, name: c.name })), { id: 'firefox-private', name: 'Private windows' }]);
        }
      } catch { /* background not ready */ }
    })();
    // The status (connecting, on, unreachable) changes while the popup is open.
    const t = setInterval(() => {
      void browser.runtime.sendMessage({ type: 'proxy-get' }).then((r) => { if (r) setInfo(r as PInfo); }, () => {});
    }, 2000);
    return () => clearInterval(t);
  }, []);
  if (!info) return null;
  const save = async (state: PState) => {
    const n = (await browser.runtime.sendMessage({ type: 'proxy-set', state })) as PInfo | undefined;
    setInfo(n ? { ...info, ...n } : { ...info, state });
  };
  const st = info.state;
  const kind = statusKind(st.enabled, info.active, info.listener ?? 'pending', !!info.unreachable);
  const line = kind === 'blocked' ? "Argus unreachable: browsing is blocked until it's back" : kind === 'on' ? 'On · filtering this browser' : kind === 'connecting' ? 'Connecting…' : kind === 'unset' ? 'Not set up in Argus' : 'Off';
  return (
    <>
      <div class="sw-row">
        <span>Use Argus{sub && <div class="muted" style="font-size:12px">{sub}</div>}</span>
        <Switch on={st.enabled} label="Use Argus in this browser" onChange={(v) => void save({ ...st, enabled: v })} />
      </div>
      <div class="note" role="status" aria-live="polite">
        {line}
        {kind === 'blocked' && <> · <button type="button" class="link" onClick={() => void save({ ...st, enabled: false })}>Turn off proxy</button></>}
        {kind === 'unset' && argus && <> · <a href={`${argus}/extension`} target="_blank" rel="noreferrer">Set up</a></>}
      </div>
      {info.firefox && names.length > 0 && (
        <details class="cont">
          <summary>Containers</summary>
          {names.map((c) => (
            <label key={c.id}>
              <input type="checkbox" checked={st.stores[c.id] !== false} onChange={(e) => void save({ ...st, stores: { ...st.stores, [c.id]: (e.target as HTMLInputElement).checked } })} />
              {c.name}
            </label>
          ))}
        </details>
      )}
    </>
  );
}

/** Sign in with a password (default) or paste an API token. */
export function SignInForm({ expired, onDone, wide }: { expired?: boolean; onDone?: () => void; wide?: boolean }) {
  const [url, setUrl] = useState('');
  const [editUrl, setEditUrl] = useState(true);
  const [user, setUser] = useState('');
  const [pw, setPw] = useState('');
  const [tok, setTok] = useState('');
  const [show, setShow] = useState(false);
  const [tokenMode, setTokenMode] = useState(false);
  const [busy, setBusy] = useState(false);
  const [slow, setSlow] = useState(false);
  const [err, setErr] = useState<{ error: ErrorKind; refused?: boolean } | null>(expired ? { error: 'sessionExpired' } : null);

  useEffect(() => {
    void (async () => {
      const stored = String((await browser.storage.local.get('argusUrl')).argusUrl ?? '');
      const u = stored || (await bundledUrl());
      if (u) { setUrl(u); setEditUrl(false); }
    })();
  }, []);

  const submit = async (e?: Event) => {
    e?.preventDefault();
    if (busy) return;
    setBusy(true); setErr(null); setSlow(false);
    const t = setTimeout(() => setSlow(true), 8000);
    try {
      const r = tokenMode
        ? await useToken(url, tok, async (s) => {
            const l = await fetchCert(s, 'connection-test.invalid');
            return l.kind === 'error' ? l.error : null;
          })
        : await signIn(url, user.trim(), pw);
      if (r.ok) { setPw(''); onDone?.(); } else setErr({ error: r.error, ...('refused' in r && r.refused ? { refused: true } : {}) });
    } finally { clearTimeout(t); setBusy(false); setSlow(false); }
  };

  const host = hostLabel(normalizeUrl(url) ?? url);
  const act = async (a: 'retry' | 'allow' | 'switch') => {
    if (a === 'allow') { try { await browser.permissions.request({ origins: [new URL(normalizeUrl(url) ?? '').origin + '/*'] }); } catch { /* ignore */ } }
    if (a !== 'switch') void submit();
  };
  return (
    <form class="form" onSubmit={submit} style={wide ? 'padding:0' : ''}>
      {!wide && <h1>Sign in</h1>}
      {editUrl ? (
        <label class="fld"><span class="lbl">Argus address</span>
          <input class="in" type="text" inputMode="url" autocomplete="url" placeholder="argus.lan:8443" value={url} onInput={(e) => setUrl((e.target as HTMLInputElement).value)} required />
        </label>
      ) : (
        <div class="urlbox"><Icon n="globe" /><span class="mono">{host}</span>
          <button type="button" class="lnk" style="padding:0" onClick={() => setEditUrl(true)}>Change</button></div>
      )}
      {tokenMode ? (
        <label class="fld"><span class="lbl">API token</span>
          <input class="in" type="password" autocomplete="off" value={tok} onInput={(e) => setTok((e.target as HTMLInputElement).value)} required />
        </label>
      ) : (
        <>
          <label class="fld"><span class="lbl">Username</span>
            <input class="in" autocomplete="username" value={user} onInput={(e) => setUser((e.target as HTMLInputElement).value)} required />
          </label>
          <label class="fld"><span class="lbl">Password</span>
            <span class="pw">
              <input class="in" type={show ? 'text' : 'password'} autocomplete="current-password" value={pw} onInput={(e) => setPw((e.target as HTMLInputElement).value)} required />
              <button type="button" class="ib" aria-label={show ? 'Hide password' : 'Show password'} onClick={() => setShow(!show)}><Icon n="eye" size={16} sw={1.8} /></button>
            </span>
          </label>
        </>
      )}
      {err && <ErrorBanner error={err.error} host={host} {...(err.refused ? { refused: true } : {})} {...(err.error === 'unreachable' || err.error === 'noHostPermission' ? { onAction: (a: 'retry' | 'allow' | 'switch') => void act(a) } : {})} />}
      <button type="submit" class="btn pri big" disabled={busy}>
        {busy && <span class="spin" />}{busy ? 'Signing in…' : 'Sign in'}
      </button>
      {slow && <div class="muted" role="status" style="text-align:center;font-size:12px">Still trying…</div>}
      <button type="button" class="alt" onClick={() => { setTokenMode(!tokenMode); setErr(null); }}>{tokenMode ? 'Use a password' : 'Use an API token'}</button>
    </form>
  );
}

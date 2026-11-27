import { useEffect, useState } from 'preact/hooks';
import { fetchFilterStats, getSiteState, setSiteOff, type FilterStats, type Settings } from '../lib/api';
import { blockedTotal, percent, totalRequests, type TabStats } from '../lib/stats';
import { Banner, Switch } from './components';

const nf = (n: number) => n.toLocaleString('en-US');

/** "Blocked on this page": the count, its share of the page's requests, and each connected domain. */
export function PageStats({ stats }: { stats: TabStats | undefined }) {
  if (!stats) return null;
  const hosts = Object.entries(stats.hosts).sort((a, b) => b[1].blocked - a[1].blocked || b[1].allowed - a[1].allowed || a[0].localeCompare(b[0]));
  return (
    <section class="card" data-testid="page-stats">
      <div class="lbl">Blocked on this page</div>
      <div class="stat">
        <span class="big" data-testid="page-blocked">{nf(blockedTotal(stats))}</span>
        <span class="muted" data-testid="page-percent">{percent(stats)}% of {nf(totalRequests(stats))} requests</span>
      </div>
      {hosts.length > 0 && (
        <details class="cont">
          <summary>{hosts.length} domains connected</summary>
          <table class="hosts">
            <tbody>
              {hosts.map(([h, c]) => (
                <tr key={h} data-host={h}>
                  <td class="hn">{h}</td>
                  <td class={c.blocked ? 'bl' : 'muted'}>{c.blocked}</td>
                  <td class="muted">{c.allowed}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </section>
  );
}

/** Blocked since start and total requests, from the proxy. */
export function GlobalStats({ settings, onScope }: { settings: Settings; onScope: () => void }) {
  const [g, setG] = useState<FilterStats>();
  useEffect(() => {
    const ac = new AbortController();
    setG(undefined);
    void fetchFilterStats(settings, ac.signal).then((r) => {
      if (ac.signal.aborted) return;
      if (r.ok) setG(r.value); else if (r.scope) onScope();
    });
    return () => ac.abort();
  }, [settings.argusUrl, settings.token]);
  if (!g) return null;
  return (
    <section class="card" data-testid="global-stats">
      <div class="lbl">Since Argus started</div>
      <dl>
        <dt>Blocked</dt><dd data-testid="global-blocked">{nf(g.blocked_requests)}</dd>
        <dt>Total</dt><dd data-testid="global-total">{nf(g.total_requests)}</dd>
      </dl>
    </section>
  );
}

/** "Argus on this site": exceptions are per registrable domain; a reload applies the change. */
export function SiteSwitch({ settings, site, onScope, reload }: { settings: Settings; site: string; onScope: () => void; reload: () => void }) {
  const [off, setOff] = useState<boolean>();
  const [busy, setBusy] = useState(false);
  const [changed, setChanged] = useState(false);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    const ac = new AbortController();
    setOff(undefined); setChanged(false); setFailed(false);
    void getSiteState(settings, site, ac.signal).then((r) => {
      if (ac.signal.aborted) return;
      if (r.ok) setOff(r.value.disabled); else if (r.scope) onScope(); else setFailed(true);
    });
    return () => ac.abort();
  }, [settings.argusUrl, settings.token, site]);
  if (off === undefined && !failed) return null;
  const toggle = async (on: boolean) => {
    setBusy(true); setFailed(false);
    const r = await setSiteOff(settings, site, !on);
    setBusy(false);
    if (r.ok) { setOff(!on); setChanged(true); } else if (r.scope) onScope(); else setFailed(true);
  };
  return (
    <section class="sec" data-testid="site-switch">
      <div class="sw-row">
        <span>Argus on <b>{site}</b></span>
        {off !== undefined && <Switch on={!off} label={`Argus on ${site}`} onChange={(v) => { if (!busy) void toggle(v); }} />}
      </div>
      {failed && <div class="note">Could not change this site. Try again.</div>}
      {changed && (
        <div class="note">
          Saved. <button type="button" class="lnk" onClick={reload}>Reload this page</button>
        </div>
      )}
    </section>
  );
}

/** Shown when the stored token predates a scope: signing in again mints a complete one. */
export function ScopeNotice({ onSignIn }: { onSignIn: () => void }) {
  return (
    <Banner tone="warn" title="Sign in again to enable page stats and the site switch" action="Sign in" onAction={onSignIn} />
  );
}

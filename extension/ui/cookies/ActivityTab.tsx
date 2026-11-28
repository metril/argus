import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import type { ChangeEntry, ChangeKind } from '../../lib/cookiejar/changelog';
import { hostOfCookie, siteOfCookie } from '../../lib/cookiejar/model';
import { activitySource, type Provenance } from '../../lib/cookiejar/provenance';
import { errText, useClient } from './client';
import { Pill, targetValue, type PillKind } from './kit';

const MAX_SHOWN = 200;
const KIND: Record<ChangeKind, { kind: PillKind; l: string }> = {
  set: { kind: 'ok', l: 'Set' }, changed: { kind: 'info', l: 'Changed' }, removed: { kind: 'err', l: 'Removed' }, expired: { kind: 'warn', l: 'Expired' }, evicted: { kind: 'err', l: 'Evicted' },
};
const p2 = (n: number) => String(n).padStart(2, '0');
const clock = (at: number) => { const d = new Date(at); return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`; };

const MAX_KEPT = 2000;

/** Entries newest first. An entry completed later keeps its id and replaces itself in place; a new one goes on the front. */
function merge(cur: ChangeEntry[], add: ChangeEntry[]): ChangeEntry[] {
  let out = cur;
  for (const e of add) {
    const i = out.findIndex((x) => x.id === e.id);
    if (i >= 0) { out = out === cur ? [...cur] : out; out[i] = e; } else out = [e, ...out];
  }
  return out.length > MAX_KEPT ? out.slice(0, MAX_KEPT) : out;
}

export function ActivityTab({ prov }: { prov: Provenance | undefined }) {
  const client = useClient();
  const [entries, setEntries] = useState<ChangeEntry[]>([]);
  const [paused, setPaused] = useState(false);
  const [site, setSite] = useState('all');
  const [err, setErr] = useState('');
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  const load = () => client.call({ op: 'activity.since', since: 0 }).then((r) => { setEntries(merge([], [...r].sort((a, b) => a.id - b.id))); setErr(''); }, (e) => setErr(errText(e)));
  useEffect(() => { void load(); }, [client]);
  useEffect(() => client.onResync(() => { if (!pausedRef.current) void load(); }), [client]);
  useEffect(() => client.onActivity((e) => { if (!pausedRef.current) setEntries((cur) => merge(cur, [e])); }), [client]);

  const sites = useMemo(() => [...new Set(entries.map((e) => siteOfCookie(e.cookie)))].sort(), [entries]);
  const shown = useMemo(() => entries.filter((e) => site === 'all' || siteOfCookie(e.cookie) === site).slice(0, MAX_SHOWN), [entries, site]);
  const records = prov?.enabled ? prov.records : [];
  const provOn = !!prov?.enabled;
  const resume = () => { setPaused(false); void load(); };

  return (
    <>
      <div class="toolbar">
        <select class="select" aria-label="Filter by site" value={site} onChange={(e) => setSite(targetValue(e))}>
          <option value="all">All sites</option>
          {sites.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <span class="muted lgd">A live record of cookies being set, changed, removed or expiring in this browser.</span>
        <span class="tbr">
          <span class="dim" role="status" data-testid="activity-state">{paused ? 'Paused' : 'Live'}</span>
          <button type="button" class="btn" aria-pressed={paused} onClick={() => (paused ? resume() : setPaused(true))}>{paused ? 'Resume' : 'Pause'}</button>
        </span>
      </div>
      {err && <div class="banner err" role="alert"><span class="bt">{err}</span></div>}
      <div class="cm-body tbl">
        <div class="tw">
          <table class="t actv" data-testid="activity-table" aria-label="Cookie activity">
            <colgroup><col style="width:96px" /><col style="width:110px" /><col style="width:22%" /><col style="width:22%" /><col /></colgroup>
            <thead><tr><th>Time</th><th>Change</th><th>Cookie</th><th>Site</th><th>Source</th></tr></thead>
            <tbody>
              {shown.map((e) => {
                const src = provOn ? activitySource(e.kind, e.cookie.name, hostOfCookie(e.cookie), e.at, records) : '';
                return (
                  <tr key={e.id}>
                    <td class="mono">{clock(e.at)}</td>
                    <td><Pill kind={KIND[e.kind].kind}>{KIND[e.kind].l}</Pill></td>
                    <td class="mono" title={e.cookie.name}>{e.cookie.name}</td>
                    <td title={siteOfCookie(e.cookie)}>{siteOfCookie(e.cookie)}</td>
                    <td {...(provOn ? { title: src } : {})}>{provOn ? src : <span class="dim" title="Turn on cookie provenance to see sources">Provenance off</span>}</td>
                  </tr>
                );
              })}
              {shown.length === 0 && <tr><td colSpan={5} class="empty muted">No cookie activity yet. Browse a site and changes will appear here.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

import { useEffect, useState } from 'preact/hooks';
import { CATEGORIES, CATEGORY_LABELS, fetchFilterStats, fetchTimeseries, getSiteState, setSiteOff, type FilterStats, type Series, type SeriesRange, type Settings } from '../lib/api';
import { chartData, type CategoryPick } from '../lib/chart';
import { blockedTotal, percent, registrableDomain, totalRequests, type TabStats } from '../lib/stats';
import { isThirdParty } from '../lib/siterules';
import { GridToggle, type SiteRules } from './siterules';
import { Banner, Switch } from './components';
import { Segmented } from './cookies/kit';

const nf = (n: number) => n.toLocaleString('en-US');

/** "On this page": the blocked count, its share of the page's requests, and each connected domain. `bare` drops the card (it sits inside the site card). */
export function PageStats({ stats, site, sr, bare }: { stats: TabStats | undefined; site?: string; sr?: SiteRules; bare?: boolean }) {
  if (!stats) return null;
  const hosts = Object.entries(stats.hosts).sort((a, b) => b[1].blocked - a[1].blocked || b[1].allowed - a[1].allowed || a[0].localeCompare(b[0]));
  const body = (
    <>
      <dl class="pdl">
        <dt>Blocked</dt><dd data-testid="page-blocked">{nf(blockedTotal(stats))}</dd>
        <dt>Share of requests</dt><dd data-testid="page-percent">{percent(stats)}% of {nf(totalRequests(stats))} requests</dd>
      </dl>
      {hosts.length > 0 && (
        <details class="cont">
          <summary data-testid="domains-summary">{hosts.filter(([, c]) => c.blocked > 0).length} of {hosts.length} domains blocked</summary>
          <table class="hosts">
            <tbody>
              {hosts.map(([h, c]) => (
                <tr key={h} data-host={h}>
                  <td class="hn">{h}</td>
                  <td class={c.blocked ? 'bl' : 'muted'}>{c.blocked}</td>
                  <td class="muted">{c.allowed}</td>
                  {sr && site && <td>{isThirdParty(h, site, registrableDomain) && <GridToggle host={h} site={site} sr={sr} />}</td>}
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </>
  );
  return bare
    ? <div class="pbare" data-testid="page-stats">{body}</div>
    : <section class="card" data-testid="page-stats"><div class="lbl">On this page</div>{body}</section>;
}

const RANGES: { id: SeriesRange; label: string }[] = [{ id: 'd7', label: '7 days' }, { id: 'd30', label: '30 days' }, { id: 'm12', label: '12 months' }];

/** Line chart of blocked requests over time (inline SVG), for one category or all. */
export function BlockedChart({ series, range, cat }: { series: Series | undefined; range: SeriesRange; cat: CategoryPick }) {
  if (!series) return <div class="note">Loading</div>;
  const W = 320, H = 90;
  const d = chartData(series.points, cat, range, W, H);
  return (
    <svg class="chart" viewBox={`0 0 ${W} ${H + 14}`} role="img" aria-label={`Blocked requests: ${nf(d.total)}`} data-testid="chart">
      <path d={d.path} />
      {d.labels.map((l) => <text key={l.x} class="ax" x={l.x} y={H + 11} text-anchor={l.x < 20 ? 'start' : l.x > W - 20 ? 'end' : 'middle'}>{l.text}</text>)}
    </svg>
  );
}

/** "Statistics" view: blocked since install and by category (a two-column grid), and the trend over time. */
export function StatsView({ settings, onScope }: { settings: Settings; onScope: () => void }) {
  const [g, setG] = useState<FilterStats>();
  const [range, setRange] = useState<SeriesRange>('d7');
  const [cat, setCat] = useState<CategoryPick>('all');
  const [series, setSeries] = useState<Series>();
  useEffect(() => {
    const ac = new AbortController();
    setG(undefined);
    void fetchFilterStats(settings, ac.signal).then((r) => {
      if (ac.signal.aborted) return;
      if (r.ok) setG(r.value); else if (r.scope) onScope();
    });
    return () => ac.abort();
  }, [settings.argusUrl, settings.token]);
  useEffect(() => {
    const ac = new AbortController();
    setSeries(undefined);
    void fetchTimeseries(settings, range, ac.signal).then((r) => { if (!ac.signal.aborted && r.ok) setSeries(r.value); });
    return () => ac.abort();
  }, [settings.argusUrl, settings.token, range]);
  if (!g) return null;
  const blocked = g.lifetime_blocked ?? g.blocked_requests;
  const total = g.lifetime_total ?? g.total_requests;
  const by = g.lifetime_by_category;
  return (
    <>
      <section class="card" data-testid="global-stats">
        <div class="lbl">Since install</div>
        <dl class="pdl" data-testid="categories">
          <dt>Blocked</dt><dd data-testid="global-blocked">{nf(blocked)}</dd>
          <dt>Requests</dt><dd data-testid="global-total">{nf(total)}</dd>
          {by && CATEGORIES.map((c) => [<dt key={`t${c}`}>{CATEGORY_LABELS[c]}</dt>, <dd key={`d${c}`} data-cat={c}>{nf(by[c] ?? 0)}</dd>])}
        </dl>
      </section>
      <section class="card" data-testid="chart-card">
        <Segmented<SeriesRange> label="Range" cls="wide" value={range} onChange={setRange} options={RANGES.map((r) => ({ v: r.id, l: r.label }))} />
        <div class="chart-bar">
          <select class="in" aria-label="Category" value={cat} onChange={(e) => setCat((e.target as HTMLSelectElement).value as CategoryPick)}>
            <option value="all">All</option>
            {CATEGORIES.map((c) => <option key={c} value={c}>{CATEGORY_LABELS[c]}</option>)}
          </select>
        </div>
        <BlockedChart series={series} range={range} cat={cat} />
      </section>
    </>
  );
}

export interface SiteSwitchState { off: boolean | undefined; busy: boolean; changed: boolean; failed: boolean; toggle: (on: boolean) => void }

/** Per-site exception state: exceptions are per registrable domain; a reload applies the change. */
export function useSiteSwitch(settings: Settings, site: string, onScope: () => void): SiteSwitchState {
  const [off, setOff] = useState<boolean>();
  const [busy, setBusy] = useState(false);
  const [changed, setChanged] = useState(false);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    const ac = new AbortController();
    setOff(undefined); setChanged(false); setFailed(false);
    if (!site) return;
    void getSiteState(settings, site, ac.signal).then((r) => {
      if (ac.signal.aborted) return;
      if (r.ok) setOff(r.value.disabled); else if (r.scope) onScope(); else setFailed(true);
    });
    return () => ac.abort();
  }, [settings.argusUrl, settings.token, site]);
  const toggle = async (on: boolean) => {
    if (busy) return;
    setBusy(true); setFailed(false);
    const r = await setSiteOff(settings, site, !on);
    setBusy(false);
    if (r.ok) { setOff(!on); setChanged(true); } else if (r.scope) onScope(); else setFailed(true);
  };
  return { off, busy, changed, failed, toggle: (on) => void toggle(on) };
}

/** "On this site" with its switch, for the site card's header. */
export function SiteToggle({ site, st }: { site: string; st: SiteSwitchState }) {
  if (st.off === undefined) return null;
  return (
    <label class="tog" data-testid="site-switch">
      On this site
      <Switch on={!st.off} label={`Argus on ${site}`} onChange={st.toggle} />
    </label>
  );
}

/** What happened after a change, below the card's header. */
export function SiteNotes({ st, reload }: { st: SiteSwitchState; reload: () => void }) {
  if (!st.failed && !st.changed) return null;
  return (
    <>
      {st.failed && <div class="note">Could not change this site. Try again.</div>}
      {st.changed && <div class="note" role="status">Saved. <button type="button" class="lnk" onClick={reload}>Reload this page</button></div>}
    </>
  );
}

/** Shown when the stored token predates a scope: signing in again mints a complete one. */
export function ScopeNotice({ onSignIn }: { onSignIn: () => void }) {
  return (
    <Banner tone="warn" title="Sign in again to enable page stats and the site switch" action="Sign in" onAction={onSignIn} />
  );
}

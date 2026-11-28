import { useEffect, useState } from 'preact/hooks';
import { CATEGORIES, CATEGORY_LABELS, fetchFilterStats, fetchTimeseries, getSiteState, setSiteOff, type FilterStats, type Series, type SeriesRange, type Settings } from '../lib/api';
import { chartData, type CategoryPick } from '../lib/chart';
import { blockedTotal, percent, registrableDomain, totalRequests, type TabStats } from '../lib/stats';
import { isThirdParty } from '../lib/siterules';
import { GridToggle, type SiteRules } from './siterules';
import { Banner, Switch } from './components';

const nf = (n: number) => n.toLocaleString('en-US');

/** "Blocked on this page": the count, its share of the page's requests, and each connected domain. */
export function PageStats({ stats, site, sr }: { stats: TabStats | undefined; site?: string; sr?: SiteRules }) {
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
    </section>
  );
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

/** "Statistics" view: blocked since install, by category, and over time. */
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
        <div class="lbl">Blocked since install</div>
        <div class="stat"><span class="big" data-testid="global-blocked">{nf(blocked)}</span><span class="muted" data-testid="global-total">of {nf(total)} requests</span></div>
        {by && (
          <table class="cats" data-testid="categories">
            <tbody>{CATEGORIES.map((c) => <tr key={c}><td>{CATEGORY_LABELS[c]}</td><td data-cat={c}>{nf(by[c] ?? 0)}</td></tr>)}</tbody>
          </table>
        )}
      </section>
      <section class="card" data-testid="chart-card">
        <div class="seg" role="group" aria-label="Range">
          {RANGES.map((r) => <button key={r.id} type="button" aria-pressed={range === r.id} onClick={() => setRange(r.id)}>{r.label}</button>)}
        </div>
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

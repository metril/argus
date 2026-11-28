import { useCallback, useEffect, useState } from 'preact/hooks';
import { fetchSiteRules, postExtRule, type Settings } from '../lib/api';
import { gridState, resetSite, setGridState, type GridState, type SiteRule } from '../lib/siterules';

export interface SiteRules {
  rules: SiteRule[] | undefined;
  failed: boolean;
  post(op: 'add' | 'remove', rule: string): Promise<{ ok: boolean }>;
  set(rules: SiteRule[]): void;
  reload(): void;
}

/** The custom rules that mention this site (`GET /ext/rules?site=`), shared by the grid and the rules card. */
export function useSiteRules(settings: Settings | null, site: string, onScope: () => void): SiteRules {
  const [rules, setRules] = useState<SiteRule[]>();
  const [failed, setFailed] = useState(false);
  const [n, setN] = useState(0);
  useEffect(() => {
    setRules(undefined); setFailed(false);
    if (!settings || !site) return;
    let alive = true;
    void fetchSiteRules(settings, site).then((r) => {
      if (!alive) return;
      if (r.ok) setRules(r.value.rules); else { setFailed(true); if (r.scope) onScope(); }
    });
    return () => { alive = false; };
  }, [settings?.argusUrl, settings?.token, site, n]);
  const post = useCallback(async (op: 'add' | 'remove', rule: string) => {
    if (!settings) return { ok: false };
    const r = await postExtRule(settings, op, rule);
    if (!r.ok && r.scope) onScope();
    return { ok: r.ok };
  }, [settings?.argusUrl, settings?.token]);
  return { rules, failed, post, set: setRules, reload: () => setN((x) => x + 1) };
}

const LABELS: [GridState, string][] = [['block', 'Block'], ['default', 'Default'], ['allow', 'Allow']];

/** Block / default / allow for one third-party host on this site (`||host^$domain=site`). */
export function GridToggle({ host, site, sr }: { host: string; site: string; sr: SiteRules }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(false);
  if (!sr.rules) return null;
  const cur = gridState(sr.rules.map((x) => x.rule), host, site);
  const pick = async (next: GridState) => {
    if (busy || next === cur) return;
    setBusy(true); setErr(false);
    const out = await setGridState(sr.post, sr.rules!, host, site, next);
    setBusy(false);
    if (out) sr.set(out); else { setErr(true); sr.reload(); }
  };
  return (
    <span class="grid" role="group" aria-label={`Rule for ${host}`} data-testid="grid">
      {LABELS.map(([v, t]) => <button key={v} type="button" class="lnk" data-state={v} aria-pressed={cur === v} disabled={busy} onClick={() => void pick(v)}>{t}</button>)}
      {err && <span class="note">failed</span>}
    </span>
  );
}

/** "Your rules on this site": each can be removed; "Reset" removes them all. */
export function SiteRulesCard({ site, sr }: { site: string; sr: SiteRules }) {
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [left, setLeft] = useState(0);
  if (!sr.rules || sr.rules.length === 0) return null;
  const remove = async (rule: string) => {
    setBusy(true);
    const r = await sr.post('remove', rule);
    setBusy(false);
    if (r.ok) sr.set(sr.rules!.filter((x) => x.rule !== rule)); else sr.reload();
  };
  const reset = async () => {
    setBusy(true);
    const rest = await resetSite(sr.post, sr.rules!, site);
    setBusy(false); setConfirm(false); setLeft(rest.length);
    sr.set(rest); sr.reload();
  };
  return (
    <section class="card" data-testid="site-rules">
      <div class="lbl">Your rules on {site}</div>
      <ul class="rules">
        {sr.rules.map((r) => (
          <li key={r.rule}><code>{r.rule}</code><button type="button" class="lnk" disabled={busy} aria-label={`Remove ${r.rule}`} onClick={() => void remove(r.rule)}>Remove</button></li>
        ))}
      </ul>
      {left > 0 && <div class="note">{left} rule{left === 1 ? '' : 's'} could not be removed here.</div>}
      {confirm
        ? <div class="note">Remove all {sr.rules.length} rules for {site}? <button type="button" class="lnk" data-testid="reset-yes" disabled={busy} onClick={() => void reset()}>Yes, reset</button> <button type="button" class="lnk" onClick={() => setConfirm(false)}>Cancel</button></div>
        : <button type="button" class="btn" data-testid="reset-site" onClick={() => setConfirm(true)}>Reset all rules for this site</button>}
    </section>
  );
}

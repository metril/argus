import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { postExtRule, type LogEntry } from '../lib/api';
import { applyFilters, exportText, noFilters, statusLabel, STATUS_KEYS, STATUS_LABELS, TYPE_KEYS, TYPE_LABELS, typeKey, type Filters, type Party, type StatusKey, type TypeKey } from '../lib/logfilter';
import type { LogRow } from '../lib/logs';
import { makeRule, type RuleOptions } from '../lib/rulegen';
import { hostnameOf, registrableDomain } from '../lib/stats';
import { settings } from './store';

const MAX_SHOWN = 1000;
type TabInfo = { id: number; title: string; url: string };

const tabFromHash = () => { const m = /tab=(\d+)/.exec(location.hash); return m ? Number(m[1]) : undefined; };
const timeOf = (iso: string) => { const d = new Date(iso); return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString([], { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0'); };

function toggled<T>(set: ReadonlySet<T>, v: T): Set<T> { const n = new Set(set); if (n.has(v)) n.delete(v); else n.add(v); return n; }

function Chip({ on, children, onClick }: { on: boolean; children: preact.ComponentChildren; onClick: () => void }) {
  return <button type="button" class={`fchip${on ? ' on' : ''}`} aria-pressed={on} onClick={onClick}>{children}</button>;
}

export function Logger() {
  const [tabs, setTabs] = useState<TabInfo[]>([]);
  const [tabId, setTabId] = useState<number | undefined>(tabFromHash());
  const [rows, setRows] = useState<LogRow[]>([]);
  const [filters, setFilters] = useState<Filters>(noFilters());
  const [paused, setPaused] = useState(false);
  const [picked, setPicked] = useState<LogRow>();
  const [copied, setCopied] = useState(false);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const tabRef = useRef(tabId);
  tabRef.current = tabId;

  useEffect(() => {
    let alive = true;
    const read = () => void browser.tabs.query({}).then((ts) => {
      if (!alive) return;
      const list = ts.filter((t) => t.id !== undefined && /^https?:/.test(t.url ?? '')).map((t) => ({ id: t.id!, title: t.title ?? '', url: t.url ?? '' }));
      setTabs(list);
      setTabId((cur) => cur ?? list[0]?.id);
    });
    read();
    const evs = [browser.tabs.onUpdated, browser.tabs.onCreated, browser.tabs.onRemoved] as any[];
    for (const e of evs) e?.addListener(read);
    return () => { alive = false; for (const e of evs) e?.removeListener(read); };
  }, []);

  // History of the chosen tab, then live rows over a port while the page is open.
  const load = (id: number) => void browser.runtime.sendMessage({ type: 'log-rows', tabId: id }).then((r) => {
    if (tabRef.current === id) setRows(((r as { rows?: LogRow[] } | undefined)?.rows ?? []).slice(-MAX_SHOWN));
  }, () => {});
  useEffect(() => { if (tabId === undefined) return; setRows([]); load(tabId); }, [tabId]);
  useEffect(() => {
    const port = browser.runtime.connect({ name: 'logger' });
    port.onMessage.addListener((m: { t?: string; rows?: LogRow[] }) => {
      if (m?.t !== 'rows' || pausedRef.current) return;
      const mine = (m.rows ?? []).filter((r) => r.tabId === tabRef.current);
      if (mine.length) setRows((cur) => [...cur, ...mine].slice(-MAX_SHOWN));
    });
    return () => port.disconnect();
  }, []);

  const shown = useMemo(() => applyFilters(rows, filters).slice().reverse(), [rows, filters]);
  const set = (f: Partial<Filters>) => setFilters((cur) => ({ ...cur, ...f }));
  const resume = () => { setPaused(false); if (tabId !== undefined) load(tabId); };
  const clear = () => { setRows([]); if (tabId !== undefined) void browser.runtime.sendMessage({ type: 'log-clear', tabId }).catch(() => {}); };
  const copy = () => void navigator.clipboard.writeText(exportText(shown.slice().reverse())).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); }, () => {});

  return (
    <div class="lg">
      <header class="lg-bar">
        <span class="brand">Argus logger</span>
        <select class="in lg-tab" aria-label="Tab" value={tabId ?? ''} onChange={(e) => setTabId(Number((e.target as HTMLSelectElement).value))}>
          {tabs.map((t) => <option key={t.id} value={t.id}>{(t.title || t.url).slice(0, 80)}</option>)}
          {tabId !== undefined && !tabs.some((t) => t.id === tabId) && <option value={tabId}>Tab {tabId}</option>}
        </select>
        <input class="in lg-search" type="search" placeholder="Search URL, rule, list" aria-label="Search" value={filters.search} onInput={(e) => set({ search: (e.target as HTMLInputElement).value })} />
        <button type="button" class="btn" onClick={() => (paused ? resume() : setPaused(true))}>{paused ? 'Resume' : 'Pause'}</button>
        <button type="button" class="btn" onClick={clear}>Clear</button>
        <button type="button" class="btn" onClick={copy}>{copied ? 'Copied' : 'Copy as text'}</button>
      </header>
      <div class="lg-chips" role="group" aria-label="Filters">
        {(['all', 'first', 'third'] as Party[]).map((p) => <Chip key={p} on={filters.party === p} onClick={() => set({ party: p })}>{p === 'all' ? 'Any party' : p === 'first' ? 'First-party' : 'Third-party'}</Chip>)}
        <span class="sepv" />
        {STATUS_KEYS.map((k: StatusKey) => <Chip key={k} on={filters.status.has(k)} onClick={() => set({ status: toggled(filters.status, k) })}>{STATUS_LABELS[k]}</Chip>)}
        <span class="sepv" />
        {TYPE_KEYS.map((k: TypeKey) => <Chip key={k} on={filters.types.has(k)} onClick={() => set({ types: toggled(filters.types, k) })}>{TYPE_LABELS[k]}</Chip>)}
      </div>
      {!settings.value?.token && <div class="note">Sign in from the extension popup to see the log.</div>}
      <div class="lg-scroll">
        <table class="lg-tbl" data-testid="log-table">
          <thead><tr><th>Time</th><th>Status</th><th>URL</th><th>Type</th><th>Rule</th><th>List</th></tr></thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.seq} class={`o-${r.outcome}`} tabIndex={0} onClick={() => setPicked(r)} onKeyDown={(e) => { if (e.key === 'Enter') setPicked(r); }}>
                <td class="mono">{timeOf(r.time)}</td>
                <td><span class={`st st-${r.outcome}`}>{statusLabel(r)}</span>{r.user_rule && <span class="st st-user">user</span>}</td>
                <td class="mono u" title={r.url}>{r.url}{r.third_party === true && <span class="tp"> 3p</span>}</td>
                <td>{TYPE_LABELS[typeKey(r.type)]}</td>
                <td class="mono u" title={r.rule ?? ''}>{r.rule ?? ''}</td>
                <td class="u">{r.list_name ?? r.list_id ?? ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {shown.length === 0 && <div class="note">{rows.length ? 'No request matches the filters.' : 'No requests logged for this tab yet. Reload the page.'}</div>}
      </div>
      {picked && <RuleDialog row={picked} onClose={() => setPicked(undefined)} />}
    </div>
  );
}

const rowSite = (e: LogEntry) => registrableDomain(e.source_host || hostnameOf(e.url));

export function RuleDialog({ row, onClose }: { row: LogEntry; onClose: () => void }) {
  const [opts, setOpts] = useState<RuleOptions>({
    action: row.outcome === 'allowed' ? 'block' : 'unblock', scope: 'site', match: 'host',
    thirdParty: row.third_party === true, important: false, site: rowSite(row),
  });
  const generated = makeRule(row.url, opts);
  const [text, setText] = useState(generated);
  const [edited, setEdited] = useState(false);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (!edited) setText(generated); }, [generated, edited]);
  const upd = (o: Partial<RuleOptions>) => { setEdited(false); setOpts((c) => ({ ...c, ...o })); };

  const send = async (op: 'add' | 'remove', rule: string) => {
    const s = settings.value;
    if (!s) return;
    setBusy(true); setMsg('');
    const r = await postExtRule(s, op, rule);
    setBusy(false);
    if (r.ok) setMsg(r.value.changed ? `${op === 'add' ? 'Saved' : 'Removed'}. ${r.value.rule_count} custom rules. Reload the page to apply.` : 'No change: the rule was already so.');
    else if (r.scope) setMsg('Sign in again from the popup to allow creating rules.');
    else setMsg(r.status === 400 ? `Argus rejected this rule: ${r.message ?? 'it is not an accepted rule.'}` : 'Could not save. Try again.');
  };
  const Radio = <K extends 'action' | 'scope' | 'match'>(k: K, v: RuleOptions[K], label: string) => (
    <label><input type="radio" name={k} checked={opts[k] === v} onChange={() => upd({ [k]: v } as Partial<RuleOptions>)} /> {label}</label>
  );
  return (
    <div class="dlg-scrim" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div class="dlg" role="dialog" aria-modal="true" aria-label="Create rule" data-testid="rule-dialog">
        <h2>Create a rule</h2>
        <div class="mono u2">{row.url}</div>
        <fieldset><legend class="lbl">Action</legend>{Radio('action', 'block', 'Block')}{Radio('action', 'unblock', 'Unblock (exception)')}</fieldset>
        <fieldset><legend class="lbl">Scope</legend>{Radio('scope', 'site', `Only on ${opts.site || 'this site'}`)}{Radio('scope', 'everywhere', 'Everywhere')}</fieldset>
        <fieldset><legend class="lbl">Match</legend>{Radio('match', 'url', 'Exact URL')}{Radio('match', 'path', 'Path prefix')}{Radio('match', 'host', 'Whole host')}</fieldset>
        <fieldset>
          <label><input type="checkbox" checked={opts.thirdParty} onChange={(e) => upd({ thirdParty: (e.target as HTMLInputElement).checked })} /> Third-party only</label>
          <label><input type="checkbox" checked={opts.important} onChange={(e) => upd({ important: (e.target as HTMLInputElement).checked })} /> Important</label>
        </fieldset>
        <label class="fld"><span class="lbl">Rule</span>
          <input class="in mono" aria-label="Rule text" value={text} onInput={(e) => { setEdited(true); setText((e.target as HTMLInputElement).value); }} />
        </label>
        {msg && <div class="note" role="status">{msg}</div>}
        <div class="dlg-act">
          {row.user_rule && row.rule && <button type="button" class="btn" disabled={busy} onClick={() => void send('remove', row.rule!)}>Remove the matching rule</button>}
          <span class="sp" />
          <button type="button" class="btn" onClick={onClose}>Close</button>
          <button type="button" class="btn pri" disabled={busy || !text.trim()} onClick={() => void send('add', text.trim())}>Add rule</button>
        </div>
      </div>
    </div>
  );
}

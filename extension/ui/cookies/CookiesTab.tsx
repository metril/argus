import { useMemo, useRef, useState } from 'preact/hooks';
import { HISTORY_NOTE, type Provenance } from '../../lib/cookiejar/provenance';
import { Icon } from '../icons';
import { errText, useClient, type ListedCookie } from './client';
import { useCookieData, useRows } from './data';
import { Drawer } from './Drawer';
import { ExportDialog } from './ExportDialog';
import { ImportDialog } from './ImportDialog';
import { Confirm, Segmented, toast } from './kit';
import { byDomainName, CHIPS, inSite, matches, type ChipKey, type Filters, type Row } from './model';
import { CookieTable } from './Table';

export type Scope = 'site' | 'all';

export function CookiesTab({ site, scope, onScope, filters, onFilters, prov }: {
  site: string; scope: Scope; onScope: (s: Scope) => void; filters: Filters; onFilters: (f: Filters) => void; prov: Provenance | undefined;
}) {
  const client = useClient();
  const data = useCookieData();
  const scoped = useMemo(() => (scope === 'site' && site ? data.cookies.filter((c) => inSite(c, site)) : data.cookies), [data.cookies, scope, site]);
  const base = useRows(scoped, prov);
  const sorted = useMemo(() => [...base].sort(byDomainName), [base]);
  const rows = useMemo(() => sorted.filter((r) => matches(r, filters, site)), [sorted, filters, site]);
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [revealed, setRevealed] = useState<ReadonlySet<string>>(new Set());
  const [open, setOpen] = useState<{ row?: Row } | null>(null);
  const [dialog, setDialog] = useState<'export' | 'import' | null>(null);
  const [exportSel, setExportSel] = useState(false);
  const scroller = useRef<HTMLDivElement>(null);
  const provOn = !!prov?.enabled;

  // Bulk actions act on rows that are both selected and shown now; the count and the header tick agree.
  const picked = useMemo(() => rows.filter((r) => selected.has(r.key) && !r.stripped), [rows, selected]);
  const n = picked.length;

  const toggle = (k: string, on: boolean) => setSelected((s) => { const x = new Set(s); if (on) x.add(k); else x.delete(k); return x; });
  const toggleAll = (on: boolean) => setSelected((s) => { const x = new Set(s); for (const r of rows) if (!r.stripped) { if (on) x.add(r.key); else x.delete(r.key); } return x; });
  const reveal = (k: string) => setRevealed((s) => { const x = new Set(s); if (x.has(k)) x.delete(k); else x.add(k); return x; });
  const setChip = (k: ChipKey) => {
    const chips = new Set(filters.chips);
    if (chips.has(k)) chips.delete(k);
    else if (k === 'stripped') { chips.clear(); chips.add(k); } else { chips.delete('stripped'); chips.add(k); }
    onFilters({ ...filters, chips });
  };

  const undelete = (cookies: ListedCookie[]) => async () => {
    let ok = 0;
    for (const c of cookies) { try { await client.call({ op: 'create', cookie: c }); ok++; } catch { /* skip */ } }
    toast(`Restored ${ok} cookie${ok === 1 ? '' : 's'}`);
    void data.reload();
  };
  const deleteSelected = async () => {
    const cookies = picked.map((r) => r.c);
    try {
      const res = await client.call({ op: 'removeMany', cookies });
      const kept = res.skipped.length;
      toast(`Deleted ${res.done.length} cookie${res.done.length === 1 ? '' : 's'}${kept ? `, kept ${kept} protected` : ''}${res.failed.length ? `, ${res.failed.length} failed` : ''}`, res.done.length ? undelete(res.done as ListedCookie[]) : undefined);
      setSelected(new Set());
    } catch (e) { toast(errText(e)); }
    void data.reload();
  };
  const allProtected = n > 0 && picked.every((r) => r.c.isProtected);
  const protect = async () => {
    try {
      await client.call({ op: 'rules.protect', cookies: picked.map((r) => r.c), protect: !allProtected });
      toast(allProtected ? 'No longer protected' : 'Protected from auto-delete');
      setSelected(new Set());
    } catch (e) { toast(errText(e)); }
    void data.reload();
  };

  const stores = data.stores;
  const defaultStore = stores.find((s) => s.kind === 'default')?.id ?? stores[0]?.id ?? '';
  const exportFrom = (sel: boolean) => { setExportSel(sel); setDialog('export'); };

  return (
    <>
      <div class="toolbar stk">
        <input class="input srch" type="search" placeholder="Search name, domain or value" aria-label="Search cookies" value={filters.q} onInput={(e) => onFilters({ ...filters, q: (e.target as HTMLInputElement).value })} />
        <Segmented<Scope> label="Scope" value={scope} onChange={onScope} options={[{ v: 'site', l: 'This site' }, { v: 'all', l: 'All sites' }]} />
        <select class="select" id="cstore" aria-label="Cookie store" value={filters.store} onChange={(e) => onFilters({ ...filters, store: (e.target as HTMLSelectElement).value })}>
          <option value="all">All stores</option>
          {stores.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
        </select>
        <span class="tbr">
          <button type="button" class="btn" onClick={() => setDialog('import')}>Import</button>
          <button type="button" class="btn" onClick={() => exportFrom(false)}>Export</button>
          <button type="button" class="btn pri" onClick={() => setOpen({})}>Add cookie</button>
        </span>
      </div>
      <div class={`cslot${n > 0 ? ' sel' : ''}`}>
        <div class="rw chips" role="group" aria-label="Filter cookies" {...(n > 0 ? { inert: true } : {})}>
          {CHIPS.map((c) => {
            const off = c.k === 'stripped' && !provOn;
            return <button key={c.k} type="button" class="chip" aria-pressed={filters.chips.has(c.k)} disabled={off} {...(off ? { title: 'Turn on cookie provenance to see stripped cookies' } : {})} onClick={() => setChip(c.k)}>{c.l}</button>;
          })}
        </div>
        <div class="bulk" role="group" aria-label="Selection" {...(n === 0 ? { inert: true } : {})}>
          <b>{n} selected</b>
          <Confirm label="Delete" onConfirm={() => void deleteSelected()} testid="bulk-delete" />
          <button type="button" class="btn cfh" onClick={() => exportFrom(true)}>Export selected</button>
          <button type="button" class="btn cfh" onClick={() => void protect()}>{allProtected ? 'Unprotect' : 'Protect'}</button>
          <button type="button" class="lnk cfh" onClick={() => setSelected(new Set())}>Clear selection</button>
        </div>
      </div>
      {provOn && <Hint note={filters.chips.has('stripped') ? `${HISTORY_NOTE} Stripped cookies never reached the browser, so they are read-only.` : HISTORY_NOTE} />}
      {data.error && <div class="banner err" role="alert"><Icon n="warn" size={16} /><span class="bt">{data.error}</span><span class="ba"><button type="button" class="btn" onClick={() => void data.reload()}>Retry</button></span></div>}
      <div class="cm-body tbl">
        <div class="tw" ref={scroller} tabIndex={-1} data-focus-fallback="">
          <CookieTable rows={rows} page={site} showSource={provOn} selected={selected} revealed={revealed} scroller={scroller} onOpen={(r) => setOpen({ row: r })} onToggle={toggle} onToggleAll={toggleAll} onReveal={reveal} />
        </div>
        {data.loading && base.length === 0 && <div class="muted center" role="status">Loading cookies…</div>}
      </div>
      {open && (
        <Drawer
          {...(open.row ? { row: open.row } : {})} stores={stores} defaultStore={filters.store !== 'all' ? filters.store : defaultStore} site={site} prov={prov}
          onClose={() => setOpen(null)} onChanged={() => void data.reload()}
        />
      )}
      {dialog === 'export' && <ExportDialog selected={exportSel ? picked.map((r) => r.c) : []} site={site} onClose={() => setDialog(null)} />}
      {dialog === 'import' && <ImportDialog stores={stores} defaultStore={defaultStore} site={site} onClose={() => setDialog(null)} onDone={() => void data.reload()} />}
    </>
  );
}

function Hint({ note }: { note: string }) {
  return <div class="hint hint-i"><Icon n="info" size={14} /><span>{note}</span></div>;
}

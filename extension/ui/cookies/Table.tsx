import type { RefObject } from 'preact';
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { NOT_SEEN_HINT, sourceLabel } from '../../lib/cookiejar/provenance';
import { Icon } from '../icons';
import { Pill, Tick } from './kit';
import { expiresText, flagPills, sizeText, type Row } from './model';

const OVERSCAN = 8;
const DEFAULT_ROW_H = 38;
/** Pills shown in one cell; the rest are counted in a "+N" pill (the cell's title lists them all). */
const MAX_PILLS = 3;

/** Whether a media query matches, kept current. Columns are rendered or not (never hidden by CSS), so header, body and spacers always share one column set. */
export function useMedia(q: string): boolean {
  const get = () => (typeof matchMedia === 'function' ? matchMedia(q).matches : false);
  const [m, setM] = useState(get);
  useEffect(() => {
    if (typeof matchMedia !== 'function') return;
    const mq = matchMedia(q);
    const f = () => setM(mq.matches);
    f();
    mq.addEventListener?.('change', f);
    return () => mq.removeEventListener?.('change', f);
  }, [q]);
  return m;
}

/** Which rows of a long list are near the viewport. Works for an inner scroller (wide) and for the window (narrow, where the page scrolls). */
export function useWindow(count: number, scroller: RefObject<HTMLElement>, anchor: RefObject<HTMLElement>, rowH: number): { start: number; end: number } {
  const [r, setR] = useState({ start: 0, end: Math.min(count, 60) });
  const calc = useCallback(() => {
    const sc = scroller.current, an = anchor.current;
    if (!sc || !an) return;
    // Wide: the table's own box scrolls. Narrow (the page scrolls): the window is the viewport.
    const inner = !(typeof matchMedia === 'function' && matchMedia('(max-width:640px)').matches);
    const box = inner ? sc.getBoundingClientRect() : { top: 0, bottom: window.innerHeight || 800 };
    const top = an.getBoundingClientRect().top;
    const h = box.bottom - box.top || window.innerHeight || 800;
    const first = Math.max(0, Math.floor((box.top - top) / rowH) - OVERSCAN);
    const last = Math.min(count, Math.ceil((box.top - top + h) / rowH) + OVERSCAN);
    setR((p) => (p.start === first && p.end === last ? p : { start: first, end: Math.max(first, last) }));
  }, [count, rowH, scroller, anchor]);
  useLayoutEffect(() => { calc(); }, [calc]);
  useEffect(() => {
    const sc = scroller.current;
    sc?.addEventListener('scroll', calc, { passive: true });
    window.addEventListener('scroll', calc, { passive: true });
    window.addEventListener('resize', calc);
    const ro = typeof ResizeObserver !== 'undefined' && sc ? new ResizeObserver(calc) : undefined;
    if (ro && sc) ro.observe(sc);
    return () => { sc?.removeEventListener('scroll', calc); window.removeEventListener('scroll', calc); window.removeEventListener('resize', calc); ro?.disconnect(); };
  }, [calc, scroller]);
  return r;
}

export interface TableProps {
  rows: Row[];
  page: string;
  showSource: boolean;
  selected: ReadonlySet<string>;
  revealed: ReadonlySet<string>;
  scroller: RefObject<HTMLElement>;
  onOpen: (r: Row) => void;
  onToggle: (key: string, on: boolean) => void;
  onToggleAll: (on: boolean) => void;
  onReveal: (key: string) => void;
}

function Flags({ r, page }: { r: Row; page: string }) {
  const pills = flagPills(r, page);
  // Over the limit, the ones that say the most stay (rule effect, partitioned, third-party), in their usual order.
  const rank = (l: string) => ['Changed by rule', 'Stripped by rule', 'Partitioned', 'Third-party', 'HttpOnly', 'Secure'].indexOf(l);
  const keep = pills.length > MAX_PILLS ? new Set([...pills].sort((a, b) => (rank(a.label) < 0 ? 99 : rank(a.label)) - (rank(b.label) < 0 ? 99 : rank(b.label))).slice(0, MAX_PILLS)) : null;
  const shown = keep ? pills.filter((p) => keep.has(p)) : pills;
  const more = pills.length - shown.length;
  return (
    <td class="flg" title={pills.map((p) => p.label).join(', ')}>
      <span class="fl">
        {shown.map((p) => <Pill key={p.label} kind={p.kind}>{p.label}</Pill>)}
        {more > 0 && <Pill>+{more}</Pill>}
      </span>
    </td>
  );
}

export function CookieTable({ rows, page, showSource, selected, revealed, scroller, onOpen, onToggle, onToggleAll, onReveal }: TableProps) {
  const body = useRef<HTMLTableSectionElement>(null);
  const [rowH, setRowH] = useState(DEFAULT_ROW_H);
  const { start, end } = useWindow(rows.length, scroller, body, rowH);
  const showVal = !useMedia('(max-width:640px)');
  const showPath = useMedia('(min-width:1400px)');
  const showSize = useMedia('(min-width:1100px)');
  // The real height of a row (zoom, fonts); everything else is arithmetic on it.
  useLayoutEffect(() => {
    const tr = body.current?.querySelector<HTMLElement>('tr[data-row]');
    const h = tr?.getBoundingClientRect().height;
    if (h && Math.abs(h - rowH) > 0.4) setRowH(h);
  });
  const sel = rows.filter((r) => !r.stripped);
  const nSel = sel.filter((r) => selected.has(r.key)).length;
  const all: boolean | 'mixed' = sel.length > 0 && nSel === sel.length ? true : nSel > 0 ? 'mixed' : false;
  const cols = 5 + (showSource ? 1 : 0) + (showVal ? 1 : 0) + (showPath ? 1 : 0) + (showSize ? 1 : 0);
  const slice = rows.slice(start, end);
  return (
    <table class="t ck" data-testid="cookie-table" aria-label="Cookies" aria-rowcount={rows.length + 1}>
      <colgroup>
        <col class="k-tick" /><col class="k-name" />{showVal && <col class="k-val" />}<col class="k-dom" />{showSource && <col class="k-src" />}{showPath && <col class="k-path" />}<col class="k-exp" /><col class="k-flags" />{showSize && <col class="k-size" />}
      </colgroup>
      <thead>
        <tr>
          <th class="stk1"><Tick checked={all} label="Select all" onChange={(on) => onToggleAll(on)} disabled={sel.length === 0} /></th>
          <th class="stk2">Name</th>{showVal && <th>Value</th>}<th>Domain</th>{showSource && <th>Source</th>}{showPath && <th>Path</th>}<th>Expires</th><th>Flags</th>{showSize && <th class="r">Size</th>}
        </tr>
      </thead>
      <tbody ref={body}>
        {start > 0 && <tr class="spacer" aria-hidden="true" style={`height:${start * rowH}px`}><td colSpan={cols} /></tr>}
        {slice.map((r, i) => {
          const c = r.c;
          const rv = revealed.has(r.key);
          const src = sourceLabel(r.info);
          const srcTitle = r.info?.seen ? src : `${src}. ${NOT_SEEN_HINT}.`;
          return (
            <tr key={r.key} data-row={start + i} class={`clk${r.stripped ? ' strip-r' : ''}`} aria-rowindex={start + i + 2} aria-selected={r.stripped ? undefined : selected.has(r.key)} onClick={(e) => { if (!(e.target as HTMLElement).closest('.cbx,.val')) onOpen(r); }}>
              <td class="stk1"><Tick checked={selected.has(r.key)} label={`Select ${c.name}`} disabled={!!r.stripped} onChange={(on) => onToggle(r.key, on)} /></td>
              <td class="nm stk2">
                <button type="button" class="lnk mono" title={c.name} onClick={() => onOpen(r)}>{c.name}</button>
                {c.isProtected && <span class="dim prot" title="Protected from delete and auto-delete" aria-label="Protected"><Icon n="lock" size={13} /></span>}
              </td>
              {showVal && (
                <td class="val">
                  {r.stripped ? <span class="dim">never stored</span>
                    : <button type="button" class={`vbtn${rv ? ' rev' : ''}`} aria-label={`${rv ? 'Hide' : 'Reveal'} value of ${c.name}`} {...(rv ? { title: c.value } : {})} onClick={() => onReveal(r.key)}>{rv ? c.value || '(empty)' : '••••••'}</button>}
                </td>
              )}
              <td class="mono dom" title={c.partitionKey ? `${c.domain} (top-level site: ${c.partitionKey.topLevelSite.replace(/^https?:\/\//, '')})` : c.domain}>{c.domain}</td>
              {showSource && <td class="src" title={srcTitle}><span class="srct">{src}</span></td>}
              {showPath && <td class="mono" title={c.path}>{c.path}</td>}
              <td class="num">{r.stripped ? 'Never stored' : expiresText(c)}</td>
              <Flags r={r} page={page} />
              {showSize && <td class="r num">{r.stripped ? '–' : sizeText(c)}</td>}
            </tr>
          );
        })}
        {end < rows.length && <tr class="spacer" aria-hidden="true" style={`height:${(rows.length - end) * rowH}px`}><td colSpan={cols} /></tr>}
        {rows.length === 0 && <tr><td colSpan={cols} class="empty muted">No cookies match.</td></tr>}
      </tbody>
    </table>
  );
}

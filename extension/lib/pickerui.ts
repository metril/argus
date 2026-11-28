/** The in-page element picker and zapper: a closed shadow root, no access to the token. */
import { candidates, cosmeticRule, resourceRule, resourceUrl, specificForAllSites, type Candidate } from './pickercore';
import type { PickerMode } from './arming';

export interface PickerOptions {
  mode: PickerMode;
  /** Registrable domain of the page. */
  site: string;
  send(msg: { type: string; rule?: string; confirmed?: boolean; allSites?: boolean }): Promise<{ ok?: boolean; error?: string; scope?: boolean } | undefined>;
  doc?: Document;
  onDone?: () => void;
}

/** Only a real user click counts as the confirmation; a page script's dispatched event is not trusted. */
export const isTrustedClick = (e: Event): boolean => e.isTrusted === true;

const CSS = `
:host{all:initial}
*{box-sizing:border-box;font:13px/1.4 system-ui,sans-serif}
.box{position:fixed;pointer-events:none;border:2px solid #e8590c;background:rgba(232,89,12,.18);z-index:2147483646;display:none}
.panel{position:fixed;right:12px;bottom:12px;width:340px;max-width:calc(100vw - 24px);background:#fff;color:#1b1b1f;border:1px solid #888;border-radius:8px;box-shadow:0 6px 24px rgba(0,0,0,.35);padding:12px;z-index:2147483647}
.panel *{color:inherit}
h1{font-size:14px;margin:0 0 8px;font-weight:600}
label{display:block;margin:4px 0}
input[type=text],textarea,select{width:100%;padding:4px 6px;border:1px solid #888;border-radius:4px;background:#fff;color:#1b1b1f;font-family:ui-monospace,monospace;font-size:12px}
input[type=range]{width:100%}
.row{display:flex;gap:6px;margin-top:8px;flex-wrap:wrap}
button{padding:5px 10px;border:1px solid #666;border-radius:4px;background:#f2f2f4;color:#1b1b1f;cursor:pointer}
button.pri{background:#e8590c;color:#fff;border-color:#e8590c}
button:disabled{opacity:.5;cursor:default}
code{display:block;padding:4px 6px;background:#eee;border-radius:4px;word-break:break-all;font-family:ui-monospace,monospace;font-size:12px}
.muted{color:#555}.err{color:#b00020}.ok{color:#1b7f3b}
`;

export function startPicker(o: PickerOptions): () => void {
  const doc = o.doc ?? document;
  const win = doc.defaultView!;
  const host = doc.createElement('div');
  host.setAttribute('popover', 'manual');
  for (const [k, v] of [['all', 'initial'], ['display', 'block'], ['position', 'fixed'], ['inset', '0'], ['width', '100vw'], ['height', '100vh'], ['border', '0'], ['padding', '0'], ['margin', '0'], ['background', 'transparent'], ['overflow', 'visible'], ['pointer-events', 'none'], ['opacity', '1'], ['visibility', 'visible'], ['transform', 'none'], ['z-index', '2147483647']] as const) host.style.setProperty(k, v, 'important');
  const root = host.attachShadow({ mode: 'closed' });
  const style = doc.createElement('style');
  style.textContent = CSS;
  const box = doc.createElement('div');
  box.className = 'box';
  root.append(style, box);
  (doc.documentElement).append(host);
  // The top layer: nothing the page draws, whatever its z-index, can sit above the panel.
  const popover = typeof (host as { showPopover?: unknown }).showPopover === 'function';
  if (popover) { try { (host as unknown as { showPopover(): void }).showPopover(); } catch { /* not shown: the intact check refuses to save */ } }
  /** The host is still ours and visible: the page cannot have hidden, faded, moved or covered it to bait a click. */
  const hostIntact = (): boolean => {
    if (!host.isConnected || host.parentNode !== doc.documentElement) return false;
    const cs = win.getComputedStyle(host);
    if (parseFloat(cs.opacity) !== 1 || cs.visibility !== 'visible' || cs.display === 'none') return false;
    if (cs.transform && cs.transform !== 'none') return false;
    if (popover) { try { if (!host.matches(':popover-open')) return false; } catch { /* unsupported selector */ } }
    return true;
  };
  // Any change the page makes to the host's attributes or style aborts the picker.
  const watch = new win.MutationObserver(() => finish());
  watch.observe(host, { attributes: true });

  const el = <K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> & { className?: string } = {}, ...kids: (Node | string)[]) => {
    const n = doc.createElement(tag);
    Object.assign(n, props);
    n.append(...kids);
    return n;
  };

  let hovered: Element | null = null;
  let chosen: Element | null = null;
  let panel: HTMLElement | null = null;
  let hidden: { el: HTMLElement; display: string; prio: string }[] = [];
  const removed: { node: Element; parent: Node; next: Node | null }[] = [];
  let done = false;
  let zapUndo: HTMLButtonElement | undefined;

  const outline = (t: Element | null) => {
    if (!t) { box.style.display = 'none'; return; }
    const r = t.getBoundingClientRect();
    Object.assign(box.style, { display: 'block', left: `${r.left}px`, top: `${r.top}px`, width: `${r.width}px`, height: `${r.height}px` });
  };
  const restore = () => {
    for (const h of hidden) { h.el.style.setProperty('display', h.display, h.prio); if (!h.display) h.el.style.removeProperty('display'); }
    hidden = [];
  };
  const preview = (sel: string): number => {
    restore();
    let list: NodeListOf<Element>;
    try { list = doc.querySelectorAll(sel); } catch { return -1; }
    list.forEach((n) => {
      const h = n as HTMLElement;
      // Never hide the picker itself or anything that holds it.
      if (!h.style || h === host || h.contains(host)) return;
      hidden.push({ el: h, display: h.style.getPropertyValue('display'), prio: h.style.getPropertyPriority('display') });
      h.style.setProperty('display', 'none', 'important');
    });
    return list.length;
  };

  const finish = () => {
    if (done) return;
    done = true;
    watch.disconnect();
    restore();
    for (const l of listeners) win.removeEventListener(l[0], l[1] as EventListener, true);
    host.remove();
    void o.send({ type: 'picker-close' });
    o.onDone?.();
  };

  const isOurs = (e: Event) => e.target === host;
  const pickable = (t: EventTarget | null): Element | null => {
    const n = t as Element | null;
    return n && n.nodeType === 1 && n !== doc.documentElement && n !== doc.body && n !== host ? n : null;
  };

  // The panel -------------------------------------------------------------
  const openPanel = (target: Element) => {
    chosen = target;
    outline(target);
    const cands: Candidate[] = candidates(target);
    const resUrl = resourceUrl(target);
    let idx = 0;
    let scope: 'site' | 'everywhere' = 'site';
    const sel = el('input', { type: 'text', value: cands[0]?.selector ?? '' });
    sel.setAttribute('aria-label', 'Selector');
    const slider = el('input', { type: 'range', min: '0', max: String(Math.max(0, cands.length - 1)), value: '0', disabled: cands.length < 2 });
    slider.setAttribute('aria-label', 'Specific to broad');
    const countLbl = el('div', { className: 'muted' });
    const ruleOut = el('code');
    const status = el('div');
    const mkRadio = (v: 'site' | 'everywhere', text: string) => {
      const r = el('input', { type: 'radio', name: 'scope', value: v, checked: v === 'site' });
      r.addEventListener('change', () => { scope = v; refresh(); });
      return { r, lbl: el('label', {}, r, ` ${text}`) };
    };
    const rs = mkRadio('site', `This site (${o.site || 'unknown'})`);
    const ra = mkRadio('everywhere', 'All sites');
    if (!o.site) { rs.r.disabled = true; rs.r.checked = false; ra.r.checked = true; scope = 'everywhere'; }
    const save = el('button', { className: 'pri', textContent: 'Hide element' });
    const block = el('button', { textContent: 'Block its resource' });
    const match = el('select');
    for (const [v, t] of [['host', 'whole host'], ['path', 'path prefix'], ['url', 'exact URL']] as const) match.append(el('option', { value: v, textContent: t }));
    const again = el('button', { textContent: 'Pick another' });
    const cancel = el('button', { textContent: 'Cancel' });
    const resRule = () => (resUrl ? resourceRule(resUrl, { scope, match: match.value as 'host' | 'path' | 'url', site: o.site }) : '');
    const refresh = () => {
      const s = sel.value.trim();
      const n = s ? preview(s) : 0;
      countLbl.textContent = n < 0 ? 'Not a valid selector' : `${n} element${n === 1 ? '' : 's'} hidden (preview)`;
      const generic = scope === 'everywhere';
      const allowed = !generic || specificForAllSites(s);
      ra.lbl.title = allowed ? '' : 'All sites needs an id, a class or an attribute value';
      ruleOut.textContent = cosmeticRule(o.site, s, scope);
      save.disabled = !s || n <= 0 || !allowed;
      status.className = 'muted';
      status.textContent = generic && !allowed ? 'Too broad for all sites: add an id, class or attribute value.' : '';
      block.disabled = !resUrl;
    };
    slider.addEventListener('input', () => { idx = Number(slider.value); sel.value = cands[idx]?.selector ?? sel.value; refresh(); });
    sel.addEventListener('input', refresh);
    match.addEventListener('change', () => { ruleOut.textContent = resRule(); });
    const submit = async (e: Event, rule: string) => {
      // A script on the page can dispatch a click; it cannot make it trusted.
      if (!isTrustedClick(e) || !rule) return;
      if (!hostIntact()) { finish(); return; }
      save.disabled = true; block.disabled = true;
      status.className = 'muted'; status.textContent = 'Saving';
      const r = await o.send({ type: 'picker-save', rule, confirmed: true, allSites: scope === 'everywhere' }).catch(() => undefined);
      if (r?.ok) { status.className = 'ok'; status.textContent = 'Saved. Reload the page to apply.'; }
      else { status.className = 'err'; status.textContent = r?.scope ? 'Sign in to Argus again to allow this.' : `Not saved${r?.error ? `: ${r.error}` : ''}`; refresh(); }
    };
    save.addEventListener('click', (e) => void submit(e, cosmeticRule(o.site, sel.value.trim(), scope)));
    block.addEventListener('click', (e) => void submit(e, resRule()));
    again.addEventListener('click', () => { restore(); panel?.remove(); panel = null; chosen = null; outline(null); });
    cancel.addEventListener('click', finish);
    panel?.remove();
    panel = el('div', { className: 'panel' },
      el('h1', {}, 'Block an element'),
      sel, el('div', { className: 'muted' }, 'Specific'), slider, el('div', { className: 'muted' }, 'Broad'),
      countLbl, rs.lbl, ra.lbl, el('div', { className: 'muted' }, 'Rule'), ruleOut,
      ...(resUrl ? [el('div', { className: 'row' }, el('span', { className: 'muted' }, 'Resource'), match, block)] : []),
      status, el('div', { className: 'row' }, save, again, cancel));
    panel.style.pointerEvents = 'auto';
    root.append(panel);
    refresh();
    if (resUrl) match.dispatchEvent(new win.Event('change'));
    refresh();
  };

  const openZapper = () => {
    const undo = el('button', { textContent: 'Undo', disabled: true });
    const exit = el('button', { className: 'pri', textContent: 'Done' });
    undo.addEventListener('click', () => {
      const r = removed.pop();
      if (r) r.parent.insertBefore(r.node, r.next);
      undo.disabled = removed.length === 0;
    });
    exit.addEventListener('click', finish);
    panel = el('div', { className: 'panel' }, el('h1', {}, 'Zapper'), el('div', { className: 'muted' }, 'Click an element to remove it from this page view. Nothing is saved. Esc exits.'), el('div', { className: 'row' }, undo, exit));
    panel.style.pointerEvents = 'auto';
    root.append(panel);
    zapUndo = undo;
  };

  // Page events ------------------------------------------------------------
  const swallow = (e: Event) => { if (!isOurs(e)) { e.preventDefault(); e.stopImmediatePropagation(); } };
  const onMove = (e: Event) => {
    if (isOurs(e) || chosen) return;
    const t = pickable(e.target);
    hovered = t;
    outline(t);
  };
  const onClick = (e: Event) => {
    if (isOurs(e)) return;
    swallow(e);
    if (chosen) return;
    const t = pickable(e.target) ?? hovered;
    if (!t) return;
    if (o.mode === 'zapper') {
      const parent = t.parentNode;
      if (!parent) return;
      removed.push({ node: t, parent, next: t.nextSibling });
      t.remove();
      outline(null);
      if (zapUndo) zapUndo.disabled = false;
      return;
    }
    openPanel(t);
  };
  const onKey = (e: Event) => {
    if ((e as KeyboardEvent).key === 'Escape') { e.preventDefault(); e.stopImmediatePropagation(); finish(); }
  };
  const listeners: [string, EventListener][] = [
    ['mousemove', onMove], ['click', onClick], ['keydown', onKey],
    ['mousedown', swallow], ['mouseup', swallow], ['pointerdown', swallow], ['pointerup', swallow], ['auxclick', swallow], ['contextmenu', swallow],
  ];
  for (const [t, f] of listeners) win.addEventListener(t, f, true);

  if (o.mode === 'zapper') openZapper();
  return finish;
}
